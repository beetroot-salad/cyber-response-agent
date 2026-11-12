"""Shared helpers for the PR 2 run-repository tests (tenant fixtures, CLI/process drivers). No test functions."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

import logging
import io
import os
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from types import SimpleNamespace
from pathlib import Path
from typing import Any

from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.oracle.live_contracts import _spec1224 as S

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
RUNS_BASE_ENV = T.RUNS_BASE_ENV

#: The launch fixture's tenant (`_spec1224.FIXTURE_TENANT`).
LAUNCH_TENANT = S.FIXTURE_TENANT
#: The source run's id (`_triplet_947.SOURCE_RUN_ID`): a uuid4, the only text `RunId` admits.
SOURCE_RUN_ID = T.SOURCE_RUN_ID
BRANCH_MESSAGE_ID = T.BRANCH_MESSAGE_ID
#: The episode id a hand-built sibling scene carries (`_triplet_947.EPISODE_ID`). A launch mints
#: its own, so a launcher test finds its episode with `launched_episodes`, never by this id.
EPISODE_ID = T.EPISODE_ID
#: The sibling fixture's tenant (`_triplet_947.SOURCE_TENANT`).
SIBLING_TENANT = T.SOURCE_TENANT


# ==========================================================================================
# The edges' argument shapes: each by-path helper delegates to its by-id `new_*` form.
# ==========================================================================================

def launch_argv(tenant_id: str, source_run_dir: Path) -> list[str]:
    """The launcher's command line for the run at `source_run_dir`, named by its folder name."""
    return new_launch_argv(tenant_id, Path(source_run_dir).name)


def new_launch_argv(tenant_id: str, source_run_id: str) -> list[str]:
    """`branch --tenant T <source_run_id> <BRANCH_MESSAGE_ID>`."""
    return ["--tenant", tenant_id, source_run_id, str(BRANCH_MESSAGE_ID)]


def sibling_argv(tenant_id: str, episode_dir: Path, label: str, *extra: str) -> list[str]:
    """A sibling's `run.py` command line for the episode at `episode_dir`, named by its id."""
    return new_sibling_argv(tenant_id, Path(episode_dir).name, label, *extra)


def new_sibling_argv(tenant_id: str, episode_id: str, label: str, *extra: str) -> list[str]:
    """`run.py --tenant T --episode <episode_id> --world L`."""
    return ["--tenant", tenant_id, "--episode", episode_id, "--world", label, *extra]


def page_argv(tenant_id: str, episode_dir: Path) -> list[str]:
    """The episode page CLI's argv for the episode at `episode_dir` (`visualize_episode.main`
    takes no program name)."""
    return new_page_argv(tenant_id, Path(episode_dir).name)


def new_page_argv(tenant_id: str, episode_id: str) -> list[str]:
    """`visualize_episode.py --tenant T <episode_id>`."""
    return ["--tenant", tenant_id, episode_id]


def run_page_argv(tenant_id: str, run_dir: Path) -> list[str]:
    """The run page CLI's argv for the natural run at `run_dir` (`visualize_run.main` takes
    `sys.argv`, program name first)."""
    return new_run_page_argv(tenant_id, Path(run_dir).name)


def new_run_page_argv(tenant_id: str, run_id: str, *, episode_id: str | None = None) -> list[str]:
    """`visualize_run.py --tenant T [--episode ep] <run_id>`."""
    episode = ["--episode", episode_id] if episode_id is not None else []
    return ["visualize_run.py", "--tenant", tenant_id, *episode, run_id]


# ==========================================================================================
# Roots and scenes.
# ==========================================================================================

def roots(tmp_path: Path, monkeypatch: Any) -> None:
    """Every configured root inside `tmp_path`: the operator runs base pre-flight exports and
    the learning state root. No episodes base: an episode lives under its tenant."""
    monkeypatch.setenv(RUNS_BASE_ENV, str(Path(tmp_path) / "defender-runs"))


def data_root() -> Path:
    return Path(os.environ[DATA_ROOT_ENV])


def episodes(tenant_id: str = LAUNCH_TENANT) -> Path:
    """`<data root>/<tenant_id>/episodes`: where every episode of that tenant lives."""
    return data_root() / tenant_id / "episodes"


def launched_episodes() -> list[Path]:
    """Every entry under `episodes()`, sorted: how a launcher test finds the episode a launch made
    (or shows it made none). Non-folders are listed too, so a squatter is not hidden."""
    folder = episodes()
    return sorted(folder.iterdir()) if folder.is_dir() else []


#: The one answer every captured call recorded and the live estate gives
#: (`test_episode_stage_timing._BASE`), so an oracle serving it unchanged calibrates every world.
BASE_ANSWER = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon",
                         "host": "web-1", "ts": "2026-07-28T15:00:00Z"}]}


def source_calls() -> list:
    return [S.Call("idp", "query", S.query_params("user:alice"), BASE_ANSWER),
            S.Call("edr", "query", S.query_params("host:db-1"), BASE_ANSWER),
            S.Call("siem-x", "lookup", {"entity": "svc-1225"}, BASE_ANSWER)]


def launch_source(tmp_path: Path, *, source_run_id: str = SOURCE_RUN_ID) -> tuple[Any, Path]:
    """`(estate, source run dir)`: the launch fixture tenant and ONE finished, branchable source
    run at `<data root>/<T>/runs/<source_run_id>` whose captured calls the live estate answers
    unchanged. The calls land through `runs_base(land_calls=...)`, before the source's session is
    seeded: the fork snapshot holds the table as of the branch point, so a table rewritten later
    no longer opens and the launch is refused (#1255)."""
    est = S.estate(tmp_path)
    est.place(tenant_id=LAUNCH_TENANT)

    def land(src: Path) -> None:
        for seq, c in enumerate(source_calls()):
            T.capture_call(src, system=c.system, verb=c.verb, params=dict(c.params),
                           payload=c.payload, lead=S.LEAD, seq=seq)
            est.answer(c.system, c.verb, c.params, c.payload)

    _base, src = location_path(T.runs_base)(tmp_path, tenant_id=LAUNCH_TENANT, source_run_id=source_run_id,
                             land_calls=land)
    return est, src


def quiet_judge() -> Any:
    """The judge double, recording every prompt it is handed: every world call answers
    `bucket: none` with nothing filed, the family call (a reply of its own shape) with no world
    finding."""
    return J.FakeJudge(
        default=J.as_reply_text(J.reply_doc(findings=[], bucket="none", systems=[])),
        family_default=J.as_reply_text(J.family_reply()))


@dataclass
class Launched:
    rc: int | None
    #: The refusal's text (`sys.exit(msg)` / `LauncherRefused(msg)`), "" when none was raised.
    message: str
    #: The exception the launch left through, `None` when it returned.
    raised: BaseException | None
    spawn: Any
    judge: Any
    questioner: Any


class CountingQuestioner:
    """The question-writer seam (`questioner=`), delegating to `_spec1224.questioner_for()` and
    counting its calls: "refused before anything is spent" is `calls == 0`."""

    def __init__(self, inner: Any = None) -> None:
        self.inner = inner if inner is not None else S.questioner_for()
        self.calls = 0

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        return self.inner(*args, **kwargs)


def drive_launch(est: Any, argv: list[str], *, spawn: Any = None, judge: Any = None,
                 **seams: Any) -> Launched:
    """Drive the REAL `learning/branch/cli.main` over `argv`, every fake by its seam: the
    role preflight neutralised, pre-flight's oracle serving every captured call unchanged and
    its verifier passing it (so the family is accepted), the judge recording its prompts."""
    from defender.cli.learning import branch as branch_entry

    # The fake sibling materialises each arm at the id the launched episode's roster holds, the
    # episode named by the child's own argv.
    spawn = spawn if spawn is not None else J.FakeSibling()  # lint-default: ok — a test builder's fresh per-call double, never a shared instance
    judge = judge if judge is not None else quiet_judge()  # lint-default: ok — a test builder's fresh per-call double, never a shared instance
    questioner = seams.pop("questioner", None) or CountingQuestioner()
    seams.setdefault("preflight", S.no_preflight)
    seams.setdefault("live_tree", T.source_capture())
    seams.setdefault("roster", est.roster())
    seams.setdefault("oracle", S.oracle(then=S.submit(BASE_ANSWER, S.EMPTY_CLAIM)).model)
    seams.setdefault("verifier", S.passing_verifier().model)
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv

    seams.setdefault("directory", directory_for_argv(argv, records=est.records()))  # r10 A1/C9: the launcher admits through the tenant records, the estate's (stated, #1366 R10)
    S.R.assert_records_within_roster(seams["directory"], argv[argv.index("--tenant") + 1], seams["roster"])
    rc: int | None = None
    message = ""
    raised: BaseException | None = None
    try:
        rc = branch_entry.main(list(argv), spawn=spawn, judge=judge, questioner=questioner, **seams)
    except SystemExit as stop:
        raised = stop
        if isinstance(stop.code, str):
            message = stop.code
        else:
            rc = stop.code if isinstance(stop.code, int) else 1
    except Exception as failed:  # noqa: BLE001 — handed back; the test asserts
        raised = failed
        message = str(failed)
    if rc not in (0, None) and message:
        # Logged so a test failing downstream of a refused launch carries why in its log.
        logging.getLogger(__name__).warning("the launch was refused (rc=%s): %s", rc, message)
    return Launched(rc, message, raised, spawn, judge, questioner)


def grade(episode_dir: Path, tenant_id: str) -> Any:
    """Grade `episode_dir` afresh for `tenant_id` through `learning.judge.grade_episode(runs,
    episode_id)`, `runs` being the tenant's repository under the configured data root. A final
    `judge.yaml` short-circuits a second pass, so it is removed first."""
    from defender.tenancy import _tenant
    from defender.tests.support.learning.judge._memory_store import MemoryStore
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1

    (Path(episode_dir) / "judge.yaml").unlink(missing_ok=True)

    runs = _tenant.accept_tenant(
        fixture_data_root(data_root()), tenant_id, defender_dir=H1.DEFENDER).runs_repository()
    return T.mod("learning.judge").grade_episode(
        runs, Path(episode_dir).name, judge=J.scripted_judge(), store=MemoryStore())


def sibling_scene(tmp_path: Path, *, roster: bool = True) -> tuple[Path, Path]:
    """`(source run dir, episode dir)` for a sibling: the fixture tenant `SIBLING_TENANT` with a
    branchable source run at its natural runs folder (`_triplet_947.runs_base`), and an episode
    at `<data root>/<SIBLING_TENANT>/episodes/<EPISODE_ID>` holding the launcher's manifest
    (naming that source) and a primed `served/base.jsonl`."""
    from defender import _yaml
    from defender.tests.storage.ids_1187 import _spec1187 as R

    _base, src = location_path(T.runs_base)(tmp_path, source_run_id=SOURCE_RUN_ID)
    doc = family_doc(src)
    labels = [w["label"] for w in doc.get("worlds", [])]
    ep = R.make_episode(data_root(), SIBLING_TENANT, EPISODE_ID, manifest=_yaml.safe_dump(doc),
                        labels=labels, roster=False)
    (ep / "served").mkdir(exist_ok=True)
    (ep / "served" / "base.jsonl").write_text("", encoding="utf-8")
    if T.PLANT_RECORDS:
        # The launch's copies of the source alert and its record, as `T.episode` plants them
        # for the suites that run with the front door's records on.
        T._plant_source_input(ep, str(src), SOURCE_RUN_ID)
    if roster:
        (ep / "runs").mkdir(exist_ok=True)
        R.write_roster(ep, {T.world_id(ep, label): R.new_id() for label in labels})
    return src, ep


def family_doc(src: Path, **over: Any) -> dict:
    """The launcher's manifest for the sibling scene (`_triplet_947.family_doc`), naming the
    source by `source_run_id`; the legacy `source_run_dir` it also carries loads but is never read."""
    return T.family_doc(**{"source_run_dir": str(src), "source_run_id": SOURCE_RUN_ID, **over})


class SiblingRecorder:
    """`run.main`'s spend seams for a sibling, recording order; `materialize` is left to the
    REAL builder (run setup), so the container's record, the arm's create and the source screen
    all run. `lifecycle` returns at once; nothing models or boxes."""

    def __init__(self) -> None:
        self.order: list[str] = []
        self.lifecycle_kwargs: dict[str, Any] = {}

    def preflight(self, _model: str | None = None, *, branching: bool = False) -> int:
        self.order.append("preflight")
        return 0

    def lifecycle(self, **kwargs: Any) -> dict[str, Any]:
        self.order.append("lifecycle")
        self.lifecycle_kwargs = kwargs
        return {"output": "spec1105-pr2", "requests": 0, "truncated_by": None}

    def visualize(self, *_a: Any, **_kw: Any) -> None:
        self.order.append("visualize")

    def enqueue(self, *_a: Any, **_kw: Any) -> bool:
        self.order.append("enqueue")
        return False

    def seams(self) -> dict[str, Any]:
        return {"preflight": self.preflight, "lifecycle": self.lifecycle,
                "visualize": self.visualize, "enqueue": self.enqueue}

    @property
    def run_dir(self) -> Path | None:
        run = self.lifecycle_kwargs.get("run")
        return run.run_dir if run is not None else None


def drive_run_py(argv: list[str], rec: SiblingRecorder, **override: Any) -> tuple[
        int | None, BaseException | None, str]:
    """Drive the REAL `run.main` over `argv` with `rec`'s seams. Returns `(exit status, the
    SystemExit it refused with or None, everything it printed to stderr)`."""
    from defender import run as run_py
    from defender.tests.support.tenancy._launch_publish_p4 import with_publish

    err = io.StringIO()
    try:
        with redirect_stderr(err):
            # Plus the in-process launch-time publish.
            rc = run_py.main(list(argv), **with_publish({**rec.seams(), **override}, argv))
    except SystemExit as refused:
        return None, refused, err.getvalue()
    return rc, None, err.getvalue()


@dataclass
class StdoutRun:
    """`drive_run_py` with stdout captured: `seen[step]` is what stdout held when `step`'s seam
    ran (`preflight`, `ticket`, `lifecycle`, ...)."""

    rc: int | None
    refusal: BaseException | None
    err: str
    out: str
    seen: dict[str, str]


class _TicketTap:
    """A ticket writer seam that records stdout when the ticket lane begins (`--update-ticket`).
    #1359: there is no open leg; run start's first act on the lane is `clear_receipt`."""

    def __init__(self, tap: Any) -> None:
        self._tap = tap

    def clear_receipt(self, *_a: Any, **_kw: Any) -> None:
        self._tap("ticket")

    def record_case_ticket(self, *_a: Any, **_kw: Any) -> None:
        return None


def drive_run_py_stdout(argv: list[str], rec: SiblingRecorder, **override: Any) -> StdoutRun:
    out = io.StringIO()
    seen: dict[str, str] = {}

    def tap(step: str) -> None:
        seen[step] = out.getvalue()

    def tapped(step: str, seam: Any) -> Any:
        def call(*a: Any, **kw: Any) -> Any:
            tap(step)
            return seam(*a, **kw)
        return call

    seams = {name: tapped(name, seam) for name, seam in rec.seams().items()}
    seams["ticket_writer"] = _TicketTap(tap)
    with redirect_stdout(out):
        rc, refusal, err = drive_run_py(argv, rec, **{**seams, **override})
    return StdoutRun(rc, refusal, err, out.getvalue(), seen)


def refusal_text(exc: BaseException | None) -> str:
    if exc is None:
        return ""
    if isinstance(exc, SystemExit):
        return exc.code if isinstance(exc.code, str) else repr(exc.code)
    return str(exc)


@dataclass
class CliResult:
    rc: int | None
    out: str
    err: str
    raised: BaseException | None = None

    @property
    def said(self) -> str:
        return f"{refusal_text(self.raised)}\n{self.err}"


def active_directory_for(main: Any, argv: list[str]) -> Any:
    """The seeded ACTIVE tenant directory a host command's `main(argv, directory=)` is driven with (r10.1 C1/C9: every
    host entry point admits through the host acceptance, whose records a test hands in): active for the tenant `--tenant`
    names, over the data root the test set. None for a `main` with no `directory` seam or an argv naming no tenant."""
    import inspect

    if "directory" not in inspect.signature(main).parameters:
        return None
    tenant = next((argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--tenant"), None)
    tenant = tenant or next((a.split("=", 1)[1] for a in argv if a.startswith("--tenant=")), None)
    if not tenant:
        return None
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv

    return directory_for_argv(argv)


def drive_cli(main: Any, argv: list[str], *, directory: Any = None) -> CliResult:
    """Call a CLI's `main(argv)`, capturing stdout and stderr; a `SystemExit` is handed back,
    never raised. A host command is handed `directory` (default: active for its `--tenant`, see
    `active_directory_for`), since it admits its tenant through the tenant records (r10 A1)."""
    out, err = io.StringIO(), io.StringIO()
    rc: int | None = None
    raised: BaseException | None = None
    records = directory if directory is not None else active_directory_for(main, argv)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(list(argv)) if records is None else main(list(argv), directory=records)
    except SystemExit as stop:
        raised = stop
        rc = stop.code if isinstance(stop.code, int) else None
    return CliResult(rc, out.getvalue(), err.getvalue(), raised)


def page_main() -> Any:
    from defender.presentation import visualize_episode

    return visualize_episode.main


def run_page_main() -> Any:
    from defender.presentation import visualize_run

    return visualize_run.main


def second_tenant(root: Path, tenant_id: str) -> Any:
    """A further real tenant under `root` (a hand-made row over the committed fixture's
    knowledge — `create_tenant` admits one per root), accepted by the real `accept_tenant`."""
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H

    return H.tenant(root, tenant_id)


def tree(root: Path) -> dict[str, tuple[str, bytes | str | None]]:
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H

    return H.tree_state(root)


# ==========================================================================================
# Curation: the queue and the drain.
# ==========================================================================================

def git_repo(path: Path) -> Path:
    """A one-commit git work tree (the drain claims git over `LoopPaths.repo_root`)."""
    import subprocess

    path.mkdir(parents=True, exist_ok=True)
    for args in (["init", "-q", "-b", "main"], ["config", "user.email", "t@e.com"],
                 ["config", "user.name", "T"]):
        subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)  # noqa: S603,S607
    (path / "README").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, capture_output=True)  # noqa: S603,S607
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "seed"], check=True,  # noqa: S603,S607
                   capture_output=True)
    return path


# #1278: a curation request is a row of the learning store, not a file under `author-queue/`. These helpers hold a
# tenant's requests the way the store hands them to the lane (`(kind, key, payload)` items) and read back the fate the
# lane decided for each (`drains._store_lead_work`: the drain's claim loop, with no database); what the store does with a
# fate (the attempt ceiling, the retirement of a waiting request) is pinned by the store's own contract tests
# (`tests/learning/store_1278/test_store_1278.py`, D8). The real tick over the store is `file_request` + `drains.lead_author_drain`.

_QUEUES: dict[str, _Queue] = {}


@dataclass
class _Queue:
    rows: dict[str, dict] = field(default_factory=dict)
    outcomes: dict[tuple[str, str], Any] = field(default_factory=dict)


def _queue_of(paths: Any) -> _Queue:
    """The requests held for `paths`' tenant (for paths with no tenant: for their checkout)."""
    tenant = paths.tenant
    return _QUEUES.setdefault(str(location_path(tenant.runs)) if tenant is not None else str(paths.repo_root), _Queue())


def queue_row(paths: Any, case_id: str, body: dict) -> None:
    """A curation request `body` (`{case_id, tenant_id, run_id}`, or any malformed payload) held for `paths`' drain
    under `case_id`."""
    _queue_of(paths).rows[case_id] = dict(body)


def _fate(paths: Any, case_id: str) -> Any:
    return _queue_of(paths).outcomes.get(("curation_request", case_id))


def dead_letter(paths: Any, case_id: str) -> dict | None:
    """`{"failed": <reason>}` when the lane decided the request dead, else None."""
    fate = _fate(paths, case_id)
    return {"failed": fate.reason} if fate is not None and fate.name == "dead" else None


def still_queued(paths: Any, case_id: str) -> bool:
    """The request is still to be served: the lane has decided no fate for it, or decided it waits."""
    fate = _fate(paths, case_id)
    return fate is None or fate.name == "waiting"


def fate_name(paths: Any, case_id: str) -> str | None:
    """The name of the fate the lane decided for the request (`dead`, `skipped`, `waiting`), None before any."""
    fate = _fate(paths, case_id)
    return None if fate is None else fate.name


@dataclass
class Lane:
    """The drain's lead-author lane (`run_lead_author`), recording the opened `Run` it was
    handed; `run_dirs` gives the folder each lives in."""

    handed: list[Any] = field(default_factory=list)

    def __call__(self, _paths: Any, _state: Any, run: Any, *, box: Any = None,
                 on_done: Any = None, items: Any = (), outcomes: Any = None, **_kw: Any) -> None:
        from defender.learning.store import Outcome

        self.handed.append(run)
        for kind, key, _payload in items:  # served: the real step decides a fate for each item it was handed
            outcomes[(kind, key)] = Outcome.skipped("served by the test's lane")
        if on_done is not None:
            on_done(None)

    @property
    def run_dirs(self) -> list[Path]:
        return [Path(getattr(h, "run_dir", h)) for h in self.handed]


def drain(paths: Any, lane: Lane) -> dict:
    """One lead-author tick's claim loop over `paths` (`drains._store_lead_work`, the drain's accepted tenant
    `paths.tenant` its only door to a run): the requests held for `paths` that have no fate yet, handed to `lane`,
    with the pitfalls step doing nothing. Returns the fates decided so far."""
    from defender.learning.core import drains

    queue = _queue_of(paths)
    held = [("curation_request", case_id, dict(body)) for case_id, body in queue.rows.items()
            if still_queued(paths, case_id)]
    drains._store_lead_work(paths, lane, lambda *_a, **_kw: 0, box=None, batch=None, held=SimpleNamespace(items=held),
                            feedback=None, outcomes=queue.outcomes)
    return queue.outcomes


def tenant_loop_paths(tenant: Any) -> Any:
    """The drain's paths for the accepted `tenant` (`paths.tenant` set). A drain rehydrates a claim only through the
    tenant its start accepted (r10.1 C1), so a drain scene names its tenant."""
    from defender.learning.core.config import LoopPaths

    return LoopPaths.for_tenant(tenant)


def loop_paths(tmp_path: Path) -> Any:
    from defender.learning.core.config import LoopPaths

    return LoopPaths(repo_root=git_repo(Path(tmp_path) / "wt"))


def store_tick_scene(dsn: str, monkeypatch: Any, tenant_id: str) -> None:
    """The learning store the REAL tenant-selected tick reads (#1278): the database named, the tenant recorded active in
    it, a lease of ten minutes with five of grace and a renewer that never fires, the pitfalls lane waking at one item."""
    from defender.tests.support.jobs._jobs1342 import register_tenant
    from defender.tests.support.learning.core import _store1278 as ST

    monkeypatch.setenv(ST.DSN_ENV, dsn)
    for name, value in ((ST.LEASE_ENV, "600"), (ST.GRACE_ENV, "300"), (ST.RENEW_ENV, "600"),
                        ("LEARNING_PITFALLS_THRESHOLD", "1")):
        monkeypatch.setenv(name, value)
    register_tenant(dsn, tenant_id)


def file_request(dsn: str, tenant_id: str, case_id: str, body: dict) -> None:
    """The curation request `body` filed in the store for `tenant_id`, as run end files it."""
    from defender.tests.support.learning.core import _store1278 as ST

    ST.call(dsn, "enqueue_request", tenant_id, str(body["run_id"]), case_id, dict(body))


def file_pitfall(dsn: str, tenant_id: str, row: dict) -> None:
    from defender.tests.support.learning.core import _store1278 as ST

    ST.call(dsn, "add_pitfall", tenant_id, row)


def store_items(dsn: str, tenant_id: str, kind: str) -> dict[str, Any]:
    """The store's work items of `kind` for `tenant_id`, by their coalesce key (a request's case id)."""
    from defender.tests.support.learning.core import _store1278 as ST

    return {i.coalesce_key or i.key: i for i in ST.call(dsn, "work", tenant_id) if i.kind == kind}


def reach_launch_store(dsn: str, monkeypatch: Any) -> None:
    """The learning store a launch's judge pass inserts its findings into (#1278: the judge is handed a store opened at
    `DEFENDER_DATABASE_DSN`, and without one its pass is refused and logged): the database named, the launch fixture's
    tenant recorded active in it."""
    from defender.tests.support.jobs._jobs1342 import register_tenant
    from defender.tests.support.learning.core import _store1278 as ST

    monkeypatch.setenv(ST.DSN_ENV, dsn)
    register_tenant(dsn, LAUNCH_TENANT)
