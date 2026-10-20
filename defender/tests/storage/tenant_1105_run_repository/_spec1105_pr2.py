"""Shared helpers for the PR 2 run-repository tests (tenant fixtures, CLI/process drivers). No test functions."""
from __future__ import annotations

import logging
import io
import json
import os
from collections.abc import Iterable
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H78

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
EPISODES_BASE_ENV = T.EPISODES_BASE_ENV
RUNS_BASE_ENV = T.RUNS_BASE_ENV

#: The launch fixture's tenant (`_spec1224.FIXTURE_TENANT`).
LAUNCH_TENANT = S.FIXTURE_TENANT
#: The source run's id: `_triplet_947.SOURCE_RUN_ID`, a uuid4 (#1187: `RunId` admits canonical
#: lowercase UUID text only).
SOURCE_RUN_ID = T.SOURCE_RUN_ID
BRANCH_MESSAGE_ID = T.BRANCH_MESSAGE_ID
#: The fixture episode id a hand-built sibling scene carries (`_triplet_947.EPISODE_ID`, a uuid4).
#: A LAUNCH mints its own (`runs.create_episode()`, #1187): a launcher test finds the episode it
#: made under `<data root>/<T>/episodes/` (`launched_episodes`), never by this id.
EPISODE_ID = T.EPISODE_ID
#: The sibling fixture's tenant (`_triplet_947.SOURCE_TENANT`).
SIBLING_TENANT = T.SOURCE_TENANT


# ==========================================================================================
# The edges' argument shapes. TODAY's shape (re-pointed here by PR 2), then the declared one.
# ==========================================================================================

def launch_argv(tenant_id: str, source_run_dir: Path,
                branch_message_id: int = BRANCH_MESSAGE_ID, *extra: str) -> list[str]:
    """The launcher's command line for `source_run_dir` of `tenant_id`. TODAY: the source as
    a positional path (`cli.py:1428`), the tenant derived from its runs folder. PR 2 (declared
    change 1): `new_launch_argv(tenant_id, source_run_dir.name, ...)`."""
    return new_launch_argv(tenant_id, Path(source_run_dir).name, branch_message_id, *extra)


def new_launch_argv(tenant_id: str, source_run_id: str,
                    branch_message_id: int = BRANCH_MESSAGE_ID, *extra: str) -> list[str]:
    """Declared change 1: `branch --tenant T <source_run_id> <branch_message_id>`."""
    return ["--tenant", tenant_id, source_run_id, str(branch_message_id),
            *T.retired_continuation_argv(), *extra]


def sibling_argv(tenant_id: str, episode_dir: Path, label: str, *extra: str) -> list[str]:
    """A sibling's `run.py` command line. TODAY: `--resume <episode>/family.yaml --world L
    --tenant T`. PR 2 (declared change 6): `new_sibling_argv(tenant_id, episode_dir.name, L)`."""
    return new_sibling_argv(tenant_id, Path(episode_dir).name, label, *extra)


def new_sibling_argv(tenant_id: str, episode_id: str, label: str, *extra: str) -> list[str]:
    """Declared change 6: `run.py --tenant T --episode <episode_id> --world L`."""
    return ["--tenant", tenant_id, "--episode", episode_id, "--world", label, *extra]


def page_argv(tenant_id: str, episode_dir: Path) -> list[str]:
    """The episode page CLI's argv (`visualize_episode.main` takes no program name). TODAY:
    the episode folder's path. PR 2 (declared change 4): `new_page_argv(tenant_id,
    episode_dir.name)`."""
    return new_page_argv(tenant_id, Path(episode_dir).name)


def new_page_argv(tenant_id: str, episode_id: str) -> list[str]:
    """Declared change 4: `visualize_episode.py --tenant T <episode_id>`."""
    return ["--tenant", tenant_id, episode_id]


def run_page_argv(tenant_id: str, run_dir: Path) -> list[str]:
    """The run page CLI's argv (`visualize_run.main` takes `sys.argv`, program name first).
    TODAY: the run folder's path. PR 2 (declared change 7): `new_run_page_argv(tenant_id,
    run_dir.name)` for a natural run."""
    return new_run_page_argv(tenant_id, Path(run_dir).name)


def new_run_page_argv(tenant_id: str, run_id: str, *, episode_id: str | None = None) -> list[str]:
    """Declared change 7: `visualize_run.py --tenant T [--episode ep] <run_id>`."""
    episode = ["--episode", episode_id] if episode_id is not None else []
    return ["visualize_run.py", "--tenant", tenant_id, *episode, run_id]


# ==========================================================================================
# Roots and scenes.
# ==========================================================================================

def roots(tmp_path: Path, monkeypatch: Any) -> None:
    """Every configured root inside `tmp_path`, as `test_1025_stage_timing`'s launches set them:
    the operator runs base pre-flight exports and the learning state root. #1187 (O9): no
    episodes base — an episode lives under its tenant (`episodes(tenant_id)`)."""
    monkeypatch.setenv(RUNS_BASE_ENV, str(Path(tmp_path) / "defender-runs"))
    _state1135.set_state_dir(monkeypatch, Path(tmp_path) / "learning-state")


def data_root() -> Path:
    return Path(os.environ[DATA_ROOT_ENV])


def episodes(tenant_id: str = LAUNCH_TENANT) -> Path:
    """`<data root>/<tenant_id>/episodes` — where #1187 puts every episode of that tenant."""
    return data_root() / tenant_id / "episodes"


def launched_episodes(tenant_id: str = LAUNCH_TENANT) -> list[Path]:
    """Every episode folder under `episodes(tenant_id)`, sorted — the census a launcher test takes
    to find the episode a launch made (it mints the id) or to show it made none. Entries that
    are not real folders are listed too, so a squatting file is not hidden."""
    folder = episodes(tenant_id)
    return sorted(folder.iterdir()) if folder.is_dir() else []


#: The one answer every captured call recorded and the live estate gives
#: (`test_1025_stage_timing._BASE`), so an oracle serving it unchanged calibrates every world.
BASE_ANSWER = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon",
                         "host": "web-1", "ts": "2026-07-28T15:00:00Z"}]}


def source_calls() -> list:
    return [S.Call("idp", "query", S.query_params("user:alice"), BASE_ANSWER),
            S.Call("edr", "query", S.query_params("host:db-1"), BASE_ANSWER),
            S.Call("siem-x", "lookup", {"entity": "svc-1225"}, BASE_ANSWER)]


def launch_source(tmp_path: Path, *, source_run_id: str = SOURCE_RUN_ID) -> tuple[Any, Path]:
    """`(estate, source run dir)`: the launch fixture tenant placed under the data root and ONE
    finished, branchable source run at `<data root>/<T>/runs/<source_run_id>` whose captured
    calls the live estate answers unchanged — `_spec1224.source_run`, at a run id the test
    names. The calls land through `runs_base(land_calls=...)`, before the source's session is
    seeded (#1255: the fork snapshot holds the table as it stood at the branch point, so a table
    rewritten after `runs_base` returns no longer opens on it and the launch is refused)."""
    est = S.estate(tmp_path)
    est.place(tenant_id=LAUNCH_TENANT)

    def land(src: Path) -> None:
        for seq, c in enumerate(source_calls()):
            T.capture_call(src, system=c.system, verb=c.verb, params=dict(c.params),
                           payload=c.payload, lead=S.LEAD, seq=seq)
            est.answer(c.system, c.verb, c.params, c.payload)

    _base, src = T.runs_base(tmp_path, tenant_id=LAUNCH_TENANT, source_run_id=source_run_id,
                             land_calls=land)
    return est, src


def quiet_judge() -> Any:
    """The judge double, recording every prompt it is handed: every world call answered
    `bucket: none` with nothing filed, the family call with no world finding (#1234: a world
    reply and a family reply are two shapes, and the family word they once shared is retired)."""
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
    from defender.learning.branch import cli

    # The fake sibling materialises each arm at the id the launched episode's roster holds
    # (#1187), the episode named by the child's own argv.
    spawn = spawn if spawn is not None else J.FakeSibling()  # lint-default: ok — a test builder's fresh per-call double, never a shared instance
    judge = judge if judge is not None else quiet_judge()  # lint-default: ok — a test builder's fresh per-call double, never a shared instance
    questioner = seams.pop("questioner", None) or CountingQuestioner()
    seams.setdefault("preflight", S.no_preflight)
    seams.setdefault("live_tree", T.source_capture())
    seams.setdefault("roster", est.roster())
    seams.setdefault("oracle", S.oracle(then=S.submit(BASE_ANSWER, S.EMPTY_CLAIM)).model)
    seams.setdefault("verifier", S.passing_verifier().model)
    rc: int | None = None
    message = ""
    raised: BaseException | None = None
    try:
        rc = cli.main(list(argv), spawn=spawn, judge=judge, questioner=questioner, **seams)
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
    """Grade `episode_dir` afresh for `tenant_id` through the judge's one entry point
    (`learning.judge.grade_episode`). Re-pointed by PR 2 to the declared shape (J3 as settled:
    the judge reads only the episode it is handed, and the world-label collision probe over
    `<T>/runs` is removed): `grade_episode(runs, episode_id)`, `runs` the tenant's repository
    under the configured data root, the episode opened by id under that tenant's
    `<T>/episodes/` (#1187). A final `judge.yaml` short-circuits a second pass, so it is removed
    first."""
    from defender.tenancy import _tenant
    from defender.tests.support.learning.core._state1135 import env_state
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1

    (Path(episode_dir) / "judge.yaml").unlink(missing_ok=True)

    runs = _tenant.accept_tenant(
        data_root(), tenant_id, defender_dir=H1.DEFENDER).runs_repository()
    return T.mod("learning.judge").grade_episode(
        runs, Path(episode_dir).name, judge=J.scripted_judge(), state=env_state())


def sibling_scene(tmp_path: Path, *, roster: bool = True,
                  doc: dict | None = None, episode_id: str = EPISODE_ID) -> tuple[Path, Path]:
    """`(source run dir, episode dir)` for a sibling: the fixture tenant `SIBLING_TENANT` with a
    branchable source run at its natural runs folder (`_triplet_947.runs_base`), and an episode
    at `<data root>/<SIBLING_TENANT>/episodes/<episode_id>` (#1187 Layout A) holding the
    launcher's manifest (`T.family_doc`, naming that source) and a primed `served/base.jsonl`,
    built by the shared `_spec1187.make_episode`.

    `roster`: `True` is the episode as RUNS leaves it — `runs/` made, then the arm roster
    (`arms.json`) naming every manifest world at a fresh uuid4 (R2); `False` is a pre-RUNS
    episode (pre-flight refused or aborted, or the launcher crashed first): no roster and no
    `runs/` — the state a sibling must refuse before anything is spent (O4b)."""
    from defender import _yaml
    from defender.tests.storage.ids_1187 import _spec1187 as R

    _base, src = T.runs_base(tmp_path, source_run_id=SOURCE_RUN_ID)
    doc = doc if doc is not None else family_doc(src)  # lint-default: ok — a test builder's fresh per-call manifest
    labels = [w["label"] for w in doc.get("worlds", [])]
    ep = R.make_episode(data_root(), SIBLING_TENANT, episode_id, manifest=_yaml.safe_dump(doc),
                        labels=labels, roster=False)
    (ep / "served").mkdir(exist_ok=True)
    (ep / "served" / "base.jsonl").write_text("", encoding="utf-8")
    if T.PLANT_RECORDS:
        # The launch's copies of the source alert and its record (#1222 A1), as `T.episode`
        # plants them for the suites that run with the front door's records on.
        T._plant_source_input(ep, str(src), SOURCE_RUN_ID)
    if roster:
        (ep / "runs").mkdir(exist_ok=True)
        R.write_roster(ep, {T.world_id(ep, label): R.new_id() for label in labels})
    return src, ep


def family_doc(src: Path, **over: Any) -> dict:
    """The launcher's manifest for the sibling scene (`_triplet_947.family_doc`), naming the
    source by `source_run_id` (`SOURCE_RUN_ID`) and — today's writer — by `source_run_dir`."""
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

    err = io.StringIO()
    try:
        with redirect_stderr(err):
            rc = run_py.main(list(argv), **{**rec.seams(), **override})
    except SystemExit as refused:
        return None, refused, err.getvalue()
    return rc, None, err.getvalue()


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


def drive_cli(main: Any, argv: list[str]) -> CliResult:
    """Call a CLI's `main(argv)`, capturing stdout and stderr; a `SystemExit` is handed back,
    never raised."""
    out, err = io.StringIO(), io.StringIO()
    rc: int | None = None
    raised: BaseException | None = None
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(list(argv))
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


def plant_record(runs: Path, tenant_id: str) -> Path:
    """`<runs>/_tenant.json` naming `tenant_id`, in the retired writer's own shape — a
    pre-#1187 container record, planted as the OLD ENTRY it now is (R1: nothing writes or
    accepts one; a listing that meets it refuses, naming the one-time command)."""
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H

    return H.plant_tenant_record(Path(runs), tenant_id)


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


def queue_row(paths: Any, case_id: str, body: dict) -> Path:
    """A curation request written by hand at `author-queue/<case_id>.json` — the queue a drain
    claims from (the shape `enqueue_curation` writes: one JSON document per request)."""
    row = Path(paths.state_root) / "author-queue" / f"{case_id}.json"
    row.parent.mkdir(parents=True, exist_ok=True)
    row.write_text(json.dumps(body) + "\n", encoding="utf-8")
    return row


def dead_letter(paths: Any, case_id: str) -> dict | None:
    failed = Path(paths.state_root) / "author-queue" / "failed" / f"{case_id}.json"
    return json.loads(failed.read_text(encoding="utf-8")) if failed.is_file() else None


def still_queued(paths: Any, case_id: str) -> bool:
    q = Path(paths.state_root) / "author-queue"
    return (q / f"{case_id}.json").is_file() or (q / "inflight" / f"{case_id}.json").is_file()


@dataclass
class Lane:
    """The drain's lead-author lane (`run_lead_author`), recording what it was handed. The
    run it serves is read as `getattr(handed, "run_dir", handed)`: today a path, after PR 2 the
    opened `Run` (D-stored) — either way, the folder that run lives in."""

    handed: list[Any] = field(default_factory=list)

    def __call__(self, _paths: Any, _state: Any, run: Any, *, box: Any = None,
                 on_done: Any = None, **_kw: Any) -> None:
        self.handed.append(run)
        if on_done is not None:
            on_done(None)

    @property
    def run_dirs(self) -> list[Path]:
        return [Path(getattr(h, "run_dir", h)) for h in self.handed]


def drain(paths: Any, lane: Lane) -> list[Any]:
    """One lead-author tick's claim loop (`_drain_lead_author_markers`) over `paths`, under
    the data root the tick resolves before it claims (`drains._data_root`: with none
    configured, the tick's configuration refusal, raised before any claim)."""
    from defender.learning.core import drains

    state = _state1135.state_for_paths(paths)
    return drains._drain_lead_author_markers(paths, state, lane, data_root=drains._data_root())


def loop_paths(tmp_path: Path) -> Any:
    from defender.learning.core.config import LoopPaths

    return LoopPaths(repo_root=git_repo(Path(tmp_path) / "wt"), state_dir=Path(tmp_path) / "state")


def ids(values: Iterable[Any]) -> list[str]:
    return [str(v) for v in values]



__all__ = ["H78"]
