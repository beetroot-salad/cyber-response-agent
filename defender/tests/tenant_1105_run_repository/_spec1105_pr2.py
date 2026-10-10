"""Shared machinery for #1105 PR 2's tests-before-code commit. NO test functions.

PR 2 (design rev 5.1, #1105 comments 6099907018 / 6099907229 / 6099907462, amended by the
owner's fork decisions 6100061869) is a pure refactor: every production site that reaches run or
episode records by path moves behind a tenant-scoped run repository (`tenant.runs_repository()`),
and every edge takes ids. The existing suite is the contract for unchanged behaviour; the three
files beside this one cover what it leaves:

* `test_1105_pr2_guards.py` — guard-table rows (G1–G25) no existing test pins through an
  observable that survives the move. GREEN at base `301f196c`.
* `test_1105_pr2_declared_changes.py` — the declared changes. RED at base, each for its own
  stated reason.
* `test_1105_pr2_repository.py` — the new surface (decision C). RED at base: the names do not
  exist yet, and every test asserts behaviour once they do.

THE BUILDERS BELOW ARE TODAY'S CALL SHAPE, AND THE ONE PLACE PR 2 CHANGES IT. A guard test (and a
declared-change test whose reason is NOT an argument change) drives the real entry point
through `launch_argv` / `sibling_argv` / `page_argv` / `run_page_argv`, so it is green or red at
base for its behavioural reason alone, never for an argparse one. When PR 2 lands its edges
(declared changes 1, 4, 6 and 7), the implementer re-points each builder HERE to the declared
shape — `new_launch_argv` and its siblings below spell it, from the design's own text — and
never edits the tests that call them. The `new_*` builders are used directly only by the tests
whose declared change IS the edge's argument shape.

Every fault is a real input through the real primitive (links, files, records naming another
tenant, a truncated manifest), planted on the real filesystem. Fakes enter only through the
entry points' own seams (`spawn=`, `judge=`, `questioner=`, `preflight=`, `materialize=`,
`lifecycle=`, the drain's `run_lead_author` argument), never `monkeypatch.setattr`.

Underscore-prefixed so pytest does not collect it.
"""
from __future__ import annotations

import io
import json
import os
from collections.abc import Iterable
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender.tests import _judge_921 as J
from defender.tests import _state1135
from defender.tests import _triplet_947 as T
from defender.tests.live_oracle_1224 import _spec1224 as S
from defender.tests.tenant_1078_pass_a import _spec1078 as H78

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
EPISODES_BASE_ENV = T.EPISODES_BASE_ENV
RUNS_BASE_ENV = T.RUNS_BASE_ENV

#: The launch fixture's tenant (`_spec1224.FIXTURE_TENANT`).
LAUNCH_TENANT = S.FIXTURE_TENANT
#: The source run's id. NOT `_triplet_947.SOURCE_RUN_ID` (`20260728T161845Z-fresh-case`): that
#: spelling is not case-stable, so `RunId.parse` refuses it, and once the launcher and the
#: sibling take ids (declared changes 1 and 6) a source under it can no longer be named at all.
#: A minted run id is case-folded; this is that id, folded. The derived episode id is unchanged
#: (`episode_id_for` folds it either way).
SOURCE_RUN_ID = T.SOURCE_RUN_ID.casefold()
BRANCH_MESSAGE_ID = T.BRANCH_MESSAGE_ID
#: The episode id the launcher derives for that source and branch point.
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
            "--continuation-prompt", "go", *extra]


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

def roots(tmp_path: Path, monkeypatch: Any) -> Path:
    """Every configured root inside `tmp_path`, as `test_1025_stage_timing`'s launches set them:
    the episodes base (outside the data root and the checkout), the operator runs base pre-flight
    exports, and the learning state root. Returns the episodes base."""
    episodes = Path(tmp_path) / "episodes-root"
    monkeypatch.setenv(RUNS_BASE_ENV, str(Path(tmp_path) / "defender-runs"))
    monkeypatch.setenv(EPISODES_BASE_ENV, str(episodes))
    _state1135.set_state_dir(monkeypatch, Path(tmp_path) / "learning-state")
    return episodes


def data_root() -> Path:
    return Path(os.environ[DATA_ROOT_ENV])


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
    names."""
    est = S.estate(tmp_path)
    est.place(tenant_id=LAUNCH_TENANT)
    _base, src = T.runs_base(tmp_path, tenant_id=LAUNCH_TENANT, source_run_id=source_run_id)
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    for seq, c in enumerate(source_calls()):
        T.capture_call(src, system=c.system, verb=c.verb, params=dict(c.params),
                       payload=c.payload, lead=S.LEAD, seq=seq)
        est.answer(c.system, c.verb, c.params, c.payload)
    return est, src


def survived_judge() -> Any:
    """The judge double: one reply valid in both scopes, recording every prompt it is handed."""
    return J.FakeJudge(default=J.as_reply_text(J.reply_doc(
        findings=[], bucket="none", systems=[], verdict_word="survived")))


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

    # The episode the fake sibling materialises arms in (never reached when the launch refuses
    # first — the episodes base may be unset on purpose).
    episode_dir = Path(os.environ.get(EPISODES_BASE_ENV, "/nonexistent-episodes")) / EPISODE_ID
    spawn = spawn if spawn is not None else J.FakeSibling(episode_dir)  # lint-default: ok — a test builder's fresh per-call double, never a shared instance
    judge = judge if judge is not None else survived_judge()  # lint-default: ok — a test builder's fresh per-call double, never a shared instance
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
    return Launched(rc, message, raised, spawn, judge, questioner)


def grade(episode_dir: Path, tenant_id: str) -> Any:
    """Grade `episode_dir` afresh for `tenant_id` through the judge's one entry point
    (`learning.judge.grade_episode`). Re-pointed by PR 2 to the declared shape (J3 as settled:
    the judge reads only the episode it is handed, and the world-label collision probe over
    `<T>/runs` is removed): `grade_episode(runs, episode_id)`, `runs` the tenant's repository
    under the configured data root, the episode opened by id under the configured episodes
    base. A final `judge.yaml` short-circuits a second pass, so it is removed first."""
    from defender import _tenant
    from defender.tests._state1135 import env_state
    from defender.tests.tenant_1105_run_repository import _spec1105 as H1

    (Path(episode_dir) / "judge.yaml").unlink(missing_ok=True)

    runs = _tenant.accept_tenant(
        data_root(), tenant_id, defender_dir=H1.DEFENDER).runs_repository()
    return T.mod("learning.judge").grade_episode(
        runs, Path(episode_dir).name, judge=J.scripted_judge(), state=env_state())


def sibling_scene(tmp_path: Path, *, container: str | None = None,
                  doc: dict | None = None, episode_id: str = EPISODE_ID) -> tuple[Path, Path]:
    """`(source run dir, episode dir)` for a sibling: the fixture tenant `SIBLING_TENANT` with a
    branchable source run at its natural runs folder (`_triplet_947.runs_base`), and an episode
    under the configured episodes base holding the launcher's manifest (`T.family_doc`, whose
    `source_run_dir` today names that source).

    `container`: `None` leaves `<episode>/runs` absent (a pre-RUNS episode); a tenant id makes
    it with a `_tenant.json` naming that tenant, through the real writer
    (`ensure_runs_base_record`), as the launcher's `start_family` does before the first arm."""
    from defender import _tenant

    _base, src = T.runs_base(tmp_path, source_run_id=SOURCE_RUN_ID)
    episodes = Path(os.environ[EPISODES_BASE_ENV])
    ep = T.episode(tmp_path, doc=doc if doc is not None else family_doc(src), root=episodes,
                   episode_id=episode_id)
    if container is not None:
        (ep / "runs").mkdir(exist_ok=True)
        _tenant.ensure_runs_base_record(ep / "runs", container)
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
        rd = self.lifecycle_kwargs.get("run_dir")
        return Path(rd) if rd is not None else None


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
    from defender.scripts.visualize import visualize_episode

    return visualize_episode.main


def run_page_main() -> Any:
    from defender.scripts.visualize import visualize_run

    return visualize_run.main


def plant_record(runs: Path, tenant_id: str) -> Path:
    """`<runs>/_tenant.json` naming `tenant_id`, through the real writer."""
    from defender import _tenant

    Path(runs).mkdir(parents=True, exist_ok=True)
    _tenant.ensure_runs_base_record(Path(runs), tenant_id)
    return Path(runs) / "_tenant.json"


def second_tenant(root: Path, tenant_id: str) -> Any:
    """A further real tenant under `root` (a hand-made row over the committed fixture's
    knowledge — `create_tenant` admits one per root), accepted by the real `accept_tenant`."""
    from defender.tests.tenant_1105_run_repository import _spec1105 as H

    return H.tenant(root, tenant_id)


def tree(root: Path) -> dict[str, tuple[str, bytes | str | None]]:
    from defender.tests.tenant_1105_run_repository import _spec1105 as H

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
    """One lead-author tick's claim loop (`_drain_lead_author_markers`) over `paths`."""
    from defender.learning.core import drains

    state = _state1135.state_for_paths(paths)
    return drains._drain_lead_author_markers(paths, state, lane)


def loop_paths(tmp_path: Path) -> Any:
    from defender.learning.core.config import LoopPaths

    return LoopPaths(repo_root=git_repo(Path(tmp_path) / "wt"), state_dir=Path(tmp_path) / "state")


def ids(values: Iterable[Any]) -> list[str]:
    return [str(v) for v in values]


def namespace(**kw: Any) -> SimpleNamespace:
    return SimpleNamespace(**kw)


__all__ = ["H78"]
