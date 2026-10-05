"""#1178/#1195: the lead-author drain lane starts its one box for each agent run and stops it
after, and its gate admits only plain files, judged by a no-follow stat.

The design (`gh issue view 1195`, "Design amendment 3 (2026-10-06): the stop fault wins, the box
carries its docker, and lanes get a run handle", refining amendment 2) replaces #1178 amendment
2's freeze (`pause_box`, `thawed`, `LeadAuthorDeps.thaw`, `run_pitfalls(thaw=)`). The drain
creates and checks the batch's box at batch start, as on main, wraps it in a `runtime.box.BoxRuns`
handle and stops it at once (`_run_worktree_batch`: `runs.stop()` first in the try whose
`finally` removes the box), and hands the lanes the handle. Each spawn site runs its spawn
inside `runtime.box.box_for_run(handle)`, handing the spawn the executor it yields:

- the claim spawn, `lead_author._run_locked`: `with _box.box_for_run(box) as run_box: rc =
  deps.invoke_agent(..., box=run_box)`;
- the pitfalls spawn, `pitfalls_curator.run_pitfalls`: the same around its `invoke`.

The box is a sandboxed executor carrying a fake daemon (`_box1195.FakeDaemon`) as its docker;
every start, stop and removal reaches the daemon through the executor, and a `Tripwire` is the
`docker` on `PATH` (one production row runs the default docker, the daemon installed there).
The lane's host steps log into a `_box1195.Journal`, which marks each into the daemon's call
log and notes what was running at that moment. A run window is a `docker start` to the next
`docker stop`. Groups, each driven through a seam, never `monkeypatch.setattr`:

- The lanes (O2'', E5', O6): one window per agent, holding the spawn alone, the spawn handed
  the batch's executor (never the handle the lane was handed); the host's steps before the
  agent and every read the gate makes after it (the lane's `tree_for`, logged) saw nothing
  running; whatever the box writes during its run is what the gate judges (O1). A run whose
  start fails (refused, not taking, or a box not `exited` beforehand: E3'), or whose stop fails
  after a clean agent (refused, without effect, unproven, the seam raising), runs no gate and
  commits nothing (O4). The baseline of strays and the minted drafts' identities are taken
  before the run starts.
- The drain (O2'', O4, O5, E3'): `_drain_lead_author(..., box=<the handle>)` hands each lane
  the handle and runs one window per agent and none between; a claim's run start or stop fault
  halts the lane rather than dead-lettering the claim; a pitfalls run's box fault halts it and
  bumps no pitfalls row; a stop fault under a failing agent or curator wins (F1): it escapes at
  once with the failure as its context, dead-letters no claim and bumps no row, whether a later
  run follows or none does; a stop fault some layer swallows makes the pitfalls tick's run
  refuse (E3'); so does a run start fault through the DEFAULT claim step and the DEFAULT
  pitfalls step, and the batch box's docker calls there are exactly `X.REFUSED_FIRST_RUN` (no
  call outside a run). Through the production `lead_author_drain` (only `start_box=` bringing
  the docker): one create at batch start and its stop before the first claim; the F1 rows; a
  claim's stop fault after a clean agent escapes; nothing is committed or delivered; the
  batch-end `rm -f` removes the box before the scan. A fault creating or checking the box at
  batch start claims no claim, bumps no attempt and dead-letters nothing.
- The plain-file rule (#1178 D4'', which stands, unchanged): every non-deletion record the gate
  admits must be placed by a held mount and be a plain, single-name regular file there, by a
  no-follow stat (it reads no content). A symlink, a hard link or a FIFO at an address no
  content rule reads (a catalog draft, a system-skill draft, `queries/<sys>/README.md`, each
  also one folder deeper; the pitfalls lane's `execution.md`) is refused with HEAD unchanged; a
  plain file commits, an executable one at 100755, and so does a plain file that is not UTF-8
  or is larger than any read takes. A `tree_for` that places no path refuses rather than
  falling back on the plain path.

`BoxRuns`/`box_for_run` themselves are in `test_1195_box_for_run.py`; the batch's start,
post-create stop and removal in `test_1195_worktree_batch.py`; the real-box row in
`test_1195_run_box_live.py`; the lessons lane in `test_1195_lessons_run_windows.py`.
"""
from __future__ import annotations

import dataclasses
import os
import subprocess
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender._io import READ_LIMIT
from defender._run_paths import RunPaths
from defender.learning.core import drains, markers, persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.author.shared import AuthorError
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime import box as box_mod
from defender.runtime.box import BoxFault
from defender.tests import _box1195 as X
from defender.tests._claim1175 import claim_git
from defender.tests._declared869 import LeadAuthorSpawn, Spawn, pitfall_row
from defender.tests._declared870 import (
    REDUCER_REL,
    commit_all,
    reducer_surface_text,
    seed_tree,
    shim_row,
    write_reducer_surface,
)
from defender.tests._lead_author_1134 import clear, lane_tree_for, lead_trees, write
from defender.tests._repo import query_template, seed_skills_repo
from defender.tests.e2e.test_922_spine import RepoBranch
from defender.tests.test_1134_lead_author_handle import (
    ELASTIC_LEAD,
    NO_MODEL,
    WAZUH_LEAD,
    _deps,
    _run_dir,
    _worktree,
    draft_of,
)

LEAD = LEAD_AUTHOR_DRAIN_LABEL

#: The container the direct drives' box names (the drain's is `defender-drain-<batch id>`).
NAME = "defender-drain-g1178"


def _outcome(fn: Callable[[], Any]) -> tuple:
    """`("returned", value)`, or `("raised", class name, message)` for the gate's refusal and the
    box's fault. Anything else (a call-shape `TypeError`, a `ValidationError`) propagates."""
    try:
        return ("returned", fn())
    except (LeadAuthorError, BoxFault) as e:
        return ("raised", type(e).__name__, str(e))


def _head_mode(repo: Path, rel: str) -> str:
    """The git mode `rel` is committed with at HEAD (`100644`, `100755`, `120000` a link)."""
    # The code under test runs no `ls-tree`; this reads HEAD as a git user would.
    return _git.git(["ls-tree", "HEAD", "--", rel], cwd=repo).split(" ", 1)[0]  # lint-oracle: ok — not the code under test's query


def _head_bytes(repo: Path, rel: str) -> bytes:
    """The blob committed at `rel` in HEAD, as bytes (no decoding: the subject may not be text).
    The observed value; the expected one is the bytes the test planted."""
    argv = ["git", "cat-file", "blob", f"HEAD:{rel}"]  # lint-oracle: ok — reads what was committed; the oracle is the planted bytes
    return subprocess.run(argv, cwd=repo, capture_output=True, check=True).stdout  # noqa: S603


def _nothing_staged(repo: Path) -> bool:
    """The index equals HEAD: no refusal or fault left a half-made commit staged."""
    return _git.git(["diff", "--cached", "--name-only", "-z"], cwd=repo) == ""


# ---------------------------------------------------------------------------------------
# The fakes the lane rows inject
# ---------------------------------------------------------------------------------------


class BoxSeenLeadSpawn(LeadAuthorSpawn):
    """`LeadAuthorSpawn`, also recording the `box` each call was handed."""

    def __init__(self, edit: Any = None, *, rc: int = 0) -> None:
        super().__init__(edit, rc=rc)
        self.boxes: list[Any] = []

    def __call__(self, run_dir, handoffs, pending_drafts=None, *, box=None, **kwargs):  # type: ignore[override]
        self.boxes.append(box)
        return super().__call__(run_dir, handoffs, pending_drafts, box=box, **kwargs)


class BoxSeenSpawn(Spawn):
    """The pitfalls `Spawn`, also recording the `box` each call was handed."""

    def __init__(self, edit: Any = None, *, rc: int = 0) -> None:
        super().__init__(edit, rc=rc)
        self.boxes: list[Any] = []

    def __call__(self, handoffs, *args, repo_root: Path | None = None, box=None, **kwargs):
        self.boxes.append(box)
        return super().__call__(handoffs, *args, repo_root=repo_root, box=box, **kwargs)


def _logging_tree_for(tree_for: Callable[..., Any], log: list) -> Callable[..., Any]:
    """The lane's real `tree_for`, logging each path asked of it: the gate's reads."""

    def logged(path):
        log.append(("read", str(path)))
        return tree_for(path)

    return logged


def _logged(name: str, fn: Callable[..., Any], log: list) -> Callable[..., Any]:
    """A host seam of the lane, logging `("host", name)` each time it is called."""

    def call(*args, **kwargs):
        log.append(("host", name))
        return fn(*args, **kwargs)

    return call


def _journaled_deps(deps: Any, log: list) -> Any:
    """`deps` with the gate's reads (`tree_for`) and the host's pre-agent steps (`extract`,
    `discover_system_drafts`, `build_handoff`) logging into `log`."""
    return dataclasses.replace(
        deps, tree_for=_logging_tree_for(deps.tree_for, log),
        extract=_logged("extract", deps.extract, log),
        discover_system_drafts=_logged("discover_system_drafts", deps.discover_system_drafts, log),
        build_handoff=_logged("build_handoff", deps.build_handoff, log),
    )


class LoggedTrees:
    """The pitfalls lane's open trees, delegating `mount`/`mounts`/`tree_for`: a `mount` call
    (the lane's first host step) is logged as `("host", "mount")`, each `tree_for` call (the
    commit gate's reads) as `("read", path)`."""

    def __init__(self, trees: Any, log: list) -> None:
        self._trees = trees
        self._log = log

    @property
    def mounts(self):
        return self._trees.mounts

    def mount(self, path):
        self._log.append(("host", "mount"))
        return self._trees.mount(path)

    def tree_for(self, path):
        self._log.append(("read", str(path)))
        return self._trees.tree_for(path)


def _assert_one_run_holds_exactly_the_agent(  # noqa: PLR0913 — one run's whole record
    log: X.Journal, daemon: X.FakeDaemon, spawn: Any, box: Any, *, head_before: str,
    head_after: str,
) -> None:
    """One window, holding the agent and nothing else, the agent handed the batch's executor
    (`box`), never the handle the lane was handed; every host step before it, and every gate
    read after it, saw nothing running; the commit (after the gate) landed; the box is
    stopped."""
    log.assert_runs_hold_exactly(["agent"], ("agent",))
    kinds = [e[0] for e in log]
    at = kinds.index("agent")
    assert "host" in kinds[:at], f"no host step was seen before the run (vacuous): {kinds}"
    assert "read" in kinds[at + 1:], f"the gate read nothing after the run: {kinds}"
    assert head_after != head_before, "nothing was committed, so 'committed with no box up' is vacuous"
    assert len(spawn.boxes) == 1, spawn.boxes
    assert spawn.boxes[0] is box, "the agent was not handed the batch's executor"
    assert daemon.status(NAME) == "exited", "the agent's box was left running"


# ---------------------------------------------------------------------------------------
# The lead-author lane's drive: `run(label=, deps=)`, the agent leaving one file
# ---------------------------------------------------------------------------------------

#: The agent's file in the wiring rows: a catalog draft whose `id:` the gate reads (the path
#: rule's directory check), so the gate's verdict depends on the bytes it read.
AGENT_NAME = "gather/queries/wazuh/_draft/w1178.md"
VETTED = query_template("wazuh.w1178", "draft")
#: Valid too, but different bytes: what the box leaves on its run's way out, still up.
VARIANT = VETTED.replace("wazuh auth events.", "wazuh auth events, rewritten in its run.")
#: Refused: its id names another system ("disagreeing with its directory").
REFUSED = query_template("elastic.w1178", "draft")
REFUSED_SAYS = "disagreeing with its directory"


@dataclasses.dataclass
class LeadScene:
    tmp: Path
    repo: Path
    paths: LoopPaths
    run_dir: Path
    head: str

    def at(self, name: str) -> Path:
        return self.paths.skills_dir / name

    def rel(self, name: str) -> str:
        return f"defender/skills/{name}"


def _lead_scene(tmp_path: Path, committed: dict[str, str] | None = None) -> LeadScene:
    """The lead worktree, with `committed` (`{name below skills/: text}`) also committed."""
    repo = _worktree(tmp_path)
    if committed:
        for name, text in committed.items():
            write(repo / "defender" / "skills" / name, text)
        commit_all(repo, "seed the names the agent rewrites")
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    return LeadScene(tmp=tmp_path, repo=repo, paths=paths, run_dir=_run_dir(tmp_path),
                     head=_git.git_head_sha(repo))


def _clear(at: Path) -> None:
    """Whatever stands at `at` removed, a FIFO included (`clear` handles files, links, dirs)."""
    if os.path.lexists(at) and not at.is_symlink() and not at.is_dir() and not at.is_file():
        at.unlink()
    clear(at)


def _plant(at: Path, text: str | bytes, kind: str, outside: Path) -> None:
    """`text` at `at` as a plain file (`plain`; bytes are written as they are), an executable
    plain file (`exec`, 0755), a symlink to a file outside the repo holding it (`link`) or a
    hard link to one (`hardlink`); a FIFO at `at` (`fifo`, `text` unused); or a sparse plain
    file of `BIG_SIZE` bytes that starts with `text` (`big`): larger than any read takes."""
    _clear(at)
    if kind == "big":
        at.parent.mkdir(parents=True, exist_ok=True)
        at.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        os.truncate(at, BIG_SIZE)
        return
    if kind in ("plain", "exec"):
        if isinstance(text, bytes):
            at.parent.mkdir(parents=True, exist_ok=True)
            at.write_bytes(text)
        else:
            write(at, text)
        if kind == "exec":
            at.chmod(0o755)
        return
    at.parent.mkdir(parents=True, exist_ok=True)
    if kind == "fifo":
        os.mkfifo(at)
        return
    assert isinstance(text, str), kind
    target = write(outside / f"{kind}-{at.parent.name}-{at.name}", text)
    if kind == "link":
        at.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, at)
    else:
        raise ValueError(kind)


def _drive_lead(  # noqa: PLR0913 — one drive, every seam a row varies
        s: LeadScene, log: list, *, name: str, text: str | bytes, kind: str = "plain",
        box: Any = None, more: dict[str, str] | None = None,
) -> tuple[tuple, BoxSeenLeadSpawn]:
    """Drive `lead_author.run` over the scene: the agent (rc 0) leaves `text` at `name` as
    `kind`, and each of `more` (`{name: text}`) as a plain file, logging `("agent",)`. The
    lane's `tree_for` and its pre-agent host seams log into `log` (`_journaled_deps`). `box` is
    handed to `run` (the batch's stopped box, or `None`); the spawn records the box it was
    handed. Returns the outcome and the spawn."""

    def leave(_run_dir: Path) -> None:
        _plant(s.at(name), text, kind, s.tmp / "outside")
        for other, other_text in (more or {}).items():
            _plant(s.at(other), other_text, "plain", s.tmp / "outside")
        log.append(("agent",))

    spawn = BoxSeenLeadSpawn(leave)
    with lead_trees(s.paths) as trees:
        deps = _journaled_deps(_deps(s.paths, trees, spawn, [ELASTIC_LEAD]), log)
        got = _outcome(lambda: lead_author.run(
            s.run_dir, label=LEAD, paths=s.paths, deps=deps, box=box))
    return got, spawn


def _run_lead(s: LeadScene, log: list, **kw: Any) -> tuple:
    """`_drive_lead`, for a drive whose agent is reached: the outcome."""
    got, spawn = _drive_lead(s, log, **kw)
    assert spawn.calls, f"the agent was never reached, so the gate never ran: {got}"
    return got


def test_the_lead_author_runs_its_agent_in_a_run_window_of_its_own(tmp_path: Path, monkeypatch):
    """`run(deps=..., box=<the batch's stopped box>)`: the agent leaves a valid draft. One run
    window starts the box after the host's pre-agent steps, holds the agent alone (handed that
    same box, and seeing it running), and stops it before the gate's first read and the commit.
    HEAD holds the draft; the box is stopped."""
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    log = X.Journal(daemon)
    got, spawn = _drive_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs)
    assert got == ("returned", 0), got
    head = _git.git_head_sha(s.repo)
    _assert_one_run_holds_exactly_the_agent(log, daemon, spawn, box, head_before=s.head,
                                            head_after=head)
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED


@pytest.mark.parametrize("at_stop", ["refused", "variant"])
def test_the_lead_author_gate_judges_what_the_box_wrote_during_its_run(
        tmp_path: Path, monkeypatch, at_stop: str):
    """The box rewrites the agent's file on its run's way out, while still up: with refused
    bytes the gate refuses (`LeadAuthorError`, HEAD unchanged, nothing staged); with valid
    different bytes (the control) those bytes are what HEAD holds. The gate runs after the stop,
    so it sees everything the box did during its run."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    bytes_out = REFUSED if at_stop == "refused" else VARIANT
    daemon.on_stop(s.at(AGENT_NAME), bytes_out, at=1)
    got = _run_lead(s, [], name=AGENT_NAME, text=VETTED, box=runs)
    if at_stop == "variant":
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VARIANT
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert REFUSED_SAYS in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "the refused bytes were committed"
    assert _nothing_staged(s.repo)


#: Paths the box first writes on its run's way out: never the agent's, so only a gate that lists
#: the batch after the run sees them. `None`: admitted and committed.
LEAD_RUN_WRITES = [
    pytest.param("gather/queries/wazuh/_draft/new1178.md", query_template("elastic.new1178", "draft"),
                 REFUSED_SAYS, id="new-md-refused"),
    pytest.param("gather/queries/wazuh/evil1178.txt", "not markdown\n", "outside", id="new-non-md"),
    pytest.param("gather/queries/wazuh/_draft/new1178.md", query_template("wazuh.new1178", "draft"),
                 None, id="new-md-admissible"),
]


@pytest.mark.parametrize(("name", "text", "says"), LEAD_RUN_WRITES)
def test_a_lead_author_path_the_box_wrote_during_its_run_is_judged(
        tmp_path: Path, monkeypatch, name: str, text: str, says: str | None):
    """The box writes a NEW path beside the agent's vetted draft on its run's way out: a draft
    whose id disagrees with its folder, or a non-`.md` file under `skills/`, is refused (HEAD
    unchanged, nothing staged); an admissible new draft (the control) is judged and committed
    with the rest."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    daemon.on_stop(s.at(name), text, at=1)
    got = _run_lead(s, [], name=AGENT_NAME, text=VETTED, box=runs)
    if says is None:
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", s.rel(name)) == text
        assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert says in got[2], got
    assert s.rel(name) in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "a path written during the run was committed"
    assert _nothing_staged(s.repo)


#: A run whose start fails: `docker start` refused, a start that answers 0 and leaves the box
#: stopped, or (E3') the box found running before the start, as a stop some layer swallowed
#: leaves it (a start on a running box answers 0, so only the check before it can tell).
START_FAULTS = ["refused", "takes-no-effect", "left-running"]


def _start_fault(daemon: X.FakeDaemon, fault: str, *, nth: int = 1) -> None:
    if fault == "refused":
        daemon.refuse_start(at=[nth])
    elif fault == "takes-no-effect":
        daemon.start_takes_no_effect(at=[nth])
    else:
        daemon.hold(NAME, "running")


@pytest.mark.parametrize("fault", START_FAULTS)
def test_a_lead_author_start_fault_runs_no_agent_and_commits_nothing(
        tmp_path: Path, monkeypatch, fault: str):
    """The run's start fails: `run` raises `BoxFault`; the agent never ran, the gate read
    nothing, HEAD is unchanged, nothing is staged, the run is not recorded done, and the box is
    stopped again. A box found running gets no `docker start` at all. Control:
    `test_the_lead_author_runs_its_agent_in_a_run_window_of_its_own` (a start that holds)."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _start_fault(daemon, fault)
    s = _lead_scene(tmp_path)
    log: list = []
    got, spawn = _drive_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs)
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the agent ran though its box never started"
    assert [e for e in log if e[0] == "read"] == [], "the gate ran though the box never started"
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)
    assert not (RunPaths(s.run_dir).lead_author / "done").exists()
    assert daemon.status(NAME) == "exited", "the refused run left its box running"
    if fault == "left-running":
        assert "start" not in daemon.steps(), "a box found running was started over"


#: A run's stop that fails after a clean agent, with nothing in flight (`X.STOP_FAULTS`: refused,
#: answering 0 with the box still running, its proof unanswered, the seam raising). `holds` is
#: the control.
STOP_FAULTS = [*X.STOP_FAULTS, "holds"]


def _stop_fault(daemon: X.FakeDaemon, stop: str) -> None:
    """The first run's stop fails as `stop` says: the direct drives' box is held `exited`, so
    its run asks the status before its start (1), after it (2) and after its stop (3)."""
    if stop != "holds":
        X.fail_stop(daemon, stop, at=1, inspect_at=3)


def _reads_after_the_agent(log: list) -> list[tuple]:
    kinds = [e[0] for e in log]
    return [e for e in log[kinds.index("agent") + 1:] if e[0] == "read"]


@pytest.mark.parametrize("stop", STOP_FAULTS)
def test_a_lead_author_stop_fault_after_a_clean_agent_halts_before_the_gate(
        tmp_path: Path, monkeypatch, stop: str):
    """The agent leaves a valid draft and returns 0; then its run's stop fails (nothing in
    flight; refused, without effect, unproven, the seam raising). `run` raises `BoxFault`, never
    the seam's own exception: the gate read nothing after the agent, HEAD is unchanged,
    nothing is staged, and the run is not recorded done. Control (`holds`): the same agent, the
    stop taking: the gate reads after the run and the draft is committed."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _stop_fault(daemon, stop)
    s = _lead_scene(tmp_path)
    log: list = []
    got, spawn = _drive_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs)
    assert len(spawn.calls) == 1, f"the agent was never reached: {got}"
    if stop == "holds":
        assert got == ("returned", 0), got
        assert _reads_after_the_agent(log), "the gate read nothing after the run (vacuous control)"
        assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
        return
    assert got[:2] == ("raised", "BoxFault"), got
    assert _reads_after_the_agent(log) == [], "the gate judged beside a box that would not stop"
    assert _git.git_head_sha(s.repo) == s.head, "a commit landed beside a box that would not stop"
    assert _nothing_staged(s.repo)
    assert not (RunPaths(s.run_dir).lead_author / "done").exists()


# ---------------------------------------------------------------------------------------
# The pitfalls lane's drive: `run_pitfalls(trees=, invoke=)`
# ---------------------------------------------------------------------------------------

#: The curator's edit in the wiring rows: one pitfall under the reducer's `## Common pitfalls`,
#: a document the content rule reads and accepts (`_readable_pair` reads it through `tree_for`).
REDUCER_VETTED = reducer_surface_text(bullets=("keep the unnest argument a LIST",))
REDUCER_VARIANT = reducer_surface_text(bullets=("a different pitfall, written in its run",))
#: Refused: the frontmatter block is rewritten.
REDUCER_REFUSED = REDUCER_VETTED.replace("name: defender-gather-sql", "name: rewritten-1178")
REDUCER_REFUSED_SAYS = "frontmatter block"

#: The system surface the pitfalls lane commits, with no content rule of its own.
EXECUTION_NAME = "elastic/execution.md"
EXECUTION_REL = f"defender/skills/{EXECUTION_NAME}"
EXECUTION_TEXT = "# execution\n\n## Common pitfalls\n\n- use the key, not the id\n"


@dataclasses.dataclass
class PitfallsScene:
    tmp: Path
    repo: Path
    paths: LoopPaths
    head: str

    def at(self, rel: str) -> Path:
        return self.repo / rel


def _pitfalls_scene(tmp_path: Path, monkeypatch, rows: list[dict]) -> PitfallsScene:
    """A committed tree carrying the reducer surface and `elastic/execution.md` (an `elastic`
    adapter and marker), with `rows` queued and the threshold at 1, so the tick offers what the
    rows name."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    repo = seed_tree(tmp_path, adapters=("elastic", "cmdb"), markers=("elastic",),
                     skills=("elastic",), catalog=(), non_systems=("gather",))
    write_reducer_surface(repo)
    commit_all(repo, "seed the reducer surface")
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    persist.append_pitfalls(rows, paths=paths)
    return PitfallsScene(tmp=tmp_path, repo=repo, paths=paths, head=_git.git_head_sha(repo))


def _reducer_rows() -> list[dict]:
    return [shim_row(f"r:l-003:{i}") for i in range(3)]


def _system_rows() -> list[dict]:
    return [pitfall_row(f"p-1178-{i}", "elastic") for i in range(3)]


def _queued(s: PitfallsScene) -> list[str]:
    return sorted(r["pitfall_id"] for r in persist.read_pitfalls(s.paths))


def _drive_pitfalls(  # noqa: PLR0913 — one drive, every seam a row varies
        s: PitfallsScene, log: list, *, rel: str, text: str | bytes, kind: str = "plain",
        box: Any = None, more: dict[str, str] | None = None,
) -> tuple[tuple, BoxSeenSpawn]:
    """Drive `run_pitfalls` over the scene: the curator (rc 0) leaves `text` at `rel` as `kind`,
    and each of `more` (`{rel: text}`) as a plain file, logging `("agent",)`. The trees log the
    lane's first host step and each `tree_for` call into `log`. `box` is handed to `run_pitfalls`
    (the batch's stopped box, or `None`); the spawn records the box it was handed. Returns the
    outcome and the spawn."""

    def curate(_root: Path) -> None:
        _plant(s.at(rel), text, kind, s.tmp / "outside")
        for other, other_text in (more or {}).items():
            _plant(s.at(other), other_text, "plain", s.tmp / "outside")
        log.append(("agent",))

    spawn = BoxSeenSpawn(curate)
    with lead_trees(s.paths) as trees:
        got = _outcome(lambda: pitfalls_curator.run_pitfalls(
            paths=s.paths, trees=LoggedTrees(trees, log), invoke=spawn, box=box))
    return got, spawn


def _run_pitfalls(s: PitfallsScene, log: list, **kw: Any) -> tuple:
    """`_drive_pitfalls`, for a drive whose curator is reached: the outcome."""
    got, spawn = _drive_pitfalls(s, log, **kw)
    assert spawn.calls, f"the curator was never reached, so the gate never ran: {got}"
    return got


def test_the_pitfalls_tick_runs_its_curator_in_a_run_window_of_its_own(
        tmp_path: Path, monkeypatch):
    """`run_pitfalls(box=<the batch's stopped box>)`: the curator appends a pitfall to the
    reducer surface. One run window starts the box after the tick's first host step, holds the
    curator alone (handed that same box), and stops it before the gate's first read and the
    commit."""
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log = X.Journal(daemon)
    got, spawn = _drive_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    assert got == ("returned", 0), got
    head = _git.git_head_sha(s.repo)
    _assert_one_run_holds_exactly_the_agent(log, daemon, spawn, box, head_before=s.head,
                                            head_after=head)
    assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED


@pytest.mark.parametrize("at_stop", ["refused", "variant"])
def test_the_pitfalls_gate_judges_what_the_box_wrote_during_its_run(
        tmp_path: Path, monkeypatch, at_stop: str):
    """The box rewrites the reducer surface on its run's way out: refused bytes (a rewritten
    frontmatter block) are refused with HEAD unchanged and nothing staged; valid different bytes
    (the control) are what HEAD holds."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    bytes_out = REDUCER_REFUSED if at_stop == "refused" else REDUCER_VARIANT
    daemon.on_stop(s.at(REDUCER_REL), bytes_out, at=1)
    got = _run_pitfalls(s, [], rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    if at_stop == "variant":
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VARIANT
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert REDUCER_REFUSED_SAYS in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "the refused bytes were committed"
    assert _nothing_staged(s.repo)


#: As `LEAD_RUN_WRITES`, for the pitfalls lane: a new draft is outside its scope, a new
#: non-`.md` is a stray; a new `execution.md` for a declared system (`cmdb`, adapter only) is
#: admitted.
PITFALLS_RUN_WRITES = [
    pytest.param("defender/skills/gather/queries/wazuh/_draft/new1178.md",
                 query_template("wazuh.new1178", "draft"), "non-execution.md", id="new-md-refused"),
    pytest.param("defender/skills/elastic/evil1178.txt", "not markdown\n", "outside",
                 id="new-non-md"),
    pytest.param("defender/skills/cmdb/execution.md", "# cmdb\n\n## Common pitfalls\n\n- key it\n",
                 None, id="new-md-admissible"),
]


@pytest.mark.parametrize(("rel", "text", "says"), PITFALLS_RUN_WRITES)
def test_a_pitfalls_path_the_box_wrote_during_its_run_is_judged(
        tmp_path: Path, monkeypatch, rel: str, text: str, says: str | None):
    """The box writes a NEW path beside the curator's vetted reducer edit on its run's way out:
    a path outside the lane's scope or a non-`.md` stray is refused (HEAD unchanged, nothing
    staged); an admissible new `execution.md` (the control) is judged and committed."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    daemon.on_stop(s.at(rel), text, at=1)
    got = _run_pitfalls(s, [], rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    if says is None:
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", rel) == text
        assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert says in got[2], got
    assert rel in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "a path written during the run was committed"
    assert _nothing_staged(s.repo)


@pytest.mark.parametrize("fault", START_FAULTS)
def test_a_pitfalls_start_fault_runs_no_curator_and_commits_nothing(
        tmp_path: Path, monkeypatch, fault: str):
    """The run's start fails: `run_pitfalls` raises `BoxFault`; the curator never ran, the gate
    read nothing, HEAD is unchanged, nothing is staged, every queued row is still queued, and
    the box is stopped again."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _start_fault(daemon, fault)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    queued = _queued(s)
    log: list = []
    got, spawn = _drive_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the curator ran though its box never started"
    assert [e for e in log if e[0] == "read"] == [], "the gate ran though the box never started"
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)
    assert _queued(s) == queued
    assert daemon.status(NAME) == "exited", "the refused run left its box running"


@pytest.mark.parametrize("stop", STOP_FAULTS)
def test_a_pitfalls_stop_fault_after_a_clean_curator_halts_before_the_gate(
        tmp_path: Path, monkeypatch, stop: str):
    """The curator appends its pitfall and returns 0; then its run's stop fails: `run_pitfalls`
    raises `BoxFault`; the gate read nothing after the curator, HEAD is unchanged, nothing is
    staged, and every queued row is still queued. Control (`holds`): the stop taking, the gate
    reads after the run and the edit is committed."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _stop_fault(daemon, stop)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    queued = _queued(s)
    log: list = []
    got, spawn = _drive_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    assert len(spawn.calls) == 1, f"the curator was never reached: {got}"
    if stop == "holds":
        assert got == ("returned", 0), got
        assert _reads_after_the_agent(log), "the gate read nothing after the run (vacuous control)"
        assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED
        return
    assert got[:2] == ("raised", "BoxFault"), got
    assert _reads_after_the_agent(log) == [], "the gate judged beside a box that would not stop"
    assert _git.git_head_sha(s.repo) == s.head, "a commit landed beside a box that would not stop"
    assert _nothing_staged(s.repo)
    assert _queued(s) == queued


# ---------------------------------------------------------------------------------------
# D4'': only a plain, single-name regular file is committed, judged by a no-follow stat
# ---------------------------------------------------------------------------------------

#: The lead lane's addresses no content rule reads, so a link there passes every other rule and
#: is committed on main (#1178 C1), with the bytes a plain file there commits with.
LEAD_ADDRESSES = [
    pytest.param("gather/queries/wazuh/_draft/d1178.md", query_template("wazuh.d1178", "draft"),
                 id="catalog-draft"),
    pytest.param("elastic/_draft/d1178.md", "# elastic draft\n\n- a lifted note\n",
                 id="system-skill-draft"),
    pytest.param("gather/queries/wazuh/README.md", "# wazuh queries\n\nWhat lives here.\n",
                 id="catalog-readme"),
    # The same three one folder deeper: the path rule admits each, and no content rule reads
    # them either.
    pytest.param("gather/queries/wazuh/_draft/sub/d1178.md",
                 query_template("wazuh.d1178", "draft"), id="nested-catalog-draft"),
    pytest.param("elastic/_draft/sub/d1178.md", "# elastic draft\n\n- a lifted note\n",
                 id="nested-system-skill-draft"),
    pytest.param("gather/queries/wazuh/sub/README.md", "# wazuh sub-queries\n\nWhat lives here.\n",
                 id="nested-catalog-readme"),
]

KINDS = ["link", "hardlink", "plain", "exec"]

#: The kinds the gate must refuse at a committed name.
REFUSED_KINDS = ("link", "hardlink", "fifo")

#: Plain-file bytes that are not UTF-8: Latin-1 `é`, and a stray `0xff 0xfe`.
NOT_UTF8 = b"# notes\n\n- caf\xe9 \xff\xfe not utf-8\n"

#: A plain file larger than any held read takes (`_io.READ_LIMIT`), planted sparse.
BIG_SIZE = READ_LIMIT + 2**20


def _assert_plain_file_rule(got: tuple, repo: Path, head: str, rel: str, text: str,
                            kind: str) -> None:
    if kind in REFUSED_KINDS:
        assert got[:2] == ("raised", "LeadAuthorError"), got
        assert "refusing to commit" in got[2], got
        assert rel in got[2], got
        assert _git.git_head_sha(repo) == head, f"a {kind} at {rel} was committed"
        assert _nothing_staged(repo)
        return
    assert got == ("returned", 0), got
    assert _git.git_show_file(repo, "HEAD", rel) == text, "the plain control was not committed"
    assert _head_mode(repo, rel) == ("100755" if kind == "exec" else "100644")


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(("name", "text"), LEAD_ADDRESSES)
def test_the_lead_author_gate_commits_only_a_plain_file(
        tmp_path: Path, name: str, text: str, kind: str):
    """Through `run(label=, deps=)`: the agent leaves `name` as a symlink to an outside file, or
    a hard link to one, holding bytes a plain file there commits with. The gate refuses it
    (`LeadAuthorError` naming the path, "refusing to commit"), HEAD unchanged, nothing staged.
    Controls on the same address: a plain file commits at 100644, an executable one at 100755."""
    s = _lead_scene(tmp_path)
    got = _run_lead(s, [], name=name, text=text, kind=kind)
    _assert_plain_file_rule(got, s.repo, s.head, s.rel(name), text, kind)


@pytest.mark.parametrize("kind", ["fifo", "plain"])
@pytest.mark.parametrize(("name", "text"), LEAD_ADDRESSES)
def test_a_fifo_at_a_committed_lead_author_name_is_refused(
        tmp_path: Path, name: str, text: str, kind: str):
    """`name` is committed as a plain file; the agent replaces it with a FIFO (`git status`
    lists a FIFO only where it stands at a tracked name). The gate refuses it as no plain file
    (`LeadAuthorError`), HEAD unchanged, nothing staged. Control: the agent rewrites the same
    committed name as a plain file, which commits.

    A folder at a committed name is not pinned: git reports it as the name's deletion plus the
    plain files below it, each judged by the rules for those records."""
    s = _lead_scene(tmp_path, committed={name: text})
    rewritten = text + "\n- rewritten by the agent\n"
    got = _run_lead(s, [], name=name, text=rewritten, kind=kind)
    _assert_plain_file_rule(got, s.repo, s.head, s.rel(name), rewritten, kind)


@pytest.mark.parametrize(("name", "_text"), LEAD_ADDRESSES)
def test_a_plain_lead_author_file_that_is_not_utf8_commits(
        tmp_path: Path, name: str, _text: str):
    """The agent leaves a plain file whose bytes are not UTF-8 at an address no content rule
    reads: the plain-file rule stats the entry and reads none of it, so the file commits, those
    exact bytes at 100644. A rule that read the file as text would refuse it as no plain file."""
    s = _lead_scene(tmp_path)
    got = _run_lead(s, [], name=name, text=NOT_UTF8)
    assert got == ("returned", 0), got
    assert _head_bytes(s.repo, s.rel(name)) == NOT_UTF8
    assert _head_mode(s.repo, s.rel(name)) == "100644"


def test_every_lead_author_record_the_gate_admits_is_placed_through_the_held_mount(
        tmp_path: Path):
    """The agent leaves a plain file at every address above in one batch: each is committed, and
    each was asked of the lane's `tree_for` (the held mount) before the commit. Structural: on
    this lane `_frontmatter_id` already asks every in-scope path, so this row does not tell the
    plain-file rule apart from that read; the address rows above do."""
    names = {p.values[0]: p.values[1] for p in LEAD_ADDRESSES}
    first, *rest = names
    s = _lead_scene(tmp_path)
    log: list = []
    got = _run_lead(s, log, name=first, text=names[first], more={n: names[n] for n in rest})
    assert got == ("returned", 0), got
    asked = {e[1] for e in log if e[0] == "read"}
    for name, text in names.items():
        assert _git.git_show_file(s.repo, "HEAD", s.rel(name)) == text, name
        assert str(s.repo / s.rel(name)) in asked, f"{name} was committed unread"


#: A system-skill draft: the path rule admits it and no content rule reads it, so with every
#: other rule falling back on the plain path, only the plain-file rule can tell a placed path
#: from an unplaced one.
UNPLACED_DRAFT = "defender/skills/elastic/_draft/u1178.md"


@pytest.mark.parametrize("tree_for", ["lane", "places-nothing"])
def test_a_lead_author_record_no_held_mount_places_is_refused(tmp_path: Path, tree_for: str):
    """`_verify_skills_state` over a plain new system-skill draft, with a `tree_for` that places
    no path: `LeadAuthorError` naming it ("refusing to commit"), never a fall-back to the plain
    path. Control: the lane's own `tree_for` admits the same draft."""
    repo = seed_skills_repo(tmp_path / "repo")
    write(repo / UNPLACED_DRAFT, "# elastic draft\n\n- a lifted note\n")
    placed = lane_tree_for(repo) if tree_for == "lane" else (lambda _p: None)
    got = _outcome(lambda: lead_author._verify_skills_state(
        repo, baseline_stray=[], systems=frozenset({"elastic", "wazuh"}), tree_for=placed,
        git=claim_git(repo)))
    if tree_for == "lane":
        assert got == ("returned", [UNPLACED_DRAFT]), got
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert "refusing to commit" in got[2], got
    assert UNPLACED_DRAFT in got[2], got


@pytest.mark.parametrize("kind", [*KINDS, "fifo"])
def test_the_pitfalls_gate_commits_only_a_plain_execution_md(
        tmp_path: Path, monkeypatch, kind: str):
    """Through `run_pitfalls(trees=, invoke=)`: the curator leaves `elastic/execution.md` (a
    surface this lane commits with no content rule) as a symlink or a hard link to an outside
    file holding a valid edit, or as a FIFO in place of the committed file: refused, HEAD
    unchanged, nothing staged. Controls: the same bytes as a plain file commit at 100644, as an
    executable one at 100755."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _system_rows())
    got = _run_pitfalls(s, [], rel=EXECUTION_REL, text=EXECUTION_TEXT, kind=kind)
    _assert_plain_file_rule(got, s.repo, s.head, EXECUTION_REL, EXECUTION_TEXT, kind)


def test_a_plain_execution_md_that_is_not_utf8_commits(tmp_path: Path, monkeypatch):
    """The curator leaves `elastic/execution.md` as a plain file whose bytes are not UTF-8: it
    commits, those exact bytes."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _system_rows())
    got = _run_pitfalls(s, [], rel=EXECUTION_REL, text=NOT_UTF8)
    assert got == ("returned", 0), got
    assert _head_bytes(s.repo, EXECUTION_REL) == NOT_UTF8
    assert _head_mode(s.repo, EXECUTION_REL) == "100644"


@pytest.mark.parametrize("tree_for", ["lane", "places-nothing"])
def test_a_pitfalls_record_no_held_mount_places_is_refused(
        tmp_path: Path, monkeypatch, tree_for: str):
    """`_verify_pitfalls_state` over an edited `elastic/execution.md`, with a `tree_for` that
    places no path: `LeadAuthorError` naming it. Control: the lane's own `tree_for` admits it."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _system_rows())
    write(s.at(EXECUTION_REL), EXECUTION_TEXT)
    with lead_trees(s.paths) as trees:
        placed = trees.tree_for if tree_for == "lane" else (lambda _p: None)
        got = _outcome(lambda: pitfalls_curator._verify_pitfalls_state(
            s.repo, [], systems=frozenset({"elastic", "cmdb"}), reducer_offered=False,
            tree_for=placed, git=claim_git(s.repo)))
    if tree_for == "lane":
        assert got == ("returned", [EXECUTION_REL]), got
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert "refusing to commit" in got[2], got
    assert EXECUTION_REL in got[2], got


def test_every_pitfalls_record_the_gate_admits_is_placed_through_the_held_mount(
        tmp_path: Path, monkeypatch):
    """The curator edits `elastic/execution.md` and the reducer surface in one tick: both are
    committed, and both were asked of the lane's `tree_for` before the commit (the
    `execution.md` by the plain-file rule alone: no content rule reads it)."""
    s = _pitfalls_scene(tmp_path, monkeypatch, [*_system_rows(), *_reducer_rows()])
    log: list = []
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED,
                        more={EXECUTION_REL: EXECUTION_TEXT})
    assert got == ("returned", 0), got
    asked = {e[1] for e in log if e[0] == "read"}
    for committed, text in ((REDUCER_REL, REDUCER_VETTED), (EXECUTION_REL, EXECUTION_TEXT)):
        assert _git.git_show_file(s.repo, "HEAD", committed) == text, committed
        assert str(s.repo / committed) in asked, f"{committed} was committed unread"


# ---------------------------------------------------------------------------------------
# The host's steps before the agent run before its run starts: the baseline and the mint
# ---------------------------------------------------------------------------------------

#: A committed file outside `skills/`: the box's write there once started is a stray only if the
#: lane took its baseline of strays before the start.
STRAY_REL = "defender/notes/stray1178.md"
STRAY_EDIT = "rewritten by the box\n"


def _commit_stray(repo: Path) -> str:
    """`STRAY_REL` committed with its first text; the new HEAD."""
    write(repo / STRAY_REL, "committed\n")
    return commit_all(repo, "a file outside skills")


@pytest.mark.parametrize("when", ["once-started", "before-the-run"])
def test_a_lead_author_stray_the_box_writes_once_started_is_refused(
        tmp_path: Path, monkeypatch, when: str):
    """The box rewrites a committed file outside `skills/` as soon as its run starts: the gate
    refuses the claim ("changed files outside", naming it), HEAD unchanged, nothing staged. The
    lane's baseline of strays was taken before the start, so the rewrite is new. Control: the
    same rewrite already standing before the run is in the baseline, and the claim commits
    (without it)."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    s = dataclasses.replace(s, head=_commit_stray(s.repo))
    stray = s.repo / STRAY_REL
    if when == "before-the-run":
        write(stray, STRAY_EDIT)
    else:
        daemon.on_start(stray, STRAY_EDIT, at=1)
    got = _run_lead(s, [], name=AGENT_NAME, text=VETTED, box=runs)
    if when == "before-the-run":
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
        assert _git.git_show_file(s.repo, "HEAD", STRAY_REL) == "committed\n"
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert "changed files outside" in got[2], got
    assert STRAY_REL in got[2], got
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)


@pytest.mark.parametrize("when", ["once-started", "before-the-run"])
def test_a_pitfalls_stray_the_box_writes_once_started_is_refused(
        tmp_path: Path, monkeypatch, when: str):
    """As the lead-author row, for the pitfalls tick: its baseline of strays is taken before its
    run starts."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    s = dataclasses.replace(s, head=_commit_stray(s.repo))
    stray = s.repo / STRAY_REL
    if when == "before-the-run":
        write(stray, STRAY_EDIT)
    else:
        daemon.on_start(stray, STRAY_EDIT, at=1)
    got = _run_pitfalls(s, [], rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    if when == "before-the-run":
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED
        assert _git.git_show_file(s.repo, "HEAD", STRAY_REL) == "committed\n"
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert "changed files outside" in got[2], got
    assert STRAY_REL in got[2], got
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)


@pytest.mark.parametrize("box_does", ["removes-it", "leaves-it"])
def test_a_draft_minted_this_tick_that_the_box_removes_once_started_is_a_departure(
        tmp_path: Path, monkeypatch, box_does: str):
    """The tick mints an untracked draft for the run's lead, then starts the box, which removes
    that draft at once. The identities the draft recorded were captured before the start, so its
    departure is seen and refused (`LeadAuthorError`, "without attributing it", naming the
    draft), HEAD unchanged. Control: the box leaves the draft, and it is committed with the
    agent's file."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    minted_name, _text = draft_of(ELASTIC_LEAD)
    if box_does == "removes-it":
        daemon.on_start(s.at(minted_name), remove=True, at=1)
    got = _run_lead(s, [], name=AGENT_NAME, text=VETTED, box=runs)
    if box_does == "leaves-it":
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", s.rel(minted_name)) is not None
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert "without attributing it" in got[2], got
    assert s.rel(minted_name) in got[2], got
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)


# ---------------------------------------------------------------------------------------
# D4'': the plain-file rule stats, it never reads (a plain file past any read limit commits)
# ---------------------------------------------------------------------------------------


def _head_size(repo: Path, rel: str) -> tuple[str, int]:
    """`(mode, size)` of the blob committed at `rel` in HEAD."""
    entry = _git.git(["ls-tree", "-l", "HEAD", "--", rel], cwd=repo)  # lint-oracle: ok — reads what was committed; the oracle is the planted size
    mode, _kind, _sha, size = entry.split("\t", 1)[0].split()
    return mode, int(size)


@pytest.mark.parametrize("name", ["elastic/_draft/b1178.md", "gather/queries/wazuh/README.md"],
                         ids=["system-skill-draft", "catalog-readme"])
def test_a_plain_lead_author_file_larger_than_any_read_commits(tmp_path: Path, name: str):
    """The agent leaves a plain (sparse) file larger than `_io.READ_LIMIT` at an address no
    content rule reads: it commits at 100644, at its full size. A plain-file rule that read the
    file would refuse it as too large."""
    s = _lead_scene(tmp_path)
    got = _run_lead(s, [], name=name, text=b"# a large note\n", kind="big")
    assert got == ("returned", 0), got
    assert _head_size(s.repo, s.rel(name)) == ("100644", BIG_SIZE)


def test_a_plain_execution_md_larger_than_any_read_commits(tmp_path: Path, monkeypatch):
    s = _pitfalls_scene(tmp_path, monkeypatch, _system_rows())
    got = _run_pitfalls(s, [], rel=EXECUTION_REL, text=EXECUTION_TEXT, kind="big")
    assert got == ("returned", 0), got
    assert _head_size(s.repo, EXECUTION_REL) == ("100644", BIG_SIZE)


# ---------------------------------------------------------------------------------------
# The drain: one run window per agent, none between; a run's box fault halts the lane
# ---------------------------------------------------------------------------------------


def _queue_claims(s: LeadScene, *run_names: str) -> list[Path]:
    """A lead-author request queued for each named run dir (`runs/<name>`, a `gather_raw/` of its
    own), keyed `case-<name>`; returns the run dirs."""
    run_dirs = []
    for name in run_names:
        run_dir = s.tmp / "runs" / name
        (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
        markers.enqueue_case_for_curation(f"case-{name}", run_dir, s.paths)
        run_dirs.append(run_dir)
    return run_dirs


class Lanes:
    """The drain's two work steps, each driving its REAL lane over the worktree it is handed:
    `run_lead` serves a claim through `lead_author.run` (only the agent and the two tables
    faked), `run_pitfalls` a tick through `run_pitfalls` (only the curator faked), each handed
    the box the drain handed down (`handed` records it). With a `log`, each lane's host steps
    and gate reads log into it. `pitfalls_ticks` counts the pitfalls ticks. With
    `swallow_claim_box_faults`, a claim's `BoxFault` is swallowed (`swallowed`), as a layer
    above a spawn may mask it."""

    def __init__(self, agent: BoxSeenLeadSpawn, curator: BoxSeenSpawn | None = None, *,
                 log: list | None = None, swallow_claim_box_faults: bool = False) -> None:
        self.agent, self.curator, self.log = agent, curator, log
        self.swallow = swallow_claim_box_faults
        self.pitfalls_ticks = 0
        self.handed: list[Any] = []
        self.swallowed: list[BoxFault] = []

    def run_lead(self, paths: LoopPaths, run_dir: Path, *, box: Any = None, on_done: Any,
                 **_kw: Any) -> int:
        self.handed.append(box)
        with lead_trees(paths) as trees:
            deps = _deps(paths, trees, self.agent, [ELASTIC_LEAD])
            if self.log is not None:
                deps = _journaled_deps(deps, self.log)
            try:
                return lead_author.run(run_dir, label=LEAD, paths=paths, deps=deps, box=box,
                                       on_done=on_done)
            except BoxFault as e:
                if not self.swallow:
                    raise
                self.swallowed.append(e)
                return 0

    def run_pitfalls(self, paths: LoopPaths, *, box: Any = None, on_curated: Any,
                     **_kw: Any) -> int:
        self.handed.append(box)
        self.pitfalls_ticks += 1
        if self.curator is None:
            return 0
        with lead_trees(paths) as trees:
            held = trees if self.log is None else LoggedTrees(trees, self.log)
            return pitfalls_curator.run_pitfalls(paths=paths, trees=held, invoke=self.curator,
                                                 box=box, on_curated=on_curated)


def _failed(s: LeadScene) -> list[str]:
    """The names of the claims the lane dead-lettered."""
    failed = s.paths.author_queue_dir / markers.FAILED_MARKER_DIRNAME
    return sorted(p.name for p in failed.glob("*.json")) if failed.is_dir() else []


def _claim_files(s: LeadScene) -> tuple[list[str], list[str]]:
    """The lead-author queue's markers: those still queued, and those claimed (`inflight/`)."""
    qdir = s.paths.author_queue_dir
    return (sorted(p.name for p in qdir.glob("*.json")),
            sorted(p.name for p in (qdir / "inflight").glob("*.json")))


def _attempts(paths: LoopPaths) -> list[Any]:
    return [r.get("attempts") for r in persist.read_pitfalls(paths)]


def test_the_lead_drain_runs_one_window_per_agent_and_none_between(tmp_path: Path, monkeypatch):
    """`_drain_lead_author(..., box=<the batch's stopped box>)` serving one claim and one
    pitfalls tick through the real lanes: each lane handed the handle (F3), and exactly two run
    windows, the claim's agent and the pitfalls curator, each holding its spawn alone, each
    spawn handed the batch's executor (O6); every host
    step of either lane (the claim's pre-agent steps and gate, the pitfalls tick's mount and
    gate) saw nothing running; the box is stopped at the end; both lanes committed."""
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(_system_rows(), paths=s.paths)
    _queue_claims(s, "run-0")
    log = X.Journal(daemon)

    def author(_run_dir: Path) -> None:
        write(s.at(AGENT_NAME), VETTED)
        log.append(("agent",))

    def curate(root: Path) -> None:
        write(root / EXECUTION_REL, EXECUTION_TEXT)
        log.append(("curator",))

    lanes = Lanes(BoxSeenLeadSpawn(author), BoxSeenSpawn(curate), log=log)

    drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls, box=runs)

    log.assert_runs_hold_exactly(["agent", "curator"], ("agent", "curator"))
    kinds = [e[0] for e in log]
    assert {"host", "read"} <= set(kinds[kinds.index("agent") + 1:kinds.index("curator")]), (
        f"no host step was seen between the runs (vacuous): {kinds}")
    assert [b is box for b in lanes.agent.boxes] == [True], lanes.agent.boxes
    assert [b is box for b in lanes.curator.boxes] == [True], lanes.curator.boxes
    assert lanes.handed == [runs, runs], f"a lane was handed something but the handle: {lanes.handed}"
    assert daemon.status(NAME) == "exited"
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
    assert _git.git_show_file(s.repo, "HEAD", EXECUTION_REL) == EXECUTION_TEXT


@pytest.mark.parametrize("fault", START_FAULTS)
def test_a_claims_run_start_fault_halts_the_lane_and_dead_letters_nothing(
        tmp_path: Path, monkeypatch, fault: str):
    """Two claims queued; the first claim's run cannot start (refused, not taking, or the box
    found running): a `BoxFault` escapes `_drain_lead_author`. The first claim's agent never
    ran, the second claim is never claimed, the pitfalls tick never runs, nothing is committed,
    no claim is dead-lettered, and the box is stopped. Control: the next row."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _start_fault(daemon, fault)
    s = _lead_scene(tmp_path)
    _queue_claims(s, "run-0", "run-1")
    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)))

    got = X.caught(lambda: drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls,
                                                     box=runs))

    assert isinstance(got, BoxFault), got
    assert lanes.agent.calls == [], "an agent ran though its box never started"
    assert _claim_files(s) == (["case-run-1.json"], ["case-run-0.json"]), (
        "the lane went on to serve another claim")
    assert lanes.pitfalls_ticks == 0, "the pitfalls tick ran after a box fault"
    assert _failed(s) == [], "a claim was dead-lettered for a box that would not start"
    assert _git.git_head_sha(s.repo) == s.head
    assert daemon.status(NAME) == "exited"


def test_control_a_claims_agent_fault_dead_letters_that_claim_and_the_next_is_served(
        tmp_path: Path, monkeypatch):
    """The first claim's agent fails (`LeadAuthorError`, not a box fault): its run's box is
    stopped on that way out, that claim is dead-lettered, and the second is served in a run
    window of its own and committed."""
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    _queue_claims(s, "run-0", "run-1")
    log = X.Journal(daemon)

    def author(run_dir: Path) -> None:
        log.append(("agent",))
        if run_dir.name == "run-0":
            raise LeadAuthorError("the agent failed")
        write(s.at(AGENT_NAME), VETTED)

    lanes = Lanes(BoxSeenLeadSpawn(author), log=log)

    drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls, box=runs)

    log.assert_runs_hold_exactly(["agent", "agent"], ("agent",))
    assert [b is box for b in lanes.agent.boxes] == [True, True], lanes.agent.boxes
    assert _failed(s) == ["case-run-0.json"], _failed(s)
    assert daemon.status(NAME) == "exited"
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED


@pytest.mark.parametrize("stop", X.STOP_FAULTS)
def test_a_claims_stop_fault_after_a_clean_agent_halts_the_lane(
        tmp_path: Path, monkeypatch, stop: str):
    """Two claims queued; the first claim's agent leaves a valid draft and returns 0, then its
    run's stop fails: a `BoxFault` escapes `_drain_lead_author`. Nothing is committed, the second
    claim is never claimed, the pitfalls tick never runs, and no claim is dead-lettered.
    Control: `test_the_lead_drain_runs_one_window_per_agent_and_none_between` (the stop
    taking)."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _stop_fault(daemon, stop)
    s = _lead_scene(tmp_path)
    _queue_claims(s, "run-0", "run-1")
    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)))

    got = X.caught(lambda: drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls,
                                                     box=runs))

    assert isinstance(got, BoxFault), got
    assert len(lanes.agent.calls) == 1, lanes.agent.calls
    assert _claim_files(s) == (["case-run-1.json"], ["case-run-0.json"]), (
        "the lane went on to serve another claim")
    assert lanes.pitfalls_ticks == 0, "the pitfalls tick ran after a box fault"
    assert _failed(s) == [], "a claim was dead-lettered for a box that would not stop"
    assert _git.git_head_sha(s.repo) == s.head, "a commit landed beside a box that would not stop"


#: Where the pitfalls run's box fails, after the claim's run held: its start, or its stop
#: after a clean curator. `curator-fails` is the control: a fault that is not a box fault.
PITFALLS_BOX_FAULTS = ["start", "stop", "curator-fails"]


@pytest.mark.parametrize("where", PITFALLS_BOX_FAULTS)
def test_a_pitfalls_box_fault_halts_the_lane_and_bumps_no_pitfalls_row(
        tmp_path: Path, monkeypatch, where: str):
    """One claim and a pitfalls tick through `_drain_lead_author`; the claim's run holds and its
    draft is committed. The pitfalls run's box will not start, or will not stop after a clean
    curator: a `BoxFault` escapes `_drain_lead_author`, the pitfalls edit is not committed, and
    no pitfalls row's attempts change (a box fault is no row's failure; the rows stay for the
    next tick).

    Control (`curator-fails`): the curator fails (rc 1, not a box fault): the tick is retired as
    a batch error, nothing escapes, and every row's attempts is bumped to 1, so the attempts
    read above is live."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    if where == "start":
        daemon.refuse_start(at=[2])
    elif where == "stop":
        daemon.refuse_stop(at=[2])
    s = _lead_scene(tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(_system_rows(), paths=s.paths)
    _queue_claims(s, "run-0")
    attempts_before = _attempts(s.paths)
    execution_before = _git.git_show_file(s.repo, "HEAD", EXECUTION_REL)

    def curate(root: Path) -> None:
        write(root / EXECUTION_REL, EXECUTION_TEXT)

    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)),
                  BoxSeenSpawn(curate, rc=1 if where == "curator-fails" else 0))

    got = X.caught(lambda: drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls,
                                                     box=runs))

    attempts = _attempts(s.paths)
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED, (
        "the claim's own commit did not stand")
    assert _git.git_show_file(s.repo, "HEAD", EXECUTION_REL) == execution_before, (
        "the pitfalls edit was committed")
    assert lanes.pitfalls_ticks == 1
    if where == "curator-fails":
        assert got is None, got
        assert attempts == [1] * len(attempts_before), attempts
        return
    assert isinstance(got, BoxFault), got
    assert len(lanes.curator.calls) == (0 if where == "start" else 1)
    assert attempts == attempts_before, f"a pitfalls row was bumped for a box fault: {attempts}"


def _run_calls(daemon: X.FakeDaemon) -> list[str]:
    """The daemon's starts, stops and status asks, in order (the direct drives' box)."""
    return [x for x in daemon.steps() if x in ("status", "start", "stop")]


#: One run that holds: its check, its start and proof, its stop and proof.
ONE_RUN = ["status", "start", "status", "stop", "status"]


def _claim_then_pitfalls(tmp_path: Path, monkeypatch: Any
                         ) -> tuple[X.FakeDaemon, Any, Any, LeadScene, list[Any], str | None]:
    """One claim queued and three pitfalls rows at threshold, over a stopped box: the daemon,
    the executor, the handle, the scene, the rows' attempts and `execution.md` at HEAD."""
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(_system_rows(), paths=s.paths)
    _queue_claims(s, "run-0")
    return (daemon, box, runs, s, _attempts(s.paths),
            _git.git_show_file(s.repo, "HEAD", EXECUTION_REL))


#: What the pitfalls curator raises inside its run: `AuthorError` (a `RETIRE_SET` member) and a
#: crash; either retires the tick's batch, bumping its rows.
PITFALLS_F1_FAILURES = [
    pytest.param(lambda: AuthorError("the curator refused"), id="AuthorError"),
    pytest.param(lambda: RuntimeError("the curator crashed"), id="RuntimeError"),
]


@pytest.mark.parametrize("stop", STOP_FAULTS)
@pytest.mark.parametrize("failure", PITFALLS_F1_FAILURES)
def test_a_stop_fault_under_a_failing_curator_halts_the_lane_and_bumps_no_pitfalls_row(
        tmp_path: Path, monkeypatch, failure: Any, stop: str):
    """F1, with no later run: `_drain_lead_author` over one claim (whose run holds and commits)
    and the pitfalls tick, the last run of the batch. The curator raises X inside its run and
    the run's stop fails (refused, without effect, unproven, the seam raising): a `BoxFault`
    escapes, never X, with X in its chain (its `__context__`, behind the seam's own exception
    when the seam raised). No pitfalls row's attempts change, and the curator's edit is not
    committed. Control (`holds`): X is handled as before: the drain retires the tick's batch as
    a batch error and bumps every row, so the attempts read is live."""
    daemon, _box, runs, s, attempts_before, execution_before = _claim_then_pitfalls(
        tmp_path, monkeypatch)
    raised = failure()

    def curate(root: Path) -> None:
        write(root / EXECUTION_REL, EXECUTION_TEXT)
        if stop != "holds":  # the pitfalls run's stop: the second; its proof, the next status ask
            X.fail_stop(daemon, stop, at=2, inspect_at=daemon.inspect_count() + 1)
        raise raised

    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)),
                  BoxSeenSpawn(curate))

    got = X.caught(lambda: drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls,
                                                     box=runs))

    assert len(lanes.curator.calls) == 1, "the curator never ran, so the row is vacuous"
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED, (
        "the claim's own commit did not stand")
    assert _git.git_show_file(s.repo, "HEAD", EXECUTION_REL) == execution_before, (
        "the failed curator's edit was committed")
    X.no_path_docker(daemon)
    if stop == "holds":
        assert got is None, got
        assert _attempts(s.paths) == [1] * len(attempts_before), _attempts(s.paths)
        return
    assert isinstance(got, BoxFault), f"the curator's failure outranked its stop fault: {got!r}"
    if stop.startswith("seam-"):
        assert daemon.seam_raised == ["stop"], daemon.seam_raised
        assert raised in X.chain(got), X.chain(got)
    else:
        assert got.__context__ is raised, X.chain(got)
    assert _attempts(s.paths) == attempts_before, "a pitfalls row was bumped for a box fault"


@pytest.mark.parametrize("stop", ["refused", "holds"])
def test_a_swallowed_stop_fault_in_the_last_claim_makes_the_pitfalls_run_refuse(
        tmp_path: Path, monkeypatch, stop: str):
    """E3' at the claim -> pitfalls boundary (N11''): `_drain_lead_author` over the real lanes,
    one claim and three pitfalls rows at threshold, the claim lane swallowing its `BoxFault` as
    a layer above a spawn may. With `refused`, the claim's agent leaves its draft and returns,
    and its run's stop is refused: that `BoxFault` is swallowed and the box keeps running. The
    pitfalls tick's run then finds it running and refuses before its curator, naming the
    status, with a best-effort stop and no `docker start`: `BoxFault` escapes, the curator is
    never called, `execution.md` is as committed, and no pitfalls row's attempts change.
    Nothing touches the box between the claim's run and the tick's.

    Control (`holds`): the claim's stop takes; the pitfalls run starts, the curator runs and its
    edit is committed."""
    daemon, _box, runs, s, attempts_before, execution_before = _claim_then_pitfalls(
        tmp_path, monkeypatch)
    if stop == "refused":
        daemon.refuse_stop(at=[1])  # the claim's run's stop

    def curate(root: Path) -> None:
        write(root / EXECUTION_REL, EXECUTION_TEXT)

    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)),
                  BoxSeenSpawn(curate), swallow_claim_box_faults=True)

    got = X.caught(lambda: drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls,
                                                     box=runs))

    assert len(lanes.agent.calls) == 1
    assert lanes.pitfalls_ticks == 1
    calls = _run_calls(daemon)
    if stop == "holds":
        assert got is None, got
        assert lanes.swallowed == []
        assert len(lanes.curator.calls) == 1
        assert _git.git_show_file(s.repo, "HEAD", EXECUTION_REL) == EXECUTION_TEXT
        assert calls == ONE_RUN * 2, calls
        return
    assert len(lanes.swallowed) == 1, "the claim's stop did not fail, so the row is vacuous"
    assert isinstance(got, BoxFault), f"the lane did not halt on a box left running: {got!r}"
    assert "running" in str(got), got
    assert lanes.curator.calls == [], "the pitfalls curator ran after a swallowed stop fault"
    assert _git.git_show_file(s.repo, "HEAD", EXECUTION_REL) == execution_before, (
        "the pitfalls edit was committed after a swallowed stop fault")
    assert _attempts(s.paths) == attempts_before
    assert calls == [*ONE_RUN, "status", "stop", "status"], (
        f"the pitfalls run did not refuse the running box with a best-effort stop: {calls}")
    assert daemon.status(NAME) == "exited"


# ---------------------------------------------------------------------------------------
# O4 through the DEFAULT work steps: a run start fault reached by the real claim and tick
# ---------------------------------------------------------------------------------------


def _held_lead_drain(s: LeadScene, monkeypatch: Any, **seams: Any
                     ) -> tuple[BaseException | None, list[str], list[str], X.ScanWatch]:
    """`lead_author_drain` with its DEFAULT work steps over the fake daemon, whose first run
    start is refused; only `start_box=` injected: `HeldStart` (a real create, minus the probes),
    whose executor carries the daemon, so the drain's own post-create stop, the runs and the
    removal reach it through that executor (a `Tripwire` is the `docker` on `PATH`). What it
    raised, the batch box's docker calls from its post-create stop on, the branch's events and
    the scan's watch."""
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)  # the agent, if ever reached, calls no model
    X.clear_opt_out(monkeypatch)
    daemon = X.FakeDaemon(s.tmp)
    daemon.tripwire = X.Tripwire(s.tmp).install(monkeypatch)
    daemon.refuse_start(at=[1])
    events: list[str] = []
    watch = X.ScanWatch(daemon, events)
    start = X.HeldStart(daemon)
    got = X.caught(lambda: drains.lead_author_drain(
        s.paths, branch=RepoBranch(s.repo, branch_prefix="lead-author/", events=events),
        start_box=start, scrub=watch, **seams))
    [request] = start.requests
    X.no_path_docker(daemon)
    return got, daemon.calls_from_the_first_stop(request.name), events, watch


@pytest.mark.parametrize("first", ["box-faults", "nothing-to-author"])
def test_a_run_start_fault_through_the_default_claim_step_halts_the_lane(
        tmp_path: Path, monkeypatch, first: str):
    """`lead_author_drain` with its DEFAULT `run_lead_author` (`_invoke_lead_author` driving the
    real `run_under_held_queue_lock` over the real deps and each claim's run dir). Two claims,
    each with an executed lead to author: the first claim's run start is refused, and the
    `BoxFault` escapes `lead_author_drain`. Only one start was ever asked for: the second claim
    is not served (still queued, unclaimed), the first is not handed back to the queue as a
    transient (it stays claimed for the next tick's reclaim), no claim is dead-lettered,
    nothing is committed or delivered, and the box is removed before the scan.

    Control (`nothing-to-author`): the first claim's run dir executed no lead, so its serve
    returns without an agent; the second claim is then served, and its default step reaches its
    run's start (the one start). So one start in the row above means the second claim never got
    that far.

    Either way the batch box's docker calls are exactly `X.REFUSED_FIRST_RUN`: no claim's
    default step asks the daemon anything outside its run."""
    s = _lead_scene(tmp_path)
    leads = {"claim-0": WAZUH_LEAD if first == "box-faults" else None, "claim-1": ELASTIC_LEAD}
    for name, lead in leads.items():
        rows = [(lead.query_id, lead.system, lead.verb)] if lead is not None else []
        markers.enqueue_case_for_curation(f"case-{name}", _run_dir(tmp_path / name, *rows),
                                          s.paths)

    got, calls, events, watch = _held_lead_drain(s, monkeypatch)

    assert isinstance(got, BoxFault), got
    assert X.POINTER not in str(got), f"a mid-batch box fault got a build pointer: {got}"
    assert calls == X.REFUSED_FIRST_RUN, f"a default step called docker outside its run: {calls}"
    assert _failed(s) == [], "a claim was dead-lettered for a box that would not start"
    assert _git.git_head_sha(s.repo) == s.head
    assert not any(e.startswith("finish_batch:") for e in events), events
    watch.assert_scanned_once_the_box_was_gone()
    queued, claimed = _claim_files(s)
    if first == "nothing-to-author":
        assert queued == [], queued
        assert "case-claim-1.json" in claimed, claimed
        return
    assert queued == ["case-claim-1.json"], (
        f"the next claim was served, or the first handed back as a transient: {queued}")
    assert claimed == ["case-claim-0.json"], claimed


def test_a_run_start_fault_through_the_default_pitfalls_step_halts_the_lane(
        tmp_path: Path, monkeypatch):
    """`lead_author_drain` with its DEFAULT `run_pitfalls` (`_invoke_pitfalls` driving the real
    `run_pitfalls` and its default curator spawn), no claim queued and three pitfalls rows at
    threshold: the tick's run start is refused before its curator, and the `BoxFault` escapes
    `lead_author_drain`. No pitfalls row's attempts change, nothing is committed or delivered,
    and the box is removed before the scan; the batch box's docker calls are exactly
    `X.REFUSED_FIRST_RUN` (nothing outside the tick's run). Control for the attempts read:
    `test_a_pitfalls_box_fault_halts_the_lane_and_bumps_no_pitfalls_row[curator-fails]`."""
    s = _lead_scene(tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(_system_rows(), paths=s.paths)
    attempts_before = _attempts(s.paths)

    got, calls, events, watch = _held_lead_drain(s, monkeypatch)

    assert isinstance(got, BoxFault), got
    assert calls == X.REFUSED_FIRST_RUN, f"the default step called docker outside its run: {calls}"
    assert _attempts(s.paths) == attempts_before, "a pitfalls row was bumped for a box fault"
    assert _git.git_head_sha(s.repo) == s.head
    assert not any(e.startswith("finish_batch:") for e in events), events
    watch.assert_scanned_once_the_box_was_gone()


# ---------------------------------------------------------------------------------------
# The production drain: the real start, stop and removal over the fake daemon
# ---------------------------------------------------------------------------------------


def _production_lead_scene(tmp_path: Path, monkeypatch: Any, *claims: str,
                           path_default: bool = False) -> tuple[LeadScene, X.FakeDaemon]:
    """The lead scene as `lead_author_drain` serves it in production: the box image inputs
    committed under the repo's `defender/`, `claims` queued, the opt-out unset. The real
    `start_box` creates the box over the fake daemon, given as its `docker=`
    (`_production_lead_drain`), with a `Tripwire` the `docker` on `PATH`; with `path_default`,
    production's own default docker reaches the daemon installed on `PATH`. Either way the
    post-create stop, each spawn's run and the removal reach the daemon through the executor."""
    X.clear_opt_out(monkeypatch)
    s = _lead_scene(tmp_path)
    X.plant_image_inputs(s.repo)
    s = dataclasses.replace(s, head=commit_all(s.repo, "the box image inputs"))
    _queue_claims(s, *claims)
    daemon = X.FakeDaemon(tmp_path)
    if path_default:
        daemon.install(monkeypatch)
    else:
        daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
    return s, daemon


def _production_lead_drain(s: LeadScene, daemon: X.FakeDaemon, author: Callable[[Path], None]
                           ) -> tuple[BaseException | None, Lanes, list[str], X.ScanWatch]:
    """`lead_author_drain` with only the lanes (their agent: `author`), the branch, the scan and
    (unless the daemon is on `PATH`) the real `start_box`'s docker injected: what it raised, the
    lanes, the branch's events and the scan's watch."""
    lanes = Lanes(BoxSeenLeadSpawn(author))
    events: list[str] = []
    branch = RepoBranch(s.repo, branch_prefix="lead-author/", events=events)
    watch = X.ScanWatch(daemon, events)
    seams: dict[str, Any] = {}
    if daemon.tripwire is not None:
        seams["start_box"] = partial(box_mod.start_box, docker=daemon)
    got = X.caught(lambda: drains.lead_author_drain(
        s.paths, run_lead_author=lanes.run_lead, run_pitfalls=lanes.run_pitfalls, branch=branch,
        scrub=watch, **seams))
    return got, lanes, events, watch


def _kept(daemon: X.FakeDaemon) -> list[str]:
    return [x for x in daemon.steps()
            if x in ("create", "start", "stop", "rm", "scan") or x.startswith("agent:")]


#: What the first claim's agent raises inside its run: the gate's own refusal, which
#: dead-letters the claim, and a crash, dead-lettered the same way.
LEAD_F1_FAILURES = [
    pytest.param(lambda: LeadAuthorError("the agent failed"), id="LeadAuthorError"),
    pytest.param(lambda: RuntimeError("the agent crashed"), id="RuntimeError"),
]


@pytest.mark.parametrize("follows", ["next-claim", "nothing-follows"])
@pytest.mark.parametrize("stop", STOP_FAULTS)
@pytest.mark.parametrize("failure", LEAD_F1_FAILURES)
def test_a_stop_fault_under_a_failing_agent_halts_the_lead_drain_with_the_failure_as_context(
        tmp_path: Path, monkeypatch, failure: Any, stop: str, follows: str):
    """F1 through `lead_author_drain` as production wires it (only `start_box=` bringing the
    docker; the lanes, the branch and the scan injected). The first claim's agent raises X
    inside its run, and its run's stop fails (refused, without effect, unproven, the seam
    raising): a `BoxFault` escapes at once, never X, with X as its `__context__` (behind the
    seam's own exception when the seam raised). So X is never handled as X: no claim is
    dead-lettered (the first stays claimed for the next tick's reclaim), nothing is committed or
    delivered, the pitfalls tick never runs, and no later `docker start` is asked, whether a
    second claim waits (`next-claim`, whose run would refuse beside the box) or nothing does
    (`nothing-follows`, where no later run would catch a box left running). The batch-end
    `rm -f` removes the box, and the tree is scanned only after.

    Control (`holds`): the stop takes; X dead-letters the first claim, the second (if any) is
    served in a run window of its own and committed, and the batch is delivered."""
    claims = ("run-0", "run-1") if follows == "next-claim" else ("run-0",)
    s, daemon = _production_lead_scene(tmp_path, monkeypatch, *claims)
    raised = failure()

    def author(run_dir: Path) -> None:
        daemon.mark(f"agent:{run_dir.name}")
        if run_dir.name != "run-0":
            write(s.at(AGENT_NAME), VETTED)
            return
        if stop != "holds":  # 1: the post-create stop; 2: this run's; its proof: the next ask
            X.fail_stop(daemon, stop, at=2, inspect_at=daemon.inspect_count() + 1)
        raise raised

    got, lanes, events, watch = _production_lead_drain(s, daemon, author)

    assert len(daemon.created()) == 1, "the batch did not create exactly its one box"
    assert daemon.names() == [], "a box outlived the batch"
    watch.assert_scanned_once_the_box_was_gone()
    X.no_path_docker(daemon)
    kept = _kept(daemon)
    if stop == "holds":
        assert got is None, got
        assert _failed(s) == ["case-run-0.json"], _failed(s)
        if follows == "next-claim":
            assert kept == ["create", "stop", "start", "agent:run-0", "stop", "start",
                            "agent:run-1", "stop", "rm", "scan"], kept
            assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
            assert any(e.startswith("finish_batch:") for e in events), events
        return
    assert isinstance(got, BoxFault), f"the agent's failure outranked its stop fault: {got!r}"
    if stop.startswith("seam-"):
        assert daemon.seam_raised == ["stop"], daemon.seam_raised
        assert raised in X.chain(got), X.chain(got)
    else:
        assert got.__context__ is raised, X.chain(got)
    assert X.POINTER not in str(got), f"a mid-batch box fault got a build pointer: {got}"
    assert _failed(s) == [], "a claim was dead-lettered under a box fault"
    assert _claim_files(s) == (["case-run-1.json"] if follows == "next-claim" else [],
                               ["case-run-0.json"]), _claim_files(s)
    assert kept[:4] == ["create", "stop", "start", "agent:run-0"], kept
    assert "start" not in kept[4:], f"a later run was started beside the box: {kept}"
    assert kept[-2:] == ["rm", "scan"], kept
    assert lanes.pitfalls_ticks == 0
    assert _git.git_head_sha(s.repo) == s.head, "a commit landed beside a box that would not stop"
    assert not any(e.startswith("finish_batch:") for e in events), events


@pytest.mark.parametrize("docker", ["carried", "path-default"])
@pytest.mark.parametrize("stop", ["refused", "holds"])
def test_a_claims_stop_fault_after_a_clean_agent_halts_the_production_drain(
        tmp_path: Path, monkeypatch, stop: str, docker: str):
    """`lead_author_drain` as production wires it, over the fake daemon, one claim queued. Its
    agent leaves a valid draft and succeeds; with `refused`, its run's stop fails, with nothing
    in flight. The claim's `BoxFault` escapes `lead_author_drain`: nothing is committed, nothing
    is delivered, and the claim is not dead-lettered. The batch-end `rm -f` removes the box (no
    container is left), and the tree is scanned only after.

    Control (`holds`): the stop takes; the draft is committed and the batch delivered. `carried`:
    the real `start_box` given the daemon as its docker, nothing reaching the `docker` on `PATH`;
    `path-default`: production's own default docker, the daemon installed on `PATH`."""
    s, daemon = _production_lead_scene(tmp_path, monkeypatch, "run-0",
                                       path_default=docker == "path-default")

    def author(run_dir: Path) -> None:
        daemon.mark(f"agent:{run_dir.name}")
        write(s.at(AGENT_NAME), VETTED)
        if stop == "refused":
            daemon.refuse_stop()

    got, _lanes, events, watch = _production_lead_drain(s, daemon, author)

    assert "agent:run-0" in daemon.steps(), "the agent was never reached"
    assert daemon.names() == [], "a box outlived the batch"
    watch.assert_scanned_once_the_box_was_gone()
    if docker == "carried":
        X.no_path_docker(daemon)
    if stop == "holds":
        assert got is None, got
        assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
        assert any(e.startswith("finish_batch:") for e in events), events
        return
    assert isinstance(got, BoxFault), got
    assert _git.git_head_sha(s.repo) == s.head, "a commit landed beside a box that would not stop"
    assert not any(e.startswith("finish_batch:") for e in events), events
    assert _failed(s) == [], "the claim was dead-lettered for a box that would not stop"


@pytest.mark.parametrize(("knob", "kind", "pointed"), X.BATCH_START_FAULTS)
def test_a_batch_start_fault_claims_nothing_and_dead_letters_nothing(
        tmp_path: Path, monkeypatch, knob: str, kind: type, pointed: bool):
    """`lead_author_drain` as production wires it, two claims and three pitfalls rows queued;
    the batch's box cannot be created, or a check at its creation fails: the fault escapes before
    any work (as on main: a `BoxFault` naming `origin/main @ <cut commit>`, a link ban as
    `AliasBanNotInForce`). No claim is claimed or charged an attempt (both markers as they
    were), none is dead-lettered, no agent runs, the pitfalls tick never runs and no row's
    attempts change, and nothing is committed or delivered."""
    s, daemon = _production_lead_scene(tmp_path, monkeypatch, "run-0", "run-1")
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(_system_rows(), paths=s.paths)
    attempts_before = _attempts(s.paths)
    qdir = s.paths.author_queue_dir
    markers_before = {p.name: p.read_bytes() for p in qdir.glob("*.json")}
    getattr(daemon, knob)()

    got, lanes, events, _watch = _production_lead_drain(
        s, daemon, lambda _rd: write(s.at(AGENT_NAME), VETTED))

    assert isinstance(got, kind), got
    assert (f"{X.POINTER}{s.head}" in str(got)) is pointed, got
    assert {p.name: p.read_bytes() for p in qdir.glob("*.json")} == markers_before, (
        "a claim was claimed or charged for a box that never came up")
    assert _claim_files(s)[1] == [], "a claim was claimed for a box that never came up"
    assert _failed(s) == []
    assert lanes.agent.calls == []
    assert lanes.pitfalls_ticks == 0
    assert _attempts(s.paths) == attempts_before
    assert _git.git_head_sha(s.repo) == s.head
    assert not any(e.startswith("finish_batch:") for e in events), events
    X.no_path_docker(daemon)
