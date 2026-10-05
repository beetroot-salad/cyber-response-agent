"""#1178/#1195: the lead-author drain lane runs each agent in a box of its own, and its gate admits
only plain files, judged by a no-follow stat.

The design (`gh issue view 1195`, amendment 2026-10-06) replaced #1178 amendment 2's freeze
(D1''-D3'': `pause_box`, `thawed`, `LeadAuthorDeps.thaw`, `run_pitfalls(thaw=)`) with one box
per agent run in both drain lanes. The `box` threaded through the lane is the batch's
`runtime.box.BoxSource`; each spawn site enters one run of it:

- the claim spawn, `lead_author._run_locked`: `with _box.box_for_run(box) as run_box: rc =
  deps.invoke_agent(..., box=run_box)`;
- the pitfalls spawn, `pitfalls_curator.run_pitfalls`: the same around its `invoke`.

Groups, each driven through a seam, never `monkeypatch.setattr`:

- The lanes (O2', E4): a recorded start/stop pair (`_box1195.Runs`) behind a source shows one
  run per agent, around exactly the spawn, the spawn handed that run's box; the host's steps
  before the agent, every read the gate makes (the lane's `tree_for`, logged) and the commit run
  with no box up; whatever the box writes during its run, up to its removal, is what the gate
  judges (O1). A run whose start fails (a `BoxFault`, or a link ban not in force, which the
  source surfaces as one) runs no agent and commits nothing (O4). The baseline of strays and
  the minted drafts' identities are taken before the box starts.
- The drain (O2', O4, E2): `_drain_lead_author(..., box=<source>)` runs one box per agent and
  none between; a claim's start fault halts the lane rather than dead-lettering the claim; and,
  through the production `lead_author_drain` over a fake daemon on `PATH`, a box a failed
  teardown left alive refuses the next claim's start before its agent runs, so nothing is
  committed or delivered.
- The plain-file rule (#1178 D4'', which stands): every non-deletion record the gate admits
  must be placed by a held mount and be a plain, single-name regular file there, by a no-follow
  stat (it reads no content). A symlink, a hard link or a FIFO at an address no content rule
  reads (a catalog draft, a system-skill draft, `queries/<sys>/README.md`, each also one folder
  deeper; the pitfalls lane's `execution.md`) is refused with HEAD unchanged; a plain file
  commits, an executable one at 100755, and so does a plain file that is not UTF-8 or is larger
  than any read takes. A `tree_for` that places no path refuses rather than falling back on the
  plain path.

`BoxSource` itself is in `test_1195_box_source.py`; the real-box row in
`test_1195_box_per_run_live.py`; the lessons lane in `test_1195_lessons_box_per_run.py`.
"""
from __future__ import annotations

import dataclasses
import logging
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender._io import READ_LIMIT
from defender._run_paths import RunPaths
from defender.learning.core import drains, markers, persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime.box import AliasBanNotInForce, BoxFault
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
    _deps,
    _run_dir,
    _worktree,
    draft_of,
)

LEAD = LEAD_AUTHOR_DRAIN_LABEL

#: The container name the recorded sources ask for (the drain's is `defender-drain-<batch id>`).
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
    """`LeadAuthorSpawn`, also recording the `box` each call was handed: the run's own box."""

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


def _runs(log: list, repo: Path, **kw: Any) -> X.Runs:
    """A recorded start/stop pair logging `("enter", HEAD)` / `("exit", HEAD)` into `log`."""
    return X.Runs(log, state=lambda: (_git.git_head_sha(repo),), **kw)


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


def _assert_one_run_holds_exactly_the_agent(
    log: list, runs: X.Runs, spawn: Any, *, head_before: str, head_after: str,
) -> None:
    """One run, holding the agent and nothing else, the agent handed that run's box; every host
    step before it, and every gate read and the commit after it, ran with no box up; the box
    was removed."""
    kinds = [e[0] for e in log]
    wins = X.windows(log)
    assert len(wins) == 1, kinds
    enter, leave = wins[0]
    assert kinds[enter + 1:leave] == ["agent"], f"the run holds more than the agent: {kinds}"
    assert "host" in kinds[:enter], f"no host step was seen before the run (vacuous): {kinds}"
    reads = [i for i, k in enumerate(kinds) if k == "read"]
    assert any(i > leave for i in reads), f"the gate read nothing after the run: {kinds}"
    assert head_after != head_before, "nothing was committed, so 'committed with no box up' is vacuous"
    assert log[leave][1] == head_before, "the commit was made while the box was up"
    assert len(runs.boxes) == 1, runs.boxes
    assert len(spawn.boxes) == 1, spawn.boxes
    assert spawn.boxes[0] is runs.boxes[0], "the agent was not handed the box its own run started"
    assert runs.alive == [], "the agent's box outlived its run"


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
        on_agent: Callable[[], object] | None = None,
) -> tuple[tuple, BoxSeenLeadSpawn]:
    """Drive `lead_author.run` over the scene: the agent (rc 0) leaves `text` at `name` as
    `kind`, and each of `more` (`{name: text}`) as a plain file, logging `("agent",)`. The
    lane's `tree_for` logs each path asked of it, and its pre-agent host seams (`extract`,
    `discover_system_drafts`, `build_handoff`) log `("host", name)`, into `log`. `box` is handed
    to `run` (a box source, or `None`); the spawn records the box it was handed. `on_agent` runs
    as the agent's last act. Returns the outcome and the spawn."""

    def leave(_run_dir: Path) -> None:
        _plant(s.at(name), text, kind, s.tmp / "outside")
        for other, other_text in (more or {}).items():
            _plant(s.at(other), other_text, "plain", s.tmp / "outside")
        log.append(("agent",))
        if on_agent is not None:
            on_agent()

    spawn = BoxSeenLeadSpawn(leave)
    with lead_trees(s.paths) as trees:
        deps = _deps(s.paths, trees, spawn, [ELASTIC_LEAD])
        deps = dataclasses.replace(
            deps, tree_for=_logging_tree_for(deps.tree_for, log),
            extract=_logged("extract", deps.extract, log),
            discover_system_drafts=_logged("discover_system_drafts",
                                           deps.discover_system_drafts, log),
            build_handoff=_logged("build_handoff", deps.build_handoff, log),
        )
        got = _outcome(lambda: lead_author.run(
            s.run_dir, label=LEAD, paths=s.paths, deps=deps, box=box))
    return got, spawn


def _run_lead(s: LeadScene, log: list, **kw: Any) -> tuple:
    """`_drive_lead`, for a drive whose agent is reached: the outcome."""
    got, spawn = _drive_lead(s, log, **kw)
    assert spawn.calls, f"the agent was never reached, so the gate never ran: {got}"
    return got



def test_the_lead_author_runs_its_agent_in_a_box_of_its_own(tmp_path: Path):
    """`run(deps=..., box=<a source>)`: the agent leaves a valid draft. One box is started after
    the host's pre-agent steps, holds the agent alone (which is handed that box), and is removed
    before the gate's first read and the commit. HEAD holds the draft."""
    s = _lead_scene(tmp_path)
    log: list = []
    runs = _runs(log, s.repo)
    got, spawn = _drive_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs.source(NAME))
    assert got == ("returned", 0), got
    head = _git.git_head_sha(s.repo)
    _assert_one_run_holds_exactly_the_agent(log, runs, spawn, head_before=s.head, head_after=head)
    assert [r.name for r in runs.requests] == [NAME]
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED


@pytest.mark.parametrize("at_removal", ["refused", "variant"])
def test_the_lead_author_gate_judges_what_the_box_wrote_during_its_run(
        tmp_path: Path, at_removal: str):
    """The box rewrites the agent's file on its run's way out, before its removal: with refused
    bytes the gate refuses (`LeadAuthorError`, HEAD unchanged, nothing staged); with valid
    different bytes (the control) those bytes are what HEAD holds. The gate sees everything the
    box did during its run."""
    s = _lead_scene(tmp_path)
    log: list = []
    bytes_out = REFUSED if at_removal == "refused" else VARIANT
    runs = _runs(log, s.repo, on_stop=lambda _b: write(s.at(AGENT_NAME), bytes_out))
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs.source(NAME))
    if at_removal == "variant":
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
        tmp_path: Path, name: str, text: str, says: str | None):
    """The box writes a NEW path beside the agent's vetted draft on its run's way out: a draft
    whose id disagrees with its folder, or a non-`.md` file under `skills/`, is refused (HEAD
    unchanged, nothing staged); an admissible new draft (the control) is judged and committed
    with the rest."""
    s = _lead_scene(tmp_path)
    log: list = []
    runs = _runs(log, s.repo, on_stop=lambda _b: write(s.at(name), text))
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs.source(NAME))
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


#: A start that fails: the box won't come up (`BoxFault`), or the link ban is not in force
#: (`AliasBanNotInForce`, which the source surfaces as a `BoxFault` chained to it).
START_FAULTS = [
    pytest.param(lambda: BoxFault("a container named it already exists and is running"),
                 id="box-fault"),
    pytest.param(lambda: AliasBanNotInForce("the alias ban is not in force under runsc"),
                 id="alias-ban"),
]


@pytest.mark.parametrize("fault", START_FAULTS)
def test_a_lead_author_start_fault_runs_no_agent_and_commits_nothing(tmp_path: Path, fault: Any):
    """The run's start fails: `run` raises `BoxFault`; the agent never ran, the gate read nothing,
    HEAD is unchanged, nothing is staged, and the run is not recorded done. Control:
    `test_the_lead_author_runs_its_agent_in_a_box_of_its_own` (a start that holds)."""
    s = _lead_scene(tmp_path)
    log: list = []
    runs = _runs(log, s.repo, start_faults={1: fault()})
    got, spawn = _drive_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs.source(NAME))
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the agent ran though its box never started"
    assert [e for e in log if e[0] == "read"] == [], "the gate ran though the box never started"
    assert _git.git_head_sha(s.repo) == s.head
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
        on_agent: Callable[[], object] | None = None,
) -> tuple[tuple, BoxSeenSpawn]:
    """Drive `run_pitfalls` over the scene: the curator (rc 0) leaves `text` at `rel` as `kind`,
    and each of `more` (`{rel: text}`) as a plain file, logging `("agent",)`. The trees log the
    lane's first host step and each `tree_for` call into `log`. `box` is handed to `run_pitfalls`
    (a box source, or `None`); the spawn records the box it was handed. `on_agent` runs as the
    curator's last act. Returns the outcome and the spawn."""

    def curate(_root: Path) -> None:
        _plant(s.at(rel), text, kind, s.tmp / "outside")
        for other, other_text in (more or {}).items():
            _plant(s.at(other), other_text, "plain", s.tmp / "outside")
        log.append(("agent",))
        if on_agent is not None:
            on_agent()

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



def test_the_pitfalls_tick_runs_its_curator_in_a_box_of_its_own(tmp_path: Path, monkeypatch):
    """`run_pitfalls(box=<a source>)`: the curator appends a pitfall to the reducer surface. One
    box is started after the tick's first host step, holds the curator alone (which is handed
    that box), and is removed before the gate's first read and the commit."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    runs = _runs(log, s.repo)
    got, spawn = _drive_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED,
                                 box=runs.source(NAME))
    assert got == ("returned", 0), got
    head = _git.git_head_sha(s.repo)
    _assert_one_run_holds_exactly_the_agent(log, runs, spawn, head_before=s.head, head_after=head)
    assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED


@pytest.mark.parametrize("at_removal", ["refused", "variant"])
def test_the_pitfalls_gate_judges_what_the_box_wrote_during_its_run(
        tmp_path: Path, monkeypatch, at_removal: str):
    """The box rewrites the reducer surface on its run's way out: refused bytes (a rewritten
    frontmatter block) are refused with HEAD unchanged and nothing staged; valid different bytes
    (the control) are what HEAD holds."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    bytes_out = REDUCER_REFUSED if at_removal == "refused" else REDUCER_VARIANT
    runs = _runs(log, s.repo, on_stop=lambda _b: write(s.at(REDUCER_REL), bytes_out))
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, box=runs.source(NAME))
    if at_removal == "variant":
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
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    runs = _runs(log, s.repo, on_stop=lambda _b: write(s.at(rel), text))
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, box=runs.source(NAME))
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
        tmp_path: Path, monkeypatch, fault: Any):
    """The run's start fails: `run_pitfalls` raises `BoxFault`; the curator never ran, the gate
    read nothing, HEAD is unchanged, nothing is staged, and every queued row is still queued."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    queued = _queued(s)
    log: list = []
    runs = _runs(log, s.repo, start_faults={1: fault()})
    got, spawn = _drive_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED,
                                 box=runs.source(NAME))
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the curator ran though its box never started"
    assert [e for e in log if e[0] == "read"] == [], "the gate ran though the box never started"
    assert _git.git_head_sha(s.repo) == s.head
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
# The host's steps before the agent run before its box starts: the baseline and the mint
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
def test_a_lead_author_stray_the_box_writes_once_started_is_refused(tmp_path: Path, when: str):
    """The box rewrites a committed file outside `skills/` as soon as it is up: the gate refuses
    the claim ("changed files outside", naming it), HEAD unchanged, nothing staged. The lane's
    baseline of strays was taken before the box started, so the rewrite is new. Control: the
    same rewrite already standing before the run is in the baseline, and the claim commits
    (without it)."""
    s = _lead_scene(tmp_path)
    s = dataclasses.replace(s, head=_commit_stray(s.repo))
    stray = s.repo / STRAY_REL
    log: list = []
    if when == "before-the-run":
        write(stray, STRAY_EDIT)
    runs = _runs(log, s.repo, on_start=(lambda _b: write(stray, STRAY_EDIT))
                 if when == "once-started" else None)
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs.source(NAME))
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
    box starts."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    s = dataclasses.replace(s, head=_commit_stray(s.repo))
    stray = s.repo / STRAY_REL
    log: list = []
    if when == "before-the-run":
        write(stray, STRAY_EDIT)
    runs = _runs(log, s.repo, on_start=(lambda _b: write(stray, STRAY_EDIT))
                 if when == "once-started" else None)
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, box=runs.source(NAME))
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
        tmp_path: Path, box_does: str):
    """The tick mints an untracked draft for the run's lead, then starts the box, which removes
    that draft at once. The identities the draft recorded were captured before the box started,
    so its departure is seen and refused (`LeadAuthorError`, "without attributing it", naming the
    draft), HEAD unchanged. Control: the box leaves the draft, and it is committed with the
    agent's file."""
    s = _lead_scene(tmp_path)
    minted_name, _text = draft_of(ELASTIC_LEAD)
    minted = s.at(minted_name)
    log: list = []

    def on_start(_box: Any) -> None:
        assert minted.is_file(), "nothing was minted, so its departure is vacuous"
        if box_does == "removes-it":
            minted.unlink()

    runs = _runs(log, s.repo, on_start=on_start)
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs.source(NAME))
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
# The drain: one box per agent, none between; a start fault halts the lane
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
    the box the drain handed down. `pitfalls_ticks` counts the pitfalls ticks."""

    def __init__(self, agent: BoxSeenLeadSpawn, curator: BoxSeenSpawn | None = None) -> None:
        self.agent, self.curator = agent, curator
        self.pitfalls_ticks = 0

    def run_lead(self, paths: LoopPaths, run_dir: Path, *, box: Any = None, on_done: Any,
                 **_kw: Any) -> int:
        with lead_trees(paths) as trees:
            deps = _deps(paths, trees, self.agent, [ELASTIC_LEAD])
            return lead_author.run(run_dir, label=LEAD, paths=paths, deps=deps, box=box,
                                   on_done=on_done)

    def run_pitfalls(self, paths: LoopPaths, *, box: Any = None, on_curated: Any,
                     **_kw: Any) -> int:
        self.pitfalls_ticks += 1
        if self.curator is None:
            return 0
        with lead_trees(paths) as trees:
            return pitfalls_curator.run_pitfalls(paths=paths, trees=trees, invoke=self.curator,
                                                 box=box, on_curated=on_curated)


def _failed(s: LeadScene) -> list[str]:
    """The names of the claims the lane dead-lettered."""
    failed = s.paths.author_queue_dir / markers.FAILED_MARKER_DIRNAME
    return sorted(p.name for p in failed.glob("*.json")) if failed.is_dir() else []


def test_the_lead_drain_runs_one_box_per_agent_and_none_between(tmp_path: Path, monkeypatch):
    """`_drain_lead_author(..., box=<a source>)` serving one claim and one pitfalls tick through
    the real lanes: exactly two runs, the claim's agent and the pitfalls curator, each holding its
    spawn alone, each a fresh box from the one request, each handed to its spawn; no box is up
    between them (the claim's reset, the pitfalls tick's host steps) or after the last; HEAD is
    the same at each run's exit as at its entry; both lanes committed."""
    s = _lead_scene(tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(_system_rows(), paths=s.paths)
    _queue_claims(s, "run-0")
    log: list = []

    def author(_run_dir: Path) -> None:
        write(s.at(AGENT_NAME), VETTED)
        log.append(("agent",))

    def curate(root: Path) -> None:
        write(root / EXECUTION_REL, EXECUTION_TEXT)
        log.append(("curator",))

    lanes = Lanes(BoxSeenLeadSpawn(author), BoxSeenSpawn(curate))
    runs = _runs(log, s.repo)

    drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls,
                              box=runs.source(NAME))

    X.assert_each_run_holds_exactly(log, ["agent", "curator"], ("agent", "curator"))
    assert len(lanes.agent.boxes) == 1, lanes.agent.boxes
    assert len(lanes.curator.boxes) == 1, lanes.curator.boxes
    assert lanes.agent.boxes[0] is runs.boxes[0], "the agent was not handed its own run's box"
    assert lanes.curator.boxes[0] is runs.boxes[1], "the curator was not handed its own run's box"
    assert [r.name for r in runs.requests] == [NAME, NAME]
    assert runs.alive == []
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
    assert _git.git_show_file(s.repo, "HEAD", EXECUTION_REL) == EXECUTION_TEXT


@pytest.mark.parametrize("fault", START_FAULTS)
def test_a_claims_start_fault_halts_the_lane_and_dead_letters_nothing(
        tmp_path: Path, fault: Any):
    """Two claims queued; the first claim's run cannot start (the box won't come up, or the link
    ban is not in force): a `BoxFault` escapes `_drain_lead_author`. The first claim's agent never
    ran, the second claim is never served, the pitfalls tick never runs, nothing is committed,
    and no claim is dead-lettered (both stay queued for the next tick). Control: the next row."""
    s = _lead_scene(tmp_path)
    _queue_claims(s, "run-0", "run-1")
    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)))
    injected = fault()
    runs = _runs([], s.repo, start_faults={1: injected})

    got = X.caught(lambda: drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls,
                                                     box=runs.source(NAME)))

    assert isinstance(got, BoxFault), got
    assert injected in X.chain(got), X.chain(got)
    assert lanes.agent.calls == [], "an agent ran though its box never started"
    assert len(runs.requests) == 1, "the lane went on to serve another claim"
    assert lanes.pitfalls_ticks == 0, "the pitfalls tick ran after a box fault"
    assert _failed(s) == [], "a claim was dead-lettered for a box that would not start"
    assert _git.git_head_sha(s.repo) == s.head


def test_control_a_claims_agent_fault_dead_letters_that_claim_and_the_next_is_served(
        tmp_path: Path):
    """The first claim's agent fails (`LeadAuthorError`, not a box fault): that claim is
    dead-lettered, and the second is served in a box of its own and committed."""
    s = _lead_scene(tmp_path)
    _queue_claims(s, "run-0", "run-1")
    log: list = []

    def author(run_dir: Path) -> None:
        log.append(("agent",))
        if run_dir.name == "run-0":
            raise LeadAuthorError("the agent failed")
        write(s.at(AGENT_NAME), VETTED)

    lanes = Lanes(BoxSeenLeadSpawn(author))
    runs = _runs(log, s.repo)

    drains._drain_lead_author(s.paths, lanes.run_lead, lanes.run_pitfalls, box=runs.source(NAME))

    X.assert_each_run_holds_exactly(log, ["agent", "agent"], ("agent",))
    assert _failed(s) == ["case-run-0.json"], _failed(s)
    assert runs.alive == []
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED


# ---------------------------------------------------------------------------------------
# E2 through the production drain: real start/stop over a fake daemon
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("teardown", ["refused", "holds"])
def test_a_box_a_failed_teardown_left_alive_refuses_the_next_claims_run(
        tmp_path: Path, monkeypatch, caplog, teardown: str):
    """`lead_author_drain` as production wires it (its own `start_box`/`stop_box` and its
    source's status probe reaching a fake daemon on `PATH`; only the lanes and the branch
    injected), two claims queued. The first claim's agent fails (`LeadAuthorError`, which
    dead-letters that claim); with `refused`, the removal of its box fails on the way out, so
    that teardown fault is only logged under the agent's failure and the box stays running. The
    second claim's start then meets the batch's name still running and raises `BoxFault` before
    its agent: nothing is committed, the pitfalls tick never runs, nothing is delivered, and the
    second claim is not dead-lettered.

    Control (`holds`): the removal takes; the second claim is served in a fresh box and
    committed, and the batch is delivered. Each agent ran in a container of its own, created
    after the drain started serving and removed after the agent; none is left."""
    caplog.set_level(logging.WARNING)
    X.clear_opt_out(monkeypatch)
    s = _lead_scene(tmp_path)
    X.plant_image_inputs(s.repo)
    s = dataclasses.replace(s, head=commit_all(s.repo, "the box image inputs"))
    _queue_claims(s, "run-0", "run-1")
    daemon = X.FakeDaemon(tmp_path)
    daemon.install(monkeypatch)

    def author(run_dir: Path) -> None:
        daemon.mark(f"agent:{run_dir.name}")
        if run_dir.name == "run-0":
            if teardown == "refused":
                daemon.refuse_rm(1)
            raise LeadAuthorError("the agent failed")
        write(s.at(AGENT_NAME), VETTED)

    lanes = Lanes(BoxSeenLeadSpawn(author))
    events: list[str] = []
    branch = RepoBranch(s.repo, branch_prefix="lead-author/", events=events)

    got = X.caught(lambda: drains.lead_author_drain(
        s.paths, run_lead_author=lanes.run_lead, run_pitfalls=lanes.run_pitfalls, branch=branch,
        scrub=lambda *_a, **_k: None))

    assert _failed(s)[:1] == ["case-run-0.json"], _failed(s)
    kept = [x for x in daemon.steps() if x in ("create", "rm") or x.startswith("agent:")]
    if teardown == "holds":
        assert got is None, got
        assert kept == ["create", "agent:run-0", "rm", "create", "agent:run-1", "rm"], kept
        assert daemon.names() == [], "a box outlived the batch"
        assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
        assert any(e.startswith("finish_batch:") for e in events), events
        return
    assert isinstance(got, BoxFault), got
    assert kept[:3] == ["create", "agent:run-0", "rm"], kept
    assert "agent:run-1" not in kept, f"the second claim's agent ran beside a live box: {kept}"
    assert len(daemon.created()) == 1, "a second box was created beside the live one"
    assert _failed(s) == ["case-run-0.json"], "the second claim was dead-lettered for a box fault"
    assert lanes.pitfalls_ticks == 0
    assert _git.git_head_sha(s.repo) == s.head, "a commit landed beside a live box"
    assert not any(e.startswith("finish_batch:") for e in events), events
