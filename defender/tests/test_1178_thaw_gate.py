"""#1178 amendment 2: the lead-author lane's box is frozen unless an agent is running, and the
gate admits only plain files, judged by a no-follow stat.

Three groups, each driven through a seam, never `monkeypatch.setattr`:

- The drain (D3''): `drains._drain_lead_author(..., pause=)` freezes the batch's box, the one it
  was handed, before it serves the first claim (or, with none queued, before the pitfalls
  tick), and a pause that cannot be proven halts the batch before any lane runs. The default
  `pause` is the real `runtime.box.pause_box`.
- The lanes (D3''): `LeadAuthorDeps.thaw` and `run_pitfalls(thaw=)`, each an injected recording
  thaw, wrap exactly the agent spawn, once per claim / tick, handed the entry point's box. The
  host's steps before the agent, every read the gate makes (the lane's `tree_for`, logged) and
  the commit run with no thaw active; whatever the box writes while thawed, up to the moment
  the re-freeze returns, is what the gate judges. A thaw that cannot be entered runs no agent
  and commits nothing. With the thaw injected, a sandboxed box naming no container commits:
  nothing else in the lane touches the box. Both seams default to the real `runtime.box.thawed`,
  which refuses a box it cannot show running before the agent is reached. The host's steps
  before the agent (the baseline of strays, the minted drafts' identities) are taken frozen:
  what the box does once thawed is judged against them. Over a `docker` shim on `PATH`, the
  default seams of both lanes, of `_drain_lead_author` and of the production
  `lead_author_drain` make exactly the proven freezes and thaws, and leave the box paused.
- The plain-file rule (D4''): every non-deletion record the gate admits must be placed by a held
  mount and be a plain, single-name regular file there, by a no-follow stat (it reads no
  content). A symlink, a hard link or a FIFO at an address no content rule reads (a catalog
  draft, a system-skill draft, `queries/<sys>/README.md`, each also one folder deeper; the
  pitfalls lane's `execution.md`) is refused with HEAD unchanged; a plain file commits, an
  executable one at 100755, and so does a plain file that is not UTF-8 or is larger than any
  read takes. A `tree_for` that places no path refuses rather than falling back on the plain
  path.

`pause_box`/`thawed` themselves are in `test_1178_box_pause.py`; the real-box row in
`test_1178_frozen_box.py`.
"""
from __future__ import annotations

import contextlib
import dataclasses
import inspect
import json
import os
import shutil
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender._io import READ_LIMIT
from defender.run_repository import RunPaths
from defender.learning.core import drains, markers, persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime import box as box_mod
from defender.runtime.box import BoxExecutor, BoxFault, BoxSpec, _DockerTransport
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
from defender.tests._spec791 import SpecBranch, loop_paths, noop_scrub, noop_stop_box
from defender.tests.test_1134_lead_author_handle import (
    ELASTIC_LEAD,
    _deps,
    _run_dir,
    _worktree,
    draft_of,
)
from defender.tests.test_1178_box_pause import PAUSED, THAWED, DockerShim

LEAD = LEAD_AUTHOR_DRAIN_LABEL


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


def _absent_box() -> BoxExecutor:
    """A sandboxed box (the docker transport) naming a container no daemon holds: the real
    `pause_box`/`thawed` cannot prove it frozen or running, whether or not a docker binary or
    daemon is there to ask."""
    name = f"defender-drain-t1178-absent-{uuid.uuid4().hex[:12]}"
    spec = BoxSpec()
    return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name)


@pytest.fixture(params=["path-as-is", "no-docker-on-path"])
def docker_on_path(request, tmp_path: Path, monkeypatch) -> str:
    """The real seam's two environments: `PATH` as the run found it (a docker binary, and a
    daemon, where the host has them), and a `PATH` holding only `git`, so the seam finds no
    docker binary at all."""
    if request.param == "no-docker-on-path":
        git = shutil.which("git")
        assert git is not None, "these rows drive real git"
        bin_dir = tmp_path / "bin-git-only"
        bin_dir.mkdir()
        (bin_dir / "git").symlink_to(git)
        monkeypatch.setenv("PATH", str(bin_dir))
        assert shutil.which("docker") is None
    return request.param


# ---------------------------------------------------------------------------------------
# The drain: `_drain_lead_author(..., pause=)` freezes the box before the lane's first step
# ---------------------------------------------------------------------------------------


def _drain_scene(tmp_path: Path, claims: int) -> LoopPaths:
    """A committed worktree with `claims` lead-author requests queued, each naming a run dir."""
    repo = seed_tree(tmp_path, adapters=("elastic",), markers=("elastic",), skills=("elastic",),
                     catalog=("elastic",))
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    for i in range(claims):
        run_dir = tmp_path / f"run-{i}"
        (run_dir / "gather_raw").mkdir(parents=True)
        write(paths.author_queue_dir / f"case-{i}.json",
              json.dumps({"case_id": f"case-{i}", "run_dir": str(run_dir)}) + "\n")
    return paths


class DrainLanes:
    """The drain's three injected steps, logging into one list: `pause(box)` as
    `("pause", box)`, each lead-author serve as `("serve", box)`, the pitfalls tick as
    `("pitfalls", box)`. `pause_fault` is raised by the pause after it is logged."""

    def __init__(self, *, pause_fault: BaseException | None = None) -> None:
        self.log: list[tuple[str, Any]] = []
        self.pause_fault = pause_fault

    def pause(self, box: Any) -> None:
        self.log.append(("pause", box))
        if self.pause_fault is not None:
            raise self.pause_fault

    def run_lead_author(self, _paths: LoopPaths, _run_dir: Path, *, box: Any = None,
                        **_kw: Any) -> None:
        self.log.append(("serve", box))

    def run_pitfalls(self, _paths: LoopPaths, *, box: Any = None, **_kw: Any) -> int:
        self.log.append(("pitfalls", box))
        return 0

    def drain(self, paths: LoopPaths, box: Any) -> Any:
        return drains._drain_lead_author(
            paths, self.run_lead_author, self.run_pitfalls, box=box, pause=self.pause,
        )


def test_the_drain_freezes_its_box_before_the_first_claim(tmp_path: Path):
    """Two queued claims: the first thing the drain does with the box is `pause(box)`, with the
    very box it was handed, before either serve; both claims are then served with that box."""
    paths = _drain_scene(tmp_path, claims=2)
    lanes, box = DrainLanes(), object()
    lanes.drain(paths, box)
    kinds = [k for k, _ in lanes.log]
    assert kinds.count("serve") == 2, lanes.log
    assert kinds[0] == "pause", f"a claim was served before the box was frozen: {kinds}"
    assert lanes.log[0][1] is box, "the drain froze some other box"
    assert all(b is box for k, b in lanes.log if k == "serve"), lanes.log


def test_the_drain_freezes_its_box_before_the_pitfalls_tick_with_no_claim_queued(
        tmp_path: Path):
    """Nothing queued for the lead author: the pitfalls tick is the lane's first step, and the
    box is frozen before it."""
    paths = _drain_scene(tmp_path, claims=0)
    lanes, box = DrainLanes(), object()
    lanes.drain(paths, box)
    kinds = [k for k, _ in lanes.log]
    assert "pitfalls" in kinds, f"the pitfalls tick never ran, so the order is vacuous: {kinds}"
    assert kinds[0] == "pause", f"the pitfalls tick ran before the box was frozen: {kinds}"
    assert lanes.log[0][1] is box


def test_a_pause_that_cannot_be_proven_halts_the_drain_before_any_lane(tmp_path: Path):
    """`pause` raises `BoxFault`: it propagates out of the drain, and neither a claim nor the
    pitfalls tick runs. Control: the first drain row (the same queue, a pause that holds)."""
    paths = _drain_scene(tmp_path, claims=1)
    fault = BoxFault("the box did not report paused")
    lanes = DrainLanes(pause_fault=fault)
    with pytest.raises(BoxFault) as got:
        lanes.drain(paths, object())
    assert got.value is fault
    assert [k for k, _ in lanes.log] == ["pause"], lanes.log


def test_the_drains_default_pause_is_runtime_box_pause_box():
    default = inspect.signature(drains._drain_lead_author).parameters["pause"].default
    assert default is box_mod.pause_box


# ---------------------------------------------------------------------------------------
# The fakes the lane rows inject
# ---------------------------------------------------------------------------------------


class Thaw:
    """The injected `thaw` seam: `thaw(box)` returns a context manager. It records each box it
    is handed, logs `("enter",)` and `("exit", <HEAD sha as the thaw returns>)` into the drive's
    shared log, and optionally raises `fault` on the way in (the box could not be shown
    running), runs `on_enter` once it is in (the box's first writes, once running), or runs
    `on_exit` on the way out, INSIDE the thaw, before it returns: the box's last writes before
    the re-freeze took hold."""

    def __init__(self, log: list, repo: Path, *, on_enter: Callable[[], object] | None = None,
                 on_exit: Callable[[], object] | None = None,
                 fault: BaseException | None = None) -> None:
        self.log = log
        self.repo = repo
        self.on_enter = on_enter
        self.on_exit = on_exit
        self.fault = fault
        self.boxes: list[Any] = []

    def __call__(self, box: Any) -> contextlib.AbstractContextManager[None]:
        self.boxes.append(box)
        return self._held()

    @contextlib.contextmanager
    def _held(self):
        self.log.append(("enter",))
        if self.fault is not None:
            raise self.fault
        if self.on_enter is not None:
            self.on_enter()
        try:
            yield
        finally:
            if self.on_exit is not None:
                self.on_exit()
            self.log.append(("exit", _git.git_head_sha(self.repo)))


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


def _assert_thawed_exactly_around_the_agent(
    log: list, thaw: Thaw, box: Any, *, head_before: str, head_after: str,
) -> None:
    """One thaw, handed the entry point's box, holding the agent and nothing else: every host
    step before it, and every gate read and the commit after it, ran with no thaw active."""
    kinds = [e[0] for e in log]
    assert kinds.count("enter") == 1, kinds
    assert kinds.count("exit") == 1, kinds
    enter, leave = kinds.index("enter"), kinds.index("exit")
    assert kinds[enter + 1:leave] == ["agent"], f"the thaw holds more than the agent: {kinds}"
    assert "host" in kinds[:enter], f"no host step was seen before the thaw (vacuous): {kinds}"
    reads = [i for i, k in enumerate(kinds) if k == "read"]
    assert any(i > leave for i in reads), f"the gate read nothing after the thaw: {kinds}"
    assert head_after != head_before, "nothing was committed, so 'committed frozen' is vacuous"
    assert log[leave][1] == head_before, "the commit was made while the box was thawed"
    assert len(thaw.boxes) == 1, thaw.boxes
    assert thaw.boxes[0] is box, thaw.boxes


# ---------------------------------------------------------------------------------------
# The lead-author lane's drive: `run(label=, deps=)`, the agent leaving one file
# ---------------------------------------------------------------------------------------

#: The agent's file in the wiring rows: a catalog draft whose `id:` the gate reads (the path
#: rule's directory check), so the gate's verdict depends on the bytes it read.
AGENT_NAME = "gather/queries/wazuh/_draft/w1178.md"
VETTED = query_template("wazuh.w1178", "draft")
#: Valid too, but different bytes: what the box leaves while still thawed.
VARIANT = VETTED.replace("wazuh auth events.", "wazuh auth events, rewritten while thawed.")
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
        thaw: Thaw | None = None, box: Any = None, more: dict[str, str] | None = None,
        on_agent: Callable[[], object] | None = None,
) -> tuple[tuple, LeadAuthorSpawn]:
    """Drive `lead_author.run` over the scene: the agent (rc 0) leaves `text` at `name` as
    `kind`, and each of `more` (`{name: text}`) as a plain file, logging `("agent",)`. The
    lane's `tree_for` logs each path asked of it, and its pre-agent host seams (`extract`,
    `discover_system_drafts`, `build_handoff`) log `("host", name)`, into `log`; with `thaw`,
    it is injected as `deps.thaw`. `on_agent` runs as the agent's last act. Returns the outcome
    and the spawn."""

    def leave(_run_dir: Path) -> None:
        _plant(s.at(name), text, kind, s.tmp / "outside")
        for other, other_text in (more or {}).items():
            _plant(s.at(other), other_text, "plain", s.tmp / "outside")
        log.append(("agent",))
        if on_agent is not None:
            on_agent()

    spawn = LeadAuthorSpawn(leave)
    with lead_trees(s.paths) as trees:
        deps = _deps(s.paths, trees, spawn, [ELASTIC_LEAD])
        deps = dataclasses.replace(
            deps, tree_for=_logging_tree_for(deps.tree_for, log),
            extract=_logged("extract", deps.extract, log),
            discover_system_drafts=_logged("discover_system_drafts",
                                           deps.discover_system_drafts, log),
            build_handoff=_logged("build_handoff", deps.build_handoff, log),
        )
        if thaw is not None:
            deps = dataclasses.replace(deps, thaw=thaw)
        got = _outcome(lambda: lead_author.run(
            s.run_dir, label=LEAD, paths=s.paths, deps=deps, box=box))
    return got, spawn


def _run_lead(s: LeadScene, log: list, **kw: Any) -> tuple:
    """`_drive_lead`, for a drive whose agent is reached: the outcome."""
    got, spawn = _drive_lead(s, log, **kw)
    assert spawn.calls, f"the agent was never reached, so the gate never ran: {got}"
    return got


def test_the_production_thaw_is_runtime_box_thawed(tmp_path: Path):
    """Both seams default to the real `runtime.box.thawed`: the deps the lane builds for itself,
    and `run_pitfalls`' `thaw=` default."""
    s = _lead_scene(tmp_path)
    with lead_trees(s.paths) as trees:
        deps = lead_author.build_lead_author_deps(s.paths, trees=trees)
        assert deps.thaw is box_mod.thawed
    default = inspect.signature(pitfalls_curator.run_pitfalls).parameters["thaw"].default
    assert default is box_mod.thawed


def test_the_lead_author_default_thaw_runs_no_agent_in_a_box_it_cannot_show_running(
        tmp_path: Path, docker_on_path: str):
    """`run(deps=<the lane's own thaw>, box=<sandboxed, no such container>)`: the default seam
    asks the real docker to unpause the box, which fails (no binary, no daemon, or no such
    container), so the run raises `BoxFault` before the agent is called; HEAD unchanged,
    nothing staged. A thaw entered after the agent (or none) would reach the spawn first."""
    s = _lead_scene(tmp_path)
    got, spawn = _drive_lead(s, [], name=AGENT_NAME, text=VETTED, box=_absent_box())
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the agent ran in a box never shown running"
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)


def test_the_lead_author_thaws_exactly_around_its_agent(tmp_path: Path):
    """`run(deps=<thaw injected>, box=<sentinel>)`: the agent leaves a valid draft. The thaw is
    entered after the host's pre-agent steps, holds the agent alone, and has returned before
    the gate's first read and the commit; once, handed the sentinel box. HEAD holds the draft."""
    s = _lead_scene(tmp_path)
    log: list = []
    box = object()
    thaw = Thaw(log, s.repo)
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, thaw=thaw, box=box)
    assert got == ("returned", 0), got
    head = _git.git_head_sha(s.repo)
    _assert_thawed_exactly_around_the_agent(log, thaw, box, head_before=s.head, head_after=head)
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED


def test_nothing_but_the_lead_author_thaw_touches_the_box(tmp_path: Path):
    """The thaw injected (it does nothing), the box a sandboxed one naming no container: the run
    commits. Anything else in the lane that asked docker about the box (a freeze left around the
    gate, a pause before the commit) would raise `BoxFault` here."""
    s = _lead_scene(tmp_path)
    log: list = []
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, thaw=Thaw(log, s.repo),
                    box=_absent_box())
    assert got == ("returned", 0), got
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED


@pytest.mark.parametrize("on_exit", ["refused", "variant"])
def test_the_lead_author_gate_judges_what_the_box_wrote_while_thawed(
        tmp_path: Path, on_exit: str):
    """The box rewrites the agent's file on the thaw's way out, before the re-freeze returns:
    with refused bytes the gate refuses (`LeadAuthorError`, HEAD unchanged, nothing staged);
    with valid different bytes (the control) those bytes are what HEAD holds. The gate sees
    everything the box did while thawed."""
    s = _lead_scene(tmp_path)
    log: list = []
    bytes_out = REFUSED if on_exit == "refused" else VARIANT
    thaw = Thaw(log, s.repo, on_exit=lambda: write(s.at(AGENT_NAME), bytes_out))
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, thaw=thaw, box=object())
    if on_exit == "variant":
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VARIANT
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert REFUSED_SAYS in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "the refused bytes were committed"
    assert _nothing_staged(s.repo)


#: Paths the box first writes on the thaw's way out: never the agent's, so only a gate that
#: lists the batch after the re-freeze sees them. `None`: admitted and committed.
LEAD_THAWED_WRITES = [
    pytest.param("gather/queries/wazuh/_draft/new1178.md", query_template("elastic.new1178", "draft"),
                 REFUSED_SAYS, id="new-md-refused"),
    pytest.param("gather/queries/wazuh/evil1178.txt", "not markdown\n", "outside", id="new-non-md"),
    pytest.param("gather/queries/wazuh/_draft/new1178.md", query_template("wazuh.new1178", "draft"),
                 None, id="new-md-admissible"),
]


@pytest.mark.parametrize(("name", "text", "says"), LEAD_THAWED_WRITES)
def test_a_lead_author_path_the_box_wrote_while_thawed_is_judged(
        tmp_path: Path, name: str, text: str, says: str | None):
    """The box writes a NEW path beside the agent's vetted draft on the thaw's way out: a draft
    whose id disagrees with its folder, or a non-`.md` file under `skills/`, is refused (HEAD
    unchanged, nothing staged); an admissible new draft (the control) is judged and committed
    with the rest."""
    s = _lead_scene(tmp_path)
    log: list = []
    thaw = Thaw(log, s.repo, on_exit=lambda: write(s.at(name), text))
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, thaw=thaw, box=object())
    if says is None:
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", s.rel(name)) == text
        assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert says in got[2], got
    assert s.rel(name) in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "a path written while thawed was committed"
    assert _nothing_staged(s.repo)


def test_a_lead_author_thaw_that_faults_runs_no_agent_and_commits_nothing(tmp_path: Path):
    """The thaw's way in raises `BoxFault` (the box could not be shown running): it propagates
    through `run`; the agent never ran, the gate read nothing, HEAD is unchanged, nothing is
    staged, and the run is not recorded done. Control: the exact-wrap row (a thaw that holds)."""
    s = _lead_scene(tmp_path)
    log: list = []
    thaw = Thaw(log, s.repo, fault=BoxFault("the box did not report running"))
    got, spawn = _drive_lead(s, log, name=AGENT_NAME, text=VETTED, thaw=thaw, box=object())
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the agent ran though the thaw failed"
    assert [e for e in log if e[0] == "read"] == [], "the gate ran though the thaw failed"
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)
    assert not (RunPaths(s.run_dir).lead_author / "done").exists()


# ---------------------------------------------------------------------------------------
# The pitfalls lane's drive: `run_pitfalls(trees=, invoke=)`
# ---------------------------------------------------------------------------------------

#: The curator's edit in the wiring rows: one pitfall under the reducer's `## Common pitfalls`,
#: a document the content rule reads and accepts (`_readable_pair` reads it through `tree_for`).
REDUCER_VETTED = reducer_surface_text(bullets=("keep the unnest argument a LIST",))
REDUCER_VARIANT = reducer_surface_text(bullets=("a different pitfall, written while thawed",))
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
        thaw: Thaw | None = None, box: Any = None, more: dict[str, str] | None = None,
        on_agent: Callable[[], object] | None = None,
) -> tuple[tuple, Spawn]:
    """Drive `run_pitfalls` over the scene: the curator (rc 0) leaves `text` at `rel` as `kind`,
    and each of `more` (`{rel: text}`) as a plain file, logging `("agent",)`. The trees log the
    lane's first host step and each `tree_for` call into `log`; with `thaw`, it is passed as
    `thaw=`. `on_agent` runs as the curator's last act. Returns the outcome and the spawn."""

    def curate(_root: Path) -> None:
        _plant(s.at(rel), text, kind, s.tmp / "outside")
        for other, other_text in (more or {}).items():
            _plant(s.at(other), other_text, "plain", s.tmp / "outside")
        log.append(("agent",))
        if on_agent is not None:
            on_agent()

    spawn = Spawn(curate)
    with lead_trees(s.paths) as trees:
        seam = {} if thaw is None else {"thaw": thaw}
        got = _outcome(lambda: pitfalls_curator.run_pitfalls(
            paths=s.paths, trees=LoggedTrees(trees, log), invoke=spawn, box=box, **seam))
    return got, spawn


def _run_pitfalls(s: PitfallsScene, log: list, **kw: Any) -> tuple:
    """`_drive_pitfalls`, for a drive whose curator is reached: the outcome."""
    got, spawn = _drive_pitfalls(s, log, **kw)
    assert spawn.calls, f"the curator was never reached, so the gate never ran: {got}"
    return got


def test_the_pitfalls_default_thaw_runs_no_curator_in_a_box_it_cannot_show_running(
        tmp_path: Path, monkeypatch, docker_on_path: str):
    """`run_pitfalls(box=<sandboxed, no such container>)` with no `thaw=`: the default seam asks
    the real docker to unpause the box and fails, so the tick raises `BoxFault` before the
    curator is called; HEAD unchanged, nothing staged, every queued row still queued."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    queued = _queued(s)
    got, spawn = _drive_pitfalls(s, [], rel=REDUCER_REL, text=REDUCER_VETTED, box=_absent_box())
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the curator ran in a box never shown running"
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)
    assert _queued(s) == queued


def test_the_pitfalls_tick_thaws_exactly_around_its_curator(tmp_path: Path, monkeypatch):
    """`run_pitfalls(thaw=<recording>, box=<sentinel>)`: the curator appends a pitfall to the
    reducer surface. The thaw is entered after the tick's first host step, holds the curator
    alone, and has returned before the gate's first read and the commit; once, handed the
    sentinel box."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    box = object()
    thaw = Thaw(log, s.repo)
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, thaw=thaw, box=box)
    assert got == ("returned", 0), got
    head = _git.git_head_sha(s.repo)
    _assert_thawed_exactly_around_the_agent(log, thaw, box, head_before=s.head, head_after=head)
    assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED


def test_nothing_but_the_pitfalls_thaw_touches_the_box(tmp_path: Path, monkeypatch):
    """As the lead-author row: the thaw injected, the box sandboxed naming no container; the tick
    commits, so nothing else in it asked docker about the box."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, thaw=Thaw(log, s.repo),
                        box=_absent_box())
    assert got == ("returned", 0), got
    assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED


@pytest.mark.parametrize("on_exit", ["refused", "variant"])
def test_the_pitfalls_gate_judges_what_the_box_wrote_while_thawed(
        tmp_path: Path, monkeypatch, on_exit: str):
    """The box rewrites the reducer surface on the thaw's way out: refused bytes (a rewritten
    frontmatter block) are refused with HEAD unchanged and nothing staged; valid different bytes
    (the control) are what HEAD holds."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    bytes_out = REDUCER_REFUSED if on_exit == "refused" else REDUCER_VARIANT
    thaw = Thaw(log, s.repo, on_exit=lambda: write(s.at(REDUCER_REL), bytes_out))
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, thaw=thaw, box=object())
    if on_exit == "variant":
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VARIANT
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert REDUCER_REFUSED_SAYS in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "the refused bytes were committed"
    assert _nothing_staged(s.repo)


#: As `LEAD_THAWED_WRITES`, for the pitfalls lane: a new draft is outside its scope, a new
#: non-`.md` is a stray; a new `execution.md` for a declared system (`cmdb`, adapter only) is
#: admitted.
PITFALLS_THAWED_WRITES = [
    pytest.param("defender/skills/gather/queries/wazuh/_draft/new1178.md",
                 query_template("wazuh.new1178", "draft"), "non-execution.md", id="new-md-refused"),
    pytest.param("defender/skills/elastic/evil1178.txt", "not markdown\n", "outside",
                 id="new-non-md"),
    pytest.param("defender/skills/cmdb/execution.md", "# cmdb\n\n## Common pitfalls\n\n- key it\n",
                 None, id="new-md-admissible"),
]


@pytest.mark.parametrize(("rel", "text", "says"), PITFALLS_THAWED_WRITES)
def test_a_pitfalls_path_the_box_wrote_while_thawed_is_judged(
        tmp_path: Path, monkeypatch, rel: str, text: str, says: str | None):
    """The box writes a NEW path beside the curator's vetted reducer edit on the thaw's way out:
    a path outside the lane's scope or a non-`.md` stray is refused (HEAD unchanged, nothing
    staged); an admissible new `execution.md` (the control) is judged and committed."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    thaw = Thaw(log, s.repo, on_exit=lambda: write(s.at(rel), text))
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, thaw=thaw, box=object())
    if says is None:
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", rel) == text
        assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert says in got[2], got
    assert rel in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "a path written while thawed was committed"
    assert _nothing_staged(s.repo)


def test_a_pitfalls_thaw_that_faults_runs_no_curator_and_commits_nothing(
        tmp_path: Path, monkeypatch):
    """The thaw's way in raises `BoxFault`: it propagates through `run_pitfalls`; the curator
    never ran, the gate read nothing, HEAD is unchanged, nothing is staged, and every queued row
    is still queued."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    queued = _queued(s)
    log: list = []
    thaw = Thaw(log, s.repo, fault=BoxFault("the box did not report running"))
    got, spawn = _drive_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, thaw=thaw,
                                 box=object())
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the curator ran though the thaw failed"
    assert [e for e in log if e[0] == "read"] == [], "the gate ran though the thaw failed"
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
# The host's steps before the agent run with the box frozen: the baseline and the mint capture
# ---------------------------------------------------------------------------------------

#: A committed file outside `skills/`: the box's write there once thawed is a stray only if the
#: lane took its baseline of strays before the thaw.
STRAY_REL = "defender/notes/stray1178.md"
STRAY_EDIT = "rewritten by the box\n"


def _commit_stray(repo: Path) -> str:
    """`STRAY_REL` committed with its first text; the new HEAD."""
    write(repo / STRAY_REL, "committed\n")
    return commit_all(repo, "a file outside skills")


@pytest.mark.parametrize("when", ["once-thawed", "before-the-run"])
def test_a_lead_author_stray_the_box_writes_once_thawed_is_refused(tmp_path: Path, when: str):
    """The box rewrites a committed file outside `skills/` as soon as it is thawed: the gate
    refuses the claim ("changed files outside", naming it), HEAD unchanged, nothing staged. The
    lane's baseline of strays was taken while the box was frozen, before the thaw, so the
    rewrite is new. Control: the same rewrite already standing before the run is in the
    baseline, and the claim commits (without it)."""
    s = _lead_scene(tmp_path)
    s = dataclasses.replace(s, head=_commit_stray(s.repo))
    stray = s.repo / STRAY_REL
    log: list = []
    if when == "before-the-run":
        write(stray, STRAY_EDIT)
    thaw = Thaw(log, s.repo,
                on_enter=(lambda: write(stray, STRAY_EDIT)) if when == "once-thawed" else None)
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, thaw=thaw, box=object())
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


@pytest.mark.parametrize("when", ["once-thawed", "before-the-run"])
def test_a_pitfalls_stray_the_box_writes_once_thawed_is_refused(
        tmp_path: Path, monkeypatch, when: str):
    """As the lead-author row, for the pitfalls tick: its baseline of strays is taken frozen,
    before the thaw."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    s = dataclasses.replace(s, head=_commit_stray(s.repo))
    stray = s.repo / STRAY_REL
    log: list = []
    if when == "before-the-run":
        write(stray, STRAY_EDIT)
    thaw = Thaw(log, s.repo,
                on_enter=(lambda: write(stray, STRAY_EDIT)) if when == "once-thawed" else None)
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, thaw=thaw, box=object())
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
def test_a_draft_minted_this_tick_that_the_box_removes_once_thawed_is_a_departure(
        tmp_path: Path, box_does: str):
    """The tick mints an untracked draft for the run's lead, then thaws the box, which removes
    that draft at once. The identities the draft recorded were captured while the box was
    frozen, before the thaw, so its departure is seen and refused (`LeadAuthorError`, "without
    attributing it", naming the draft), HEAD unchanged. Control: the box leaves the draft, and
    it is committed with the agent's file."""
    s = _lead_scene(tmp_path)
    minted_name, _text = draft_of(ELASTIC_LEAD)
    minted = s.at(minted_name)
    log: list = []

    def on_enter() -> None:
        assert minted.is_file(), "nothing was minted, so its departure is vacuous"
        if box_does == "removes-it":
            minted.unlink()

    thaw = Thaw(log, s.repo, on_enter=on_enter)
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, thaw=thaw, box=object())
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
# The default seams over a `docker` on PATH: nothing but the pause and each thaw asks it
# ---------------------------------------------------------------------------------------


def test_the_lead_author_default_seams_leave_the_box_frozen_after_the_commit(
        tmp_path: Path, monkeypatch):
    """`run(deps=<the lane's own thaw>, box=<the shim's container, paused as the drain left
    it>)`: the shim logs exactly one proven thaw, the agent, one proven freeze, and nothing
    after the commit; the box ends paused."""
    s = _lead_scene(tmp_path)
    shim = DockerShim(tmp_path, monkeypatch, state="paused")
    got = _run_lead(s, [], name=AGENT_NAME, text=VETTED, box=shim.box(),
                    on_agent=lambda: shim.mark("agent"))
    assert got == ("returned", 0), got
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
    assert shim.steps() == [*THAWED, "agent", *PAUSED]
    assert shim.state() == "paused"


def test_the_pitfalls_default_seams_leave_the_box_frozen_after_the_commit(
        tmp_path: Path, monkeypatch):
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    shim = DockerShim(tmp_path, monkeypatch, state="paused")
    got = _run_pitfalls(s, [], rel=REDUCER_REL, text=REDUCER_VETTED, box=shim.box(),
                        on_agent=lambda: shim.mark("curator"))
    assert got == ("returned", 0), got
    assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED
    assert shim.steps() == [*THAWED, "curator", *PAUSED]
    assert shim.state() == "paused"


def test_the_drains_default_seams_hold_the_box_frozen_except_around_each_agent(
        tmp_path: Path, monkeypatch):
    """`_drain_lead_author` with its default `pause`, serving one claim and one pitfalls tick
    through the real lanes (their default thaws; only the spawns are faked), over the shim's
    running container: the shim logs one proven freeze, then for each agent one proven thaw,
    the agent and one proven freeze, and nothing else; the box ends paused, and both lanes
    committed."""
    s = _lead_scene(tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(_system_rows(), paths=s.paths)
    write(s.paths.author_queue_dir / "case-0.json",
          json.dumps({"case_id": "case-0", "run_dir": str(s.run_dir)}) + "\n")
    shim = DockerShim(tmp_path, monkeypatch)

    def author(_run_dir: Path) -> None:
        write(s.at(AGENT_NAME), VETTED)
        shim.mark("agent")

    def curate(root: Path) -> None:
        write(root / EXECUTION_REL, EXECUTION_TEXT)
        shim.mark("curator")

    lead_spawn, curator = LeadAuthorSpawn(author), Spawn(curate)

    def run_lead(paths: LoopPaths, run_dir: Path, *, box: Any = None, on_done: Any) -> int:
        with lead_trees(paths) as trees:
            deps = _deps(paths, trees, lead_spawn, [ELASTIC_LEAD])
            return lead_author.run(run_dir, label=LEAD, paths=paths, deps=deps, box=box,
                                   on_done=on_done)

    def run_pitfalls(paths: LoopPaths, *, box: Any = None, on_curated: Any) -> int:
        with lead_trees(paths) as trees:
            return pitfalls_curator.run_pitfalls(paths=paths, trees=trees, invoke=curator,
                                                 box=box, on_curated=on_curated)

    drains._drain_lead_author(s.paths, run_lead, run_pitfalls, box=shim.box())
    assert lead_spawn.calls, "the lead-author claim never reached its agent"
    assert curator.calls, "the pitfalls tick never reached its curator"
    assert shim.steps() == [*PAUSED, *THAWED, "agent", *PAUSED, *THAWED, "curator", *PAUSED]
    assert shim.state() == "paused"
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
    assert _git.git_show_file(s.repo, "HEAD", EXECUTION_REL) == EXECUTION_TEXT


def test_the_production_drain_freezes_its_box_before_it_serves(tmp_path: Path, monkeypatch):
    """`lead_author_drain` as production wires it (its own `_drain_lead_author` call; only the
    lanes, the branch and the box lifecycle injected), its box the shim's running container:
    the shim logs one proven freeze before the claim is served and the pitfalls tick runs, and
    nothing else; the box ends paused."""
    paths = loop_paths(tmp_path)
    run_dir = tmp_path / "runs" / "run-1"
    (run_dir / "gather_raw").mkdir(parents=True)
    markers.enqueue_case_for_curation("case-1", run_dir, paths)
    shim = DockerShim(tmp_path, monkeypatch)
    box = shim.box()
    started: list[Any] = []

    def start_box(request: Any, **_kw: Any) -> BoxExecutor:
        started.append(request)
        return box

    def serve(_paths: LoopPaths, _run_dir: Path, *, box: Any = None, on_done: Any,
              **_kw: Any) -> None:
        shim.mark("serve")
        on_done(None)

    def curate(_paths: LoopPaths, *, box: Any = None, **_kw: Any) -> int:
        shim.mark("pitfalls")
        return 0

    drains.lead_author_drain(
        paths, run_lead_author=serve, run_pitfalls=curate,
        branch=SpecBranch(tmp_path / "worktrees"), start_box=start_box,
        stop_box=noop_stop_box, scrub=noop_scrub,
    )
    assert len(started) == 1, "the drain never started its box"
    assert shim.steps() == [*PAUSED, "serve", "pitfalls"]
    assert shim.state() == "paused"
