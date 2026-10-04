"""#1178, second design ("freeze the box for the gate and the commit"): both lead-author-lane
committers judge and commit with their drain box frozen, and the gate admits only plain files.

Four groups, each driven through a seam, never `monkeypatch.setattr`:

- `frozen` (D1'): `runtime.box.frozen(box, docker=...)` over an injected docker seam that
  records every argv. A no-op without a sandboxed box; otherwise pause, confirm the pause by
  inspect, run the body, unpause; every fault before the body refuses it (`BoxFault`); an
  unpause fault is a `BoxFault` unless the body's own exception is in flight.
- Wiring (D2'): `LeadAuthorDeps.freeze` and `run_pitfalls(freeze=)`, each an injected recording
  freeze. Entered after the agent returned and before the gate's first read (the lane's
  `tree_for`, wrapped to log), left only once the commit exists, once per claim / batch,
  handed the entry point's `box`. A freeze that cannot be entered propagates `BoxFault` with
  nothing committed or staged.
- What the freeze protects: bytes written on the way in are what the gate judges and the
  commit carries; bytes written on the way out (after the commit) never reach HEAD.
- The plain-file rule (D3'): a symlink or a hard link at an address no content rule reads
  (a catalog draft, a system-skill draft, `queries/<sys>/README.md`; the pitfalls lane's
  `execution.md`) is refused with HEAD unchanged; a plain file there commits, and so does an
  executable one (mode 100755).

The real-box row (a live writer held still by `frozen`) is in `test_1178_frozen_box.py`.
"""
from __future__ import annotations

import contextlib
import dataclasses
import logging
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender._run_paths import RunPaths
from defender.learning.core import persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime.box import BoxExecutor, BoxFault, BoxSpec, _DockerTransport, unboxed_executor
from defender.tests._declared869 import LeadAuthorSpawn, Spawn, pitfall_row
from defender.tests._declared870 import (
    REDUCER_REL,
    commit_all,
    reducer_surface_text,
    seed_tree,
    shim_row,
    write_reducer_surface,
)
from defender.tests._lead_author_1134 import clear, lead_trees, write
from defender.tests._repo import query_template
from defender.tests.test_1134_lead_author_handle import ELASTIC_LEAD, _deps, _run_dir, _worktree

LEAD = LEAD_AUTHOR_DRAIN_LABEL


def _frozen() -> Callable[..., Any]:
    """`runtime.box.frozen`, imported at call time so this module collects (and the D3' rows
    run) while it does not exist yet."""
    from defender.runtime.box import frozen

    return frozen


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


def _nothing_staged(repo: Path) -> bool:
    """The index equals HEAD: no refusal or fault left a half-made commit staged."""
    return _git.git(["diff", "--cached", "--name-only", "-z"], cwd=repo) == ""


# ---------------------------------------------------------------------------------------
# frozen: the context manager, over an injected docker
# ---------------------------------------------------------------------------------------

BOX_NAME = "defender-drain-f1178"


def _sandboxed() -> BoxExecutor:
    """A box as `start_box` hands one back for a started container: the docker transport, so
    `sandboxed` is true, named as its container. Nothing is started; the docker seam is faked."""
    spec = BoxSpec()
    return BoxExecutor(spec=spec, transport=_DockerTransport(BOX_NAME, spec), name=BOX_NAME)


class Daemon:
    """The injected `docker=` seam: appends `("docker", verb, argv)` to the shared `log` and
    answers per verb. It decides nothing about what an answer means.

    `inspect` is answered for the question asked: `true`/`false` for a `.State.Paused` format,
    `paused`/`running` for a `.State.Status` one (either is a way to ask "is it paused")."""

    def __init__(self, log: list, *, pause_rc: int = 0, inspect_rc: int = 0,
                 paused: bool = True, unpause_rc: int = 0) -> None:
        self.log = log
        self.pause_rc = pause_rc
        self.inspect_rc = inspect_rc
        self.paused = paused
        self.unpause_rc = unpause_rc

    def __call__(self, argv, **_kwargs: object) -> subprocess.CompletedProcess:
        argv = list(argv)
        verb = argv[1] if len(argv) > 1 else ""
        self.log.append(("docker", verb, argv))
        if verb == "pause":
            return self._reply(argv, self.pause_rc, "")
        if verb == "unpause":
            return self._reply(argv, self.unpause_rc, "")
        if verb == "inspect":
            asked = " ".join(argv)
            if "Status" in asked:
                state = "paused" if self.paused else "running"
            else:
                state = "true" if self.paused else "false"
            return self._reply(argv, self.inspect_rc, f"{state}\n")
        return self._reply(argv, 1, "")

    @staticmethod
    def _reply(argv: list[str], rc: int, out: str) -> subprocess.CompletedProcess:
        err = "" if rc == 0 else f"Error response from daemon: refused by the fake ({argv[1]})\n"
        return subprocess.CompletedProcess(argv, rc, out if rc == 0 else "", err)


def _docker_calls(log: list) -> list[tuple[str, list[str]]]:
    return [(e[1], e[2]) for e in log if e[0] == "docker"]


def _steps(log: list) -> list[str]:
    """The shared log as one sequence: each docker verb, and `body` where the body ran."""
    return [e[1] if e[0] == "docker" else e[0] for e in log]


def _hold(box: Any, daemon: Daemon, log: list, *, raises: BaseException | None = None) -> None:
    """Run a body under `frozen(box, docker=daemon)`: it logs `("body",)`, then raises `raises`
    if given (the gate refusing inside the freeze)."""
    with _frozen()(box, docker=daemon):
        log.append(("body",))
        if raises is not None:
            raise raises


@pytest.mark.parametrize("which", ["none", "unsandboxed"])
def test_frozen_runs_no_docker_without_a_sandboxed_box(which: str):
    """`frozen(None)` and `frozen(<unboxed executor>)` (the `DEFENDER_ALLOW_UNSANDBOXED`
    fallback) run the body and ask the daemon nothing: there is no container to pause."""
    box = None if which == "none" else unboxed_executor()
    log: list = []
    _hold(box, Daemon(log), log)
    assert log == [("body",)], log


def test_frozen_pauses_confirms_runs_the_body_and_unpauses():
    """The positive path, in one sequence: `pause <name>`, `inspect <name>` (it says paused),
    the body, `unpause <name>`, and nothing else."""
    log: list = []
    _hold(_sandboxed(), Daemon(log), log)
    assert _steps(log) == ["pause", "inspect", "body", "unpause"], log
    for verb, argv in _docker_calls(log):
        assert argv[0] == "docker", (verb, argv)
        assert BOX_NAME in argv, (verb, argv)


@pytest.mark.parametrize("fault", [
    {"pause_rc": 1},
    {"inspect_rc": 1},
    {"paused": False},
], ids=["pause-fails", "inspect-fails", "inspect-says-not-paused"])
def test_a_freeze_that_cannot_be_shown_to_hold_refuses_the_body(fault: dict):
    """A pause the daemon refuses, an inspect it refuses, or an inspect saying the box is not
    paused: `BoxFault`, and the body never runs. The control is the positive path above (the
    same box, a daemon that pauses and says so)."""
    log: list = []
    with pytest.raises(BoxFault):
        _hold(_sandboxed(), Daemon(log, **fault), log)
    assert ("body",) not in log, log
    assert [v for v, _ in _docker_calls(log)][:1] == ["pause"], log


def test_an_unpause_that_fails_after_a_clean_body_is_a_fault():
    """The body ran and returned; the daemon refuses the unpause: `BoxFault` (a box left frozen
    is a systemic fault, like a failed teardown). Control: the positive path's unpause rc 0."""
    log: list = []
    with pytest.raises(BoxFault):
        _hold(_sandboxed(), Daemon(log, unpause_rc=1), log)
    assert _steps(log) == ["pause", "inspect", "body", "unpause"], log


@pytest.mark.parametrize("unpause_rc", [0, 1], ids=["unpause-ok", "unpause-fails"])
def test_the_bodys_own_exception_outranks_an_unpause_fault(unpause_rc: int, caplog):
    """The body (the gate) raises `LeadAuthorError`: the unpause is still run, and the body's
    exception propagates unchanged whether it succeeds or not. When it fails, the fault is
    logged (naming the box) rather than raised over the refusal."""
    log: list = []
    refusal = LeadAuthorError("agent wrote x; refusing to commit")
    with caplog.at_level(logging.WARNING), pytest.raises(LeadAuthorError) as got:
        _hold(_sandboxed(), Daemon(log, unpause_rc=unpause_rc), log, raises=refusal)
    assert got.value is refusal
    assert _steps(log) == ["pause", "inspect", "body", "unpause"], log
    if unpause_rc:
        said = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert any(BOX_NAME in m for m in said), said


# ---------------------------------------------------------------------------------------
# The fakes the wiring rows inject
# ---------------------------------------------------------------------------------------


class Freeze:
    """The injected `freeze` seam: `freeze(box)` returns a context manager. It records each box
    it is handed, logs `("enter",)` and `("exit", <HEAD sha at exit>)` into the drive's shared
    log, and optionally acts on the way in (`on_enter`, or raises `fault`) or on the way out
    (`on_exit`, run after HEAD is read)."""

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
            self.log.append(("exit", _git.git_head_sha(self.repo)))
            if self.on_exit is not None:
                self.on_exit()


def _logging_tree_for(tree_for: Callable[..., Any], log: list) -> Callable[..., Any]:
    """The lane's real `tree_for`, logging each path asked of it: the gate's reads (nothing
    before the agent asks it; the pre-agent reads go through `deps.skills`)."""

    def logged(path):
        log.append(("read", str(path)))
        return tree_for(path)

    return logged


class LoggedTrees:
    """The pitfalls lane's open trees, delegating `mount`/`mounts`/`tree_for`, logging each
    `tree_for` call: the commit gate's reads."""

    def __init__(self, trees: Any, log: list) -> None:
        self._trees = trees
        self._log = log

    @property
    def mounts(self):
        return self._trees.mounts

    def mount(self, path):
        return self._trees.mount(path)

    def tree_for(self, path):
        self._log.append(("read", str(path)))
        return self._trees.tree_for(path)


def _assert_gate_and_commit_inside_one_freeze(
    log: list, freeze: Freeze, box: Any, *, head_before: str, head_after: str,
) -> None:
    """Entered once, after the agent returned and before the gate's first read; left once, after
    the gate's last read, with the commit already at HEAD; handed the entry point's box."""
    kinds = [e[0] for e in log]
    assert kinds.count("enter") == 1, kinds
    assert kinds.count("exit") == 1, kinds
    reads = [i for i, k in enumerate(kinds) if k == "read"]
    assert reads, f"the gate read nothing through the lane's tree_for, so the order is vacuous: {kinds}"
    agent, enter, leave = kinds.index("agent"), kinds.index("enter"), kinds.index("exit")
    assert agent < enter < reads[0], f"not entered between the agent and the gate: {kinds}"
    assert reads[-1] < leave, f"the gate read after the freeze was left: {kinds}"
    assert head_after != head_before, "nothing was committed, so 'left after the commit' is vacuous"
    assert log[leave][1] == head_after, "the freeze was left before the commit existed"
    assert len(freeze.boxes) == 1, freeze.boxes
    assert freeze.boxes[0] is box, freeze.boxes


# ---------------------------------------------------------------------------------------
# The lead-author lane's drive: `run(label=, deps=)`, the agent leaving one file
# ---------------------------------------------------------------------------------------

#: The agent's file in the wiring rows: a catalog draft whose `id:` the gate reads (the path
#: rule's directory check), so the gate's verdict depends on the bytes it read.
AGENT_NAME = "gather/queries/wazuh/_draft/w1178.md"
VETTED = query_template("wazuh.w1178", "draft")
#: Valid too, but different bytes: what a write on the way in leaves for the gate to judge.
VARIANT = VETTED.replace("wazuh auth events.", "wazuh auth events, rewritten on the way in.")
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


def _lead_scene(tmp_path: Path) -> LeadScene:
    repo = _worktree(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    return LeadScene(tmp=tmp_path, repo=repo, paths=paths, run_dir=_run_dir(tmp_path),
                     head=_git.git_head_sha(repo))


def _plant(at: Path, text: str, kind: str, outside: Path) -> None:
    """`text` at `at` as a plain file (`plain`), an executable plain file (`exec`, 0755), a
    symlink to a file outside the repo holding it (`link`) or a hard link to one (`hardlink`)."""
    clear(at)
    if kind in ("plain", "exec"):
        write(at, text)
        if kind == "exec":
            at.chmod(0o755)
        return
    target = write(outside / f"{kind}-{at.parent.name}-{at.name}", text)
    at.parent.mkdir(parents=True, exist_ok=True)
    if kind == "link":
        at.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, at)
    else:
        raise ValueError(kind)


def _run_lead(s: LeadScene, log: list, *, name: str, text: str, kind: str = "plain",
              freeze: Freeze | None = None, box: Any = None) -> tuple:
    """Drive `lead_author.run` over the scene: the agent (rc 0) leaves `text` at `name` as
    `kind`. With `freeze`, it is injected as `deps.freeze` and the lane's `tree_for` logs."""

    def leave(_run_dir: Path) -> None:
        _plant(s.at(name), text, kind, s.tmp / "outside")
        log.append(("agent",))

    spawn = LeadAuthorSpawn(leave)
    with lead_trees(s.paths) as trees:
        deps = _deps(s.paths, trees, spawn, [ELASTIC_LEAD])
        if freeze is not None:
            deps = dataclasses.replace(
                deps, freeze=freeze, tree_for=_logging_tree_for(deps.tree_for, log),
            )
        got = _outcome(lambda: lead_author.run(
            s.run_dir, label=LEAD, paths=s.paths, deps=deps, box=box))
    assert spawn.calls, "the agent was never reached, so the gate never ran"
    return got


def test_the_lead_author_gate_and_commit_run_inside_one_freeze(tmp_path: Path):
    """`run(deps=<freeze injected>, box=<sentinel>)`: the agent leaves a valid draft; the
    freeze is entered after it returned and before the gate's first read, left after the commit
    (HEAD has moved by `__exit__`), once, handed the sentinel box; HEAD holds the draft."""
    s = _lead_scene(tmp_path)
    log: list = []
    box = object()
    freeze = Freeze(log, s.repo)
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, freeze=freeze, box=box)
    assert got == ("returned", 0), got
    head = _git.git_head_sha(s.repo)
    _assert_gate_and_commit_inside_one_freeze(log, freeze, box, head_before=s.head, head_after=head)
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED


@pytest.mark.parametrize("on_enter", ["refused", "variant"])
def test_the_lead_author_gate_judges_the_bytes_as_they_stand_inside_the_freeze(
        tmp_path: Path, on_enter: str):
    """The freeze's way in rewrites the agent's file (the box's last write before it holds):
    with refused bytes the gate refuses (`LeadAuthorError`, HEAD unchanged, nothing staged);
    with valid different bytes (the control) those bytes are what HEAD holds. A gate that read
    before the freeze would pass the agent's bytes and commit the refused ones."""
    s = _lead_scene(tmp_path)
    log: list = []
    bytes_in = REFUSED if on_enter == "refused" else VARIANT
    freeze = Freeze(log, s.repo, on_enter=lambda: write(s.at(AGENT_NAME), bytes_in))
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, freeze=freeze, box=object())
    if on_enter == "variant":
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VARIANT
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert REFUSED_SAYS in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "the refused bytes were committed"
    assert _nothing_staged(s.repo)


def test_a_lead_author_write_after_the_commit_never_reaches_head(tmp_path: Path):
    """The freeze's way out (after HEAD is read) rewrites the agent's file with refused bytes, as
    a box resuming would: the run returns 0 and HEAD holds the vetted bytes. A commit made after
    the freeze was left would re-read the working tree and carry the refused ones."""
    s = _lead_scene(tmp_path)
    log: list = []
    freeze = Freeze(log, s.repo, on_exit=lambda: write(s.at(AGENT_NAME), REFUSED))
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, freeze=freeze, box=object())
    assert got == ("returned", 0), got
    assert _git.git_show_file(s.repo, "HEAD", s.rel(AGENT_NAME)) == VETTED
    assert s.at(AGENT_NAME).read_text(encoding="utf-8") == REFUSED, "the way-out write never ran"


def test_a_lead_author_freeze_that_faults_commits_nothing(tmp_path: Path):
    """The freeze's way in raises `BoxFault` (the pause could not be shown to hold): it
    propagates through `run`; the gate read nothing, HEAD is unchanged, nothing is staged, and
    the run is not recorded done. Control: the first wiring row (the same drive, a freeze that
    holds, commits)."""
    s = _lead_scene(tmp_path)
    log: list = []
    freeze = Freeze(log, s.repo, fault=BoxFault("the box did not report paused"))
    got = _run_lead(s, log, name=AGENT_NAME, text=VETTED, freeze=freeze, box=object())
    assert got[:2] == ("raised", "BoxFault"), got
    assert [e for e in log if e[0] == "read"] == [], "the gate ran without the freeze"
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)
    assert not (RunPaths(s.run_dir).lead_author / "done").exists()


# ---------------------------------------------------------------------------------------
# The pitfalls lane's drive: `run_pitfalls(trees=, invoke=)`
# ---------------------------------------------------------------------------------------

#: The curator's edit in the wiring rows: one pitfall under the reducer's `## Common pitfalls`,
#: a document the content rule reads and accepts (`_readable_pair` reads it through `tree_for`).
REDUCER_VETTED = reducer_surface_text(bullets=("keep the unnest argument a LIST",))
REDUCER_VARIANT = reducer_surface_text(bullets=("a different pitfall, written on the way in",))
#: Refused: the frontmatter block is rewritten.
REDUCER_REFUSED = REDUCER_VETTED.replace("name: defender-gather-sql", "name: rewritten-1178")
REDUCER_REFUSED_SAYS = "frontmatter block"

#: The system surface the pitfalls lane commits, with no content rule of its own.
EXECUTION_NAME = "elastic/execution.md"
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


def _run_pitfalls(s: PitfallsScene, log: list, *, rel: str, text: str, kind: str = "plain",
                  freeze: Freeze | None = None, box: Any = None) -> tuple:
    """Drive `run_pitfalls` over the scene: the curator (rc 0) leaves `text` at `rel` as `kind`.
    With `freeze`, it is passed as `freeze=` and the trees log each `tree_for` call."""

    def curate(_root: Path) -> None:
        _plant(s.at(rel), text, kind, s.tmp / "outside")
        log.append(("agent",))

    spawn = Spawn(curate)
    with lead_trees(s.paths) as trees:
        if freeze is None:
            got = _outcome(lambda: pitfalls_curator.run_pitfalls(
                paths=s.paths, trees=trees, invoke=spawn, box=box))
        else:
            got = _outcome(lambda: pitfalls_curator.run_pitfalls(
                paths=s.paths, trees=LoggedTrees(trees, log), invoke=spawn, box=box,
                freeze=freeze))
    assert spawn.calls, "the curator was never reached, so the gate never ran"
    return got


def test_the_pitfalls_gate_and_commit_run_inside_one_freeze(tmp_path: Path, monkeypatch):
    """`run_pitfalls(freeze=<recording>, box=<sentinel>)`: the curator appends a pitfall to the
    reducer surface; the freeze is entered after it returned and before the gate's first read,
    left after the commit (HEAD has moved by `__exit__`), once, handed the sentinel box."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    box = object()
    freeze = Freeze(log, s.repo)
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, freeze=freeze, box=box)
    assert got == ("returned", 0), got
    head = _git.git_head_sha(s.repo)
    _assert_gate_and_commit_inside_one_freeze(log, freeze, box, head_before=s.head, head_after=head)
    assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED


@pytest.mark.parametrize("on_enter", ["refused", "variant"])
def test_the_pitfalls_gate_judges_the_bytes_as_they_stand_inside_the_freeze(
        tmp_path: Path, monkeypatch, on_enter: str):
    """The freeze's way in rewrites the reducer surface: refused bytes (a rewritten frontmatter
    block) are refused with HEAD unchanged and nothing staged; valid different bytes (the
    control) are what HEAD holds."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    bytes_in = REDUCER_REFUSED if on_enter == "refused" else REDUCER_VARIANT
    freeze = Freeze(log, s.repo, on_enter=lambda: write(s.at(REDUCER_REL), bytes_in))
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, freeze=freeze,
                        box=object())
    if on_enter == "variant":
        assert got == ("returned", 0), got
        assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VARIANT
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert REDUCER_REFUSED_SAYS in got[2], got
    assert _git.git_head_sha(s.repo) == s.head, "the refused bytes were committed"
    assert _nothing_staged(s.repo)


def test_a_pitfalls_write_after_the_commit_never_reaches_head(tmp_path: Path, monkeypatch):
    """The freeze's way out rewrites the reducer surface with refused bytes after HEAD is read:
    the tick returns 0 and HEAD holds the vetted bytes."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log: list = []
    freeze = Freeze(log, s.repo, on_exit=lambda: write(s.at(REDUCER_REL), REDUCER_REFUSED))
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, freeze=freeze,
                        box=object())
    assert got == ("returned", 0), got
    assert _git.git_show_file(s.repo, "HEAD", REDUCER_REL) == REDUCER_VETTED
    assert s.at(REDUCER_REL).read_text(encoding="utf-8") == REDUCER_REFUSED


def test_a_pitfalls_freeze_that_faults_commits_nothing(tmp_path: Path, monkeypatch):
    """The freeze's way in raises `BoxFault`: it propagates through `run_pitfalls`; the gate read
    nothing, HEAD is unchanged, nothing is staged, and every queued row is still queued."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    queued = sorted(r["pitfall_id"] for r in persist.read_pitfalls(s.paths))
    log: list = []
    freeze = Freeze(log, s.repo, fault=BoxFault("the box did not report paused"))
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, freeze=freeze,
                        box=object())
    assert got[:2] == ("raised", "BoxFault"), got
    assert [e for e in log if e[0] == "read"] == [], "the gate ran without the freeze"
    assert _git.git_head_sha(s.repo) == s.head
    assert _nothing_staged(s.repo)
    assert sorted(r["pitfall_id"] for r in persist.read_pitfalls(s.paths)) == queued


# ---------------------------------------------------------------------------------------
# D3': only a plain, single-name regular file is committed
# ---------------------------------------------------------------------------------------

#: The lead lane's addresses no content rule reads, so a link there passes every rule on main
#: and is committed (#1178 C1), with the bytes a plain file there commits with.
LEAD_ADDRESSES = [
    pytest.param("gather/queries/wazuh/_draft/d1178.md", query_template("wazuh.d1178", "draft"),
                 id="catalog-draft"),
    pytest.param("elastic/_draft/d1178.md", "# elastic draft\n\n- a lifted note\n",
                 id="system-skill-draft"),
    pytest.param("gather/queries/wazuh/README.md", "# wazuh queries\n\nWhat lives here.\n",
                 id="catalog-readme"),
]

KINDS = ["link", "hardlink", "plain", "exec"]


def _assert_plain_file_rule(got: tuple, repo: Path, head: str, rel: str, text: str,
                            kind: str) -> None:
    if kind in ("link", "hardlink"):
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
    Controls on the same address: a plain file commits at 100644, an executable one at 100755.

    Red on main: the link rows commit (a 120000 entry; the hard link's outside bytes)."""
    s = _lead_scene(tmp_path)
    got = _run_lead(s, [], name=name, text=text, kind=kind)
    _assert_plain_file_rule(got, s.repo, s.head, s.rel(name), text, kind)


@pytest.mark.parametrize("kind", KINDS)
def test_the_pitfalls_gate_commits_only_a_plain_execution_md(
        tmp_path: Path, monkeypatch, kind: str):
    """Through `run_pitfalls(trees=, invoke=)`: the curator leaves `elastic/execution.md` (a
    surface this lane commits with no content rule) as a symlink or a hard link to an outside
    file holding a valid edit: refused, HEAD unchanged, nothing staged. Controls: the same bytes
    as a plain file commit at 100644, as an executable one at 100755.

    Red on main: the link rows commit."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _system_rows())
    rel = f"defender/skills/{EXECUTION_NAME}"
    got = _run_pitfalls(s, [], rel=rel, text=EXECUTION_TEXT, kind=kind)
    _assert_plain_file_rule(got, s.repo, s.head, rel, EXECUTION_TEXT, kind)
