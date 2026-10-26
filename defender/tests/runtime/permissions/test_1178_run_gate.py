from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import contextlib
import dataclasses
import json
import os
import subprocess
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender._io import READ_LIMIT
from defender.records import RunPaths
from defender.learning.core import drains, persist
from defender.learning.core.config import LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.author.shared import AuthorError
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender import box as box_mod
from defender.runtime.agent_definition import bind
from defender.box import AliasBanNotInForce, BoxFault
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.sandbox import _box1195 as X
from defender.tests.support.learning.core import _state1135
from defender.tests.support.runtime.engine._declared869 import LeadAuthorSpawn, Spawn, pitfall_row
from defender.tests.support.learning.core._declared870 import (
    REDUCER_REL,
    commit_all,
    reducer_surface_text,
    seed_agent_files,
    seed_product,
    shim_row,
)
from defender.tests.support.learning.curation import _curator1134 as C
from defender.tests.support.learning.curation._lead_author_1134 import (
    clear,
    draft_lead_deps,
    lead_trees,
    write,
)
from defender.tests.support.shared.contracts._repo import query_template
from defender.tests.learning.curation.test_1134_lead_author_handle import (
    ELASTIC_LEAD,
    NO_MODEL,
    WAZUH_LEAD,
    _run_dir,
    _worktree,
    draft_of,
)

LEAD = LEAD_AUTHOR_DRAIN_LABEL

#: The container the direct drives' box names (the drain's is `defender-drain-<batch id>`).
NAME = "defender-drain-g1178"


def _outcome(fn: Callable[[], Any]) -> tuple:
    """`("returned", value)`, or `("raised", class name, message)` for the gate's refusal, the
    box's fault and P3's commit-maker refusal (`DeliveryRefused`: a ChangeSet holding a link,
    FIFO, oversized file or out-of-lane path, #1108 P4 OD18 — the direct entry raises it, the
    drain routes it as a U10 refused claim). Anything else (a call-shape `TypeError`, a
    `ValidationError`) propagates."""
    from defender.learning.author.version_control import DeliveryRefused

    try:
        return ("returned", fn())
    except (LeadAuthorError, BoxFault, DeliveryRefused) as e:
        return ("raised", type(e).__name__, str(e))


def _head_mode(repo: Path, rel: str, rev: str = "HEAD") -> str:
    """The git mode `rel` is committed with at `rev` (`100644`, `100755`, `120000` a link)."""
    # The code under test runs no `ls-tree`; this reads HEAD as a git user would.
    return _git.git(["ls-tree", rev, "--", rel], cwd=repo).split(" ", 1)[0]  # lint-oracle: ok — not the code under test's query


def _head_bytes(repo: Path, rel: str, rev: str = "HEAD") -> bytes:
    """The blob committed at `rel` in `rev`, as bytes (no decoding: the subject may not be text).
    The observed value; the expected one is the bytes the test planted."""
    argv = ["git", "cat-file", "blob", f"{rev}:{rel}"]  # lint-oracle: ok — reads what was committed; the oracle is the planted bytes
    return subprocess.run(argv, cwd=repo, capture_output=True, check=True).stdout  # noqa: S603


def _nothing_staged(repo: Path) -> bool:
    """The index equals HEAD: no refusal or fault left a half-made commit staged."""
    return _git.git(["diff", "--cached", "--name-only", "-z"], cwd=repo) == ""


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


#: The agent's file in the wiring rows: a catalog draft whose `id:` the gate reads (the path
#: rule's directory check), so the gate's verdict depends on the bytes it read.
AGENT_NAME = "gather/queries/wazuh/_draft/w1178.md"
VETTED = query_template("wazuh.w1178", "draft")
#: Valid too, but different bytes: what the box leaves on its run's way out, still up.
VARIANT = VETTED.replace("wazuh auth events.", "wazuh auth events, rewritten in its run.")
#: Refused: its id names another system ("disagreeing with its directory").
REFUSED = query_template("elastic.w1178", "draft")
REFUSED_SAYS = "disagreeing with its directory"


# #1108 P4 (O7, OD6, OD12 class ii): the lead-author rows run over a git-free draft of a P3
# batch (`_curator1134.draft_lane`, lane `skills`), never a product worktree: the legacy
# worktree's `defender/skills/` tree is the tenant's `agent/skills/` in the batch base, its
# adapters stay in the product checkout (#1172). What a run committed is read from the batch
# branch (its tip stands where HEAD stood); "no half-made commit staged" is the tenant clone's
# index (the draft has none). ASSUMED SEAMS (S-H): `build_lead_author_deps(..., batch=)`
# (`draft_lead_deps`); `_verify_skills_state(root, *, change_set, systems, tree_for)`.


@dataclasses.dataclass
class LeadScene:
    tmp: Path
    lane: C.DraftLane
    run_dir: Path
    head: str

    @property
    def repo(self) -> Path:
        """The draft's root (it holds `agent/`): where the agent writes and the gate reads."""
        return Path(self.lane.batch.draft_root)

    @property
    def paths(self) -> LoopPaths:
        return self.lane.paths

    def at(self, name: str) -> Path:
        return self.lane.skills_dir / name

    def rel(self, name: str) -> str:
        return f"agent/skills/{name}"

    def committed(self, rel: str) -> str | None:
        """The text at `rel` on the batch branch's tip (the base before any commit)."""
        return self.lane.text_at_tip(rel)

    def nothing_landed(self) -> bool:
        """No commit reached the batch branch and none was left staged in the clone."""
        return self.lane.tip() == self.head and _nothing_staged(self.lane.clone)


def _lead_scene(tmp_path: Path, committed: dict[str, str] | None = None, *,
                files: dict[str, str] | None = None) -> LeadScene:
    """A started batch whose draft carries the legacy lead worktree's tree (the `elastic` and
    `wazuh` markers and catalogs, the `elastic` skill, the catalog schema) plus `committed`
    (`{name below skills/: text}`) and `files` (agent-relative), all in the batch base; the
    product checkout holds the `elastic` and `wazuh` adapters."""
    product = seed_product(tmp_path, adapters=("elastic", "wazuh"))
    agent_files = {**seed_agent_files(markers=("elastic", "wazuh"), skills=("elastic",),
                                      catalog=("elastic", "wazuh")),
                   "skills/gather/queries/SCHEMA.md": "# template schema\n",
                   **{f"skills/{name}": text for name, text in (committed or {}).items()},
                   **(files or {})}
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, files=agent_files, product=product)
    location_path(lane.paths.state_root).mkdir(parents=True, exist_ok=True)  # the root is never created lazily (#1135)
    return LeadScene(tmp=lane.tmp, lane=lane, run_dir=_run_dir(), head=lane.base)


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
    deps = _journaled_deps(draft_lead_deps(s.lane, invoke_agent=spawn,
                                           extract=lambda _run_dir: ([], [ELASTIC_LEAD])), log)
    got = _outcome(lambda: lead_author.run(
        _state1135.run_of(s.run_dir), label=LEAD, paths=s.paths, deps=deps, box=box))
    return got, spawn


def _run_lead(s: LeadScene, log: list, **kw: Any) -> tuple:
    """`_drive_lead`, for a drive whose agent is reached: the outcome."""
    got, spawn = _drive_lead(s, log, **kw)
    assert spawn.calls, f"the agent was never reached, so the gate never ran: {got}"
    return got


def test_the_lead_author_runs_its_agent_in_a_run_window_of_its_own(tmp_path: Path, monkeypatch):
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    log = X.Journal(daemon)
    got, spawn = _drive_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs)
    assert got == ("returned", 0), got
    head = s.lane.tip()
    _assert_one_run_holds_exactly_the_agent(log, daemon, spawn, box, head_before=s.head,
                                            head_after=head)
    assert s.committed(s.rel(AGENT_NAME)) == VETTED


@pytest.mark.parametrize("at_stop", ["refused", "variant"])
def test_the_lead_author_gate_judges_what_the_box_wrote_during_its_run(
        tmp_path: Path, monkeypatch, at_stop: str):
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    bytes_out = REFUSED if at_stop == "refused" else VARIANT
    daemon.on_stop(s.at(AGENT_NAME), bytes_out, at=1)
    got = _run_lead(s, [], name=AGENT_NAME, text=VETTED, box=runs)
    if at_stop == "variant":
        assert got == ("returned", 0), got
        assert s.committed(s.rel(AGENT_NAME)) == VARIANT
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert REFUSED_SAYS in got[2], got
    assert s.nothing_landed(), "the refused bytes were committed"


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
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    daemon.on_stop(s.at(name), text, at=1)
    got = _run_lead(s, [], name=AGENT_NAME, text=VETTED, box=runs)
    if says is None:
        assert got == ("returned", 0), got
        assert s.committed(s.rel(name)) == text
        assert s.committed(s.rel(AGENT_NAME)) == VETTED
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert says in got[2], got
    assert s.rel(name) in got[2], got
    assert s.nothing_landed(), "a path written during the run was committed"


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
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _start_fault(daemon, fault)
    s = _lead_scene(tmp_path)
    log: list = []
    got, spawn = _drive_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs)
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the agent ran though its box never started"
    assert [e for e in log if e[0] == "read"] == [], "the gate ran though the box never started"
    assert s.nothing_landed()
    assert not (RunPaths(s.run_dir).lead_author / "done").exists()
    assert daemon.status(NAME) == "exited", "the refused run left its box running"
    if fault == "left-running":
        assert "start" not in daemon.steps(), "a box found running was started over"


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
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _stop_fault(daemon, stop)
    s = _lead_scene(tmp_path)
    log: list = []
    got, spawn = _drive_lead(s, log, name=AGENT_NAME, text=VETTED, box=runs)
    assert len(spawn.calls) == 1, f"the agent was never reached: {got}"
    if stop == "holds":
        assert got == ("returned", 0), got
        assert _reads_after_the_agent(log), "the gate read nothing after the run (vacuous control)"
        assert s.committed(s.rel(AGENT_NAME)) == VETTED
        return
    assert got[:2] == ("raised", "BoxFault"), got
    assert _reads_after_the_agent(log) == [], "the gate judged beside a box that would not stop"
    assert s.nothing_landed(), "a commit landed beside a box that would not stop"
    assert not (RunPaths(s.run_dir).lead_author / "done").exists()


#: The curator's edit in the wiring rows: one pitfall under the reducer's `## Common pitfalls`,
#: a document the content rule reads and accepts (`_readable_pair` reads it through `tree_for`).
REDUCER_VETTED = reducer_surface_text(bullets=("keep the unnest argument a LIST",))
REDUCER_VARIANT = reducer_surface_text(bullets=("a different pitfall, written in its run",))
#: Refused: the frontmatter block is rewritten.
REDUCER_REFUSED = REDUCER_VETTED.replace("name: defender-gather-sql", "name: rewritten-1178")
REDUCER_REFUSED_SAYS = "frontmatter block"

#: The system surface the pitfalls lane commits, with no content rule of its own.
EXECUTION_NAME = "elastic/execution.md"
#: The page in a batch draft (#1108 P4, OD6: repo-relative in the tenant repo).
DRAFT_EXECUTION_REL = f"agent/skills/{EXECUTION_NAME}"
EXECUTION_TEXT = "# execution\n\n## Common pitfalls\n\n- use the key, not the id\n"


# #1108 P4 (O7, OD6, OD12 class ii): the pitfalls rows run over a git-free draft of a P3 batch
# (`_curator1134.draft_lane`, lane `skills`), never a product worktree, as `test_870_partition`
# does. What a tick committed is read from the batch branch (its tip stands where HEAD stood);
# "no half-made commit staged" is the tenant clone's index (the draft has none). ASSUMED SEAMS
# (S-H): `run_pitfalls(..., batch=)`; `_verify_pitfalls_state(root, *, change_set, systems,
# reducer_offered, tree_for)`.


@dataclasses.dataclass
class PitfallsScene:
    tmp: Path
    lane: C.DraftLane
    head: str

    @property
    def repo(self) -> Path:
        """The draft's root (it holds `agent/`): where the curator writes and the gate reads."""
        return Path(self.lane.batch.draft_root)

    @property
    def paths(self) -> LoopPaths:
        return self.lane.paths

    def at(self, rel: str) -> Path:
        return self.repo / rel

    def committed(self, rel: str) -> str | None:
        """The text at `rel` on the batch branch's tip (the base before any commit)."""
        return self.lane.text_at_tip(rel)

    def nothing_landed(self) -> bool:
        """No commit reached the batch branch and none was left staged in the clone."""
        return self.lane.tip() == self.head and _nothing_staged(self.lane.clone)


def _pitfalls_scene(tmp_path: Path, monkeypatch, rows: list[dict], *,
                    files: dict[str, str] | None = None) -> PitfallsScene:
    """A started batch whose draft carries the reducer add-on and `elastic/execution.md` (the
    `elastic` marker and skill, the `gather` non-system skill) plus `files` (agent-relative), all
    in the batch base; the product checkout holds the `elastic` and `cmdb` adapters. `rows` are
    queued and the threshold is 1, so the tick offers what the rows name."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    product = seed_product(tmp_path, adapters=("elastic", "cmdb"))
    agent_files = {**seed_agent_files(markers=("elastic",), skills=("elastic",), catalog=(),
                                      non_systems=("gather",)),
                   REDUCER_REL.removeprefix("agent/"): reducer_surface_text(), **(files or {})}
    lane = C.draft_lane(tmp_path, lanes=C.LEAD_LANES, files=agent_files, product=product)
    persist.append_pitfalls(rows, state=_state1135.state_for_paths(lane.paths))
    return PitfallsScene(tmp=lane.tmp, lane=lane, head=lane.base)


def _reducer_rows() -> list[dict]:
    return [shim_row(f"r:l-003:{i}") for i in range(3)]


def _system_rows() -> list[dict]:
    return [pitfall_row(f"p-1178-{i}", "elastic") for i in range(3)]


def _queued(s: PitfallsScene) -> list[str]:
    return sorted(r["pitfall_id"] for r in persist.read_pitfalls(_state1135.state_for_paths(s.paths)))


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
    with C.draft_trees(s.lane) as trees:
        got = _outcome(lambda: pitfalls_curator.run_pitfalls(
            paths=s.paths, trees=LoggedTrees(trees, log), batch=s.lane.batch, invoke=spawn,
            box=box))
    return got, spawn


def _run_pitfalls(s: PitfallsScene, log: list, **kw: Any) -> tuple:
    """`_drive_pitfalls`, for a drive whose curator is reached: the outcome."""
    got, spawn = _drive_pitfalls(s, log, **kw)
    assert spawn.calls, f"the curator was never reached, so the gate never ran: {got}"
    return got


def test_the_pitfalls_tick_runs_its_curator_in_a_run_window_of_its_own(
        tmp_path: Path, monkeypatch):
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    log = X.Journal(daemon)
    got, spawn = _drive_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    assert got == ("returned", 0), got
    _assert_one_run_holds_exactly_the_agent(log, daemon, spawn, box, head_before=s.head,
                                            head_after=s.lane.tip())
    assert s.committed(REDUCER_REL) == REDUCER_VETTED


@pytest.mark.parametrize("at_stop", ["refused", "variant"])
def test_the_pitfalls_gate_judges_what_the_box_wrote_during_its_run(
        tmp_path: Path, monkeypatch, at_stop: str):
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    bytes_out = REDUCER_REFUSED if at_stop == "refused" else REDUCER_VARIANT
    daemon.on_stop(s.at(REDUCER_REL), bytes_out, at=1)
    got = _run_pitfalls(s, [], rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    if at_stop == "variant":
        assert got == ("returned", 0), got
        assert s.committed(REDUCER_REL) == REDUCER_VARIANT
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert REDUCER_REFUSED_SAYS in got[2], got
    assert s.nothing_landed(), "the refused bytes were committed"


PITFALLS_RUN_WRITES = [
    pytest.param("agent/skills/gather/queries/wazuh/_draft/new1178.md",
                 query_template("wazuh.new1178", "draft"), "non-execution.md", id="new-md-refused"),
    pytest.param("agent/skills/elastic/evil1178.txt", "not markdown\n", "outside",
                 id="new-non-md"),
    pytest.param("agent/skills/cmdb/execution.md", "# cmdb\n\n## Common pitfalls\n\n- key it\n",
                 None, id="new-md-admissible"),
]


@pytest.mark.parametrize(("rel", "text", "says"), PITFALLS_RUN_WRITES)
def test_a_pitfalls_path_the_box_wrote_during_its_run_is_judged(
        tmp_path: Path, monkeypatch, rel: str, text: str, says: str | None):
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    daemon.on_stop(s.at(rel), text, at=1)
    got = _run_pitfalls(s, [], rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    if says is None:
        assert got == ("returned", 0), got
        assert s.committed(rel) == text
        assert s.committed(REDUCER_REL) == REDUCER_VETTED
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert says in got[2], got
    assert rel in got[2], got
    assert s.nothing_landed(), "a path written during the run was committed"


@pytest.mark.parametrize("fault", START_FAULTS)
def test_a_pitfalls_start_fault_runs_no_curator_and_commits_nothing(
        tmp_path: Path, monkeypatch, fault: str):
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _start_fault(daemon, fault)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows())
    queued = _queued(s)
    log: list = []
    got, spawn = _drive_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    assert got[:2] == ("raised", "BoxFault"), got
    assert spawn.calls == [], "the curator ran though its box never started"
    assert [e for e in log if e[0] == "read"] == [], "the gate ran though the box never started"
    assert s.nothing_landed()
    assert _queued(s) == queued
    assert daemon.status(NAME) == "exited", "the refused run left its box running"


@pytest.mark.parametrize("stop", STOP_FAULTS)
def test_a_pitfalls_stop_fault_after_a_clean_curator_halts_before_the_gate(
        tmp_path: Path, monkeypatch, stop: str):
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
        assert s.committed(REDUCER_REL) == REDUCER_VETTED
        return
    assert got[:2] == ("raised", "BoxFault"), got
    assert _reads_after_the_agent(log) == [], "the gate judged beside a box that would not stop"
    assert s.nothing_landed(), "a commit landed beside a box that would not stop"
    assert _queued(s) == queued


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


def _assert_plain_file_rule_on_the_batch(got: tuple, s: PitfallsScene | LeadScene, rel: str,
                                         text: str, kind: str) -> None:
    """The plain-file rule over a draft scene. #1108 P4 (OD18/OD23, owner ruling 2026-10-23 2):
    a link, hard link or FIFO in the lane is a ChangeSet refusal of the whole claim, naming
    `rel`, and nothing lands (the drain routes it as U10, `test_refused_claims.py`). A plain
    file commits with its bytes; an executable one commits as a plain file too — its bytes, mode
    `100644` (P3's commit-maker writes plain files only: `tenant_1108_delivery/test_changes.py::
    test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files`)."""
    if kind in REFUSED_KINDS:
        assert got[:2] == ("raised", "DeliveryRefused"), got
        assert rel in got[2], got
        assert s.nothing_landed(), f"a {kind} at {rel} was committed"
        return
    assert got == ("returned", 0), got
    assert s.committed(rel) == text, "the plain control was not committed"
    assert _head_mode(s.lane.clone, rel, s.lane.tip()) == "100644"


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(("name", "text"), LEAD_ADDRESSES)
def test_the_lead_author_gate_commits_only_a_plain_file(
        tmp_path: Path, name: str, text: str, kind: str):
    s = _lead_scene(tmp_path)
    got = _run_lead(s, [], name=name, text=text, kind=kind)
    _assert_plain_file_rule_on_the_batch(got, s, s.rel(name), text, kind)


@pytest.mark.parametrize("kind", ["fifo", "plain"])
@pytest.mark.parametrize(("name", "text"), LEAD_ADDRESSES)
def test_a_fifo_at_a_committed_lead_author_name_is_refused(
        tmp_path: Path, name: str, text: str, kind: str):
    s = _lead_scene(tmp_path, committed={name: text})
    rewritten = text + "\n- rewritten by the agent\n"
    got = _run_lead(s, [], name=name, text=rewritten, kind=kind)
    _assert_plain_file_rule_on_the_batch(got, s, s.rel(name), rewritten, kind)


@pytest.mark.parametrize(("name", "_text"), LEAD_ADDRESSES)
def test_a_plain_lead_author_file_that_is_not_utf8_commits(
        tmp_path: Path, name: str, _text: str):
    s = _lead_scene(tmp_path)
    got = _run_lead(s, [], name=name, text=NOT_UTF8)
    assert got == ("returned", 0), got
    assert _head_bytes(s.lane.clone, s.rel(name), s.lane.tip()) == NOT_UTF8
    assert _head_mode(s.lane.clone, s.rel(name), s.lane.tip()) == "100644"


def test_every_lead_author_record_the_gate_admits_is_placed_through_the_held_mount(
        tmp_path: Path):
    names = {p.values[0]: p.values[1] for p in LEAD_ADDRESSES}
    first, *rest = names
    s = _lead_scene(tmp_path)
    log: list = []
    got = _run_lead(s, log, name=first, text=names[first], more={n: names[n] for n in rest})
    assert got == ("returned", 0), got
    asked = {e[1] for e in log if e[0] == "read"}
    for name, text in names.items():
        assert s.committed(s.rel(name)) == text, name
        assert str(s.repo / s.rel(name)) in asked, f"{name} was committed unread"


UNPLACED_DRAFT = "agent/skills/elastic/_draft/u1178.md"


@pytest.mark.parametrize("tree_for", ["lane", "places-nothing"])
def test_a_lead_author_record_no_held_mount_places_is_refused(tmp_path: Path, tree_for: str):
    """`_verify_skills_state` over a draft whose ChangeSet holds one new system-skill draft,
    with a `tree_for` that places no path: `LeadAuthorError` naming it. Control: the lane's own
    `tree_for` admits it. (#1108 P4, OD12 class ii: the legacy `baseline_stray=`/`git=` seam is
    the claim's ChangeSet, OD15; ASSUMED SEAM `_verify_skills_state(root, *, change_set, ...)`.)"""
    s = _lead_scene(tmp_path)
    write(s.repo / UNPLACED_DRAFT, "# elastic draft\n\n- a lifted note\n")
    with C.draft_trees(s.lane) as trees:
        placed = trees.tree_for if tree_for == "lane" else (lambda _p: None)
        got = _outcome(lambda: lead_author._verify_skills_state(
            s.repo, change_set=s.lane.batch.change_set(), systems=frozenset({"elastic", "wazuh"}),
            tree_for=placed))
    if tree_for == "lane":
        assert got == ("returned", [UNPLACED_DRAFT]), got
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert "refusing to commit" in got[2], got
    assert UNPLACED_DRAFT in got[2], got


@pytest.mark.parametrize("kind", [*KINDS, "fifo"])
def test_the_pitfalls_gate_commits_only_a_plain_execution_md(
        tmp_path: Path, monkeypatch, kind: str):
    s = _pitfalls_scene(tmp_path, monkeypatch, _system_rows())
    got = _run_pitfalls(s, [], rel=DRAFT_EXECUTION_REL, text=EXECUTION_TEXT, kind=kind)
    _assert_plain_file_rule_on_the_batch(got, s, DRAFT_EXECUTION_REL, EXECUTION_TEXT, kind)


def test_a_plain_execution_md_that_is_not_utf8_commits(tmp_path: Path, monkeypatch):
    """The curator leaves `elastic/execution.md` as a plain file whose bytes are not UTF-8: it
    commits, those exact bytes."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _system_rows())
    got = _run_pitfalls(s, [], rel=DRAFT_EXECUTION_REL, text=NOT_UTF8)
    assert got == ("returned", 0), got
    assert _head_bytes(s.lane.clone, DRAFT_EXECUTION_REL, s.lane.tip()) == NOT_UTF8
    assert _head_mode(s.lane.clone, DRAFT_EXECUTION_REL, s.lane.tip()) == "100644"


@pytest.mark.parametrize("tree_for", ["lane", "places-nothing"])
def test_a_pitfalls_record_no_held_mount_places_is_refused(
        tmp_path: Path, monkeypatch, tree_for: str):
    """`_verify_pitfalls_state` over an edited `elastic/execution.md`, with a `tree_for` that
    places no path: `LeadAuthorError` naming it. Control: the lane's own `tree_for` admits it."""
    s = _pitfalls_scene(tmp_path, monkeypatch, _system_rows())
    write(s.at(DRAFT_EXECUTION_REL), EXECUTION_TEXT)
    with C.draft_trees(s.lane) as trees:
        placed = trees.tree_for if tree_for == "lane" else (lambda _p: None)
        got = _outcome(lambda: pitfalls_curator._verify_pitfalls_state(
            s.repo, change_set=s.lane.batch.change_set(), systems=frozenset({"elastic", "cmdb"}),
            reducer_offered=False, tree_for=placed))
    if tree_for == "lane":
        assert got == ("returned", [DRAFT_EXECUTION_REL]), got
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert "refusing to commit" in got[2], got
    assert DRAFT_EXECUTION_REL in got[2], got


def test_every_pitfalls_record_the_gate_admits_is_placed_through_the_held_mount(
        tmp_path: Path, monkeypatch):
    s = _pitfalls_scene(tmp_path, monkeypatch, [*_system_rows(), *_reducer_rows()])
    log: list = []
    got = _run_pitfalls(s, log, rel=REDUCER_REL, text=REDUCER_VETTED,
                        more={DRAFT_EXECUTION_REL: EXECUTION_TEXT})
    assert got == ("returned", 0), got
    asked = {e[1] for e in log if e[0] == "read"}
    for committed, text in ((REDUCER_REL, REDUCER_VETTED), (DRAFT_EXECUTION_REL, EXECUTION_TEXT)):
        assert s.committed(committed) == text, committed
        assert str(s.repo / committed) in asked, f"{committed} was committed unread"


STRAY_EDIT = "rewritten by the box\n"
#: A file in the batch base under the draft's `agent/` but outside `agent/skills/`: the box's
#: write there once started is a stray.
DRAFT_STRAY_REL = "agent/notes/stray1178.md"

# #1108 P4, OD15: a claim's ChangeSet is its draft against the batch base, the draft re-synced
# per claim, so there is no "pre-run stray tolerated" baseline. The legacy `before-the-run` rows
# (a stray edited before the run is tolerated and the tick commits) are deleted (OD12 class i);
# the derivation is pinned by P3's `tenant_1108_delivery/test_changes.py::
# test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files`,
# `::test_claims_commit_and_reset_one_after_another_within_one_batch` and
# `::test_a_claim_reset_resyncs_the_draft_and_never_follows_box_links`. `untouched` is the
# positive control: the stray left as the base holds it, the tick commits.


@pytest.mark.parametrize("when", ["once-started", "untouched"])
def test_a_lead_author_stray_the_box_writes_once_started_is_refused(
        tmp_path: Path, monkeypatch, when: str):
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path, files={DRAFT_STRAY_REL.removeprefix("agent/"): "committed\n"})
    stray = s.repo / DRAFT_STRAY_REL
    if when == "once-started":
        daemon.on_start(stray, STRAY_EDIT, at=1)
    got = _run_lead(s, [], name=AGENT_NAME, text=VETTED, box=runs)
    if when == "untouched":
        assert got == ("returned", 0), got
        assert s.committed(s.rel(AGENT_NAME)) == VETTED
        assert s.committed(DRAFT_STRAY_REL) == "committed\n"
        return
    # OD18: a path outside the lane is a ChangeSet refusal of the whole claim (P3's
    # out-of-lane rule), routed by the drain as U10; the direct entry raises it, naming the path.
    assert got[:2] == ("raised", "DeliveryRefused"), got
    assert DRAFT_STRAY_REL in got[2], got
    assert s.nothing_landed()


@pytest.mark.parametrize("when", ["once-started", "untouched"])
def test_a_pitfalls_stray_the_box_writes_once_started_is_refused(
        tmp_path: Path, monkeypatch, when: str):
    """As the lead-author row, for the pitfalls tick."""
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _pitfalls_scene(tmp_path, monkeypatch, _reducer_rows(),
                        files={DRAFT_STRAY_REL.removeprefix("agent/"): "committed\n"})
    stray = s.at(DRAFT_STRAY_REL)
    if when == "once-started":
        daemon.on_start(stray, STRAY_EDIT, at=1)
    got = _run_pitfalls(s, [], rel=REDUCER_REL, text=REDUCER_VETTED, box=runs)
    if when == "untouched":
        assert got == ("returned", 0), got
        assert s.committed(REDUCER_REL) == REDUCER_VETTED
        assert s.committed(DRAFT_STRAY_REL) == "committed\n"
        return
    # OD18: a path outside the lane is a ChangeSet refusal of the whole claim (P3's
    # out-of-lane rule), routed by the drain as U10; the direct entry raises it, naming the path.
    assert got[:2] == ("raised", "DeliveryRefused"), got
    assert DRAFT_STRAY_REL in got[2], got
    assert s.nothing_landed()


@pytest.mark.parametrize("box_does", ["removes-it", "leaves-it"])
def test_a_draft_minted_this_tick_that_the_box_removes_once_started_is_a_departure(
        tmp_path: Path, monkeypatch, box_does: str):
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    minted_name, _text = draft_of(ELASTIC_LEAD)
    if box_does == "removes-it":
        daemon.on_start(s.at(minted_name), remove=True, at=1)
    got = _run_lead(s, [], name=AGENT_NAME, text=VETTED, box=runs)
    if box_does == "leaves-it":
        assert got == ("returned", 0), got
        assert s.committed(s.rel(minted_name)) is not None
        return
    assert got[:2] == ("raised", "LeadAuthorError"), got
    assert "without attributing it" in got[2], got
    assert s.rel(minted_name) in got[2], got
    assert s.nothing_landed()


def _head_size(repo: Path, rel: str, rev: str = "HEAD") -> tuple[str, int]:
    """`(mode, size)` of the blob committed at `rel` in `rev`."""
    entry = _git.git(["ls-tree", "-l", rev, "--", rel], cwd=repo)  # lint-oracle: ok — reads what was committed; the oracle is the planted size
    mode, _kind, _sha, size = entry.split("\t", 1)[0].split()
    return mode, int(size)


# #1108 P4 (OD18): an oversized file in the lane is a ChangeSet refusal of the whole claim (P3's
# size bound), not a commit: the legacy "larger than any read commits" rows are re-spelled to
# the refusal, naming the entry, with nothing landed. A plain file under the bound commits
# (`test_the_lead_author_gate_commits_only_a_plain_file[*-plain]`).
@pytest.mark.parametrize("name", ["elastic/_draft/b1178.md", "gather/queries/wazuh/README.md"],
                         ids=["system-skill-draft", "catalog-readme"])
def test_a_plain_lead_author_file_larger_than_any_read_is_refused(tmp_path: Path, name: str):
    s = _lead_scene(tmp_path)
    got = _run_lead(s, [], name=name, text=b"# a large note\n", kind="big")
    assert got[:2] == ("raised", "DeliveryRefused"), got
    assert s.rel(name) in got[2], got
    assert s.nothing_landed(), "an oversized file was committed"


def test_a_plain_execution_md_larger_than_any_read_is_refused(tmp_path: Path, monkeypatch):
    s = _pitfalls_scene(tmp_path, monkeypatch, _system_rows())
    got = _run_pitfalls(s, [], rel=DRAFT_EXECUTION_REL, text=EXECUTION_TEXT, kind="big")
    assert got[:2] == ("raised", "DeliveryRefused"), got
    assert DRAFT_EXECUTION_REL in got[2], got
    assert s.nothing_landed(), "an oversized file was committed"


def _queue_claims(s: LeadScene, *run_names: str) -> list[Path]:
    """A lead-author request queued for each named run dir (`runs/<name>`, a `gather_raw/` of its
    own), keyed `case-<name>`; returns the run dirs."""
    run_dirs = []
    for name in run_names:
        run_dir = _state1135.curation_run_dir(name)
        (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
        _state1135.enqueue_case(_state1135.state_for_paths(s.paths), f"case-{name}", run_dir)
        run_dirs.append(run_dir)
    return run_dirs


class Lanes:
    """The drain's two work steps, each driving its REAL lane over the scene's batch draft:
    `run_lead` serves a claim through the run `lead_author.run_under_held_queue_lock` makes
    (`_run_locked`, over the real deps on the drain's handle; only the agent and the two tables
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
        #: The batch the lanes serve (`_drain` sets the scene's; #1108 P4, ASSUMED SEAMS
        #: `build_lead_author_deps(..., batch=)`, `run_pitfalls(..., batch=)`).
        self.lane: C.DraftLane | None = None
        self.seam_faults: list[TypeError] = []
        self.swallowed: list[BoxFault] = []

    def run_lead(self, paths: LoopPaths, state: Any, run: Any, *, box: Any = None,
                 on_done: Any, **_kw: Any) -> int:
        self.handed.append(box)
        deps = self._seamed(lambda: draft_lead_deps(
            self.lane, state=state, invoke_agent=self.agent,
            extract=lambda _run_dir: ([], [ELASTIC_LEAD])))
        if self.log is not None:
            deps = _journaled_deps(deps, self.log)
        try:
            return lead_author._run_locked(run.run_dir, deps, box=box, on_done=on_done)
        except BoxFault as e:
            if not self.swallow:
                raise
            self.swallowed.append(e)
            return 0

    def run_pitfalls(self, paths: LoopPaths, state: Any, *, box: Any = None, on_curated: Any,
                     **_kw: Any) -> int:
        self.handed.append(box)
        self.pitfalls_ticks += 1
        if self.curator is None:
            return 0
        if self.lane is None:  # `TenantLanes`: the drain-level rows, red on the drain's seams
            with lead_trees(paths) as trees:
                return pitfalls_curator.run_pitfalls(paths=paths, state=state, trees=trees,
                                                     invoke=self.curator, box=box,
                                                     on_curated=on_curated)
        lane = self.lane
        with C.draft_trees(lane) as trees:
            held = trees if self.log is None else LoggedTrees(trees, self.log)
            return self._seamed(lambda: pitfalls_curator.run_pitfalls(
                paths=paths, state=state, trees=held, batch=lane.batch, invoke=self.curator,
                box=box, on_curated=on_curated))

    def _seamed(self, call: Callable[[], Any]) -> Any:
        """`call()`, a refused keyword (the P4 batch seam) recorded in `seam_faults`."""
        try:
            return call()
        except TypeError as e:
            if "unexpected keyword" in str(e):
                self.seam_faults.append(e)
            raise


def _request_dir(s: LeadScene, *below: str) -> Path:
    """The lead-author request queue's folder (or one below it), spelled literally as the #1135
    suite spells it: `state.py` names it for no caller."""
    return location_path(s.paths.state_root).joinpath("author-queue", *below)


def _drain(s: LeadScene, lanes: Lanes, **kw: Any) -> Any:
    """`drains._drain_lead_author` over the scene's paths, on a learning-state handle over its
    root (as the lane's entry opens one), its two work steps `lanes`', serving the scene's batch."""
    lanes.lane = s.lane
    try:
        return drains._drain_lead_author(
            s.paths, _state1135.state_for_paths(s.paths), lanes.run_lead, lanes.run_pitfalls,
            accept_tenant=drains._tenant_acceptor(s.paths.tenant), **kw)
    finally:
        _assert_the_lanes_took_their_seams(lanes)


def _assert_the_lanes_took_their_seams(lanes: Lanes) -> None:
    """The drain swallows a claim's error into a quarantine and a pitfalls error into a log
    line: a lane refusing the P4 batch seam fails the row here, named, rather than as a
    downstream observation of a lane that never ran."""
    assert not lanes.seam_faults, f"the lanes do not take the P4 batch seam yet: {lanes.seam_faults[0]}"


def _caught_drain(s: LeadScene, lanes: Lanes, **kw: Any) -> BaseException | None:
    """`X.caught` over `_drain`, the seam check re-raised rather than judged as the drain's."""
    got = X.caught(lambda: _drain(s, lanes, **kw))
    _assert_the_lanes_took_their_seams(lanes)
    return got


def _failed(s: LeadScene) -> list[str]:
    """The names of the claims the lane dead-lettered."""
    failed = _request_dir(s, "failed")
    return sorted(p.name for p in failed.glob("*.json")) if failed.is_dir() else []


def _claim_files(s: LeadScene) -> tuple[list[str], list[str]]:
    """The lead-author queue's markers: those still queued, and those claimed (`inflight/`)."""
    qdir = _request_dir(s)
    return (sorted(p.name for p in qdir.glob("*.json")),
            sorted(p.name for p in (qdir / "inflight").glob("*.json")))


def _attempts(paths: LoopPaths) -> list[Any]:
    return [r.get("attempts") for r in persist.read_pitfalls(_state1135.state_for_paths(paths))]


def _claim_attempts(s: LeadScene) -> dict[str, Any]:
    """Each claimed marker's (`inflight/`) `attempts`: a serve is charged once, before its run
    (N14), and a box fault charges nothing more."""
    inflight = _request_dir(s, "inflight")
    return {p.name: json.loads(p.read_text(encoding="utf-8")).get("attempts")
            for p in sorted(inflight.glob("*.json"))}


def test_the_lead_drain_runs_one_window_per_agent_and_none_between(tmp_path: Path, monkeypatch):
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(_system_rows(), state=_state1135.state_for_paths(s.paths))
    _queue_claims(s, "run-0")
    log = X.Journal(daemon)

    def author(_run_dir: Path) -> None:
        write(s.at(AGENT_NAME), VETTED)
        log.append(("agent",))

    def curate(root: Path) -> None:
        write(s.repo / DRAFT_EXECUTION_REL, EXECUTION_TEXT)
        log.append(("curator",))

    lanes = Lanes(BoxSeenLeadSpawn(author), BoxSeenSpawn(curate), log=log)

    _drain(s, lanes, box=runs)

    log.assert_runs_hold_exactly(["agent", "curator"], ("agent", "curator"))
    kinds = [e[0] for e in log]
    assert {"host", "read"} <= set(kinds[kinds.index("agent") + 1:kinds.index("curator")]), (
        f"no host step was seen between the runs (vacuous): {kinds}")
    assert [b is box for b in lanes.agent.boxes] == [True], lanes.agent.boxes
    assert [b is box for b in lanes.curator.boxes] == [True], lanes.curator.boxes
    assert lanes.handed == [runs, runs], f"a lane was handed something but the handle: {lanes.handed}"
    assert daemon.status(NAME) == "exited"
    assert s.committed(s.rel(AGENT_NAME)) == VETTED
    assert s.committed(DRAFT_EXECUTION_REL) == EXECUTION_TEXT


@pytest.mark.parametrize("fault", START_FAULTS)
def test_a_claims_run_start_fault_halts_the_lane_and_dead_letters_nothing(
        tmp_path: Path, monkeypatch, fault: str):
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _start_fault(daemon, fault)
    s = _lead_scene(tmp_path)
    _queue_claims(s, "run-0", "run-1")
    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)))

    got = _caught_drain(s, lanes, box=runs)

    assert isinstance(got, BoxFault), got
    assert lanes.agent.calls == [], "an agent ran though its box never started"
    assert _claim_files(s) == (["case-run-1.json"], ["case-run-0.json"]), (
        "the lane went on to serve another claim")
    assert lanes.pitfalls_ticks == 0, "the pitfalls tick ran after a box fault"
    assert _failed(s) == [], "a claim was dead-lettered for a box that would not start"
    assert _claim_attempts(s) == {"case-run-0.json": 1}, (
        f"the box fault charged the claim more than its one serve: {_claim_attempts(s)}")
    assert s.lane.tip() == s.head
    assert daemon.status(NAME) == "exited"


def test_control_a_claims_agent_fault_dead_letters_that_claim_and_the_next_is_served(
        tmp_path: Path, monkeypatch):
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    _queue_claims(s, "run-0", "run-1")
    log = X.Journal(daemon)

    def author(run_dir: Path) -> None:
        log.append(("agent",))
        if run_dir.name == fixture_uuid("run-0"):
            raise LeadAuthorError("the agent failed")
        write(s.at(AGENT_NAME), VETTED)

    lanes = Lanes(BoxSeenLeadSpawn(author), log=log)

    _drain(s, lanes, box=runs)

    log.assert_runs_hold_exactly(["agent", "agent"], ("agent",))
    assert [b is box for b in lanes.agent.boxes] == [True, True], lanes.agent.boxes
    assert _failed(s) == ["case-run-0.json"], _failed(s)
    assert daemon.status(NAME) == "exited"
    assert s.committed(s.rel(AGENT_NAME)) == VETTED


@pytest.mark.parametrize("stop", X.STOP_FAULTS)
def test_a_claims_stop_fault_after_a_clean_agent_halts_the_lane(
        tmp_path: Path, monkeypatch, stop: str):
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    _stop_fault(daemon, stop)
    s = _lead_scene(tmp_path)
    _queue_claims(s, "run-0", "run-1")
    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)))

    got = _caught_drain(s, lanes, box=runs)

    assert isinstance(got, BoxFault), got
    assert len(lanes.agent.calls) == 1, lanes.agent.calls
    assert _claim_files(s) == (["case-run-1.json"], ["case-run-0.json"]), (
        "the lane went on to serve another claim")
    assert lanes.pitfalls_ticks == 0, "the pitfalls tick ran after a box fault"
    assert _failed(s) == [], "a claim was dead-lettered for a box that would not stop"
    assert _claim_attempts(s) == {"case-run-0.json": 1}, (
        f"the box fault charged the claim more than its one serve: {_claim_attempts(s)}")
    assert s.lane.tip() == s.head, "a commit landed beside a box that would not stop"


#: Where the pitfalls run's box fails, after the claim's run held: its start, or its stop
#: after a clean curator. `curator-fails` is the control: a fault that is not a box fault.
PITFALLS_BOX_FAULTS = ["start", "stop", "curator-fails"]


@pytest.mark.parametrize("where", PITFALLS_BOX_FAULTS)
def test_a_pitfalls_box_fault_halts_the_lane_and_bumps_no_pitfalls_row(
        tmp_path: Path, monkeypatch, where: str):
    daemon, _box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    if where == "start":
        daemon.refuse_start(at=[2])
    elif where == "stop":
        daemon.refuse_stop(at=[2])
    s = _lead_scene(tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls(_system_rows(), state=_state1135.state_for_paths(s.paths))
    _queue_claims(s, "run-0")
    attempts_before = _attempts(s.paths)
    execution_before = s.committed(DRAFT_EXECUTION_REL)

    def curate(root: Path) -> None:
        write(s.repo / DRAFT_EXECUTION_REL, EXECUTION_TEXT)

    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)),
                  BoxSeenSpawn(curate, rc=1 if where == "curator-fails" else 0))

    got = _caught_drain(s, lanes, box=runs)

    attempts = _attempts(s.paths)
    assert s.committed(s.rel(AGENT_NAME)) == VETTED, (
        "the claim's own commit did not stand")
    assert s.committed(DRAFT_EXECUTION_REL) == execution_before, (
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
    persist.append_pitfalls(_system_rows(), state=_state1135.state_for_paths(s.paths))
    _queue_claims(s, "run-0")
    return (daemon, box, runs, s, _attempts(s.paths),
            s.committed(DRAFT_EXECUTION_REL))


#: What the pitfalls curator raises inside its run: `AuthorError` (a `RETIRE_SET` member), a
#: crash, and its own process faults; each retires the tick's batch, bumping its rows.
PITFALLS_F1_FAILURES = [
    pytest.param(lambda: AuthorError("the curator refused"), id="AuthorError"),
    pytest.param(lambda: RuntimeError("the curator crashed"), id="RuntimeError"),
    *X.PROCESS_FAULTS,
]


@pytest.mark.parametrize("stop", STOP_FAULTS)
@pytest.mark.parametrize("failure", PITFALLS_F1_FAILURES)
def test_a_stop_fault_under_a_failing_curator_halts_the_lane_and_bumps_no_pitfalls_row(
        tmp_path: Path, monkeypatch, failure: Any, stop: str):
    daemon, _box, runs, s, attempts_before, execution_before = _claim_then_pitfalls(
        tmp_path, monkeypatch)
    raised = failure()

    def curate(root: Path) -> None:
        write(s.repo / DRAFT_EXECUTION_REL, EXECUTION_TEXT)
        if stop != "holds":  # the pitfalls run's stop: the second; its proof, the next status ask
            X.fail_stop(daemon, stop, at=2, inspect_at=daemon.inspect_count() + 1)
        raise raised

    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)),
                  BoxSeenSpawn(curate))

    got = _caught_drain(s, lanes, box=runs)

    assert len(lanes.curator.calls) == 1, "the curator never ran, so the row is vacuous"
    assert s.committed(s.rel(AGENT_NAME)) == VETTED, (
        "the claim's own commit did not stand")
    assert s.committed(DRAFT_EXECUTION_REL) == execution_before, (
        "the failed curator's edit was committed")
    X.no_path_docker(daemon)
    if stop == "holds":
        assert got is None, got
        assert _attempts(s.paths) == [1] * len(attempts_before), _attempts(s.paths)
        return
    X.assert_the_stop_fault_won(got, raised, daemon, stop)
    assert _attempts(s.paths) == attempts_before, "a pitfalls row was bumped for a box fault"


@pytest.mark.parametrize("stop", ["refused", "holds"])
def test_a_swallowed_stop_fault_in_the_last_claim_makes_the_pitfalls_run_refuse(
        tmp_path: Path, monkeypatch, stop: str):
    daemon, _box, runs, s, attempts_before, execution_before = _claim_then_pitfalls(
        tmp_path, monkeypatch)
    if stop == "refused":
        daemon.refuse_stop(at=[1])  # the claim's run's stop

    def curate(root: Path) -> None:
        write(s.repo / DRAFT_EXECUTION_REL, EXECUTION_TEXT)

    lanes = Lanes(BoxSeenLeadSpawn(lambda _rd: write(s.at(AGENT_NAME), VETTED)),
                  BoxSeenSpawn(curate), swallow_claim_box_faults=True)

    got = _caught_drain(s, lanes, box=runs)

    assert len(lanes.agent.calls) == 1
    assert lanes.pitfalls_ticks == 1
    calls = _run_calls(daemon)
    if stop == "holds":
        assert got is None, got
        assert lanes.swallowed == []
        assert len(lanes.curator.calls) == 1
        assert s.committed(DRAFT_EXECUTION_REL) == EXECUTION_TEXT
        assert calls == ONE_RUN * 2, calls
        return
    assert len(lanes.swallowed) == 1, "the claim's stop did not fail, so the row is vacuous"
    assert isinstance(got, BoxFault), f"the lane did not halt on a box left running: {got!r}"
    assert "running" in str(got), got
    assert lanes.curator.calls == [], "the pitfalls curator ran after a swallowed stop fault"
    assert s.committed(DRAFT_EXECUTION_REL) == execution_before, (
        "the pitfalls edit was committed after a swallowed stop fault")
    assert _attempts(s.paths) == attempts_before
    assert calls == [*ONE_RUN, "status", "stop", "status"], (
        f"the pitfalls run did not refuse the running box with a best-effort stop: {calls}")
    assert daemon.status(NAME) == "exited"


# ---------------------------------------------------------------------------------------------
# The drain-level rows (#1108 P4 re-spelling, OD12 class ii): the lane runs over a tenant draft
# and delivers to the tenant forge (`lead_author_drain(..., client=, identity=, start_box=,
# stop_box=)`), not a product worktree through `branch=`/`scrub=`. The #1178/#1195 promises
# stand: a box fault halts the lane before anything is committed, pushed or opened, no claim is
# dead-lettered for it, and a claim is charged its one serve. "Nothing delivered" is read on the
# tenant origin (`lead-author/` branches) and the forge's PR creates; the product checkout's HEAD
# never moves. The batch scan (`scrub=`) and the worktree cut-commit pointer are gone with the
# worktree (amendment 3 C3: a draft is never scrubbed) and are not re-asserted.
# ---------------------------------------------------------------------------------------------


@dataclasses.dataclass
class TenantLeadScene:
    """`LeadScene`'s fields over the P4 tenant path: `repo` is the product checkout the drain
    runs over (adapters declaring elastic/wazuh, as the legacy worktree had), `paths` the
    tenant's learning paths over it, `t` the published tenant whose `agent/skills/` holds the
    same catalog and skills the legacy worktree's `defender/skills/` did."""

    tmp: Path
    repo: Path
    paths: LoopPaths
    run_dir: Path
    head: str
    t: Any


@contextlib.contextmanager
def _tenant_lead_scene(tmp_path: Path, data_root: Path) -> Iterator[TenantLeadScene]:
    from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

    repo = _worktree(tmp_path)
    skills = repo / "defender" / "skills"
    files = {f"agent/skills/{p.relative_to(skills).as_posix()}": p.read_bytes()
             for p in skills.rglob("*") if p.is_file()}
    with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
        bind_forge(t)
        yield TenantLeadScene(tmp=tmp_path, repo=repo, paths=drain_paths(t, repo),
                              run_dir=_run_dir(), head=_git.git_head_sha(repo), t=t)


def _delivered(s: TenantLeadScene) -> dict[str, str]:
    """The tenant origin's `lead-author/` branches (`{branch: tip}`)."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import LEAD_PREFIX, remote_branches

    return remote_branches(s.t.remote, LEAD_PREFIX)


def _nothing_delivered(s: TenantLeadScene) -> None:
    assert _delivered(s) == {}, f"a lead-author branch reached the tenant origin: {_delivered(s)}"
    assert s.t.forge.creates == [], f"a PR was opened: {s.t.forge.creates}"
    assert _git.git_head_sha(s.repo) == s.head, "the product checkout moved"


def _delivered_text(s: TenantLeadScene, name: str) -> str:
    """`agent/skills/<name>` at the tip of the one delivered `lead-author/` branch, whose PR the
    forge was asked to open."""
    (branch, tip), = _delivered(s).items()
    assert [c["head"] for c in s.t.forge.creates] == [branch], s.t.forge.creates
    return _git.git(["show", f"{tip}:agent/skills/{name}"], cwd=s.t.remote)


class TenantLanes(Lanes):
    """`Lanes` whose agent writes where the lane's own deps put its skills (the draft's, on the
    P4 path): `skills_dir` is read off the deps the claim's run is served with."""

    skills_dir: Path | None = None

    def run_lead(self, paths: LoopPaths, state: Any, run: Any, *, box: Any = None,
                 on_done: Any, batch: Any, **_kw: Any) -> int:
        from defender.tests.tenancy.tenant_1108_p4._drain_support import (
            LEAD_DRAFT_LANES,
            draft_lane_trees,
            draft_root_of,
        )

        self.handed.append(box)
        # The lane's held `skills/` mount over the draft of the batch the drain handed down
        # (OD16), its deps built with that batch (S-H's `batch=`), never `paths`' checkout.
        with draft_lane_trees(batch, LEAD_DRAFT_LANES) as trees:
            deps = dataclasses.replace(
                lead_author.build_lead_author_deps(paths, state=state, trees=trees, batch=batch),
                invoke_agent=self.agent, extract=lambda _run_dir: ([], [ELASTIC_LEAD]))
            # The draft's `skills/` lane (OD6: `agent/skills` under the batch's draft root),
            # where the box's agent writes — not `deps.paths`, which stays product-rooted.
            self.skills_dir = draft_root_of(batch) / LEAD_DRAFT_LANES[0]
            return lead_author._run_locked(run.run_dir, deps, box=box, on_done=on_done)


def _vetted_author(lanes_ref: list) -> Callable[[Path], None]:
    def author(_run_dir: Path) -> None:
        write(lanes_ref[0].skills_dir / AGENT_NAME, VETTED)
    return author


def _held_lead_drain(s: TenantLeadScene, monkeypatch: Any, **seams: Any
                     ) -> tuple[BaseException | None, list[str]]:
    """`lead_author_drain` with its DEFAULT work steps over the fake daemon, whose first run
    start is refused; `start_box=` is `HeldStart` (a real create, minus the probes), whose
    executor carries the daemon, so the drain's own post-create stop, the runs and the removal
    reach it through that executor (a `Tripwire` is the `docker` on `PATH`). What it raised and
    the batch box's docker calls from its post-create stop on."""
    monkeypatch.setenv("LEAD_AUTHOR_MODEL", NO_MODEL)  # the agent, if ever reached, calls no model
    X.clear_opt_out(monkeypatch)
    daemon = X.FakeDaemon(s.tmp)
    daemon.tripwire = X.Tripwire(s.tmp).install(monkeypatch)
    daemon.refuse_start(at=[1])
    start = X.HeldStart(daemon)
    got = _p4_caught(lambda: drains.lead_author_drain(
        s.paths, client=s.t.forge.client, identity=s.t.vault.identity(), start_box=start,
        **seams))
    [request] = start.requests
    X.no_path_docker(daemon)
    return got, daemon.calls_from_the_first_stop(request.name)


@pytest.mark.parametrize("first", ["box-faults", "nothing-to-author"])
def test_a_run_start_fault_through_the_default_claim_step_halts_the_lane(
        tmp_path: Path, monkeypatch, data_root: Path, first: str):
    """#1178/#1195 on the P4 lane: a run-start fault in the default claim step halts the lane
    with nothing delivered, nothing dead-lettered, the claim charged its one serve."""
    with _tenant_lead_scene(tmp_path, data_root) as s:
        leads = {"claim-0": WAZUH_LEAD if first == "box-faults" else None, "claim-1": ELASTIC_LEAD}
        for name, lead in leads.items():
            rows = [(lead.query_id, lead.system, lead.verb)] if lead is not None else []
            _state1135.enqueue_case(_state1135.state_for_paths(s.paths), f"case-{name}",
                                    _run_dir(*rows, run_id=name))

        got, calls = _held_lead_drain(s, monkeypatch)

        assert isinstance(got, BoxFault), got
        assert X.POINTER not in str(got), f"a mid-batch box fault got a build pointer: {got}"
        assert calls == X.REFUSED_FIRST_RUN, f"a default step called docker outside its run: {calls}"
        assert _failed(s) == [], "a claim was dead-lettered for a box that would not start"
        _nothing_delivered(s)
        queued, claimed = _claim_files(s)
        if first == "nothing-to-author":
            assert queued == [], queued
            assert "case-claim-1.json" in claimed, claimed
            return
        assert queued == ["case-claim-1.json"], (
            f"the next claim was served, or the first handed back as a transient: {queued}")
        assert claimed == ["case-claim-0.json"], claimed
        assert _claim_attempts(s) == {"case-claim-0.json": 1}, (
            f"the box fault charged the claim more than its one serve: {_claim_attempts(s)}")


def test_a_run_start_fault_through_the_default_pitfalls_step_halts_the_lane(
        tmp_path: Path, monkeypatch, data_root: Path):
    """#1178/#1195 on the P4 lane: a run-start fault in the default pitfalls step halts the lane,
    bumps no pitfalls row and delivers nothing."""
    with _tenant_lead_scene(tmp_path, data_root) as s:
        monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
        persist.append_pitfalls(_system_rows(), state=_state1135.state_for_paths(s.paths))
        attempts_before = _attempts(s.paths)

        got, calls = _held_lead_drain(s, monkeypatch)

        assert isinstance(got, BoxFault), got
        assert calls == X.REFUSED_FIRST_RUN, f"the default step called docker outside its run: {calls}"
        assert _attempts(s.paths) == attempts_before, "a pitfalls row was bumped for a box fault"
        _nothing_delivered(s)


@contextlib.contextmanager
def _production_tenant_lead_scene(tmp_path: Path, monkeypatch: Any, data_root: Path, *claims: str,
                                  path_default: bool = False
                                  ) -> Iterator[tuple[TenantLeadScene, X.FakeDaemon]]:
    """The tenant lead scene as `lead_author_drain` serves it in production: the box image
    inputs committed under the product checkout's `defender/`, `claims` queued, the opt-out
    unset. The real `start_box` creates the box over the fake daemon, given as its `docker=`
    (`_production_lead_drain`), with a `Tripwire` the `docker` on `PATH`; with `path_default`,
    production's own default docker reaches the daemon installed on `PATH`."""
    X.clear_opt_out(monkeypatch)
    with _tenant_lead_scene(tmp_path, data_root) as s:
        X.plant_image_inputs(s.repo)
        s = dataclasses.replace(s, head=commit_all(s.repo, "the box image inputs"))
        _queue_claims(s, *claims)
        daemon = X.FakeDaemon(tmp_path)
        if path_default:
            daemon.install(monkeypatch)
        else:
            daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
        yield s, daemon


from defender.tests.tenancy.tenant_1108_p4._drain_support import _p4_caught  # noqa: E402 — #1108 P4's shared seam check


def _production_lead_drain(s: TenantLeadScene, daemon: X.FakeDaemon,
                           author: Callable[[Path], None] | None = None, *,
                           lanes: TenantLanes | None = None,
                           ) -> tuple[BaseException | None, TenantLanes]:
    """`lead_author_drain` over the tenant with only the lanes (their agent: `author`), the
    forge client and identity and (unless the daemon is on `PATH`) the real `start_box`'s docker
    injected: what it raised and the lanes."""
    if lanes is None:
        lanes = TenantLanes(BoxSeenLeadSpawn(author))
    seams: dict[str, Any] = {}
    if daemon.tripwire is not None:
        seams["start_box"] = partial(box_mod.start_box, docker=daemon)
    got = _p4_caught(lambda: drains.lead_author_drain(
        s.paths, run_lead_author=lanes.run_lead, run_pitfalls=lanes.run_pitfalls,
        client=s.t.forge.client, identity=s.t.vault.identity(), **seams))
    return got, lanes


def _kept(daemon: X.FakeDaemon) -> list[str]:
    return [x for x in daemon.steps()
            if x in ("create", "start", "stop", "rm") or x.startswith("agent:")]


LEAD_F1_FAILURES = [
    pytest.param(lambda: LeadAuthorError("the agent failed"), id="LeadAuthorError"),
    pytest.param(lambda: RuntimeError("the agent crashed"), id="RuntimeError"),
    *X.PROCESS_FAULTS,
]


@pytest.mark.parametrize("follows", ["next-claim", "nothing-follows"])
@pytest.mark.parametrize("stop", STOP_FAULTS)
@pytest.mark.parametrize("failure", LEAD_F1_FAILURES)
def test_a_stop_fault_under_a_failing_agent_halts_the_lead_drain_with_the_failure_as_context(
        tmp_path: Path, monkeypatch, data_root: Path, failure: Any, stop: str, follows: str):
    """#1195 F1 on the P4 lane: a stop fault under a failing agent halts the drain with the
    agent's failure as context, nothing delivered, nothing dead-lettered; with the stop holding
    (control) the failing claim is dead-lettered and the next claim's commit is delivered as a
    `lead-author/` PR on the tenant forge."""
    claims = ("run-0", "run-1") if follows == "next-claim" else ("run-0",)
    with _production_tenant_lead_scene(tmp_path, monkeypatch, data_root, *claims) as (s, daemon):
        raised = failure()
        ref: list = []

        def author(run_dir: Path) -> None:
            daemon.mark(f"agent:{run_dir.name}")
            if run_dir.name != fixture_uuid("run-0"):
                write(ref[0].skills_dir / AGENT_NAME, VETTED)
                return
            if stop != "holds":  # 1: the post-create stop; 2: this run's; its proof: the next ask
                X.fail_stop(daemon, stop, at=2, inspect_at=daemon.inspect_count() + 1)
            raise raised

        lanes = TenantLanes(BoxSeenLeadSpawn(author))
        ref.append(lanes)
        got, lanes = _production_lead_drain(s, daemon, lanes=lanes)

        assert len(daemon.created()) == 1, "the batch did not create exactly its one box"
        assert daemon.names() == [], "a box outlived the batch"
        X.no_path_docker(daemon)
        kept = _kept(daemon)
        if stop == "holds":
            assert got is None, got
            assert _failed(s) == ["case-run-0.json"], _failed(s)
            if follows == "next-claim":
                assert kept == ["create", "stop", "start", f"agent:{fixture_uuid('run-0')}", "stop",
                                "start", f"agent:{fixture_uuid('run-1')}", "stop", "rm"], kept
                assert _delivered_text(s, AGENT_NAME) == VETTED.strip()
            return
        X.assert_the_stop_fault_won(got, raised, daemon, stop)
        assert X.POINTER not in str(got), f"a mid-batch box fault got a build pointer: {got}"
        assert _failed(s) == [], "a claim was dead-lettered under a box fault"
        assert _claim_attempts(s) == {"case-run-0.json": 1}, (
            f"the box fault charged the claim more than its one serve: {_claim_attempts(s)}")
        assert _claim_files(s) == (["case-run-1.json"] if follows == "next-claim" else [],
                                   ["case-run-0.json"]), _claim_files(s)
        assert kept[:4] == ["create", "stop", "start", f"agent:{fixture_uuid('run-0')}"], kept
        assert "start" not in kept[4:], f"a later run was started beside the box: {kept}"
        assert kept[-1:] == ["rm"], kept
        assert lanes.pitfalls_ticks == 0
        _nothing_delivered(s)


@pytest.mark.parametrize("docker", ["carried", "path-default"])
@pytest.mark.parametrize("stop", ["refused", "holds"])
def test_a_claims_stop_fault_after_a_clean_agent_halts_the_production_drain(
        tmp_path: Path, monkeypatch, data_root: Path, stop: str, docker: str):
    """#1195 on the P4 lane: a claim's stop fault after a clean agent halts the production drain
    with nothing delivered and the claim charged once; with the stop holding (control) the
    agent's draft is delivered as a `lead-author/` PR on the tenant forge."""
    with _production_tenant_lead_scene(tmp_path, monkeypatch, data_root, "run-0",
                                       path_default=docker == "path-default") as (s, daemon):
        ref: list = []

        def author(run_dir: Path) -> None:
            daemon.mark(f"agent:{run_dir.name}")
            write(ref[0].skills_dir / AGENT_NAME, VETTED)
            if stop == "refused":
                daemon.refuse_stop()

        lanes = TenantLanes(BoxSeenLeadSpawn(author))
        ref.append(lanes)
        got, _lanes = _production_lead_drain(s, daemon, lanes=lanes)

        assert f"agent:{fixture_uuid('run-0')}" in daemon.steps(), "the agent was never reached"
        assert daemon.names() == [], "a box outlived the batch"
        if docker == "carried":
            X.no_path_docker(daemon)
        if stop == "holds":
            assert got is None, got
            assert _delivered_text(s, AGENT_NAME) == VETTED.strip()
            return
        assert isinstance(got, BoxFault), got
        _nothing_delivered(s)
        assert _failed(s) == [], "the claim was dead-lettered for a box that would not stop"
        assert _claim_attempts(s) == {"case-run-0.json": 1}, (
            f"the box fault charged the claim more than its one serve: {_claim_attempts(s)}")


def test_a_claim_a_box_fault_halted_is_served_on_the_next_tick(
        tmp_path: Path, monkeypatch, data_root: Path):
    """#1195 on the P4 lane: a claim a box fault halted is served again on the next tick, and its
    commit is then delivered on the tenant forge."""
    with _production_tenant_lead_scene(tmp_path, monkeypatch, data_root, "run-0") as (s, daemon):
        served: list[str] = []
        ref: list = []

        def author(run_dir: Path) -> None:
            daemon.mark(f"agent:{run_dir.name}")
            served.append(run_dir.name)
            write(ref[0].skills_dir / AGENT_NAME, VETTED)
            if len(served) == 1:
                daemon.refuse_stop()  # tick 1's run only

        lanes = TenantLanes(BoxSeenLeadSpawn(author))
        ref.append(lanes)
        got1, _ = _production_lead_drain(s, daemon, lanes=lanes)
        assert isinstance(got1, BoxFault), f"tick 1 did not halt on its box fault: {got1!r}"
        _nothing_delivered(s)
        assert _claim_attempts(s) == {"case-run-0.json": 1}, _claim_attempts(s)

        got2, _ = _production_lead_drain(s, daemon, lanes=lanes)

        assert got2 is None, f"tick 2 did not serve the claim: {got2!r}"
        assert served == [fixture_uuid("run-0"), fixture_uuid("run-0")], (
            f"tick 2 did not serve the claim again: {served}")
        assert _failed(s) == [], f"the claim was quarantined or dead-lettered: {_failed(s)}"
        assert _delivered_text(s, AGENT_NAME) == VETTED.strip()
        assert _claim_files(s) == ([], []), _claim_files(s)
        X.no_path_docker(daemon)


@pytest.mark.parametrize("handed", ["handle", "executor"])
def test_the_lead_authors_deps_refuse_the_handle_as_its_box(tmp_path: Path, monkeypatch,
                                                            handed: str):
    daemon, box, runs = X.boxed(tmp_path, monkeypatch, NAME)
    s = _lead_scene(tmp_path)
    built: list[Any] = []
    got = X.caught(lambda: built.append(bind(
        LEAD_AUTHOR_DEF, s.run_dir, defender_dir=s.paths.repo_root / "defender",
        box=runs if handed == "handle" else box)))
    assert daemon.docker_calls() == [], f"binding the spawn's deps asked docker: {daemon.steps()}"
    X.no_path_docker(daemon)
    if handed == "executor":
        assert got is None, got
        assert built[0].box is box
        return
    assert isinstance(got, ValueError), f"the spawn's deps took the run handle as its box: {got!r}"
    assert built == []


#: A batch box that never comes up (#1195): the create refused, the sentinel refused, the alias
#: ban not in force. The legacy worktree cut-commit pointer is gone with the worktree.
BATCH_START_FAULTS = [
    pytest.param("refuse_create", BoxFault, id="create"),
    pytest.param("refuse_sentinel", BoxFault, id="sentinel"),
    pytest.param("allow_an_alias", AliasBanNotInForce, id="link-ban"),
]


@pytest.mark.parametrize(("knob", "kind"), BATCH_START_FAULTS)
def test_a_batch_start_fault_claims_nothing_and_dead_letters_nothing(
        tmp_path: Path, monkeypatch, data_root: Path, knob: str, kind: type):
    """#1195 on the P4 lane: a batch box that never comes up claims and charges nothing, runs no
    lane step and delivers nothing."""
    with _production_tenant_lead_scene(tmp_path, monkeypatch, data_root, "run-0", "run-1") as (s, daemon):
        monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
        persist.append_pitfalls(_system_rows(), state=_state1135.state_for_paths(s.paths))
        attempts_before = _attempts(s.paths)
        qdir = _request_dir(s)
        markers_before = {p.name: p.read_bytes() for p in qdir.glob("*.json")}
        getattr(daemon, knob)()

        got, lanes = _production_lead_drain(s, daemon, lambda _rd: None)

        assert isinstance(got, kind), got
        assert {p.name: p.read_bytes() for p in qdir.glob("*.json")} == markers_before, (
            "a claim was claimed or charged for a box that never came up")
        assert _claim_files(s)[1] == [], "a claim was claimed for a box that never came up"
        assert _failed(s) == []
        assert lanes.agent.calls == []
        assert lanes.pitfalls_ticks == 0
        assert _attempts(s.paths) == attempts_before
        _nothing_delivered(s)
        X.no_path_docker(daemon)
