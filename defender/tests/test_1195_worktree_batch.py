"""#1195 amendment (2026-10-06), E3/E6/N12: the drain's batch hands its work a box SOURCE, starts no
box itself, proves the box gone at batch end, and names the cut commit on a box fault.

`drains._run_worktree_batch(..., start_box=, stop_box=, scrub=)` keeps its seams. It builds
`BoxSource(_drain_box_request(wt, batch_id, label, paths), start_box=, stop_box=)` instead of
starting a box, passes it as `do_work(wt_paths, box=source)`, and at batch end runs
`stop_and_scrub(source, wt, stop_box=lambda s: s.teardown(), ...)`: taint and the scan are
unchanged. `start_box` is called once per agent run, never at batch start. A `BoxFault`
escaping `do_work` is re-raised, chained, with a pointer naming `origin/main @ <cut sha>` (the
commit recorded at `start_batch`, not the worktree's HEAD), plus the build-remedy clause when
the fault carries one (E6).

The work steps here stand in for a lane: each "agent run" is `box_for_run(box)`, the spawn
sites' own `with`. Fakes enter through `start_box=`, `stop_box=`, `scrub=`, `branch=`, and a
`docker` program first on `PATH` (`_box1195.FakeDaemon`), which the source's default status
probe reaches.

Tests -> obligations:

- E3 (-> O2', O3'): `test_the_drain_starts_no_box_and_hands_its_work_the_batchs_source` (both
  lanes), `test_each_run_in_the_work_starts_the_drains_own_request_once_and_removes_it`,
  `test_the_batch_end_teardown_removes_a_box_a_run_left_before_the_scan` (a masked run fault:
  the batch delivers only once the box is gone), `test_a_batch_end_teardown_that_cannot_remove_the_box_blocks_the_scan_and_delivery`,
  `test_a_batch_end_teardown_fault_under_a_failing_work_is_logged_and_the_work_fault_escapes`
  (the work's own fault, or a `BoxFault`),
  `test_the_batch_end_teardown_removes_the_box_under_an_escaping_box_fault`.
- N12: `test_an_unboxed_batch_makes_no_docker_call_at_batch_end` (with its sandboxed control),
  `test_the_opt_out_fallback_makes_no_docker_call_after_its_last_run`.
- E6 (-> O4): `test_a_box_fault_escaping_the_work_names_the_cut_commit_after_a_batch_commit`
  (raised by the work, or by a run's start; with and without the build remedy), with
  `test_control_a_fault_that_is_not_a_box_fault_escapes_unchanged`.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import pytest

from defender.learning.core import drains
from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.runtime import box as box_mod
from defender.runtime.box import BoxFault, unboxed_executor
from defender.runtime.scrub import verdict_path
from defender.tests import _box1195 as X
from defender.tests._declared869 import commit_all
from defender.tests._spec1092 import GitWorktreeBranch
from defender.tests.e2e._box665 import RecordingBranch, loop_paths

LABELS = [pytest.param(AUTHOR_DRAIN_LABEL, id="lessons"),
          pytest.param(LEAD_AUTHOR_DRAIN_LABEL, id="lead-author")]


class Scrub:
    """The `scrub=` seam: records each tree it walks into the shared `events`."""

    def __init__(self, events: list) -> None:
        self.events = events
        self.trees: list[Path] = []

    def __call__(self, tree: Path, *_a: Any, **_kw: Any) -> None:
        self.events.append(f"scrub:{tree}")
        self.trees.append(tree)


def _batch_id(events: list[str]) -> str:
    started = [e.split(":", 1)[1] for e in events if e.startswith("start_batch:")]
    assert len(started) == 1, events
    return started[0]


def _drive(tmp_path: Path, *, do_work: Any, start_box: Any, stop_box: Any, events: list,
           branch: Any = None, label: Any = AUTHOR_DRAIN_LABEL) -> tuple[int, Any, Scrub]:
    paths = loop_paths(tmp_path)
    branch = (  # lint-default: ok — the default is built from this call's tmp_path and events
        branch if branch is not None else RecordingBranch(tmp_path / "wt", events=events))
    scrub = Scrub(events)
    rc = drains._run_worktree_batch(
        paths, branch, label=label, has_work=lambda _p: True, do_work=do_work,
        start_box=start_box, stop_box=stop_box, scrub=scrub,
    )
    return rc, branch, scrub


def _runs_in_work(n: int, events: list, seen: list) -> Any:
    """A work step with `n` agent runs, each `box_for_run(box)` logging `run:<i>` inside it."""
    def work(_wt_paths: LoopPaths, *, box: Any = None) -> None:
        seen.append(box)
        for i in range(n):
            with X.box_for_run(box) as run_box:
                events.append(f"run:{i}")
                seen.append(run_box)

    return work


# ---------------------------------------------------------------------------------------
# E3: no box at batch start; one start per run; the source's name is the batch's
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", LABELS)
def test_the_drain_starts_no_box_and_hands_its_work_the_batchs_source(tmp_path: Path, label: Any):
    """A batch whose work runs no agent: `start_box` is never called — not before the work, not
    during it, not after. The work is handed a box source named for the batch
    (`defender-drain-<batch id>`), and the batch delivers."""
    events: list[str] = []
    runs = X.Runs()
    seen: list[Any] = []

    def work(_wt_paths: LoopPaths, *, box: Any = None) -> None:
        events.append("work")
        assert runs.requests == [], "a box was started before the work ran"
        seen.append(box)

    rc, _branch, _scrub = _drive(tmp_path, do_work=work, start_box=runs.start,
                                 stop_box=runs.stop, events=events, label=label)
    assert rc == 0
    assert runs.requests == [], "the drain started a box with no agent run to hold"
    assert runs.stopped == []
    assert len(seen) == 1, seen
    assert seen[0] is not None, "the work was handed no box source"
    assert seen[0].name == f"defender-drain-{_batch_id(events)}"
    assert any(e.startswith("finish_batch:") for e in events), events


@pytest.mark.parametrize("label", LABELS)
def test_each_run_in_the_work_starts_the_drains_own_request_once_and_removes_it(
        tmp_path: Path, label: Any):
    """A work step with two agent runs: two starts, each handed the drain's own request for the
    batch (`_drain_box_request(wt, batch_id, label, paths)`: one container name per batch), each
    started inside the work, its run's body handed that start's box, and each box stopped before
    the next start. The scan follows the last run; the delivery follows the scan."""
    events: list[str] = []
    runs = X.Runs()
    runs.on_start = lambda b: events.append(f"start:{b.n}")
    runs.on_stop = lambda b: events.append(f"stop:{b.n}")
    seen: list[Any] = []
    rc, branch, _scrub = _drive(tmp_path, do_work=_runs_in_work(2, events, seen),
                                start_box=runs.start, stop_box=runs.stop, events=events,
                                label=label)
    assert rc == 0
    batch_id = _batch_id(events)
    wt = tmp_path / "wt" / f"{branch.branch_prefix.rstrip('/').replace('/', '-')}-{batch_id}"
    want = drains._drain_box_request(wt, batch_id, label, loop_paths(tmp_path))
    assert runs.requests == [want, want], runs.requests
    assert len(runs.boxes) == 2, runs.boxes
    assert seen[1:] == runs.boxes, "a run's body was not handed its own start's box"
    assert [id(b) for b in runs.stopped] == [id(b) for b in runs.boxes]
    order = [e for e in events if e.split(":")[0] in
             ("start_batch", "start", "run", "stop", "scrub", "finish_batch")]
    kinds = [e.split(":")[0] for e in order]
    assert kinds == ["start_batch", "start", "run", "stop", "start", "run", "stop", "scrub",
                     "finish_batch"], order


# ---------------------------------------------------------------------------------------
# E3: the batch-end teardown proves the name gone before the scan
# ---------------------------------------------------------------------------------------


class DaemonStart:
    """A `start_box=` that registers the request's container, running, with `daemon` and hands
    back a sandboxed executor naming it (what the real start does, minus the probes)."""

    def __init__(self, daemon: X.FakeDaemon, events: list) -> None:
        self.daemon, self.events = daemon, events
        self.requests: list[Any] = []

    def __call__(self, request: Any, *_a: Any, **_kw: Any) -> Any:
        self.requests.append(request)
        self.daemon.hold(request.name, "running")
        self.events.append("start")
        return X.sandboxed(request.name)


def _masking_work(events: list, daemon: X.FakeDaemon, *, refusals: int,
                  then_raise: BaseException | None = None) -> Any:
    """One agent run whose removal is refused `refusals` times; the run's teardown fault is
    caught by the work itself (a layer that masks it), then `then_raise` is raised, if given."""
    def work(_wt_paths: LoopPaths, *, box: Any = None) -> None:
        daemon.refuse_rm(refusals)
        try:
            with X.box_for_run(box):
                events.append("run")
                daemon.mark("run")
        except BoxFault:
            events.append("masked")
        if then_raise is not None:
            raise then_raise

    return work


def test_the_batch_end_teardown_removes_a_box_a_run_left_before_the_scan(
        tmp_path: Path, monkeypatch):
    """The run's removal is refused and the work masks that fault, so the box is still running
    when the work returns. The batch-end teardown asks the status, removes it, and only then is
    the tree scanned and the batch delivered: no container is left."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    events: list[str] = []
    start = DaemonStart(daemon, events)
    rc, _branch, _scrub = _drive(tmp_path, do_work=_masking_work(events, daemon, refusals=1),
                                 start_box=start, stop_box=box_mod.stop_box, events=events)
    assert rc == 0
    name = start.requests[0].name
    assert "masked" in events, "the run's removal was not refused, so the row is vacuous"
    assert daemon.names() == [], "a box outlived the batch"
    after_run = daemon.steps(of=name)[daemon.steps(of=name).index("run"):]
    assert "status" in after_run, after_run
    assert after_run.count("rm") >= 2, after_run
    scrub_at = next(i for i, e in enumerate(events) if e.startswith("scrub:"))
    finish_at = next(i for i, e in enumerate(events) if e.startswith("finish_batch:"))
    assert events.index("masked") < scrub_at < finish_at, events


class VerdictAtCleanup(RecordingBranch):
    """`RecordingBranch` noting, at each cleanup, whether a did-not-run verdict stood beside the
    worktree (the cleanup removes it)."""

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.verdicts: list[bool] = []

    def cleanup(self, wt: Path) -> None:
        self.verdicts.append(verdict_path(wt).exists())
        super().cleanup(wt)


def test_a_batch_end_teardown_that_cannot_remove_the_box_blocks_the_scan_and_delivery(
        tmp_path: Path, monkeypatch):
    """The same masked run, with the batch-end removal refused too: the teardown raises
    `BoxFault` (nothing else is in flight), the tree is not scanned, its did-not-run verdict is
    written, and nothing is delivered. Control: the row above."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    events: list[str] = []
    start = DaemonStart(daemon, events)
    branch = VerdictAtCleanup(tmp_path / "wt", events=events)
    with pytest.raises(BoxFault):
        _drive(tmp_path, do_work=_masking_work(events, daemon, refusals=-1), start_box=start,
               stop_box=box_mod.stop_box, events=events, branch=branch)
    assert not any(e.startswith("scrub:") for e in events), events
    assert not any(e.startswith("finish_batch:") for e in events), events
    assert branch.verdicts == [True], "no did-not-run verdict stood for the unscanned tree"
    assert daemon.status(start.requests[0].name) == "running"


#: What the work raises after its masked run: a fault of its own, or a `BoxFault` (a later
#: run's start refusing, say). Either way the batch-end teardown still runs.
WORK_FAULTS = [
    pytest.param(lambda: RuntimeError("the lane failed after its run"), id="work-fault"),
    pytest.param(lambda: BoxFault("a later run's box would not start"), id="box-fault"),
]


@pytest.mark.parametrize("make_crash", WORK_FAULTS)
def test_a_batch_end_teardown_fault_under_a_failing_work_is_logged_and_the_work_fault_escapes(
        tmp_path: Path, monkeypatch, caplog, make_crash: Any):
    """The masked run, then the work fails; the batch-end removal is refused too: the work's own
    fault escapes (a `BoxFault` with the cut commit added, E6), the teardown's is logged, naming
    the box, so the teardown was tried, and nothing is scanned or delivered."""
    caplog.set_level(logging.WARNING)
    daemon = X.FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    events: list[str] = []
    crash = make_crash()
    start = DaemonStart(daemon, events)
    got = X.caught(lambda: _drive(
        tmp_path, do_work=_masking_work(events, daemon, refusals=-1, then_raise=crash),
        start_box=start, stop_box=box_mod.stop_box, events=events))
    assert X.carries(got, crash), (got, X.chain(got))
    assert isinstance(got, type(crash)), got
    assert not any(e.startswith(("scrub:", "finish_batch:")) for e in events), events
    name = start.requests[0].name
    assert any(r.levelno >= logging.ERROR and name in r.getMessage() for r in caplog.records), (
        "the batch-end teardown fault left no trace under the work's own failure")


def test_the_batch_end_teardown_removes_the_box_under_an_escaping_box_fault(
        tmp_path: Path, monkeypatch):
    """The masked run leaves its box running, then a `BoxFault` escapes the work. The batch-end
    teardown still runs under it: it asks the status and removes the box, so none outlives the
    batch, and the tree is scanned, if at all, only once it is gone. The `BoxFault` escapes the
    drain (with the cut commit added) and nothing is delivered. Control:
    `test_the_batch_end_teardown_removes_a_box_a_run_left_before_the_scan` (no fault)."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    events: list[str] = []
    crash = BoxFault("a later run's box would not start")
    start = DaemonStart(daemon, events)
    watch = X.ScanWatch(daemon, events)
    got = X.caught(lambda: drains._run_worktree_batch(
        loop_paths(tmp_path), RecordingBranch(tmp_path / "wt", events=events),
        label=AUTHOR_DRAIN_LABEL, has_work=lambda _p: True,
        do_work=_masking_work(events, daemon, refusals=1, then_raise=crash),
        start_box=start, stop_box=box_mod.stop_box, scrub=watch))
    assert isinstance(got, BoxFault), got
    assert X.carries(got, crash), X.chain(got)
    assert "masked" in events, "the run's removal was not refused, so the row is vacuous"
    name = start.requests[0].name
    after_run = daemon.steps(of=name)[daemon.steps(of=name).index("run"):]
    assert "status" in after_run, f"no batch-end teardown under the box fault: {after_run}"
    assert daemon.names() == [], "the box the run left outlived the batch"
    watch.assert_no_scan_beside_a_box()
    assert not any(e.startswith("finish_batch:") for e in events), events


# ---------------------------------------------------------------------------------------
# N12: an unboxed batch asks no daemon at batch end
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("executor", ["unboxed", "sandboxed"])
def test_an_unboxed_batch_makes_no_docker_call_at_batch_end(
        tmp_path: Path, monkeypatch, executor: str):
    """Every run hands back an unboxed executor (the opt-out's): the batch-end teardown makes no
    docker call at all, the tree is scanned and the batch delivers. Control: the same batch with
    sandboxed executors, whose teardown asks the daemon the batch box's status after the last
    run."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    events: list[str] = []

    def start(request: Any, *_a: Any, **_kw: Any) -> Any:
        return unboxed_executor() if executor == "unboxed" else X.sandboxed(request.name)

    def work(_wt_paths: LoopPaths, *, box: Any = None) -> None:
        for _ in range(2):
            with X.box_for_run(box):
                daemon.mark("run")

    rc, _branch, _scrub = _drive(tmp_path, do_work=work, start_box=start,
                                 stop_box=lambda *_a, **_k: None, events=events)
    assert rc == 0
    assert any(e.startswith("scrub:") for e in events), events
    steps = daemon.steps()
    tail = steps[len(steps) - steps[::-1].index("run"):]
    if executor == "unboxed":
        assert steps == ["run", "run"], f"an unboxed batch asked the daemon: {steps}"
        return
    assert "status" in tail, f"the sandboxed control's teardown asked nothing: {steps}"


def test_the_opt_out_fallback_makes_no_docker_call_after_its_last_run(
        tmp_path: Path, monkeypatch, caplog):
    """`DEFENDER_ALLOW_UNSANDBOXED=1` and a daemon that refuses every create: each run's real
    `start_box` falls back to a host executor (warning), the runs complete, and after the last
    one no docker call is made — the batch-end teardown asks the daemon nothing (N12)."""
    monkeypatch.setenv(box_mod._ALLOW_UNSANDBOXED, "1")
    daemon = X.FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    daemon.refuse_create()
    events: list[str] = []

    class PlantedBranch(RecordingBranch):
        def start_batch(self, batch_id: str) -> Path:
            wt = super().start_batch(batch_id)
            X.plant_image_inputs(wt)
            return wt

    hosts: list[Any] = []

    def work(_wt_paths: LoopPaths, *, box: Any = None) -> None:
        for _ in range(2):
            with X.box_for_run(box) as run_box:
                hosts.append(run_box)
                daemon.mark("run")

    rc, _branch, _scrub = _drive(tmp_path, do_work=work, start_box=box_mod.start_box,
                                 stop_box=box_mod.stop_box, events=events,
                                 branch=PlantedBranch(tmp_path / "wt", events=events))
    assert rc == 0
    assert len(hosts) == 2, hosts
    assert not any(h.sandboxed for h in hosts), hosts
    assert "create" in daemon.steps(), "the start never asked the daemon, so the row is vacuous"
    steps = daemon.steps()
    after_last = steps[len(steps) - steps[::-1].index("run"):]
    assert after_last == [], f"the opt-out batch asked the daemon after its last run: {after_last}"


# ---------------------------------------------------------------------------------------
# E6: the escaping box fault names the commit the worktree was cut from
# ---------------------------------------------------------------------------------------

_POINTER = re.compile(r"origin/main @ ([0-9a-f]{7,40})")


def _box_fault(wt: Path, *, remedy: bool) -> BoxFault:
    if remedy:
        return BoxFault(f"the daemon holds no image defender-box:x — {box_mod.build_remedy(wt)}")
    return BoxFault("a container named defender-drain-x already exists and is running")


@pytest.mark.parametrize("remedy", [True, False], ids=["build-remedy", "no-remedy"])
@pytest.mark.parametrize("raised_by", ["work", "run-start"])
def test_a_box_fault_escaping_the_work_names_the_cut_commit_after_a_batch_commit(
        tmp_path: Path, raised_by: str, remedy: bool):
    """The work commits into the worktree (HEAD moves past the cut), then a `BoxFault` escapes
    it — raised by the work, or by the next agent run's start. The drain re-raises a `BoxFault`
    chained to it, naming `origin/main @ <the commit the worktree was cut from>` (never the
    batch commit), with "check out" and — only when the fault carries the build remedy — "run
    the build". The worktree is gone, so the pointer is all that names where to build."""
    events: list[str] = []
    branch = GitWorktreeBranch(tmp_path / "wt", events=events)
    faults: list[BoxFault] = []
    heads: list[str] = []
    runs = X.Runs()

    def work(wt_paths: LoopPaths, *, box: Any = None) -> None:
        wt = wt_paths.repo_root
        (wt / "batch-commit.md").write_text("a commit this batch made\n", encoding="utf-8")
        heads.append(commit_all(wt, "a batch commit"))
        fault = _box_fault(wt, remedy=remedy)
        faults.append(fault)
        if raised_by == "work":
            raise fault
        runs.start_faults[1] = fault
        with X.box_for_run(box):
            events.append("agent")

    with pytest.raises(BoxFault) as got:
        _drive(tmp_path, do_work=work, start_box=runs.start, stop_box=runs.stop, events=events,
               branch=branch)
    assert "agent" not in events
    assert X.carries(got.value, faults[0]), X.chain(got.value)
    assert got.value is not faults[0], "the box fault escaped without the pointer"
    message = str(got.value)
    pointer = _POINTER.search(message)
    assert pointer, message
    assert branch.cut_commit is not None
    assert branch.cut_commit != heads[0], "the work never moved HEAD, so the row is vacuous"
    assert branch.cut_commit.startswith(pointer.group(1)), (pointer.group(1), branch.cut_commit)
    assert not heads[0].startswith(pointer.group(1)), "the pointer names the batch commit"
    tail = message[pointer.end():].lower()
    assert "check out" in tail, message
    assert ("build" in tail) is remedy, message
    assert "cleanup" in events, events
    assert not _wt_of(branch, events).exists(), "the worktree survived the box fault"


def _wt_of(branch: Any, events: list[str]) -> Path:
    batch_id = _batch_id(events)
    return branch._base / f"{branch.branch_prefix.rstrip('/').replace('/', '-')}-{batch_id}"


def test_control_a_fault_that_is_not_a_box_fault_escapes_unchanged(tmp_path: Path):
    """The same batch commit, then a `RuntimeError`: it escapes as itself, with no pointer."""
    events: list[str] = []
    branch = GitWorktreeBranch(tmp_path / "wt", events=events)
    crash = RuntimeError("the lane failed")

    def work(wt_paths: LoopPaths, *, box: Any = None) -> None:
        (wt_paths.repo_root / "batch-commit.md").write_text("x\n", encoding="utf-8")
        commit_all(wt_paths.repo_root, "a batch commit")
        raise crash

    with pytest.raises(RuntimeError) as got:
        _drive(tmp_path, do_work=work, start_box=X.Runs().start, stop_box=lambda *_a: None,
               events=events, branch=branch)
    assert got.value is crash
