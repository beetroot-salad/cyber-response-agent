"""#1195 design amendment 3 (2026-10-06) at the batch: one box per batch, created and checked at
batch start, wrapped in a run handle, stopped at once, started only for each agent run; the box
carries its docker, and a stop fault halts the batch.

`drains._run_worktree_batch(..., start_box=, stop_box=, scrub=)` is main's (6443b33b) plus:
`box = start_box(_drain_box_request(...))` at batch start, then `runs = BoxRuns(box)`, both under
main's `_unwind_worktree_start_fault` and its cut-commit pointer; then, as the first statements
inside the `try` whose `finally` runs `stop_and_scrub(box, wt, stop_box=stop_box, ...)`,
`runs.stop()` and `do_work(wt_paths, box=runs)`.

The work steps here stand in for a lane: each "agent run" is `box_for_run(handle)`, the spawn
sites' own `with`. Only `start_box=` brings a docker: `X.HeldStart` (or the real `start_box`
with `docker=` the fake daemon) hands back an executor carrying the in-process
`_box1195.FakeDaemon`, and the batch's own stop, the runs and the default `stop_box` reach it
through that executor. The `docker` first on `PATH` is a `Tripwire`. `scrub=` and `branch=` are
the other seams. Never `monkeypatch.setattr`.

Tests -> obligations:

- E1' (-> O2''), F3: `test_the_batch_hands_the_work_a_handle_on_its_one_box_stopped_before_the_work`
  (both lanes: one `start_box` of the drain's own request; the work is handed a `BoxRuns`,
  never the executor; the box `exited` at the work's first step; the executor reached only
  inside a run), `test_each_agent_run_in_the_work_starts_the_one_box_and_stops_it` (one window
  per run; the batch-end `rm -f` before the scan, whether the work returns or raises).
- F2: those two and every row below: the post-create stop, each start and stop, and the
  batch-end removal reach the carried docker, none the `docker` on `PATH`.
- E1'/O4, the post-create stop: `test_a_post_create_stop_fault_still_gets_the_batch_end_removal`
  (refused, no effect, unproven, the seam raising: no work, `rm -f`, the scan after it, no
  pointer), with its `holds` control; F4:
  `test_a_post_create_stop_is_proven_only_by_exited_or_dead` (`dead` proves it; `paused` and
  `restarting` do not).
- O4, batch start: `test_a_batch_start_fault_escapes_as_on_main_before_any_work` (a create or
  sentinel `BoxFault` with main's pointer, a link-ban `AliasBanNotInForce` as itself; no work,
  no stop or start, the worktree cleaned up); F2/F3, the handle at batch start:
  `test_an_executor_the_batch_cannot_hold_a_handle_on_is_a_batch_start_fault` (an object that
  cannot say whether it is sandboxed; a sandboxed executor carrying no docker).
- F1 (O5): `test_a_run_stop_fault_under_a_failing_run_halts_the_batch_with_the_failure_as_context`
  (no pointer, no delivery, the removal and the scan), with its `holds` control.
- E3' (-> O2'', N11''): `test_a_swallowed_run_stop_fault_makes_the_next_run_refuse_and_the_batch_halt`
  (no pointer on a mid-batch `BoxFault`), with `test_control_two_runs_whose_stops_hold_deliver`.
- N12: `test_an_unboxed_batch_asks_the_daemon_nothing` (with its sandboxed control),
  `test_the_opt_out_fallback_asks_the_daemon_nothing_after_its_failed_create`.
"""
from __future__ import annotations

from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.learning.core import drains
from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL, LoopPaths
from defender.runtime import box as box_mod
from defender.runtime.box import AliasBanNotInForce, BoxFault, unboxed_executor
from defender.tests import _box1195 as X
from defender.tests._spec1092 import GitWorktreeBranch
from defender.tests.e2e._box665 import RecordingBranch, loop_paths

LABELS = [pytest.param(AUTHOR_DRAIN_LABEL, id="lessons"),
          pytest.param(LEAD_AUTHOR_DRAIN_LABEL, id="lead-author")]


class TreedBranch(GitWorktreeBranch):
    """`GitWorktreeBranch` (a real git worktree holding the image inputs, its HEAD the cut
    commit) whose worktree also holds the lessons lane's writable trees, so the real
    `start_box` can plant and read back a sentinel in each of the drain's mounts."""

    def start_batch(self, batch_id: str) -> Path:
        wt = super().start_batch(batch_id)
        for tree in AUTHOR_DRAIN_LABEL.writable_trees(loop_paths(self._base).with_repo_root(wt)):
            tree.mkdir(parents=True, exist_ok=True)
        return wt


def _batch_id(events: list[str]) -> str:
    started = [e.split(":", 1)[1] for e in events if e.startswith("start_batch:")]
    assert len(started) == 1, events
    return started[0]


def _drive(tmp_path: Path, *, do_work: Any, start_box: Any, events: list, scrub: Any,
           stop_box: Any = box_mod.stop_box, branch: Any = None,
           label: Any = AUTHOR_DRAIN_LABEL) -> tuple[BaseException | None, Any]:
    """`_run_worktree_batch` over a recording branch (or `branch`): what it raised, and the
    branch."""
    branch = (  # lint-default: ok — the default is built from this call's tmp_path and events
        branch if branch is not None else RecordingBranch(tmp_path / "wt", events=events))
    got = X.caught(lambda: drains._run_worktree_batch(
        loop_paths(tmp_path), branch, label=label, has_work=lambda _p: True, do_work=do_work,
        start_box=start_box, stop_box=stop_box, scrub=scrub,
    ))
    return got, branch


def _daemon(tmp_path: Path, monkeypatch: Any) -> X.FakeDaemon:
    """The fake daemon, reached only through the executor `start_box` hands back; a `Tripwire`
    is the `docker` on `PATH`."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
    return daemon


class RunsInWork:
    """A work step marking `work` first, then `n` agent runs (`box_for_run(box)`, each marking
    `run` inside and noting what the run yielded), then raising `then_raise` if given (inside
    the last run when `inside`). `seen` holds what it was handed and every container's status
    at its first step; `got`, what each run yielded."""

    def __init__(self, daemon: X.FakeDaemon, n: int, *,
                 then_raise: BaseException | None = None, inside: bool = False) -> None:
        self.daemon, self.n, self.then_raise, self.inside = daemon, n, then_raise, inside
        self.seen: list[tuple[Any, dict[str, str | None]]] = []
        self.got: list[Any] = []

    def __call__(self, _wt_paths: LoopPaths, *, box: Any = None) -> None:
        self.seen.append((box, {n: self.daemon.status(n) for n in self.daemon.names()}))
        self.daemon.mark("work")
        for i in range(self.n):
            with X.box_for_run(box) as got:
                self.got.append(got)
                self.daemon.mark("run")
                if self.inside and i == self.n - 1 and self.then_raise is not None:
                    raise self.then_raise
        if self.then_raise is not None:
            raise self.then_raise


# ---------------------------------------------------------------------------------------
# E1': one box per batch, created at batch start and stopped before the work
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", LABELS)
def test_the_batch_hands_the_work_a_handle_on_its_one_box_stopped_before_the_work(
        tmp_path: Path, monkeypatch, label: Any):
    """`start_box` is called once, at batch start, with the drain's own request
    (`_drain_box_request(wt, batch_id, label, paths)`), and leaves the box running (the
    positive control); `docker stop -t 0 <name>` follows, through the docker the executor
    carries, before the work's first step, which sees the box `exited`. The work is handed a
    `BoxRuns`, never the executor itself, and reaches `start_box`'s executor only inside a run;
    the batch starts nothing itself."""
    daemon = _daemon(tmp_path, monkeypatch)
    events: list[str] = []
    start = X.HeldStart(daemon, events)
    work = RunsInWork(daemon, 1)
    got, branch = _drive(tmp_path, do_work=work, start_box=start, events=events,
                         scrub=X.ScanWatch(daemon, events), label=label)
    assert got is None, got
    batch_id = _batch_id(events)
    wt = tmp_path / "wt" / f"{branch.branch_prefix.rstrip('/').replace('/', '-')}-{batch_id}"
    want = drains._drain_box_request(wt, batch_id, label, loop_paths(tmp_path))
    assert start.requests == [want], start.requests
    name = want.name
    [(handle, statuses)] = work.seen
    assert isinstance(handle, X.box_runs_type()), f"the work was handed {handle!r}, not a handle"
    assert statuses == {name: "exited"}, statuses
    assert work.got == [start.boxes[0]], "the run did not yield start_box's executor"
    steps = daemon.steps(of=name)
    assert steps.index("start_box") < steps.index("stop") < steps.index("work"), steps
    assert ["docker", "stop", "-t", "0", name] in daemon.docker_calls()
    assert "start" not in steps[:steps.index("work")], f"the batch started its box: {steps}"
    X.no_path_docker(daemon)


@pytest.mark.parametrize("work_raises", [False, True], ids=["work-returns", "work-raises"])
@pytest.mark.parametrize("label", LABELS)
def test_each_agent_run_in_the_work_starts_the_one_box_and_stops_it(
        tmp_path: Path, monkeypatch, label: Any, work_raises: bool):
    """Two agent runs in the work: each window (a `docker start` to the next `docker stop`)
    holds exactly its run; the one box is never created again; after the work, returning or
    raising, the batch-end `docker rm -f` removes it and only then is the tree scanned."""
    daemon = _daemon(tmp_path, monkeypatch)
    events: list[str] = []
    start = X.HeldStart(daemon, events)
    crash = RuntimeError("the lane failed after its runs")
    watch = X.ScanWatch(daemon, events)
    work = RunsInWork(daemon, 2, then_raise=crash if work_raises else None)
    got, _branch = _drive(tmp_path, do_work=work, start_box=start, events=events, scrub=watch,
                          label=label)
    assert got is (crash if work_raises else None), got
    assert len(start.requests) == 1
    assert daemon.windows() == [["run"], ["run"]], daemon.steps()
    steps = daemon.steps(of=start.requests[0].name)
    last_run = len(steps) - 1 - steps[::-1].index("run")
    assert last_run < steps.index("rm") < steps.index("scan"), steps
    watch.assert_scanned_once_the_box_was_gone()
    assert any(e.startswith("finish_batch:") for e in events) is not work_raises, events
    assert ["docker", "rm", "-f", start.requests[0].name] in daemon.docker_calls()
    X.no_path_docker(daemon)


# ---------------------------------------------------------------------------------------
# E1'/O4: the post-create stop sits inside the try the batch-end removal guards
# ---------------------------------------------------------------------------------------


def _drive_past_the_post_create_stop(tmp_path: Path, daemon: X.FakeDaemon,
                                     ) -> tuple[Any, RunsInWork, list[str], str]:
    """One batch over `daemon`, the real `start_box` making the box and its post-create stop:
    asserts the batch-end `docker rm -f` removed the box, the tree was scanned only after, and
    `PATH`'s docker was never asked. Returns what escaped, the work, the event log and the
    box's name."""
    events: list[str] = []
    start = X.HeldStart(daemon, events)
    work = RunsInWork(daemon, 0)
    watch = X.ScanWatch(daemon, events)
    got, _branch = _drive(tmp_path, do_work=work, start_box=start, events=events, scrub=watch)
    assert ["docker", "rm", "-f", start.requests[0].name] in daemon.docker_calls(), (
        "no batch-end removal")
    watch.assert_scanned_once_the_box_was_gone()
    X.no_path_docker(daemon)
    return got, work, events, start.requests[0].name


@pytest.mark.parametrize("stop", [*X.STOP_FAULTS, "holds"])
def test_a_post_create_stop_fault_still_gets_the_batch_end_removal(
        tmp_path: Path, monkeypatch, stop: str):
    """The stop right after the create fails (refused, answering 0 with the box still
    running, taking while its proof goes unanswered, or the seam raising): a `BoxFault` escapes
    the batch with no cut-commit pointer (it is not a build problem); the work never runs; the
    batch-end `docker rm -f` still removes the box, and the tree is scanned only after; nothing
    is delivered. Control (`holds`): the work runs."""
    daemon = _daemon(tmp_path, monkeypatch)
    if stop != "holds":
        X.fail_stop(daemon, stop, at=1, inspect_at=1)
    got, work, events, _name = _drive_past_the_post_create_stop(tmp_path, daemon)
    if stop == "holds":
        assert got is None, got
        assert len(work.seen) == 1
        return
    assert isinstance(got, BoxFault), got
    assert X.POINTER not in str(got), f"a post-create stop fault got a build pointer: {got}"
    assert work.seen == [], "the work ran beside a box that would not stop"
    assert not any(e.startswith("finish_batch:") for e in events), events


@pytest.mark.parametrize("left", ["dead", "paused", "restarting"])
def test_a_post_create_stop_is_proven_only_by_exited_or_dead(tmp_path: Path, monkeypatch,
                                                             left: str):
    """F4: the post-create stop answers 0 and leaves the box `dead`: nothing runs in it, so it
    is proven stopped and the work runs. Left `paused` (its processes frozen, not killed) or
    `restarting`, it is not: a `BoxFault` naming the status escapes with no pointer, the work
    never runs, the batch-end `rm -f` still removes the box and nothing is delivered."""
    daemon = _daemon(tmp_path, monkeypatch)
    daemon.stop_leaves_it_as(left, at=1)
    got, work, events, name = _drive_past_the_post_create_stop(tmp_path, daemon)
    if left == "dead":
        assert got is None, got
        assert [s for _, s in work.seen] == [{name: "dead"}], work.seen
        assert any(e.startswith("finish_batch:") for e in events), events
        return
    assert isinstance(got, BoxFault), f"a box left {left!r} passed as stopped: {got!r}"
    assert left in str(got), f"the fault does not name the status it saw: {got}"
    assert X.POINTER not in str(got), got
    assert work.seen == [], f"the work ran beside a box left {left!r}"
    assert not any(e.startswith("finish_batch:") for e in events), events


# ---------------------------------------------------------------------------------------
# O4: a fault creating or checking the box escapes at batch start, as on main
# ---------------------------------------------------------------------------------------

#: What makes the real `start_box` fail at batch start, how main surfaces it, and the words
#: that say which check failed: a create or sentinel fault is a `BoxFault` re-raised with the
#: cut commit; a link ban not in force is `AliasBanNotInForce` (a plain `Exception`), escaping
#: as itself.
START_FAULTS = [
    pytest.param("refuse_create", BoxFault, True, "could not create the box", id="create"),
    pytest.param("refuse_sentinel", BoxFault, True, "could not read back the startup sentinel",
                 id="sentinel"),
    pytest.param("allow_an_alias", AliasBanNotInForce, False, "ALLOWED", id="link-ban"),
]


@pytest.mark.parametrize(("knob", "kind", "pointed", "says"), START_FAULTS)
def test_a_batch_start_fault_escapes_as_on_main_before_any_work(  # noqa: PLR0913 — one fault, its class, pointer and words
        tmp_path: Path, monkeypatch, knob: str, kind: type, pointed: bool, says: str):
    """The REAL `start_box` over the daemon faults at batch start: the fault escapes the batch
    as on main (a `BoxFault` chained to the start's own and naming `origin/main @ <cut
    commit>`; a link ban as `AliasBanNotInForce`, unpointed); the work never runs, the box is
    never stopped or started, no container is left, and the worktree is cleaned up."""
    X.clear_opt_out(monkeypatch)
    daemon = _daemon(tmp_path, monkeypatch)
    getattr(daemon, knob)()
    events: list[str] = []
    branch = TreedBranch(tmp_path / "wt", events=events)
    work = RunsInWork(daemon, 1)
    got, _branch = _drive(tmp_path, do_work=work,
                          start_box=partial(box_mod.start_box, docker=daemon), events=events,
                          scrub=X.ScanWatch(daemon, events), branch=branch)
    assert isinstance(got, kind), got
    assert says in str(got), got
    assert work.seen == [], "the work ran though the box never came up"
    verbs = [c[1] for c in daemon.docker_calls()]
    assert "start" not in verbs, verbs
    assert "stop" not in verbs, verbs
    assert daemon.names() == [], "a container outlived the failed start"
    assert "cleanup" in events, events
    if pointed:
        assert f"{X.POINTER}{branch.cut_commit}" in str(got), got
        assert isinstance(got.__cause__, BoxFault), X.chain(got)
    else:
        assert X.POINTER not in str(got), got
    X.no_path_docker(daemon)


#: What `start_box` hands back that the batch can hold no handle on: an object that cannot say
#: whether it is sandboxed, and a sandboxed executor carrying no docker (its container created).
UNHELD = [
    pytest.param(lambda _start, _req: SimpleNamespace(name="defender-drain-x1195"),
                 id="unknown-object"),
    pytest.param(lambda start, req: X.sandboxed(start(req).name), id="sandboxed-without-docker"),
]


@pytest.mark.parametrize("hand_back", UNHELD)
def test_an_executor_the_batch_cannot_hold_a_handle_on_is_a_batch_start_fault(
        tmp_path: Path, monkeypatch, hand_back: Any):
    """`start_box` hands back what `BoxRuns` refuses: the `BoxFault` unwinds as a start fault
    does on main (the cut-commit pointer, the worktree cleaned up), before any work, with no
    docker asked, the `docker` on `PATH` least of all. Control:
    `test_the_batch_hands_the_work_a_handle_on_its_one_box_stopped_before_the_work`."""
    daemon = _daemon(tmp_path, monkeypatch)
    events: list[str] = []
    held = X.HeldStart(daemon, events)
    branch = TreedBranch(tmp_path / "wt", events=events)
    work = RunsInWork(daemon, 1)
    got, _branch = _drive(tmp_path, do_work=work, start_box=lambda req: hand_back(held, req),
                          events=events, scrub=X.ScanWatch(daemon, events), branch=branch)
    assert isinstance(got, BoxFault), got
    assert f"{X.POINTER}{branch.cut_commit}" in str(got), f"not unwound as a start fault: {got}"
    assert work.seen == [], "the work ran with no handle on its box"
    assert daemon.docker_calls() == [], daemon.docker_calls()
    assert "cleanup" in events, events
    assert not any(e.startswith("finish_batch:") for e in events), events
    X.no_path_docker(daemon)


# ---------------------------------------------------------------------------------------
# F1 (O5): a run's stop fault halts the batch, outranking the run's own failure
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("stop", [*X.STOP_FAULTS, "holds"])
@pytest.mark.parametrize("failure", [
    pytest.param(lambda: RuntimeError("the agent crashed"), id="exception"),
    pytest.param(KeyboardInterrupt, id="keyboard-interrupt"),
    *X.PROCESS_FAULTS,
])
def test_a_run_stop_fault_under_a_failing_run_halts_the_batch_with_the_failure_as_context(
        tmp_path: Path, monkeypatch, failure: Any, stop: str):
    """The work's run raises X (a crash, an interrupt, the spawn's own `TimeoutExpired` or
    `OSError`) and the run's stop fails: a `BoxFault` escapes the batch, never X, with X in its
    chain (its `__context__`, behind the seam's own exception when the seam raised at the stop
    or at its proof); no pointer (mid-batch); nothing delivered; the batch-end `rm -f` and the
    scan after it still run. Control (`holds`): X escapes as itself."""
    daemon = _daemon(tmp_path, monkeypatch)
    if stop != "holds":
        # 1: the post-create stop; 2: the run's. The status asks: 1 proves the post-create
        # stop; the run asks 2 before its start, 3 after it, 4 after its stop.
        X.fail_stop(daemon, stop, at=2, inspect_at=4)
    events: list[str] = []
    raised = failure()
    watch = X.ScanWatch(daemon, events)
    start = X.HeldStart(daemon, events)
    got, _branch = _drive(tmp_path, do_work=RunsInWork(daemon, 1, then_raise=raised, inside=True),
                          start_box=start, events=events, scrub=watch)
    assert ["docker", "rm", "-f", start.requests[0].name] in daemon.docker_calls()
    watch.assert_scanned_once_the_box_was_gone()
    assert not any(e.startswith("finish_batch:") for e in events), events
    X.no_path_docker(daemon)
    if stop == "holds":
        assert got is raised, got
        return
    X.assert_the_stop_fault_won(got, raised, daemon, stop)
    assert X.POINTER not in str(got), got


# ---------------------------------------------------------------------------------------
# E3': a swallowed stop fault is caught at the next run's start
# ---------------------------------------------------------------------------------------


class MaskingRuns:
    """Two agent runs; the first's `BoxFault` (its stop refused) is swallowed by the work, as
    a layer above a spawn may mask it; the second run's is not."""

    def __init__(self, daemon: X.FakeDaemon, events: list) -> None:
        self.daemon, self.events = daemon, events

    def __call__(self, _wt_paths: LoopPaths, *, box: Any = None) -> None:
        try:
            with X.box_for_run(box):
                self.daemon.mark("run")
        except BoxFault:
            self.events.append("masked")
        with X.box_for_run(box):
            self.daemon.mark("run")


def test_a_swallowed_run_stop_fault_makes_the_next_run_refuse_and_the_batch_halt(
        tmp_path: Path, monkeypatch):
    """Run 1's stop is refused (the box keeps running) and the work swallows that `BoxFault`.
    Run 2 refuses before its body and stops the box best-effort; its `BoxFault` escapes the
    batch with no pointer (mid-batch, not a build problem). The batch-end `rm -f` removes the
    box, the scan follows it, and nothing is delivered."""
    daemon = _daemon(tmp_path, monkeypatch)
    daemon.refuse_stop(at=[2])  # 1: the post-create stop; 2: run 1's
    events: list[str] = []
    watch = X.ScanWatch(daemon, events)
    got, _branch = _drive(tmp_path, do_work=MaskingRuns(daemon, events),
                          start_box=X.HeldStart(daemon, events), events=events, scrub=watch)
    assert "masked" in events, "run 1's stop did not fail, so the row is vacuous"
    assert isinstance(got, BoxFault), got
    assert X.POINTER not in str(got), got
    steps = daemon.steps()
    assert steps.count("run") == 1, f"run 2's body ran beside a running box: {steps}"
    assert steps.count("start") == 1, f"run 2 started a box that was still running: {steps}"
    assert steps.count("stop") == 3, f"no best-effort stop on run 2's refusal: {steps}"
    watch.assert_scanned_once_the_box_was_gone()
    assert not any(e.startswith("finish_batch:") for e in events), events
    X.no_path_docker(daemon)


def test_control_two_runs_whose_stops_hold_deliver(tmp_path: Path, monkeypatch):
    daemon = _daemon(tmp_path, monkeypatch)
    events: list[str] = []
    got, _branch = _drive(tmp_path, do_work=MaskingRuns(daemon, events),
                          start_box=X.HeldStart(daemon, events), events=events,
                          scrub=X.ScanWatch(daemon, events))
    assert got is None, got
    assert "masked" not in events
    assert daemon.steps().count("run") == 2
    assert any(e.startswith("finish_batch:") for e in events), events


# ---------------------------------------------------------------------------------------
# N12: the opt-out's executor stands for no container
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("executor", ["unboxed", "sandboxed"])
def test_an_unboxed_batch_asks_the_daemon_nothing(tmp_path: Path, monkeypatch, executor: str):
    """`start_box` hands back the opt-out's host executor: the post-create stop, both runs and
    the batch-end removal ask the daemon nothing, and the batch scans and delivers. Control: a
    sandboxed executor, whose stop, starts and removal all reach the daemon."""
    daemon = _daemon(tmp_path, monkeypatch)
    events: list[str] = []
    held = X.HeldStart(daemon)
    host = unboxed_executor()

    def start(req: Any, *_a: Any, **_kw: Any) -> Any:
        return host if executor == "unboxed" else held(req)

    work = RunsInWork(daemon, 2)
    got, _branch = _drive(tmp_path, do_work=work, start_box=start,
                          events=events, scrub=X.ScanWatch(daemon, events))
    assert got is None, got
    assert any(e.startswith("finish_batch:") for e in events), events
    assert isinstance(work.seen[0][0], X.box_runs_type()), work.seen
    X.no_path_docker(daemon)
    verbs = [c[1] for c in daemon.docker_calls()]
    if executor == "unboxed":
        assert verbs == [], f"an unboxed batch asked the daemon: {verbs}"
        assert work.got == [host, host], work.got
        return
    assert verbs.count("start") == 2, verbs
    assert "stop" in verbs, verbs
    assert "rm" in verbs, verbs


def test_the_opt_out_fallback_asks_the_daemon_nothing_after_its_failed_create(
        tmp_path: Path, monkeypatch):
    """`DEFENDER_ALLOW_UNSANDBOXED=1` and a daemon that refuses the create: the real `start_box`
    falls back to a host executor; the post-create stop, the runs and the batch-end removal
    then start, stop or remove nothing (N12)."""
    monkeypatch.setenv(box_mod._ALLOW_UNSANDBOXED, "1")
    daemon = _daemon(tmp_path, monkeypatch)
    daemon.refuse_create()
    events: list[str] = []
    work = RunsInWork(daemon, 2)
    got, _branch = _drive(tmp_path, do_work=work,
                          start_box=partial(box_mod.start_box, docker=daemon), events=events,
                          scrub=X.ScanWatch(daemon, events),
                          branch=TreedBranch(tmp_path / "wt", events=events))
    assert got is None, got
    assert isinstance(work.seen[0][0], X.box_runs_type()), work.seen
    assert [g.sandboxed for g in work.got] == [False, False], work.got
    X.no_path_docker(daemon)
    steps = daemon.steps()
    assert "create" in steps, "the start never asked the daemon, so the row is vacuous"
    assert steps.count("run") == 2
    after = steps[steps.index("work"):]
    assert [s for s in after if s not in ("work", "run", "scan")] == [], after
