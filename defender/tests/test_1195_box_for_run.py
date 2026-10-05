"""#1195 design amendment 3 (2026-10-06): the stop fault wins, the box carries its docker, and
lanes get a run handle.

The units: `runtime.box.BoxRuns(box)`, the lanes' handle on the batch's box (`.stop()`, the
post-create stop; `.run()`, one agent run), `runtime.box.box_for_run(handle)`, the spawn sites'
`with`, the executor's carried `docker`, and `stop_box`'s use of it. The executor carries a fake
daemon (`_box1195.FakeDaemon`, a container's state as a daemon keeps it) as its `docker`, and a
`Tripwire` is the `docker` first on `PATH`; never `monkeypatch.setattr`. The handle's executor
is private: rows reach it only as what `.run()` yields.

Tests -> obligations:

- F3 construction (O6, fail closed):
  `test_a_handle_on_an_object_that_cannot_say_whether_it_is_sandboxed_is_a_box_fault`,
  `test_a_handle_on_a_sandboxed_box_that_carries_no_docker_is_a_box_fault`,
  `test_a_handle_on_a_sandboxed_box_that_names_no_container_is_a_box_fault`; the opt-out (N12):
  `test_the_opt_out_handle_yields_the_executor_and_asks_no_docker`.
- The run's sequence (E2', O2'', O3'): `test_a_run_starts_the_stopped_box_for_its_body_and_stops_it_after`,
  `test_each_run_starts_and_stops_the_one_box`.
- The check before the start (E3', F4):
  `test_a_box_that_is_not_exited_before_the_start_is_refused_naming_its_status` (dead, paused,
  running, created, restarting, absent; a best-effort stop),
  `test_a_stop_that_failed_and_was_swallowed_makes_the_next_run_refuse_before_its_body` (with
  `test_control_a_stop_that_holds_lets_the_next_run_start`).
- An unproven start: `test_a_start_that_cannot_be_proven_runs_no_body_and_is_stopped_again`,
  `test_a_seam_fault_at_the_best_effort_stop_still_refuses_with_a_box_fault`.
- F1 (O5), the stop fault wins: `test_a_stop_fault_with_nothing_in_flight_is_a_box_fault`,
  `test_a_stop_fault_under_an_in_flight_failure_wins_with_the_failure_as_its_context` (an
  exception, `KeyboardInterrupt`, `SystemExit`, a body's own `BoxFault`; a stop refused, taking
  no effect, its proof unanswered, the seam raising); control:
  `test_a_run_stops_its_box_when_the_body_raises` (the stop holds: the body's exception escapes
  as itself).
- F4: `test_a_stop_that_leaves_the_box_dead_counts_as_stopped`,
  `test_stop_stops_the_box_and_proves_it_exited_or_dead`,
  `test_a_stop_that_cannot_prove_the_box_stopped_is_a_box_fault_naming_its_status`.
- `box_for_run` (O6): `test_box_for_run_of_none_yields_none`,
  `test_box_for_run_of_a_handle_yields_its_executor_only_inside_the_run`,
  `test_box_for_run_refuses_anything_but_a_handle` (a raw executor included).
- F2, the carried docker:
  `test_every_lifecycle_call_reaches_the_carried_docker_and_none_reaches_path`,
  `test_stop_box_removes_a_sandboxed_box_through_its_carried_docker`,
  `test_stop_box_of_a_sandboxed_box_that_carries_no_docker_is_a_box_fault`,
  `test_start_box_stamps_the_docker_it_created_the_box_with` (both creation paths),
  `test_the_production_default_stamps_the_real_docker`,
  `test_the_opt_out_executor_carries_no_docker`,
  `test_the_carried_docker_is_left_out_of_equality_and_repr`.
- Every docker call goes through `_call`: the seam raising at one call
  (`FakeDaemon.seam_raises`: the status after the start, the best-effort stop, the run's stop,
  `.stop()`), and
  `test_a_docker_seam_that_raises_everywhere_is_a_box_fault`.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.runtime import box as box_mod
from defender.runtime.box import BoxExecutor, BoxFault, BoxSpec, unboxed_executor
from defender.tests import _box1195 as X

NAME = "defender-drain-u1195"

START = ["docker", "start", NAME]
STOP = ["docker", "stop", "-t", "0", NAME]


def _stopped(tmp_path: Path, monkeypatch: Any) -> tuple[X.FakeDaemon, BoxExecutor, Any]:
    """The daemon holding the batch's box `exited` (after its post-create stop), the executor
    carrying the daemon as its docker, and the handle on it. The `docker` on `PATH` is a
    tripwire."""
    return X.boxed(tmp_path, monkeypatch, NAME)


def _run(daemon: X.FakeDaemon, runs: Any, body: Any = None) -> Any:
    """One `runs.run()`: the body marks `body` in the daemon's log and runs `body()` if given.
    Returns what the run yielded; re-raises what escaped."""
    seen: list[Any] = []

    def go() -> None:
        with runs.run() as got:
            daemon.mark("body")
            seen.append(got)
            if body is not None:
                body()

    raised = X.caught(go)
    if raised is not None:
        raise raised
    return seen[0] if seen else None


def _proven_after_the_stop(daemon: X.FakeDaemon) -> bool:
    """A status ask follows the last `docker stop`: the stop's outcome was asked of the status,
    never read off the stop's own exit code."""
    steps = daemon.steps()
    last = len(steps) - 1 - steps[::-1].index("stop")
    return "status" in steps[last + 1:]


# ---------------------------------------------------------------------------------------
# F3: constructing the handle fails closed; the opt-out handle asks nothing
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("make", [
    pytest.param(object, id="object"),
    pytest.param(lambda: SimpleNamespace(name=NAME), id="no-sandboxed-attribute"),
])
def test_a_handle_on_an_object_that_cannot_say_whether_it_is_sandboxed_is_a_box_fault(
        tmp_path: Path, monkeypatch, make: Any):
    """An unknown box is never assumed safe: `BoxFault`, and no docker is asked."""
    daemon, _box, _runs = _stopped(tmp_path, monkeypatch)
    got = X.caught(lambda: X.box_runs(make()))
    assert isinstance(got, BoxFault), got
    assert daemon.docker_calls() == []
    X.no_path_docker(daemon)


def test_a_handle_on_a_sandboxed_box_that_carries_no_docker_is_a_box_fault(
        tmp_path: Path, monkeypatch):
    """A sandboxed executor created without a docker: `BoxFault`, never a fall-back on the
    `docker` on `PATH`. Control: every row below (an executor carrying its docker)."""
    daemon, _box, _runs = _stopped(tmp_path, monkeypatch)
    got = X.caught(lambda: X.box_runs(X.sandboxed(NAME)))
    assert isinstance(got, BoxFault), got
    X.no_path_docker(daemon)


def test_a_handle_on_a_sandboxed_box_that_names_no_container_is_a_box_fault(
        tmp_path: Path, monkeypatch):
    daemon, _box, _runs = _stopped(tmp_path, monkeypatch)
    got = X.caught(lambda: X.box_runs(X.sandboxed("", docker=daemon)))
    assert isinstance(got, BoxFault), got
    assert daemon.docker_calls() == []


@pytest.mark.parametrize("make", [
    pytest.param(unboxed_executor, id="unboxed-executor"),
    pytest.param(BoxExecutor, id="unattached-executor"),
])
def test_the_opt_out_handle_yields_the_executor_and_asks_no_docker(
        tmp_path: Path, monkeypatch, make: Any):
    """An unsandboxed executor (the opt-out's host executor, N12): its handle's stop and run ask
    no docker, and the run yields that executor; so does `box_for_run` of the handle."""
    daemon, _box, _runs = _stopped(tmp_path, monkeypatch)
    executor = make()
    runs = X.box_runs(executor)
    runs.stop()
    with runs.run() as got:
        assert got is executor
    with X.box_for_run(runs) as got:
        assert got is executor
    assert daemon.docker_calls() == []
    X.no_path_docker(daemon)


# ---------------------------------------------------------------------------------------
# A run: exited -> start -> running -> body (the executor) -> stop -> exited
# ---------------------------------------------------------------------------------------


def test_a_run_starts_the_stopped_box_for_its_body_and_stops_it_after(tmp_path: Path,
                                                                      monkeypatch):
    """The box is `exited`: the run asks its status, `docker start <name>`, proves it
    `running`, yields the executor (whose body sees it running), then `docker stop -t 0 <name>`
    and proves it stopped, all through the executor's own docker."""
    daemon, box, runs = _stopped(tmp_path, monkeypatch)
    saw: list[str | None] = []
    got = _run(daemon, runs, body=lambda: saw.append(daemon.status(NAME)))
    assert got is box, "the run did not yield the batch's executor"
    assert saw == ["running"], "the body ran while the box was not running"
    assert daemon.steps() == ["status", "start", "status", "body", "stop", "status"], (
        daemon.steps())
    assert START in daemon.docker_calls()
    assert STOP in daemon.docker_calls()
    assert daemon.status(NAME) == "exited"
    X.no_path_docker(daemon)


def test_each_run_starts_and_stops_the_one_box(tmp_path: Path, monkeypatch):
    """Three runs of one handle: each starts the box and stops it again; it is `exited` between
    them, and nothing creates or removes a container."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    for _ in range(3):
        _run(daemon, runs)
        assert daemon.status(NAME) == "exited", "the box outlived its run running"
    assert daemon.windows() == [["body"]] * 3, daemon.steps()
    assert [c for c in daemon.docker_calls() if c[1] in ("run", "rm")] == []


# ---------------------------------------------------------------------------------------
# E3', F4: the status before the start must be `exited`
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["running", "paused", "dead", "created", "restarting", None],
                         ids=lambda s: s or "absent")
def test_a_box_that_is_not_exited_before_the_start_is_refused_naming_its_status(
        tmp_path: Path, monkeypatch, status: str | None):
    """The box is not `exited` when its run is entered (`docker start` on a running container
    answers 0 and does nothing, C3, so only the status can tell): `BoxFault` naming the status
    it saw, the body never runs, nothing is started, and a best-effort stop was tried, so a box
    left running is stopped before the refusal unwinds. Control: the rows above (`exited`)."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    if status is None:
        daemon.forget(NAME)
    else:
        daemon.hold(NAME, status)
    got = X.caught(lambda: _run(daemon, runs))
    assert isinstance(got, BoxFault), got
    if status is not None:
        assert status in str(got), f"the refusal does not name the status {status!r}: {got}"
    steps = daemon.steps()
    assert "body" not in steps, "the body ran beside a box that was not stopped"
    assert "start" not in steps, f"the box was started though it was not stopped: {steps}"
    assert STOP in daemon.docker_calls(), f"no best-effort stop on the refusal: {steps}"
    if status == "running":
        assert daemon.status(NAME) == "exited", "the refusal left the box running"


@pytest.mark.parametrize("start", ["refused", "takes-no-effect", "status-unanswered",
                                   "status-seam-OSError", "status-seam-TimeoutExpired"])
def test_a_start_that_cannot_be_proven_runs_no_body_and_is_stopped_again(
        tmp_path: Path, monkeypatch, start: str):
    """`docker start` is refused, answers 0 and changes nothing, or takes while the status asked
    after it goes unanswered or raises at the seam: `BoxFault`, the body never runs, and a stop
    follows the start, so a start that took is undone before the refusal unwinds."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    if start == "refused":
        daemon.refuse_start()
    elif start == "takes-no-effect":
        daemon.start_takes_no_effect()
    elif start == "status-unanswered":
        daemon.refuse_inspect(at=[2])  # the status asked after the start
    else:  # the status asked after the start: the run's second
        daemon.seam_raises(start.removeprefix("status-seam-"), step="status", at=[2])
    got = X.caught(lambda: _run(daemon, runs))
    assert isinstance(got, BoxFault), got
    if start.startswith("status-seam-"):
        assert daemon.seam_raised, "the seam never raised after the start: the row is vacuous"
    steps = daemon.steps()
    assert "body" not in steps, steps
    assert "stop" in steps[steps.index("start"):], f"no stop after the unproven start: {steps}"
    assert daemon.status(NAME) == "exited", "the unproven start left the box running"


@pytest.mark.parametrize("kind", ["OSError", "TimeoutExpired"])
def test_a_seam_fault_at_the_best_effort_stop_still_refuses_with_a_box_fault(
        tmp_path: Path, monkeypatch, kind: str):
    """The start is refused, and the best-effort stop after it raises at the seam: the refusal
    still surfaces as `BoxFault`, never the seam's exception, and the body never runs. Control:
    `test_a_start_that_cannot_be_proven_runs_no_body_and_is_stopped_again[refused]`."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.refuse_start()
    daemon.seam_raises(kind, step="stop")
    got = X.caught(lambda: _run(daemon, runs))
    assert daemon.seam_raised, "the best-effort stop was never tried, so the row is vacuous"
    assert isinstance(got, BoxFault), got
    assert "body" not in daemon.steps()


def test_a_stop_that_failed_and_was_swallowed_makes_the_next_run_refuse_before_its_body(
        tmp_path: Path, monkeypatch):
    """E3': run 1's stop is refused, and a layer above swallows the `BoxFault` (N11''): the box
    is still running. Run 2 refuses before its body, naming the status, starts nothing, and
    stops the box best-effort, so it is `exited` once the refusal unwinds."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.refuse_stop()
    swallowed = X.caught(lambda: _run(daemon, runs))
    assert isinstance(swallowed, BoxFault), swallowed
    assert daemon.status(NAME) == "running", "the fake did not leave the box running"
    starts_before = daemon.steps().count("start")

    got = X.caught(lambda: _run(daemon, runs))

    assert isinstance(got, BoxFault), got
    assert "running" in str(got), got
    assert daemon.steps().count("body") == 1, "run 2's body ran beside a running box"
    assert daemon.steps().count("start") == starts_before, "run 2 started a running box"
    assert daemon.status(NAME) == "exited", "the refusal left the box running"


def test_control_a_stop_that_holds_lets_the_next_run_start(tmp_path: Path, monkeypatch):
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    _run(daemon, runs)
    _run(daemon, runs)
    assert daemon.steps().count("body") == 2
    assert daemon.steps().count("start") == 2


# ---------------------------------------------------------------------------------------
# F1 (O5): the stop fault wins, on every exit
# ---------------------------------------------------------------------------------------


def _body_failures() -> list:
    return [
        pytest.param(lambda: RuntimeError("the agent crashed"), id="exception"),
        pytest.param(KeyboardInterrupt, id="keyboard-interrupt"),
        # Neither an `Exception` nor an interrupt: a spawn that calls `sys.exit`.
        pytest.param(lambda: SystemExit(3), id="system-exit"),
        pytest.param(lambda: BoxFault("the agent's own box fault"), id="box-fault"),
    ]


def _failing_stop(tmp_path: Path, monkeypatch: Any, stop: str
                  ) -> tuple[X.FakeDaemon, BoxExecutor, Any]:
    """A stopped box whose run's stop fails as `stop` says. The run asks the status before its
    start (1), after it (2), and after its stop (3)."""
    daemon, box, runs = _stopped(tmp_path, monkeypatch)
    X.fail_stop(daemon, stop, at=1, inspect_at=3)
    return daemon, box, runs


def _raise(exc: BaseException) -> Any:
    def body() -> None:
        raise exc

    return body


@pytest.mark.parametrize("failure", _body_failures())
def test_a_run_stops_its_box_when_the_body_raises(tmp_path: Path, monkeypatch, failure: Any):
    """The F1 control: the body raises and the stop holds. The box is stopped after it and
    proven stopped, and the body's own exception escapes as itself."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    raised = failure()
    got = X.caught(lambda: _run(daemon, runs, body=_raise(raised)))
    assert got is raised, got
    steps = daemon.steps()
    assert "stop" in steps[steps.index("body"):], f"no stop after the body: {steps}"
    assert _proven_after_the_stop(daemon), steps
    assert daemon.status(NAME) == "exited"


@pytest.mark.parametrize("stop", X.STOP_FAULTS)
def test_a_stop_fault_with_nothing_in_flight_is_a_box_fault(tmp_path: Path, monkeypatch,
                                                            stop: str):
    """The body returns; the stop fails: `BoxFault`, never the seam's own exception. Short of a
    seam fault at the stop itself, its outcome was asked of the status after it. Control:
    `test_a_run_starts_the_stopped_box_for_its_body_and_stops_it_after`."""
    daemon, _box, runs = _failing_stop(tmp_path, monkeypatch, stop)
    got = X.caught(lambda: _run(daemon, runs))
    assert isinstance(got, BoxFault), f"a stop fault escaped as {got!r}"
    assert daemon.steps().count("body") == 1
    if stop.startswith("seam-"):
        assert daemon.seam_raised, "the seam never raised at the stop, so the row is vacuous"
    else:
        assert _proven_after_the_stop(daemon), f"the stop was never proven: {daemon.steps()}"


@pytest.mark.parametrize("stop", X.STOP_FAULTS)
@pytest.mark.parametrize("failure", _body_failures())
def test_a_stop_fault_under_an_in_flight_failure_wins_with_the_failure_as_its_context(
        tmp_path: Path, monkeypatch, failure: Any, stop: str):
    """F1: the body raises X (an exception, an interrupt, `SystemExit`, its own `BoxFault`) and
    the stop fails too: a `BoxFault` from the stop escapes, never X, with X as its `__context__`
    (one link further, behind the seam's own exception, when the seam raised at the stop). The
    host's next step must not run beside a box that may still be running. Control:
    `test_a_run_stops_its_box_when_the_body_raises` (the stop holds: X escapes as itself)."""
    daemon, _box, runs = _failing_stop(tmp_path, monkeypatch, stop)
    raised = failure()
    got = X.caught(lambda: _run(daemon, runs, body=_raise(raised)))
    assert isinstance(got, BoxFault), f"the in-flight failure outranked the stop fault: {got!r}"
    assert got is not raised, "the body's own exception escaped though the stop failed"
    if stop.startswith("seam-"):
        assert daemon.seam_raised, "the seam never raised at the stop, so the row is vacuous"
        assert raised in X.chain(got), f"the in-flight failure was lost: {X.chain(got)}"
    else:
        assert got.__context__ is raised, (
            f"the in-flight failure is not the context: {X.chain(got)}")
        assert _proven_after_the_stop(daemon), f"the stop was never proven: {daemon.steps()}"


# ---------------------------------------------------------------------------------------
# F4: `.stop()`, proven `exited` or `dead`
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("before", ["running", "exited", "running-left-dead"])
def test_stop_stops_the_box_and_proves_it_exited_or_dead(tmp_path: Path, monkeypatch,
                                                         before: str):
    """`.stop()` (the drain's post-create stop): `docker stop -t 0 <name>`, then the status
    is asked, and `exited` or `dead` (nothing runs in either) is proven stopped. An
    already-stopped box is proven the same way."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.hold(NAME, "exited" if before == "exited" else "running")
    if before == "running-left-dead":
        daemon.stop_leaves_it_dead()
    runs.stop()
    assert STOP in daemon.docker_calls(), daemon.docker_calls()
    assert daemon.steps()[-1] == "status", "the stop was not proven by the status"
    assert daemon.status(NAME) == ("dead" if before == "running-left-dead" else "exited")
    X.no_path_docker(daemon)


@pytest.mark.parametrize("stop", X.STOP_FAULTS)
def test_a_stop_that_cannot_prove_the_box_stopped_is_a_box_fault_naming_its_status(
        tmp_path: Path, monkeypatch, stop: str):
    """`.stop()` is refused, answers 0 with the box still running, takes while its proof goes
    unanswered, or the seam raises at it: `BoxFault` (the status is the proof, never the stop's
    own exit code); a box seen still running is named so. Control: the row above."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.hold(NAME, "running")
    X.fail_stop(daemon, stop, at=1, inspect_at=1)
    got = X.caught(runs.stop)
    assert isinstance(got, BoxFault), got
    if stop.startswith("seam-"):
        assert daemon.seam_raised, "the seam never raised at the stop, so the row is vacuous"
    if stop in ("refused", "takes-no-effect"):
        assert "running" in str(got), f"the fault does not name the status it saw: {got}"


def test_a_stop_that_leaves_the_box_dead_counts_as_stopped(tmp_path: Path, monkeypatch):
    """F4: run 1's stop leaves the box `dead`: the run returns, as stopped (nothing runs in a
    dead box). Run 2 then finds it `dead`, not `exited`, and refuses to start it, naming the
    status, before its body. Control: `test_control_a_stop_that_holds_lets_the_next_run_start`."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.stop_leaves_it_dead()
    _run(daemon, runs)
    assert daemon.status(NAME) == "dead"
    got = X.caught(lambda: _run(daemon, runs))
    assert isinstance(got, BoxFault), got
    assert "dead" in str(got), got
    assert daemon.steps().count("body") == 1
    assert daemon.steps().count("start") == 1


# ---------------------------------------------------------------------------------------
# `box_for_run` (O6): only a handle opens a run
# ---------------------------------------------------------------------------------------


def test_box_for_run_of_none_yields_none(tmp_path: Path, monkeypatch):
    daemon, _box, _runs = _stopped(tmp_path, monkeypatch)
    with X.box_for_run(None) as got:
        assert got is None
    assert daemon.docker_calls() == []
    X.no_path_docker(daemon)


def test_box_for_run_of_a_handle_yields_its_executor_only_inside_the_run(tmp_path: Path,
                                                                         monkeypatch):
    """The spawn site's `with box_for_run(handle) as run_box`: `run_box` is the batch's
    executor, the box running for the body only; before and after, it is stopped."""
    daemon, box, runs = _stopped(tmp_path, monkeypatch)
    saw: list[Any] = []
    with X.box_for_run(runs) as got:
        saw.append((got, daemon.status(NAME)))
    assert saw == [(box, "running")]
    assert daemon.status(NAME) == "exited"
    X.no_path_docker(daemon)


@pytest.mark.parametrize("make", [
    pytest.param(lambda d: X.sandboxed(NAME, docker=d), id="raw-sandboxed-executor"),
    pytest.param(lambda d: unboxed_executor(), id="raw-unboxed-executor"),
    pytest.param(lambda d: object(), id="object"),
    pytest.param(lambda d: SimpleNamespace(sandboxed=True, name=NAME, docker=d),
                 id="executor-shaped-namespace"),
])
def test_box_for_run_refuses_anything_but_a_handle(tmp_path: Path, monkeypatch, make: Any):
    """O6: `box_for_run` of anything but a `BoxRuns` (or `None`), a raw executor included, is a
    `BoxFault`: the body never runs and no docker is asked. Control: the row above."""
    daemon, _box, _runs = _stopped(tmp_path, monkeypatch)
    ran: list[str] = []

    def go() -> None:
        with X.box_for_run(make(daemon)):
            ran.append("body")

    got = X.caught(go)
    assert isinstance(got, BoxFault), got
    assert ran == []
    assert daemon.docker_calls() == []
    X.no_path_docker(daemon)


# ---------------------------------------------------------------------------------------
# F2: the box carries its docker
# ---------------------------------------------------------------------------------------


def test_every_lifecycle_call_reaches_the_carried_docker_and_none_reaches_path(
        tmp_path: Path, monkeypatch):
    """A post-create stop, a run, and the batch-end `stop_box`, over an executor carrying the
    daemon, with a tripwire as the `docker` on `PATH`: every call reaches the daemon (stop,
    start, stop, `rm -f`), none the tripwire, and the box is gone."""
    daemon, box, runs = _stopped(tmp_path, monkeypatch)
    daemon.hold(NAME, "running")
    runs.stop()
    with X.box_for_run(runs):
        pass
    box_mod.stop_box(box)
    verbs = [c[1] for c in daemon.docker_calls() if c[1] in ("start", "stop", "rm")]
    assert verbs == ["stop", "start", "stop", "rm"], daemon.docker_calls()
    assert daemon.names() == []
    X.no_path_docker(daemon)


def test_stop_box_removes_a_sandboxed_box_through_its_carried_docker(tmp_path: Path,
                                                                     monkeypatch):
    daemon, box, _runs = _stopped(tmp_path, monkeypatch)
    box_mod.stop_box(box)
    assert ["docker", "rm", "-f", NAME] in daemon.docker_calls()
    assert daemon.names() == []
    X.no_path_docker(daemon)


def test_stop_box_of_a_sandboxed_box_that_carries_no_docker_is_a_box_fault(tmp_path: Path,
                                                                           monkeypatch):
    """F2: the batch-end removal of a sandboxed executor with no docker is a `BoxFault`, never
    a fall-back on the `docker` on `PATH`. A box naming no container is still a no-op. Control:
    the row above."""
    daemon, _box, _runs = _stopped(tmp_path, monkeypatch)
    got = X.caught(lambda: box_mod.stop_box(X.sandboxed(NAME)))
    assert isinstance(got, BoxFault), got
    assert daemon.names() == [NAME], "the box was removed by something"
    box_mod.stop_box(unboxed_executor())
    X.no_path_docker(daemon)


def test_start_box_stamps_the_docker_it_created_the_box_with(tmp_path: Path, monkeypatch):
    """Both sandboxed creation paths: `start_box(request, docker=d)` and `start_box(run_dir,
    defender_dir, spec=..., docker=d)` create, check and probe through `d`, and the executor
    they hand back carries `d`; none of it reaches the `docker` on `PATH`."""
    X.clear_opt_out(monkeypatch)
    daemon = X.FakeDaemon(tmp_path)
    daemon.tripwire = X.Tripwire(tmp_path).install(monkeypatch)
    writable = tmp_path / "rw"
    writable.mkdir()
    by_request = box_mod.start_box(X.request("defender-drain-s1195", writable=writable),
                                   docker=daemon)
    assert by_request.sandboxed, by_request
    assert by_request.docker is daemon, "the request path did not stamp its docker"
    run_dir = tmp_path / "s1195run"
    run_dir.mkdir()
    (tmp_path / "defender").mkdir()
    by_run_dir = box_mod.start_box(run_dir, tmp_path / "defender", docker=daemon,
                                   spec=BoxSpec(runtime="runc", rootfs="defender-box:t1195"))
    assert by_run_dir.sandboxed, by_run_dir
    assert by_run_dir.docker is daemon, "the run-dir path did not stamp its docker"
    assert len(daemon.created()) == 2
    X.no_path_docker(daemon)


def test_the_production_default_stamps_the_real_docker(tmp_path: Path, monkeypatch):
    """`start_box(request)` with no `docker=`: the executor carries the default docker seam, so
    its handle's calls reach the `docker` on `PATH` (here the fake daemon installed there); a
    box stamped with no docker would be refused its handle instead."""
    X.clear_opt_out(monkeypatch)
    daemon = X.FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    writable = tmp_path / "rw"
    writable.mkdir()
    box = box_mod.start_box(X.request(NAME, writable=writable))
    runs = X.box_runs(box)
    runs.stop()
    with X.box_for_run(runs):
        assert daemon.status(NAME) == "running"
    assert daemon.status(NAME) == "exited"


def test_the_opt_out_executor_carries_no_docker():
    assert unboxed_executor().docker is None


def test_the_carried_docker_is_left_out_of_equality_and_repr(tmp_path: Path):
    daemon = X.FakeDaemon(tmp_path)
    with_it, without = X.sandboxed(NAME, docker=daemon), X.sandboxed(NAME)
    assert with_it.docker is daemon
    assert with_it == without
    assert "FakeDaemon" not in repr(with_it), repr(with_it)


@pytest.mark.parametrize("kind", ["OSError", "TimeoutExpired"])
def test_a_docker_seam_that_raises_everywhere_is_a_box_fault(tmp_path: Path, monkeypatch,
                                                             kind: str):
    """The carried docker raises on every call: the run's entry and `.stop()` each raise
    `BoxFault`, and the body never runs."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.seam_raises(kind, step="*")
    ran: list[str] = []

    def enter() -> None:
        with runs.run():
            ran.append("body")

    assert isinstance(X.caught(enter), BoxFault)
    assert ran == []
    assert isinstance(X.caught(runs.stop), BoxFault)
