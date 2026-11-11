from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
import contextlib
import dataclasses
import os
import shlex
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator

import pytest

from defender.tests.support.storage._alert_plant import plant_alert
from defender import box as box_mod
from defender.box import BoxExecutor, BoxFault, BoxSpec, unboxed_executor
from defender.tests.support.sandbox import _box1195 as X
from defender.tests.support.sandbox._box1343 import input_open
from defender.tests.support.tenancy._host1214 import TEST_TENANT
from defender import _git
from defender.tests.support.sandbox._docker import dood_anchor, is_dood
from defender.tests.e2e._spec771 import DEFENDER, requires_real_box
from defender.tests.tenancy.tenant_1108_delivery._support import (
    LANES,
    ForgeHTTP,
    build_tenant,
    configured_origin,
    fixture_identity,
)
from defender.tests.tenancy.tenant_1108_delivery._support import target as p3_target


NAME = "defender-drain-u1195"

#: A run window's start (#1344 amendment 2): attached, its input held by the window's holder.
ATTACH = ["docker", "start", "-a", "-i", NAME]
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


def test_the_handle_is_no_box(tmp_path: Path, monkeypatch):
    _daemon, box, runs = _stopped(tmp_path, monkeypatch)
    assert isinstance(box, box_mod.BoxLike), "the control: the executor is a BoxLike"
    assert not isinstance(runs, box_mod.BoxLike), "the run handle passes as a box"
    assert not hasattr(runs, "run_parsed"), "the run handle can run a command"


@pytest.mark.parametrize("make", [
    pytest.param(unboxed_executor, id="unboxed-executor"),
    pytest.param(BoxExecutor, id="unattached-executor"),
])
def test_the_opt_out_handle_yields_the_executor_and_asks_no_docker(
        tmp_path: Path, monkeypatch, make: Any):
    """An unsandboxed executor (the opt-out's host executor): its handle's stop and run ask
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


def test_a_run_starts_the_stopped_box_for_its_body_and_stops_it_after(tmp_path: Path,
                                                                      monkeypatch):
    """The window's start is attached (#1344 amendment 2): its input is held open while the body
    runs and closed once the window ends, so the box cannot outlive the window's holder."""
    daemon, box, runs = _stopped(tmp_path, monkeypatch)
    saw: list[tuple[str | None, bool]] = []
    got = _run(daemon, runs, body=lambda: saw.append(
        (daemon.status(NAME), input_open(daemon.asks[-1].read_fd))))
    assert got is box, "the run did not yield the batch's executor"
    assert saw == [("running", True)], "the body ran while the box was not running, or its input was not held"
    assert daemon.steps() == ["status", "attach", "status", "body", "stop", "status"], (
        daemon.steps())
    assert [a.argv for a in daemon.asks] == [ATTACH]
    assert START not in daemon.docker_calls(), "the window started the box detached from its holder"
    assert STOP in daemon.docker_calls()
    assert daemon.asks[-1].returncode is not None, "the window's attached start outlived it"
    assert not input_open(daemon.asks[-1].read_fd), "the window's input was left open"
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
    assert [c for c in daemon.docker_calls() if c[1] in ("run", "create", "rm")] == []


@pytest.mark.parametrize("status", ["running", "paused", "dead", "created", "restarting", None],
                         ids=lambda s: s or "absent")
def test_a_box_that_is_not_exited_before_the_start_is_refused_naming_its_status(
        tmp_path: Path, monkeypatch, status: str | None):
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
    assert not {"start", "attach"} & set(steps), (
        f"the box was started though it was not stopped: {steps}")
    assert STOP in daemon.docker_calls(), f"no best-effort stop on the refusal: {steps}"
    if status == "running":
        assert daemon.status(NAME) == "exited", "the refusal left the box running"


@pytest.mark.parametrize("start", ["refused", "takes-no-effect", "status-unanswered",
                                   "status-seam-OSError", "status-seam-TimeoutExpired"])
def test_a_start_that_cannot_be_proven_runs_no_body_and_is_stopped_again(
        tmp_path: Path, monkeypatch, start: str):
    """`status-unanswered`: no status ask after the attached start answers, so its wait for
    `running` (#1344 amendment 2; production's 30 s) runs out."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    if start == "refused":
        daemon.refuse_start()
    elif start == "takes-no-effect":
        daemon.start_takes_no_effect()
    elif start == "status-unanswered":
        daemon.refuse_inspect(at=range(2, 2000))  # every status asked after the start
    else:  # the status asked after the start: the run's second
        daemon.seam_raises(start.removeprefix("status-seam-"), step="status", at=[2])
    got = X.caught(lambda: _run(daemon, runs))
    assert isinstance(got, BoxFault), got
    X.no_path_docker(daemon)
    if start.startswith("status-seam-"):
        assert daemon.seam_raised, "the seam never raised after the start: the row is vacuous"
    steps = daemon.steps()
    assert "body" not in steps, steps
    assert "stop" in steps[steps.index("attach"):], f"no stop after the unproven start: {steps}"
    assert daemon.asks[-1].returncode is not None, "the unproven start's client was left running"
    assert daemon.status(NAME) == "exited", "the unproven start left the box running"


@pytest.mark.parametrize("kind", ["OSError", "TimeoutExpired"])
def test_a_seam_fault_at_the_best_effort_stop_still_refuses_with_a_box_fault(
        tmp_path: Path, monkeypatch, kind: str):
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.refuse_start()
    daemon.seam_raises(kind, step="stop")
    got = X.caught(lambda: _run(daemon, runs))
    assert daemon.seam_raised, "the best-effort stop was never tried, so the row is vacuous"
    assert isinstance(got, BoxFault), got
    assert "body" not in daemon.steps()
    X.no_path_docker(daemon)


def test_a_stop_that_failed_and_was_swallowed_makes_the_next_run_refuse_before_its_body(
        tmp_path: Path, monkeypatch):
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.refuse_stop()
    swallowed = X.caught(lambda: _run(daemon, runs))
    assert isinstance(swallowed, BoxFault), swallowed
    assert daemon.status(NAME) == "running", "the fake did not leave the box running"
    starts_before = daemon.steps().count("attach")

    got = X.caught(lambda: _run(daemon, runs))

    assert isinstance(got, BoxFault), got
    assert "running" in str(got), got
    assert daemon.steps().count("body") == 1, "run 2's body ran beside a running box"
    assert daemon.steps().count("attach") == starts_before, "run 2 started a running box"
    assert "start" not in daemon.steps(), "a window started the box plainly"
    assert daemon.status(NAME) == "exited", "the refusal left the box running"


def test_control_a_stop_that_holds_lets_the_next_run_start(tmp_path: Path, monkeypatch):
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    _run(daemon, runs)
    _run(daemon, runs)
    assert daemon.steps().count("body") == 2
    assert daemon.steps().count("attach") == 2


def _body_failures() -> list:
    return [
        pytest.param(lambda: RuntimeError("the agent crashed"), id="exception"),
        pytest.param(KeyboardInterrupt, id="keyboard-interrupt"),
        # Neither an `Exception` nor an interrupt: a spawn that calls `sys.exit`.
        pytest.param(lambda: SystemExit(3), id="system-exit"),
        pytest.param(lambda: BoxFault("the agent's own box fault"), id="box-fault"),
        # The spawn's own process faults: its CLI timing out, its pipe breaking.
        *X.PROCESS_FAULTS,
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
    daemon, _box, runs = _failing_stop(tmp_path, monkeypatch, stop)
    got = X.caught(lambda: _run(daemon, runs))
    assert isinstance(got, BoxFault), f"a stop fault escaped as {got!r}"
    assert daemon.steps().count("body") == 1
    step = X.seam_step(stop)
    if step is not None:
        assert daemon.seam_raised == [step], "the seam never raised where set (vacuous)"
    else:
        assert _proven_after_the_stop(daemon), f"the stop was never proven: {daemon.steps()}"
    X.no_path_docker(daemon)


@pytest.mark.parametrize("stop", X.STOP_FAULTS)
@pytest.mark.parametrize("failure", _body_failures())
def test_a_stop_fault_under_an_in_flight_failure_wins_with_the_failure_as_its_context(
        tmp_path: Path, monkeypatch, failure: Any, stop: str):
    daemon, _box, runs = _failing_stop(tmp_path, monkeypatch, stop)
    raised = failure()
    got = X.caught(lambda: _run(daemon, runs, body=_raise(raised)))
    X.assert_the_stop_fault_won(got, raised, daemon, stop)
    if X.seam_step(stop) is None:
        assert _proven_after_the_stop(daemon), f"the stop was never proven: {daemon.steps()}"
    X.no_path_docker(daemon)


@pytest.mark.parametrize("before", ["running", "exited", "running-left-dead"])
def test_stop_stops_the_box_and_proves_it_exited_or_dead(tmp_path: Path, monkeypatch,
                                                         before: str):
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
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.hold(NAME, "running")
    X.fail_stop(daemon, stop, at=1, inspect_at=1)
    got = X.caught(runs.stop)
    assert isinstance(got, BoxFault), got
    step = X.seam_step(stop)
    if step is not None:
        assert daemon.seam_raised == [step], "the seam never raised where set (vacuous)"
    if stop in ("refused", "takes-no-effect"):
        assert "running" in str(got), f"the fault does not name the status it saw: {got}"
    X.no_path_docker(daemon)


def test_a_stop_that_leaves_the_box_dead_counts_as_stopped(tmp_path: Path, monkeypatch):
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.stop_leaves_it_dead()
    _run(daemon, runs)
    assert daemon.status(NAME) == "dead"
    got = X.caught(lambda: _run(daemon, runs))
    assert isinstance(got, BoxFault), got
    assert "dead" in str(got), got
    assert daemon.steps().count("body") == 1
    assert daemon.steps().count("attach") == 1


LEFT_AFTER_A_STOP = ["paused", "restarting", "dead"]


@pytest.mark.parametrize("left", LEFT_AFTER_A_STOP)
def test_a_stop_that_leaves_the_box_paused_or_restarting_proves_nothing(
        tmp_path: Path, monkeypatch, left: str):
    """`.stop()` answers 0 and leaves the box `paused` or `restarting`: `BoxFault` naming the
    status, since only `exited` or `dead` prove a stop. Control (`dead`): the stop is proven."""
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.hold(NAME, "running")
    daemon.stop_leaves_it_as(left, at=1)
    got = X.caught(runs.stop)
    assert daemon.status(NAME) == left, "the fake did not leave the box as set (vacuous)"
    if left == "dead":
        assert got is None, got
        return
    assert isinstance(got, BoxFault), f"a box left {left!r} passed as stopped: {got!r}"
    assert left in str(got), f"the fault does not name the status it saw: {got}"


@pytest.mark.parametrize("in_flight", [False, True], ids=["body-returns", "body-raises"])
@pytest.mark.parametrize("left", LEFT_AFTER_A_STOP)
def test_a_run_whose_stop_leaves_the_box_paused_or_restarting_is_a_box_fault(
        tmp_path: Path, monkeypatch, left: str, in_flight: bool):
    daemon, _box, runs = _stopped(tmp_path, monkeypatch)
    daemon.stop_leaves_it_as(left, at=1)
    raised = RuntimeError("the agent crashed")
    got = X.caught(lambda: _run(daemon, runs, body=_raise(raised) if in_flight else None))
    assert daemon.steps().count("body") == 1
    assert daemon.status(NAME) == left, "the fake did not leave the box as set (vacuous)"
    if left == "dead":
        assert got is (raised if in_flight else None), got
        return
    assert isinstance(got, BoxFault), f"a run returned beside a box left {left!r}: {got!r}"
    assert left in str(got), f"the fault does not name the status it saw: {got}"
    if in_flight:
        assert got.__context__ is raised, X.chain(got)


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
    """`box_for_run` of anything but a `BoxRuns` (or `None`), a raw executor included, is a
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


def test_every_lifecycle_call_reaches_the_carried_docker_and_none_reaches_path(
        tmp_path: Path, monkeypatch):
    daemon, box, runs = _stopped(tmp_path, monkeypatch)
    daemon.hold(NAME, "running")
    runs.stop()
    with X.box_for_run(runs):
        pass
    box_mod.stop_box(box)
    verbs = [c[1] for c in daemon.docker_calls() if c[1] in ("start", "stop", "rm")]
    assert verbs == ["stop", "start", "stop", "rm"], daemon.docker_calls()
    assert ATTACH in daemon.docker_calls(), "the window's start was not the attached one"
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
    daemon, _box, _runs = _stopped(tmp_path, monkeypatch)
    got = X.caught(lambda: box_mod.stop_box(X.sandboxed(NAME)))
    assert isinstance(got, BoxFault), got
    assert daemon.names() == [NAME], "the box was removed by something"
    box_mod.stop_box(unboxed_executor())
    X.no_path_docker(daemon)


def test_stop_box_ends_the_attached_starter_even_when_the_box_carries_no_docker(tmp_path: Path,
                                                                                monkeypatch):
    """Tearing down a docker-backed box always ends its attached start (#1170, regressed by
    #1467): the daemon not being resolvable still reaches the caller as a `BoxFault`, but the
    start's held input is closed, so the box stops on its own rather than outliving its owner."""
    daemon, _box, _runs = _stopped(tmp_path, monkeypatch)
    starter = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE)
    try:
        box = dataclasses.replace(X.sandboxed(NAME), starter=starter)
        got = X.caught(lambda: box_mod.stop_box(box))
        assert isinstance(got, BoxFault), got
        assert starter.poll() is not None, "the attached start still runs after the teardown"
    finally:
        if starter.poll() is None:
            starter.kill()
            starter.wait()
    X.no_path_docker(daemon)


def test_stop_box_removes_the_box_and_ends_its_attached_starter(tmp_path: Path, monkeypatch):
    """The normal teardown (#1170): the box is removed through its carried docker and its
    attached start is ended with it."""
    daemon, box, _runs = _stopped(tmp_path, monkeypatch)
    starter = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE)
    try:
        box_mod.stop_box(dataclasses.replace(box, starter=starter))
        assert starter.poll() is not None, "the attached start still runs after the teardown"
    finally:
        if starter.poll() is None:
            starter.kill()
            starter.wait()
    assert daemon.names() == []
    X.no_path_docker(daemon)


def test_start_box_stamps_the_docker_it_created_the_box_with(tmp_path: Path, monkeypatch):
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
    plant_alert(run_dir)
    (tmp_path / "defender").mkdir()
    by_run_dir = box_mod.start_box(run_dir, tmp_path / "defender", docker=daemon,
                                   spec=BoxSpec(runtime="runc", rootfs="defender-box:t1195"), tenant_id=TEST_TENANT)
    assert by_run_dir.sandboxed, by_run_dir
    assert by_run_dir.docker is daemon, "the run-dir path did not stamp its docker"
    assert len(daemon.created()) == 2
    X.no_path_docker(daemon)


def test_the_production_default_stamps_the_real_docker(tmp_path: Path, monkeypatch):
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
    X.no_path_docker(daemon)


#: The file run 1's writer appends to, in the draft's one writable lane (`agent/lessons/`).
LEFT = "left1195.md"


#: What run 1 leaves in the box's scratch space: a run 2 that finds either kept it.
MARKERS = ("/tmp/m1195", "/dev/shm/m1195")


#: How long a writer that must be gone is watched for a write it must not make.
STILL_FOR = 1.0


#: Counts the processes whose command line carries the writer's file name, built from two
#: halves so this script's own command line never matches.
_COUNT_WRITERS = """
import os
needle = ("left" + "1195").encode()
n = 0
for pid in os.listdir("/proc"):
    if pid.isdigit():
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                if needle in f.read():
                    n += 1
        except OSError:
            pass
print(n)
"""


@contextlib.contextmanager
def _batch(base: Path) -> Iterator[Any]:
    """A tenant batch the way a drain cuts one: the tenant, its git-free draft and the product
    code the box mounts (this checkout's image inputs and code check file), all under `base`."""
    X.plant_image_inputs(base / "product")
    code = base / "product" / "defender"
    with build_tenant(base / "tenant") as built:
        http = ForgeHTTP(remote=built[1])
        origin = configured_origin(built[0].knowledge)
        if origin is not None:
            http.serve(origin)
        delivery = p3_target().TenantDelivery.open(
            built[0], defender_dir=code, client=http.client,
            identity=fixture_identity(str(built[0].id)), origin=origin)
        yield delivery.start_batch(f"t1195-{uuid.uuid4().hex[:8]}", lanes=LANES), built[0]


def _grew(path: Path, past: int) -> bool:
    """Whether `path` grows past `past` bytes within ten seconds."""
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if path.stat().st_size > past:
            return True
        time.sleep(0.1)
    return False


def _held_still(path: Path) -> bool:
    """Whether `path`'s size stays put for `STILL_FOR` seconds."""
    before = path.stat().st_size
    time.sleep(STILL_FOR)
    return path.stat().st_size == before


def _exec(box: box_mod.BoxExecutor, *argv: str, cwd: Path | None = None) -> tuple[int, str]:
    flags = ["-w", str(cwd)] if cwd is not None else []
    proc = box_mod.run_docker(["docker", "exec", *flags, box.name, *argv])
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _status(name: str) -> str:
    return box_mod.run_docker(["docker", "inspect", "-f", "{{.State.Status}}", name]).stdout.strip()


def _writers(box: box_mod.BoxExecutor) -> int:
    rc, out = _exec(box, "python3", "-c", _COUNT_WRITERS)
    assert rc == 0, out
    return int(out.strip())


def _leave_a_writer(box: box_mod.BoxExecutor, target: Path) -> None:
    """A detached loop inside `box` appending to `target`: what an agent leaves running."""
    loop = f"while :; do printf X >> {shlex.quote(str(target))}; sleep 0.05; done"
    started = box_mod.run_docker(["docker", "exec", "-d", box.name, "sh", "-c", loop])
    assert started.returncode == 0, started.stderr


def _one_run(runs: object, ran: list[bool]) -> None:
    with X.box_for_run(runs):
        ran.append(True)


@pytest.fixture
def live_worktree_base(tmp_path: Path) -> Iterator[Path]:
    """Put only this live box's tenant and draft on the daemon-visible shared mount under DooD."""
    if not is_dood():
        yield tmp_path
        return
    anchor = dood_anchor()
    assert anchor is not None, "the real-box guard requires a shared repo mount under DooD"
    base = anchor / f"t1195-{uuid.uuid4().hex[:12]}"
    base.mkdir(parents=True)
    try:
        yield base
    finally:
        # A box can write root-owned artifacts; cleanup follows the live shared fixtures.
        shutil.rmtree(base, ignore_errors=True)


@requires_real_box
@pytest.mark.box
def test_a_stopped_box_keeps_nothing_a_run_left_and_keeps_its_link_ban(
        tmp_path: Path, live_worktree_base: Path, monkeypatch):
    """On a drain box (`Batch.box_request()` over a tenant draft): a stopped box keeps
    nothing a run left (no writer, no scratch), keeps its link ban across a restart, refuses a
    run in a box someone else started, and the draft as run 1 left it is what the batch commits."""
    with contextlib.ExitStack() as stack:
        _the_box_life(stack, live_worktree_base, monkeypatch)


def _the_box_life(  # noqa: PLR0915 — one box's whole life
        stack: contextlib.ExitStack, live_worktree_base: Path, monkeypatch: Any) -> None:
    # A startup fault must fail this test, never degrade to a host executor no stop holds.
    X.clear_opt_out(monkeypatch)
    batch, tenant = stack.enter_context(_batch(live_worktree_base))
    assert box_mod.image_tag(batch.defender_dir) == box_mod.image_tag(DEFENDER)
    request = batch.box_request()
    writable = [m for m in request.mounts if m.writable]
    assert len(writable) == 1, f"expected the draft's one writable lane: {writable}"
    host_tree, inside_tree = Path(writable[0].source), Path(writable[0].target)
    left = host_tree / LEFT
    left.write_text("seed\n", encoding="utf-8")  # the draft's file run 1's writer appends to
    box = box_mod.start_box(request)
    try:
        assert box.sandboxed, "start_box handed back a host executor"
        assert box.docker is not None, "start_box handed back an executor that carries no docker"
        runs = X.box_runs(box)
        runs.stop()
        assert _status(box.name) == "exited", "the post-create stop left the box up"

        with X.box_for_run(runs) as run_box:
            assert run_box is box, "a run handed its spawn something but the batch's executor"
            _leave_a_writer(box, inside_tree / left.relative_to(host_tree))
            for marker in MARKERS:
                rc, out = _exec(box, "sh", "-c", f"printf m > {marker}")
                assert rc == 0, f"run 1 could not leave {marker}: {out}"
            # Controls: the writer is live and listed, the markers stand.
            assert _grew(left, left.stat().st_size), "the writer inside run 1's box never wrote"
            assert _writers(box) >= 1, "the writer is not in the box's process table"
            for marker in MARKERS:
                assert _exec(box, "test", "-e", marker)[0] == 0, f"{marker} is not there in run 1"
        assert _status(box.name) == "exited", "run 1 left the box up"
        assert _held_still(left), "a writer run 1 left wrote after run 1's stop"
        judged = left.read_text(encoding="utf-8")

        with X.box_for_run(runs):
            assert _status(box.name) == "running", "run 2 did not start the box"
            assert _held_still(left), "run 1's writer wrote during run 2"
            assert _writers(box) == 0, "run 1's writer is still in the box's process table"
            for marker in MARKERS:
                assert _exec(box, "test", "-e", marker)[0] != 0, f"run 1's {marker} survived its stop"
            draft, inside_draft = host_tree, inside_tree
            rc, out = _exec(box, "sh", "-c", "printf x > plain1195", cwd=inside_draft)
            assert rc == 0, f"an ordinary create in the writable mount failed (control): {out}"
            for argv in (["ln", "-s", "plain1195", "sym1195"], ["ln", "plain1195", "hard1195"]):
                rc, out = _exec(box, *argv, cwd=inside_draft)
                assert rc != 0, f"`{' '.join(argv)}` was allowed after a restart: {out}"
                assert not os.path.lexists(draft / argv[-1]), f"`{' '.join(argv)}` left a link"
            (draft / "plain1195").unlink()

        assert box_mod.run_docker(["docker", "start", box.name]).returncode == 0
        assert _status(box.name) == "running"
        ran: list[bool] = []
        got = X.caught(lambda: _one_run(runs, ran))
        assert isinstance(got, BoxFault), got
        assert "running" in str(got), f"the refusal does not name the status it saw: {got}"
        assert ran == [], "a run's spawn ran in a box someone else had started"
        assert _status(box.name) == "exited", "the refused run left the box up"
    finally:
        box_mod.stop_box(box)

    probe = box_mod.run_docker(["docker", "inspect", "-f", "{{.State.Status}}", request.name])
    assert probe.returncode != 0, f"a container still holds {request.name}: {probe.stdout}"
    rel = f"agent/{LANES[0]}/{LEFT}"
    changes = batch.change_set()
    assert [c.path for c in changes.changes] == [rel], changes
    sha = batch.commit(changes, "learning(lead-author): what run 1 left")
    assert sha, "nothing was committed"
    assert _git.git_show_file(tenant.knowledge, sha, rel) == judged
    assert left.read_text(encoding="utf-8") == judged, "the file changed after the commit"
