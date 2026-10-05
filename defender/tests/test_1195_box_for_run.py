"""#1195 design amendment 2 (2026-10-06): one box per batch, stopped between agent runs.

The units: `runtime.box.box_for_run(box, *, docker=)`, the spawn sites' `with` around one agent
run, and `runtime.box.stop_run_box(box, *, docker=)`, the stop it ends with (and the drain's
post-create stop). Both are driven over a fake daemon (`_box1195.FakeDaemon`, a container's
state as a daemon keeps it) as the injected `docker=` seam, or, for the default seam, as the
`docker` program first on `PATH`; never `monkeypatch.setattr`.

Tests -> obligations:

- E2', the run's sequence (-> O2'', O3'): the status must be `exited`, then `docker start`, then
  `running`, the body (handed the same box), then `docker stop -t 0 <name>` and `exited`:
  `test_a_run_starts_the_stopped_box_for_its_body_and_stops_it_after`,
  `test_each_run_starts_and_stops_the_one_box`.
- E2'/E3', the check before the start: `test_a_box_that_is_not_exited_before_the_start_is_refused`
  (with a best-effort stop on the refusal; positive control: the rows above, `exited`), and
  `test_a_stop_that_failed_and_was_swallowed_makes_the_next_run_refuse_before_its_body`, with
  `test_control_a_stop_that_holds_lets_the_next_run_start`.
- E2', an unproven start: `test_a_start_that_cannot_be_proven_runs_no_body_and_is_stopped_again`.
- E2', the stop on every exit: `test_a_run_stops_its_box_when_the_body_raises` (an exception,
  `KeyboardInterrupt`, `SystemExit`, a `BoxFault`); its fault's precedence:
  `test_a_stop_fault_with_nothing_in_flight_is_raised`,
  `test_a_stop_fault_under_an_in_flight_exception_is_logged_and_the_exception_propagates`.
- No-ops and fail-closed: `test_box_for_run_with_no_box_or_an_unsandboxed_one_asks_no_daemon`,
  `test_box_for_run_refuses_an_object_that_cannot_say_whether_it_is_sandboxed`, and the same
  for `stop_run_box`.
- `stop_run_box` (-> O4): `test_stop_run_box_stops_a_running_box_and_proves_it_exited`,
  `test_stop_run_box_that_cannot_prove_the_box_exited_is_a_box_fault`.
- Every docker call goes through `_call`: `test_a_docker_seam_that_raises_is_a_box_fault`.
- The default seam: `test_the_default_seam_reaches_the_docker_on_path`.
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.runtime.box import BoxExecutor, BoxFault, unboxed_executor
from defender.tests import _box1195 as X

NAME = "defender-drain-u1195"

START = ["docker", "start", NAME]
STOP = ["docker", "stop", "-t", "0", NAME]


def _stopped_box(tmp_path: Path) -> tuple[X.FakeDaemon, BoxExecutor]:
    """The daemon holding the batch's box `exited` (after its post-create stop), and the box."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.hold(NAME, "exited")
    return daemon, X.sandboxed(NAME)


def _run(daemon: X.FakeDaemon, box: Any, body: Any = None) -> Any:
    """One run of `box` over `daemon`: the body marks `body` in the daemon's log, notes the
    status it saw, and runs `body()` if given. Returns what the body was handed, or `None`."""
    seen: list[Any] = []

    def go() -> None:
        with X.box_for_run(box, docker=daemon) as got:
            daemon.mark("body")
            seen.append(got)
            if body is not None:
                body()

    raised = X.caught(go)
    if raised is not None:
        raise raised
    return seen[0] if seen else None


# ---------------------------------------------------------------------------------------
# E2': exited -> start -> running -> body -> stop -> exited
# ---------------------------------------------------------------------------------------


def test_a_run_starts_the_stopped_box_for_its_body_and_stops_it_after(tmp_path: Path):
    """The box is `exited`: the run asks its status, `docker start <name>`, proves it
    `running`, hands the body the SAME box (which sees it running), then `docker stop -t 0
    <name>` and proves it `exited`."""
    daemon, box = _stopped_box(tmp_path)
    saw: list[str | None] = []
    got = _run(daemon, box, body=lambda: saw.append(daemon.status(NAME)))
    assert got is box, "the body was not handed the box itself"
    assert saw == ["running"], "the body ran while the box was not running"
    assert daemon.steps() == ["status", "start", "status", "body", "stop", "status"], (
        daemon.steps())
    calls = daemon.docker_calls()
    assert START in calls, calls
    assert STOP in calls, calls
    assert daemon.status(NAME) == "exited"


def test_each_run_starts_and_stops_the_one_box(tmp_path: Path):
    """Three runs of one box: each starts it and stops it again; it is `exited` between them
    and after the last, and nothing creates or removes a container."""
    daemon, box = _stopped_box(tmp_path)
    for _ in range(3):
        _run(daemon, box)
        assert daemon.status(NAME) == "exited", "the box outlived its run running"
    assert daemon.windows() == [["body"]] * 3, daemon.steps()
    assert [c for c in daemon.docker_calls() if c[1] in ("run", "rm")] == []


# ---------------------------------------------------------------------------------------
# E2'/E3': the status before the start must be `exited`
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["running", "paused", "created", "restarting", "dead", None],
                         ids=lambda s: s or "absent")
def test_a_box_that_is_not_exited_before_the_start_is_refused(tmp_path: Path,
                                                              status: str | None):
    """The box is not `exited` when its run is entered (`docker start` on a running container
    answers 0 and does nothing, C3, so only the status can tell): `BoxFault`, the body never
    runs, nothing is started, and a best-effort stop was tried, so a box left running is
    stopped before the refusal unwinds. Control: the rows above (`exited`)."""
    daemon = X.FakeDaemon(tmp_path)
    if status is not None:
        daemon.hold(NAME, status)
    got = X.caught(lambda: _run(daemon, X.sandboxed(NAME)))
    assert isinstance(got, BoxFault), got
    steps = daemon.steps()
    assert "body" not in steps, "the body ran beside a box that was not stopped"
    assert "start" not in steps, f"the box was started though it was not stopped: {steps}"
    assert STOP in daemon.docker_calls(), f"no best-effort stop on the refusal: {steps}"
    if status == "running":
        assert daemon.status(NAME) == "exited", "the refusal left the box running"


@pytest.mark.parametrize("start", ["refused", "takes-no-effect", "status-unanswered"])
def test_a_start_that_cannot_be_proven_runs_no_body_and_is_stopped_again(tmp_path: Path,
                                                                         start: str):
    """`docker start` is refused, answers 0 and changes nothing, or takes while the status asked
    after it goes unanswered: `BoxFault`, the body never runs, and a stop follows the start, so
    a start that took is undone before the refusal unwinds (`status-unanswered`: the box is
    `exited` again)."""
    daemon, box = _stopped_box(tmp_path)
    if start == "refused":
        daemon.refuse_start()
    elif start == "takes-no-effect":
        daemon.start_takes_no_effect()
    else:
        daemon.refuse_inspect(at=[2])  # the status asked after the start
    got = X.caught(lambda: _run(daemon, box))
    assert isinstance(got, BoxFault), got
    steps = daemon.steps()
    assert "body" not in steps, steps
    assert "stop" in steps[steps.index("start"):], f"no stop after the unproven start: {steps}"
    assert daemon.status(NAME) == "exited", "the unproven start left the box running"


def test_a_stop_that_failed_and_was_swallowed_makes_the_next_run_refuse_before_its_body(
        tmp_path: Path):
    """E3': run 1's stop is refused, and a layer above swallows the `BoxFault`: the box is
    still running. Run 2 refuses before its body, starts nothing, and stops the box
    best-effort, so it is `exited` once the refusal unwinds."""
    daemon, box = _stopped_box(tmp_path)
    daemon.refuse_stop()
    swallowed = X.caught(lambda: _run(daemon, box))
    assert isinstance(swallowed, BoxFault), swallowed
    assert daemon.status(NAME) == "running", "the fake did not leave the box running"
    starts_before = daemon.steps().count("start")

    got = X.caught(lambda: _run(daemon, box))

    assert isinstance(got, BoxFault), got
    assert daemon.steps().count("body") == 1, "run 2's body ran beside a running box"
    assert daemon.steps().count("start") == starts_before, "run 2 started a running box"
    assert daemon.status(NAME) == "exited", "the refusal left the box running"


def test_control_a_stop_that_holds_lets_the_next_run_start(tmp_path: Path):
    daemon, box = _stopped_box(tmp_path)
    _run(daemon, box)
    _run(daemon, box)
    assert daemon.steps().count("body") == 2
    assert daemon.steps().count("start") == 2


# ---------------------------------------------------------------------------------------
# E2': the stop on every exit, and its fault's precedence
# ---------------------------------------------------------------------------------------


def _body_failures() -> list:
    return [
        pytest.param(lambda: RuntimeError("the agent crashed"), id="exception"),
        pytest.param(KeyboardInterrupt, id="keyboard-interrupt"),
        # Neither an `Exception` nor an interrupt: a spawn that calls `sys.exit`.
        pytest.param(lambda: SystemExit(3), id="system-exit"),
        pytest.param(lambda: BoxFault("the agent's own box fault"), id="box-fault"),
    ]


def _raise(exc: BaseException) -> Any:
    def body() -> None:
        raise exc

    return body


@pytest.mark.parametrize("failure", _body_failures())
def test_a_run_stops_its_box_when_the_body_raises(tmp_path: Path, failure: Any):
    """The body raises: the box is stopped after it and proven `exited`, and the body's own
    exception propagates unchanged."""
    daemon, box = _stopped_box(tmp_path)
    raised = failure()
    got = X.caught(lambda: _run(daemon, box, body=_raise(raised)))
    assert got is raised, got
    steps = daemon.steps()
    assert "stop" in steps[steps.index("body"):], f"no stop after the body: {steps}"
    assert daemon.status(NAME) == "exited"


@pytest.mark.parametrize("stop", ["refused", "takes-no-effect"])
def test_a_stop_fault_with_nothing_in_flight_is_raised(tmp_path: Path, stop: str):
    """The body returns; the stop is refused, or answers 0 with the box still running:
    `BoxFault`, and the box is still running (nothing else claims to have stopped it)."""
    daemon, box = _stopped_box(tmp_path)
    if stop == "refused":
        daemon.refuse_stop()
    else:
        daemon.stop_takes_no_effect()
    got = X.caught(lambda: _run(daemon, box))
    assert isinstance(got, BoxFault), got
    assert daemon.steps().count("body") == 1
    assert daemon.status(NAME) == "running"


@pytest.mark.parametrize("failure", _body_failures())
def test_a_stop_fault_under_an_in_flight_exception_is_logged_and_the_exception_propagates(
        tmp_path: Path, caplog, failure: Any):
    """The body raises and the stop is refused too: the body's exception propagates (the same
    object), and the stop fault is logged at ERROR or worse, naming the box. Control: the row
    above (nothing in flight: the stop fault is raised)."""
    caplog.set_level(logging.WARNING)
    daemon, box = _stopped_box(tmp_path)
    daemon.refuse_stop()
    raised = failure()
    got = X.caught(lambda: _run(daemon, box, body=_raise(raised)))
    assert got is raised, got
    assert STOP in daemon.docker_calls(), "the box was never stopped"
    logged = [r for r in caplog.records if r.levelno >= logging.ERROR and NAME in r.getMessage()]
    assert logged, "the stop fault left no trace under the in-flight exception"


# ---------------------------------------------------------------------------------------
# No-ops, and fail-closed
# ---------------------------------------------------------------------------------------

#: Boxes standing for no container: none, the opt-out's host executor, an unattached
#: executor, a stand-in saying it is unsandboxed.
NO_CONTAINER = [
    pytest.param(lambda: None, id="none"),
    pytest.param(unboxed_executor, id="unboxed-executor"),
    pytest.param(BoxExecutor, id="unattached-executor"),
    pytest.param(lambda: SimpleNamespace(sandboxed=False, name=NAME), id="says-unsandboxed"),
]

#: Objects that cannot say whether they are sandboxed: never assumed safe.
UNKNOWN = [
    pytest.param(object, id="object"),
    pytest.param(lambda: SimpleNamespace(name=NAME), id="no-sandboxed-attribute"),
]


@pytest.mark.parametrize("make", NO_CONTAINER)
def test_box_for_run_with_no_box_or_an_unsandboxed_one_asks_no_daemon(tmp_path: Path, make: Any):
    """`None`, or a box standing for no container (the opt-out, N12): the body runs, handed that
    same object, and the daemon is asked nothing, though it holds a running box under the name.
    Control: the sandboxed rows above."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.hold(NAME, "running")
    box = make()
    got = _run(daemon, box)
    assert got is box, got
    assert daemon.docker_calls() == [], daemon.docker_calls()


@pytest.mark.parametrize("make", UNKNOWN)
def test_box_for_run_refuses_an_object_that_cannot_say_whether_it_is_sandboxed(
        tmp_path: Path, make: Any):
    """An object with no `sandboxed`: `BoxFault`, the body never runs, no docker call."""
    daemon, _box = _stopped_box(tmp_path)
    got = X.caught(lambda: _run(daemon, make()))
    assert isinstance(got, BoxFault), got
    assert "body" not in daemon.steps()
    assert daemon.docker_calls() == [], daemon.docker_calls()


@pytest.mark.parametrize("make", NO_CONTAINER)
def test_stop_run_box_with_no_box_or_an_unsandboxed_one_asks_no_daemon(tmp_path: Path, make: Any):
    daemon = X.FakeDaemon(tmp_path)
    daemon.hold(NAME, "running")
    X.stop_run_box(make(), docker=daemon)
    assert daemon.docker_calls() == [], daemon.docker_calls()
    assert daemon.status(NAME) == "running"


@pytest.mark.parametrize("make", UNKNOWN)
def test_stop_run_box_refuses_an_object_that_cannot_say_whether_it_is_sandboxed(
        tmp_path: Path, make: Any):
    daemon = X.FakeDaemon(tmp_path)
    got = X.caught(lambda: X.stop_run_box(make(), docker=daemon))
    assert isinstance(got, BoxFault), got
    assert daemon.docker_calls() == []


# ---------------------------------------------------------------------------------------
# stop_run_box
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("before", ["running", "exited"])
def test_stop_run_box_stops_a_running_box_and_proves_it_exited(tmp_path: Path, before: str):
    """`docker stop -t 0 <name>`, then the status is `exited`: it returns. An already-stopped
    box is proven the same way."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.hold(NAME, before)
    X.stop_run_box(X.sandboxed(NAME), docker=daemon)
    assert STOP in daemon.docker_calls(), daemon.docker_calls()
    assert daemon.steps()[-1] == "status", "the stop was not proven by the status"
    assert daemon.status(NAME) == "exited"


@pytest.mark.parametrize("stop", ["refused", "takes-no-effect", "status-unanswered"])
def test_stop_run_box_that_cannot_prove_the_box_exited_is_a_box_fault(tmp_path: Path, stop: str):
    """The stop is refused, answers 0 with the box still running, or takes while the status
    asked after it goes unanswered: `BoxFault` (the status is the proof, never the stop's own
    exit code). Control: the row above."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.hold(NAME, "running")
    if stop == "refused":
        daemon.refuse_stop()
    elif stop == "takes-no-effect":
        daemon.stop_takes_no_effect()
    else:
        daemon.refuse_inspect(at=[1])
    got = X.caught(lambda: X.stop_run_box(X.sandboxed(NAME), docker=daemon))
    assert isinstance(got, BoxFault), got
    assert STOP in daemon.docker_calls()


# ---------------------------------------------------------------------------------------
# Every docker call goes through `_call`
# ---------------------------------------------------------------------------------------


def _raising_docker(kind: str) -> Any:
    fault: BaseException = (FileNotFoundError(2, "No such file or directory", "docker")
                            if kind == "OSError"
                            else subprocess.TimeoutExpired(cmd=["docker"], timeout=120))

    def docker(*_a: Any, **_k: Any) -> Any:
        raise fault

    return docker


@pytest.mark.parametrize("kind", ["OSError", "TimeoutExpired"])
def test_a_docker_seam_that_raises_is_a_box_fault(kind: str):
    """The `docker=` seam raises (no binary; a daemon that never answered): `box_for_run`'s
    entry and `stop_run_box` each raise `BoxFault`, and the body never runs."""
    ran: list[str] = []

    def enter() -> None:
        with X.box_for_run(X.sandboxed(NAME), docker=_raising_docker(kind)):
            ran.append("body")

    assert isinstance(X.caught(enter), BoxFault)
    assert ran == []
    got = X.caught(lambda: X.stop_run_box(X.sandboxed(NAME), docker=_raising_docker(kind)))
    assert isinstance(got, BoxFault), got


# ---------------------------------------------------------------------------------------
# The default seam
# ---------------------------------------------------------------------------------------


def test_the_default_seam_reaches_the_docker_on_path(tmp_path: Path, monkeypatch):
    """No `docker=`: the run and `stop_run_box` reach the `docker` program first on `PATH` (as
    the spawn sites and the drain's post-create stop do), over the same container."""
    daemon, box = X.boxed(tmp_path, monkeypatch, NAME)
    saw: list[str | None] = []
    with X.box_for_run(box) as got:
        saw.append(daemon.status(NAME))
    assert got is box
    assert saw == ["running"]
    assert daemon.status(NAME) == "exited"
    daemon.hold(NAME, "running")
    X.stop_run_box(box)
    assert daemon.status(NAME) == "exited"
    assert daemon.docker_calls().count(START) == 1
    assert daemon.docker_calls().count(STOP) == 2
