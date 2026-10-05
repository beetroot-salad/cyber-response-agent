"""#1195 amendment (2026-10-06), E1-E3: one box per agent run, through `runtime.box.BoxSource`.

`BoxSource(request, *, start_box=, stop_box=, docker=)` holds one batch's box request and the
start/stop seams; `.run()` is one agent run's box; `.teardown()` is the batch-end proof that
the box is gone; `box_for_run(source)` is the spawn sites' `with`. Every fake enters through
those seams (a recorded `start_box`/`stop_box` pair, `_box1195.Runs`; a fake daemon as the
`docker=` seam, `_box1195.FakeDaemon`), never `monkeypatch.setattr`.

Tests -> obligations:

- E1 (-> O2', O3'), one start and one stop per run, the stop on every exit:
  `test_a_run_starts_its_box_once_and_removes_it_once`,
  `test_each_run_starts_a_fresh_box_and_none_outlives_its_run`,
  `test_a_run_removes_its_box_when_the_body_raises` (an exception, an interrupt).
- E1, teardown-fault precedence: `test_a_teardown_fault_with_nothing_in_flight_is_raised`,
  `test_a_teardown_fault_under_an_in_flight_exception_is_logged_and_the_exception_propagates`.
- E1/E5 (-> O4), every start failure is a `BoxFault`:
  `test_a_start_fault_propagates_and_the_body_never_runs`,
  `test_a_start_failure_that_is_not_a_box_fault_surfaces_as_one_chained_to_it`
  (`AliasBanNotInForce`, and any other `Exception`), positive control
  `test_control_a_start_that_holds_runs_the_body`.
- E4: `test_box_for_run_with_no_source_starts_nothing_and_yields_none`,
  `test_box_for_run_with_a_source_is_one_run_of_it`.
- E3 (-> O2'), the batch-end teardown:
  `test_teardown_asks_no_daemon_when_no_run_started_a_sandboxed_box` (N12: none ran, or only
  unsandboxed executors), `test_teardown_after_the_box_is_gone_removes_nothing`,
  `test_teardown_removes_a_box_the_daemon_still_holds`,
  `test_teardown_that_cannot_remove_the_box_is_a_box_fault`,
  `test_teardown_that_cannot_learn_the_status_is_a_box_fault`.
- E2 (-> O2'), through the real `start_box` (and its `_reap_stale_before_create`) over a fake
  daemon: `test_a_box_left_alive_by_a_failed_teardown_refuses_the_next_run_before_its_body`
  (the earlier teardown fault raised, or logged under an in-flight fault), with
  `test_control_a_teardown_that_holds_lets_the_next_run_start_fresh`; and
  `test_a_link_ban_failure_at_a_real_start_is_a_box_fault_and_no_body_runs`.
"""
from __future__ import annotations

import functools
import logging
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.runtime import box as box_mod
from defender.runtime.box import AliasBanNotInForce, BoxExecutor, BoxFault, unboxed_executor
from defender.tests import _box1195 as X

NAME = "defender-drain-u1195"


def _source(runs: X.Runs, *, docker: Any = None, name: str = NAME) -> Any:
    seams: dict[str, Any] = {"start_box": runs.start, "stop_box": runs.stop}
    if docker is not None:
        seams["docker"] = docker
    return X.box_source(X.request(name), **seams)


def _kinds(log: list) -> list[str]:
    return [e[0] for e in log]


# ---------------------------------------------------------------------------------------
# E1: `.run()` — one start, one stop, the stop on every exit
# ---------------------------------------------------------------------------------------


def test_a_run_starts_its_box_once_and_removes_it_once():
    """`.run()`: `start_box` is handed the source's own request, once; the body gets the
    executor that start handed back; `stop_box` is handed that executor, once, after the body.
    `.name` is the request's name."""
    log: list = []
    runs = X.Runs(log)
    req = X.request(NAME)
    source = X.box_source(req, start_box=runs.start, stop_box=runs.stop)
    assert source.name == NAME

    with source.run() as box:
        log.append(("body", box))

    assert runs.requests == [req]
    assert runs.requests[0] is req, "the start was handed some other request"
    assert len(runs.boxes) == 1
    assert _kinds(log) == ["enter", "body", "exit"], log
    assert log[1][1] is runs.boxes[0], "the body did not get the box its run started"
    assert runs.stopped == [runs.boxes[0]]
    assert runs.stopped[0] is runs.boxes[0]
    assert runs.alive == []


def test_each_run_starts_a_fresh_box_and_none_outlives_its_run():
    """Three runs of one source: three starts, each handed the same request (one container name
    per batch, E2), three distinct executors, each stopped before the next start; no box is up
    before the first run, between two, or after the last."""
    log: list = []
    runs = X.Runs(log)
    source = _source(runs)
    seen: list[Any] = []
    assert runs.alive == [], "a box was up before the first run"
    for _ in range(3):
        with source.run() as box:
            seen.append(box)
            assert runs.alive == [box], runs.alive
        assert runs.alive == [], "a box outlived its run"
    assert _kinds(log) == ["enter", "exit"] * 3, log
    assert [r.name for r in runs.requests] == [NAME] * 3
    assert len({id(b) for b in seen}) == 3, "a run reused an earlier run's box"
    assert [id(b) for b in runs.stopped] == [id(b) for b in seen]


def _body_failures() -> list:
    return [
        pytest.param(lambda: RuntimeError("the agent crashed"), id="exception"),
        pytest.param(KeyboardInterrupt, id="keyboard-interrupt"),
        pytest.param(lambda: BoxFault("the agent's own box fault"), id="box-fault"),
    ]


@pytest.mark.parametrize("failure", _body_failures())
def test_a_run_removes_its_box_when_the_body_raises(failure: Any):
    """The body raises (an `Exception`, an interrupt, a `BoxFault`): the box is stopped, once,
    after the body, and the body's own exception propagates unchanged."""
    log: list = []
    runs = X.Runs(log)
    source = _source(runs)
    raised = failure()

    def go() -> None:
        with source.run():
            log.append(("body",))
            raise raised

    got = X.caught(go)
    assert got is raised, got
    assert _kinds(log) == ["enter", "body", "exit"], log
    assert len(runs.boxes) == 1, runs.boxes
    assert runs.stopped == runs.boxes, "the box was not stopped once, after the body"
    assert runs.alive == []


# ---------------------------------------------------------------------------------------
# E1: a teardown fault — raised with nothing in flight, logged under an in-flight one
# ---------------------------------------------------------------------------------------


def test_a_teardown_fault_with_nothing_in_flight_is_raised():
    """The body returns; the stop raises `BoxFault`: `.run()` raises it."""
    fault = BoxFault("could not tear down the box: refused")
    runs = X.Runs(stop_faults={1: fault})
    source = _source(runs)
    log: list = []

    def go() -> None:
        with source.run():
            log.append("body")

    got = X.caught(go)
    assert isinstance(got, BoxFault), got
    assert fault in X.chain(got), (got, X.chain(got))
    assert log == ["body"]


@pytest.mark.parametrize("failure", _body_failures())
def test_a_teardown_fault_under_an_in_flight_exception_is_logged_and_the_exception_propagates(
        failure: Any, caplog):
    """The body raises and the stop raises `BoxFault` too: the body's exception propagates (the
    same object), and the teardown fault is logged at ERROR or worse, by its own words.
    Control: the row above (nothing in flight, the teardown fault is raised)."""
    caplog.set_level(logging.WARNING)
    fault = BoxFault("could not tear down the box u1195-teardown-words")
    runs = X.Runs(stop_faults={1: fault})
    source = _source(runs)
    raised = failure()

    def go() -> None:
        with source.run():
            raise raised

    got = X.caught(go)
    assert got is raised, got
    assert len(runs.stopped) == 1, "the box was never stopped"
    logged = [r for r in caplog.records if r.levelno >= logging.ERROR
              and ("u1195-teardown-words" in r.getMessage()
                   or (r.exc_info and r.exc_info[1] is fault))]
    assert logged, "the teardown fault left no trace under the in-flight exception"


# ---------------------------------------------------------------------------------------
# E1/E5: every start failure is a `BoxFault`
# ---------------------------------------------------------------------------------------


def test_control_a_start_that_holds_runs_the_body():
    runs = X.Runs()
    ran: list[Any] = []
    with _source(runs).run() as box:
        ran.append(box)
    assert len(ran) == 1, ran
    assert ran == runs.boxes


def test_a_start_fault_propagates_and_the_body_never_runs():
    """The start raises `BoxFault`: `.run()` raises it (the same object) and the body never runs.
    Control: the row above."""
    fault = BoxFault("a container named defender-drain-u1195 already exists and is running")
    runs = X.Runs(start_faults={1: fault})
    ran: list[str] = []

    def go() -> None:
        with _source(runs).run():
            ran.append("body")

    got = X.caught(go)
    assert got is fault, got
    assert ran == []


@pytest.mark.parametrize("make", [
    pytest.param(lambda: AliasBanNotInForce("the alias ban is not in force under runsc"),
                 id="alias-ban-not-in-force"),
    pytest.param(lambda: OSError(28, "No space left on device"), id="os-error"),
])
def test_a_start_failure_that_is_not_a_box_fault_surfaces_as_one_chained_to_it(make: Any):
    """The start raises something that is not a `BoxFault` — `AliasBanNotInForce` (a plain
    `Exception`, outside `SYSTEMIC_FAULTS`), or any other failure: `.run()` raises a `BoxFault`
    whose `__cause__` is the original, and the body never runs. A drain then halts on it rather
    than dead-lettering a claim or containing it to one curator (E5). Control:
    `test_control_a_start_that_holds_runs_the_body`."""
    original = make()
    runs = X.Runs(start_faults={1: original})
    ran: list[str] = []

    def go() -> None:
        with _source(runs).run():
            ran.append("body")

    got = X.caught(go)
    assert isinstance(got, BoxFault), got
    assert got.__cause__ is original, (got, got.__cause__)
    assert ran == []


# ---------------------------------------------------------------------------------------
# E4: `box_for_run`
# ---------------------------------------------------------------------------------------


def test_box_for_run_with_no_source_starts_nothing_and_yields_none():
    with X.box_for_run(None) as box:
        assert box is None


def test_box_for_run_with_a_source_is_one_run_of_it():
    log: list = []
    runs = X.Runs(log)
    with X.box_for_run(_source(runs)) as box:
        log.append(("body", box))
    assert _kinds(log) == ["enter", "body", "exit"]
    assert log[1][1] is runs.boxes[0]
    assert runs.alive == []


# ---------------------------------------------------------------------------------------
# E3: the batch-end teardown
# ---------------------------------------------------------------------------------------


def _teardown_source(daemon: X.FakeDaemon, *, starts: Any) -> Any:
    """A source whose runs hand back `starts()`'s executors and whose stop is the real
    `stop_box` over `daemon` — so any removal, the run's or the teardown's, is a call the daemon
    logs — and whose status probe is `daemon`."""
    def start(_request: Any, *_a: Any, **_kw: Any) -> Any:
        return starts()

    return X.box_source(X.request(NAME), start_box=start,
                        stop_box=functools.partial(box_mod.stop_box, docker=daemon),
                        docker=daemon)


#: Executors a run may hand back that stand for no container: the opt-out's host executor, an
#: unattached executor, a stand-in saying it is unsandboxed.
UNSANDBOXED = [
    pytest.param(unboxed_executor, id="unboxed-executor"),
    pytest.param(BoxExecutor, id="unattached-executor"),
    pytest.param(lambda: SimpleNamespace(sandboxed=False, name=""), id="says-unsandboxed"),
]


@pytest.mark.parametrize("runs", [0, 2])
@pytest.mark.parametrize("make", UNSANDBOXED)
def test_teardown_asks_no_daemon_when_no_run_started_a_sandboxed_box(
        tmp_path: Path, make: Any, runs: int):
    """No run at all, or runs whose executors are not sandboxed (the opt-out, N12): `.teardown()`
    returns and makes no docker call, even with the batch's name held by a running container the
    daemon would otherwise be asked about. Control: the rows below, where a sandboxed run makes
    the teardown ask."""
    daemon = X.FakeDaemon(tmp_path)
    daemon.hold(NAME, "running")
    source = _teardown_source(daemon, starts=make)
    for _ in range(runs):
        with source.run():
            pass
    before = len(daemon.calls())
    source.teardown()
    assert daemon.calls()[before:] == [], daemon.calls()[before:]


def test_teardown_after_the_box_is_gone_removes_nothing(tmp_path: Path):
    """A sandboxed run whose own stop removed the box: `.teardown()` asks the status, finds no
    such container, and removes nothing."""
    daemon = X.FakeDaemon(tmp_path)
    source = _teardown_source(daemon, starts=lambda: X.sandboxed(NAME))
    daemon.hold(NAME, "running")
    with source.run():
        pass
    assert daemon.status(NAME) is None, "the run's own stop did not remove the box"
    before = len(daemon.calls())
    source.teardown()
    teardown = daemon.steps()[before:]
    assert "status" in teardown, f"the teardown never asked the status: {teardown}"
    assert "rm" not in teardown, f"the teardown removed a box that was gone: {teardown}"


@pytest.mark.parametrize("status", ["running", "paused", "created", "restarting", "exited", "dead"])
def test_teardown_removes_a_box_the_daemon_still_holds(tmp_path: Path, status: str):
    """A sandboxed run, and the batch's name held at batch end, in any state: `.teardown()` asks
    the status, then `docker rm -f <name>`, and the name is gone. Control: the row above (absent:
    no removal)."""
    daemon = X.FakeDaemon(tmp_path)
    source = _teardown_source(daemon, starts=lambda: X.sandboxed(NAME))
    with source.run():
        pass
    daemon.hold(NAME, status)
    before = len(daemon.calls())
    source.teardown()
    teardown = daemon.calls()[before:]
    assert ["docker", "rm", "-f", NAME] in teardown, teardown
    assert daemon.status(NAME) is None


def test_teardown_that_cannot_remove_the_box_is_a_box_fault(tmp_path: Path):
    """The batch's name is held `running` at batch end and every removal fails:
    `.teardown()` raises `BoxFault`, and the box is still there. Control: the row above."""
    daemon = X.FakeDaemon(tmp_path)
    source = _teardown_source(daemon, starts=lambda: X.sandboxed(NAME))
    with source.run():
        pass
    daemon.hold(NAME, "running")
    daemon.refuse_rm(-1)
    with pytest.raises(BoxFault):
        source.teardown()
    assert daemon.status(NAME) == "running"
    assert ["docker", "rm", "-f", NAME] in daemon.calls(), "the teardown never tried to remove it"


def test_teardown_that_cannot_learn_the_status_is_a_box_fault(tmp_path: Path):
    """The daemon answers neither the status nor its own version: `.teardown()` raises
    `BoxFault` rather than reading "no answer" as "no container"."""
    daemon = X.FakeDaemon(tmp_path)
    source = X.box_source(X.request(NAME), start_box=lambda *_a, **_k: X.sandboxed(NAME),
                          stop_box=lambda *_a, **_k: None, docker=daemon)
    with source.run():
        pass
    daemon.go_down()
    with pytest.raises(BoxFault):
        source.teardown()


@pytest.mark.parametrize("kind", ["OSError", "TimeoutExpired"])
def test_teardown_whose_daemon_seam_raises_is_a_box_fault(tmp_path: Path, kind: str):
    """The `docker=` seam raises (no binary; a daemon that never answered): `BoxFault`."""
    fault: BaseException = (FileNotFoundError(2, "No such file or directory", "docker")
                            if kind == "OSError"
                            else subprocess.TimeoutExpired(cmd=["docker"], timeout=120))

    def docker(*_a: Any, **_k: Any) -> Any:
        raise fault

    source = X.box_source(X.request(NAME), start_box=lambda *_a, **_k: X.sandboxed(NAME),
                          stop_box=lambda *_a, **_k: None, docker=docker)
    with source.run():
        pass
    with pytest.raises(BoxFault):
        source.teardown()


# ---------------------------------------------------------------------------------------
# E2: a box that outlived its teardown refuses the next run's start
# ---------------------------------------------------------------------------------------


def _real_source(tmp_path: Path, daemon: X.FakeDaemon) -> Any:
    """A source whose start and stop are the REAL `start_box`/`stop_box` over `daemon`: the
    create, the mount sentinel, the alias probe and the pre-create sweep
    (`_reap_stale_before_create`) all run as in production."""
    writable = tmp_path / "corpus"
    writable.mkdir()
    return X.box_source(
        X.request(NAME, writable=writable),
        start_box=functools.partial(box_mod.start_box, docker=daemon),
        stop_box=functools.partial(box_mod.stop_box, docker=daemon),
        docker=daemon,
    )


@pytest.mark.parametrize("first_run", ["returns", "raises"])
def test_a_box_left_alive_by_a_failed_teardown_refuses_the_next_run_before_its_body(
        tmp_path: Path, monkeypatch, caplog, first_run: str):
    """Run 1 starts a real box; its removal is refused and the box stays `running`. Whether that
    teardown fault was raised (run 1's body returned) or only logged under run 1's own failure
    (its body raised), run 2's start meets the same name still running and raises `BoxFault`
    before its body runs: no second container is created. Control: the next row."""
    X.clear_opt_out(monkeypatch)
    caplog.set_level(logging.WARNING)
    daemon = X.FakeDaemon(tmp_path)
    source = _real_source(tmp_path, daemon)
    crash = RuntimeError("the agent crashed")
    ran: list[str] = []

    def run_1() -> None:
        with source.run() as box:
            ran.append("run 1")
            assert box.sandboxed, box
            assert box.name == NAME, box
            daemon.refuse_rm(1)
            if first_run == "raises":
                raise crash

    got_1 = X.caught(run_1)
    if first_run == "raises":
        assert got_1 is crash, got_1
    else:
        assert isinstance(got_1, BoxFault), got_1
    assert daemon.status(NAME) == "running", "the fake did not leave the box alive"

    def run_2() -> None:
        with source.run():
            ran.append("run 2")

    got_2 = X.caught(run_2)
    assert isinstance(got_2, BoxFault), got_2
    assert ran == ["run 1"], "run 2's body ran beside the box run 1 left alive"
    assert daemon.created() == [NAME], "run 2 created a box beside the live one"


def test_control_a_teardown_that_holds_lets_the_next_run_start_fresh(
        tmp_path: Path, monkeypatch):
    """The same two runs with every removal taking: each run creates its own container, runs
    its body, and removes it; nothing is left after run 2."""
    X.clear_opt_out(monkeypatch)
    daemon = X.FakeDaemon(tmp_path)
    source = _real_source(tmp_path, daemon)
    ran: list[str] = []
    for n in (1, 2):
        with source.run() as box:
            assert daemon.status(NAME) == "running"
            assert box.sandboxed
            ran.append(f"run {n}")
        assert daemon.status(NAME) is None
    assert ran == ["run 1", "run 2"]
    assert daemon.created() == [NAME, NAME]
    source.teardown()
    assert daemon.names() == []


def test_a_link_ban_failure_at_a_real_start_is_a_box_fault_and_no_body_runs(
        tmp_path: Path, monkeypatch):
    """The real start's alias probe reports a banned shape allowed (`AliasBanNotInForce`, which
    `start_box` does not turn into a `BoxFault`): `.run()` raises a `BoxFault` chained to it, the
    body never runs, and the start reaped its own container."""
    X.clear_opt_out(monkeypatch)
    daemon = X.FakeDaemon(tmp_path)
    daemon.allow_an_alias()
    source = _real_source(tmp_path, daemon)
    ran: list[str] = []

    def go() -> None:
        with source.run():
            ran.append("body")

    got = X.caught(go)
    assert isinstance(got, BoxFault), got
    assert isinstance(got.__cause__, AliasBanNotInForce), (got, got.__cause__)
    assert ran == []
    assert daemon.names() == []
