"""#1178 amendment 2, D1''/D2'': the lane's box is frozen unless an agent is running.

`runtime.box.pause_box(box, *, docker=...)` freezes a box and proves it frozen;
`runtime.box.thawed(box, *, docker=...)` thaws it for a `with` body (the agent's run) and
re-freezes it on every exit. Both are driven over an injected docker seam (`Daemon`), never
`monkeypatch.setattr`:

- No box (`None`), or a box whose `sandboxed` is false (the unsandboxed fallback, an unattached
  executor, a stand-in saying so), asks the daemon nothing. An object with no `sandboxed` at all
  fails closed (`BoxFault`), also without a docker call: an unknown box is never assumed safe.
- "Frozen" is proven by `docker inspect`'s `.State.Status`: `paused`, or `exited`/`dead` (a box
  that writes nothing). The daemon fake answers the other fields an implementation might ask
  (`.State.Paused`, `.State.Running`) with `true` whatever the status is, so only the status
  field tells a box that froze from one that did not, or one that thawed from one that did not.
- `thawed` runs its body only once the status says `running`; on every exit (a return, an
  `Exception`, a `KeyboardInterrupt`) it re-freezes and proves it. A re-freeze that fails is a
  `BoxFault` even over the body's own exception (which stays its context); one that holds lets
  the body's exception through unchanged.
- A seam that raises (`OSError`: no binary; `subprocess.TimeoutExpired`: a daemon that never
  answered) is a `BoxFault`, the systemic class a drain halts on.
- The default seam (the real docker) with a sandboxed box naming no container refuses, whether
  or not a docker binary is on `PATH`.

The lanes' wiring is in `test_1178_thaw_gate.py`; the real-box row in `test_1178_frozen_box.py`.
"""
from __future__ import annotations

import shutil
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.runtime.box import BoxExecutor, BoxFault, BoxSpec, _DockerTransport, unboxed_executor

BOX_NAME = "defender-drain-p1178"


def _pause_box() -> Callable[..., None]:
    """`runtime.box.pause_box`, imported at call time so this module collects while it does not
    exist yet."""
    from defender.runtime.box import pause_box

    return pause_box


def _thawed() -> Callable[..., Any]:
    """`runtime.box.thawed`, imported at call time (see `_pause_box`)."""
    from defender.runtime.box import thawed

    return thawed


def _sandboxed(name: str = BOX_NAME) -> BoxExecutor:
    """A box as `start_box` hands one back for a started container: the docker transport, so
    `sandboxed` is true, named as its container. Nothing is started; the docker seam is faked."""
    spec = BoxSpec()
    return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name)


class Daemon:
    """The injected `docker=` seam: a container's state, as a daemon keeps it. Appends
    `("docker", verb, argv)` to the shared `log` for every call and decides nothing about what
    an answer means.

    `state` is what `.State.Status` reports. A `pause` moves it to `on_pause` and an `unpause`
    to `on_unpause` (`None`: the verb does not take, the state stays), each answering its `_rc`.
    `.State.Paused` and `.State.Running` answer `true` whatever the state is (a paused container
    is still "running" to docker), and any other field is no answer at all: so only the status
    field tells a box that froze from one that did not.

    `raises` maps `verb` (every call of it) or `verb#n` (its n-th call, from 1) to the exception
    the seam raises instead of answering, after logging the call, as the real seam does when the
    binary is missing (`OSError`) or the daemon hangs (`subprocess.TimeoutExpired`)."""

    def __init__(self, log: list, *, state: str = "running", on_pause: str | None = "paused",
                 on_unpause: str | None = "running", pause_rc: int = 0, unpause_rc: int = 0,
                 inspect_rc: int = 0, raises: dict[str, BaseException] | None = None) -> None:
        self.log = log
        self.state = state
        self.on_pause = on_pause
        self.on_unpause = on_unpause
        self.pause_rc = pause_rc
        self.unpause_rc = unpause_rc
        self.inspect_rc = inspect_rc
        self.raises = dict(raises or {})
        self._seen: dict[str, int] = {}

    def __call__(self, argv, **_kwargs: object) -> subprocess.CompletedProcess:
        argv = list(argv)
        verb = argv[1] if len(argv) > 1 else ""
        self.log.append(("docker", verb, argv))
        self._seen[verb] = self._seen.get(verb, 0) + 1
        fault = self.raises.get(f"{verb}#{self._seen[verb]}", self.raises.get(verb))
        if fault is not None:
            raise fault
        if verb == "pause":
            if self.on_pause is not None:
                self.state = self.on_pause
            return self._reply(argv, self.pause_rc, "")
        if verb == "unpause":
            if self.on_unpause is not None:
                self.state = self.on_unpause
            return self._reply(argv, self.unpause_rc, "")
        if verb == "inspect":
            return self._reply(argv, self.inspect_rc, self._field(" ".join(argv)))
        return self._reply(argv, 1, "")

    def _field(self, asked: str) -> str:
        if ".State.Status" in asked:
            return f"{self.state}\n"
        if ".State.Paused" in asked or ".State.Running" in asked:
            return "true\n"
        return "map[asked:a field this fake does not model]\n"

    @staticmethod
    def _reply(argv: list[str], rc: int, out: str) -> subprocess.CompletedProcess:
        err = "" if rc == 0 else f"Error response from daemon: refused by the fake ({argv[1]})\n"
        return subprocess.CompletedProcess(argv, rc, out if rc == 0 else "", err)


def _steps(log: list) -> list[str]:
    """The shared log as one sequence: each docker verb, and `body` where the body ran."""
    return [e[1] if e[0] == "docker" else e[0] for e in log]


def _docker_calls(log: list) -> list[tuple[str, list[str]]]:
    return [(e[1], e[2]) for e in log if e[0] == "docker"]


def _assert_each_call_names_the_box(log: list, name: str = BOX_NAME) -> None:
    """Every docker call is `docker <verb> ... <name>`, and every inspect asks the status field."""
    calls = _docker_calls(log)
    assert calls, "no docker call was made, so the naming check is vacuous"
    for verb, argv in calls:
        assert argv[0] == "docker", (verb, argv)
        assert name in argv, (verb, argv)
        if verb == "inspect":
            assert any(".State.Status" in a for a in argv), f"inspect did not ask the status: {argv}"


def _seam_fault(kind: str) -> BaseException:
    """What the real docker seam raises: no binary (`OSError`), or a daemon that never answered
    within the seam's timeout (`subprocess.TimeoutExpired`)."""
    if kind == "OSError":
        return FileNotFoundError(2, "No such file or directory", "docker")
    return subprocess.TimeoutExpired(cmd=["docker"], timeout=120)


def _caught(fn: Callable[[], object]) -> BaseException | None:
    """What `fn` raised, any `BaseException` included, or `None`: a `KeyboardInterrupt` a body
    raises is judged here, never left to abort the test session."""
    try:
        fn()
    except BaseException as e:  # noqa: BLE001 — judged by the caller, whatever its class
        return e
    return None


def _in_context_chain(exc: BaseException, target: BaseException) -> bool:
    """Whether `target` is `exc`'s `__context__`, or one further down that chain."""
    seen = exc.__context__
    while seen is not None:
        if seen is target:
            return True
        seen = seen.__context__
    return False


# A box `pause_box`/`thawed` must leave alone: nothing there is a container.
NO_OP_BOXES = [
    pytest.param(lambda: None, id="none"),
    pytest.param(unboxed_executor, id="unsandboxed-fallback"),
    pytest.param(BoxExecutor, id="unattached-executor"),
    pytest.param(lambda: SimpleNamespace(sandboxed=False, name=BOX_NAME), id="says-unsandboxed"),
]

#: Objects that do not say whether they are sandboxed: refused, never assumed safe.
UNKNOWN_BOXES = [
    pytest.param(object, id="object"),
    pytest.param(lambda: SimpleNamespace(name=BOX_NAME), id="named-stand-in"),
]


# ---------------------------------------------------------------------------------------
# pause_box
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("make", NO_OP_BOXES)
def test_pause_box_asks_the_daemon_nothing_without_a_sandboxed_box(make: Callable[[], Any]):
    """No box, or one whose `sandboxed` is false: `pause_box` returns and makes no docker call."""
    log: list = []
    assert _pause_box()(make(), docker=Daemon(log)) is None
    assert log == [], log


@pytest.mark.parametrize("make", UNKNOWN_BOXES)
def test_pause_box_fails_closed_on_a_box_that_does_not_say_whether_it_is_sandboxed(
        make: Callable[[], Any]):
    """An object with no `sandboxed` attribute: `BoxFault`, and no docker call (nothing is
    assumed about it, the daemon included). Control: the no-op rows above, which do say."""
    log: list = []
    with pytest.raises(BoxFault):
        _pause_box()(make(), docker=Daemon(log))
    assert log == [], log


def test_pause_box_pauses_then_proves_the_pause_by_the_status():
    """The positive path: `docker pause <name>`, then `docker inspect` of `.State.Status` (it
    says `paused`), and nothing else."""
    log: list = []
    daemon = Daemon(log, state="running")
    _pause_box()(_sandboxed(), docker=daemon)
    assert _steps(log) == ["pause", "inspect"], log
    _assert_each_call_names_the_box(log)
    assert daemon.state == "paused"


#: `(pause rc, the status after it)` a box counts as frozen at: paused, or no longer running at
#: all. A non-zero pause rc is fine there (docker refuses to pause a paused or an exited box).
FROZEN = [(rc, status) for rc in (0, 1) for status in ("paused", "exited", "dead")]
#: ... and statuses it does not: the box may still write.
NOT_FROZEN = [(rc, status) for rc in (0, 1)
              for status in ("running", "restarting", "created", "removing", "")]


@pytest.mark.parametrize(("pause_rc", "status"), FROZEN)
def test_pause_box_accepts_a_box_the_status_shows_frozen(pause_rc: int, status: str):
    """The pause leaves the status at `paused` (already paused) or the box has exited / died:
    `pause_box` returns, whatever the pause's rc was. The fake's `.State.Paused` says `true`
    either way, so this row and the next differ only in what the status field says."""
    log: list = []
    _pause_box()(_sandboxed(), docker=Daemon(log, state=status, on_pause=None, pause_rc=pause_rc))
    _assert_each_call_names_the_box(log)


@pytest.mark.parametrize(("pause_rc", "status"), NOT_FROZEN)
def test_pause_box_refuses_a_box_the_status_does_not_show_frozen(pause_rc: int, status: str):
    """The pause did not take (the status stays `running`, or is a state that may still run),
    whether docker refused it or claimed it worked: `BoxFault`. An implementation that asked
    `.State.Paused` (always `true` here) would pass this box. Control: the row above."""
    log: list = []
    with pytest.raises(BoxFault):
        _pause_box()(_sandboxed(),
                     docker=Daemon(log, state=status, on_pause=None, pause_rc=pause_rc))
    assert [v for v, _ in _docker_calls(log)][:1] == ["pause"], log


def test_pause_box_refuses_a_box_whose_status_the_daemon_will_not_give():
    """`inspect` answers non-zero (no such container): `BoxFault`, even though the pause said it
    worked. Control: the positive path (inspect rc 0)."""
    log: list = []
    with pytest.raises(BoxFault):
        _pause_box()(_sandboxed(), docker=Daemon(log, inspect_rc=1))


@pytest.mark.parametrize("verb", ["pause", "inspect"])
@pytest.mark.parametrize("kind", ["OSError", "TimeoutExpired"])
def test_pause_box_turns_a_seam_raise_into_a_box_fault(kind: str, verb: str):
    """The seam raises at the pause or at the inspect: a `BoxFault`, never the bare `OSError` /
    `TimeoutExpired`. At the pause the box would still answer `paused` to the inspect, so a
    raise there is not read as an "already paused" refusal."""
    log: list = []
    daemon = Daemon(log, state="paused", raises={verb: _seam_fault(kind)})
    with pytest.raises(BoxFault):
        _pause_box()(_sandboxed(), docker=daemon)


# ---------------------------------------------------------------------------------------
# thawed
# ---------------------------------------------------------------------------------------


def _hold(box: Any, daemon: Daemon, log: list, *, raises: BaseException | None = None,
          during: Callable[[], object] | None = None) -> None:
    """Run a body under `thawed(box, docker=daemon)`: it logs `("body",)`, runs `during` (the
    box changing while thawed), then raises `raises` if given (the agent failing)."""
    with _thawed()(box, docker=daemon):
        log.append(("body",))
        if during is not None:
            during()
        if raises is not None:
            raise raises


@pytest.mark.parametrize("make", NO_OP_BOXES)
def test_thawed_runs_the_body_and_asks_the_daemon_nothing_without_a_sandboxed_box(
        make: Callable[[], Any]):
    log: list = []
    _hold(make(), Daemon(log), log)
    assert log == [("body",)], log


@pytest.mark.parametrize("make", UNKNOWN_BOXES)
def test_thawed_fails_closed_on_a_box_that_does_not_say_whether_it_is_sandboxed(
        make: Callable[[], Any]):
    """No `sandboxed` attribute: `BoxFault`, the body never runs, no docker call."""
    log: list = []
    with pytest.raises(BoxFault):
        _hold(make(), Daemon(log), log)
    assert log == [], log


def test_thawed_unpauses_proves_it_runs_the_body_and_refreezes():
    """The positive path, in one sequence: `unpause`, `inspect` (it says `running`), the body,
    `pause`, `inspect` (it says `paused`); every call names the box and asks its status."""
    log: list = []
    daemon = Daemon(log, state="paused")
    _hold(_sandboxed(), daemon, log)
    assert _steps(log) == ["unpause", "inspect", "body", "pause", "inspect"], log
    _assert_each_call_names_the_box(log)
    assert daemon.state == "paused"


@pytest.mark.parametrize("fault", [
    {"unpause_rc": 1, "on_unpause": None},
    {"on_unpause": None},
    {"on_unpause": "exited"},
    {"on_unpause": "restarting"},
    {"inspect_rc": 1},
], ids=["unpause-refused", "unpause-did-not-take", "exited", "restarting", "inspect-refused"])
def test_a_thaw_that_cannot_be_shown_running_refuses_the_body(fault: dict):
    """The unpause is refused, claims to work but the status stays `paused`, the box comes back
    in another state, or the daemon will not give the status: `BoxFault`, and the body (the
    agent) never runs. The fake's `.State.Running` says `true` throughout, so only the status
    tells these apart from the positive path, which is their control."""
    log: list = []
    with pytest.raises(BoxFault):
        _hold(_sandboxed(), Daemon(log, state="paused", **fault), log)
    assert ("body",) not in log, log
    assert [v for v, _ in _docker_calls(log)][:1] == ["unpause"], log


def test_a_refreeze_that_fails_after_a_clean_body_is_a_fault():
    """The body returns; the re-freeze does not take (pause refused, status still `running`):
    `BoxFault` (a box left live is unsafe for the host's next step)."""
    log: list = []
    with pytest.raises(BoxFault):
        _hold(_sandboxed(), Daemon(log, state="paused", on_pause=None, pause_rc=1), log)
    assert _steps(log)[:3] == ["unpause", "inspect", "body"], log
    assert "pause" in _steps(log)[3:], log


def test_a_box_that_died_while_thawed_counts_as_frozen():
    """The box exits during the body; the re-freeze's pause is refused, and the status says
    `exited`: `thawed` returns cleanly (a dead box writes nothing)."""
    log: list = []
    daemon = Daemon(log, state="paused", on_pause=None, pause_rc=1)

    def die() -> None:
        daemon.state = "exited"

    _hold(_sandboxed(), daemon, log, during=die)
    assert _steps(log) == ["unpause", "inspect", "body", "pause", "inspect"], log


def _body_failures() -> list:
    return [
        pytest.param(lambda: LeadAuthorError("agent wrote x; refusing to commit"), id="exception"),
        pytest.param(KeyboardInterrupt, id="keyboard-interrupt"),
    ]


@pytest.mark.parametrize("failure", _body_failures())
def test_the_body_failing_still_refreezes_and_its_exception_propagates(
        failure: Callable[[], BaseException]):
    """The body raises (an `Exception`, or a `KeyboardInterrupt`, which is not one): the box is
    re-frozen and proven (`pause`, `inspect` after the body), and the body's own exception
    propagates unchanged."""
    log: list = []
    raised = failure()
    got = _caught(lambda: _hold(_sandboxed(), Daemon(log, state="paused"), log, raises=raised))
    assert got is raised, got
    assert _steps(log) == ["unpause", "inspect", "body", "pause", "inspect"], log


@pytest.mark.parametrize("failure", _body_failures())
def test_a_refreeze_fault_outranks_the_bodys_exception(failure: Callable[[], BaseException]):
    """The body raises and the re-freeze does not take: the `BoxFault` propagates (the batch
    halts), with the body's exception as its context. Control: the row above (re-freeze holds,
    the body's exception propagates)."""
    log: list = []
    raised = failure()
    got = _caught(lambda: _hold(
        _sandboxed(), Daemon(log, state="paused", on_pause=None, pause_rc=1), log, raises=raised))
    assert isinstance(got, BoxFault), got
    assert _in_context_chain(got, raised), (got, got.__context__)
    assert "pause" in _steps(log)[_steps(log).index("body"):], log


@pytest.mark.parametrize("at", ["unpause", "inspect#1"])
@pytest.mark.parametrize("kind", ["OSError", "TimeoutExpired"])
def test_a_seam_raise_before_the_body_is_a_fault_and_the_body_never_runs(kind: str, at: str):
    log: list = []
    with pytest.raises(BoxFault):
        _hold(_sandboxed(), Daemon(log, state="paused", raises={at: _seam_fault(kind)}), log)
    assert ("body",) not in log, log


@pytest.mark.parametrize("body", ["returns", "raises"])
@pytest.mark.parametrize("at", ["pause", "inspect#2"])
@pytest.mark.parametrize("kind", ["OSError", "TimeoutExpired"])
def test_a_seam_raise_at_the_refreeze_is_a_fault(kind: str, at: str, body: str):
    """The seam raises at the re-freeze's pause or its proving inspect: a `BoxFault`, whether
    the body returned or raised (whose exception is then in its context)."""
    log: list = []
    refusal = LeadAuthorError("agent wrote x; refusing to commit") if body == "raises" else None
    with pytest.raises(BoxFault) as got:
        _hold(_sandboxed(), Daemon(log, state="paused", raises={at: _seam_fault(kind)}), log,
              raises=refusal)
    assert ("body",) in log, log
    if refusal is not None:
        assert _in_context_chain(got.value, refusal), (got.value, got.value.__context__)


# ---------------------------------------------------------------------------------------
# The default seam: the real docker
# ---------------------------------------------------------------------------------------


def _absent_box() -> BoxExecutor:
    """A sandboxed box naming a container no daemon holds."""
    return _sandboxed(f"defender-drain-p1178-absent-{uuid.uuid4().hex[:12]}")


@pytest.fixture(params=["path-as-is", "no-docker-on-path"])
def docker_on_path(request, tmp_path: Path, monkeypatch) -> str:
    """The real seam's two environments: `PATH` as the run found it (a docker binary, and a
    daemon, where the host has them), and an empty `PATH`, so the seam finds no binary."""
    if request.param == "no-docker-on-path":
        bin_dir = tmp_path / "bin-empty"
        bin_dir.mkdir()
        monkeypatch.setenv("PATH", str(bin_dir))
        assert shutil.which("docker") is None
    return request.param


def test_the_default_pause_refuses_a_box_no_daemon_holds(docker_on_path: str):
    with pytest.raises(BoxFault):
        _pause_box()(_absent_box())


def test_the_default_thaw_refuses_a_box_no_daemon_holds(docker_on_path: str):
    log: list = []
    with pytest.raises(BoxFault), _thawed()(_absent_box()):
        log.append(("body",))
    assert log == [], "the body ran in a box that was never shown running"
