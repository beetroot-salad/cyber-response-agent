"""Amendment 3, C4 (R8): network git on our own terms. It runs in its own session with a wall
timeout, and on any exit from the call (a timeout, an exception, an interrupt) the whole
process group is killed before the error surfaces: a stalled forge fails the fetch or the
push within the timeout, and no process (git, or its `git-remote-http` helper, which a plain
`subprocess.run(timeout=)` leaves orphaned in the clone) outlives the call.

The forge is a real smart-HTTP remote (`http_repo`) whose server stalls the first request of
a service until the test lets it go: silent, or trickling bytes faster than any low-speed
limit (`Trickle`), so curl's `http.lowSpeedLimit`/`lowSpeedTime` cannot end the wait and only
the wall timeout and the group kill can. The timeout is `TenantDelivery.open`'s
`network_timeout` (seconds), the one knob the contract adds for it."""
from __future__ import annotations

import signal
import threading
import time

import pytest

from ._support import LANES, ForgeHTTP, Trickle, delivery, quiet, target

#: The wall timeout the cases give network git, and how long past it a call may take to end.
_TIMEOUT = 3.0
_SLACK = 12.0


class _Stall:
    """`on_service` for the smart-HTTP server: the first request of `service` holds until
    `release()` (or a minute), after `then()` runs; silent, or answered by a `Trickle`."""

    def __init__(self, service, then=None, trickle=False):
        self.service, self.then, self.trickle = service, then, trickle
        self.reached = threading.Event()
        self._go = threading.Event()

    def __call__(self, service):
        if service != self.service:
            return
        self.reached.set()
        if self.then is not None:
            self.then()
        if self.trickle:
            return Trickle(self._go)
        self._go.wait(60)
        return None

    def release(self):
        self._go.set()


def _left(tenant, server):
    """Processes still at work in the tenant's folders, or talking to the server, a moment
    after the call ended (a killed process may take that long to go)."""
    return quiet(tenant.dir, naming=(server.url,), seconds=1.0)


def _stalled_route(http_repo, service, then=None, trickle=False):
    """A delivery (network timeout `_TIMEOUT`) and the call that meets the stall: `publish`'s
    fetch for `git-upload-pack`, `finish`'s push (after a committed claim) for
    `git-receive-pack`."""
    server = http_repo[3]
    d = delivery(http_repo, ForgeHTTP(), network_timeout=_TIMEOUT)
    if service == "git-upload-pack":
        call = d.publish
    else:
        batch = d.start_batch("stalled", lanes=LANES)
        (batch.draft_root / "agent/lessons/stalled.md").write_text("a lesson\n", encoding="utf-8")
        batch.commit(batch.change_set(), "claim")

        def call():
            return d.finish(batch)
    stall = _Stall(service, then, trickle)
    server.rearm()
    server.on_service = stall
    return call, stall


@pytest.mark.parametrize("trickle", [False, True], ids=["silent", "trickle"])
@pytest.mark.parametrize("service", ["git-upload-pack", "git-receive-pack"], ids=["fetch", "push"])
def test_a_stalled_forge_fails_within_the_timeout_and_leaves_no_process(http_repo, service, trickle):
    """R8: the forge accepts the connection and never finishes its answer: it sends nothing,
    or it trickles bytes for ever above any low-speed limit (so `lowSpeedTime` alone never
    ends it, and a `git-remote-http` left behind by a kill of git alone keeps receiving). The
    fetch (publish) or the push (finish) is refused within the timeout, and nothing is left
    running: no git, no `git-remote-http` in the clone or naming the forge's URL."""
    tenant, server = http_repo[0], http_repo[3]
    call, stall = _stalled_route(http_repo, service, trickle=trickle)
    started = time.monotonic()
    try:
        with pytest.raises(target().DeliveryRefused):
            call()
        elapsed = time.monotonic() - started
        assert stall.reached.is_set(), "the call never reached the stalled forge"
        left = _left(tenant, server)
    finally:
        stall.release()
    assert left == [], f"a process outlived the timed-out call: {left}"
    assert elapsed < _TIMEOUT + _SLACK, f"the stalled call took {elapsed:.1f} s against a {_TIMEOUT} s timeout"


class _Fault(Exception):
    """An exception raised into the call while git waits on the forge."""


class _Interrupt(BaseException):
    """An interrupt (a `BaseException`, as `KeyboardInterrupt` is) raised into the call while
    git waits on the forge. Not `KeyboardInterrupt` itself, which would end the session."""


@pytest.mark.parametrize("raised", [_Fault, _Interrupt], ids=["exception", "interrupt"])
@pytest.mark.parametrize("service", ["git-upload-pack", "git-receive-pack"], ids=["fetch", "push"])
def test_an_exception_or_interrupt_during_network_git_leaves_no_process(http_repo, service, raised):
    """R8: while the fetch (publish) or the push (finish) waits on the forge, a signal handler
    raises an exception, or an interrupt, into the call in the main thread. It leaves the
    call (an exception may come out as `DeliveryRefused`), and nothing is left running: the
    process group was killed on the way out."""
    tenant, server = http_repo[0], http_repo[3]

    def handler(signum, frame):
        raise raised("raised while git waited on the forge")
    previous = signal.signal(signal.SIGUSR1, handler)
    call, stall = _stalled_route(http_repo, service,
                                 then=lambda: signal.pthread_kill(threading.main_thread().ident, signal.SIGUSR1))
    expected = (raised,) if raised is _Interrupt else (raised, target().DeliveryRefused)
    try:
        with pytest.raises(expected):
            call()
        assert stall.reached.is_set(), "the call never reached the stalled forge"
        left = _left(tenant, server)
    finally:
        stall.release()
        signal.signal(signal.SIGUSR1, previous)
    assert left == [], f"a process outlived the call: {left}"
