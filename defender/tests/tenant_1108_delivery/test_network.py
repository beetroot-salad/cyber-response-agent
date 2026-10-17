"""Amendment 3, C4 (R8): network git on our own terms. It runs in its own session with a wall
timeout, and on any exit from the call (a timeout, an exception, an interrupt) the whole
process group is killed before the error surfaces: a stalled forge fails the fetch or the
push within the timeout, and no process (git, or its `git-remote-http` helper, which a plain
`subprocess.run(timeout=)` leaves orphaned in the clone) outlives the call. That holds on
every route that runs network git: publish's fetch, `start_batch`'s, finish's PR lookup when
it goes through git, finish's push, deliver's push, and the revert's fetch and push.

The forge is a real smart-HTTP remote (`http_repo`) whose server stalls the first request of
a service until the test lets it go: silent, or trickling bytes faster than any low-speed
limit (`Trickle`), so curl's `http.lowSpeedLimit`/`lowSpeedTime` cannot end the wait and only
the wall timeout and the group kill can. The timeout is `TenantDelivery.open`'s
`network_timeout` (seconds); without it, the module's `NETWORK_TIMEOUT` applies, finite
(orchestrator ruling)."""
from __future__ import annotations

import math
import signal
import threading
import time

import pytest

from ._support import LANES, ForgeHTTP, Trickle, delivery, merge_on_remote, opened, quiet, target

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
            return None
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


#: Each route that runs network git, the service whose first request is stalled, and
#: whether the route must reach it. Finish's lookup reaches git only when it goes through
#: `refs/pull/*` (it may ask the forge's API instead); deliver's push is needed only when the
#: retained branch is not already on the remote at its tip, which here it is.
_ROUTES = {
    "publish-fetch": ("git-upload-pack", True),
    "start_batch-fetch": ("git-upload-pack", True),
    "finish-lookup": ("git-upload-pack", False),
    "finish-push": ("git-receive-pack", True),
    "deliver-push": ("git-receive-pack", False),
    "revert-fetch": ("git-upload-pack", True),
    "revert-push": ("git-receive-pack", True),
}


def _claimed(d, tag):
    batch = d.start_batch(tag, lanes=LANES)
    (batch.draft_root / f"agent/lessons/{tag}.md").write_text("a lesson\n", encoding="utf-8")
    batch.commit(batch.change_set(), "claim")
    return batch


def _stalled_route(http_repo, tmp_path, route, then=None, trickle=False):
    """A delivery (network timeout `_TIMEOUT`), set up so that `call` is the route's call
    with nothing else left to do on the network first, and the stall armed for its service.
    Returns `(call, stall, required)`."""
    server = http_repo[3]
    http = ForgeHTTP()
    d = delivery(http_repo, http, network_timeout=_TIMEOUT)
    service, required = _ROUTES[route]
    if route == "publish-fetch":
        call = d.publish
    elif route == "start_batch-fetch":
        def call():
            return d.start_batch("stalled", lanes=LANES)
    elif route in ("finish-lookup", "finish-push"):
        batch = _claimed(d, "stalled")

        def call():
            return d.finish(batch)
    elif route == "deliver-push":
        batch = _claimed(d, "stalled")
        http.fail_create = True
        with pytest.raises(target().DeliveryRefused):
            d.finish(batch)
        http.fail_create = False

        def call():
            return d.deliver("stalled")
    else:
        batch = _claimed(d, "stalled")
        opened(d.finish(batch))
        merge_on_remote(http_repo, tmp_path, batch.branch)

        def call():
            return d.revert("agent/lessons/stalled.md", "stalled")
    stall = _Stall(service, then, trickle)
    server.rearm()
    server.on_service = stall
    return call, stall, required


@pytest.mark.parametrize("trickle", [False, True], ids=["silent", "trickle"])
@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_a_stalled_forge_fails_within_the_timeout_and_leaves_no_process(http_repo, tmp_path, route, trickle):
    """R8: on each route, the forge accepts the connection and never finishes its answer: it
    sends nothing, or it trickles bytes for ever above any low-speed limit (so `lowSpeedTime`
    alone never ends it, and a `git-remote-http` left behind by a kill of git alone keeps
    receiving). The call is refused within the timeout, and nothing is left running: no
    git, no `git-remote-http` in the clone or naming the forge's URL. A route that need not
    reach git (`finish-lookup`, `deliver-push`) and does not completes normally instead."""
    tenant, server = http_repo[0], http_repo[3]
    call, stall, required = _stalled_route(http_repo, tmp_path, route, trickle=trickle)
    started = time.monotonic()
    try:
        result, error = None, None
        try:
            result = call()
        except target().DeliveryRefused as refused:
            error = refused
        elapsed = time.monotonic() - started
        reached = stall.reached.is_set()
        left = _left(tenant, server)
    finally:
        stall.release()
    if reached or required:
        assert reached, f"{route} never reached the stalled forge"
        assert error is not None, f"{route} was not refused by the stalled forge: {result!r}"
    else:
        assert error is None, f"{route} was refused, though it never reached git: {error}"
    assert left == [], f"a process outlived the timed-out call: {left}"
    assert elapsed < _TIMEOUT + _SLACK, f"{route} took {elapsed:.1f} s against a {_TIMEOUT} s timeout"


class _Fault(Exception):
    """An exception raised into the call while git waits on the forge."""


class _Interrupt(BaseException):
    """An interrupt (a `BaseException`, as `KeyboardInterrupt` is) raised into the call while
    git waits on the forge. Not `KeyboardInterrupt` itself, which would end the session."""


@pytest.mark.parametrize("raised", [_Fault, _Interrupt], ids=["exception", "interrupt"])
@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_an_exception_or_interrupt_during_network_git_leaves_no_process(http_repo, tmp_path, route, raised):
    """R8: while the route's network git waits on the forge, a signal handler raises an
    exception, or an interrupt, into the call in the main thread. It leaves the call (an
    exception may come out as `DeliveryRefused`), and nothing is left running: the process
    group was killed on the way out. A route that need not reach git and does not completes
    normally instead."""
    tenant, server = http_repo[0], http_repo[3]

    def handler(signum, frame):
        raise raised("raised while git waited on the forge")
    previous = signal.signal(signal.SIGUSR1, handler)
    try:
        call, stall, required = _stalled_route(
            http_repo, tmp_path, route,
            then=lambda: signal.pthread_kill(threading.main_thread().ident, signal.SIGUSR1))
        expected = (raised,) if raised is _Interrupt else (raised, target().DeliveryRefused)
        try:
            error = None
            try:
                call()
            except expected as caught:
                error = caught
            reached = stall.reached.is_set()
            left = _left(tenant, server)
        finally:
            stall.release()
    finally:
        signal.signal(signal.SIGUSR1, previous)
    if reached or required:
        assert reached, f"{route} never reached the stalled forge"
        assert error is not None, f"{route} came back as if nothing was raised"
    else:
        assert error is None, error
    assert left == [], f"a process outlived the call: {left}"


def test_network_git_has_a_finite_wall_timeout_by_default(repo):
    """R8 / C4 (orchestrator ruling): a production drain, which passes no `network_timeout`,
    still has a wall timeout: the module exports `NETWORK_TIMEOUT`, a finite number of
    seconds above zero, and a delivery opened without the argument uses it
    (`.network_timeout`); one opened with it uses what it was given."""
    mod = target()
    default = mod.NETWORK_TIMEOUT
    assert isinstance(default, (int, float)), default
    assert not isinstance(default, bool), default
    assert math.isfinite(default), default
    assert default > 0, default
    assert delivery(repo, ForgeHTTP()).network_timeout == default
    assert delivery(repo, ForgeHTTP(), network_timeout=_TIMEOUT).network_timeout == _TIMEOUT
