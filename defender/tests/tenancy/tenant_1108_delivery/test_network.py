from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import math
import signal
import threading
import time

import pytest

from ._revert_store import claimed_batch, reviewed, revert_with
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
    return quiet(location_path(tenant.tenant_root), naming=(server.url,), seconds=1.0)


_ROUTES = {
    "publish-fetch": ("git-upload-pack", True),
    "start_batch-fetch": ("git-upload-pack", True),
    "finish-lookup": ("git-upload-pack", False),
    "finish-push": ("git-receive-pack", True),
    "refinish-push": ("git-receive-pack", False),
    "revert-fetch": ("git-upload-pack", True),
    "revert-push": ("git-receive-pack", True),
}


#: The revert routes need the learning store (postgres); the rest need no database.
_ROUTE_PARAMS = [pytest.param(route, marks=pytest.mark.postgres) if route.startswith("revert") else route
                 for route in sorted(_ROUTES)]


def _store_for(route, request):
    return request.getfixturevalue("http_store") if route.startswith("revert") else None


def _claimed(d, tag, recorded=None):
    """A batch with one commit; `recorded` is `(repo, store)` to claim it in the learning store (a revert route)."""
    batch, held = claimed_batch(recorded[0], recorded[1], d, tag) if recorded else (d.start_batch(tag, lanes=LANES), None)
    (batch.draft_root / f"agent/lessons/{tag}.md").write_text("a lesson\n", encoding="utf-8")
    batch.commit(batch.change_set(), "claim")
    return (batch, held) if recorded else batch


def _stalled_route(http_repo, tmp_path, route, then=None, trickle=False, store=None):
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
    elif route == "refinish-push":
        batch = _claimed(d, "stalled")
        http.fail_create = True
        with pytest.raises(target().DeliveryRefused):
            d.finish(batch)
        http.fail_create = False

        def call():
            return d.finish(batch)
    else:
        batch, held = _claimed(d, "stalled", (http_repo, store))
        finished = d.finish(batch)
        opened(finished)
        reviewed(store, held, finished)
        merge_on_remote(http_repo, tmp_path, batch.branch)

        def call():
            return revert_with(d, store, "agent/lessons/stalled.md", "stalled")
    stall = _Stall(service, then, trickle)
    server.rearm()
    server.on_service = stall
    return call, stall, required


@pytest.mark.parametrize("trickle", [False, True], ids=["silent", "trickle"])
@pytest.mark.parametrize("route", _ROUTE_PARAMS)
def test_a_stalled_forge_fails_within_the_timeout_and_leaves_no_process(http_repo, tmp_path, route, trickle, request):
    tenant, server = http_repo[0], http_repo[3]
    call, stall, required = _stalled_route(http_repo, tmp_path, route, trickle=trickle, store=_store_for(route, request))
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
@pytest.mark.parametrize("route", _ROUTE_PARAMS)
def test_an_exception_or_interrupt_during_network_git_leaves_no_process(http_repo, tmp_path, route, raised, request):
    tenant, server = http_repo[0], http_repo[3]

    def handler(signum, frame):
        raise raised("raised while git waited on the forge")
    previous = signal.signal(signal.SIGUSR1, handler)
    try:
        call, stall, required = _stalled_route(
            http_repo, tmp_path, route, store=_store_for(route, request),
            then=lambda: signal.pthread_kill(threading.main_thread().ident, signal.SIGUSR1),
            trickle=True)
        expected = (raised,) if raised is _Interrupt else (raised, target().DeliveryRefused)
        started = time.monotonic()
        try:
            error = None
            try:
                call()
            except expected as caught:
                error = caught
            elapsed = time.monotonic() - started
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
    assert elapsed < _TIMEOUT + _SLACK, f"{route} took {elapsed:.1f} s to propagate the exception"


def test_network_git_has_a_finite_wall_timeout_by_default(repo):
    mod = target()
    default = mod.NETWORK_TIMEOUT
    assert isinstance(default, (int, float)), default
    assert not isinstance(default, bool), default
    assert math.isfinite(default), default
    assert default > 0, default
    assert delivery(repo, ForgeHTTP()).network_timeout == default
    assert delivery(repo, ForgeHTTP(), network_timeout=_TIMEOUT).network_timeout == _TIMEOUT
