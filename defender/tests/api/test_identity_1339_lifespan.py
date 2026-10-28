"""#1339 the async identity service behind the API: the harness drives start and sends (O5), and the
lifespan's sender is a task on the app's loop that stops before the repository closes (O5, S-2)."""
from __future__ import annotations

import asyncio
import datetime as _dt
import inspect
import threading
import time
from typing import Any

import pytest

pytest.importorskip("fastapi")

# A forgotten `world.call` leaves a never-awaited coroutine; pytest reports its RuntimeWarning as an unraisable exception, so both are errors.
pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    NEW,
    T1,
    FakeSignIn,
    HOUR,
    World,
    wait_until,
)

INTERVAL = _dt.timedelta(milliseconds=50)


class RecordingRepository:
    """The repository with every awaited call recorded as (name, the loop it ran on)."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls: list[tuple[str, asyncio.AbstractEventLoop]] = []

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not inspect.iscoroutinefunction(attr):
            return attr

        async def recorded(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, asyncio.get_running_loop()))
            return await attr(*args, **kwargs)
        return recorded

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


class ClosingSignIn(FakeSignIn):
    """The sign-in fake with a `close` that records itself and how many port calls had happened by then."""

    def __init__(self) -> None:
        super().__init__()
        self.closes = 0
        self.calls_at_close = -1

    async def close(self) -> None:
        self.closes += 1
        self.calls_at_close = len(self.every_call)


def test_the_harness_runs_bootstrap_and_a_send_pass_and_the_api_serves_over_them() -> None:
    """World(start=True) awaits start and one sender pass; the person can then sign in through the API (O5)."""
    world = World(tenants={T1: [ANN]})
    assert world.signin.sends_to(ANN) == 1
    ann = world.sign_in(ANN)
    assert world.invite(ann, T1, NEW).status_code == 202
    assert world.signin.sends_to(NEW) == 0
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1


def test_the_lifespan_sender_runs_on_the_apps_loop_and_stops_before_the_repository_closes() -> None:
    """Start-up pass and later passes run as a task on the app's loop; shutdown is prompt and closes the repository last (O5, S-2)."""
    world = World(tenants={T1: [ANN]}, start=False, send_interval=INTERVAL)
    world.repo = RecordingRepository(world.repo)
    world.signin = ClosingSignIn()
    world.build(administrators=(), tenants={T1: [ANN]})
    with world.lifespan_client() as browser:
        assert wait_until(lambda: world.signin.sends_to(ANN) == 1)
        app_loop = browser.portal.call(asyncio.get_running_loop)
        assert wait_until(lambda: world.repo.names().count("claim_set_password") >= 3)  # periodic passes
        leaving = time.monotonic()
    assert time.monotonic() - leaving < 2
    assert {loop for _, loop in world.repo.calls} == {app_loop}
    names = world.repo.names()
    assert names.count("close") == 1, names[-5:]
    assert names[-1] == "close", names[-5:]
    assert world.signin.closes == 1  # the service closes its sign-in port too, once, after the last send
    assert world.signin.calls_at_close == len(world.signin.every_call)
    settled = len(names)
    time.sleep(3 * INTERVAL.total_seconds())
    assert len(world.repo.names()) == settled  # nothing ran after shutdown
    assert len(world.signin.every_call) == world.signin.calls_at_close


def test_shutdown_cancels_a_send_in_flight_promptly_and_closes_once_afterwards() -> None:
    """A send stuck at the provider does not hold shutdown past S-2's 2 s; close still runs once, last (O5, S-2)."""
    world = World(tenants={T1: [ANN]}, start=False, send_interval=INTERVAL)
    world.repo = RecordingRepository(world.repo)
    world.signin = ClosingSignIn()
    world.build(administrators=(), tenants={T1: [ANN]})
    inside: list[bool] = []
    sender_threads: list[threading.Thread] = []
    started_before = set(threading.enumerate())

    async def stuck_at_the_provider() -> None:
        inside.append(True)
        sender_threads.append(threading.current_thread())
        await asyncio.sleep(30)  # only cancellation ends it within the test's bound

    world.signin.during_send = stuck_at_the_provider
    with world.lifespan_client():
        assert wait_until(lambda: bool(inside)), "the start-up pass never reached the send"
        # S-2: the sender is a task on the harness's loop, not a thread the app started
        assert [t.name for t in sender_threads] == ["world-loop"]
        assert set(threading.enumerate()) - started_before == set()
        leaving = time.monotonic()
    assert time.monotonic() - leaving < 2
    names = world.repo.names()
    assert names.count("close") == 1, names[-5:]
    assert names[-1] == "close", names[-5:]
    assert world.signin.closes == 1
    settled = len(names)
    time.sleep(3 * INTERVAL.total_seconds())
    assert len(world.repo.names()) == settled  # the cancelled sender did not carry on


def test_the_bootstrap_finishes_before_the_lifespan_start_up_returns_and_before_any_send() -> None:
    """Entering the lifespan awaits the bootstrap: when it returns the file is applied, and no port was called yet (O5, DC-4)."""
    world = World(tenants={T1: [ANN]}, start=False, send_interval=HOUR, failing_writes=True)
    finished: list[bool] = []
    ports_seen: list[list[str]] = []

    async def slow_bootstrap_step() -> None:
        ports_seen.append(list(world.signin.every_call))
        await asyncio.sleep(0.3)
        finished.append(True)

    world.repo.after["register_tenant"] = slow_bootstrap_step
    with world.lifespan_client():
        assert finished == [True], "the lifespan started serving while the bootstrap was still running"
        assert world.call(world.repo.user_by_email, ANN) is not None
    assert ports_seen == [[]]
