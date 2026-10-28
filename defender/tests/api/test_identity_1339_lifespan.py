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

from defender.identity import SignInUnavailable  # noqa: E402
from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
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


def _leave_during_a_held_send(world: World, *, fails: bool = False) -> list[str]:
    """Run the lifespan; ask it to stop while the start-up pass's first set-password send is held at
    the provider (accepted there, not yet recorded), releasing the hold only after shutdown began.
    With `fails`, the held call then raises. Returns the hook's progress: 'held', then 'released'."""
    progress: list[str] = []
    release = threading.Event()
    sender_threads: list[threading.Thread] = []
    started_before = set(threading.enumerate())

    async def held_at_the_provider() -> None:
        progress.append("held")
        sender_threads.append(threading.current_thread())
        while not release.is_set():
            await asyncio.sleep(0.01)
        progress.append("released")
        world.repo.calls.append(("send released", asyncio.get_running_loop()))
        if fails:
            raise SignInUnavailable("the held send failed")

    world.signin.during_send = held_at_the_provider
    # Released 3 s after shutdown is asked for: past r3's 2 s, so an API that stops waiting at a
    # deadline of its own closes before the release. Armed in `finally` so a failing check above
    # fails the test instead of hanging it.
    with world.lifespan_client():
        try:
            assert wait_until(lambda: "held" in progress), "the start-up pass never reached the send"
            # S-2: the sender is a task on the harness's loop, not a thread the app started
            assert [t.name for t in sender_threads] == ["world-loop"]
            assert set(threading.enumerate()) - started_before == set()
        finally:
            threading.Timer(3.0, release.set).start()
    return progress


def _nothing_runs_after_shutdown(world: World) -> None:
    settled, sent = len(world.repo.names()), len(world.signin.every_call)
    time.sleep(3 * INTERVAL.total_seconds())
    assert len(world.repo.names()) == settled
    assert len(world.signin.every_call) == sent


def test_shutdown_during_a_send_lets_it_finish_and_be_recorded_so_it_is_not_sent_again() -> None:
    """Leaving mid-send waits for that email: it is recorded as sent, the service closes after it, and no later pass resends it (O8a, O8d)."""
    world = World(tenants={T1: [ANN]}, start=False, send_interval=INTERVAL)
    world.repo = RecordingRepository(world.repo)
    world.signin = ClosingSignIn()
    world.build(administrators=(), tenants={T1: [ANN]})
    assert _leave_during_a_held_send(world) == ["held", "released"]
    names = world.repo.names()
    assert names.index("send released") < names.index("settle_set_password") < names.index("close"), names
    assert names.count("close") == 1, names[-5:]
    assert names[-1] == "close", names[-5:]
    assert world.signin.closes == 1
    assert world.signin.calls_at_close == len(world.signin.every_call)
    _nothing_runs_after_shutdown(world)
    ann = world.call(world.repo.user_by_email, ANN)
    assert ann.set_password_sent_seq == ann.set_password_requested_seq
    assert ann.set_password_sent_at is not None
    world.clock.advance(HOUR)  # well past the claim hold
    world.send_pending()
    assert world.signin.sends_to(ANN) == 1


@pytest.mark.parametrize("outcome", ["sent", "failed", "repository_fails"])
def test_shutdown_during_a_send_claims_nothing_more_and_the_rest_stays_pending(outcome: str) -> None:
    """After shutdown is asked for, whether the email in flight went out, failed (deferred), or the repository raised, the sender claims nothing more; the rest stays sendable (O8b, O8d)."""
    world = World(tenants={T1: [ANN, BOB]}, start=False, send_interval=INTERVAL, failing_writes=True)
    failing = world.repo
    if outcome == "repository_fails":  # recording the email fails, and so does deferring it: the pass raises
        failing.failing |= {"settle_set_password", "defer_set_password"}
    world.repo = RecordingRepository(failing)
    world.signin = ClosingSignIn()
    world.build(administrators=(), tenants={T1: [ANN, BOB]})
    assert _leave_during_a_held_send(world, fails=outcome == "failed") == ["held", "released"]
    names = world.repo.names()
    settle = "settle_set_password" if outcome != "failed" else "defer_set_password"
    assert names.index("send released") < names.index(settle) < names.index("close"), names
    assert names.count("claim_set_password") == 1, names
    assert "claim_notification" not in names, names  # the notification loop did not start either
    assert names.count("close") == 1, names[-5:]
    assert names[-1] == "close", names[-5:]
    _nothing_runs_after_shutdown(world)
    assert len(world.signin.send_attempts) == 1
    failing.failing.clear()
    world.send_pending()  # control: BOB was pending and sendable all along
    assert world.signin.send_attempts[1:] == [world.signin.account_for(BOB)]


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
