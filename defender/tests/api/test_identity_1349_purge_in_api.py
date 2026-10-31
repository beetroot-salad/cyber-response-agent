"""#1349: the API's own background loop removes the sessions sign-in refuses (expired, or idle
past the limit): at start, then once per `PURGE_INTERVAL` on the service's clock, never on every
send pass. A failing or stuck purge and a failing send pass do not stop each other."""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import time

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.identity.service import PURGE_INTERVAL, SESSION_IDLE_LIMIT  # noqa: E402
from defender.tests.support.api._identity1306 import ANN, NEW, T1, World, wait_until  # noqa: E402

INTERVAL = _dt.timedelta(milliseconds=50)
SECOND = _dt.timedelta(seconds=1)


def _session(world: World, value: str, expires_in: _dt.timedelta, *, seen_ago: _dt.timedelta = _dt.timedelta()) -> None:
    user = world.call(world.repo.user_by_email, ANN)
    now = world.clock()
    world.call(world.repo.add_session, value, user.id, now=now - seen_ago, expires_at=now + expires_in)


def _held(world: World, value: str) -> bool:
    return world.call(world.repo.session_by_value, value) is not None


def _counting_passes(world: World) -> list[int]:
    """A counter of finished send passes: the hook runs after each pass's last claim. A hook runs
    once, so it re-arms itself."""
    passes = [0]

    async def counted() -> None:
        passes[0] += 1
        world.repo.after["claim_notification"] = counted
    world.repo.after["claim_notification"] = counted
    return passes


def test_the_api_removes_expired_sessions_when_it_starts_and_keeps_live_ones() -> None:
    world = World(tenants={T1: [ANN]}, send_interval=INTERVAL)
    _session(world, "old", -SECOND)
    _session(world, "live", _dt.timedelta(hours=1))
    with world.lifespan_client():
        assert wait_until(lambda: not _held(world, "old"))
        assert _held(world, "live")


def test_the_api_also_removes_sessions_idle_past_the_limit_and_logs_how_many_went(caplog: pytest.LogCaptureFixture) -> None:
    world = World(tenants={T1: [ANN]}, send_interval=INTERVAL)
    _session(world, "idle", _dt.timedelta(days=1), seen_ago=SESSION_IDLE_LIMIT + SECOND)
    _session(world, "recent", _dt.timedelta(days=1), seen_ago=SESSION_IDLE_LIMIT - SECOND)
    _session(world, "old", -SECOND)
    with caplog.at_level(logging.INFO, logger="defender.identity.service"), world.lifespan_client():
        assert wait_until(lambda: not _held(world, "idle"))
        assert _held(world, "recent")
        assert wait_until(lambda: any("purged 2" in r.getMessage() for r in caplog.records))


def test_a_stuck_purge_is_cut_off_logged_and_neither_stops_the_sending_nor_holds_up_shutdown(
        caplog: pytest.LogCaptureFixture) -> None:
    world = World(tenants={T1: [ANN]}, start=False, send_interval=INTERVAL, failing_writes=True)
    world.service.purge_deadline = _dt.timedelta(milliseconds=200)
    stuck = [0]

    async def hang() -> None:  # long past the deadline and the waits below, but finite: no deadline fails, not hangs
        stuck[0] += 1
        await asyncio.sleep(8)
    world.repo.after["purge_expired_sessions"] = hang
    with caplog.at_level(logging.ERROR), world.lifespan_client() as browser:
        assert wait_until(lambda: stuck[0] == 1)
        world.sign_in(ANN, browser=browser)
        assert world.invite(browser, T1, NEW).status_code == 202
        assert wait_until(lambda: world.signin.sends_to(NEW) == 1)
        world.repo.after["purge_expired_sessions"] = hang
        world.clock.advance(PURGE_INTERVAL)
        assert wait_until(lambda: stuck[0] == 2)
        leaving = time.monotonic()
    assert time.monotonic() - leaving < 2
    assert any("purge" in r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR)


def test_the_next_purge_waits_for_the_purge_interval_on_the_clock_not_the_next_send_pass() -> None:
    world = World(tenants={T1: [ANN]}, send_interval=INTERVAL, failing_writes=True)
    passes = _counting_passes(world)
    with world.lifespan_client():
        assert wait_until(lambda: passes[0] >= 1)
        _session(world, "soon", _dt.timedelta(minutes=1))
        world.clock.advance(_dt.timedelta(minutes=2))
        seen = passes[0]
        assert wait_until(lambda: passes[0] >= seen + 3)
        assert _held(world, "soon")  # expired, but no purge is due yet
        world.clock.advance(PURGE_INTERVAL)
        assert wait_until(lambda: not _held(world, "soon"))


def test_a_failing_purge_is_logged_and_does_not_stop_the_sending(caplog: pytest.LogCaptureFixture) -> None:
    world = World(tenants={T1: [ANN]}, start=False, send_interval=INTERVAL, failing_writes=True)
    world.repo.failing.add("purge_expired_sessions")
    with caplog.at_level(logging.ERROR), world.lifespan_client() as browser:
        assert wait_until(lambda: world.repo.refusals.get("purge_expired_sessions", 0) >= 1)
        world.sign_in(ANN, browser=browser)
        assert world.invite(browser, T1, NEW).status_code == 202  # made after the failed purge
        assert wait_until(lambda: world.signin.sends_to(NEW) == 1)
    assert any("purge" in r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR)


def test_a_failing_send_pass_does_not_stop_the_purge() -> None:
    world = World(tenants={T1: [ANN]}, send_interval=INTERVAL, failing_writes=True)
    _session(world, "old", -SECOND)
    world.repo.failing.add("claim_set_password")
    with world.lifespan_client():
        assert wait_until(lambda: world.repo.refusals.get("claim_set_password", 0) >= 1)
        assert wait_until(lambda: not _held(world, "old"))
