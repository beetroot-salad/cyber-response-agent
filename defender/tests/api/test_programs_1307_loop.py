"""#1307 O6, D3: the API's own background loop runs the realm reconciliation (at start, then once per
`PURGE_INTERVAL` on the service's clock), and a failing listing stops neither the sending nor the session purge."""
from __future__ import annotations

import datetime as _dt
import logging

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

from defender.identity import SignInUnavailable  # noqa: E402
from defender.identity.service import PURGE_INTERVAL  # noqa: E402
from defender.tests.support.api._identity1306 import ANN, NEW, T1, wait_until  # noqa: E402
from defender.tests.support.api._programs1307 import (  # noqa: E402
    Client,
    ProgramsWorld,
    create_program,
    issue_oauth,
)

INTERVAL = _dt.timedelta(milliseconds=50)
ORPHAN = "00000000-0000-4000-8000-0000000000aa"  # a program client no credential row names


def _orphan(world: ProgramsWorld) -> None:
    world.realm.clients[ORPHAN] = Client(ORPHAN, "00000000-5a00-4000-8000-0000000000aa", "kc-secret-orphan")


def _world() -> tuple[ProgramsWorld, str]:
    """T1 with admin ann, one program holding a live OAuth credential (returns its client id)."""
    world = ProgramsWorld(tenants={T1: [ANN]}, send_interval=INTERVAL)
    ann = world.sign_in(ANN)
    return world, issue_oauth(ann, T1, str(create_program(ann, T1)["id"]))


def test_the_api_deletes_a_client_without_a_credential_when_it_starts_and_keeps_a_live_ones() -> None:
    """The started API reconciles the programs realm (O6, D3)."""
    world, live = _world()
    _orphan(world)
    with world.lifespan_client():
        assert wait_until(lambda: ORPHAN not in world.realm.clients)
        assert world.realm.deleted == [ORPHAN]
    assert live in world.realm.clients


def test_the_next_reconciliation_waits_for_the_purge_interval_on_the_clock() -> None:
    """A client orphaned after start survives until the clock passes `PURGE_INTERVAL` (D3: the purge tick)."""
    world, live = _world()
    with world.lifespan_client():
        assert wait_until(lambda: world.realm.list_calls >= 1)
        _orphan(world)
        world.clock.advance(PURGE_INTERVAL / 2)
        seen = world.realm.list_calls
        assert not wait_until(lambda: world.realm.list_calls > seen, seconds=0.5)  # no reconciliation is due
        assert ORPHAN in world.realm.clients
        world.clock.advance(PURGE_INTERVAL)
        assert wait_until(lambda: ORPHAN not in world.realm.clients)
        assert live in world.realm.clients


def test_a_realm_that_cannot_be_listed_stops_neither_the_sending_nor_the_session_purge(
        caplog: pytest.LogCaptureFixture) -> None:
    """Keycloak down at the listing is logged; invitations still go out and expired sessions still go (D3)."""
    world, _ = _world()
    world.realm.fail_lists = 10_000
    user = world.call(world.repo.user_by_email, ANN)
    now = world.clock()
    world.call(world.repo.add_session, "old", user.id, now=now - _dt.timedelta(days=2),
               expires_at=now - _dt.timedelta(seconds=1))
    with caplog.at_level(logging.ERROR), world.lifespan_client() as browser:
        assert wait_until(lambda: world.realm.list_calls >= 1)
        world.sign_in(ANN, browser=browser)
        assert world.invite(browser, T1, NEW).status_code == 202
        assert wait_until(lambda: world.signin.sends_to(NEW) == 1)
        assert wait_until(lambda: world.call(world.repo.session_by_value, "old") is None)
    assert any(r.exc_info and isinstance(r.exc_info[1], SignInUnavailable)
               for r in caplog.records if r.levelno >= logging.ERROR)


@pytest.mark.parametrize("failing", ["session-purge", "reconciliation"])
def test_each_purge_tick_job_runs_when_the_other_fails_and_the_failed_one_waits_a_full_interval(
        failing: str, caplog: pytest.LogCaptureFixture) -> None:
    """The purge tick runs the session purge and the realm reconciliation as independent jobs (A9, D3): when either one fails
    the other still runs in that tick, and the failed one is retried at the next purge tick (`PURGE_INTERVAL` on the clock),
    not on the next send pass."""
    world = ProgramsWorld(tenants={T1: [ANN]}, send_interval=INTERVAL, failing_writes=True)
    ann = world.sign_in(ANN)
    live = issue_oauth(ann, T1, str(create_program(ann, T1)["id"]))
    user = world.call(world.repo.user_by_email, ANN)
    now = world.clock()
    _orphan(world)
    world.call(world.repo.add_session, "old", user.id, now=now - _dt.timedelta(days=2), expires_at=now - _dt.timedelta(seconds=1))

    def attempts() -> int:
        return world.repo.refusals.get("purge_expired_sessions", 0) if failing == "session-purge" else world.realm.list_calls

    if failing == "session-purge":
        world.repo.failing = {"purge_expired_sessions"}
    else:
        world.realm.fail_lists = 10_000

    def other_ran() -> bool:  # the job that is not failing: it has done its work for this tick
        if failing == "session-purge":
            return ORPHAN not in world.realm.clients
        return world.call(world.repo.session_by_value, "old") is None

    def other_ran_again() -> bool:
        if failing == "session-purge":
            return ORPHAN not in world.realm.clients
        return world.call(world.repo.session_by_value, "old-2") is None

    with caplog.at_level(logging.ERROR), world.lifespan_client():
        assert wait_until(lambda: attempts() >= 1 and other_ran())  # first tick: both jobs were tried
        tried = attempts()
        world.clock.advance(PURGE_INTERVAL / 2)  # the send passes keep coming; the retry is not due
        assert not wait_until(lambda: attempts() > tried, seconds=0.5)
        if failing == "session-purge":
            _orphan(world)  # a second orphan, to see the reconciliation go on running at the next tick
        else:
            world.call(world.repo.add_session, "old-2", user.id, now=now - _dt.timedelta(days=2),
                       expires_at=now - _dt.timedelta(seconds=1))
        world.clock.advance(PURGE_INTERVAL)  # the next purge tick
        assert wait_until(lambda: attempts() > tried)  # the failed job is tried again, once the tick is due
        assert wait_until(other_ran_again)  # and the job that works did its work again at that tick
    assert live in world.realm.clients
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR and r.exc_info]
    assert errors, "the failure was not logged"
