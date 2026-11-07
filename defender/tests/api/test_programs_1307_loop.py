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
    assert any(("purge" in r.getMessage().lower() or "reconcil" in r.getMessage().lower())
               for r in caplog.records if r.levelno >= logging.ERROR)
