"""#1592 OD-12: the worker works only in polls where it holds its lock (S2-26..29). The worker's reaction is tested over a
tenants object whose `people_lock` answers a scripted bool; the standby, crash and takeover cases run on PostgreSQL.
Postgres-marked."""
from __future__ import annotations

import asyncio
import datetime as dt
import logging

import pytest

from defender.tests.tenancy.people_1592._sessions1592 import MINUTE, sessions  # noqa: F401 — overrides the fixture
from defender.tests.tenancy.people_1592._spec1592 import (
    end_backend,
    login_of,
    people_lock_held_elsewhere,
    people_lock_namespace,
    session_key,
    signed_in_data,
)
from defender.tests.tenancy.people_1592._worker1592 import ScriptedLock, errors, settled, until, use
from defender.tests.tenancy.people_1592._world1592 import T, People

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


def holders(dsn: str) -> list[int]:
    """Backends holding the lock in THIS database (the package helper counts every database on the server)."""
    from defender.tests.support.shared._postgres1339 import execute

    return [p for (p,) in execute(dsn, """SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted
        AND classid = %s AND objid = 0 AND objsubid = 2
        AND database = (SELECT oid FROM pg_database WHERE datname = current_database())""", (people_lock_namespace(),))]


async def _bob(people: People):
    await people.tenant(T)
    bob = await people.person("bob@x.org", T)
    await settled(people)
    await people.end(bob, T)
    return bob


def _standby_case(people: People, caplog) -> None:
    caplog.set_level(logging.INFO)
    people.sessions.plant("old", signed_in_data(2), signed_in_at=dt.datetime.now(dt.UTC) - 120 * MINUTE)


async def test_without_the_lock_the_worker_does_nothing_and_logs_one_standby_error(people: People, caplog):
    """S2-26 (scripted): no Forgejo call, the request stays, the cap job does not run, one error names the standby."""
    bob = await _bob(people)
    _standby_case(people, caplog)
    script = ScriptedLock(people.tenants, held=False)
    use(people, tenants=script)

    for _ in range(3):
        people.clock.advance(2 * MINUTE)
        await people.step()

    assert people.forge.arrived == []
    assert (str(bob.id), T) in await people.open_requests()
    assert session_key("old") in people.sessions.keys(), "the cap job ran without the lock"  # noqa: SIM118 — a method
    standby = [m for m in errors(caplog) if "standby" in m.lower()]
    assert len(standby) == 1
    assert len(errors(caplog)) == 1


async def test_a_lock_lost_with_a_run_in_flight_cancels_it_and_deletes_no_ids_then_resumes(people: People, caplog):
    """S2-27 (scripted): the lock goes; the gated run's ids survive its release; an error is logged; on regaining it the
    request is carried out."""
    bob = await _bob(people)
    script = ScriptedLock(people.tenants, held=True)
    worker = use(people, tenants=script)
    path = f"/api/v1/users/{login_of(str(bob.id))}"
    first = people.forge.gate("GET", path)
    await worker.poll()
    assert await until(lambda: f"GET {path}" in people.forge.arrived)
    second = people.forge.gate("GET", path)
    before = len(errors(caplog))
    script.held = False
    try:
        await worker.poll()
        first.set()
        await asyncio.sleep(0.2)
        assert (str(bob.id), T) in await people.open_requests(), "a run that lost the lock deleted its ids"
        assert len(errors(caplog)) > before
        assert any("lock" in m.lower() for m in errors(caplog)[before:])
    finally:
        second.set()
    script.held = True
    await people.steps(2)

    assert login_of(str(bob.id)) not in people.forge.members(T)
    assert await people.open_requests() == []


async def test_a_standby_worker_on_postgres_logs_once_and_calls_nothing(pg_people: People, caplog):
    """S2-26: another session holds the lock: no call, the request stays, one standby error over three polls."""
    caplog.set_level(logging.INFO)
    bob = await _bob(pg_people)
    with people_lock_held_elsewhere(pg_people.dsn):
        await pg_people.steps(3)

    assert pg_people.forge.arrived == []
    assert (str(bob.id), T) in await pg_people.open_requests()
    assert len([m for m in errors(caplog) if "standby" in m.lower()]) == 1


async def test_a_holder_whose_backend_ends_loses_its_run_ids_and_the_lock_is_regained(pg_people: People, caplog):
    """S2-27: a crash of the holder's connection mid-run: ids kept, an error logged, the lock regained at a later poll."""
    bob = await _bob(pg_people)
    path = f"/api/v1/users/{login_of(str(bob.id))}"
    first = pg_people.forge.gate("GET", path)
    worker = use(pg_people)
    await worker.poll()
    assert await until(lambda: f"GET {path}" in pg_people.forge.arrived)
    (old,) = holders(pg_people.dsn)
    second = pg_people.forge.gate("GET", path)
    before = len(errors(caplog))
    end_backend(pg_people.dsn, old)
    try:
        await worker.poll()
        first.set()
        await asyncio.sleep(0.2)
        assert (str(bob.id), T) in await pg_people.open_requests(), "the run deleted its ids after the loss"
        assert len(errors(caplog)) > before
    finally:
        second.set()
    await pg_people.steps(3)

    assert await pg_people.open_requests() == []
    assert len(holders(pg_people.dsn)) == 1
    assert holders(pg_people.dsn) != [old]


async def test_a_second_worker_takes_over_when_the_first_holders_backend_ends(pg_people: People):
    """S2-28: the standby does nothing while the first holds; after the holder's crash it carries the request out."""
    bob = await _bob(pg_people)  # settled by the world's own worker, which now holds the lock
    (held,) = holders(pg_people.dsn)
    standby = pg_people.build()
    await settled_one(standby, pg_people)
    assert (str(bob.id), T) in await pg_people.open_requests(), "the standby acted while the lock was held"
    end_backend(pg_people.dsn, held)

    await settled_one(standby, pg_people)

    assert await pg_people.open_requests() == []
    taken = holders(pg_people.dsn)
    assert len(taken) == 1
    assert taken != [held]


async def settled_one(worker, people: People) -> None:
    await worker.poll()
    await asyncio.wait_for(worker.settle(), 5)


async def test_people_lock_takes_confirms_and_answers_held_elsewhere(pg_people: People):
    """S2-29: True, True on the same store; another store on the same database answers False until the holder closes."""
    from defender.tenancy.postgres import PostgresTenantRepository

    first, second = PostgresTenantRepository(pg_people.dsn), PostgresTenantRepository(pg_people.dsn)
    try:
        assert await first.people_lock() is True
        assert await first.people_lock() is True
        assert len(holders(pg_people.dsn)) == 1
        assert await second.people_lock() is False
    finally:
        await first.close()
    try:
        assert await second.people_lock() is True
    finally:
        await second.close()


async def test_the_memory_twin_always_holds_its_lock():
    """S2-29: one store is one process."""
    from defender.tenancy import InMemoryTenantRepository

    twin = InMemoryTenantRepository()
    assert await twin.people_lock() is True
    assert await twin.people_lock() is True
