"""#1592 OD-12: the worker works only in polls where it holds its lock (S2-26..29). The worker's reaction is tested over a
tenants object whose `people_lock` answers a scripted bool; the standby, crash and takeover cases run on PostgreSQL.
Postgres-marked."""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import logging
import random

import pytest

from defender.tests.tenancy.people_1592._sessions1592 import MINUTE, sessions  # noqa: F401 — overrides the fixture
from defender.tests.tenancy.people_1592._spec1592 import (
    end_backend,
    login_of,
    org_of,
    people_lock_held_elsewhere,
    people_lock_namespace,
    session_key,
    sessions_port,
    signed_in_data,
)
from defender.tests.tenancy.people_1592._worker1592 import (
    CountingSessions,
    ScriptedLock,
    errors,
    settled,
    until,
    use,
)
from defender.tests.tenancy.people_1592._world1592 import U2, T, People

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
    assert len(errors(caplog)) == 1, "the log since setup holds more than the one standby error"


def _held_sequence(seed: int, length: int = 14) -> list[bool]:
    """A seeded held/not-held sequence whose first answer alternates with the seed, so both starts are covered."""
    rng = random.Random(seed)
    return [seed % 2 == 0, *(rng.random() < 0.5 for _ in range(length - 1))]


@pytest.mark.parametrize("seed", range(8))
async def test_the_worker_logs_one_error_per_change_the_first_poll_included_and_none_on_an_unchanged_poll(
        people: People, caplog, seed: int):
    """S2-26b (OD-12, r15.2 "The worker's lock"): over a scripted lock, poll one logs one error (a take, or `standby`), a
    later change logs one (`lost the people lock` on a loss), and a poll with no change logs none."""
    await people.tenant(T)
    await settled(people)
    script = ScriptedLock(people.tenants)
    use(people, tenants=script)
    previous: bool | None = None
    for polled, held in enumerate(_held_sequence(seed)):
        script.held = held
        before = len(errors(caplog))
        await people.step()
        new = errors(caplog)[before:]
        where = f"seed {seed}, poll {polled} ({previous} -> {held}): {new}"
        if previous is not None and held == previous:
            assert new == [], f"an error on an unchanged poll, {where}"
            continue
        assert len(new) == 1, f"one error per change, {where}"
        if not held:
            assert ("standby" if previous is None else "lost the people lock") in new[0].lower(), where
        previous = held


class LockUnanswered(Exception):
    """The scripted lock's failure: the database could not be asked (not a driver error the port maps to False)."""


#: Every way a held lock stops being held (OD-12): the port answers False, the port raises, the holder's backend ends.
LOSSES = ("answers-false", "raises", "backend-ends")


@pytest.fixture(params=LOSSES)
def loss_world(request) -> tuple[str, People]:
    """The loss, with its world: the scripted lock over the memory twins, or a real hold on PostgreSQL."""
    return request.param, request.getfixturevalue("pg_people" if request.param == "backend-ends" else "people")


async def test_a_lock_lost_with_a_run_and_an_expansion_in_flight_cancels_them_and_deletes_no_ids_then_resumes(
        loss_world: tuple[str, People], caplog):
    """S2-27 (OD-12): however the hold ends, after the losing poll every task the worker started is cancelled, no forge
    or sessions call begins, no id is deleted and nothing starts while not held; an error names the lock; on regaining
    it the requests are carried out. Calls in flight at the loss may still land (OD-7's residual): not asserted."""
    loss, people = loss_world
    bob = await _bob(people)
    await people.tenant(U2)  # a (none, U2) request: an expansion to gate in its team lookup
    script = None if loss == "backend-ends" else ScriptedLock(people.tenants, held=True)
    counting = CountingSessions(sessions_port(people.sessions.dsn))
    worker = use(people, tenants=script, sessions=counting)
    path = f"/api/v1/users/{login_of(str(bob.id))}"
    search = f"/api/v1/orgs/{org_of(U2)}/teams/search"
    first, lookup = people.forge.gate("GET", path), people.forge.gate("GET", search)
    await worker.poll()
    assert await until(lambda: f"GET {path}" in people.forge.arrived), "control: the run is in flight"
    assert await until(lambda: f"GET {search}" in people.forge.arrived), "control: the expansion is in flight"
    second = people.forge.gate("GET", path)
    before = len(errors(caplog))
    with contextlib.ExitStack() as held_elsewhere:
        if loss == "backend-ends":
            (old,) = holders(people.dsn)
            end_backend(people.dsn, old)  # the lock is free: the losing poll must answer not held all the same
        else:
            assert script is not None
            script.held = False if loss == "answers-false" else LockUnanswered("the database could not be asked")
        try:
            await worker.poll()  # the losing poll
            if loss == "backend-ends":
                held_elsewhere.enter_context(people_lock_held_elsewhere(people.dsn))  # not held at every later poll
            arrived, sessions_calls = len(people.forge.arrived), dict(counting.calls)
            try:
                await asyncio.wait_for(worker.settle(), 2)  # the gates are shut: only cancelled tasks are done
            except TimeoutError:
                pytest.fail(f"{loss}: a task the worker started was not cancelled when the lock was lost")
            first.set()
            lookup.set()
            await asyncio.sleep(0.2)
            for _ in range(2):  # later polls while not held, the cap job due at each
                people.clock.advance(2 * MINUTE)
                await worker.poll()
                await asyncio.wait_for(worker.settle(), 5)
            assert people.forge.arrived[arrived:] == [], f"{loss}: forge calls began after the loss"
            assert counting.calls == sessions_calls, f"{loss}: sessions calls began after the loss"
            open_now = await people.open_requests()
            assert (str(bob.id), T) in open_now, "a run that lost the lock deleted its ids"
            assert (None, U2) in open_now, "an expansion that lost the lock deleted the tenant request"
            assert not [p for p in open_now if p[0] is not None and p[1] == U2], "an expansion recorded after the loss"
            assert len(errors(caplog)) > before
            assert any("lock" in m.lower() for m in errors(caplog)[before:])
        finally:
            second.set()
            first.set()
            lookup.set()
    if script is not None:
        script.held = True
    await people.steps(2 if script is not None else 3)

    assert login_of(str(bob.id)) not in people.forge.members(T)
    assert await people.open_requests() == []
    if loss == "backend-ends":
        assert len(holders(people.dsn)) == 1
        assert holders(people.dsn) != [old]


async def test_a_standby_worker_on_postgres_logs_once_and_calls_nothing(pg_people: People, caplog):
    """S2-26: another session holds the lock: no call, the request stays, one standby error over three polls."""
    caplog.set_level(logging.INFO)
    bob = await _bob(pg_people)
    with people_lock_held_elsewhere(pg_people.dsn):
        await pg_people.steps(3)

    assert pg_people.forge.arrived == []
    assert (str(bob.id), T) in await pg_people.open_requests()
    assert len([m for m in errors(caplog) if "standby" in m.lower()]) == 1


async def test_a_second_worker_takes_over_when_the_first_holders_backend_ends(pg_people: People):
    """S2-28: the standby does nothing while the first holds; after the holder's crash it carries the request out."""
    await pg_people.tenant(T)
    bob = await pg_people.person("bob@x.org", T)
    await settled(pg_people)  # the setup worker over its own repository, closed: the lock is free
    await pg_people.step()  # the world's worker takes the lock (nothing to carry out yet)
    (held,) = holders(pg_people.dsn)
    await pg_people.end(bob, T)  # a request the standby could carry out
    standby = pg_people.build()  # a second process: a repository of its own
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
