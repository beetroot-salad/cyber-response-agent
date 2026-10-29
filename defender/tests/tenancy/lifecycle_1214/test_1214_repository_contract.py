"""#1214 tenant repository contract (r9 RC-3, DC-4): one suite over the in-memory twin and the PostgreSQL
repository. Requests are one conditional update each; reads are detached copies; values are Python-side.

RC-1's lock and fence belong to the job-model slice and are not asserted here. The PostgreSQL run is marked
`postgres` (needs DEFENDER_TEST_POSTGRES_DSN; CI fails rather than skips without it).
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._pglocks1339 import TIMEOUT, connections, until, until_blocked
from defender.tests.support.shared._postgres1339 import database, execute

pytestmark = pytest.mark.anyio

NOW = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.UTC)
SEEDED_AT = dt.datetime(2026, 9, 1, 8, 0, tzinfo=dt.UTC)
T1 = fixture_uuid("tenant:1214-repo-1")
T2 = fixture_uuid("tenant:1214-repo-2")
ABSENT = fixture_uuid("tenant:1214-repo-absent")
ORIGIN = "http://forge.test/tenants/t1.git"
ADOPT_FAILURE = "registered before #1214: adopt it"

#: A row to seed: (state, pending_action, step, step_actor, failure).
ACTIVE = ("active", None, None, None, None)
CREATING = ("creating", "create", "provider", "service", None)
CREATING_FAILED = ("creating", "create", "provider", "service", "forge answered 502: bad gateway")
UNADOPTED = ("creating", "create", "adopt", "service", ADOPT_FAILURE)
ROTATING = ("active", "rotate", "install", "host", None)
ROTATING_FAILED = ("active", "rotate", "retire", "service", "openbao answered 500")
OFFBOARDING = ("offboarding", "offboard", "teardown", "host", None)
OFFBOARDING_FAILED = ("offboarding", "offboard", "teardown", "host", "host folder busy")
OFFBOARDED = ("offboarded", None, None, None, None)
DELETING = ("offboarded", "delete_repo", "delete_repo", "service", None)
DELETING_FAILED = ("offboarded", "delete_repo", "delete_repo", "service", "forge answered 500")
ALL_ROWS = {
    "creating": CREATING, "creating-failed": CREATING_FAILED, "unadopted": UNADOPTED, "active": ACTIVE,
    "rotating": ROTATING, "rotating-failed": ROTATING_FAILED, "offboarding": OFFBOARDING,
    "offboarding-failed": OFFBOARDING_FAILED, "offboarded": OFFBOARDED, "deleting": DELETING,
    "deleting-failed": DELETING_FAILED}


class Store:
    """The repository under test plus the way to put a row into it that is NOT a request: the twin's seeder,
    or raw SQL. Neither implements the policy under test."""

    def __init__(self, repo: Any, dsn: str | None, twin: Any) -> None:
        self.repo, self.dsn, self.twin = repo, dsn, twin

    async def seed(self, tenant: str, row: tuple = ACTIVE, *, repo: str | None = None, origin: str | None = None) -> None:
        state, action, step, actor, failure = row
        if self.dsn is None:
            extra = {k: v for k, v in dict(pending_action=action, step=step, step_actor=actor, failure=failure,
                                           repo=repo, origin=origin).items() if v is not None}
            await self.twin.add_tenant(tenant, created_at=SEEDED_AT, state=state, **extra)
            return
        execute(self.dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor, failure)
                             VALUES (%s, %s, %s, %s, %s, %s, %s)""", (tenant, SEEDED_AT, state, action, step, actor, failure))
        if repo is not None:
            execute(self.dsn, "INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES (%s, %s, %s)",
                    (tenant, repo, origin or ORIGIN))


async def _build(dsn: str | None) -> tuple[Any, Any]:
    if dsn is None:
        from defender.tenancy import InMemoryTenantRepository

        twin: Any = InMemoryTenantRepository()
        return twin, twin
    from defender.tenancy.postgres import PostgresTenantRepository

    return None, PostgresTenantRepository(dsn)


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
async def store(request) -> AsyncIterator[Store]:
    """The repository under test on each twin; PostgreSQL gets a migrated database of this test's own."""
    with contextlib.ExitStack() as stack:
        dsn = None if request.param == "memory" else stack.enter_context(database(migrated=True))
        twin, repo = await _build(dsn)
        try:
            yield Store(repo, dsn, twin)
        finally:
            await repo.close()


@pytest.fixture
async def pg_store() -> AsyncIterator[Store]:
    """PostgreSQL only (the cases below use the database itself)."""
    with database(migrated=True) as dsn:
        twin, repo = await _build(dsn)
        try:
            yield Store(repo, dsn, twin)
        finally:
            await repo.close()


@pytest.fixture
async def twin_store() -> Store:
    twin, repo = await _build(None)
    return Store(repo, None, twin)


def _values(model: object) -> dict[str, object]:
    """Every field of a returned record, read now (a detached record with an unloaded field raises here)."""
    return {f.name: getattr(model, f.name) for f in dataclasses.fields(model)}  # type: ignore[arg-type]


def _job(record: Any) -> tuple:
    return (record.state, record.pending_action, record.step, record.step_actor, record.failure)


async def _refused(call: Any, kind: str) -> None:
    """The request raised the API's `Conflict` or `NotFound` (GAP-A-1: the defining module is the implementer's)."""
    with pytest.raises(Exception) as raised:  # noqa: PT011
        await call
    assert type(raised.value).__name__ == kind, repr(raised.value)


# --- the pinned names -------------------------------------------------------------------------------


def test_the_pinned_record_types_carry_the_pinned_fields():
    """The record, generation and wiring types expose the fields the pinned interface names (DC-4)."""
    from defender.tenancy import ForgeWiring, Generation, TenantRecord

    def names(cls: type) -> set[str]:
        return {f.name for f in dataclasses.fields(cls)}

    assert {"id", "created_at", "state", "pending_action", "step", "step_actor", "failure", "repo_url",
            "offboarded_at", "repo_delete_after"} <= names(TenantRecord)
    assert {"salt", "status", "bot_login", "oidc_role", "approle", "role_id", "entity", "audience",
            "host_secret_file", "secret_accessor"} <= names(Generation)
    assert {"repo", "origin"} <= names(ForgeWiring)


# --- request_create ---------------------------------------------------------------------------------


async def test_a_create_request_inserts_a_creating_tenant_at_the_names_step(store):
    """request_create stores a `creating` tenant, `create` pending, step `names`, actor `service`, no failure, at `now` (RC-3)."""
    record = await store.repo.request_create(now=NOW)
    assert uuid.UUID(record.id).version == 4
    assert _job(record) == ("creating", "create", "names", "service", None)
    assert (record.created_at, record.repo_url, record.offboarded_at, record.repo_delete_after) == (NOW, None, None, None)
    assert _values(await store.repo.tenant(record.id)) == _values(record)  # stored, not just returned
    assert await store.repo.generations(record.id) == []  # the pending generation is the names step's, not the request's


async def test_two_create_requests_are_two_tenants(store):
    """Each create mints its own id and adds a row; `tenants()` lists both (RC-3)."""
    first, second = await store.repo.request_create(now=NOW), await store.repo.request_create(now=NOW)
    assert first.id != second.id
    assert {t.id for t in await store.repo.tenants()} == {first.id, second.id}


async def test_tenants_lists_every_state_and_nothing_else(store):
    """`tenants()` returns one record per stored tenant in every state, none when empty (O1, DC-6)."""
    assert await store.repo.tenants() == []
    for number, row in enumerate(ALL_ROWS.values()):
        await store.seed(fixture_uuid(f"tenant:1214-all-{number}"), row)
    listed = await store.repo.tenants()
    assert {_job(t) for t in listed} == set(ALL_ROWS.values())
    assert len(listed) == len(ALL_ROWS)


# --- request_resume ---------------------------------------------------------------------------------

#: Rows with a failure the API may resume: resume clears the failure and nothing else.
RESUMABLE = ["creating-failed", "rotating-failed", "offboarding-failed", "deleting-failed"]


@pytest.mark.parametrize("name", RESUMABLE)
async def test_resume_clears_the_failure_and_nothing_else(store, name):
    """request_resume only clears `failure`: state, pending action, step and actor stay where the worker left them (RC-3, DC-4)."""
    await store.seed(T1, ALL_ROWS[name])
    await store.seed(T2, ALL_ROWS[name])
    before = _values(await store.repo.tenant(T1))
    record = await store.repo.request_resume(T1)
    assert record.failure is None
    assert _values(record) == {**before, "failure": None}
    assert _values(await store.repo.tenant(T1)) == _values(record)
    assert (await store.repo.tenant(T2)).failure == ALL_ROWS[name][4]  # another tenant's failure is not touched


@pytest.mark.parametrize("name", ["creating", "active", "rotating", "offboarding", "offboarded", "deleting"])
async def test_resume_with_no_failure_is_a_conflict_and_changes_nothing(store, name):
    """request_resume on a tenant with no failure is refused (409) and leaves the row as it was (RC-3)."""
    await store.seed(T1, ALL_ROWS[name])
    before = _values(await store.repo.tenant(T1))
    await _refused(store.repo.request_resume(T1), "Conflict")
    assert _values(await store.repo.tenant(T1)) == before


async def test_resume_at_adopt_is_a_conflict_only_adoption_clears(store):
    """A backfilled row at step `adopt` keeps its failure: resume is refused (O9, RC-3)."""
    await store.seed(T1, UNADOPTED)
    await _refused(store.repo.request_resume(T1), "Conflict")
    record = await store.repo.tenant(T1)
    assert (record.step, record.failure) == ("adopt", ADOPT_FAILURE)
    await store.seed(T2, CREATING_FAILED)  # control: the same state at another step resumes
    assert (await store.repo.request_resume(T2)).failure is None


async def test_a_second_resume_is_a_conflict(store):
    """Resume twice: the first clears, the second finds no failure and is refused (RC-3)."""
    await store.seed(T1, CREATING_FAILED)
    await store.repo.request_resume(T1)
    await _refused(store.repo.request_resume(T1), "Conflict")


# --- request_offboard -------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["creating", "creating-failed", "unadopted", "active", "rotating", "rotating-failed"])
async def test_offboard_from_creating_or_active_replaces_any_pending_action_and_clears_the_failure(store, name):
    """request_offboard from `creating`|`active` sets `offboarding`, `offboard` pending, first step `offboard` (service), no failure (RC-3, DC-3)."""
    await store.seed(T1, ALL_ROWS[name])
    await store.seed(T2, ALL_ROWS[name])
    before = _values(await store.repo.tenant(T1))
    record = await store.repo.request_offboard(T1, now=NOW)
    assert _job(record) == ("offboarding", "offboard", "offboard", "service", None)
    assert (record.id, record.created_at) == (T1, before["created_at"])
    assert _values(await store.repo.tenant(T1)) == _values(record)
    assert _job(await store.repo.tenant(T2)) == ALL_ROWS[name]  # only the addressed tenant


@pytest.mark.parametrize("name", ["offboarding", "offboarding-failed", "offboarded", "deleting"])
async def test_offboard_from_any_other_state_is_a_conflict_and_changes_nothing(store, name):
    """request_offboard is refused (409) unless the tenant is `creating` or `active`; the row stays (RC-3)."""
    await store.seed(T1, ALL_ROWS[name])
    before = _values(await store.repo.tenant(T1))
    await _refused(store.repo.request_offboard(T1, now=NOW), "Conflict")
    assert _values(await store.repo.tenant(T1)) == before


# --- request_rotate ---------------------------------------------------------------------------------


async def test_rotate_from_active_with_nothing_pending_starts_at_names(store):
    """request_rotate on an idle `active` tenant sets `rotate` pending, step `names`, actor `service`, state unchanged (RC-3)."""
    await store.seed(T1, ACTIVE)
    await store.seed(T2, ACTIVE)
    record = await store.repo.request_rotate(T1)
    assert _job(record) == ("active", "rotate", "names", "service", None)
    assert _values(await store.repo.tenant(T1)) == _values(record)
    assert _job(await store.repo.tenant(T2)) == ACTIVE


@pytest.mark.parametrize("name", ["rotating", "rotating-failed", "creating", "creating-failed", "unadopted",
                                  "offboarding", "offboarded", "deleting"])
async def test_rotate_unless_active_with_nothing_pending_is_a_conflict_and_changes_nothing(store, name):
    """request_rotate is refused (409) unless `active` with nothing pending, a failed rotation included (RC-3)."""
    await store.seed(T1, ALL_ROWS[name])
    before = _values(await store.repo.tenant(T1))
    await _refused(store.repo.request_rotate(T1), "Conflict")
    assert _values(await store.repo.tenant(T1)) == before


async def test_a_rotate_request_after_a_rotate_request_is_a_conflict(store):
    """Rotate twice in a row: the second finds the first pending (RC-3)."""
    await store.seed(T1, ACTIVE)
    await store.repo.request_rotate(T1)
    await _refused(store.repo.request_rotate(T1), "Conflict")


# --- unknown tenant, and requests after requests ----------------------------------------------------


@pytest.mark.parametrize("ask", ["request_resume", "request_rotate", "request_offboard"])
async def test_a_request_for_an_unknown_tenant_is_not_found_and_stores_nothing(store, ask):
    """Every request names its tenant; an absent one is NotFound (404), and the repository gains no row (RC-3)."""
    await store.seed(T1, ACTIVE)
    call = store.repo.request_offboard(ABSENT, now=NOW) if ask == "request_offboard" else getattr(store.repo, ask)(ABSENT)
    await _refused(call, "NotFound")
    assert [t.id for t in await store.repo.tenants()] == [T1]


async def test_requests_chain_through_the_lifecycle(store):
    """create -> (seeded active) rotate -> offboard -> rotate/offboard refused: each request sees the previous one's row (RC-3)."""
    await store.seed(T1, ACTIVE)
    await store.repo.request_rotate(T1)
    assert _job(await store.repo.request_offboard(T1, now=NOW))[:2] == ("offboarding", "offboard")
    await _refused(store.repo.request_rotate(T1), "Conflict")
    await _refused(store.repo.request_offboard(T1, now=NOW), "Conflict")
    await _refused(store.repo.request_resume(T1), "Conflict")


# --- reads ------------------------------------------------------------------------------------------


async def test_forge_wiring_is_the_recorded_repo_and_origin(store):
    """`forge_wiring` returns the recorded repo and origin (not derived), None for a tenant without wiring (Flow 4, DC-4)."""
    await store.seed(T1, ACTIVE, repo="tenants/playground", origin=ORIGIN)
    await store.seed(T2, ACTIVE)
    wiring = await store.repo.forge_wiring(T1)
    assert (wiring.repo, wiring.origin) == ("tenants/playground", ORIGIN)
    assert await store.repo.forge_wiring(T2) is None  # GAP-A-3: absent answers None


async def test_a_seeded_tenant_reads_back_as_seeded(store):
    """The seeder (twin) and raw rows (PostgreSQL) read back through `tenant`: the harness's own control."""
    await store.seed(T1, CREATING_FAILED)
    record = await store.repo.tenant(T1)
    assert (record.id, record.created_at, _job(record)) == (T1, SEEDED_AT, CREATING_FAILED)


# --- P4: detached copies ----------------------------------------------------------------------------


def _mutate(model: object) -> int:
    """Change every field of `model` to a different value; how many fields took the change."""
    taken = 0
    for name, value in _values(model).items():
        if isinstance(value, dt.datetime):
            changed: object = value + dt.timedelta(days=1)
        elif isinstance(value, str):
            changed = value + "-mutated"
        else:
            changed = "mutated"
        with contextlib.suppress(dataclasses.FrozenInstanceError, AttributeError):
            setattr(model, name, changed)
            taken += 1
    return taken


READS = {
    "tenant": lambda r: r.tenant(T1),
    "tenants": lambda r: r.tenants(),
    "request_create": lambda r: r.request_create(now=NOW),
    "request_rotate": lambda r: r.request_rotate(T1),
    "request_offboard": lambda r: r.request_offboard(T1, now=NOW),
    "forge_wiring": lambda r: r.forge_wiring(T1),
}


def _records(result: object) -> list[object]:
    return [m for item in result for m in _records(item)] if isinstance(result, list) else [result]


@pytest.mark.parametrize("read", sorted(READS))
async def test_every_returned_record_is_readable_and_editing_it_changes_nothing_stored(store, read):
    """Detached copies: every field of what a method returns is readable, and mutating it stores nothing (P4, #1339)."""
    await store.seed(T1, ACTIVE, repo="tenants/t1", origin=ORIGIN)
    returned = _records(await READS[read](store.repo))
    assert returned
    before = [_values(r) for r in returned]
    stored_before = {t.id: _values(t) for t in await store.repo.tenants()}
    wiring_before = _values(await store.repo.forge_wiring(T1))
    assert any([_mutate(r) for r in returned])  # control: the edit took on the copies
    assert [_values(r) for r in returned] != before
    assert {t.id: _values(t) for t in await store.repo.tenants()} == stored_before
    assert _values(await store.repo.forge_wiring(T1)) == wiring_before


async def test_a_record_read_twice_is_two_copies(store):
    """Two reads of one tenant give separate objects; editing one leaves the other as it was (P4)."""
    await store.seed(T1, ACTIVE)
    first, second = await store.repo.tenant(T1), await store.repo.tenant(T1)
    assert first is not second
    _mutate(first)
    assert _values(second) == _values(await store.repo.tenant(T1))


# --- PostgreSQL only: Python-side values, generations, concurrency -----------------------------------


def fill_row(dsn: str, table: str, **given: object) -> None:
    """Insert one row into `tenancy.<table>`: `given` columns plus a plausible value for every other NOT NULL
    column without a default (the table's other columns are not pinned)."""
    columns = execute(dsn, """SELECT column_name, data_type FROM information_schema.columns
                              WHERE table_schema = 'tenancy' AND table_name = %s AND is_nullable = 'NO'
                                AND column_default IS NULL""", (table,))
    values = dict(given)
    for name, kind in columns:
        if name in values:
            continue
        values[name] = (NOW if kind.startswith("timestamp") else False if kind == "boolean" else 0 if kind in
                        ("integer", "bigint", "smallint") else "{}" if kind in ("json", "jsonb") else f"{name}-{uuid.uuid4()}")
    names = ", ".join(f'"{n}"' for n in values)
    execute(dsn, f'INSERT INTO tenancy."{table}" ({names}) VALUES ({", ".join(["%s"] * len(values))})',  # noqa: S608
            tuple(values.values()))


@pytest.mark.postgres
async def test_generations_are_read_as_detached_copies(pg_store):
    """`generations(T)` returns the tenant's generation rows as readable records; editing one stores nothing (P4)."""
    await pg_store.seed(T1, ACTIVE)
    await pg_store.seed(T2, ACTIVE)
    fill_row(pg_store.dsn, "generations", tenant_id=T1, salt="s1", status="live", bot_login="bot-s1")
    fill_row(pg_store.dsn, "generations", tenant_id=T1, salt="s2", status="retiring", bot_login="bot-s2")
    fill_row(pg_store.dsn, "generations", tenant_id=T2, salt="s3", status="live", bot_login="bot-s3")
    got = {g.salt: g for g in await pg_store.repo.generations(T1)}
    assert {s: (g.status, g.bot_login) for s, g in got.items()} == {"s1": ("live", "bot-s1"), "s2": ("retiring", "bot-s2")}
    before = {s: _values(g) for s, g in got.items()}
    assert any([_mutate(g) for g in got.values()])
    assert {g.salt: _values(g) for g in await pg_store.repo.generations(T1)} == before
    assert await pg_store.repo.generations(ABSENT) == []


async def test_a_tenant_without_generations_has_none(store):
    """`generations` of a tenant with none (or no tenant) is the empty list, on both twins (DC-4)."""
    await store.seed(T1, ACTIVE)
    assert await store.repo.generations(T1) == []
    assert await store.repo.generations(ABSENT) == []


@pytest.mark.postgres
async def test_created_at_is_the_callers_now_and_returned_in_utc_whatever_the_zone(pg_store):
    """Python-side values: request_create stores exactly the `now` passed; the database's own zone never shows (P4, D)."""
    name = execute(pg_store.dsn, "SELECT current_database()")[0][0]
    execute(pg_store.dsn, f"ALTER DATABASE \"{name}\" SET timezone TO 'Pacific/Chatham'")
    record = await pg_store.repo.request_create(now=NOW)
    await pg_store.seed(T1, ACTIVE)
    stamps = [getattr(r, f) for r in (record, await pg_store.repo.tenant(record.id), await pg_store.repo.tenant(T1))
              for f in ("created_at",)]
    assert stamps == [NOW, NOW, SEEDED_AT]
    assert [s.utcoffset() for s in stamps] == [dt.timedelta(0)] * 3
    [(stored,)] = execute(pg_store.dsn, "SELECT created_at FROM tenancy.tenants WHERE id = %s", (record.id,))
    assert stored == NOW
    # control: the zone is in force for a plain connection, so a naive read would have shown it
    assert execute(pg_store.dsn, "SELECT created_at FROM tenancy.tenants WHERE id = %s", (T1,))[0][0].utcoffset() != dt.timedelta(0)


@pytest.mark.postgres
async def test_closing_the_repository_releases_every_connection(pg_store):
    """close() disposes the engine: after requests and reads no backend stays connected (P1 #1339 engine rule)."""
    await pg_store.seed(T1, ACTIVE)
    await pg_store.repo.request_rotate(T1)
    await pg_store.repo.tenants()
    assert await connections(pg_store.dsn) > 0  # control: connections are held while open
    await pg_store.repo.close()

    async def idle() -> bool:
        return await connections(pg_store.dsn) == 0

    await until(idle)


@contextlib.asynccontextmanager
async def _holding_tenant(dsn: str, tenant: str) -> AsyncIterator[None]:
    """`SELECT ... FOR UPDATE` on one tenants row in an open transaction, released on exit."""
    import psycopg

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        cur = await conn.execute("SELECT id FROM tenancy.tenants WHERE id = %s FOR UPDATE", (tenant,))
        assert await cur.fetchall() == [(tenant,)], "the row to hold does not exist"
        try:
            yield
        finally:
            await conn.commit()


def _ask(repo: Any, request: str, tenant: str) -> Any:
    return repo.request_offboard(tenant, now=NOW) if request == "offboard" else getattr(repo, f"request_{request}")(tenant)


RACES = {"rotate": ACTIVE, "resume": CREATING_FAILED, "offboard": ACTIVE}


@pytest.mark.postgres
@pytest.mark.parametrize("request_kind", sorted(RACES))
async def test_two_identical_requests_racing_for_one_precondition_apply_exactly_one(pg_store, request_kind):
    """RC-3: both requests wait at the row; once released one applies and the other is a Conflict (one conditional UPDATE each)."""
    await pg_store.seed(T1, RACES[request_kind])
    from defender.tenancy.postgres import PostgresTenantRepository

    other = PostgresTenantRepository(pg_store.dsn)
    try:
        async with _holding_tenant(pg_store.dsn, T1):
            tasks = []
            for count, repo in enumerate((pg_store.repo, other), start=1):
                tasks.append(asyncio.ensure_future(_ask(repo, request_kind, T1)))
                await until_blocked(pg_store.dsn, count)
            assert not any(t.done() for t in tasks)
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), TIMEOUT)
    finally:
        await other.close()
    applied = [r for r in results if not isinstance(r, BaseException)]
    refused = [r for r in results if isinstance(r, BaseException)]
    assert len(applied) == 1, results
    assert [type(r).__name__ for r in refused] == ["Conflict"]


@pytest.mark.postgres
@pytest.mark.parametrize("order", [("rotate", "offboard"), ("offboard", "rotate")])
async def test_a_rotate_cannot_overwrite_an_offboard_that_got_there_first(pg_store, order):
    """RC-3: offboard replaces a rotate that came first; a rotate arriving second is a Conflict and offboarding stands."""
    await pg_store.seed(T1, ACTIVE)
    from defender.tenancy.postgres import PostgresTenantRepository

    other = PostgresTenantRepository(pg_store.dsn)
    try:
        async with _holding_tenant(pg_store.dsn, T1):
            tasks = {}
            for count, (kind, repo) in enumerate(zip(order, (pg_store.repo, other), strict=True), start=1):
                tasks[kind] = asyncio.ensure_future(_ask(repo, kind, T1))
                await until_blocked(pg_store.dsn, count)
        results = dict(zip(tasks, await asyncio.wait_for(
            asyncio.gather(*tasks.values(), return_exceptions=True), TIMEOUT), strict=True))
    finally:
        await other.close()
    assert not isinstance(results[order[0]], BaseException)
    assert isinstance(results["rotate"], BaseException) == (order == ("offboard", "rotate"))
    assert not isinstance(results["offboard"], BaseException)
    final = await pg_store.repo.tenant(T1)
    assert _job(final) == ("offboarding", "offboard", "offboard", "service", None)


async def test_the_twin_applies_racing_requests_once_too(twin_store):
    """The twin's requests are atomic on one loop: two gathered rotates apply one and refuse one (RC-3, twin parity)."""
    await twin_store.seed(T1, ACTIVE)
    results = await asyncio.gather(twin_store.repo.request_rotate(T1), twin_store.repo.request_rotate(T1), return_exceptions=True)
    assert [type(r).__name__ for r in results if isinstance(r, BaseException)] == ["Conflict"]
    assert len([r for r in results if not isinstance(r, BaseException)]) == 1
