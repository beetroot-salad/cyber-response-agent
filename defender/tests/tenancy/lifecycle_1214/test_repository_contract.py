# ruff: noqa: F811, PT018
"""#1214 tenant repository contract (r9 RC-3, DC-4): one suite over the in-memory twin and the PostgreSQL
repository. Requests are one conditional update each; reads are detached copies; values are Python-side.

RC-1's lock and fence belong to the job-model slice and are not asserted here. The PostgreSQL run is marked
`postgres` (needs DEFENDER_TEST_POSTGRES_DSN; CI fails rather than skips without it).

#1214 attack-1 on the tenant repository's twins: the tenant lock excludes a second holder (H-16), the fence includes the
actor and the failure (H-16), a commit never replaces a recorded wiring (H-17), a write the store refuses as data is the
step's recorded failure, not a lost lock (DC-14) (P6, RC-1, RC-9).

#1214 attack-2 D1, as #1382 r3.1 restates it: a malformed tenant id never reaches the repository past the API (which
answers 422) or a host entry (`TenantId(raw)`), and the repository takes `TenantId`, so the type checker refuses plain
text. Text that gets past the types anyway fails loudly at PostgreSQL: the read and every request raise, and the
repository gains no row. (D1's "an unknown tenant" answer is withdrawn with D-a; neither repository parses ids, so the
in-memory twin, which stores what it is handed, is not asked, #1382 O6.)
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import json
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.tenancy._active1214 import offboard_on_database
from defender.tests.support.tenancy._twin1496 import offboard_twin

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._pglocks1339 import TIMEOUT, connections, until, until_blocked
from defender.tests.support.shared._postgres1339 import database, execute
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.tenancy._twin1496 import seed_tenant
from defender.tests.support.tenancy._active1214 import CREATE_RETENTION


pytestmark = pytest.mark.anyio


NOW = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.UTC)


SEEDED_AT = dt.datetime(2026, 9, 1, 8, 0, tzinfo=dt.UTC)


T1 = fixture_uuid("tenant:1214-repo-1")


T2 = fixture_uuid("tenant:1214-repo-2")


ABSENT = fixture_uuid("tenant:1214-repo-absent")


T3 = fixture_uuid("tenant:1214-repo-3")


ORIGIN = "http://forge.test/tenants/t1.git"


BACKFILL_FAILURE = "registered before #1214: record its forge wiring if it has a repository, then resume"


#: A row to seed: (state, pending_action, step, step_actor, failure).
ACTIVE = ("active", None, None, None, None)


CREATING = ("creating", "create", "provider", "service", None)


CREATING_FAILED = ("creating", "create", "provider", "service", "forge answered 502: bad gateway")


BACKFILLED = ("creating", "create", "names", "service", BACKFILL_FAILURE)


ROTATING = ("active", "rotate", "install", "host", None)


ROTATING_FAILED = ("active", "rotate", "retire", "service", "openbao answered 500")


OFFBOARDING = ("offboarding", "offboard", "teardown", "host", None)


OFFBOARDING_FAILED = ("offboarding", "offboard", "teardown", "host", "host folder busy")


OFFBOARDED = ("offboarded", None, None, None, None)


DELETING = ("offboarded", "delete_repo", "delete_repo", "service", None)


DELETING_FAILED = ("offboarded", "delete_repo", "delete_repo", "service", "forge answered 500")


ALL_ROWS = {
    "creating": CREATING, "creating-failed": CREATING_FAILED, "backfilled": BACKFILLED, "active": ACTIVE,
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
            await seed_tenant(self.twin, tenant, created_at=SEEDED_AT, state=state, **extra)
            return
        execute(self.dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor, failure)
                             VALUES (%s, %s, %s, %s, %s, %s, %s)""", (tenant, SEEDED_AT, state, action, step, actor, failure))
        if repo is not None:
            execute(self.dsn, "INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES (%s, %s, %s)",
                    (tenant, repo, origin or ORIGIN))

    async def offboard(self, tenant: str) -> Any:
        """Move `tenant` to `offboarding` (#1496: the twin's seeder, or tenancy's own `offboard` on the database)."""
        if self.dsn is None:
            return await offboard_twin(self.twin, tenant)
        return await offboard_on_database(self.dsn, tenant)


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
            "host_secret_file", "secret_accessor", "wrapped_secret"} <= names(Generation)
    assert {"sign_approle", "sign_entity", "sign_role_id", "sign_secret_file", "sign_wrapped_secret",
            "sign_secret_accessor"} <= names(Generation)  # A24' (r8.4)
    assert {"repo", "origin"} <= names(ForgeWiring)


# --- request_create ---------------------------------------------------------------------------------


async def test_a_create_request_inserts_a_creating_tenant_at_the_names_step(store):
    """request_create stores a `creating` tenant, `create` pending, step `names`, actor `service`, no failure, at `now` (RC-3)."""
    record = await store.repo.request_create(now=NOW, **CREATE_RETENTION)
    assert uuid.UUID(record.id).version == 4
    assert _job(record) == ("creating", "create", "names", "service", None)
    assert (record.created_at, record.repo_url, record.offboarded_at, record.repo_delete_after) == (NOW, None, None, None)
    assert _values(await store.repo.tenant(record.id)) == _values(record)  # stored, not just returned
    assert await store.repo.generations(record.id) == []  # the pending generation is the names step's, not the request's


@pytest.mark.postgres
async def test_request_create_writes_the_retention_row_in_the_same_transaction_as_the_tenants_row(pg_store):
    """`request_create(now=, investigation_days=, learning_days=)` leaves the tenant `creating` with its retention row holding
    both values; a value the database refuses (29 days) leaves no tenant row either; the row exists while `creating`.
    (A-O7, D16)"""
    import psycopg

    from defender.tests.support.shared._postgres1339 import execute

    made = await pg_store.repo.request_create(now=NOW, investigation_days=45, learning_days=500)
    assert made.state == "creating"
    assert execute(pg_store.dsn, "SELECT investigation_days, learning_days FROM tenancy.evidence_retention WHERE tenant_id = %s",
                   (made.id,)) == [(45, 500)]
    before = execute(pg_store.dsn, "SELECT count(*) FROM tenancy.tenants")
    with pytest.raises(psycopg.errors.CheckViolation):
        await pg_store.repo.request_create(now=NOW, investigation_days=29, learning_days=500)
    assert execute(pg_store.dsn, "SELECT count(*) FROM tenancy.tenants") == before


@pytest.mark.postgres
async def test_1345_d2_a_tenant_made_by_the_create_request_has_no_alert_mapping_and_no_investigation_can_start(pg_store):
    """No mapping is made with a tenant (D2): a tenant from the product's `request_create` reads no mapping through the
    records or the jobs store, and creating an investigation for its alert is `Conflict` with `ALERT_MAPPING_MISSING`;
    the same tenant after a mapping is saved creates (control). (#1345 D2, O4)"""
    from defender.jobs import Conflict, JobStore
    from defender.records.formats import ALERT_MAPPING_MISSING
    from defender.tests.support.jobs._jobs1342 import an_alert
    from defender.tests.support.tenancy._mapping1345 import mapping_value

    tenant = (await pg_store.repo.request_create(now=NOW, **CREATE_RETENTION)).id
    store = JobStore(pg_store.dsn, clock=lambda: NOW)
    try:
        assert await pg_store.repo.alert_mapping(tenant) is None
        assert await store.get_alert_mapping(tenant) is None
        alert = await an_alert(store, tenant)
        with pytest.raises(Conflict) as refused:
            await store.create_investigation(tenant, alert.alert_id, "k1", actor="u-1")
        assert str(refused.value) == ALERT_MAPPING_MISSING
        await store.put_alert_mapping(tenant, mapping_value({}), actor="u-1")
        await store.create_investigation(tenant, alert.alert_id, "k1", actor="u-1")  # control: a saved mapping lets it through
    finally:
        await store.close()


async def test_1345_m1_the_mapping_read_is_the_asked_tenants_own_when_another_tenant_has_saved_one(store):
    """A has a saved mapping, B never saved one: B reads none and A reads exactly its own, on both repositories. (#1345 M1, O4)"""
    from defender.tests.support.tenancy._mapping1345 import mapping_value, seed_postgres, seed_twin

    mine = {"signature": "rule.id", "summary": "rule.description", "title": "t"}
    await store.seed(T1)
    await store.seed(T2)
    if store.dsn is None:
        seed_twin(store.twin, T1, mine)
    else:
        seed_postgres(store.dsn, T1, mine)

    assert await store.repo.alert_mapping(T2) is None
    assert await store.repo.alert_mapping(T1) == mapping_value(mine)
    assert await store.repo.alert_mapping(ABSENT) is None


async def test_two_create_requests_are_two_tenants(store):
    """Each create mints its own id and adds a row; `tenants()` lists both (RC-3)."""
    first, second = await store.repo.request_create(now=NOW, **CREATE_RETENTION), await store.repo.request_create(now=NOW, **CREATE_RETENTION)
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
#: The backfilled row has no special standing (O11): it resumes like any failed create.
RESUMABLE = ["creating-failed", "backfilled", "rotating-failed", "offboarding-failed", "deleting-failed"]


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


async def test_a_second_resume_is_a_conflict(store):
    """Resume twice: the first clears, the second finds no failure and is refused (RC-3)."""
    await store.seed(T1, CREATING_FAILED)
    await store.repo.request_resume(T1)
    await _refused(store.repo.request_resume(T1), "Conflict")


# --- #1360: the tenancy `offboard` operation ---------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[4]
#: Imports the door and the models by path (`-I` ignores PYTHONPATH), optionally the PostgreSQL repository, and reports
#: what the operation is and whether the PostgreSQL repository module ended up loaded. Driver modules (psycopg, asyncpg)
#: are not asserted on: nothing shows the probe would see them load, so such a check would pass vacuously.
_LOADS = """
import inspect, json, sys
sys.path.insert(0, sys.argv[1])
import defender.tenancy as door
import defender.tenancy.models as models
if sys.argv[2] == "with-repository":
    import defender.tenancy.postgres
loaded = sorted(m for m in sys.modules if m == "defender.tenancy.postgres")
print(json.dumps({"same": door.offboard is models.offboard, "async": inspect.iscoroutinefunction(door.offboard),
                  "loaded": loaded}))
"""


def _probe(mode: str) -> dict[str, Any]:
    proc = subprocess.run([sys.executable, "-I", "-c", _LOADS, str(REPO), mode], capture_output=True, text=True,
                          check=False, timeout=180)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.splitlines()[-1])


def test_1360_offboard_is_an_async_operation_of_the_tenancy_door_and_models_that_does_not_load_the_postgres_repository():
    """`defender.tenancy.offboard` is `defender.tenancy.models.offboard`, a coroutine function, and importing them does
    not load the PostgreSQL repository; the probe does see it when it is imported (the positive control). (#1360 D1, D6a)"""
    found = _probe("door")
    assert (found["same"], found["async"], found["loaded"]) == (True, True, [])
    assert "defender.tenancy.postgres" in _probe("with-repository")["loaded"]


@pytest.fixture
async def engine(pg_store) -> AsyncIterator[Any]:
    from defender.database import async_engine

    engine = async_engine(pg_store.dsn, max_connections=2)
    try:
        yield engine
    finally:
        await engine.dispose()


@contextlib.asynccontextmanager
async def _executor(engine: Any, kind: str) -> AsyncIterator[Any]:
    """A transaction on `engine`, handed over as a Core connection or an ORM session; committed on a clean exit."""
    if kind == "connection":
        async with engine.begin() as connection:
            yield connection
    else:
        from defender.database import sessions

        async with sessions(engine)() as session, session.begin():
            yield session


class _Abandon(Exception):
    pass


@pytest.mark.postgres
@pytest.mark.parametrize("kind", ["connection", "session"])
@pytest.mark.parametrize("name", ["creating", "creating-failed", "backfilled", "active", "rotating", "rotating-failed"])
async def test_1360_offboard_moves_the_tenant_on_a_connection_or_a_session(pg_store, engine, kind, name):
    """`offboard(executor, tenant)` from `creating`|`active` sets `offboarding`, `offboard` pending, first step `offboard`
    (service), no failure, replacing any pending action; returns a record that outlives the executor and touches no
    other tenant. (#1360 D1, D6a, RC-3, DC-3; #1496: the one offboard transition, so its cases are all here)"""
    from defender.tenancy import offboard

    await pg_store.seed(T1, ALL_ROWS[name])
    await pg_store.seed(T2, ALL_ROWS[name])
    before = _values(await pg_store.repo.tenant(T1))
    async with _executor(engine, kind) as executor:
        record = await offboard(executor, T1)
    assert _job(record) == ("offboarding", "offboard", "offboard", "service", None)
    assert (record.id, record.created_at) == (T1, before["created_at"])
    assert _values(await pg_store.repo.tenant(T1)) == _values(record)
    assert _job(await pg_store.repo.tenant(T2)) == ALL_ROWS[name]


@pytest.mark.postgres
@pytest.mark.parametrize("kind", ["connection", "session"])
async def test_1360_offboard_is_part_of_the_callers_transaction_and_a_rollback_takes_it_back(pg_store, engine, kind):
    """Nothing is visible to another connection before the caller commits, and the caller's rollback leaves the tenant
    as it was; a commit (the case above) keeps it. (#1360 D1, D6a)"""
    from defender.tenancy import offboard

    async def abandoned() -> None:
        async with _executor(engine, kind) as executor:
            await offboard(executor, T1)
            assert _job(await pg_store.repo.tenant(T1)) == ACTIVE, "the operation committed on its own"
            raise _Abandon

    await pg_store.seed(T1, ACTIVE)
    with pytest.raises(_Abandon):
        await abandoned()
    assert _job(await pg_store.repo.tenant(T1)) == ACTIVE


@pytest.mark.postgres
@pytest.mark.parametrize("kind", ["connection", "session"])
@pytest.mark.parametrize("name", ["offboarding", "offboarding-failed", "offboarded", "deleting", "absent"])
async def test_1360_offboard_refuses_with_tenancys_own_errors(pg_store, engine, kind, name):
    """An absent tenant is `NotFound`, any state but `creating`/`active` a `Conflict`; the row stays. (#1360 D1, D6a)"""
    from defender.tenancy import Conflict, NotFound, offboard

    if name != "absent":
        await pg_store.seed(T1, ALL_ROWS[name])
    await pg_store.seed(T2, ACTIVE)
    before = None if name == "absent" else _values(await pg_store.repo.tenant(T1))
    with pytest.raises(NotFound if name == "absent" else Conflict):
        async with _executor(engine, kind) as executor:
            await offboard(executor, ABSENT if name == "absent" else T1)
    after = await pg_store.repo.tenant(T1)
    assert (None if after is None else _values(after)) == before
    assert _job(await pg_store.repo.tenant(T2)) == ACTIVE


# --- request_rotate ---------------------------------------------------------------------------------


async def test_rotate_from_active_with_nothing_pending_starts_at_names(store):
    """request_rotate on an idle `active` tenant sets `rotate` pending, step `names`, actor `service`, state unchanged (RC-3)."""
    await store.seed(T1, ACTIVE)
    await store.seed(T2, ACTIVE)
    record = await store.repo.request_rotate(T1)
    assert _job(record) == ("active", "rotate", "names", "service", None)
    assert _values(await store.repo.tenant(T1)) == _values(record)
    assert _job(await store.repo.tenant(T2)) == ACTIVE


@pytest.mark.parametrize("name", ["rotating", "rotating-failed", "creating", "creating-failed", "backfilled",
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


@pytest.mark.parametrize("ask", ["request_resume", "request_rotate", "offboard"])
async def test_a_request_for_an_unknown_tenant_is_not_found_and_stores_nothing(store, ask):
    """Every request names its tenant; an absent one is NotFound (404), and the repository gains no row (RC-3)."""
    await store.seed(T1, ACTIVE)
    call = store.offboard(ABSENT) if ask == "offboard" else getattr(store.repo, ask)(ABSENT)
    await _refused(call, "NotFound")
    assert [t.id for t in await store.repo.tenants()] == [T1]


async def test_requests_chain_through_the_lifecycle(store):
    """create -> (seeded active) rotate -> offboard -> rotate/offboard refused: each request sees the previous one's row (RC-3)."""
    await store.seed(T1, ACTIVE)
    await store.repo.request_rotate(T1)
    assert _job(await store.offboard(T1))[:2] == ("offboarding", "offboard")
    await _refused(store.repo.request_rotate(T1), "Conflict")
    await _refused(store.offboard(T1), "Conflict")
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
    "request_create": lambda r: r.request_create(now=NOW, **CREATE_RETENTION),
    "request_rotate": lambda r: r.request_rotate(T1),
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
    fill_row(pg_store.dsn, "generations", tenant_id=T1, salt="s1", status="live", bot_login="bot-s1",
             sign_approle="sign-s1", sign_entity="entity-s1-sign", sign_role_id="role-s1-sign",
             sign_secret_file="/secrets/t1/sign-s1", sign_wrapped_secret="wrap-s1-sign", sign_secret_accessor="acc-s1-sign")
    fill_row(pg_store.dsn, "generations", tenant_id=T1, salt="s2", status="retiring", bot_login="bot-s2")
    fill_row(pg_store.dsn, "generations", tenant_id=T2, salt="s3", status="live", bot_login="bot-s3")
    got = {g.salt: g for g in await pg_store.repo.generations(T1)}
    assert {s: (g.status, g.bot_login) for s, g in got.items()} == {"s1": ("live", "bot-s1"), "s2": ("retiring", "bot-s2")}
    assert (got["s1"].sign_approle, got["s1"].sign_entity, got["s1"].sign_role_id, got["s1"].sign_secret_file,
            got["s1"].sign_wrapped_secret, got["s1"].sign_secret_accessor) == (
        "sign-s1", "entity-s1-sign", "role-s1-sign", Path("/secrets/t1/sign-s1"), "wrap-s1-sign", "acc-s1-sign")
    assert got["s2"].sign_approle is None, "a generation recorded before A24' reads back with no sign names"
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
    record = await pg_store.repo.request_create(now=NOW, **CREATE_RETENTION)
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

    from psycopg.types.string import TextLoader

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        conn.adapters.register_loader("uuid", TextLoader)  # ids read back as their text (#1382)
        cur = await conn.execute("SELECT id FROM tenancy.tenants WHERE id = %s FOR UPDATE", (tenant,))
        assert await cur.fetchall() == [(tenant,)], "the row to hold does not exist"
        try:
            yield
        finally:
            await conn.commit()


def _ask(repo: Any, request: str, tenant: str, dsn: str) -> Any:
    """`request` on `repo`; the offboard, tenancy's own `offboard` on a connection of its own (#1496)."""
    return offboard_on_database(dsn, tenant) if request == "offboard" else getattr(repo, f"request_{request}")(tenant)


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
                tasks.append(asyncio.ensure_future(_ask(repo, request_kind, T1, pg_store.dsn)))
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
                tasks[kind] = asyncio.ensure_future(_ask(repo, kind, T1, pg_store.dsn))
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


# --- r10 Finding 9: one read for admission ----------------------------------------------------------


async def test_admission_is_none_none_for_an_absent_tenant(store):
    """`admission` of a tenant with no row answers `(None, None)` (r10 A1 step 4: absent is not an error)."""
    assert await store.repo.admission(ABSENT) == (None, None)


@pytest.mark.parametrize("name", sorted(ALL_ROWS))
async def test_admission_is_the_state_and_the_recorded_wiring_or_none(store, name):
    """For a tenant in each state `admission` returns its state with the recorded repo and origin when wiring was
    recorded, and with `None` when none was: wiring is never invented (r10 A1 step 4, Finding 9)."""
    await store.seed(T1, ALL_ROWS[name])
    await store.seed(T2, ALL_ROWS[name], repo="tenants/playground", origin=ORIGIN)
    state, wiring = await store.repo.admission(T1)
    assert (state, wiring) == (ALL_ROWS[name][0], None)
    state, wiring = await store.repo.admission(T2)
    assert state == ALL_ROWS[name][0]
    recorded = await store.repo.forge_wiring(T2)
    assert wiring is not None
    assert (wiring.repo, wiring.origin) == ("tenants/playground", ORIGIN)
    assert (wiring.repo, wiring.origin) == (recorded.repo, recorded.origin)


async def test_a_second_lock_on_a_held_tenant_yields_nothing_on_both_twins(store: Store):
    """While T's lock is open another `lock(T)` yields None, another tenant's is free, and T's is free again after (P6)."""
    await store.seed(T1, CREATING)
    await store.seed(T2, CREATING)
    async with store.repo.lock(T1) as first:
        assert first is not None
        async with store.repo.lock(T1) as second:
            assert second is None
        async with store.repo.lock(T2) as other:
            assert other is not None
    async with store.repo.lock(T1) as again:
        assert again is not None


async def _change(store: Store, column: str, value: Any) -> None:
    """Change one column of T1 behind the hold's back (neither twin offers a request that changes only this)."""
    if store.dsn is not None:
        execute(store.dsn, f"UPDATE tenancy.tenants SET {column} = %s WHERE id = %s", (value, T1))
    else:
        store.twin._tenants[T1] = dataclasses.replace(store.twin._tenants[T1], **{column: value})


@pytest.mark.parametrize("write", ["commit", "fail"])
@pytest.mark.parametrize("changed", ["step_actor", "failure", "step", "nothing"])
async def test_a_write_lands_only_if_step_actor_and_failure_are_as_read_on_both_twins(store: Store, changed, write):
    """The row changes one column under the hold: the hold's commit or failure misses and the row is as the change left it;
    with nothing changed the same write lands (RC-1)."""
    from defender.tenancy import FenceMissed

    await store.seed(T1, CREATING)
    values = {"step_actor": "host", "failure": "put there by the case", "step": "repo"}
    async with store.repo.lock(T1) as held:
        assert held is not None
        if changed != "nothing":
            await _change(store, changed, values[changed])
        before = await store.repo.tenant(T1)
        attempt = (held.commit(step="repo", actor="service") if write == "commit"
                   else held.fail("boom", step="provider", actor="service"))
        if changed == "nothing":
            await attempt
            assert await store.repo.tenant(T1) != before, "control: an unchanged row takes the write"
        else:
            with pytest.raises(FenceMissed):
                await attempt
            assert await store.repo.tenant(T1) == before, f"the write ignored a changed {changed}"


async def test_a_commit_for_a_tenant_that_has_a_wiring_leaves_the_recorded_one_on_both_twins(store: Store):
    """`names` keeps an already recorded repo and origin (the lab's own); a tenant without one gets the committed one (RC-9)."""
    from defender.tenancy import ForgeWiring

    await store.seed(T1, CREATING, repo="tenants/playground", origin=ORIGIN)
    await store.seed(T2, CREATING)
    for tenant in (T1, T2):
        async with store.repo.lock(tenant) as held:
            assert held is not None
            await held.commit(step="repo", actor="service",
                              wiring=ForgeWiring(tenant_id=tenant, repo=f"tenants/{tenant}", origin="http://forge.test/new.git"))
    kept = await store.repo.forge_wiring(T1)
    assert (kept.repo, kept.origin) == ("tenants/playground", ORIGIN)
    fresh = await store.repo.forge_wiring(T2)
    assert (fresh.repo, fresh.origin) == (f"tenants/{T2}", "http://forge.test/new.git")


# --- a write the store refuses as data ---------------------------------------------------------------

#: Commits the store refuses for what they say, not because the lock is lost.
REFUSED = {"state-and-action-pair": dict(state="offboarded", pending_action="create"),  # ck_tenants_state_allows_pending_action
           "nul": dict(repo_url="http://forge.test/a\x00b")}  # PostgreSQL text cannot hold a NUL


async def _two_passes(store: Store, refused: dict[str, Any]) -> tuple[list[int], int, Any]:
    """A service actor whose `provider` step commits `refused`, run for two passes on T1 (creating, at provider): the
    passes' step counts, how often the step ran, and T1 after."""
    from defender.lifecycle._job import SERVICE, Actor

    class _Refusing(Actor):
        actor = SERVICE
        runs = 0

        def steps(self) -> Any:
            return {"provider": self._provider}

        async def _provider(self, held: Any) -> None:
            self.runs += 1
            await held.commit(step="repo", actor=SERVICE, **refused)

    await store.seed(T1, CREATING)
    worker = _Refusing(store.repo, clock=lambda: NOW)
    ran = [await worker.work(), await worker.work()]
    return ran, worker.runs, await store.repo.tenant(T1)


def _recorded_once(ran: list[int], runs: int, after: Any) -> None:
    assert (ran, runs) == ([1, 0], 1), f"the refused step was not recorded as failed and ran again: {ran}, {runs} runs"
    assert (after.state, after.step, after.step_actor) == ("creating", "provider", "service"), after
    assert after.failure and after.failure.startswith("provider: ") and "\x00" not in after.failure, after.failure


async def test_a_commit_the_store_refuses_is_the_steps_recorded_failure_and_is_not_rerun_on_both_twins(store: Store):
    """A step's commit breaks the state/pending-action pair: the store refuses it, the lock is still held, so the job
    records the failure at the step (restart there) and the next pass leaves the tenant alone (DC-14, RC-1)."""
    _recorded_once(*await _two_passes(store, REFUSED["state-and-action-pair"]))


@pytest.mark.postgres
async def test_a_commit_with_a_value_postgresql_cannot_store_is_the_steps_recorded_failure(pg_store: Store):
    """A NUL in a committed value is a data error, not a lost lock: the failure is recorded once, the step not rerun.
    (The in-memory twin stores a NUL, so this case is PostgreSQL's.)"""
    _recorded_once(*await _two_passes(pg_store, REFUSED["nul"]))


@pytest.mark.postgres
async def test_a_write_that_times_out_waiting_for_the_row_spends_the_hold_and_records_nothing(pg_store: Store):
    """A transient refusal is not the step's failure: the tenant row is locked by another session past the lock
    connection's `lock_timeout`, so the commit raises `FenceMissed` and leaves the row for the next pass (RC-1)."""
    import psycopg
    from sqlalchemy import text

    from defender.tenancy import FenceMissed

    await pg_store.seed(T1, CREATING)
    with psycopg.connect(pg_store.dsn) as blocker:
        blocker.execute("SELECT 1 FROM tenancy.tenants WHERE id = %s FOR UPDATE", (T1,))
        async with pg_store.repo.lock(T1) as held:
            assert held is not None
            await held._conn.execute(text("SET lock_timeout = '100ms'"))  # the hold's own session, as H-3 does
            await held._conn.commit()
            with pytest.raises(FenceMissed):
                await held.commit(step="repo", actor="service")
        blocker.rollback()
    after = await pg_store.repo.tenant(T1)
    assert (after.step, after.failure) == ("provider", None), after


#: Not a UUID: a NUL, text, an over-long id, empty, non-ASCII, a 100k-character one.
MALFORMED = ["a\x00b", "not-a-tenant-id", "a" * 65, "", "é" * 8, "a" * 100_000]


@pytest.mark.parametrize("bad", MALFORMED, ids=["nul", "text", "65", "empty", "non-ascii", "100k"])
async def test_a_malformed_tenant_id_is_refused_by_every_read_and_request(pg_store, bad):  # noqa: F811
    """`tenant` and `request_resume/rotate/offboard` raise for a malformed id; the one real row stays alone; a real
    tenant is answered on the same channel (control) (RC-3, O2, #1382 r3.1)."""
    store = pg_store
    await store.seed(T1)
    assert (await store.repo.tenant(T1)).id == T1, "control: a real id is found"
    for call in (store.repo.tenant(bad), store.repo.request_resume(bad), store.repo.request_rotate(bad),
                 store.offboard(bad)):
        with pytest.raises(Exception):  # noqa: B017, PT011 — whatever the driver raises, so long as it is loud
            await call
    assert [t.id for t in await store.repo.tenants()] == [T1]
    assert (await store.repo.tenant(T1)).id == T1, "control: the connection still answers after the malformed ones"


# --- #1366 R10, R11, O10: the current-records read, on both twins ---------------------------------------------


def _records_value(**systems: tuple[int, bool, int]) -> Any:
    """`TenantRecords` (imported) with the ticket case record and the named systems, `name=(version, enabled, generation)`."""
    from defender.tests.support.tenancy import _systems1366 as R

    spec = R.RecordsSpec({s: R.SysSpec({f"{s.upper()}_TIMEOUT_SEC": "10"}, R.declaration(f"http://{s}.test"), version=v,
                                       generation=g, enabled=e) for s, (v, e, g) in systems.items()}, R.CaseSpec())
    return R.to_value(spec)


def _declaration(system: str) -> str:
    from defender.tests.support.tenancy import _systems1366 as R

    return R.declaration(f"http://{system}.test")


def _system_row(store: Store, tenant: str, system: str, version: int, *, enabled: bool = True, deleted: bool = False,
                generation: int = 1) -> None:
    """One stored system version, raw SQL (the writer is not the oracle of its own read)."""
    execute(store.dsn, """INSERT INTO tenancy.system_versions (tenant_id, system_id, version, adapter_id, enabled, settings,
                          access, credential_generation, deleted, author, written_at)
                          VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, 'seed', %s)""",
            (tenant, system, version, system, enabled, json.dumps({f"{system.upper()}_TIMEOUT_SEC": "10"}),
             _declaration(system), generation, deleted, SEEDED_AT))


def _plant_mark(dsn: str, tenant: str) -> None:
    """Before #1470's migration the tenant create request also wrote the mark; the table is gone after it (a base-only shim)."""
    if execute(dsn, "SELECT to_regclass('tenancy.records_mark')::text")[0][0] is not None:
        execute(dsn, "INSERT INTO tenancy.records_mark (tenant_id) VALUES (%s)", (tenant,))


async def _seed_records(store: Store, tenant: str, value: Any) -> None:
    """Put `value` into the read side: the twin's seeder, or one row per record on PostgreSQL."""
    if store.dsn is None:
        await store.twin.add_records(tenant, value)
        return
    _plant_mark(store.dsn, tenant)
    for system, rec in value.systems.items():
        _system_row(store, tenant, system, rec.version, enabled=rec.enabled, generation=rec.credential_generation)
    if value.case is not None:
        execute(store.dsn, """INSERT INTO tenancy.case_versions (tenant_id, version, system_id, deleted, author,
                              written_at) VALUES (%s, %s, %s, false, 'seed', %s)""",  # #1471 W7: no comment body
                (tenant, value.case.version, value.case.system_id, SEEDED_AT))


async def test_1470_o8_an_active_tenant_nothing_was_written_for_reads_empty(store):
    """An active tenant with no records reads no systems and no case record: not a refusal. (#1470 O8; replaces #1366
    R10's not-imported read)"""
    await store.seed(T1)
    await _plant_mark_for(store, T1)
    read = await store.repo.current_records(T1)
    assert (dict(read.systems), read.case) == ({}, None)


async def _plant_mark_for(store: Store, tenant: str) -> None:
    if store.dsn is not None:
        _plant_mark(store.dsn, tenant)


@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
async def test_1470_o8_a_tenant_that_is_not_active_and_a_tenant_with_no_row_are_refused_not_read_as_empty(store, state):
    """`current_records` of a tenant whose state is not `active`, or with no row, raises `TenantRefused` (not the transient
    `RecordsUnreachable`), on both repositories; an active tenant beside it reads (control). (#1470 O8: known iff active)"""
    from defender.records.formats import TenantRefused
    from defender.tenancy import RecordsUnreachable

    await store.seed(T1, ALL_ROWS[state])
    await store.seed(T2)
    await _plant_mark_for(store, T1)  # the mark existing must not make a tenant that is not active readable
    await _seed_records(store, T2, _records_value(cmdb=(1, True, 1)))
    assert set((await store.repo.current_records(T2)).systems) == {"cmdb"}, "control"
    for tenant in (T1, ABSENT):
        with pytest.raises(TenantRefused) as refused:
            await store.repo.current_records(tenant)
        assert not isinstance(refused.value, RecordsUnreachable), tenant


async def _move(store: Store, tenant: str, row: tuple) -> None:
    """`tenant`'s row moved in place to `row` (state, pending action, step, actor, failure), its records kept: as a
    lifecycle step leaves them until its last step."""
    state, action, step, actor, failure = row
    if store.dsn is None:
        with store.twin._mutex:
            held = store.twin._tenants[tenant]
            held.state, held.pending_action, held.step, held.step_actor, held.failure = row
        return
    execute(store.dsn, "UPDATE tenancy.tenants SET state = %s, pending_action = %s, step = %s, step_actor = %s, "
                       "failure = %s WHERE id = %s", (state, action, step, actor, failure, tenant))


def _rows_not_active() -> list[str]:
    """Every seeded row whose state is not `active`; together they hold every state of the state type but `active`."""
    import typing

    from defender.tenancy.models import TenantState

    names = [n for n, row in ALL_ROWS.items() if row[0] != "active"]
    assert {ALL_ROWS[n][0] for n in names} == set(typing.get_args(TenantState)) - {"active"}, "premise: every state"
    return names


@pytest.mark.parametrize("name", _rows_not_active())
async def test_1470_o8_a_tenant_moved_out_of_active_is_refused_though_its_records_remain(store, name):
    """T1's records are written while it is active and read (control); its row then moves to each row that is not
    active, the records kept: `current_records` raises `TenantRefused` (not `RecordsUnreachable`), on both repositories.
    (#1470 O8: known exactly while active, whatever records the tenant holds)"""
    from defender.records.formats import TenantRefused
    from defender.tenancy import RecordsUnreachable

    await store.seed(T1)
    await _seed_records(store, T1, _records_value(cmdb=(1, True, 1)))
    assert set((await store.repo.current_records(T1)).systems) == {"cmdb"}, "control: while active the records read"
    await _move(store, T1, ALL_ROWS[name])
    with pytest.raises(TenantRefused) as refused:
        await store.repo.current_records(T1)
    assert not isinstance(refused.value, RecordsUnreachable), name


async def test_1366_r10_the_read_is_the_asked_tenants_own_records_disabled_ones_included_and_the_case(store):
    """T1 holds an enabled and a disabled system and a case record, T2 one other system: each reads exactly its own,
    the disabled one with `enabled` false at its version and generation. (#1366 R10, O1, R7)"""
    await store.seed(T1)
    await store.seed(T2)
    mine = _records_value(cmdb=(3, True, 2), identity=(5, False, 4))
    await _seed_records(store, T1, mine)
    await _seed_records(store, T2, _records_value(ticket=(1, True, 1)))

    assert await store.repo.current_records(T1) == mine
    read = await store.repo.current_records(T2)
    assert set(read.systems) == {"ticket"}


async def test_1366_r10_the_current_record_is_the_highest_version_and_a_delete_hides_the_system(pg_store):
    """cmdb v1 enabled then v2 disabled (current: v2, disabled); identity v1 then v2 a delete (absent); elastic v1, a delete
    v2 and a re-create v3 (current: v3); a case v1 then a case delete v2 (no case). (#1366 R10, O5)"""
    store, tenant = pg_store, T1
    await store.seed(tenant)
    _plant_mark(store.dsn, tenant)
    for system, version, kw in (("cmdb", 1, {}), ("cmdb", 2, {"enabled": False}), ("identity", 1, {}),
                                ("identity", 2, {"deleted": True}), ("elastic", 1, {}), ("elastic", 2, {"deleted": True}),
                                ("elastic", 3, {"generation": 2}), ("ticket", 1, {})):
        _system_row(store, tenant, system, version, **kw)
    for version, deleted in ((1, False), (2, True)):
        execute(store.dsn, """INSERT INTO tenancy.case_versions (tenant_id, version, system_id, deleted, author,
                              written_at) VALUES (%s, %s, 'ticket', %s, 'seed', %s)""", (tenant, version, deleted, SEEDED_AT))

    read = await store.repo.current_records(tenant)

    assert {s: (r.version, r.enabled, r.credential_generation) for s, r in read.systems.items()} == {
        "cmdb": (2, False, 1), "elastic": (3, True, 2), "ticket": (1, True, 1)}
    assert read.case is None


async def test_1470_o8_a_tenant_made_by_the_create_request_is_refused_until_it_is_active(store):
    """`request_create` makes a `creating` tenant: its records are unknown (`TenantRefused`), as every tenant's are until
    it is `active`. (#1470 O8: `creating` newly refused; replaces #1366 R11)"""
    from defender.records.formats import TenantRefused

    made = (await store.repo.request_create(now=NOW, **CREATE_RETENTION)).id
    with pytest.raises(TenantRefused):
        await store.repo.current_records(made)


@pytest.mark.parametrize("fenced", [True, False])
async def test_1366_o10_a_commit_that_drops_records_removes_that_tenants_versions_only_inside_its_fence(store, fenced):
    """`commit(drop_records=True)` of the offboarding step leaves the tenant with no system or case record and the
    other tenants' untouched (an OFFBOARDING one, whose rows are counted, and an active one, still read); with the fence
    missed nothing is dropped (and the commit raises). The offboarded tenant's records are not read (`TenantRefused`, #1470 O8); the drop is asserted on the rows (Postgres)
    and the twin's own records (memory). (#1366 O10, #1470 O8)"""
    from defender.tenancy import FenceMissed

    await store.seed(T1, OFFBOARDING)
    await store.seed(T2, OFFBOARDING)
    await store.seed(T3)
    mine, theirs = _records_value(cmdb=(2, True, 1), ticket=(1, True, 1)), _records_value(cmdb=(1, True, 1))
    await _seed_records(store, T1, mine)
    await _seed_records(store, T2, theirs)
    await _seed_records(store, T3, theirs)

    async with store.repo.lock(T1) as held:
        assert held is not None
        if not fenced:
            await _change(store, "step_actor", "service")
        attempt = held.commit(step=None, actor=None, state="offboarded", pending_action=None, offboarded_at=NOW,
                              drop_records=True)
        if fenced:
            await attempt
        else:
            with pytest.raises(FenceMissed):
                await attempt

    from defender.records.formats import TenantRefused

    def rows(tenant: str) -> tuple[int, int]:
        count = "SELECT count(*) FROM tenancy.{} WHERE tenant_id = %s"
        return (execute(store.dsn, count.format("system_versions"), (tenant,))[0][0],
                execute(store.dsn, count.format("case_versions"), (tenant,))[0][0])

    if fenced:
        with pytest.raises(TenantRefused):  # offboarded: no longer a tenant whose records are known
            await store.repo.current_records(T1)
    assert await store.repo.current_records(T3) == theirs, "control: an active tenant's records stay, and are read"
    if store.dsn is not None:  # a tenant that is not active is not read, so the rows are counted in the tables
        assert rows(T1) == ((0, 0) if fenced else (len(mine.systems), 1)), "this tenant's records"
        assert rows(T2) == (len(theirs.systems), 1), "control: the other tenant's rows stay"
        assert rows(T3) == (len(theirs.systems), 1), "control: the active tenant's rows stay"
        if not fenced:
            from defender.tests.support.tenancy import _systems1366 as R

            assert {(s, v.version, v.enabled, v.credential_generation) for s in mine.systems
                    for v in R.system_versions(store.dsn, T1, s)} == {
                (s, r.version, r.enabled, r.credential_generation) for s, r in mine.systems.items()}, "this tenant's records"
            assert [(c.system_id, c.version) for c in R.case_versions(store.dsn, T1)] == [
                (mine.case.system_id, mine.case.version)]  # #1471 W7: the record is its system and version
    else:  # the twin's own records (the memory repository reads none for a tenant that is not active)
        assert (T1 in store.twin._records) is (not fenced), "the commit's drop on the twin"
        assert store.twin._records[T2] == theirs, "control: the other tenant's records stay"
        assert store.twin._records[T3] == theirs
        if not fenced:
            assert store.twin._records[T1] == mine, "nothing of this tenant's is dropped"
