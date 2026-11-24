"""#1592 r15.1 "Who records a request": database triggers on `memberships.status`, `tenants.state` and
`users.signed_out_at` record a people request in the writing transaction (OD-10), and the memory twins mirror them
where their stores write the column (OD-8, PP-4). Seeding records on both backends, so every case asserts on the
requests recorded after a baseline taken at the end of its setup (`RequestLog.mark`).

S1-1..7 (triggers, raw SQL, PostgreSQL), S1-8..10 (every G33 writer and the seeders, both backends), S1-11 (parity).
The world here is the bare pair of repositories over one store: the worker's `People` world needs a sessions database
and `LifecycleConfig` fields these cases do not touch.
"""
from __future__ import annotations

import collections
import contextlib
import dataclasses
import datetime as dt
import hashlib
import random
import re
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from defender.tests.support.identity._seed1496 import seed_membership, seed_user
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import database, execute
from defender.tests.support.tenancy._active1214 import CREATE_RETENTION
from defender.tests.support.tenancy._twin1496 import offboard_twin, seed_tenant
from defender.tests.tenancy.people_1592._spec1592 import RequestLog, requests_port, requests_sql, sql_reader

pytestmark = pytest.mark.anyio

NOW = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.UTC)
WEEK = dt.timedelta(days=7)
T1 = fixture_uuid("tenant:1592-rec-1")
T2 = fixture_uuid("tenant:1592-rec-2")
U1 = fixture_uuid("user:1592-rec-1")
U2 = fixture_uuid("user:1592-rec-2")
M1 = fixture_uuid("membership:1592-rec-1")
UNKNOWN_USER = fixture_uuid("user:1592-rec-unknown")
PendingJob = tuple[str | None, str | None, str | None]
CREATING: PendingJob = ("create", "activate", "service")
Pair = tuple[str | None, str | None]


def one(user: str | None, tenant: str | None, count: int = 1) -> collections.Counter[Pair]:
    return collections.Counter({(user, tenant): count}) if count else collections.Counter()


# --- raw SQL on the migrated database (S1-1..7) ----------------------------------------------------


@pytest.fixture
def pg() -> Any:
    """A migrated database of this test's own, and a `RequestLog` that reads the requests table by raw SQL."""
    with database(migrated=True) as dsn:
        yield dsn


def sql_user(dsn: str, user: str, *, signed_out_at: dt.datetime | None = None) -> None:
    """A person row by SQL. Every NOT NULL column named (the table has no server defaults)."""
    execute(dsn, """INSERT INTO identity.users (id, email, display_name, status, is_platform_admin,
                    set_password_requested_seq, set_password_sent_seq, set_password_attempts, created_at, updated_at,
                    activated_at) VALUES (%s, %s, '', 'active', false, 0, 0, 0, %s, %s, %s)""",
            (user, f"{user}@x.org", NOW, NOW, NOW))
    if signed_out_at is not None:
        execute(dsn, "UPDATE identity.users SET signed_out_at = %s WHERE id = %s", (signed_out_at, user))


def sql_tenant(dsn: str, tenant: str, state: str = "active", job: PendingJob = (None, None, None)) -> None:
    execute(dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                    VALUES (%s, %s, %s, %s, %s, %s)""", (tenant, NOW, state, *job))


MEMBER_COLUMNS = "(id, user_id, tenant_id, status, created_at, notify_requested_seq, notify_sent_seq, notify_attempts, role"


def sql_member(dsn: str, membership: str, user: str, tenant: str, status: str = "invited") -> None:
    accepted = {"active": "accepted_at", "ended": "accepted_at"}
    execute(dsn, f"""INSERT INTO identity.memberships {MEMBER_COLUMNS}, accepted_at, ended_at)
                     VALUES (%s, %s, %s, %s, %s, 0, 0, 0, 'admin', %s, %s)""",
            (membership, user, tenant, status, NOW, NOW if status in accepted else None, NOW if status == "ended" else None))


async def sql_log(dsn: str) -> RequestLog:
    """The baseline at the end of a case's setup."""
    log = RequestLog(sql_reader(dsn))
    await log.mark()
    return log


async def test_a_membership_inserted_by_sql_records_the_person_in_that_tenant_whatever_its_status(pg):
    """S1-1 (OD-10): a raw INSERT of a membership, of any status, leaves exactly (U, T)."""
    sql_tenant(pg, T1)
    sql_user(pg, U1)
    for n, status in enumerate(("invited", "active", "revoked", "ended")):
        user = fixture_uuid(f"user:1592-rec-status-{n}")
        sql_user(pg, user)
        log = await sql_log(pg)
        sql_member(pg, fixture_uuid(f"membership:1592-rec-status-{n}"), user, T1, status)
        assert await log.since() == one(user, T1), status


async def test_a_membership_update_records_only_a_changed_status(pg):
    """S1-2 (OD-10): `status` to a new value records (U, T); the same value, or another column, records nothing."""
    sql_tenant(pg, T1)
    sql_user(pg, U1)
    sql_member(pg, M1, U1, T1, "invited")
    log = await sql_log(pg)

    execute(pg, "UPDATE identity.memberships SET status = 'revoked' WHERE id = %s", (M1,))
    assert await log.since() == one(U1, T1), "a changed status"
    execute(pg, "UPDATE identity.memberships SET status = 'revoked' WHERE id = %s", (M1,))
    assert await log.since() == one(U1, T1), "the same value recorded again"
    execute(pg, "UPDATE identity.memberships SET expires_at = %s, notify_attempts = 3 WHERE id = %s", (NOW + WEEK, M1))
    assert await log.since() == one(U1, T1), "another column recorded"


async def test_a_tenant_insert_and_a_changed_state_record_the_tenant_and_nothing_else_does(pg):
    """S1-3 (OD-10): INSERT records (none, T); `state` changed records, `state` unchanged and `step` changed do not."""
    log = await sql_log(pg)
    sql_tenant(pg, T1, "creating", CREATING)
    assert await log.since() == one(None, T1), "the insert"

    execute(pg, "UPDATE tenancy.tenants SET state = 'active', pending_action = NULL, step = NULL, step_actor = NULL "
                "WHERE id = %s", (T1,))
    assert await log.since() == one(None, T1, 2), "a changed state"
    execute(pg, "UPDATE tenancy.tenants SET state = 'active' WHERE id = %s", (T1,))
    assert await log.since() == one(None, T1, 2), "the same state recorded again"
    execute(pg, "UPDATE tenancy.tenants SET failure = 'x', repo_url = 'u' WHERE id = %s", (T1,))
    assert await log.since() == one(None, T1, 2), "another column recorded"
    sql_tenant(pg, T2, "creating", CREATING)
    execute(pg, "UPDATE tenancy.tenants SET step = 'repo' WHERE id = %s", (T2,))
    assert await log.since() == collections.Counter({(None, T1): 2, (None, T2): 1}), "a step change recorded"


async def test_a_changed_signed_out_at_records_the_person_and_no_other_user_write_does(pg):
    """S1-4 (OD-10): `signed_out_at` changed records (U, none); unchanged, another column, or an insert, do not."""
    log = await sql_log(pg)
    sql_user(pg, U1)
    assert await log.since() == one(None, None, 0), "a user insert recorded"
    execute(pg, "UPDATE identity.users SET signed_out_at = %s WHERE id = %s", (NOW, U1))
    assert await log.since() == one(U1, None), "a changed signed_out_at"
    execute(pg, "UPDATE identity.users SET signed_out_at = %s WHERE id = %s", (NOW, U1))
    assert await log.since() == one(U1, None), "the same value recorded again"
    execute(pg, "UPDATE identity.users SET status = 'active', display_name = 'Ann', is_platform_admin = true "
                "WHERE id = %s", (U1,))
    assert await log.since() == one(U1, None), "another column recorded"
    execute(pg, "UPDATE identity.users SET signed_out_at = NULL WHERE id = %s", (U1,))
    assert await log.since() == one(U1, None, 2), "clearing the stamp is a change"


def _connection(dsn: str) -> Any:
    import psycopg
    from psycopg.types.string import TextLoader

    conn = psycopg.connect(dsn)
    conn.adapters.register_loader("uuid", TextLoader)
    return conn


async def test_a_request_is_recorded_in_the_writing_transaction_with_that_transactions_time(pg):
    """S1-5 (PP-4): a rolled-back write leaves no request; two writes in one transaction record two rows with
    equal `requested_at`, the transaction's `now()` (not the statement's)."""
    sql_tenant(pg, T1)
    sql_user(pg, U1)
    sql_user(pg, U2)
    log = await sql_log(pg)

    with contextlib.closing(_connection(pg)) as conn:
        conn.execute("UPDATE identity.users SET signed_out_at = %s WHERE id = %s", (NOW, U1))
        conn.rollback()
    assert await log.new() == [], "a rolled-back write recorded a request"

    with contextlib.closing(_connection(pg)) as conn:
        conn.execute("UPDATE identity.users SET signed_out_at = %s WHERE id = %s", (NOW, U1))
        conn.execute("SELECT pg_sleep(0.05)")
        conn.execute("UPDATE identity.users SET signed_out_at = %s WHERE id = %s", (NOW, U2))
        [(transaction_now,)] = conn.execute("SELECT now()").fetchall()
        conn.commit()
    rows = await log.new()
    assert collections.Counter((r.user, r.tenant) for r in rows) == collections.Counter({(U1, None): 1, (U2, None): 1})
    assert {r.requested_at for r in rows} == {transaction_now}, "requested_at is not the transaction's now()"


async def test_every_recorded_request_has_a_fresh_id_in_the_families_format_and_a_row_needs_a_user_or_a_tenant(pg):
    """S1-6: ids are distinct canonical uuid text (`PeopleRequestId`); (null, null) is refused; an unknown `user_id`
    is accepted (no foreign key); both ids may be set."""
    from defender.records.formats import PeopleRequestId

    log = await sql_log(pg)
    sql_tenant(pg, T1)
    sql_user(pg, U1)
    sql_member(pg, M1, U1, T1, "active")
    execute(pg, "UPDATE identity.users SET signed_out_at = %s WHERE id = %s", (NOW, U1))
    execute(pg, "UPDATE identity.memberships SET status = 'ended', ended_at = %s WHERE id = %s", (NOW, M1))
    rows = await log.new()
    assert len(rows) == 4, rows
    ids = [r.id for r in rows]
    assert len(set(ids)) == 4
    for raw in ids:
        assert PeopleRequestId(raw) == raw, "the trigger's id is not the family's canonical text"
        assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", raw), raw

    import psycopg

    with pytest.raises(psycopg.errors.CheckViolation):
        execute(pg, "INSERT INTO tenancy.forge_people_requests (id, user_id, tenant_id, requested_at) "
                    "VALUES (gen_random_uuid(), NULL, NULL, now())")
    execute(pg, "INSERT INTO tenancy.forge_people_requests (id, user_id, tenant_id, requested_at) "
                "VALUES (gen_random_uuid(), %s, NULL, now())", (UNKNOWN_USER,))
    assert (UNKNOWN_USER, None) in {(r.user, r.tenant) for r in requests_sql(pg)}, "an FK on user_id refused it"


# --- the world for both backends (S1-8..11) --------------------------------------------------------


@dataclasses.dataclass
class World:
    """Identity and tenancy over one store: the twins sharing `InMemoryTenantRepository`, or both PostgreSQL
    repositories over one migrated database (`dsn`). Seeders are the contract's own (twin seeders, raw SQL on
    PostgreSQL); they record on both backends."""

    identity: Any
    tenants: Any
    dsn: str | None
    log: RequestLog

    async def mark(self) -> None:
        await self.log.mark()

    async def since(self) -> collections.Counter[Pair]:
        return await self.log.since()

    async def tenant(self, tenant: str, *, state: str = "active", job: PendingJob | None = None) -> None:
        job = job or (CREATING if state == "creating" else (None, None, None))
        if self.dsn is None:
            extra = {k: v for k, v in dict(pending_action=job[0], step=job[1], step_actor=job[2]).items() if v}
            await seed_tenant(self.tenants, tenant, created_at=NOW, state=state, **extra)
        else:
            sql_tenant(self.dsn, tenant, state, job)

    async def person(self, email: str = "ann@x.org") -> Any:
        return await seed_user(self.identity, email, created_at=NOW, status="active", signin_account_id=f"sub-{email}")

    async def member(self, user: Any, tenant: str, status: str = "active") -> Any:
        return await seed_membership(self.identity, user.id, tenant, status=status, invited_by=None, created_at=NOW,
                                     accepted_at=NOW if status in ("active", "ended") else None,
                                     ended_at=NOW if status == "ended" else None)

    async def offboard(self, tenant: str) -> Any:
        if self.dsn is None:
            return await offboard_twin(self.tenants, tenant)
        from defender.tests.support.tenancy._active1214 import offboard_on_database

        return await offboard_on_database(self.dsn, tenant)

    async def session(self, user: Any, value: str) -> None:
        await self.identity.add_session(value, user.id, now=NOW, expires_at=NOW + WEEK)

    def change_behind_the_hold(self, tenant: str) -> None:
        """One fenced column changed under a hold (as #1214's contract stages a fence miss)."""
        if self.dsn is not None:
            execute(self.dsn, "UPDATE tenancy.tenants SET step_actor = 'host' WHERE id = %s", (tenant,))
        else:
            self.tenants._tenants[tenant] = dataclasses.replace(self.tenants._tenants[tenant], step_actor="host")


@contextlib.asynccontextmanager
async def build_world(backend: str) -> AsyncIterator[World]:
    with contextlib.ExitStack() as stack:
        if backend == "memory":
            from defender.identity import InMemoryIdentityRepository
            from defender.tenancy import InMemoryTenantRepository

            tenants: Any = InMemoryTenantRepository()
            identity: Any = InMemoryIdentityRepository(tenants=tenants)
            dsn = None
            log = RequestLog(lambda: requests_port(tenants))
        else:
            from defender.identity.postgres import PostgresIdentityRepository
            from defender.tenancy.postgres import PostgresTenantRepository

            dsn = stack.enter_context(database(migrated=True))
            tenants, identity = PostgresTenantRepository(dsn), PostgresIdentityRepository(dsn)
            log = RequestLog(sql_reader(dsn))
        try:
            yield World(identity, tenants, dsn, log)
        finally:
            await identity.close()
            await tenants.close()


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
async def world(request) -> AsyncIterator[World]:
    async with build_world(request.param) as w:
        yield w


# --- every writer records (S1-8), the seeders too (S1-9) --------------------------------------------


async def _invite(w: World) -> Pair:
    await w.tenant(T1)
    ann = await w.person()
    await w.mark()
    await w.identity.ensure_invitation(ann.id, T1, invited_by=None, now=NOW)
    return str(ann.id), T1


async def _accept(w: World) -> Pair:
    await w.tenant(T1)
    ann = await w.person()
    row = await w.member(ann, T1, status="invited")
    await w.mark()
    assert await w.identity.accept_invitation(row.id, now=NOW) is True
    return str(ann.id), T1


async def _end(w: World) -> Pair:
    await w.tenant(T1)
    ann = await w.person()
    row = await w.member(ann, T1)
    await w.mark()
    assert await w.identity.end_membership(row.id, ended_by=None, now=NOW) is True
    return str(ann.id), T1


async def _revoke(w: World) -> Pair:
    await w.tenant(T1)
    ann = await w.person()
    row = await w.member(ann, T1, status="invited")
    await w.mark()
    assert await w.identity.revoke_invitation(row.id) is True
    return str(ann.id), T1


async def _sign_out(w: World) -> Pair:
    ann = await w.person()
    await w.session(ann, "v")
    await w.mark()
    await w.identity.sign_out(ann.id, "v")
    return str(ann.id), None


async def _request_create(w: World) -> Pair:
    await w.mark()
    record = await w.tenants.request_create(now=NOW, **CREATE_RETENTION)
    return None, str(record.id)


async def _commit_state(w: World) -> Pair:
    await w.tenant(T1, state="creating")
    await w.mark()
    async with w.tenants.lock(T1) as held:
        assert held is not None
        await held.commit(step=None, actor=None, state="active", pending_action=None)
    return None, T1


async def _offboard(w: World) -> Pair:
    """tenancy's `offboard` on the database; its memory form is test support's `offboard_twin`."""
    await w.tenant(T1)
    await w.mark()
    await w.offboard(T1)
    return None, T1


#: The writers by symbol (G33). A writer added later and missing here is not caught by this test (a census by symbol
#: is the design's own check: `contract-first:symbol-refs` over the writers' modules).
WRITERS: dict[str, Callable[[World], Any]] = {
    "IdentityRepository.ensure_invitation": _invite,
    "IdentityRepository.accept_invitation": _accept,
    "IdentityRepository.end_membership": _end,
    "IdentityRepository.revoke_invitation": _revoke,
    "IdentityRepository.sign_out": _sign_out,
    "TenantRepository.request_create": _request_create,
    "HeldTenant.commit(state=)": _commit_state,
    "tenancy.offboard / offboard_twin": _offboard,
}


@pytest.mark.parametrize("writer", sorted(WRITERS))
async def test_census_every_writer_records_exactly_its_request(world: World, writer):
    """S1-8 (OD-8, G33): no exempt list; each writer, on each backend, leaves exactly the request its row names."""
    expected = await WRITERS[writer](world)
    assert await world.since() == one(*expected), f"{writer} recorded {dict(await world.since())}, not {expected}"


async def test_the_seeders_record_like_any_write_a_tenant_a_membership_of_any_status_and_not_a_user(world: World):
    """S1-9 (OD-10): `seed_tenant` / raw SQL records (none, T), a membership of any status (U, T), a user nothing."""
    await world.mark()
    ann = await world.person()
    assert await world.since() == one(None, None, 0), "a user seed recorded"
    await world.tenant(T1)
    assert await world.since() == one(None, T1)
    for status in ("invited", "active", "revoked", "ended"):
        tenant = fixture_uuid(f"tenant:1592-rec-seed-{status}")
        await world.tenant(tenant)
        await world.mark()
        await world.member(ann, tenant, status)
        assert await world.since() == one(str(ann.id), tenant), f"a {status} membership seed"


# --- a write that changes nothing records nothing (S1-10) --------------------------------------------


async def test_a_missed_fence_and_a_membership_that_is_already_ended_record_nothing(world: World):
    """S1-10: `HeldTenant.commit` whose fence missed lands neither the state nor its request; `end_membership` on an
    ended row changes nothing and records nothing."""
    from defender.tenancy import FenceMissed

    await world.tenant(T1, state="creating")
    await world.tenant(T2)
    ann = await world.person()
    row = await world.member(ann, T2, status="ended")
    await world.mark()

    async with world.tenants.lock(T1) as held:
        assert held is not None
        world.change_behind_the_hold(T1)
        with pytest.raises(FenceMissed):
            await held.commit(step=None, actor=None, state="active", pending_action=None)
    assert (await world.tenants.tenant(T1)).state == "creating"
    assert await world.identity.end_membership(row.id, ended_by=None, now=NOW) is False
    assert await world.since() == one(None, None, 0), "a write that changed nothing recorded a request"


async def test_a_commit_that_leaves_the_state_as_it_was_records_nothing(world: World):
    """S1-3 on both backends: a commit of the step alone, or of the state already held, is not a state change."""
    await world.tenant(T1, state="creating")
    await world.mark()
    async with world.tenants.lock(T1) as held:
        assert held is not None
        await held.commit(step="repo", actor="service")
        await held.commit(step="bot", actor="service", state="creating")
    assert await world.since() == one(None, None, 0)


# --- parity (S1-11, cross-slice, owner S1) ---------------------------------------------------------

OPS = ("tenant", "user", "member", "invite", "accept", "end", "revoke", "sign_out", "create", "step", "activate",
       "same_state", "offboard", "end_again")


@dataclasses.dataclass
class Model:
    """Test-side bookkeeping of what exists, so a generated sequence only asks for writes both backends allow."""

    tenants: dict[str, str] = dataclasses.field(default_factory=dict)
    users: dict[str, Any] = dataclasses.field(default_factory=dict)
    members: dict[tuple[str, str], tuple[Any, str]] = dataclasses.field(default_factory=dict)  # live rows
    ended: list[Any] = dataclasses.field(default_factory=list)
    programs: list[Any] = dataclasses.field(default_factory=list)
    credentials: list[Any] = dataclasses.field(default_factory=list)
    #: the last sequence number a `request_set_password` / `request_notification` answered, by user or membership id
    seqs: dict[str, int] = dataclasses.field(default_factory=dict)
    sessions: list[str] = dataclasses.field(default_factory=list)
    attempts: list[str] = dataclasses.field(default_factory=list)


async def _apply(w: World, model: Model, op: str, rng: random.Random, n: int) -> None:  # noqa: C901, PLR0912
    tenant = rng.choice([T1, T2])
    email = rng.choice(["a@x.org", "b@x.org"])
    user = model.users.get(email)
    live = model.members.get((email, tenant))
    state = model.tenants.get(tenant)
    if op == "tenant" and state is None:
        state = rng.choice(["active", "creating"])
        await w.tenant(tenant, state=state)
        model.tenants[tenant] = state
    elif op == "user" and user is None:
        model.users[email] = await w.person(email)
    elif op == "member" and user and state and live is None:
        status = rng.choice(["invited", "active"])
        model.members[(email, tenant)] = (await w.member(user, tenant, status), status)
    elif op == "invite" and user and state == "active":
        row = await w.identity.ensure_invitation(user.id, tenant, invited_by=None, now=NOW)
        if live is None and row is not None:
            model.members[(email, tenant)] = (row, "invited")
    elif op == "accept" and live:
        if await w.identity.accept_invitation(live[0].id, now=NOW):
            model.members[(email, tenant)] = (live[0], "active")
    elif op == "end" and live:
        if await w.identity.end_membership(live[0].id, ended_by=None, now=NOW):
            model.ended.append(live[0])
            del model.members[(email, tenant)]
    elif op == "end_again" and model.ended:
        await w.identity.end_membership(rng.choice(model.ended).id, ended_by=None, now=NOW)
    elif op == "revoke" and live:
        if await w.identity.revoke_invitation(live[0].id):
            del model.members[(email, tenant)]
    elif op == "sign_out" and user:
        await w.session(user, f"v-{n}")
        await w.identity.sign_out(user.id, rng.choice([f"v-{n}", f"none-{n}"]))
    elif op == "create":
        record = await w.tenants.request_create(now=NOW, **CREATE_RETENTION)
        model.tenants[str(record.id)] = "creating"
    elif op in ("step", "activate", "same_state") and state == "creating":
        async with w.tenants.lock(tenant) as held:
            assert held is not None
            if op == "step":
                await held.commit(step="repo", actor="service")
            elif op == "same_state":
                await held.commit(step="bot", actor="service", state="creating")
            else:
                await held.commit(step=None, actor=None, state="active", pending_action=None)
                model.tenants[tenant] = "active"
    elif op == "offboard" and state in ("active", "creating"):
        await w.offboard(tenant)
        model.tenants[tenant] = "offboarding"


# --- the census of the repositories' writes (S1-11: every public write method is a generated op) ---------------------

#: Every public method of the ports that reads only (or opens a hold whose writes are `HeldTenant`'s), so it is no op.
READS = frozenset({
    "IdentityRepository.close", "IdentityRepository.tenant_exists", "IdentityRepository.active_tenants",
    "IdentityRepository.tenant_has_active_members", "IdentityRepository.user", "IdentityRepository.user_by_email",
    "IdentityRepository.user_by_signin_account", "IdentityRepository.platform_admins", "IdentityRepository.membership",
    "IdentityRepository.memberships_of_user", "IdentityRepository.memberships_of_tenant",
    "IdentityRepository.people_of_tenant", "IdentityRepository.active_membership", "IdentityRepository.wanted_tenants",
    "IdentityRepository.wanted_users", "IdentityRepository.program", "IdentityRepository.programs_of_tenant",
    "IdentityRepository.credential_by_id", "IdentityRepository.admit_by_key", "IdentityRepository.admit_by_client",
    "IdentityRepository.admit_by_credential", "IdentityRepository.tenants_of_credentials",
    "IdentityRepository.credentials_of_program", "IdentityRepository.oauth_credentials_to_keep",
    "IdentityRepository.warning_deliveries", "IdentityRepository.session_by_value",
    "IdentityRepository.live_signin_attempts",
    "TenantRepository.close", "TenantRepository.tenant", "TenantRepository.tenants", "TenantRepository.generations",
    "TenantRepository.forge_wiring", "TenantRepository.admission",
    "TenantRepository.alert_mapping", "TenantRepository.current_records", "TenantRepository.claimable",
    "TenantRepository.open_people_requests", "TenantRepository.lock",
    "TenantRepository.evidence_retention",  # #1546 A-O7: the tenant's retention row
    "HeldTenant.generations", "HeldTenant.forge_wiring",
})


def port_methods() -> set[str]:
    """The census: every public method of the identity and tenancy repository ports and of the tenant hold."""
    from defender.identity.ports import IdentityRepository
    from defender.tenancy.repository import HeldTenant, TenantRepository

    return {f"{port.__name__}.{name}" for port in (IdentityRepository, TenantRepository, HeldTenant)
            for name, member in vars(port).items() if not name.startswith("_") and callable(member)}


def _users(m: Model) -> list[Any]:
    return [m.users[e] for e in sorted(m.users)]


def _rows(m: Model) -> list[Any]:
    return [row for row, _status in m.members.values()] + m.ended


def _pick(rng: random.Random, items: list[Any]) -> Any:
    return rng.choice(items) if items else None


def _tenants(m: Model) -> list[str]:
    """T1, T2 and the created tenants in creation order (their ids differ between the backends; their order does not)."""
    return [T1, T2, *(t for t in m.tenants if t not in (T1, T2))]


def _when(rng: random.Random) -> dt.datetime:
    return NOW + dt.timedelta(days=rng.randint(-20, 40), minutes=rng.randint(0, 59))


#: an expiry warning's thresholds (14 and 3 days before expiry) and one that is neither
THRESHOLDS = (dt.timedelta(days=14), dt.timedelta(days=3), dt.timedelta(days=5))


async def _ensure_user(w: World, m: Model, r: random.Random) -> None:
    email = r.choice(["a@x.org", "b@x.org", "c@x.org"])
    user = await w.identity.ensure_user(email, now=NOW)
    m.users.setdefault(email, user)


async def _record_signin_account(w: World, m: Model, r: random.Random) -> None:
    if user := _pick(r, _users(m)):
        await w.identity.record_signin_account(user.id, f"sub-census-{r.randint(0, 3)}")


async def _activate_user(w: World, m: Model, r: random.Random) -> None:
    if user := _pick(r, _users(m)):
        await w.identity.activate_user(user.id, display_name=f"name {r.randint(0, 9)}", now=_when(r))


async def _set_display_name(w: World, m: Model, r: random.Random) -> None:
    if user := _pick(r, _users(m)):
        await w.identity.set_display_name(user.id, f"shown {r.randint(0, 9)}", now=_when(r))


async def _set_platform_admin(w: World, m: Model, r: random.Random) -> None:
    if user := _pick(r, _users(m)):
        await w.identity.set_platform_admin(user.id, r.random() < 0.5)


async def _add_program(w: World, m: Model, r: random.Random) -> None:
    if user := _pick(r, _users(m)):
        m.programs.append(await w.identity.add_program(r.choice([T1, T2]), display_name=f"prog {r.randint(0, 9)}",
                                                       created_by=user.id, now=NOW))


async def _remove_program(w: World, m: Model, r: random.Random) -> None:
    if program := _pick(r, m.programs):
        user = _pick(r, _users(m))
        await w.identity.remove_program(program.id, removed_by=user.id if user else None, now=_when(r))


async def _add_credential(w: World, m: Model, r: random.Random) -> None:
    program, user = _pick(r, m.programs), _pick(r, _users(m))
    if program and user:
        key = r.random() < 0.5
        made = await w.identity.add_credential(
            program.id, kind="key" if key else "oauth_client", name=f"cred {r.randint(0, 9)}", created_by=user.id,
            expires_at=NOW + dt.timedelta(days=r.randint(1, 30)), now=NOW,
            key_hash=hashlib.sha256(f"key-{r.random()}".encode()).hexdigest() if key else None)
        if made is not None:
            m.credentials.append(made)


async def _go_live(w: World, m: Model, r: random.Random) -> None:
    if credential := _pick(r, m.credentials):
        await w.identity.go_live(credential.id, service_account_id=f"sa-{r.randint(0, 3)}",
                                 now=NOW + dt.timedelta(minutes=r.randint(0, 20)))


async def _revoke_credential(w: World, m: Model, r: random.Random) -> None:
    if credential := _pick(r, m.credentials):
        user = _pick(r, _users(m))
        await w.identity.revoke_credential(credential.id, revoked_by=user.id if user else None, now=_when(r))


async def _touch_credential(w: World, m: Model, r: random.Random) -> None:
    if credential := _pick(r, m.credentials):
        await w.identity.touch_credential(credential.id, now=_when(r))


async def _revoke_stale_pending(w: World, m: Model, r: random.Random) -> None:
    await w.identity.revoke_stale_pending(now=NOW + dt.timedelta(minutes=r.randint(0, 30)))


async def _claim_expiry_warning(w: World, m: Model, r: random.Random) -> None:
    now = _when(r)
    await w.identity.claim_expiry_warning(now=now, hold_until=now + dt.timedelta(minutes=5))


async def _settle_expiry_warning(w: World, m: Model, r: random.Random) -> None:
    if credential := _pick(r, m.credentials):
        await w.identity.settle_expiry_warning(credential.id, r.choice(THRESHOLDS))


async def _defer_expiry_warning(w: World, m: Model, r: random.Random) -> None:
    if credential := _pick(r, m.credentials):
        await w.identity.defer_expiry_warning(credential.id, r.choice(THRESHOLDS), until=_when(r))


async def _record_warning_delivery(w: World, m: Model, r: random.Random) -> None:
    credential, user = _pick(r, m.credentials), _pick(r, _users(m))
    if credential and user:
        await w.identity.record_warning_delivery(credential.id, r.choice(THRESHOLDS), user.id, sent_at=_when(r))


def _invitees(m: Model) -> list[Any]:
    """Users with an invited row: where a settled set-password's `expires_at` lands (a membership write, not status)."""
    invited = {str(row.user_id) for row in _invited(m)}
    return [u for u in _users(m) if str(u.id) in invited]


async def _request_set_password(w: World, m: Model, r: random.Random) -> None:
    if user := _prefer(r, _invitees(m), _users(m)):
        m.seqs[str(user.id)] = await w.identity.request_set_password(user.id, now=_when(r))


def _invited(m: Model) -> list[Any]:
    return [row for row, status in m.members.values() if status == "invited"]


def _prefer(r: random.Random, likely: list[Any], every: list[Any]) -> Any:
    """Mostly one of `likely` (the rows or users a write can apply to), sometimes any of `every`."""
    return _pick(r, likely) if likely and r.random() < 0.8 else _pick(r, every)


async def _request_notification(w: World, m: Model, r: random.Random) -> None:
    if row := _prefer(r, _invited(m), _rows(m)):
        m.seqs[str(row.id)] = await w.identity.request_notification(row.id, now=_when(r))


async def _claim_set_password(w: World, m: Model, r: random.Random) -> None:
    now = _when(r) if r.random() < 0.3 else NOW + dt.timedelta(days=60)
    await w.identity.claim_set_password(now=now, hold_until=now + dt.timedelta(minutes=r.randint(1, 30)))


async def _claim_notification(w: World, m: Model, r: random.Random) -> None:
    """Mostly at a time after every requested send, so a requested invited row is due and its next try moves."""
    now = _when(r) if r.random() < 0.3 else NOW + dt.timedelta(days=60)
    await w.identity.claim_notification(now=now, hold_until=now + dt.timedelta(minutes=r.randint(1, 30)))


async def _defer_set_password(w: World, m: Model, r: random.Random) -> None:
    if user := _pick(r, _users(m)):
        await w.identity.defer_set_password(user.id, until=_when(r))


async def _defer_notification(w: World, m: Model, r: random.Random) -> None:
    if row := _pick(r, _rows(m)):
        await w.identity.defer_notification(row.id, until=_when(r))


async def _settle_set_password(w: World, m: Model, r: random.Random) -> None:
    """With an `expires_at` it moves the user's invited rows' expiry: a membership write that is not of `status`."""
    requested = [u for u in _users(m) if str(u.id) in m.seqs]
    if user := _prefer(r, [u for u in requested if u in _invitees(m)] or requested, _users(m)):
        await w.identity.settle_set_password(user.id, m.seqs.get(str(user.id), 0) + (r.random() < 0.2),
                                             sent_at=_when(r) if r.random() < 0.7 else None,
                                             expires_at=_when(r) if r.random() < 0.7 else None)


async def _settle_notification(w: World, m: Model, r: random.Random) -> None:
    if row := _prefer(r, [row for row in _rows(m) if str(row.id) in m.seqs], _rows(m)):
        await w.identity.settle_notification(row.id, m.seqs.get(str(row.id), 0) + (r.random() < 0.2),
                                             sent_at=_when(r) if r.random() < 0.7 else None,
                                             expires_at=_when(r) if r.random() < 0.7 else None)


async def _add_session(w: World, m: Model, r: random.Random) -> None:
    if user := _pick(r, _users(m)):
        value = f"census-{len(m.sessions)}"
        await w.identity.add_session(value, user.id, now=NOW, expires_at=NOW + dt.timedelta(days=r.randint(-1, 7)),
                                     used_otp=r.random() < 0.5)
        m.sessions.append(value)


async def _touch_session(w: World, m: Model, r: random.Random) -> None:
    if value := _pick(r, m.sessions):
        await w.identity.touch_session(value, now=_when(r))


async def _purge_expired_sessions(w: World, m: Model, r: random.Random) -> None:
    await w.identity.purge_expired_sessions(now=_when(r), idle_since=_when(r))


async def _add_signin_attempt(w: World, m: Model, r: random.Random) -> None:
    from defender.identity.models import SignInAttempt

    state = f"state-{r.randint(0, 3)}"  # a state already stored is refused on both backends
    await w.identity.add_signin_attempt(SignInAttempt(
        state=state, token_hash=hashlib.sha256(f"token-{state}".encode()).hexdigest(), nonce=f"n-{state}",
        verifier=f"v-{state}", return_path="/", expires_at=_when(r)))
    m.attempts.append(state)


async def _take_signin_attempt(w: World, m: Model, r: random.Random) -> None:
    if state := _pick(r, m.attempts):
        await w.identity.take_signin_attempt(state, f"token-{state}" if r.random() < 0.7 else "wrong", now=_when(r))


async def _purge_expired_signin_attempts(w: World, m: Model, r: random.Random) -> None:
    await w.identity.purge_expired_signin_attempts(now=_when(r))


async def _request_resume(w: World, m: Model, r: random.Random) -> None:
    await w.tenants.request_resume(r.choice(_tenants(m)))


async def _request_rotate(w: World, m: Model, r: random.Random) -> None:
    await w.tenants.request_rotate(r.choice(_tenants(m)))


async def _set_evidence_retention(w: World, m: Model, r: random.Random) -> None:
    """#1546 A-O7: the retention row is no people change (no trigger on `tenancy.evidence_retention`)."""
    from defender.tenancy import EvidenceRetention

    kept = EvidenceRetention(investigation_days=r.randint(30, 730), learning_days=r.randint(30, 730))
    await w.tenants.set_evidence_retention(r.choice([T1, T2]), kept)


async def _fail(w: World, m: Model, r: random.Random) -> None:
    tenant = r.choice(_tenants(m))
    async with w.tenants.lock(tenant) as held:
        if held is not None:
            await held.fail(f"failed {r.randint(0, 9)}", step="repo", actor="service")


async def _edit_people_requests(w: World, m: Model, r: random.Random) -> None:
    user = _pick(r, _users(m))
    pair = r.choice([(user.id if user else None, r.choice([T1, T2])), (None, r.choice([T1, T2])),
                     (user.id if user else None, None), (None, None)])
    await w.tenants.edit_people_requests(add=[pair])


async def _people_lock(w: World, m: Model, r: random.Random) -> None:
    await w.tenants.people_lock()


#: Each write method of the census and the ops that call it: the hand-written sequence ops above (`OPS`) for the
#: status and state writers, one generator each for the rest.
GENERATED: dict[str, Callable[[World, Model, random.Random], Any]] = {
    "IdentityRepository.ensure_user": _ensure_user,
    "IdentityRepository.record_signin_account": _record_signin_account,
    "IdentityRepository.activate_user": _activate_user,
    "IdentityRepository.set_display_name": _set_display_name,
    "IdentityRepository.set_platform_admin": _set_platform_admin,
    "IdentityRepository.add_program": _add_program,
    "IdentityRepository.remove_program": _remove_program,
    "IdentityRepository.add_credential": _add_credential,
    "IdentityRepository.go_live": _go_live,
    "IdentityRepository.revoke_credential": _revoke_credential,
    "IdentityRepository.touch_credential": _touch_credential,
    "IdentityRepository.revoke_stale_pending": _revoke_stale_pending,
    "IdentityRepository.claim_expiry_warning": _claim_expiry_warning,
    "IdentityRepository.settle_expiry_warning": _settle_expiry_warning,
    "IdentityRepository.defer_expiry_warning": _defer_expiry_warning,
    "IdentityRepository.record_warning_delivery": _record_warning_delivery,
    "IdentityRepository.request_set_password": _request_set_password,
    "IdentityRepository.request_notification": _request_notification,
    "IdentityRepository.claim_set_password": _claim_set_password,
    "IdentityRepository.claim_notification": _claim_notification,
    "IdentityRepository.defer_set_password": _defer_set_password,
    "IdentityRepository.defer_notification": _defer_notification,
    "IdentityRepository.settle_set_password": _settle_set_password,
    "IdentityRepository.settle_notification": _settle_notification,
    "IdentityRepository.add_session": _add_session,
    "IdentityRepository.touch_session": _touch_session,
    "IdentityRepository.purge_expired_sessions": _purge_expired_sessions,
    "IdentityRepository.add_signin_attempt": _add_signin_attempt,
    "IdentityRepository.take_signin_attempt": _take_signin_attempt,
    "IdentityRepository.purge_expired_signin_attempts": _purge_expired_signin_attempts,
    "TenantRepository.request_resume": _request_resume,
    "TenantRepository.request_rotate": _request_rotate,
    "TenantRepository.set_evidence_retention": _set_evidence_retention,  # #1546 A-O7
    "TenantRepository.edit_people_requests": _edit_people_requests,
    "TenantRepository.people_lock": _people_lock,
    "HeldTenant.fail": _fail,
}
#: The write methods `_apply`'s ops call.
BY_OPS: dict[str, tuple[str, ...]] = {
    "IdentityRepository.ensure_invitation": ("invite",), "IdentityRepository.accept_invitation": ("accept",),
    "IdentityRepository.end_membership": ("end", "end_again"), "IdentityRepository.revoke_invitation": ("revoke",),
    "IdentityRepository.sign_out": ("sign_out",), "TenantRepository.request_create": ("create",),
    "HeldTenant.commit": ("step", "activate", "same_state"),
}
#: Every op of a generated sequence: the seeders and status writers of `OPS`, then one per generated write method.
ALL_OPS = (*OPS, *sorted(GENERATED))


def test_the_sequences_call_every_write_method_of_the_ports():
    """S1-11's census: each public method of the identity and tenancy ports (and the tenant hold) is a read or has a
    generator; a write added later without one fails here."""
    census = port_methods()
    unclassified = census - READS - set(GENERATED) - set(BY_OPS)
    assert unclassified == set(), f"write methods with no generator (or reads not listed): {sorted(unclassified)}"
    assert (READS | set(GENERATED) | set(BY_OPS)) - census == set(), "classified names the ports do not have"
    assert not READS & (set(GENERATED) | set(BY_OPS))
    assert not set(GENERATED) & set(BY_OPS)
    assert {op for ops in BY_OPS.values() for op in ops} <= set(OPS)


def _outcome(error: BaseException | None) -> str | None:
    return None if error is None else type(error).__name__


async def run_sequence(backend: str, seed: int, length: int = 40,
                       ops: tuple[str, ...] = OPS) -> tuple[collections.Counter[Pair], list[tuple[Any, ...]]]:
    """The requests a seeded op sequence leaves, as a multiset of (user, tenant) with each user and generated tenant
    named by its role (ids differ between backends: users are minted by the seeders, created tenants by the store),
    and its trace: each op with the exception it raised (or none) and the requests it recorded."""
    rng = random.Random(seed)  # noqa: S311 — generated cases, not secrets
    async with build_world(backend) as w:
        model = Model()

        async def recorded() -> collections.Counter[Pair]:
            users = {str(u.id): email for email, u in model.users.items()}
            created = {t for t in model.tenants if t not in (T1, T2)}
            rows = await w.log._read()  # noqa: SLF001 — every request, the seeds included (the baseline stays empty)
            return collections.Counter(
                (users.get(r.user, r.user), "created" if r.tenant in created else r.tenant) for r in rows)

        trace: list[tuple[Any, ...]] = []
        before = await recorded()
        for n in range(length):
            generated = [o for o in ops if o not in OPS]  # half the draws stay on the seeders and status writers
            op = rng.choice(generated) if generated and rng.random() < 0.5 else rng.choice(OPS)
            sub = random.Random(rng.getrandbits(64))  # noqa: S311 — one stream per op, so a skipped op shifts nothing
            error: BaseException | None = None
            try:
                if op in OPS:
                    await _apply(w, model, op, sub, n)
                else:
                    await GENERATED[op](w, model, sub)
            except Exception as raised:  # noqa: BLE001 — the refusal itself is compared between the backends
                error = raised
            after = await recorded()
            trace.append((n, op, _outcome(error), sorted((after - before).items(), key=str),
                          sorted((before - after).items(), key=str)))
            before = after
        return before, trace


@pytest.mark.postgres
@pytest.mark.parametrize("seed", range(60))
async def test_generated_write_sequences_leave_the_same_requests_on_the_twin_and_on_postgresql(seed):
    """S1-11 (cross-slice): seeds included, a generated sequence over every write method of the ports (the census above)
    records the same requests in memory and on PostgreSQL at each op, or raises the same refusal, same-value writes (a
    state set to itself, a membership ended again) and non-status writes (a notification's claim, an expiry) among them."""
    twin, twin_trace = await run_sequence("memory", seed, length=120, ops=ALL_OPS)
    database_, database_trace = await run_sequence("postgres", seed, length=120, ops=ALL_OPS)
    for mine, theirs in zip(twin_trace, database_trace, strict=True):
        assert mine == theirs, f"seed {seed}: in memory {mine}, on PostgreSQL {theirs}"
    assert twin == database_, f"seed {seed}: only in memory {twin - database_}, only on PostgreSQL {database_ - twin}"
    assert sum(twin.values()), "control: the sequence recorded nothing, so it compares nothing"
