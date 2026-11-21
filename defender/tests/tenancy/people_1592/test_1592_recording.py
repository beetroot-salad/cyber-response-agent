"""#1592 r12 "Who records a request": every write of a membership's status or a tenant's state, and every product
sign-out, records a people request in the same transaction, inside the owner's method, on both twins (OD-8, PP-4).

One representative writer of each kind, then the census over every G33 writer. The PostgreSQL run is marked
`postgres`; it reads the requests by SQL on the pinned table, the twin through `_spec1592.requests_twin` (FC-1).
"""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
from collections.abc import AsyncIterator
from typing import Any

import pytest

from defender.tests.support.identity._seed1496 import seed_membership, seed_user
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import database, execute
from defender.tests.support.tenancy._twin1496 import offboard_twin, seed_tenant
from defender.tests.tenancy.people_1592._spec1592 import pairs, requests_port, requests_sql

pytestmark = pytest.mark.anyio

NOW = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.UTC)
T1 = fixture_uuid("tenant:1592-rec-1")
T2 = fixture_uuid("tenant:1592-rec-2")


@dataclasses.dataclass
class Twins:
    """Identity and tenancy over one store: the twins sharing `InMemoryTenantRepository`, or both PostgreSQL
    repositories over one migrated database (`dsn`)."""

    identity: Any
    tenants: Any
    dsn: str | None

    async def requests(self) -> list[tuple[str | None, str | None]]:
        rows = requests_sql(self.dsn) if self.dsn is not None else await requests_port(self.tenants)
        return sorted(pairs(rows).elements(), key=str)

    async def tenant(self, tenant: str, *, state: str = "active", pending: tuple = (None, None, None)) -> None:
        """A tenant row as written, not requested (neither seeder is a writer under census)."""
        action, step, actor = pending
        if self.dsn is None:
            extra = {k: v for k, v in dict(pending_action=action, step=step, step_actor=actor).items() if v}
            await seed_tenant(self.tenants, tenant, created_at=NOW, state=state, **extra)
            return
        execute(self.dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                             VALUES (%s, %s, %s, %s, %s, %s)""", (tenant, NOW, state, action, step, actor))

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

    def change_behind_the_hold(self, tenant: str) -> None:
        """One fenced column changed under a hold (as #1214's contract stages a fence miss)."""
        if self.dsn is not None:
            execute(self.dsn, "UPDATE tenancy.tenants SET step_actor = 'host' WHERE id = %s", (tenant,))
        else:
            self.tenants._tenants[tenant] = dataclasses.replace(self.tenants._tenants[tenant], step_actor="host")


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
async def twins(request) -> AsyncIterator[Twins]:
    with contextlib.ExitStack() as stack:
        if request.param == "memory":
            from defender.identity import InMemoryIdentityRepository
            from defender.tenancy import InMemoryTenantRepository

            tenants: Any = InMemoryTenantRepository()
            world = Twins(InMemoryIdentityRepository(tenants=tenants), tenants, None)
        else:
            from defender.identity.postgres import PostgresIdentityRepository
            from defender.tenancy.postgres import PostgresTenantRepository

            dsn = stack.enter_context(database(migrated=True))
            world = Twins(PostgresIdentityRepository(dsn), PostgresTenantRepository(dsn), dsn)
        try:
            yield world
        finally:
            await world.identity.close()
            await world.tenants.close()


# --- one writer of each kind ---------------------------------------------------------------------


async def test_ending_a_membership_records_the_person_in_that_tenant(twins: Twins):
    """`end_membership` writes `memberships.status`, so its transaction records (U, T): nothing else, no other tenant."""
    await twins.tenant(T1)
    await twins.tenant(T2)
    ann = await twins.person()
    row = await twins.member(ann, T1)
    await twins.member(ann, T2)
    assert (await twins.requests()) == [], "control: seeding is not a writer under census"

    assert await twins.identity.end_membership(row.id, ended_by=None, now=NOW) is True
    assert (await twins.requests()) == [(str(ann.id), T1)]


async def test_sign_out_deletes_the_session_stamps_signed_out_at_and_records_the_person(twins: Twins):
    """`sign_out(user, session value)` replaces `delete_session`: the product session is gone, `signed_out_at` is set
    (database time) and (U, none) is recorded, in one transaction. Another device's session stays."""
    await twins.tenant(T1)
    ann = await twins.person()
    await twins.member(ann, T1)
    for device in ("device-1", "device-2"):
        await twins.identity.add_session(device, ann.id, now=NOW, expires_at=NOW + dt.timedelta(days=7))
    assert (await twins.identity.user(ann.id)).signed_out_at is None

    await twins.identity.sign_out(ann.id, "device-1")

    assert await twins.identity.session_by_value("device-1") is None
    assert (await twins.identity.session_by_value("device-2")).user_id == ann.id
    assert (await twins.identity.user(ann.id)).signed_out_at is not None
    assert (await twins.requests()) == [(str(ann.id), None)]
    assert not hasattr(twins.identity, "delete_session"), "sign_out replaces delete_session in the port and both twins"


async def test_a_state_commit_records_the_tenant_and_a_missed_fence_records_nothing(twins: Twins):
    """`HeldTenant.commit(state=…)` records (none, T) from the fence's own rows: the activation lands with its request;
    a commit whose fence misses lands neither."""
    from defender.tenancy import FenceMissed

    await twins.tenant(T1, state="creating", pending=("create", "activate", "service"))
    await twins.tenant(T2, state="creating", pending=("create", "activate", "service"))

    async with twins.tenants.lock(T1) as held:
        assert held is not None
        await held.commit(step=None, actor=None, state="active", pending_action=None)
    assert (await twins.requests()) == [(None, T1)]

    async with twins.tenants.lock(T2) as held:
        assert held is not None
        twins.change_behind_the_hold(T2)
        with pytest.raises(FenceMissed):
            await held.commit(step=None, actor=None, state="active", pending_action=None)
    assert (await twins.tenants.tenant(T2)).state == "creating"
    assert (await twins.requests()) == [(None, T1)], "a missed fence recorded a request"


# --- the census (G33): every writer of memberships.status and tenants.state records ------------------


async def _invite(twins: Twins) -> tuple[str | None, str | None]:
    await twins.tenant(T1)
    ann = await twins.person()
    await twins.identity.ensure_invitation(ann.id, T1, invited_by=None, now=NOW)
    return str(ann.id), T1


async def _accept(twins: Twins) -> tuple[str | None, str | None]:
    await twins.tenant(T1)
    ann = await twins.person()
    row = await twins.member(ann, T1, status="invited")
    assert await twins.identity.accept_invitation(row.id, now=NOW) is True
    return str(ann.id), T1


async def _end(twins: Twins) -> tuple[str | None, str | None]:
    await twins.tenant(T1)
    ann = await twins.person()
    row = await twins.member(ann, T1)
    assert await twins.identity.end_membership(row.id, ended_by=None, now=NOW) is True
    return str(ann.id), T1


async def _revoke(twins: Twins) -> tuple[str | None, str | None]:
    await twins.tenant(T1)
    ann = await twins.person()
    row = await twins.member(ann, T1, status="invited")
    assert await twins.identity.revoke_invitation(row.id) is True
    return str(ann.id), T1


async def _sign_out(twins: Twins) -> tuple[str | None, str | None]:
    ann = await twins.person()
    await twins.identity.add_session("v", ann.id, now=NOW, expires_at=NOW + dt.timedelta(days=7))
    await twins.identity.sign_out(ann.id, "v")
    return str(ann.id), None


async def _request_create(twins: Twins) -> tuple[str | None, str | None]:
    record = await twins.tenants.request_create(now=NOW)
    return None, str(record.id)


async def _commit_state(twins: Twins) -> tuple[str | None, str | None]:
    await twins.tenant(T1, state="creating", pending=("create", "activate", "service"))
    async with twins.tenants.lock(T1) as held:
        await held.commit(step=None, actor=None, state="active", pending_action=None)
    return None, T1


async def _offboard(twins: Twins) -> tuple[str | None, str | None]:
    """tenancy's `offboard` on the database; its in-memory form is test support's `offboard_twin` (FC-6)."""
    await twins.tenant(T1)
    await twins.offboard(T1)
    return None, T1


#: The writers by symbol (G33). FC-7: how a writer added later and missing from this list is caught is not designed.
WRITERS = {
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
async def test_census_every_writer_records_its_request(twins: Twins, writer):
    """OD-8: no exempt list. Each writer, on each twin, leaves exactly the request its row names."""
    expected = await WRITERS[writer](twins)
    assert (await twins.requests()) == [expected], f"{writer} recorded {(await twins.requests())}, not {expected}"
