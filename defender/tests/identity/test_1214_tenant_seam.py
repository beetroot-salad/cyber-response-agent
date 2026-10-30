"""#1214 identity seam (r9 DC-6): identity reads tenant state from the tenant store. `tenant_exists` means present and
`active`, on the in-memory twin (which shares the tenant twin's store) and on PostgreSQL (`tenancy.tenants`).
No port has `register_tenant`; tenant rows come from the tenant repository."""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
from collections.abc import AsyncIterator
from typing import Any

import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import database, execute

pytestmark = pytest.mark.anyio

NOW = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.UTC)
#: One row per state, each with a pending action its state allows (data model).
ROWS = {
    "creating": ("create", "provider", "service"),
    "active": (None, None, None),
    "offboarding": ("offboard", "offboard", "service"),
    "offboarded": (None, None, None),
}
EXPECTED = {"creating": False, "active": True, "offboarding": False, "offboarded": False}
T1 = fixture_uuid("tenant:1214-seam-1")
ABSENT = fixture_uuid("tenant:1214-seam-absent")


@dataclasses.dataclass
class World:
    """An identity repository and the tenant repository it reads, over one backend."""

    identity: Any
    tenants: Any
    dsn: str | None

    async def seed(self, tenant: str, state: str = "active") -> None:
        action, step, actor = ROWS[state]
        if self.dsn is None:
            extra = {} if action is None else dict(pending_action=action, step=step, step_actor=actor)
            await self.tenants.add_tenant(tenant, created_at=NOW, state=state, **extra)
        else:
            execute(self.dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                                 VALUES (%s, %s, %s, %s, %s, %s)""", (tenant, NOW, state, action, step, actor))


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
async def world(request) -> AsyncIterator[World]:
    with contextlib.ExitStack() as stack:
        if request.param == "memory":
            from defender.identity import InMemoryIdentityRepository
            from defender.tenancy import InMemoryTenantRepository

            tenants: Any = InMemoryTenantRepository()
            built = World(InMemoryIdentityRepository(tenants=tenants), tenants, None)
        else:
            from defender.identity.postgres import PostgresIdentityRepository
            from defender.tenancy.postgres import PostgresTenantRepository

            dsn = stack.enter_context(database(migrated=True))
            built = World(PostgresIdentityRepository(dsn), PostgresTenantRepository(dsn), dsn)
        try:
            yield built
        finally:
            await built.identity.close()
            if built.dsn is not None:
                await built.tenants.close()


async def test_only_an_active_tenant_exists_for_identity(world):
    """creating, offboarding, offboarded and absent tenants do not exist for identity; an active one does (seam, O4)."""
    ids = {state: fixture_uuid(f"tenant:1214-seam-{state}") for state in ROWS}
    for state, tenant in ids.items():
        await world.seed(tenant, state)
    assert {state: await world.identity.tenant_exists(tenant) for state, tenant in ids.items()} == EXPECTED
    assert await world.identity.tenant_exists(ABSENT) is False


async def test_the_active_tenants_among_several_are_read_at_once(world):
    """`active_tenants(ids)` is `tenant_exists` over a set of ids in one read: only the active ones come back, an absent
    one and an empty set included (seam, O4)."""
    ids = {state: fixture_uuid(f"tenant:1214-seam-{state}") for state in ROWS}
    for state, tenant in ids.items():
        await world.seed(tenant, state)
    assert await world.identity.active_tenants([*ids.values(), ABSENT]) == {ids["active"]}
    assert await world.identity.active_tenants([]) == set()


def test_me_reads_the_tenant_states_once_however_many_memberships():
    """`/me` for a member of three tenants, one of them offboarding: one read of the tenant states, not one per
    membership, and the view still leaves the offboarding tenant out."""
    pytest.importorskip("fastapi")
    from defender.tests.support.api._identity1306 import ANN, BOB, LAB, T1, T2, World

    world = World(tenants={T1: [ANN], T2: [ANN], LAB: [ANN, BOB]})
    try:
        world.call(world.tenants.request_offboard, LAB, now=world.clock())
        reads: list[str] = []
        for name in ("tenant_exists", "active_tenants"):
            real = getattr(world.raw_repo, name, None)
            if real is not None:
                async def counted(*a: Any, _real: Any = real, _name: str = name, **k: Any) -> Any:
                    reads.append(_name)
                    return await _real(*a, **k)
                setattr(world.raw_repo, name, counted)
        browser = world.sign_in(ANN)
        reads.clear()
        me = browser.get("/me")
        assert me.status_code == 200, me.text
        assert {t["tenant_id"] for t in me.json()["tenants"]} == {T1, T2}
        assert len(reads) == 1, reads
    finally:
        world.close()


async def test_offboarding_ends_existence_for_identity_at_once(world):
    """The request that moves an active tenant to offboarding is what identity sees next: no cache, no second step (O4, DC-6)."""
    await world.seed(T1)
    assert await world.identity.tenant_exists(T1) is True
    await world.tenants.request_offboard(T1, now=NOW)
    assert await world.identity.tenant_exists(T1) is False


async def test_a_tenant_created_by_request_is_not_existing_until_active(world):
    """A tenant born of `request_create` is `creating`: identity does not see it as existing (O1, DC-6)."""
    record = await world.tenants.request_create(now=NOW)
    assert await world.identity.tenant_exists(record.id) is False


async def test_accepting_an_invitation_needs_the_tenant_active_in_the_same_statement(world):
    """An invitation of a tenant that went offboarding does not accept; the row stays invited; an active tenant's accepts (DC-6)."""
    other = fixture_uuid("tenant:1214-seam-2")
    for tenant in (T1, other):
        await world.seed(tenant)
    user = await world.identity.add_user("ann@x.org", created_at=NOW)
    kept = await world.identity.ensure_invitation(user.id, T1, invited_by="system", now=NOW)
    live = await world.identity.ensure_invitation(user.id, other, invited_by="system", now=NOW)
    await world.tenants.request_offboard(T1, now=NOW)
    assert await world.identity.accept_invitation(kept.id, now=NOW) is False
    assert (await world.identity.membership(kept.id)).status == "invited"
    assert await world.identity.accept_invitation(live.id, now=NOW) is True  # control: same user, active tenant
    assert (await world.identity.membership(live.id)).status == "active"


async def test_an_identity_twin_built_without_a_tenant_store_has_a_store_of_its_own():
    """Without `tenants=` the identity twin does not see another twin's tenants (DC-6: the shared store is opt-in)."""
    from defender.identity import InMemoryIdentityRepository
    from defender.tenancy import InMemoryTenantRepository

    elsewhere: Any = InMemoryTenantRepository()
    await elsewhere.add_tenant(T1, created_at=NOW, state="active")
    alone = InMemoryIdentityRepository()
    assert await alone.tenant_exists(T1) is False
    sharing = InMemoryIdentityRepository(tenants=elsewhere)  # control: given the store it sees the tenant
    assert await sharing.tenant_exists(T1) is True


async def test_a_tenant_added_after_the_identity_twin_was_built_is_seen():
    """The identity twin shares the tenant twin's store rather than copying it (DC-6, DC-7)."""
    from defender.identity import InMemoryIdentityRepository
    from defender.tenancy import InMemoryTenantRepository

    tenants: Any = InMemoryTenantRepository()
    identity = InMemoryIdentityRepository(tenants=tenants)
    assert await identity.tenant_exists(T1) is False
    await tenants.add_tenant(T1, created_at=NOW, state="active")
    assert await identity.tenant_exists(T1) is True


def test_no_identity_port_registers_a_tenant():
    """`register_tenant` is gone from the service, the protocol and both repositories; tenant rows come from tenancy (DC-6)."""
    from defender.identity import IdentityService, InMemoryIdentityRepository
    from defender.identity import ports
    from defender.identity.postgres import PostgresIdentityRepository

    holders = [IdentityService, InMemoryIdentityRepository, PostgresIdentityRepository,
               *(c for c in vars(ports).values() if isinstance(c, type) and c.__module__ == ports.__name__)]
    from defender.identity import bootstrap

    assert [h.__name__ for h in holders if hasattr(h, "register_tenant")] == []
    assert not hasattr(bootstrap, "register_tenant")  # the helper function that wrapped it
    assert hasattr(InMemoryIdentityRepository, "tenant_exists")  # control: the seam's own method stays


def test_the_bootstrap_has_no_tenants_section():
    """`Bootstrap(administrators=...)` is all there is; a tenants mapping is refused (DC-6, Q3)."""
    from defender.identity import Bootstrap

    assert Bootstrap(administrators=("ops@x.org",)).administrators == ("ops@x.org",)
    with pytest.raises((TypeError, ValueError)):  # a pydantic model refuses an unknown field as ValueError
        Bootstrap(administrators=(), tenants={})  # type: ignore[call-arg]
