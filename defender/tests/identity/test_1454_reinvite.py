# ruff: noqa: F811  — the #1306 contract's fixtures are imported, as in test_1307_repository_contract.py
"""#1454 P-L for an invitee who already has a live row in the tenant: `ensure_invitation` holds the tenant `active` whatever the
person's state, not only when it inserts a row. A person already `invited` or already `active` in a tenant that left `active`
is refused with `TenantNotActive`, not answered with the old row (invited) or None (active), in both repositories; and in
PostgreSQL the refusal waits for an uncommitted offboard on the tenant row, as the insert does (C14)."""
from __future__ import annotations

import asyncio

import pytest

from defender.tests.identity.test_1307_repository_contract import _active, _invited, _user
from defender.tests.identity.test_identity_repository_contract import (  # noqa: F401  (fixtures)
    NOW,
    T1,
    T2,
    backend,
    pg_dsn,
    repo,
    seeded,
    tenants,
    two_repositories,
)
from defender.tests.support.identity._tenant_states1454 import NOT_ACTIVE, leave_active
from defender.tests.support.shared._pglocks1339 import TIMEOUT, until_blocked

pytestmark = pytest.mark.anyio

WHO = ["invited", "active"]



@pytest.mark.parametrize("state", NOT_ACTIVE)
@pytest.mark.parametrize("who", WHO)
async def test_inviting_a_person_who_already_has_a_live_row_in_a_tenant_that_left_active_is_refused(
        seeded, backend, tenants, state, who):
    """The invitee is `invited` (bob) or `active` (cy) in T2 when T2 leaves `active`: `ensure_invitation` raises `TenantNotActive`
    and the row stays as it was; in T1, which stays active, the same re-invitation answers as before (the row / None) (P-L)."""
    from defender.identity import TenantNotActive

    ann, bob, cy = await _user(seeded), await _user(seeded, "bob@x.org"), await _user(seeded, "cy@x.org")
    invitee = bob if who == "invited" else cy
    here = await (_invited(seeded, invitee, T1) if who == "invited" else _active(seeded, invitee, T1))
    there = await (_invited(seeded, invitee, T2) if who == "invited" else _active(seeded, invitee, T2))
    await leave_active(backend, tenants, T2, state)
    with pytest.raises(TenantNotActive):
        await seeded.ensure_invitation(invitee.id, T2, invited_by=ann.id, now=NOW)
    assert (await seeded.membership(there.id)).status == who
    assert [m.id for m in await seeded.memberships_of_tenant(T2)] == [there.id]
    again = await seeded.ensure_invitation(invitee.id, T1, invited_by=ann.id, now=NOW)  # control: an active tenant
    assert (again.id if again is not None else None) == (here.id if who == "invited" else None)


@pytest.mark.postgres
@pytest.mark.parametrize("who", WHO)
async def test_a_re_invitation_waits_for_an_uncommitted_offboard_then_is_refused(two_repositories, pg_dsn, who):
    """C14, offboard first (transaction still open), for an invitee already `invited` / `active`: the re-invitation blocks on the
    tenant row, then raises `TenantNotActive` once the offboard commits; the row stays as it was (P-L)."""
    from defender.identity import TenantNotActive
    from defender.database import async_engine
    from defender.tenancy.models import offboard

    one, _ = two_repositories
    ann, bob = await _user(one), await _user(one, "bob@x.org")
    row = await (_invited(one, bob) if who == "invited" else _active(one, bob))
    engine = async_engine(pg_dsn)
    try:
        async with engine.begin() as conn:
            assert (await offboard(conn, T1)).state == "offboarding"
            attempt = asyncio.ensure_future(one.ensure_invitation(bob.id, T1, invited_by=ann.id, now=NOW))
            await until_blocked(pg_dsn, 1)  # it waits on the tenant row, though it would insert nothing
            assert not attempt.done()
        with pytest.raises(TenantNotActive):
            await asyncio.wait_for(attempt, TIMEOUT)
        assert (await one.membership(row.id)).status == who
    finally:
        await engine.dispose()
