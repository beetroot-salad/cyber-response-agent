# ruff: noqa: F811  — the #1306 contract's fixture is imported, as in test_1307_repository_contract.py
"""#1454 P-L: `tenancy.models.share_tenant(executor, tenant_id) -> state | None`, the one owner of the tenant share lock that
every identity write making something live in a tenant (and the jobs store) takes. PostgreSQL only: the lock is a row lock."""
from __future__ import annotations

import asyncio

import pytest

from defender.tests.identity.test_identity_repository_contract import NOW, pg_dsn  # noqa: F401  (fixture)
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._pglocks1339 import TIMEOUT, until_blocked
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

#: One row per state, each with a pending action its state allows (as test_tenant_seam's).
ROWS = {"creating": ("create", "provider", "service"), "active": (None, None, None),
        "offboarding": ("offboard", "offboard", "service"), "offboarded": (None, None, None)}
ABSENT = fixture_uuid("tenant:1454-share-absent")


def _seed(dsn: str, state: str) -> str:
    tenant = fixture_uuid(f"tenant:1454-share-{state}")
    action, step, actor = ROWS[state]
    execute(dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                    VALUES (%s, %s, %s, %s, %s, %s)""", (tenant, NOW, state, action, step, actor))
    return tenant


async def test_share_tenant_answers_the_tenants_state_and_none_for_an_absent_tenant(pg_dsn):
    """It returns each state's name, and None where there is no row (an absent tenant reads as not active) (P-L)."""
    from defender.database import async_engine
    from defender.tenancy.models import share_tenant

    tenants = {state: _seed(pg_dsn, state) for state in ROWS}
    engine = async_engine(pg_dsn)
    try:
        async with engine.begin() as conn:
            got = {state: await share_tenant(conn, tenant) for state, tenant in tenants.items()}
            assert got == {state: state for state in ROWS}
            assert await share_tenant(conn, ABSENT) is None
    finally:
        await engine.dispose()


async def test_a_held_share_makes_the_offboard_wait_and_two_shares_do_not_wait_for_each_other(pg_dsn):
    """While one transaction shares the tenant, another share goes through at once and the offboard write waits until the first ends (P-L)."""
    from defender.database import async_engine
    from defender.tenancy.models import offboard, share_tenant

    tenant = _seed(pg_dsn, "active")
    engine = async_engine(pg_dsn)

    async def leaving():
        async with engine.begin() as conn:
            return await offboard(conn, tenant)

    try:
        async with engine.begin() as holder:
            assert await share_tenant(holder, tenant) == "active"
            async with engine.begin() as other:
                assert await asyncio.wait_for(share_tenant(other, tenant), TIMEOUT) == "active"  # control: shares agree
            leave = asyncio.ensure_future(leaving())
            await until_blocked(pg_dsn, 1)
            assert not leave.done()
        assert (await asyncio.wait_for(leave, TIMEOUT)).state == "offboarding"
    finally:
        await engine.dispose()


async def test_a_share_taken_while_the_offboard_is_uncommitted_waits_and_then_reads_the_new_state(pg_dsn):
    """The other order: the share waits for the offboard's transaction and then answers `offboarding`, never the state it started from (C14, P-L)."""
    from defender.database import async_engine
    from defender.tenancy.models import offboard, share_tenant

    tenant = _seed(pg_dsn, "active")
    engine = async_engine(pg_dsn)

    async def sharing():
        async with engine.begin() as conn:
            return await share_tenant(conn, tenant)

    try:
        async with engine.begin() as conn:
            await offboard(conn, tenant)
            share = asyncio.ensure_future(sharing())
            await until_blocked(pg_dsn, 1)
            assert not share.done()
        assert await asyncio.wait_for(share, TIMEOUT) == "offboarding"
    finally:
        await engine.dispose()
