"""#1454 test support: move a tenant out of `active` in either repository, the way production does.

A tenant is seeded `active`, programs and invitations are made in it, and only then does it leave: no create ever
lands in a `creating` tenant (P-L). `offboarding` is tenancy's own request; `offboarded` is the end of the teardown.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.tenancy._active1214 import offboard_tenant_row

LEFT_AT = dt.datetime(2026, 10, 26, 12, 0, tzinfo=dt.UTC)
#: The states a tenant reaches after `active`; the standing rule and P-L treat both the same.
NOT_ACTIVE = ("offboarding", "offboarded")


async def leave_active(backend: str | None, tenants: Any, tenant: str, state: str) -> None:
    """Move the `active` tenant `tenant` to `offboarding` or `offboarded`.

    `backend` is None for the in-memory pair (`tenants` is the tenant twin the identity twin reads), else the DSN of a
    migrated database (`tenants` is unused there).
    """
    assert state in NOT_ACTIVE, state
    if backend is None:
        await offboard_tenant_row(tenants, tenant)
        if state == "offboarded":
            async with tenants.lock(tenant) as held:
                await held.commit(step=None, actor=None, state="offboarded", pending_action=None, offboarded_at=LEFT_AT)
        return
    from defender.tenancy.postgres import PostgresTenantRepository

    tenancy = PostgresTenantRepository(backend)
    try:
        await offboard_tenant_row(tenancy, tenant)
    finally:
        await tenancy.close()
    if state == "offboarded":
        execute(backend, """UPDATE tenancy.tenants SET state = 'offboarded', pending_action = NULL, step = NULL,
                            step_actor = NULL, offboarded_at = %s WHERE id = %s""", (LEFT_AT, str(tenant)))
