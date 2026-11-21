"""#1592: people planted in a migrated database as the identity repository stores them, for the readers of
`wanted_users` (feedback's default seam, the synchronous wrapper). Test support: it plants rows, it decides nothing."""
from __future__ import annotations

import asyncio
import datetime as dt

from defender.identity.models import MembershipStatus
from defender.identity.postgres import PostgresIdentityRepository
from defender.records.formats import TenantId, UserId
from defender.tests.support.identity._seed1496 import seed_membership, seed_user

NOW = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.UTC)


async def _plant(dsn: str, tenant_id: str, email: str, status: MembershipStatus) -> str:
    repo = PostgresIdentityRepository(dsn)
    try:
        user = await seed_user(repo, email, created_at=NOW, status="active")
        fields: dict = {}
        if status in ("active", "ended"):
            fields["accepted_at"] = NOW
        if status == "ended":
            fields["ended_at"] = NOW
        await seed_membership(repo, UserId(str(user.id)), TenantId(tenant_id), status=status, invited_by=None,
                              created_at=NOW, **fields)
        return str(user.id)
    finally:
        await repo.close()


def plant_member(dsn: str, tenant_id: str, email: str, status: MembershipStatus = "active") -> str:
    """A user with one membership of `tenant_id` in `status`; the user's id."""
    return asyncio.run(_plant(dsn, tenant_id, email, status))
