"""#1214 identity seam on PostgreSQL: `tenant_exists` reads `tenancy.tenants` and means present and `active`."""
from __future__ import annotations

import datetime as dt

import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import database, execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

NOW = dt.datetime(2026, 10, 28, 12, 0, tzinfo=dt.UTC)
#: One row per state, each with a pending action its state allows (data model).
ROWS = {
    "creating": ("create", "provider", "service"),
    "active": (None, None, None),
    "offboarding": ("offboard", "offboard", "service"),
    "offboarded": (None, None, None),
}


@pytest.fixture
def migrated_database():
    with database(migrated=True) as dsn:
        yield dsn


async def test_only_an_active_tenant_exists_for_identity(migrated_database):
    """creating, offboarding, offboarded and absent tenants do not exist; an active one does (seam, O4)."""
    from defender.identity.postgres import PostgresIdentityRepository

    ids = {state: fixture_uuid(f"tenant:1214-{state}") for state in ROWS}
    for state, (action, step, actor) in ROWS.items():
        execute(migrated_database, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                                      VALUES (%s, %s, %s, %s, %s, %s)""", (ids[state], NOW, state, action, step, actor))
    repo = PostgresIdentityRepository(migrated_database)
    try:
        exists = {state: await repo.tenant_exists(ids[state]) for state in ROWS}
        assert exists == {"creating": False, "active": True, "offboarding": False, "offboarded": False}
        assert await repo.tenant_exists(fixture_uuid("tenant:1214-absent")) is False
    finally:
        await repo.close()
