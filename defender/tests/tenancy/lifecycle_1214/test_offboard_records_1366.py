"""#1366 sketch: offboarding deletes the tenant's system and case records, all versions, and the imported mark (O10).

Entry: the lifecycle's own service and host actors (`LifecycleWorld`'s fakes for forge and OpenBao) over the
PostgreSQL tenant repository on a migrated database (Postgres-gated), offboarding requested through the repository
and driven to `offboarded`; the records were seeded (`register_tenant` imports the published tenant's settings) and edited by the operator command. A second tenant's stay (control).
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from defender.tests.support.tenancy._active1214 import offboard_on_database

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant, second_tenant

TENANT_FILES = R.import_files()

pytestmark = pytest.mark.postgres


def _offboard(world: LifecycleWorld, dsn: str, tenant_id: str) -> Any:
    from defender.tenancy.postgres import PostgresTenantRepository

    repo = PostgresTenantRepository(dsn)
    service = world.new_service(repo, identity=world.service)
    host = world.new_host(repo)
    try:
        world.call(offboard_on_database, dsn, tenant_id)
        for _ in range(20):
            if world.call(service.work) + world.call(host.work) == 0:
                break
        return world.call(repo.tenant, tenant_id)
    finally:
        asyncio.run(repo.close())


def test_1366_o10_offboarding_removes_every_record_version(
        tmp_path, data_root, migrated_database):  # noqa: F811 — the imported fixture
    """A and B hold records (seeded through the store), A's cmdb edited then deleted (three versions): after A is
    offboarded A has no system version and no case version; B's records are untouched. (#1366 O10; #1470 O8: no mark)"""
    from defender.tests.support.tenancy import _records1470 as K

    with published_tenant(tmp_path / "forge", root=data_root, files=TENANT_FILES) as a, second_tenant(a, files=TENANT_FILES) as b:
        for t in (a, b):
            register_tenant(migrated_database, t.tenant_id, data_root=t.data_root)
        config, access = R.FIXTURE_FOLDERS["cmdb"]

        async def edit_then_delete(store):
            await store.put_system(a.tenant_id, "cmdb", replaces=1, adapter="cmdb", enabled=True,
                                   settings=dict(config), access=access, author=K.SEED)
            await store.delete_system(a.tenant_id, "cmdb", replaces=2, author=K.SEED)

        K.run(migrated_database, edit_then_delete)
        assert [v.version for v in R.system_versions(migrated_database, a.tenant_id, "cmdb")] == [1, 2, 3], "premise"
        world = LifecycleWorld(tmp_path / "world", data_root)
        try:
            record = _offboard(world, migrated_database, a.tenant_id)
        finally:
            world.close()

    assert record.state == "offboarded", record
    assert all(R.system_versions(migrated_database, a.tenant_id, s) == [] for s in R.FIXTURE_SYSTEMS)
    assert R.case_versions(migrated_database, a.tenant_id) == []
    assert {s for s in R.FIXTURE_SYSTEMS if R.system_versions(migrated_database, b.tenant_id, s)} == R.FIXTURE_SYSTEMS, \
        "control: the other tenant's records stay"
    assert R.case_versions(migrated_database, b.tenant_id), "control: and its case record"
