"""#1366 sketch: offboarding deletes the tenant's system and case records, all versions, and the imported mark (O10).

Entry: the lifecycle's own service and host actors (`LifecycleWorld`'s fakes for forge and OpenBao) over the
PostgreSQL tenant repository on a migrated database (Postgres-gated), offboarding requested through the repository
and driven to `offboarded`; the records were seeded (`register_tenant` imports the published tenant's settings) and edited by the operator command. A second tenant's stay (control).
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

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
        world.call(repo.request_offboard, tenant_id, now=world.clock())
        for _ in range(20):
            if world.call(service.work) + world.call(host.work) == 0:
                break
        return world.call(repo.tenant, tenant_id)
    finally:
        asyncio.run(repo.close())


def test_1366_o10_offboarding_removes_every_record_version_and_the_imported_mark(
        tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811 — the imported fixture
    """A and B imported (seeded), A's cmdb edited then deleted (three versions): after A is offboarded A has no system version, no case version and no
    mark; B's records are untouched. (#1366 O10, R8)"""
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    with published_tenant(tmp_path / "forge", root=data_root, files=TENANT_FILES) as a, second_tenant(a, files=TENANT_FILES) as b:
        ops = {}
        for t in (a, b):
            register_tenant(migrated_database, t.tenant_id, data_root=t.data_root)
            ops[t.tenant_id] = R.Operator(t.tenant_id, migrated_database, tmp_path / f"op-{t.tenant_id}", capsys)
            assert R.imported(migrated_database, t.tenant_id), "premise: registered tenants are seeded imported"
        config, access = R.FIXTURE_FOLDERS["cmdb"]
        assert ops[a.tenant_id].set_system("cmdb", replaces=1, config=config, access=access)[0] == 0
        assert ops[a.tenant_id].delete_system("cmdb", replaces=2)[0] == 0
        assert len(ops[a.tenant_id].versions("cmdb")) == 3, "premise: three stored versions of cmdb"
        world = LifecycleWorld(tmp_path / "world", data_root)
        try:
            record = _offboard(world, migrated_database, a.tenant_id)
        finally:
            world.close()

    assert record.state == "offboarded", record
    assert ops[a.tenant_id].current() == {}
    assert all(ops[a.tenant_id].versions(s) == [] for s in R.FIXTURE_SYSTEMS)
    assert R.current_records(migrated_database, a.tenant_id).case is None
    assert R.case_versions(migrated_database, a.tenant_id) == []
    assert not R.imported(migrated_database, a.tenant_id)
    assert set(ops[b.tenant_id].current()) == R.FIXTURE_SYSTEMS  # control: the other tenant's records stay
    assert R.imported(migrated_database, b.tenant_id)
