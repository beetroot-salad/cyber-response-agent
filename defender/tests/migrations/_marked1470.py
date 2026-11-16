"""#1470 O12 test machinery: an upgrade of a development database that holds tenants from before #1366, to head.
NO test functions."""
from __future__ import annotations

from defender.tests.support.shared._postgres1339 import execute

#: The head before the migration that drops the records mark; the dropping revision sits directly on it.
BEFORE_DROP = "0018_learning_set_aside_indexes"


def upgrade_marking_tenants(dsn: str) -> None:
    """Upgrade `dsn` to head as a database whose tenants all have their records mark: up to the revision before the drop,
    a mark for every tenant not offboarded (what creating a tenant wrote since #1366), then on to head. The drop's guard
    stops an upgrade over a tenant without one; a test of something else plants the marks."""
    from defender.migrations import upgrade
    from defender.tests.migrations.test_1214_migrations import _upgrade_to

    _upgrade_to(dsn, BEFORE_DROP)
    execute(dsn, "INSERT INTO tenancy.records_mark (tenant_id) SELECT id FROM tenancy.tenants WHERE state <> 'offboarded' "
                 "ON CONFLICT DO NOTHING")
    upgrade(dsn)
