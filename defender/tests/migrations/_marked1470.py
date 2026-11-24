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
    from defender.tests.migrations.test_1214_migrations import _upgrade_to

    _upgrade_to(dsn, BEFORE_DROP)
    execute(dsn, "INSERT INTO tenancy.records_mark (tenant_id) SELECT id FROM tenancy.tenants WHERE state <> 'offboarded' "
                 "ON CONFLICT DO NOTHING")
    upgrade_with_retention(dsn)


#: The values a test of something else gives a tenant planted before #1546's retention row (any two in 30-730 days).
PLANTED_RETENTION_DAYS = 90


def upgrade_with_retention(dsn: str) -> None:
    """Upgrade `dsn` to head as a database whose tenants all have their retention row (#1546 r9 B: what creating a tenant
    writes since #1546): up to the revision before `*_retention_required`, a row for every tenant not offboarded that lacks
    one, then on to head. That revision refuses an upgrade over such a tenant; a test of something else plants the rows."""
    from defender.migrations import upgrade
    from defender.tests.migrations.test_1214_migrations import _upgrade_to
    from defender.tests.support.shared import _revisions1485 as revisions

    _upgrade_to(dsn, revisions.down_of(revisions.by_suffix("_retention_required")))
    execute(dsn, "INSERT INTO tenancy.evidence_retention (tenant_id, investigation_days, learning_days) "
                 "SELECT id, %s, %s FROM tenancy.tenants WHERE state <> 'offboarded' ON CONFLICT DO NOTHING",
            (PLANTED_RETENTION_DAYS, PLANTED_RETENTION_DAYS))
    upgrade(dsn)
