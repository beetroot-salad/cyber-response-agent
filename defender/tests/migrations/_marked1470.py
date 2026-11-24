"""#1470 O12 test machinery: an upgrade of a development database that holds tenants from before #1366, to head.
NO test functions."""
from __future__ import annotations

from defender.tests.support.shared._postgres1339 import execute

#: The head before the migration that drops the records mark; the dropping revision sits directly on it.
BEFORE_DROP = "0018_learning_set_aside_indexes"
#: The revision 0027 sits on: the last one that upgrades over pending work.
BEFORE_PEOPLE = "0026_host_requests"


def upgrade_marking_tenants(dsn: str, *, to: str | None = None) -> None:
    """Upgrade `dsn` to head as a database whose tenants all have their records mark and no pending action: up to the
    revision before the drop, a mark for every tenant not offboarded (what creating a tenant wrote since #1366), then on
    to head. The drop's guard stops an upgrade over a tenant without one; a test of something else plants the marks.

    #1592 (OD-5, Upgrade from before #1592, step 1): 0027 refuses while any tenant has a pending action, so at
    `0026_host_requests`, and only when the upgrade goes on to head, every pending action is finished as the
    operator does before upgrading: `creating` becomes `active`, `offboarding` becomes `offboarded`, and the action, its
    step, actor and failure are cleared. A call that stops at `to` (the revision's own backfill test) finishes nothing,
    so the rows it asserts stay. Only the states the callers plant are mapped; any other state stops loudly.

    #1546 r9 B: the rest of the way to head goes through `upgrade_with_retention`, so every tenant not offboarded has its
    retention row before `*_retention_required`."""
    from defender.tests.migrations.test_1214_migrations import _upgrade_to

    _upgrade_to(dsn, BEFORE_DROP)
    execute(dsn, "INSERT INTO tenancy.records_mark (tenant_id) SELECT id FROM tenancy.tenants WHERE state <> 'offboarded' "
                 "ON CONFLICT DO NOTHING")
    if to is not None:
        _upgrade_to(dsn, to)
        return
    _upgrade_to(dsn, BEFORE_PEOPLE)
    states = {s for (s,) in execute(dsn, "SELECT DISTINCT state FROM tenancy.tenants WHERE pending_action IS NOT NULL")}
    assert states <= {"creating", "active"}, f"the helper finishes only creating and active tenants, found {states}"
    execute(dsn, "UPDATE tenancy.tenants SET state = CASE state WHEN 'creating' THEN 'active' ELSE state END, "
                 "pending_action = NULL, step = NULL, step_actor = NULL, failure = NULL WHERE pending_action IS NOT NULL")
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
