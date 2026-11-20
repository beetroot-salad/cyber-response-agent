"""#1589: the revision on `0023_findings_at_job_end` drops `jobs.learning_jobs.findings_count`; every row survives the
drop with its other values."""
from __future__ import annotations

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.migrations.test_1487_publish_state_migration import _plant
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

PRIOR = "0023_findings_at_job_end"
TENANT = fixture_uuid("1589-mig-tenant")
KEPT = ("id, tenant_id, alert_id, investigation_id, request_key, attempt, trigger, status, reason, message, "
        "created_at, finished_at, sibling_cost_usd, publish_state")


def _columns(dsn: str) -> set[str]:
    return {r[0] for r in execute(dsn, "SELECT column_name FROM information_schema.columns "
                                       "WHERE table_schema = 'jobs' AND table_name = 'learning_jobs'")}


def _revision_on_prior() -> str:
    from defender.migrations import _scripts

    found = [r.revision for r in _scripts().walk_revisions() if r.down_revision == PRIOR]
    assert len(found) == 1, f"one revision should sit directly on {PRIOR}, found {found}"
    return found[0]


def test_1589_one_revision_sits_on_the_findings_at_job_end_revision():
    from defender.migrations import head, heads

    from defender.tests.support.shared import _revisions1485 as revisions

    child = _revision_on_prior()
    assert heads() == (head(),)
    assert child == head() or child in revisions.ancestors(head())


@pytest.mark.postgres
def test_1589_the_upgrade_drops_the_count_and_keeps_every_row(empty_database):
    dsn = empty_database
    _upgrade_to(dsn, PRIOR)
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (TENANT,))
    jobs = [_plant(dsn, TENANT, n, state) for n, state in ((7, "refused"), (3, "done"), (0, "none"))]
    before = {r[0]: r for r in execute(dsn, f"SELECT {KEPT} FROM jobs.learning_jobs")}  # noqa: S608
    assert "findings_count" in _columns(dsn)

    _upgrade_to(dsn, _revision_on_prior())  # its own revision, not the head a later migration moves

    assert "findings_count" not in _columns(dsn)
    after = {r[0]: r for r in execute(dsn, f"SELECT {KEPT} FROM jobs.learning_jobs")}  # noqa: S608
    assert after == before
    assert set(after) == set(jobs)
