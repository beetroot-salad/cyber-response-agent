"""#1471 slice A: the revision after `0025_alert_outcome` makes `jobs.host_requests` and touches nothing else
(`test-surface.md` §4: the host-requests revision on the head before it, columns, stage check, running-has-a-lease, one queued row per kind and key)."""
from __future__ import annotations

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import execute

PRIOR = "0025_alert_outcome"  # repair 5: main's head when #1471 lands (#1581); the revision is `0026_host_requests`
COLUMNS = {"id", "tenant_id", "kind", "dedupe_key", "system_id", "requester", "created_at", "started_at", "finished_at",
           "stage", "lease_expires_at", "result", "failure_reason", "failure_message"}


def _revision() -> str:
    return revisions.by_suffix("_host_requests")


def test_the_history_has_one_head_and_the_host_requests_revision_sits_on_the_alert_outcome_revision():
    """One line of history; `*_host_requests` is built on `0025_alert_outcome` and the head is not behind it. (§4)"""
    from defender.migrations import head, heads

    assert heads() == (head(),)
    assert revisions.down_of(_revision()) == PRIOR
    assert _revision() == head() or _revision() in revisions.ancestors(head())


@pytest.mark.postgres
def test_before_the_revision_there_is_no_table_and_after_it_the_table_has_exactly_the_surfaces_columns(empty_database):
    """The table appears with the revision, with the columns the store and the tests name, JSON `result` and a uuid id. (§4, §7)"""
    dsn = empty_database
    _upgrade_to(dsn, PRIOR)
    assert execute(dsn, "SELECT 1 FROM information_schema.tables WHERE table_schema = 'jobs' AND table_name = 'host_requests'") == []
    _upgrade_to(dsn, _revision())
    cols = dict(execute(dsn, "SELECT column_name, data_type FROM information_schema.columns "
                             "WHERE table_schema = 'jobs' AND table_name = 'host_requests'"))
    assert set(cols) == COLUMNS
    assert (cols["id"], cols["result"]) == ("uuid", "jsonb")


@pytest.mark.postgres
def test_the_revision_leaves_the_existing_job_tables_as_they_were(empty_database):
    """Every other table of the `jobs` schema is the same set of columns before and after. (§7)"""
    dsn = empty_database
    _upgrade_to(dsn, PRIOR)
    shape = ("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'jobs' "
             "AND table_name <> 'host_requests' ORDER BY 1, 2")
    before = execute(dsn, shape)
    _upgrade_to(dsn, _revision())
    assert execute(dsn, shape) == before


@pytest.mark.postgres
def test_the_revision_makes_the_queued_uniqueness_a_partial_index_and_the_checks(empty_database):
    """A unique index over (kind, dedupe_key) limited to queued rows, a stage check and a lease check exist. (§7)"""
    dsn = empty_database
    _upgrade_to(dsn, _revision())
    indexes = [d for (d,) in execute(dsn, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'jobs' AND tablename = 'host_requests'")]
    assert any("UNIQUE" in d and "kind" in d and "dedupe_key" in d and "queued" in d for d in indexes), indexes
    checks = " ".join(d for (d,) in execute(dsn, "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'jobs.host_requests'::regclass AND contype = 'c'"))
    for word in ("queued", "running", "completed", "failed", "lease_expires_at"):
        assert word in checks, word
