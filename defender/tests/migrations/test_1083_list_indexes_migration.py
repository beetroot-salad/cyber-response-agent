"""#1083 upgrade: the revision after `0015_system_records` adds the newest-first list indexes of the job store's alerts,
investigations and learning jobs (Data). Database cases are marked `postgres`, each on a database of its own."""
from __future__ import annotations

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared._postgres1339 import execute

PREVIOUS = "0015_system_records"
#: table -> the time column its list is ordered by (design Data: `(tenant_id, <time> desc, id desc)`).
LISTS = {"alerts": "fired_at", "investigations": "created_at", "learning_jobs": "created_at"}


def _indexes(dsn: str, table: str) -> list[str]:
    return [d for (d,) in execute(dsn, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'jobs' AND tablename = %s",
                                  (table,))]


def _list_indexes(dsn: str, table: str) -> list[str]:
    """Indexes with exactly the design's key, whole (no predicate)."""
    return [d for d in _indexes(dsn, table) if f"(tenant_id, {LISTS[table]} DESC, id DESC)" in d and "WHERE" not in d]


def test_the_list_indexes_revision_sits_directly_on_the_previous_head_and_is_the_head():
    """The history's single head is a revision whose parent is `0015_system_records`. (#1083 Data)"""
    from defender.migrations import _scripts, head

    assert head() != PREVIOUS
    assert _scripts().get_revision(head()).down_revision == PREVIOUS


@pytest.mark.postgres
@pytest.mark.parametrize("table", sorted(LISTS))
def test_at_head_each_list_has_one_whole_table_index_keyed_tenant_first_time_then_id_descending(migrated_database, table):
    """One non-partial index per list on `(tenant_id, <time> DESC, id DESC)`. (#1083 Data)"""
    assert len(_list_indexes(migrated_database, table)) == 1


@pytest.mark.postgres
def test_the_learning_jobs_queued_only_partial_index_is_not_taken_for_the_list_index(migrated_database):
    """Control for the census: the existing queued-only partial index on learning jobs does not match the list key. (#1083 Data)"""
    partial = [d for d in _indexes(migrated_database, "learning_jobs") if "WHERE" in d]
    assert partial, "the existing queued-only partial index"
    assert not any("(tenant_id, created_at DESC, id DESC)" in d for d in partial)


@pytest.mark.postgres
@pytest.mark.parametrize("table", sorted(LISTS))
def test_a_tenants_newest_first_page_is_read_in_index_order_without_a_sort(migrated_database, table):
    """With sequential scans off the planner serves `ORDER BY time DESC, id DESC LIMIT` for one tenant from an index alone. (#1083 Data)"""
    import psycopg

    time = LISTS[table]
    with psycopg.connect(migrated_database, autocommit=True) as conn:
        conn.execute("SET enable_seqscan = off")
        plan = "\n".join(r[0] for r in conn.execute(
            f"EXPLAIN SELECT id FROM jobs.{table} WHERE tenant_id = %s ORDER BY {time} DESC, id DESC LIMIT 5",  # noqa: S608
            ("5d0e7a10-1083-4c00-8a00-0000000000aa",)))
    assert "Index" in plan
    assert "Sort" not in plan


@pytest.mark.postgres
def test_an_upgrade_over_stored_work_keeps_every_row_and_adds_the_indexes(empty_database):
    """A database at the previous head holding an alert keeps it through the upgrade and gains the list indexes. (#1083 Data)"""
    from defender.migrations import check_version, upgrade
    from defender.tests.support.jobs._jobs1342 import NOW, T1, register_tenant

    _upgrade_to(empty_database, PREVIOUS)
    register_tenant(empty_database, T1)
    execute(empty_database, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, "
                            "received_at, title, description, raw) VALUES (%s, %s, 'elastic', 'T-1', %s, %s, %s, 't', 'd', %s)",
            ("6b0d9f7e-1083-4c00-8a00-000000000001", T1, NOW, NOW, NOW, b"{}"))
    assert _list_indexes(empty_database, "alerts") == [], "control: not there before the upgrade"

    upgrade(empty_database)

    check_version(empty_database)
    assert execute(empty_database, "SELECT count(*) FROM jobs.alerts") == [(1,)]
    assert [len(_list_indexes(empty_database, table)) for table in sorted(LISTS)] == [1, 1, 1]
