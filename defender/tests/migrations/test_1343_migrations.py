"""#1343 piece B's migration on `0004_jobs`: the lease and final-accounting columns, the running-row lease CHECK, and the
backfill of A-era rows (r5 item 9). Column names are the contract's (r5 item 11)."""
from __future__ import annotations

import pytest

from defender.tests.support.shared._postgres1339 import execute

TERMINAL = ("completed", "unparseable", "failed", "aborted")


def test_b_the_history_stays_one_line_with_the_new_revision_on_the_jobs_revision():
    """One head, directly on `0004_jobs`, which keeps its id and place. (B Data model: one migration on A's)"""
    from defender.migrations import _scripts, head, heads

    scripts = _scripts()
    assert heads() == (head(),)
    assert head() != "0004_jobs"
    assert scripts.get_revision(head()).down_revision == "0004_jobs"
    assert scripts.get_revision("0004_jobs").down_revision == "0003_sign_login"
    assert [r.revision for r in scripts.walk_revisions()][1:] == ["0004_jobs", "0003_sign_login", "0002_tenancy", "0001_baseline"]


def _plant(dsn: str, inv: str, stage: str, ticket: str, *, cost: float = 0) -> None:
    alert = f"al-{ticket}"
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, "
                 "title, description, raw) VALUES (%s, 't-1', 'elastic', %s, now(), now(), now(), 't', 'd', '\\x7b7d')",
            (alert, ticket))
    started = "now() - interval '2 hours'" if stage != "queued" else "NULL"
    finished = "now() - interval '1 hour'" if stage in TERMINAL else "NULL"
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 f"started_at, finished_at, cost_usd) VALUES (%s, 't-1', %s, 'k', 1, %s, now(), {started}, {finished}, %s)",  # noqa: S608
            (inv, alert, stage, cost))


def _a_era_database(dsn: str) -> None:
    """A database at `0004_jobs` holding a running row, a queued row and one row of each terminal stage."""
    from alembic import command

    from defender.migrations import _config

    config = _config()
    config.attributes["dsn"] = dsn
    command.upgrade(config, "0004_jobs")
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES ('t-1', now(), 'active')")
    _plant(dsn, "i-run", "running", "1", cost=1.5)
    _plant(dsn, "i-queued", "queued", "2")
    for n, stage in enumerate(TERMINAL):
        _plant(dsn, f"i-{stage}", stage, f"t{n}", cost=2.5)


@pytest.mark.postgres
def test_b_migration_gives_a_era_running_rows_a_lapsed_lease_and_no_mark(empty_database):
    """From `0004_jobs`: a running row's lease is already lapsed (retried at once) and unmarked; a queued row has neither. (B Data model, r5 item 9)"""
    from defender.migrations import upgrade

    _a_era_database(empty_database)
    upgrade(empty_database)
    got = {r[0]: r[1:] for r in execute(empty_database, "SELECT id, lease_expires_at < now(), accounting_written_at IS NULL, "
                                                          "lease_expires_at IS NULL FROM jobs.investigations WHERE stage IN ('running', 'queued')")}
    assert got == {"i-run": (True, True, False), "i-queued": (None, True, True)}


@pytest.mark.postgres
def test_b_migration_marks_a_era_terminal_rows_with_their_finish_time_and_changes_no_old_column(empty_database):
    """Each terminal row's mark equals its `finished_at` (their accounting is final); the queued row and the running row stay unmarked; every A-era column keeps its value. (B Data model, r5 item 9)"""
    from defender.migrations import upgrade

    old_columns = ("id, tenant_id, alert_id, request_key, attempt, stage, created_at, started_at, finished_at, disposition, "
                   "cost_usd, knowledge, failure_reason, failure_message")
    _a_era_database(empty_database)
    before = execute(empty_database, f"SELECT {old_columns} FROM jobs.investigations ORDER BY id")  # noqa: S608
    upgrade(empty_database)

    assert execute(empty_database, f"SELECT {old_columns} FROM jobs.investigations ORDER BY id") == before  # noqa: S608
    marks = execute(empty_database, "SELECT stage, accounting_written_at = finished_at FROM jobs.investigations "
                                    "WHERE stage = ANY(%s) ORDER BY stage", (list(TERMINAL),))
    assert marks == [(stage, True) for stage in sorted(TERMINAL)]
    assert execute(empty_database, "SELECT count(*) FROM jobs.investigations WHERE accounting_written_at IS NOT NULL") == [(4,)]
    assert execute(empty_database, "SELECT count(*) FROM jobs.investigations WHERE lease_expires_at IS NOT NULL") == [(1,)], \
        "only the running row gets a lease"


@pytest.mark.postgres
def test_b_the_new_columns_are_nullable_timestamps_with_no_default(migrated_database):
    """`lease_expires_at` and `accounting_written_at`: timestamptz, nullable, no server default. (B Data model, M10)"""
    rows = execute(migrated_database, "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns "
                                      "WHERE table_schema = 'jobs' AND table_name = 'investigations' "
                                      "AND column_name IN ('lease_expires_at', 'accounting_written_at') ORDER BY column_name")
    assert rows == [("accounting_written_at", "timestamp with time zone", "YES", None),
                    ("lease_expires_at", "timestamp with time zone", "YES", None)]


@pytest.mark.postgres
def test_b_a_running_row_must_have_a_lease_and_other_stages_need_none(migrated_database):
    """The CHECK: inserting or updating a row to `running` without a lease, or clearing a running row's lease, is refused; with one it is accepted; queued and terminal rows hold none. (B Data model)"""
    import psycopg

    dsn = migrated_database
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES ('t-1', now(), 'active')")
    for ticket in ("1", "2", "3"):
        _plant(dsn, f"i-{ticket}", "queued", ticket)
    insert = ("INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, started_at, "
              "cost_usd, lease_expires_at) VALUES ('i-new', 't-1', 'al-new', 'k', 1, %s, now(), now(), 0, {lease})")
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, title, "
                 "description, raw) VALUES ('al-new', 't-1', 'elastic', 'new', now(), now(), now(), 't', 'd', '\\x7b7d')")
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(dsn, insert.format(lease="NULL"), ("running",))
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now() WHERE id = 'i-1'")
    execute(dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now(), "
                 "lease_expires_at = now() + interval '30 seconds' WHERE id = 'i-1'")  # control: with a lease it moves
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(dsn, "UPDATE jobs.investigations SET lease_expires_at = NULL WHERE id = 'i-1'")
    execute(dsn, "UPDATE jobs.investigations SET stage = 'failed', finished_at = now() WHERE id = 'i-1'")  # a lease may stay on an ended row
    execute(dsn, insert.format(lease="NULL"), ("failed",))  # control: other stages need no lease
