"""#1343 piece B's migration, `0006_job_leases`, on `0005_uuid_ids` (record ids are PostgreSQL `uuid`, #1382): the lease and final-accounting columns, the running-row lease CHECK, and the
backfill of A-era rows (r5 item 9). Column names are the contract's (r5 item 11)."""
from __future__ import annotations

import uuid

import pytest

from defender.tests.support.shared._postgres1339 import execute

TERMINAL = ("completed", "unparseable", "failed", "aborted")
PRE_STATE = "0005_uuid_ids"
TENANT = "a3000000-0000-4000-8000-000000000001"


def _id(kind: str, name: str) -> str:
    """A stable uuid for a named row (record ids are `uuid` since `0005_uuid_ids`)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"1343/{kind}/{name}"))


def _inv(name: str) -> str:
    return _id("investigation", name)


def test_b_the_history_stays_one_line_with_the_new_revision_on_the_uuid_ids_revision():
    """One head (#1345's `0007_alert_mapping`, then #1377's `0008_cost_lower_limit`, since), with `0006_job_leases` directly on `0005_uuid_ids`, which sits on `0004_jobs`; both keep their id and place. (B Data model: one migration on A's; renumbered after #1382)"""
    from defender.migrations import _scripts, head, heads

    scripts = _scripts()
    assert heads() == (head(),)
    assert scripts.get_revision("0007_alert_mapping").down_revision == "0006_job_leases"
    assert scripts.get_revision("0006_job_leases").down_revision == "0005_uuid_ids"
    assert scripts.get_revision("0005_uuid_ids").down_revision == "0004_jobs"
    assert scripts.get_revision("0004_jobs").down_revision == "0003_sign_login"
    assert [r.revision for r in scripts.walk_revisions()][3:] == [
        "0005_uuid_ids", "0004_jobs", "0003_sign_login", "0002_tenancy", "0001_baseline"]


def _plant(dsn: str, inv: str, stage: str, ticket: str, *, cost: float = 0, at_head: bool = False) -> None:
    """A row at the database's revision: `at_head` adds #1377's required `cost_is_lower_limit` (false), which a database
    at an older revision does not have."""
    alert = _id("alert", ticket)
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, "
                 "title, description, raw) VALUES (%s, %s, 'elastic', %s, now(), now(), now(), 't', 'd', '\\x7b7d')",
            (alert, TENANT, ticket))
    started = "now() - interval '2 hours'" if stage != "queued" else "NULL"
    finished = "now() - interval '1 hour'" if stage in TERMINAL else "NULL"
    mark_column, mark = (", cost_is_lower_limit", ", false") if at_head else ("", "")
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 f"started_at, finished_at, cost_usd{mark_column}) VALUES (%s, %s, %s, 'k', 1, %s, now(), {started}, {finished}, "  # noqa: S608
                 f"%s{mark})", (inv, TENANT, alert, stage, cost))


def _a_era_database(dsn: str) -> None:
    """A database at `0005_uuid_ids` holding a running row, a queued row and one row of each terminal stage."""
    from alembic import command

    from defender.migrations import _config

    config = _config()
    config.attributes["dsn"] = dsn
    command.upgrade(config, PRE_STATE)
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (TENANT,))
    _plant(dsn, _inv("run"), "running", "1", cost=1.5)
    _plant(dsn, _inv("queued"), "queued", "2")
    for n, stage in enumerate(TERMINAL):
        _plant(dsn, _inv(stage), stage, f"t{n}", cost=2.5)


@pytest.mark.postgres
def test_b_migration_gives_a_era_running_rows_a_lapsed_lease_and_no_mark(empty_database):
    """From `0005_uuid_ids`: a running row's lease is already lapsed (retried at once) and unmarked; a queued row has neither. (B Data model, r5 item 9)"""
    from defender.migrations import upgrade

    _a_era_database(empty_database)
    upgrade(empty_database)
    got = {str(r[0]): r[1:] for r in execute(empty_database, "SELECT id, lease_expires_at < now(), accounting_written_at IS NULL, "
                                                          "lease_expires_at IS NULL FROM jobs.investigations WHERE stage IN ('running', 'queued')")}
    assert got == {_inv("run"): (True, True, False), _inv("queued"): (None, True, True)}


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
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (TENANT,))
    for ticket in ("1", "2", "3"):
        _plant(dsn, _inv(ticket), "queued", ticket, at_head=True)
    i_1 = _inv("1")
    insert = ("INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, started_at, "
              f"cost_usd, cost_is_lower_limit, lease_expires_at) VALUES ('{_inv('new')}', '{TENANT}', '{_id('alert', 'new')}', 'k', 1, %s, "
              "now(), now(), 0, false, {lease})")  # cost_is_lower_limit: #1377's required column, at head
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, title, "
                 "description, raw) VALUES (%s, %s, 'elastic', 'new', now(), now(), now(), 't', 'd', '\\x7b7d')",
            (_id("alert", "new"), TENANT))
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(dsn, insert.format(lease="NULL"), ("running",))
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now() WHERE id = %s", (i_1,))
    execute(dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now(), "
                 "lease_expires_at = now() + interval '30 seconds' WHERE id = %s", (i_1,))  # control: with a lease it moves
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(dsn, "UPDATE jobs.investigations SET lease_expires_at = NULL WHERE id = %s", (i_1,))
    execute(dsn, "UPDATE jobs.investigations SET stage = 'failed', finished_at = now() WHERE id = %s", (i_1,))  # a lease may stay on an ended row
    execute(dsn, insert.format(lease="NULL"), ("failed",))  # control: other stages need no lease
