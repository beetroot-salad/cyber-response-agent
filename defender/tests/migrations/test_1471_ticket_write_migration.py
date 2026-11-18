"""#1471 data model: the revision after `0020_signin_attempts` gives `jobs.investigations` its `update_ticket` (boolean,
not null, false for existing rows) and no outcome-word column (r9 R9-1: `ticket_write` is not added)."""
from __future__ import annotations

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.migrations.test_1343_migrations import TENANT, _id, _inv
from defender.tests.support.jobs._jobs1342 import T1, an_alert, job_store, register_tenant
from defender.tests.support.shared._postgres1339 import execute

PRIOR = "0020_signin_attempts"


def _revision_on_prior() -> str:
    from defender.migrations import _scripts

    found = [r.revision for r in _scripts().walk_revisions() if r.down_revision == PRIOR]
    assert len(found) == 1, f"one revision should sit directly on {PRIOR}, found {found}"
    return found[0]


def _plant_at_prior(dsn: str, inv: str, stage: str, ticket: str) -> None:
    """A row at revision `0019`, written with exactly the columns that schema requires (`cost_is_lower_limit` false), so
    a later revision's required column cannot change what is planted."""

    alert = _id("alert", ticket)
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, "
                 "title, description, raw) VALUES (%s, %s, 'elastic', %s, now(), now(), now(), 't', 'd', '\\x7b7d')",
            (alert, TENANT, ticket))
    started = "NULL" if stage == "queued" else "now() - interval '2 hours'"
    finished = "now() - interval '1 hour'" if stage not in ("queued", "running") else "NULL"
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 f"started_at, finished_at, cost_usd, cost_is_lower_limit) VALUES (%s, %s, %s, 'k', 1, %s, now(), "  # noqa: S608
                 f"{started}, {finished}, 1.5, false)", (inv, TENANT, alert, stage))


def _columns(dsn: str) -> list[tuple]:
    return execute(dsn, "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'jobs' AND table_name = 'investigations' "
                        "AND column_name IN ('update_ticket', 'ticket_write') ORDER BY column_name")


def test_the_history_stays_one_line_with_one_revision_on_the_records_mark_drop():
    """One head, and exactly one revision directly on `0020_signin_attempts`. (data model: numbered after 0019)"""
    from defender.migrations import head, heads

    assert heads() == (head(),)
    assert _revision_on_prior()


@pytest.mark.postgres
def test_existing_rows_read_unflagged_and_nothing_else_changes(empty_database):
    """Upgrading a database holding a queued, a running and each terminal row at `0020`: every row gets
    `update_ticket` false, a boolean not null column; no `ticket_write` column appears; no old column changes. (data model,
    r9 R9-1)"""
    dsn = empty_database
    _upgrade_to(dsn, "0018_learning_set_aside_indexes")
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (TENANT,))
    execute(dsn, "INSERT INTO tenancy.records_mark (tenant_id) VALUES (%s)", (TENANT,))
    _upgrade_to(dsn, PRIOR)
    assert _columns(dsn) == [], "premise: the columns are new"
    stages = ("queued", "running", "completed", "unparseable", "failed", "aborted")
    for n, stage in enumerate(stages):
        _plant_at_prior(dsn, _inv(stage), "queued" if stage == "running" else stage, str(n))
    execute(dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now(), "
                 "lease_expires_at = now() + interval '30 seconds' WHERE id = %s", (_inv("running"),))
    old = "id, tenant_id, alert_id, request_key, attempt, stage, created_at, started_at, finished_at, disposition, cost_usd"
    before = execute(dsn, f"SELECT {old} FROM jobs.investigations ORDER BY id")  # noqa: S608

    _upgrade_to(dsn, _revision_on_prior())

    assert execute(dsn, f"SELECT {old} FROM jobs.investigations ORDER BY id") == before  # noqa: S608
    assert execute(dsn, "SELECT update_ticket, count(*) FROM jobs.investigations "
                        "GROUP BY update_ticket") == [(False, len(stages))]
    assert _columns(dsn) == [("update_ticket", "boolean", "NO")]


@pytest.fixture
async def a_row(migrated_database: str):
    """The head database with one investigation (stored through the store), and its id."""
    register_tenant(migrated_database, T1)
    async with job_store(migrated_database) as store:
        alert = await an_alert(store, T1)
        created, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
    return migrated_database, str(created.investigation_id)


@pytest.mark.postgres
@pytest.mark.anyio
async def test_update_ticket_cannot_be_null(a_row):
    """`update_ticket` is not null: setting it null is refused. (data model)"""
    import psycopg

    dsn, inv = a_row
    with pytest.raises(psycopg.errors.NotNullViolation):
        execute(dsn, "UPDATE jobs.investigations SET update_ticket = NULL WHERE id = %s", (inv,))


@pytest.mark.postgres
@pytest.mark.anyio
async def test_update_ticket_has_no_server_default_after_the_upgrade(a_row):
    """`update_ticket` keeps no server default (the migration adds one, backfills, then drops it), while the old rows read
    false. (C-3 amended)"""
    dsn, _ = a_row
    assert execute(dsn, "SELECT column_default FROM information_schema.columns WHERE table_schema = 'jobs' "
                        "AND table_name = 'investigations' AND column_name = 'update_ticket'") == [(None,)]
