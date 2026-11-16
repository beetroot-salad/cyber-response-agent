"""#1471 r8 data model: the revision after `0019_drop_records_mark` gives `jobs.investigations` its `update_ticket` (boolean,
not null, false for existing rows) and `ticket_write` (text, null, one of W6's six words)."""
from __future__ import annotations

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.migrations.test_1343_migrations import TENANT, _inv, _plant
from defender.tests.support.jobs._jobs1342 import T1, an_alert, job_store, register_tenant
from defender.tests.support.shared._postgres1339 import execute

PRIOR = "0019_drop_records_mark"
WORDS = ("commented", "escalated", "error", "unknown", "no_receipt", "not_read")
#: Words that are not in the set: the sketch's retired ones, a near miss, the empty text and a stray case.
OUTSIDE = ("refused", "not_sent", "Commented", "not read", "")


def _revision_on_prior() -> str:
    from defender.migrations import _scripts

    found = [r.revision for r in _scripts().walk_revisions() if r.down_revision == PRIOR]
    assert len(found) == 1, f"one revision should sit directly on {PRIOR}, found {found}"
    return found[0]


def _columns(dsn: str) -> list[tuple]:
    return execute(dsn, "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                        "WHERE table_schema = 'jobs' AND table_name = 'investigations' "
                        "AND column_name IN ('update_ticket', 'ticket_write') ORDER BY column_name")


def test_the_history_stays_one_line_with_one_revision_on_the_records_mark_drop():
    """One head, and exactly one revision directly on `0019_drop_records_mark`. (data model: numbered after 0019)"""
    from defender.migrations import head, heads

    assert heads() == (head(),)
    assert _revision_on_prior()


@pytest.mark.postgres
def test_existing_rows_read_unflagged_with_no_word_and_nothing_else_changes(empty_database):
    """Upgrading a database holding a queued, a running and each terminal row at `0019`: every row gets
    `update_ticket` false and `ticket_write` null; both columns have their types; no old column changes. (data model)"""
    dsn = empty_database
    _upgrade_to(dsn, "0018_learning_set_aside_indexes")
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (TENANT,))
    execute(dsn, "INSERT INTO tenancy.records_mark (tenant_id) VALUES (%s)", (TENANT,))
    _upgrade_to(dsn, PRIOR)
    assert _columns(dsn) == [], "premise: the columns are new"
    stages = ("queued", "running", "completed", "unparseable", "failed", "aborted")
    for n, stage in enumerate(stages):
        _plant(dsn, _inv(stage), "queued" if stage == "running" else stage, str(n), cost=1.5, at_head=True)
    execute(dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now(), "
                 "lease_expires_at = now() + interval '30 seconds' WHERE id = %s", (_inv("running"),))
    old = "id, tenant_id, alert_id, request_key, attempt, stage, created_at, started_at, finished_at, disposition, cost_usd"
    before = execute(dsn, f"SELECT {old} FROM jobs.investigations ORDER BY id")  # noqa: S608

    _upgrade_to(dsn, _revision_on_prior())

    assert execute(dsn, f"SELECT {old} FROM jobs.investigations ORDER BY id") == before  # noqa: S608
    assert execute(dsn, "SELECT update_ticket, ticket_write, count(*) FROM jobs.investigations "
                        "GROUP BY update_ticket, ticket_write") == [(False, None, len(stages))]
    assert _columns(dsn) == [("ticket_write", "text", "YES"), ("update_ticket", "boolean", "NO")]


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
@pytest.mark.parametrize("word", WORDS)
async def test_the_database_accepts_each_word_and_null_and_refuses_any_other(a_row, word):
    """`ticket_write` takes each of the six words and null; text outside the set is a check violation, the row keeping
    its word. (W6: the closed set at the database)"""
    import psycopg

    dsn, inv = a_row
    execute(dsn, "UPDATE jobs.investigations SET ticket_write = %s WHERE id = %s", (word, inv))
    for bad in OUTSIDE:
        with pytest.raises(psycopg.errors.CheckViolation):
            execute(dsn, "UPDATE jobs.investigations SET ticket_write = %s WHERE id = %s", (bad, inv))
    assert execute(dsn, "SELECT ticket_write FROM jobs.investigations WHERE id = %s", (inv,)) == [(word,)]
    execute(dsn, "UPDATE jobs.investigations SET ticket_write = NULL WHERE id = %s", (inv,))
    assert execute(dsn, "SELECT ticket_write FROM jobs.investigations WHERE id = %s", (inv,)) == [(None,)]


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
