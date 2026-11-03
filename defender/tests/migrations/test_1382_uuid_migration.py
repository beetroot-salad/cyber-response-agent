"""#1382 O1/O2/D3: `0005_uuid_ids` makes every record id column PostgreSQL `uuid`, turns the actor columns' `'system'`
into NULL and keeps a user id, and stops on a row whose id is not UUID text, leaving the database as it was.

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`).
"""
from __future__ import annotations

import datetime as _dt

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared._postgres1339 import execute

JOBS = "0004_jobs"
CREATED = _dt.datetime(2026, 9, 1, 8, 0, tzinfo=_dt.UTC)
TENANT = "a2000000-0000-4000-8000-000000000001"
ANN = "d2000000-0000-4000-8000-000000000001"
BOB = "d2000000-0000-4000-8000-000000000002"
#: (schema, table, column) of every record id column after the revision (O1, O2).
ID_COLUMNS = {
    ("tenancy", "tenants", "id"), ("identity", "users", "id"),
    *(("identity", "memberships", c) for c in ("id", "user_id", "tenant_id", "invited_by", "ended_by")),
    ("identity", "sessions", "user_id"),
    *(("tenancy", t, "tenant_id") for t in ("forge_wiring", "generations", "publish_status")),
    *(("jobs", "alerts", c) for c in ("id", "tenant_id")),
    *(("jobs", "investigations", c) for c in ("id", "tenant_id", "alert_id")),
}


def _types(dsn: str) -> dict[tuple[str, str, str], str]:
    return {(s, t, c): d for s, t, c, d in execute(dsn, """SELECT table_schema, table_name, column_name, data_type
        FROM information_schema.columns WHERE table_schema IN ('tenancy', 'identity', 'jobs')""")}


def _user(dsn: str, user: str, email: str) -> None:
    execute(dsn, """INSERT INTO identity.users (id, email, display_name, status, is_platform_admin,
                    set_password_requested_seq, set_password_sent_seq, set_password_attempts, created_at, updated_at)
                    VALUES (%s, %s, '', 'invited', false, 0, 0, 0, %s, %s)""", (user, email, CREATED, CREATED))


def _membership(dsn: str, row: str, user: str, invited_by: str, ended_by: str | None) -> None:
    status, ended_at = ("ended", CREATED) if ended_by is not None else ("active", None)
    execute(dsn, """INSERT INTO identity.memberships (id, user_id, tenant_id, status, invited_by, created_at, accepted_at,
                    ended_at, ended_by, notify_requested_seq, notify_sent_seq, notify_attempts)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0, 0, 0)""",
            (row, user, TENANT, status, invited_by, CREATED, CREATED, ended_at, ended_by))


def _at_jobs(dsn: str) -> None:
    """A database at `0004_jobs` with a tenant, two users and two memberships: one invited and ended by the system,
    one invited by a user."""
    _upgrade_to(dsn, JOBS)
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')", (TENANT, CREATED))
    _user(dsn, ANN, "ann@x.org")
    _user(dsn, BOB, "bob@x.org")
    _membership(dsn, "e2000000-0000-4000-8000-000000000001", ANN, "system", "system")
    _membership(dsn, "e2000000-0000-4000-8000-000000000002", BOB, ANN, None)


@pytest.mark.postgres
def test_every_record_id_column_is_uuid_at_head(migrated_database):
    """O1/O2: the id columns, the actor columns included, are `uuid`; the vendor's ticket id and the session key are not."""
    types = _types(migrated_database)
    assert {column: types[column] for column in ID_COLUMNS} == dict.fromkeys(ID_COLUMNS, "uuid")
    assert types[("jobs", "alerts", "vendor_ticket_id")] == "text"
    assert types[("identity", "sessions", "token_hash")] == "text"


@pytest.mark.postgres
def test_the_system_actor_becomes_null_and_a_user_actor_is_kept(empty_database):
    """D2: `'system'` in invited_by/ended_by is NULL after the upgrade; a user id stays, and the rows keep their ids."""
    _at_jobs(empty_database)
    _upgrade_to(empty_database, "head")
    rows = execute(empty_database, "SELECT id, invited_by, ended_by FROM identity.memberships ORDER BY id")
    assert rows == [("e2000000-0000-4000-8000-000000000001", None, None),
                    ("e2000000-0000-4000-8000-000000000002", ANN, None)]


@pytest.mark.postgres
@pytest.mark.parametrize("bad", ["acme", "A2000000-0000-4000-8000-0000000000FF", "{a2000000-0000-4000-8000-0000000000ff}",
                                 "a20000000000400080000000000000ff"],
                         ids=["not-a-uuid", "upper-case", "braced", "no-hyphens"])
def test_a_row_whose_id_is_not_canonical_uuid_text_stops_the_upgrade_and_changes_nothing(empty_database, bad):
    """D3: an id the code would refuse stops the upgrade, naming the row, even one PostgreSQL's cast would take and
    rewrite (its run folders carry the old text); the database stays at `0004_jobs` with its text columns and rows."""
    _at_jobs(empty_database)
    execute(empty_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')", (bad, CREATED))
    with pytest.raises(Exception, match=r"tenancy\.tenants\.id holds .*not canonical") as stopped:  # noqa: PT011
        _upgrade_to(empty_database, "head")
    assert type(stopped.value).__name__ == "NotCanonical"
    assert execute(empty_database, "SELECT version_num FROM public.alembic_version") == [(JOBS,)]
    assert _types(empty_database)[("tenancy", "tenants", "id")] == "text"
    assert execute(empty_database, "SELECT invited_by FROM identity.memberships ORDER BY id") == [("system",), (ANN,)]


@pytest.mark.postgres
@pytest.mark.parametrize("column", ["invited_by", "ended_by"])
def test_an_actor_who_is_no_user_stops_the_upgrade_naming_the_row(empty_database, column):
    """D2: the new actor foreign keys would refuse a membership whose actor names no user without naming the row; the
    upgrade stops first, naming it, and changes nothing."""
    _at_jobs(empty_database)
    ghost = "d2000000-0000-4000-8000-0000000000ff"
    execute(empty_database, f"UPDATE identity.memberships SET {column} = %s WHERE user_id = %s", (ghost, ANN))
    with pytest.raises(Exception, match=rf"memberships\.{column} of membership .* names '{ghost}', which is no user"):  # noqa: PT011
        _upgrade_to(empty_database, "head")
    assert execute(empty_database, "SELECT version_num FROM public.alembic_version") == [(JOBS,)]
