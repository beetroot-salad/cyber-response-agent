"""#1307 upgrade: the revision after `0007_alert_mapping` gives users a `kind` (and a program's creator) and a nullable
email, memberships a `role`, and adds `identity.program_credentials`; existing people stay people with `admin` rows.

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`).

Design-implied names (the design names no column): `users.kind`, `users.created_by`, `memberships.role`, table
`identity.program_credentials` with `id, program_id, kind, name, state, key_hash, service_account_id, created_by,
created_at, expires_at, pending_deadline, last_used_at, revoked_at, revoked_by` (the repository contract's row fields).
"""
from __future__ import annotations

import datetime as _dt

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared._postgres1339 import execute

ALERT_MAPPING = "0007_alert_mapping"
CREATED = _dt.datetime(2026, 11, 1, 8, 0, tzinfo=_dt.UTC)
TENANT = "a7000000-0000-4000-8000-000000000001"
ANN = "a7000000-0000-4000-8000-0000000000a1"
BOB = "a7000000-0000-4000-8000-0000000000b1"
SOAR = "a7000000-0000-4000-8000-0000000000c1"
ANN_ROW = "a7000000-0000-4000-8000-0000000000d1"
BOB_ROW = "a7000000-0000-4000-8000-0000000000d2"
CREDENTIAL_COLUMNS = ("id", "program_id", "kind", "name", "state", "key_hash", "service_account_id", "created_by",
                      "created_at", "expires_at", "pending_deadline", "last_used_at", "revoked_at", "revoked_by")


def _columns(dsn: str, table: str) -> dict[str, tuple[str, str]]:
    return {c: (t, n) for c, t, n in execute(dsn, """SELECT column_name, data_type, is_nullable FROM information_schema.columns
        WHERE table_schema = 'identity' AND table_name = %s""", (table,))}


def _tenant(dsn: str) -> None:
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')", (TENANT, CREATED))


def _user(dsn: str, user: str, email: str | None, *, kind: str | None = None) -> None:
    """A user row as the database stores it; `kind` is left out for the pre-#1307 shape."""
    columns, values = ["id", "email", "display_name", "status", "is_platform_admin", "set_password_requested_seq",
                       "set_password_sent_seq", "set_password_attempts", "created_at", "updated_at", "activated_at"], \
        [user, email, "", "active", False, 0, 0, 0, CREATED, CREATED, CREATED]
    if kind is not None:
        columns.append("kind")
        values.append(kind)
    execute(dsn, f"INSERT INTO identity.users ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(values))})", tuple(values))  # noqa: S608


def _membership(dsn: str, row: str, user: str, *, role: str | None = None) -> None:
    columns, values = ["id", "user_id", "tenant_id", "status", "created_at", "accepted_at", "notify_requested_seq",
                       "notify_sent_seq", "notify_attempts"], [row, user, TENANT, "active", CREATED, CREATED, 0, 0, 0]
    if role is not None:
        columns.append("role")
        values.append(role)
    execute(dsn, f"INSERT INTO identity.memberships ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(values))})", tuple(values))  # noqa: S608


@pytest.mark.postgres
def test_the_upgrade_makes_existing_people_persons_with_admin_memberships(empty_database):
    """From `0007_alert_mapping` with two people and their memberships: at head every user is `person` with no creator, every
    membership `admin`, and nothing else of them changed; no credentials exist. (Data model)"""
    from defender.migrations import head, upgrade

    assert head() != ALERT_MAPPING
    _upgrade_to(empty_database, ALERT_MAPPING)
    _tenant(empty_database)
    _user(empty_database, ANN, "ann@x.org")
    _user(empty_database, BOB, "bob@x.org")
    _membership(empty_database, ANN_ROW, ANN)
    _membership(empty_database, BOB_ROW, BOB)

    upgrade(empty_database)

    assert execute(empty_database, "SELECT id, email, status, kind, created_by FROM identity.users ORDER BY email") == [
        (ANN, "ann@x.org", "active", "person", None), (BOB, "bob@x.org", "active", "person", None)]
    assert execute(empty_database, "SELECT id, user_id, status, role FROM identity.memberships ORDER BY id") == [
        (ANN_ROW, ANN, "active", "admin"), (BOB_ROW, BOB, "active", "admin")]
    assert execute(empty_database, "SELECT count(*) FROM identity.program_credentials") == [(0,)]


@pytest.mark.postgres
def test_at_head_the_credential_table_has_the_designs_columns_and_email_may_be_absent(migrated_database):
    """`program_credentials` has its columns, with `expires_at` required; `users.email` is nullable and `kind`, `role` are required. (Data model)"""
    credentials = _columns(migrated_database, "program_credentials")
    assert set(CREDENTIAL_COLUMNS) <= set(credentials), sorted(set(CREDENTIAL_COLUMNS) - set(credentials))
    assert credentials["expires_at"][1] == "NO"
    assert credentials["key_hash"][1] == "YES"
    assert _columns(migrated_database, "users")["email"][1] == "YES"
    assert _columns(migrated_database, "users")["kind"][1] == "NO"
    assert _columns(migrated_database, "memberships")["role"][1] == "NO"


@pytest.mark.postgres
def test_at_head_email_is_absent_exactly_for_programs(migrated_database):
    """A person needs an email, a program has none (CHECK); a program row with no email is accepted (control). (Data model)"""
    import psycopg

    _user(migrated_database, SOAR, None, kind="program")
    _user(migrated_database, ANN, "ann@x.org", kind="person")
    assert execute(migrated_database, "SELECT kind, email FROM identity.users ORDER BY kind") == [
        ("person", "ann@x.org"), ("program", None)]
    with pytest.raises(psycopg.errors.CheckViolation):
        _user(migrated_database, BOB, None, kind="person")
    with pytest.raises(psycopg.errors.CheckViolation):
        _user(migrated_database, BOB, "bob@x.org", kind="program")
    with pytest.raises(psycopg.errors.CheckViolation):
        _user(migrated_database, BOB, "bob@x.org", kind="robot")


@pytest.mark.postgres
def test_at_head_a_role_is_admin_or_automation_and_a_credential_state_is_one_of_three(migrated_database):
    """Roles and credential states outside the design are refused; the accepted values go in (control). (Data model)"""
    import psycopg

    _tenant(migrated_database)
    _user(migrated_database, ANN, "ann@x.org", kind="person")
    _user(migrated_database, SOAR, None, kind="program")
    _membership(migrated_database, ANN_ROW, ANN, role="admin")
    _membership(migrated_database, BOB_ROW, SOAR, role="automation")
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(migrated_database, "UPDATE identity.memberships SET role = 'owner' WHERE id = %s", (ANN_ROW,))
    insert = """INSERT INTO identity.program_credentials (id, program_id, kind, name, state, key_hash, created_by, created_at, expires_at)
                VALUES (%s, %s, 'key', 'k', %s, 'h', %s, %s, %s)"""
    for n, state in enumerate(("pending", "live", "revoked")):
        execute(migrated_database, insert, (f"a7000000-0000-4000-8000-00000000e00{n}", SOAR, state, ANN, CREATED, CREATED))
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(migrated_database, insert, ("a7000000-0000-4000-8000-00000000e0ff", SOAR, "disabled", ANN, CREATED, CREATED))
    with pytest.raises(psycopg.errors.NotNullViolation):
        execute(migrated_database, insert, ("a7000000-0000-4000-8000-00000000e0fe", SOAR, "live", ANN, CREATED, None))
