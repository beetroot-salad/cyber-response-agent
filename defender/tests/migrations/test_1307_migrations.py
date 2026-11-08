"""#1307 upgrade: the revision after `0007_alert_mapping` gives users a `kind` (and a program's creator) and a nullable
email, memberships a `role`, and adds `identity.program_credentials`; existing people stay people with `admin` rows.

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`).

Design-implied names (the design names no column): `users.kind`, `users.created_by`, `memberships.role`, table
`identity.program_credentials` with `id, program_id, program_kind (A1), kind, name, state, key_hash, service_account_id, created_by,
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
CREDENTIAL_COLUMNS = ("id", "program_id", "program_kind", "kind", "name", "state", "key_hash", "service_account_id", "created_by",
                      "created_at", "expires_at", "pending_deadline", "last_used_at", "revoked_at", "revoked_by")


def _columns(dsn: str, table: str) -> dict[str, tuple[str, str]]:
    return {c: (t, n) for c, t, n in execute(dsn, """SELECT column_name, data_type, is_nullable FROM information_schema.columns
        WHERE table_schema = 'identity' AND table_name = %s""", (table,))}


def _tenant(dsn: str) -> None:
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')", (TENANT, CREATED))


def _user(dsn: str, user: str, email: str | None, *, kind: str | None = None, created_by: str | None = None) -> None:
    """A user row as the database stores it; `kind` is left out for the pre-#1307 shape; a program has a creator."""
    columns, values = ["id", "email", "display_name", "status", "is_platform_admin", "set_password_requested_seq",
                       "set_password_sent_seq", "set_password_attempts", "created_at", "updated_at", "activated_at"], \
        [user, email, "", "active", False, 0, 0, 0, CREATED, CREATED, CREATED]
    if kind is not None:
        columns.append("kind")
        values.append(kind)
    if created_by is not None:
        columns.append("created_by")
        values.append(created_by)
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

    _user(migrated_database, ANN, "ann@x.org", kind="person")
    _user(migrated_database, SOAR, None, kind="program", created_by=ANN)
    assert execute(migrated_database, "SELECT kind, email FROM identity.users ORDER BY kind") == [
        ("person", "ann@x.org"), ("program", None)]
    with pytest.raises(psycopg.errors.CheckViolation):
        _user(migrated_database, BOB, None, kind="person")
    with pytest.raises(psycopg.errors.CheckViolation):
        _user(migrated_database, BOB, "bob@x.org", kind="program", created_by=ANN)
    with pytest.raises(psycopg.errors.CheckViolation):
        _user(migrated_database, BOB, "bob@x.org", kind="robot")


@pytest.mark.postgres
def test_at_head_a_role_is_admin_or_automation_and_a_credential_state_is_one_of_three(migrated_database):
    """Roles and credential states outside the design are refused; design-valid rows of each state go in (control). (Data model)"""
    import psycopg

    _tenant(migrated_database)
    _user(migrated_database, ANN, "ann@x.org", kind="person")
    _user(migrated_database, SOAR, None, kind="program", created_by=ANN)
    _membership(migrated_database, ANN_ROW, ANN, role="admin")
    _membership(migrated_database, BOB_ROW, SOAR, role="automation")
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(migrated_database, "UPDATE identity.memberships SET role = 'owner' WHERE id = %s", (ANN_ROW,))
    expires = CREATED + _dt.timedelta(days=90)
    deadline = CREATED + _dt.timedelta(minutes=10)
    insert = """INSERT INTO identity.program_credentials
                (id, program_id, program_kind, kind, name, state, key_hash, created_by, created_at, expires_at, pending_deadline,
                 revoked_at, revoked_by)
                VALUES (%s, %s, 'program', %s, 'c', %s, %s, %s, %s, %s, %s, %s, %s)"""

    def row(n: int, *, kind: str = "key", state: str = "live", expires_at: _dt.datetime | None = expires, **over: object) -> tuple:
        fields = {"key_hash": "h" if kind == "key" else None, "pending_deadline": deadline if state == "pending" else None,
                  "revoked_at": CREATED if state == "revoked" else None, "revoked_by": ANN if state == "revoked" else None}
        fields.update(over)
        return (f"a7000000-0000-4000-8000-00000000e0{n:02d}", SOAR, kind, state, fields["key_hash"], ANN, CREATED,
                expires_at, fields["pending_deadline"], fields["revoked_at"], fields["revoked_by"])

    for valid in (row(0, kind="oauth_client", state="pending"), row(1, state="live"), row(2, state="revoked")):
        execute(migrated_database, insert, valid)  # control: each state, as the design describes it
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(migrated_database, insert, row(3, state="disabled"))
    with pytest.raises(psycopg.errors.NotNullViolation):
        execute(migrated_database, insert, row(4, expires_at=None))


@pytest.mark.postgres
def test_at_head_the_credentials_program_is_a_user_of_kind_program_by_a_composite_key(migrated_database):
    """A1: `program_credentials.program_kind` is required and constrained to `program`, `users` is unique on `(id, kind)`, and
    `(program_id, program_kind)` is a foreign key to it, so the schema (not a recheck) keeps a person from holding a credential."""
    import re

    assert _columns(migrated_database, "program_credentials")["program_kind"][1] == "NO"
    definitions = [(table, d) for table, d in execute(migrated_database, """SELECT r.relname, pg_get_constraintdef(c.oid) FROM pg_constraint c
        JOIN pg_class r ON r.oid = c.conrelid JOIN pg_namespace n ON n.oid = r.relnamespace
        WHERE n.nspname = 'identity' AND r.relname IN ('users', 'program_credentials')""")]
    # unique on (id, kind): a constraint or a plain unique index (a constraint is backed by one, so the index list covers both)
    unique = [tuple(columns) for (columns,) in execute(migrated_database, """SELECT array_agg(a.attname::text ORDER BY k.ord)
        FROM pg_index i JOIN pg_class r ON r.oid = i.indrelid JOIN pg_namespace n ON n.oid = r.relnamespace
        CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
        JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum = k.attnum
        WHERE n.nspname = 'identity' AND r.relname = 'users' AND i.indisunique AND i.indpred IS NULL AND i.indexprs IS NULL
        GROUP BY i.indexrelid""")]
    assert ("id", "kind") in unique, unique
    foreign = [d for table, d in definitions if table == "program_credentials"]
    assert any(re.match(r"FOREIGN KEY \(program_id, program_kind\) REFERENCES (identity\.)?users\(id, kind\)", d)
               for d in foreign), foreign
    # a CHECK that leaves `program` as the only value program_kind may hold, however PostgreSQL renders it (`= 'program'::text`,
    # `= ANY (ARRAY['program'::text])`, `IN ('program')`)
    assert any(d.startswith("CHECK") and "program_kind" in d and set(re.findall(r"'([^']*)'", d)) == {"program"}
               for d in foreign), foreign
