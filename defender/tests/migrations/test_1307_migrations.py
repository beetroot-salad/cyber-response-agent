"""#1307 upgrade: the revision after `0007_alert_mapping` gives memberships a `role` and adds `identity.program_credentials`;
existing people stay people with `admin` rows. #1454 then moves programs out of `users`/`memberships` into `identity.programs`
(the revision after `0011_merge_eligibility`, whose id these tests never spell: they ask `head()`): users keep a required email and
lose `kind`, a membership's role is `admin` only, a credential's `program_id` is a plain foreign key to `programs`, and the upgrade
refuses while any program (a users row of kind `program`) or any membership whose role is not `admin` exists (R1, R2, O-G).

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`).

Names the design fixes: table `identity.programs` with `id, tenant_id, display_name, created_by, created_at, removed_at, removed_by`
(removed exactly when it has a removal time); `identity.program_credentials` with `id, program_id, kind, name, state, key_hash, service_account_id, created_by,
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
MERGE_ELIGIBILITY = "0011_merge_eligibility"  # the last revision before programs have a table; a revision #1454 builds on, not one it adds
PROGRAM_COLUMNS = ("id", "tenant_id", "display_name", "created_by", "created_at", "removed_at", "removed_by")
CREDENTIAL_COLUMNS = ("id", "program_id", "kind", "name", "state", "key_hash", "service_account_id", "created_by",
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


def _version(dsn: str) -> list[tuple]:
    return execute(dsn, "SELECT version_num FROM public.alembic_version")


def _program(dsn: str, program: str, *, tenant: str | None = TENANT, created_by: str | None = ANN,
             removed_at: _dt.datetime | None = None, removed_by: str | None = None) -> None:
    """A `programs` row as the database stores it (PostgreSQL's own checks decide what goes in)."""
    execute(dsn, """INSERT INTO identity.programs (id, tenant_id, display_name, created_by, created_at, removed_at, removed_by)
                    VALUES (%s, %s, 'SOAR prod', %s, %s, %s, %s)""",
            (program, tenant, created_by, CREATED, removed_at, removed_by))


@pytest.mark.postgres
def test_the_upgrade_keeps_existing_people_with_admin_memberships_and_gives_users_no_kind(empty_database):
    """From `0007_alert_mapping` with two people and their memberships: at head both are as they were, every membership `admin`,
    users have no `kind` or creator column, no credentials and no programs exist. (Data model, R1)"""
    from defender.migrations import head, upgrade

    assert head() != ALERT_MAPPING
    _upgrade_to(empty_database, ALERT_MAPPING)
    _tenant(empty_database)
    _user(empty_database, ANN, "ann@x.org")
    _user(empty_database, BOB, "bob@x.org")
    _membership(empty_database, ANN_ROW, ANN)
    _membership(empty_database, BOB_ROW, BOB)

    upgrade(empty_database)

    assert execute(empty_database, "SELECT id, email, status FROM identity.users ORDER BY email") == [
        (ANN, "ann@x.org", "active"), (BOB, "bob@x.org", "active")]
    assert execute(empty_database, "SELECT id, user_id, status, role FROM identity.memberships ORDER BY id") == [
        (ANN_ROW, ANN, "active", "admin"), (BOB_ROW, BOB, "active", "admin")]
    assert execute(empty_database, "SELECT count(*) FROM identity.program_credentials") == [(0,)]
    assert execute(empty_database, "SELECT count(*) FROM identity.programs") == [(0,)]
    assert {"kind", "created_by"}.isdisjoint(_columns(empty_database, "users"))


@pytest.mark.postgres
def test_at_head_programs_have_their_columns_and_the_credential_table_keeps_its_own(migrated_database):
    """`programs` has its columns (name, creator, tenant and creation time required, removal optional); `program_credentials` has
    its columns without `program_kind`, with `expires_at` required; `users.email` and `memberships.role` are required. (Data model)"""
    programs = _columns(migrated_database, "programs")
    assert set(PROGRAM_COLUMNS) == set(programs), sorted(set(PROGRAM_COLUMNS) ^ set(programs))  # no status: the removal time is it
    assert {c: programs[c][1] for c in PROGRAM_COLUMNS} == {
        "id": "NO", "tenant_id": "NO", "display_name": "NO", "created_by": "NO", "created_at": "NO",
        "removed_at": "YES", "removed_by": "YES"}
    credentials = _columns(migrated_database, "program_credentials")
    assert set(CREDENTIAL_COLUMNS) <= set(credentials), sorted(set(CREDENTIAL_COLUMNS) - set(credentials))
    assert "program_kind" not in credentials
    assert credentials["expires_at"][1] == "NO"
    assert credentials["key_hash"][1] == "YES"
    users = _columns(migrated_database, "users")
    assert users["email"][1] == "NO"
    assert {"kind", "created_by"}.isdisjoint(users)
    assert _columns(migrated_database, "memberships")["role"][1] == "NO"


@pytest.mark.postgres
def test_at_head_a_user_needs_an_email(migrated_database):
    """A user without an email is refused (programs no longer share the table); a person with one is stored (control). (Data model)"""
    import psycopg

    _user(migrated_database, ANN, "ann@x.org")
    with pytest.raises(psycopg.errors.NotNullViolation):
        _user(migrated_database, BOB, None)
    assert execute(migrated_database, "SELECT id, email FROM identity.users") == [(ANN, "ann@x.org")]


@pytest.mark.postgres
def test_at_head_a_membership_role_is_admin_only(migrated_database):
    """`admin` is stored; `automation` (a program's, now none) and other roles are refused, on insert and on update. (R1)"""
    import psycopg

    _tenant(migrated_database)
    _user(migrated_database, ANN, "ann@x.org")
    _user(migrated_database, BOB, "bob@x.org")
    _membership(migrated_database, ANN_ROW, ANN, role="admin")  # control
    for refused in ("automation", "owner"):
        with pytest.raises(psycopg.errors.CheckViolation):
            _membership(migrated_database, BOB_ROW, BOB, role=refused)
        with pytest.raises(psycopg.errors.CheckViolation):
            execute(migrated_database, "UPDATE identity.memberships SET role = %s WHERE id = %s", (refused, ANN_ROW))
    assert execute(migrated_database, "SELECT role FROM identity.memberships") == [("admin",)]


@pytest.mark.postgres
def test_at_head_a_program_names_a_person_who_made_it_and_a_tenant_it_belongs_to(migrated_database):
    """A program needs a creator who is a user and a tenant that exists; a remover, when named, is a user too; a creator that
    is a user is stored (control). (Data model, P-K)"""
    import psycopg

    _tenant(migrated_database)
    _user(migrated_database, ANN, "ann@x.org")
    ghost = "a7000000-0000-4000-8000-0000000000ee"
    _program(migrated_database, "a7000000-0000-4000-8000-00000000f100")  # control
    with pytest.raises(psycopg.errors.NotNullViolation):
        _program(migrated_database, "a7000000-0000-4000-8000-00000000f101", created_by=None)
    with pytest.raises(psycopg.errors.NotNullViolation):
        _program(migrated_database, "a7000000-0000-4000-8000-00000000f102", tenant=None)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _program(migrated_database, "a7000000-0000-4000-8000-00000000f103", created_by=ghost)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _program(migrated_database, "a7000000-0000-4000-8000-00000000f104", tenant=ghost)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _program(migrated_database, "a7000000-0000-4000-8000-00000000f105", removed_at=CREATED, removed_by=ghost)
    assert execute(migrated_database, "SELECT count(*) FROM identity.programs") == [(1,)]


@pytest.mark.postgres
def test_at_head_a_credential_belongs_to_a_program_row_and_its_state_is_one_of_three(migrated_database):
    """`program_credentials.program_id` is a plain foreign key to `programs`: a program's credential is stored, a person's id is
    refused; states outside the design and a missing expiry are refused, each state as the design describes it goes in (control). (Data model, P-J)"""
    import re

    import psycopg

    _tenant(migrated_database)
    _user(migrated_database, ANN, "ann@x.org")
    _program(migrated_database, SOAR)
    foreign = [d for (d,) in execute(migrated_database, """SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
        JOIN pg_class r ON r.oid = c.conrelid JOIN pg_namespace n ON n.oid = r.relnamespace
        WHERE n.nspname = 'identity' AND r.relname = 'program_credentials' AND c.contype = 'f'""")]
    assert any(re.match(r"FOREIGN KEY \(program_id\) REFERENCES (identity\.)?programs\(id\)", d) for d in foreign), foreign
    expires = CREATED + _dt.timedelta(days=90)
    deadline = CREATED + _dt.timedelta(minutes=10)
    insert = """INSERT INTO identity.program_credentials
                (id, program_id, kind, name, state, key_hash, created_by, created_at, expires_at, pending_deadline,
                 revoked_at, revoked_by)
                VALUES (%s, %s, %s, 'c', %s, %s, %s, %s, %s, %s, %s, %s)"""

    def row(n: int, *, holder: str = SOAR, kind: str = "key", state: str = "live", expires_at: _dt.datetime | None = expires) -> tuple:
        return (f"a7000000-0000-4000-8000-00000000e0{n:02d}", holder, kind, state, f"h{n}" if kind == "key" else None, ANN, CREATED,
                expires_at, deadline if state == "pending" else None, CREATED if state == "revoked" else None,
                ANN if state == "revoked" else None)

    for valid in (row(0, kind="oauth_client", state="pending"), row(1, state="live"), row(2, state="revoked")):
        execute(migrated_database, insert, valid)  # control: each state, as the design describes it
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        execute(migrated_database, insert, row(3, holder=ANN))
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(migrated_database, insert, row(4, state="disabled"))
    with pytest.raises(psycopg.errors.NotNullViolation):
        execute(migrated_database, insert, row(5, expires_at=None))


@pytest.mark.postgres
def test_the_upgrade_refuses_while_a_program_row_exists_and_changes_nothing(empty_database):
    """From `0011_merge_eligibility` holding a program (a users row of kind program, its automation membership): the upgrade
    fails naming programs, the database stays at 0011, no `programs` table appears and both people and program rows remain (O-G, R2)."""
    from defender.migrations import head, upgrade

    assert head() != MERGE_ELIGIBILITY
    _upgrade_to(empty_database, MERGE_ELIGIBILITY)
    _tenant(empty_database)
    _user(empty_database, ANN, "ann@x.org", kind="person")
    _membership(empty_database, ANN_ROW, ANN, role="admin")
    _user(empty_database, SOAR, None, kind="program", created_by=ANN)
    _membership(empty_database, BOB_ROW, SOAR, role="automation")
    with pytest.raises(Exception, match=r"(?i)program"):  # noqa: PT011 — the design names no error type, only that it fails loudly
        upgrade(empty_database)
    assert _version(empty_database) == [(MERGE_ELIGIBILITY,)]
    assert _columns(empty_database, "programs") == {}
    assert execute(empty_database, "SELECT id, kind FROM identity.users ORDER BY kind") == [(ANN, "person"), (SOAR, "program")]
    assert execute(empty_database, "SELECT id, role FROM identity.memberships ORDER BY role") == [(ANN_ROW, "admin"), (BOB_ROW, "automation")]


@pytest.mark.postgres
def test_the_upgrade_refuses_while_a_person_holds_a_role_other_than_admin_and_changes_nothing(empty_database):
    """From `0011_merge_eligibility` with no program but a person holding `automation` (the old schema let any user hold it):
    the upgrade fails naming the role, before any change, rather than at the new role CHECK (O-G, R1)."""
    from defender.migrations import head, upgrade

    assert head() != MERGE_ELIGIBILITY
    _upgrade_to(empty_database, MERGE_ELIGIBILITY)
    _tenant(empty_database)
    _user(empty_database, ANN, "ann@x.org", kind="person")
    _membership(empty_database, ANN_ROW, ANN, role="admin")
    _user(empty_database, BOB, "bob@x.org", kind="person")
    _membership(empty_database, BOB_ROW, BOB, role="automation")
    with pytest.raises(RuntimeError, match=r"1 membership\(s\) whose role is not 'admin'"):
        upgrade(empty_database)
    assert _version(empty_database) == [(MERGE_ELIGIBILITY,)]
    assert _columns(empty_database, "programs") == {}
    assert execute(empty_database, "SELECT id, role FROM identity.memberships ORDER BY role") == [(ANN_ROW, "admin"), (BOB_ROW, "automation")]


@pytest.mark.postgres
def test_the_upgrade_of_people_only_keeps_them_and_reaches_head(empty_database):
    """Control for the refusal: from `0011_merge_eligibility` with one person and her admin membership, the upgrade reaches
    head and both rows are as they were (O-G)."""
    from defender.migrations import head, upgrade

    assert head() != MERGE_ELIGIBILITY
    _upgrade_to(empty_database, MERGE_ELIGIBILITY)
    _tenant(empty_database)
    _user(empty_database, ANN, "ann@x.org", kind="person")
    _membership(empty_database, ANN_ROW, ANN, role="admin")
    upgrade(empty_database)
    assert _version(empty_database) == [(head(),)]
    assert execute(empty_database, "SELECT id, email, status FROM identity.users") == [(ANN, "ann@x.org", "active")]
    assert execute(empty_database, "SELECT id, user_id, status, role FROM identity.memberships") == [(ANN_ROW, ANN, "active", "admin")]
    assert execute(empty_database, "SELECT count(*) FROM identity.programs") == [(0,)]
