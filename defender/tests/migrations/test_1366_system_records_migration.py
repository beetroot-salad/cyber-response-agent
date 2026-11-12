"""#1366 upgrade: `0015_system_records` creates the three records tables and the proxy's read-only role (R14, shared-interface).

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`). Roles are cluster-wide and the
tests share one server, so no case drops the role: an earlier upgrade (any database's) has usually created it already.
"""
from __future__ import annotations

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared._postgres1339 import execute

ROLE = "defender_proxy_reader"
PREVIOUS = "0014_learning_cutover_action"  # the head before #1366 (main's learning-store cutover revision, #1278)
TABLES = {
    "system_versions": {"tenant_id", "system_id", "version", "adapter_id", "enabled", "settings", "access",
                        "credential_generation", "deleted", "author", "written_at"},
    "case_versions": {"tenant_id", "version", "system_id", "comment_body", "deleted", "author", "written_at"},
    "records_mark": {"tenant_id"},
}


def _columns(dsn: str, table: str) -> set[str]:
    return {c for (c,) in execute(dsn, "SELECT column_name FROM information_schema.columns "
                                       "WHERE table_schema = 'tenancy' AND table_name = %s", (table,))}


def _can(dsn: str, table: str, privilege: str) -> bool:
    return execute(dsn, "SELECT has_table_privilege(%s, %s, %s)", (ROLE, f"tenancy.{table}", privilege))[0][0]


def _ensure_role(dsn: str) -> None:
    execute(dsn, f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{ROLE}') "
                 f"THEN CREATE ROLE {ROLE} NOLOGIN; END IF; END $$")


def test_the_revision_sits_directly_on_the_previous_head():
    from defender.migrations import _scripts

    assert _scripts().get_revision("0015_system_records").down_revision == PREVIOUS


@pytest.mark.postgres
def test_at_head_the_records_tables_have_the_designed_columns_a_tenant_key_and_a_tenant_that_exists(migrated_database):
    """The system-versions, case-versions and mark tables hold exactly the designed columns; the key of each starts with
    the tenant, and the tenant must exist. (#1366 data model)"""
    for table, columns in TABLES.items():
        assert _columns(migrated_database, table) == columns, table
        keyed = execute(migrated_database, """SELECT a.attname FROM pg_index i JOIN pg_attribute a
            ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
            WHERE i.indrelid = %s::regclass AND i.indisprimary ORDER BY array_position(i.indkey::int2[], a.attnum)""",
                        (f"tenancy.{table}",))
        assert [c for (c,) in keyed][:1] == ["tenant_id"], (table, keyed)
        refs = execute(migrated_database, "SELECT confrelid::regclass::text FROM pg_constraint "
                                          "WHERE conrelid = %s::regclass AND contype = 'f'", (f"tenancy.{table}",))
        assert ("tenancy.tenants",) in refs, (table, refs)
    key = [c for (c,) in execute(migrated_database, """SELECT a.attname FROM pg_index i JOIN pg_attribute a
        ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
        WHERE i.indrelid = 'tenancy.system_versions'::regclass AND i.indisprimary""")]
    assert set(key) == {"tenant_id", "system_id", "version"}


@pytest.mark.postgres
def test_at_head_the_proxy_role_cannot_log_in_and_may_only_select_the_system_versions_and_the_mark(migrated_database):
    """`defender_proxy_reader` is NOLOGIN, may SELECT `system_versions` and `records_mark` and nothing else there: no
    write to either, no read of the case table or the tenants. (#1366 R14, amended: the proxy reads whether a token's
    tenant is imported from the mark)"""
    assert execute(migrated_database, "SELECT rolcanlogin FROM pg_roles WHERE rolname = %s", (ROLE,)) == [(False,)]
    assert _can(migrated_database, "system_versions", "SELECT"), "control"
    assert _can(migrated_database, "records_mark", "SELECT"), "control"
    wrong = [(t, p) for t, p in [("system_versions", "INSERT"), ("system_versions", "UPDATE"), ("system_versions", "DELETE"),
                                 ("system_versions", "TRUNCATE"), ("case_versions", "SELECT"), ("records_mark", "INSERT"),
                                 ("records_mark", "DELETE"), ("tenants", "SELECT")] if _can(migrated_database, t, p)]
    assert wrong == []


@pytest.mark.postgres
def test_an_upgrade_over_a_role_that_already_exists_succeeds_and_grants_it(empty_database):
    """The role may exist before the upgrade (roles are cluster-wide): the upgrade neither fails nor leaves it without
    its SELECT. (#1366 R14: idempotent)"""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, PREVIOUS)
    _ensure_role(empty_database)

    upgrade(empty_database)

    assert _can(empty_database, "system_versions", "SELECT")

