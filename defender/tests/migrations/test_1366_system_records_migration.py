"""#1366 upgrade: `0015_system_records` creates the three records tables and the proxy's read-only role (R14, shared-interface).

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`). Roles are cluster-wide and the
tests share one server, so no case drops the role: an earlier upgrade (any database's) has usually created it already.
"""
from __future__ import annotations

import pytest

from defender.tests.migrations._marked1470 import BEFORE_DROP
from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared._postgres1339 import execute

ROLE = "defender_proxy_reader"
PREVIOUS = "0014_learning_cutover_action"  # the head before #1366 (main's learning-store cutover revision, #1278)
TABLES = {
    "system_versions": {"tenant_id", "system_id", "version", "adapter_id", "enabled", "settings", "access",
                        "credential_generation", "deleted", "author", "written_at"},
    "case_versions": {"tenant_id", "version", "system_id", "comment_body", "deleted", "author", "written_at"},
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
def test_at_head_the_proxy_role_cannot_log_in_and_may_only_select_system_versions_and_the_tenant_rows_id_and_state(
        migrated_database):
    """`defender_proxy_reader` is NOLOGIN, may SELECT `system_versions` and exactly the `id` and `state` columns of the
    tenant row, checked column by column; the mark table is gone. (#1366 R14, amended by #1470 O8)"""
    assert execute(migrated_database, "SELECT rolcanlogin FROM pg_roles WHERE rolname = %s", (ROLE,)) == [(False,)]
    assert _can(migrated_database, "system_versions", "SELECT"), "control"
    assert execute(migrated_database, "SELECT to_regclass('tenancy.records_mark')") == [(None,)]
    columns = {c for (c,) in execute(migrated_database, "SELECT column_name FROM information_schema.columns "
                                                        "WHERE table_schema = 'tenancy' AND table_name = 'tenants'")}
    assert {"id", "state"} < columns, "premise"
    readable = {c for c in columns if execute(migrated_database, "SELECT has_column_privilege(%s, 'tenancy.tenants', %s, "
                                                                 "'SELECT')", (ROLE, c))[0][0]}
    assert readable == {"id", "state"}
    wrong = [(t, p) for t, p in [("system_versions", "INSERT"), ("system_versions", "UPDATE"), ("system_versions", "DELETE"),
                                 ("system_versions", "TRUNCATE"), ("case_versions", "SELECT"), ("tenants", "SELECT"),
                                 ("tenants", "UPDATE")] if _can(migrated_database, t, p)]
    assert wrong == []


#: Tenants by id: a stated state's tenant without a mark, an active one with its mark (control), an offboarded one without.
UNMARKED, MARKED, GONE = (f"a1470000-0000-4000-8000-00000000000{n}" for n in (1, 2, 3))
_PENDING = {"creating": ("create", "names", "service"), "offboarding": ("offboard", "offboard", "service")}


def _tenant(dsn: str, tenant: str, state: str, *, mark: bool) -> None:
    action, step, actor = _PENDING.get(state, (None, None, None))
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor) "
                 "VALUES (%s, now(), %s, %s, %s, %s)", (tenant, state, action, step, actor))
    if mark:
        execute(dsn, "INSERT INTO tenancy.records_mark (tenant_id) VALUES (%s)", (tenant,))


def test_the_revision_that_drops_the_mark_sits_directly_on_the_previous_head():
    """The one new revision follows `0016_list_indexes`. (#1470 O8)"""
    from defender.migrations import _scripts

    head = _scripts().get_current_head()
    assert head != BEFORE_DROP
    assert _scripts().get_revision(head).down_revision == BEFORE_DROP


@pytest.mark.postgres
@pytest.mark.parametrize("state", ["creating", "active", "offboarding"])
def test_1470_o12_the_mark_drop_stops_naming_the_tenants_without_a_mark_and_changes_nothing(empty_database, state):
    """A tenant that is not offboarded and has no mark (from before #1366, never imported) stops the upgrade, the message
    lists it and neither the marked tenant nor the offboarded one; the mark table, its rows and the revision stay.
    (O12, guard in the 0005/0012 pattern)"""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, BEFORE_DROP)
    _tenant(empty_database, UNMARKED, state, mark=False)
    _tenant(empty_database, MARKED, "active", mark=True)
    _tenant(empty_database, GONE, "offboarded", mark=False)

    with pytest.raises(RuntimeError) as stopped:
        upgrade(empty_database)

    message = str(stopped.value)
    assert UNMARKED in message, message
    assert MARKED not in message, message
    assert GONE not in message, message
    assert execute(empty_database, "SELECT tenant_id FROM tenancy.records_mark") == [(MARKED,)]
    assert execute(empty_database, "SELECT version_num FROM alembic_version") == [(BEFORE_DROP,)]


@pytest.mark.postgres
def test_1470_o12_the_mark_drop_runs_when_every_tenant_not_offboarded_has_its_mark_and_keeps_the_records(empty_database):
    """Marked tenants (any state but offboarded) and an offboarded one without: the upgrade reaches head, the mark table
    is gone and the tenants' version rows are as they were. (O12, O8)"""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, BEFORE_DROP)
    _tenant(empty_database, MARKED, "active", mark=True)
    _tenant(empty_database, GONE, "offboarded", mark=False)
    execute(empty_database, "INSERT INTO tenancy.system_versions (tenant_id, system_id, version, adapter_id, enabled, settings, "
                            "access, credential_generation, deleted, author, written_at) VALUES "
                            "(%s, 'ticket', 1, 'ticket', true, '{}'::jsonb, 'x', 1, false, 'seed', now())", (MARKED,))

    upgrade(empty_database)

    assert execute(empty_database, "SELECT to_regclass('tenancy.records_mark')") == [(None,)]
    assert execute(empty_database, "SELECT system_id, version FROM tenancy.system_versions WHERE tenant_id = %s",
                   (MARKED,)) == [("ticket", 1)]
    assert execute(empty_database, "SELECT id FROM tenancy.tenants ORDER BY id") == [(MARKED,), (GONE,)]


@pytest.mark.postgres
def test_an_upgrade_over_a_role_that_already_exists_succeeds_and_grants_it(empty_database):
    """The role may exist before the upgrade (roles are cluster-wide): the upgrade neither fails nor leaves it without
    its SELECT. (#1366 R14: idempotent)"""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, PREVIOUS)
    _ensure_role(empty_database)

    upgrade(empty_database)

    assert _can(empty_database, "system_versions", "SELECT")

