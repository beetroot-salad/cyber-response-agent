"""#1214 O11: one revision moves `tenants` to `tenancy`, adds the lifecycle tables, backfills
existing rows for adoption; code at the new head refuses a database still at #1339's baseline."""
from __future__ import annotations

import datetime as _dt

import pytest

from defender.tests.support.shared._postgres1339 import execute

pytestmark = pytest.mark.postgres

BASELINE = "0001_baseline"
LAB = "37963319-1bcf-49a6-9644-6a0699bfe9a3"
CREATED = _dt.datetime(2026, 9, 1, 8, 0, tzinfo=_dt.UTC)


def _upgrade_to(dsn: str, revision: str) -> None:
    from alembic import command
    from alembic.config import Config

    from defender.migrations import HERE

    config = Config()
    config.set_main_option("script_location", str(HERE))
    config.attributes["dsn"] = dsn
    command.upgrade(config, revision)


def _tables(dsn: str, schema: str) -> set[str]:
    return {t for (t,) in execute(dsn, "SELECT tablename FROM pg_tables WHERE schemaname = %s", (schema,))}


def test_code_at_head_refuses_a_database_at_the_baseline_naming_both(empty_database):
    """The 'behind' check #1339 deferred: a database at the baseline is refused, naming it and head (O11)."""
    from defender.migrations import RevisionMismatch, check_version, head

    assert head() != BASELINE
    _upgrade_to(empty_database, BASELINE)
    with pytest.raises(RevisionMismatch) as refused:
        check_version(empty_database)
    assert (refused.value.database, refused.value.head) == (BASELINE, head())
    assert BASELINE in str(refused.value) and head() in str(refused.value)


def test_the_revision_moves_tenants_and_adds_the_lifecycle_tables(migrated_database):
    """At head `tenancy` holds tenants and the new tables, `identity` no tenants, and memberships
    reference `tenancy.tenants` (O11)."""
    assert _tables(migrated_database, "tenancy") == {"tenants", "forge_wiring", "generations", "publish_status"}
    assert "tenants" not in _tables(migrated_database, "identity")
    [(target,)] = execute(migrated_database, """
        SELECT c.confrelid::regclass::text FROM pg_constraint c
        WHERE c.conrelid = 'identity.memberships'::regclass AND c.contype = 'f'
          AND c.confrelid::regclass::text LIKE '%%tenants'""")
    assert target == "tenancy.tenants"


def test_an_existing_tenant_row_is_backfilled_as_a_failed_create_awaiting_adoption(empty_database):
    """A pre-#1214 row becomes `creating`, `create` pending, step `adopt`, with a failure naming adoption (O11, O9)."""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, BASELINE)
    execute(empty_database, "INSERT INTO identity.tenants (id, created_at) VALUES (%s, %s)", (LAB, CREATED))
    upgrade(empty_database)
    [row] = execute(empty_database, """SELECT id, created_at, state, pending_action, step, failure
                                       FROM tenancy.tenants""")
    assert row[:5] == (LAB, CREATED, "creating", "create", "adopt")
    assert "adopt" in row[5]


def test_the_state_and_pending_action_must_be_an_allowed_pair(migrated_database):
    """The CHECK refuses `active` with `create` pending and takes `active` with nothing pending (O11, data model)."""
    insert = """INSERT INTO tenancy.tenants (id, created_at, state, pending_action)
                VALUES (gen_random_uuid()::text, now(), 'active', %s)"""
    import psycopg.errors

    execute(migrated_database, insert, (None,))  # control
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(migrated_database, insert, ("create",))
