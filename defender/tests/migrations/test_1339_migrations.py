"""#1339 the one migration history: single head (O1), empty -> head (O1, O6e), the version check (O2),
and migrations matching the models (O3).

PostgreSQL cases are marked `postgres`; each runs on a database of its own (`conftest.py`).
"""
from __future__ import annotations

from typing import Any

import pytest

from defender.tests.support.shared._postgres1339 import VERSION_TABLE, database, execute

#: The schemas PostgreSQL itself owns; everything else in a database is ours to compare.
_SYSTEM = "nspname !~ '^pg_' AND nspname <> 'information_schema'"
IDENTITY_TABLES = {"tenants", "users", "memberships", "sessions"}
UNKNOWN_REVISION = "f00dfeedbeef"


def catalog(dsn: str) -> dict[str, Any]:
    """Every column, constraint and index of every non-system schema, Alembic's version table aside."""
    columns = execute(dsn, f"""
        SELECT c.table_schema, c.table_name, c.column_name, c.data_type, c.is_nullable, c.column_default
        FROM information_schema.columns c JOIN pg_namespace n ON n.nspname = c.table_schema
        WHERE {_SYSTEM} AND (c.table_schema, c.table_name) <> ('public', 'alembic_version')""")
    constraints = execute(dsn, f"""
        SELECT n.nspname, t.relname, k.conname, k.contype, pg_get_constraintdef(k.oid)
        FROM pg_constraint k JOIN pg_class t ON t.oid = k.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE {_SYSTEM} AND (n.nspname, t.relname) <> ('public', 'alembic_version')""")
    indexes = execute(dsn, f"""
        SELECT i.schemaname, i.tablename, i.indexname, i.indexdef
        FROM pg_indexes i JOIN pg_namespace n ON n.nspname = i.schemaname
        WHERE {_SYSTEM} AND (i.schemaname, i.tablename) <> ('public', 'alembic_version')""")
    schemas = execute(dsn, f"SELECT nspname FROM pg_namespace WHERE {_SYSTEM}")
    return {"schemas": sorted(schemas), "columns": sorted(columns, key=repr),
            "constraints": sorted(constraints), "indexes": sorted(indexes)}


def _recorded_revision(dsn: str) -> list[str]:
    return [r[0] for r in execute(dsn, f"SELECT version_num FROM {VERSION_TABLE}")]


def _tables(dsn: str, schema: str) -> set[str]:
    return {r[0] for r in execute(
        dsn, "SELECT table_name FROM information_schema.tables WHERE table_schema = %s", (schema,))}


# --- O1 one history, one head ----------------------------------------------------------------------


def test_the_history_has_exactly_one_head():
    """The shared history has one head, and that is the head the code names (O1, P1)."""
    from defender.migrations import head, heads

    assert len(heads()) == 1
    assert heads() == (head(),)


@pytest.mark.postgres
def test_upgrading_an_empty_database_records_head_and_creates_identitys_tables(empty_database):
    """Empty -> head: the version table in `public` holds head; identity's four tables are in `identity` (O1)."""
    from defender.migrations import head, upgrade

    upgrade(empty_database)
    assert _recorded_revision(empty_database) == [head()]
    assert _tables(empty_database, "identity") == IDENTITY_TABLES
    assert _tables(empty_database, "public") == {"alembic_version"}


@pytest.mark.postgres
def test_upgrading_a_database_already_at_head_changes_nothing(migrated_database):
    """Re-upgrade is a no-op: same revision, same catalog (O1, O6e)."""
    from defender.migrations import head, upgrade

    before = catalog(migrated_database)
    upgrade(migrated_database)
    assert _recorded_revision(migrated_database) == [head()]
    assert catalog(migrated_database) == before


# --- O2 the version check ------------------------------------------------------------------------


@pytest.mark.postgres
def test_the_version_check_passes_at_head(migrated_database):
    """A database at head passes the check (O2, P2)."""
    from defender.migrations import check_version

    assert check_version(migrated_database) is None


@pytest.mark.postgres
@pytest.mark.parametrize("state", ["ahead", "unmigrated"])
def test_the_version_check_refuses_a_database_not_at_head_naming_both_revisions(state, migrated_database, empty_database):
    """Ahead (a revision this code does not know) or unmigrated: refused, naming the database's revision and head (O2)."""
    from defender.migrations import RevisionMismatch, check_version, head

    if state == "ahead":
        dsn, recorded = migrated_database, UNKNOWN_REVISION
        execute(dsn, f"UPDATE {VERSION_TABLE} SET version_num = %s", (recorded,))
    else:
        dsn, recorded = empty_database, None
    with pytest.raises(RevisionMismatch) as refused:
        check_version(dsn)
    assert (refused.value.database, refused.value.head) == (recorded, head())
    assert head() in str(refused.value)
    if recorded is not None:
        assert recorded in str(refused.value)


# --- O3 models match migrations ------------------------------------------------------------------


@pytest.mark.postgres
def test_the_migrated_schema_is_the_schema_the_models_declare(migrated_database):
    """A database at head and one built from the models have one catalog, CHECKs and partial indexes included (O3)."""
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url

    from defender.migrations import target_metadata

    with database(migrated=False) as from_models:
        for schema in sorted({t.schema for t in target_metadata.tables.values()}):
            execute(from_models, f'CREATE SCHEMA "{schema}"')
        engine = create_engine(make_url(from_models).set(drivername="postgresql+psycopg"))
        try:
            target_metadata.create_all(engine)
        finally:
            engine.dispose()
        assert catalog(from_models) == catalog(migrated_database)

    # The comparison sees what O3 is about: CHECKs, the partial unique index, and no server defaults (P4).
    migrated = catalog(migrated_database)
    assert [s for (s,) in migrated["schemas"] if s != "public"] == ["identity"]
    assert any(c[:2] == ("identity", "users") and c[3] == "c" for c in migrated["constraints"])
    assert any(i[:2] == ("identity", "memberships") and "WHERE" in i[3] and "invited" in i[3]
               for i in migrated["indexes"])
    assert [c for c in migrated["columns"] if c[5] is not None] == []
