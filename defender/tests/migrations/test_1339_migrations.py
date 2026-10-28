"""#1339 the one migration history: single head (O1), empty -> head (O1, O6e), the version check (O2),
and migrations matching the models (O3).

PostgreSQL cases are marked `postgres`; each runs on a database of its own (`conftest.py`).
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._postgres1339 import VERSION_TABLE, database, execute

#: The schemas PostgreSQL itself owns; everything else in a database is ours to compare.
_SYSTEM = "nspname !~ '^pg_' AND nspname <> 'information_schema'"
IDENTITY_TABLES = {"tenants", "users", "memberships", "sessions"}
UNKNOWN_REVISION = "f00dfeedbeef"
ROOT = Path(__file__).resolve().parents[3]  # the checkout under test, put first on the child's path


def run_python(code: str, **env: str | None) -> subprocess.CompletedProcess[str]:
    """`code` in a fresh interpreter (clean sys.modules); `env` entries set, or removed when None."""
    child = {**os.environ, "PYTHONPATH": os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")])}
    for key, value in env.items():
        child.pop(key, None) if value is None else child.__setitem__(key, value)
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], env=child, cwd=ROOT,
                          capture_output=True, text=True, timeout=120)


def dev_command(dsn: str | None, *args: str) -> subprocess.CompletedProcess[str]:
    """`python -m defender.migrations <args>` as a developer runs it, reading DEFENDER_DATABASE_DSN."""
    child = {k: v for k, v in os.environ.items() if k != "DEFENDER_DATABASE_DSN"}
    child["PYTHONPATH"] = os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")])
    if dsn is not None:
        child["DEFENDER_DATABASE_DSN"] = dsn
    return subprocess.run([sys.executable, "-m", "defender.migrations", *args], env=child, cwd=ROOT,
                          capture_output=True, text=True, timeout=120)


def catalog(dsn: str) -> dict[str, Any]:
    """Every column (full formatted type), constraint and index of every non-system schema, Alembic's version table aside."""
    columns = execute(dsn, f"""
        SELECT n.nspname, t.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
               pg_get_expr(d.adbin, d.adrelid)
        FROM pg_attribute a JOIN pg_class t ON t.oid = a.attrelid JOIN pg_namespace n ON n.oid = t.relnamespace
        LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE a.attnum > 0 AND NOT a.attisdropped AND t.relkind IN ('r', 'p') AND {_SYSTEM}
          AND (n.nspname, t.relname) <> ('public', 'alembic_version')""")
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

    from defender.migrations.models import target_metadata

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


#: Single-statement drifts of a migrated database, each of a kind autogenerate alone does not see (O3, C7) or P4 forbids.
_DRIFTS = {
    "a CHECK's text": "ALTER TABLE identity.users DROP CONSTRAINT {check}, ADD CONSTRAINT {check} CHECK (true)",
    "a constraint's name": "ALTER TABLE identity.users RENAME CONSTRAINT {check} TO renamed_by_hand",
    "a partial index's predicate": "DROP INDEX identity.{partial}; CREATE UNIQUE INDEX {partial} ON identity.memberships (user_id, tenant_id) WHERE status = 'invited'",
    "a server default": "ALTER TABLE identity.tenants ALTER COLUMN created_at SET DEFAULT now()",
    "a column's type modifier": "ALTER TABLE identity.tenants ALTER COLUMN created_at TYPE timestamptz(3)",
}


@pytest.mark.postgres
@pytest.mark.parametrize("drift", sorted(_DRIFTS))
def test_the_catalog_comparison_sees_each_kind_of_drift(drift, migrated_database):
    """The O3 comparison's control: each drift changes the catalog, so equality above means something."""
    before = catalog(migrated_database)
    check = next(c[2] for c in before["constraints"] if c[:2] == ("identity", "users") and c[3] == "c")
    partial = next(i[2] for i in before["indexes"] if i[:2] == ("identity", "memberships") and "WHERE" in i[3])
    for statement in _DRIFTS[drift].format(check=check, partial=partial).split(";"):
        execute(migrated_database, statement)
    assert catalog(migrated_database) != before


def _autogenerate_diff(dsn: str) -> list[Any]:
    """What autogenerate would write for `dsn`, filtered as the Alembic environment filters it."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url

    from defender.migrations import VERSION_TABLE_SCHEMA, include_object
    from defender.migrations.models import target_metadata

    engine = create_engine(make_url(dsn).set(drivername="postgresql+psycopg"))
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn, opts={
                "include_schemas": True, "include_object": include_object,
                "version_table_schema": VERSION_TABLE_SCHEMA, "target_metadata": target_metadata})
            return compare_metadata(context, target_metadata)
    finally:
        engine.dispose()


@pytest.mark.postgres
def test_autogenerate_ignores_tables_in_public_and_still_sees_drift_in_a_feature_schema(migrated_database):
    """A table in `public` (Alembic's own, or anyone's) is never one to drop; a feature table's drift still shows."""
    execute(migrated_database, "CREATE TABLE public.not_ours (id int)")
    assert _autogenerate_diff(migrated_database) == []

    execute(migrated_database, "ALTER TABLE identity.users DROP COLUMN display_name")
    assert [d[0] for d in _autogenerate_diff(migrated_database)] == ["add_column"]


@pytest.mark.postgres
def test_tenants_created_at_is_a_column_the_repository_must_supply(migrated_database):
    """D/P4: `tenants.created_at` exists and has no server default (the caller passes `now`)."""
    rows = execute(migrated_database, """SELECT column_default FROM information_schema.columns
                   WHERE table_schema = 'identity' AND table_name = 'tenants' AND column_name = 'created_at'""")
    assert rows == [(None,)]


# --- O2 refinements ------------------------------------------------------------------------------


@pytest.mark.postgres
def test_the_version_check_treats_a_version_table_without_a_row_as_unmigrated(migrated_database):
    """An emptied version table is `None`, like a missing one (F)."""
    from defender.migrations import RevisionMismatch, check_version

    execute(migrated_database, f"DELETE FROM {VERSION_TABLE}")
    with pytest.raises(RevisionMismatch) as refused:
        check_version(migrated_database)
    assert refused.value.database is None


@pytest.mark.postgres
def test_the_version_check_only_reads(empty_database):
    """Refusing an unmigrated database does not create the version table or anything else (O2)."""
    from defender.migrations import RevisionMismatch, check_version

    before = catalog(empty_database)
    with pytest.raises(RevisionMismatch):
        check_version(empty_database)
    assert catalog(empty_database) == before
    assert execute(empty_database, "SELECT to_regclass('public.alembic_version')") == [(None,)]


# --- H, I: what a process loads ------------------------------------------------------------------


def test_head_and_heads_load_no_features_models():
    """H: reading the history imports no `defender.identity`; the control shows the probe can see it."""
    probe = run_python("""
        import sys
        from defender.migrations import head, heads
        heads(); head()
        print("identity" if "defender.identity" in sys.modules else "clean")
        from defender.migrations.models import target_metadata
        print("identity" if "defender.identity" in sys.modules else "clean")
    """)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.split() == ["clean", "identity"]


@pytest.mark.postgres
def test_the_version_check_loads_no_features_models(migrated_database):
    """H: a process that checks its version has not loaded `defender.identity`."""
    probe = run_python("""
        import os, sys
        from defender.migrations import check_version
        check_version(os.environ["DSN"])
        print("identity" if "defender.identity" in sys.modules else "clean")
    """, DSN=migrated_database)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.split() == ["clean"]


def test_importing_identity_loads_no_database_driver():
    """I: `import defender.identity` brings in no psycopg; the identity package itself did load."""
    probe = run_python("""
        import sys
        import defender.identity
        print("identity" if "defender.identity" in sys.modules else "missing")
        print("psycopg" if any(m == "psycopg" or m.startswith("psycopg.") for m in sys.modules) else "no-driver")
    """)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.split() == ["identity", "no-driver"]


# --- G the dev command ---------------------------------------------------------------------------


@pytest.mark.postgres
def test_the_dev_command_upgrades_the_database_named_by_the_environment(empty_database):
    """G/O7: `python -m defender.migrations upgrade` takes the DSN from DEFENDER_DATABASE_DSN; a second run is a no-op."""
    from defender.migrations import head

    for _ in range(2):
        done = dev_command(empty_database, "upgrade")
        assert done.returncode == 0, done.stderr
        assert _recorded_revision(empty_database) == [head()]
    assert _tables(empty_database, "identity") == IDENTITY_TABLES


def test_the_dev_command_without_a_database_refuses_loudly():
    """G: no DEFENDER_DATABASE_DSN -> non-zero exit and a message on stderr, naming the variable."""
    done = dev_command(None, "upgrade")
    assert done.returncode != 0
    assert "DEFENDER_DATABASE_DSN" in done.stderr
