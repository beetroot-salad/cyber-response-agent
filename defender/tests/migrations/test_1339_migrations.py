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
IDENTITY_TABLES = {"users", "memberships", "sessions", "program_credentials", "warning_deliveries"}  # #1214: `tenants` moved to `tenancy`; #1307 adds credentials and their warning deliveries
LEARNING_TABLES = {"work_items", "batches", "commits", "commit_changes",
                   "feedback_issues", "feedback_comments", "feedback_tick"}  # #1278: learning's work tracking, A4 feedback (design: Schema)
JOBS_TABLES = {"alerts", "investigations", "learning_jobs", "learning_checks"}  # #1342, #1344 (amendment 3: learning_checks) (#1345 r5: the mapping table is a tenant record, in `tenancy`)
UNKNOWN_REVISION = "f00dfeedbeef"
#: #1345 r5 Upgrade: the migration after `0006_job_leases`. r5 names no id: this one is DESIGN-IMPLIED for the code stage.
ALERT_MAPPING_REVISION = "0007_alert_mapping"
#: #1344: the learning jobs table, on the alert-mapping revision; head. The handoff names it.
LEARNING_JOBS_REVISION = "0008_learning_jobs"
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
    """Empty -> head: the version table in `public` holds head; identity's five tables are in `identity` (O1)."""
    from defender.migrations import head, upgrade

    upgrade(empty_database)
    assert _recorded_revision(empty_database) == [head()]
    assert _tables(empty_database, "identity") == IDENTITY_TABLES
    assert _tables(empty_database, "jobs") == JOBS_TABLES
    assert _tables(empty_database, "learning") == LEARNING_TABLES
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
    assert [s for (s,) in migrated["schemas"] if s != "public"] == ["identity", "jobs", "learning", "tenancy"]  # #1342 adds `jobs`, #1278 `learning`
    assert any(c[:2] == ("identity", "users") and c[3] == "c" for c in migrated["constraints"])
    assert any(i[:2] == ("identity", "memberships") and "WHERE" in i[3] and "invited" in i[3]
               for i in migrated["indexes"])
    assert [c for c in migrated["columns"] if c[5] is not None] == []


#: Single-statement drifts of a migrated database, each of a kind autogenerate alone does not see (O3, C7) or P4 forbids.
_DRIFTS = {
    "a CHECK's text": "ALTER TABLE identity.users DROP CONSTRAINT {check}, ADD CONSTRAINT {check} CHECK (true)",
    "a constraint's name": "ALTER TABLE identity.users RENAME CONSTRAINT {check} TO renamed_by_hand",
    "a partial index's predicate": "DROP INDEX identity.{partial}; CREATE UNIQUE INDEX {partial} ON identity.memberships (user_id, tenant_id) WHERE status = 'invited'",
    "a server default": "ALTER TABLE tenancy.tenants ALTER COLUMN created_at SET DEFAULT now()",
    "a column's type modifier": "ALTER TABLE tenancy.tenants ALTER COLUMN created_at TYPE timestamptz(3)",
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
                   WHERE table_schema = 'tenancy' AND table_name = 'tenants' AND column_name = 'created_at'""")
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
    """H: reading the history imports no `defender.identity` or `defender.jobs`; the control shows the probe can see both."""
    probe = run_python("""
        import sys
        from defender.migrations import head, heads
        heads(); head()
        def seen():
            return " ".join(name for name in ("identity", "jobs") if f"defender.{name}" in sys.modules) or "clean"
        print(seen())
        from defender.migrations.models import target_metadata
        print(seen())
    """)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.splitlines() == ["clean", "identity jobs"]


@pytest.mark.postgres
def test_the_version_check_loads_no_features_models(migrated_database):
    """H: a process that checks its version has not loaded `defender.identity`."""
    probe = run_python("""
        import os, sys
        from defender.migrations import check_version
        check_version(os.environ["DSN"])
        print("loaded" if {"defender.identity", "defender.jobs"} & set(sys.modules) else "clean")
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
    assert _tables(empty_database, "learning") == LEARNING_TABLES


def test_the_dev_command_without_a_database_refuses_loudly():
    """G: no DEFENDER_DATABASE_DSN -> non-zero exit and a message on stderr, naming the variable."""
    done = dev_command(None, "upgrade")
    assert done.returncode != 0
    assert "DEFENDER_DATABASE_DSN" in done.stderr


# --- #1342 the jobs schema: revision 0004 on #1163's 0003_sign_login, the lean constraints and nothing more ----------


def test_the_jobs_revision_sits_directly_on_the_sign_login_revision():
    """The history is the baseline, `0002_tenancy`, `0003_sign_login`, then `0004_jobs` (#1342 O1; r6: tenants are
    #1214's records; jobs follows #1163's revision, so the history stays one line), then #1382's `0005_uuid_ids`,
    #1343's `0006_job_leases`, #1345's `0007_alert_mapping` and #1344's `0008_learning_jobs` (#1307's `0009_programs` above it). (The name predates
    them; the node id is kept.)"""
    from defender.migrations import _scripts, head

    scripts = _scripts()
    # `0009_programs` (#1307, design: data model, new columns) now sits on 0008, and later revisions may follow: the line pinned
    # here is the one from the baseline up to 0008, read from the bottom, with a single head above it.
    assert len(scripts.get_heads()) == 1
    assert head() in {r.revision for r in scripts.walk_revisions()}
    assert scripts.get_revision(LEARNING_JOBS_REVISION).down_revision == ALERT_MAPPING_REVISION
    assert scripts.get_revision(ALERT_MAPPING_REVISION).down_revision == "0006_job_leases"
    assert scripts.get_revision("0006_job_leases").down_revision == "0005_uuid_ids"
    assert scripts.get_revision("0005_uuid_ids").down_revision == "0004_jobs"
    assert scripts.get_revision("0004_jobs").down_revision == "0003_sign_login"
    assert scripts.get_revision("0003_sign_login").down_revision == "0002_tenancy"
    assert scripts.get_revision("0002_tenancy").down_revision == "0001_baseline"
    assert [r.revision for r in scripts.walk_revisions()][-8:] == [
        LEARNING_JOBS_REVISION, ALERT_MAPPING_REVISION, "0006_job_leases", "0005_uuid_ids", "0004_jobs", "0003_sign_login", "0002_tenancy",
        "0001_baseline"]


@pytest.mark.postgres
def test_upgrading_a_database_at_the_baseline_adds_jobs_and_keeps_the_tenant_in_tenancy(empty_database):
    """From `0001_baseline` with a tenant row, `upgrade` moves it to `tenancy`, adds the jobs tables and records head (#1342 O1, r6)."""
    from alembic import command

    from defender.migrations import _config, head, upgrade

    config = _config()
    config.attributes["dsn"] = empty_database
    command.upgrade(config, "0001_baseline")
    assert _tables(empty_database, "jobs") == set()
    execute(empty_database, "INSERT INTO identity.tenants (id, created_at) VALUES ('f1000000-0000-4000-8000-000000000001', now())")

    upgrade(empty_database)
    assert _recorded_revision(empty_database) == [head()]
    assert _tables(empty_database, "jobs") == JOBS_TABLES
    assert execute(empty_database, "SELECT id FROM tenancy.tenants") == [("f1000000-0000-4000-8000-000000000001",)]


def _jobs_columns(dsn: str, table: str) -> dict[str, tuple[str, bool, Any]]:
    rows = execute(dsn, """SELECT column_name, data_type, is_nullable = 'YES', column_default
                           FROM information_schema.columns WHERE table_schema = 'jobs' AND table_name = %s""",
                   (table,))
    return {name: (kind, nullable, default) for name, kind, nullable, default in rows}


def _jobs_constraints(dsn: str, table: str) -> list[tuple[str, tuple[str, ...], str]]:
    """(type, key columns sorted, definition) of every constraint on `jobs.<table>`."""
    rows = execute(dsn, """
        SELECT k.contype, array_agg(a.attname ORDER BY a.attname), pg_get_constraintdef(k.oid)
        FROM pg_constraint k JOIN pg_class t ON t.oid = k.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
        LEFT JOIN LATERAL unnest(k.conkey) AS u(attnum) ON true
        LEFT JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.attnum
        WHERE n.nspname = 'jobs' AND t.relname = %s GROUP BY k.oid, k.contype""", (table,))
    return sorted((kind, tuple(cols), definition) for kind, cols, definition in rows if kind != "n")


def _jobs_indexes(dsn: str, table: str) -> list[str]:
    return sorted(r[0] for r in execute(
        dsn, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'jobs' AND tablename = %s", (table,)))


@pytest.mark.postgres
def test_the_jobs_columns_are_the_designed_ones_without_server_defaults(migrated_database):
    """Both tables hold exactly the designed columns; required ones are NOT NULL (an alert's title and description, derived by the store, are nullable, #1345); `cost_usd` is a nullable float and #1377's `cost_is_lower_limit` a required boolean; `raw` is bytea; no defaults (#1342 M10, R3; #1377 r4 API field)."""
    alerts = _jobs_columns(migrated_database, "alerts")
    investigations = _jobs_columns(migrated_database, "investigations")
    assert set(alerts) == {"id", "tenant_id", "vendor", "vendor_ticket_id", "fired_at", "changed_at",
                           "received_at", "title", "description", "raw"}
    assert set(investigations) == {"id", "tenant_id", "alert_id", "request_key", "attempt", "stage", "created_at",
                                   "started_at", "finished_at", "disposition", "cost_usd", "knowledge",
                                   "failure_reason", "failure_message", "lease_expires_at", "accounting_written_at",
                                   "cost_is_lower_limit"}
    # #1345 (data model): the store derives an alert's title and description from the tenant's mapping, so both are nullable.
    assert {n for n, (_, nullable, _) in alerts.items() if nullable} == {"title", "description"}
    nullable = {n for n, (_, can_be_null, _) in investigations.items() if can_be_null}
    assert nullable == {"started_at", "finished_at", "disposition", "cost_usd", "knowledge", "failure_reason",
                        "failure_message", "lease_expires_at", "accounting_written_at"}
    assert alerts["raw"][0] == "bytea"
    assert investigations["cost_usd"][0] == "double precision"
    assert investigations["cost_is_lower_limit"][0] == "boolean"
    assert [c for cols in (alerts, investigations) for c, (_, _, default) in cols.items() if default is not None] == []


@pytest.mark.postgres
def test_the_jobs_constraints_are_exactly_the_designed_ones(migrated_database):
    """PKs, the tenant FK, the alert uniques, the composite FK, the attempt unique, a stage CHECK, #1343's lease CHECK and #1377's
    lower-limit-needs-a-cost CHECK; no other constraint (#1342 M10; #1377 S4: the job row enforces it)."""
    alerts = _jobs_constraints(migrated_database, "alerts")
    assert [(kind, cols) for kind, cols, _ in alerts] == sorted([
        ("f", ("tenant_id",)), ("p", ("id",)), ("u", ("id", "tenant_id")),
        ("u", ("tenant_id", "vendor", "vendor_ticket_id"))])
    assert next(d for k, _, d in alerts if k == "f") == "FOREIGN KEY (tenant_id) REFERENCES tenancy.tenants(id)", \
        "no ON DELETE / ON UPDATE action: the default restricts (M10)"

    investigations = _jobs_constraints(migrated_database, "investigations")
    assert sorted((kind, cols) for kind, cols, _ in investigations if kind != "c") == sorted([
        ("f", ("alert_id", "tenant_id")), ("p", ("id",)),
        ("u", ("alert_id", "attempt", "request_key", "tenant_id"))])
    foreign = next(d for k, _, d in investigations if k == "f")
    assert foreign == "FOREIGN KEY (tenant_id, alert_id) REFERENCES jobs.alerts(tenant_id, id)", \
        "no ON DELETE / ON UPDATE action: delete and cascade are the store's, under the alert lock (M10, O10)"
    checks = [d for k, _, d in investigations if k == "c"]
    assert len(checks) == 3, "the stage CHECK, #1343's running-has-a-lease CHECK and #1377's mark-needs-a-cost CHECK, no other"
    [check] = [d for d in checks if "completed" in d]
    for stage in ("queued", "running", "completed", "unparseable", "failed", "aborted"):
        assert f"'{stage}'" in check
    [mark] = [d for d in checks if "cost_is_lower_limit" in d]
    assert "cost_usd" in mark
    [lease] = [d for d in checks if "completed" not in d and d != mark]
    assert "lease_expires_at" in lease
    assert "'running'" in lease  # (#1343: second CHECK; conflict updated)


@pytest.mark.postgres
def test_the_jobs_indexes_are_the_constraints_plus_one_partial_unique_and_nothing_else(migrated_database):
    """Three indexes per table: key-backed ones, and on investigations one partial unique over the live stages only (#1342 M10)."""
    assert len(_jobs_indexes(migrated_database, "alerts")) == 3
    investigations = _jobs_indexes(migrated_database, "investigations")
    assert len(investigations) == 3
    [partial] = [i for i in investigations if "WHERE" in i]
    assert "UNIQUE" in partial
    assert "(tenant_id, alert_id)" in partial
    assert "'queued'" in partial
    assert "'running'" in partial
    assert not any(f"'{stage}'" in partial for stage in ("completed", "unparseable", "failed", "aborted"))

    execute(migrated_database, "CREATE INDEX extra_1342 ON jobs.investigations (stage)")  # control: the census sees one
    assert len(_jobs_indexes(migrated_database, "investigations")) == 4
