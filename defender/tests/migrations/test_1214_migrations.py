"""#1214 O11: one revision moves `tenants` to `tenancy`, adds the lifecycle tables, backfills existing rows as
failed creates; code at the new head refuses a database still at #1339's baseline; models match migrations.

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`).
"""
from __future__ import annotations

import datetime as _dt
import itertools

import pytest

from defender.tests.migrations.test_1339_migrations import catalog
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.tenancy.lifecycle_1214.test_1214_repository_contract import fill_row

BASELINE = "0001_baseline"
LAB = "37963319-1bcf-49a6-9644-6a0699bfe9a3"
OTHER = "5c1f2a52-0a47-4c0c-8a7e-6f3a0a7f4a11"
THIRD = "c8a3d1e0-2b0f-4f4e-9c61-1f7a9a0f9b22"
CREATED = _dt.datetime(2026, 9, 1, 8, 0, tzinfo=_dt.UTC)
TENANT_COLUMNS = {"id", "created_at", "state", "pending_action", "step", "step_actor", "failure", "repo_url",
                  "offboarded_at", "repo_delete_after"}
NOT_NULL = {"id", "created_at", "state"}
#: state -> the pending actions the CHECK allows with it (data model).
ALLOWED = {"creating": {"create"}, "active": {None, "rotate"}, "offboarding": {"offboard"},
           "offboarded": {None, "delete_repo"}}
ACTIONS = [None, "create", "rotate", "offboard", "delete_repo"]
_ids = itertools.count(1)


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


def _at_baseline(dsn: str, *, tenants: tuple[str, ...] = ()) -> None:
    """A database at #1339's baseline holding `tenants`, the first of which has an invited member."""
    _upgrade_to(dsn, BASELINE)
    for tenant in tenants:
        execute(dsn, "INSERT INTO identity.tenants (id, created_at) VALUES (%s, %s)", (tenant, CREATED))
    if tenants:
        execute(dsn, """INSERT INTO identity.users (id, email, display_name, status, is_platform_admin,
                        set_password_requested_seq, set_password_sent_seq, set_password_attempts, created_at, updated_at)
                        VALUES ('u1', 'ann@x.org', '', 'invited', false, 0, 0, 0, %s, %s)""", (CREATED, CREATED))
        execute(dsn, """INSERT INTO identity.memberships (id, user_id, tenant_id, status, invited_by, created_at,
                        notify_requested_seq, notify_sent_seq, notify_attempts)
                        VALUES ('m1', 'u1', %s, 'invited', 'system', %s, 0, 0, 0)""", (tenants[0], CREATED))


def _fk_to_tenants(dsn: str) -> list[tuple[str, str]]:
    return execute(dsn, """SELECT k.conname, k.confrelid::regclass::text FROM pg_constraint k
                           WHERE k.conrelid = 'identity.memberships'::regclass AND k.contype = 'f'
                             AND k.confrelid::regclass::text LIKE '%%tenants'""")


# --- one revision, the version check ----------------------------------------------------------------


def test_the_history_is_the_baseline_and_exactly_one_revision_on_it():
    """#1214 adds ONE revision on #1339's history, leaving the baseline as it was (O11)."""
    from alembic.script import ScriptDirectory

    from defender.migrations import _config

    chain = [(r.revision, r.down_revision) for r in ScriptDirectory.from_config(_config()).walk_revisions()]
    assert len(chain) == 2
    [(head_revision, down), (base, base_down)] = chain
    assert (down, base, base_down) == (BASELINE, BASELINE, None)
    assert head_revision != BASELINE


@pytest.mark.postgres
def test_code_at_head_refuses_a_database_at_the_baseline_naming_both(empty_database):
    """The 'behind' check #1339 deferred: a baseline database is refused naming it and head; once upgraded it passes (O11)."""
    from defender.migrations import RevisionMismatch, check_version, head, upgrade

    assert head() != BASELINE
    _upgrade_to(empty_database, BASELINE)
    with pytest.raises(RevisionMismatch) as refused:
        check_version(empty_database)
    assert (refused.value.database, refused.value.head) == (BASELINE, head())
    assert BASELINE in str(refused.value)
    assert head() in str(refused.value)
    upgrade(empty_database)
    assert check_version(empty_database) is None  # control: the same database passes at head


# --- the move ---------------------------------------------------------------------------------------


@pytest.mark.postgres
def test_the_revision_moves_tenants_and_adds_the_lifecycle_tables(migrated_database):
    """At head `tenancy` holds tenants and the new tables, `identity` no tenants, and memberships reference `tenancy.tenants` (O11)."""
    assert _tables(migrated_database, "tenancy") == {"tenants", "forge_wiring", "generations", "publish_status"}
    assert "tenants" not in _tables(migrated_database, "identity")
    assert [target for _, target in _fk_to_tenants(migrated_database)] == ["tenancy.tenants"]


@pytest.mark.postgres
def test_set_schema_keeps_the_rows_the_memberships_and_the_foreign_keys_name(empty_database):
    """The move carries the tenant row, the membership that references it and the FK's schema-free name; the FK still bites (O11)."""
    import psycopg.errors

    from defender.migrations import upgrade

    _at_baseline(empty_database, tenants=(LAB, OTHER))
    [(name, target)] = _fk_to_tenants(empty_database)
    assert target == "identity.tenants"
    upgrade(empty_database)
    assert _fk_to_tenants(empty_database) == [(name, "tenancy.tenants")]
    assert {r[0] for r in execute(empty_database, "SELECT id FROM tenancy.tenants")} == {LAB, OTHER}
    assert execute(empty_database, "SELECT id, tenant_id, status FROM identity.memberships") == [("m1", LAB, "invited")]
    with pytest.raises(psycopg.errors.ForeignKeyViolation):  # a membership of a tenant that is not there
        execute(empty_database, """INSERT INTO identity.memberships (id, user_id, tenant_id, status, invited_by, created_at,
                                   notify_requested_seq, notify_sent_seq, notify_attempts)
                                   VALUES ('m2', 'u1', 'no-such-tenant', 'invited', 'system', %s, 0, 0, 0)""", (CREATED,))
    with pytest.raises(psycopg.errors.ForeignKeyViolation):  # a tenant with a membership cannot be deleted
        execute(empty_database, "DELETE FROM tenancy.tenants WHERE id = %s", (LAB,))
    execute(empty_database, "DELETE FROM tenancy.tenants WHERE id = %s", (OTHER,))  # control: one without can


BACKFILL_FAILURE = "registered before #1214: record its forge wiring if it has a repository, then resume"

# --- the backfill -----------------------------------------------------------------------------------


@pytest.mark.postgres
def test_existing_tenant_rows_are_backfilled_as_failed_creates_at_names(empty_database):
    """Every pre-#1214 row becomes `creating`/`create`/step `names`/actor `service` with the backfill failure (so no
    worker takes it until an administrator resumes it), dates kept (O11)."""
    from defender.migrations import upgrade

    _at_baseline(empty_database, tenants=(LAB, OTHER, THIRD))
    upgrade(empty_database)
    rows = execute(empty_database, """SELECT id, created_at, state, pending_action, step, step_actor, failure,
                                      repo_url, offboarded_at, repo_delete_after FROM tenancy.tenants ORDER BY id""")
    assert len(rows) == 3
    for row in rows:
        assert row[1:6] == (CREATED, "creating", "create", "names", "service"), row
        assert row[6] == BACKFILL_FAILURE
        assert row[7:] == (None, None, None)
    assert {r[0] for r in rows} == {LAB, OTHER, THIRD}
    for table in ("forge_wiring", "generations", "publish_status"):  # the administrator, not the migration, records the wiring
        assert execute(empty_database, f"SELECT count(*) FROM tenancy.{table}") == [(0,)]  # noqa: S608


@pytest.mark.postgres
def test_a_database_upgraded_with_rows_has_the_catalog_of_one_upgraded_empty(empty_database, migrated_database):
    """Nullable -> fill -> NOT NULL leaves no trace: a populated upgrade and an empty one end with one catalog (O11, O3)."""
    from defender.migrations import check_version, upgrade

    _at_baseline(empty_database, tenants=(LAB, OTHER))
    upgrade(empty_database)
    assert check_version(empty_database) is None
    assert catalog(empty_database) == catalog(migrated_database)
    assert [c for c in catalog(empty_database)["columns"] if c[5] is not None] == []


@pytest.mark.postgres
def test_tenants_columns_are_the_data_models_and_only_the_identity_ones_are_required(migrated_database):
    """tenancy.tenants has exactly the data model's columns; id, created_at and state are NOT NULL, the rest nullable, no default (O11, P4)."""
    import psycopg.errors

    rows = execute(migrated_database, """SELECT column_name, is_nullable, column_default FROM information_schema.columns
                                         WHERE table_schema = 'tenancy' AND table_name = 'tenants'""")
    assert {r[0] for r in rows} == TENANT_COLUMNS
    assert {r[0] for r in rows if r[1] == "NO"} == NOT_NULL
    assert [r for r in rows if r[2] is not None] == []
    with pytest.raises(psycopg.errors.NotNullViolation):  # no default left to supply a state
        execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at) VALUES ('x', now())")


# --- the data model's constraints -------------------------------------------------------------------


def _tenant(dsn: str, state: str, action: str | None) -> bool:
    """Whether the database takes a tenant row in this state with this pending action."""
    import psycopg.errors

    try:
        execute(dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action)
                        VALUES (%s, now(), %s, %s)""", (f"t-{next(_ids)}", state, action))
    except psycopg.errors.CheckViolation:
        return False
    return True


@pytest.mark.postgres
def test_the_state_and_pending_action_must_be_an_allowed_pair(migrated_database):
    """The CHECK takes exactly the data model's pairs (creating<->create, active<->rotate|none, offboarding<->offboard, offboarded<->delete_repo|none) (O11)."""
    taken = {(s, a): _tenant(migrated_database, s, a) for s in ALLOWED for a in ACTIONS}
    assert taken == {(s, a): a in ALLOWED[s] for s in ALLOWED for a in ACTIONS}


@pytest.mark.postgres
def test_a_state_or_action_outside_the_model_is_refused(migrated_database):
    """An unknown state or pending action is refused even beside an allowed partner; the allowed row beside it is taken (O11)."""
    assert _tenant(migrated_database, "active", None)  # control
    assert not _tenant(migrated_database, "paused", None)
    assert not _tenant(migrated_database, "active", "pause")


@pytest.mark.postgres
def test_at_most_one_live_generation_per_tenant(migrated_database):
    """A tenant has any number of pending/retiring/destroyed generations but one `live`; another tenant's live is separate (O11, P4)."""
    import psycopg.errors

    for tenant in ("ta", "tb"):
        execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (tenant,))
    given = dict(tenant_id="ta")
    fill_row(migrated_database, "generations", salt="s1", status="live", **given)
    for salt, status in (("s2", "retiring"), ("s3", "pending"), ("s4", "destroyed"), ("s5", "destroyed")):
        fill_row(migrated_database, "generations", salt=salt, status=status, **given)
    fill_row(migrated_database, "generations", tenant_id="tb", salt="s6", status="live")
    with pytest.raises(psycopg.errors.UniqueViolation):
        fill_row(migrated_database, "generations", salt="s7", status="live", **given)
    execute(migrated_database, "UPDATE tenancy.generations SET status = 'retiring' WHERE salt = 's1'")
    fill_row(migrated_database, "generations", salt="s7", status="live", **given)  # control: the flip frees the slot


@pytest.mark.postgres
def test_a_generation_status_outside_the_model_is_refused(migrated_database):
    """Generation status is one of pending|live|retiring|destroyed (O11)."""
    import psycopg.errors

    execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES ('ta', now(), 'active')")
    fill_row(migrated_database, "generations", tenant_id="ta", salt="s1", status="pending")  # control
    with pytest.raises(psycopg.errors.CheckViolation):
        fill_row(migrated_database, "generations", tenant_id="ta", salt="s2", status="paused")


@pytest.mark.postgres
@pytest.mark.parametrize("table", ["forge_wiring", "generations", "publish_status"])
def test_each_lifecycle_table_belongs_to_a_tenant(table, migrated_database):
    """forge_wiring, generations and publish_status rows need an existing tenant (foreign keys, O11)."""
    import psycopg.errors

    execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES ('ta', now(), 'active')")
    extra = {"salt": "s1", "status": "pending"} if table == "generations" else {}
    fill_row(migrated_database, table, tenant_id="ta", **extra)  # control
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        fill_row(migrated_database, table, tenant_id="nobody", **(extra | {"salt": "s2"} if extra else {}))
