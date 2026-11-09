"""#1214 O11: one revision moves `tenants` to `tenancy`, adds the lifecycle tables, backfills existing rows as
failed creates; code at the new head refuses a database still at #1339's baseline; models match migrations.

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`).
"""
from __future__ import annotations

import datetime as _dt
import itertools
import json

import pytest

from defender.tests.migrations.test_1339_migrations import catalog
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.tenancy.lifecycle_1214.test_1214_repository_contract import fill_row

BASELINE = "0001_baseline"
TENANCY = "0002_tenancy"
SIGN_LOGIN = "0003_sign_login"
SIGN_COLUMNS = {"sign_approle", "sign_entity", "sign_role_id", "sign_secret_file", "sign_wrapped_secret", "sign_secret_accessor"}
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
                        VALUES ('d1000000-0000-4000-8000-000000000001', 'ann@x.org', '', 'invited', false, 0, 0, 0, %s, %s)""", (CREATED, CREATED))
        execute(dsn, """INSERT INTO identity.memberships (id, user_id, tenant_id, status, invited_by, created_at,
                        notify_requested_seq, notify_sent_seq, notify_attempts)
                        VALUES ('e1000000-0000-4000-8000-000000000001', 'd1000000-0000-4000-8000-000000000001', %s, 'invited', 'system', %s, 0, 0, 0)""", (tenants[0], CREATED))


def _fk_to_tenants(dsn: str) -> list[tuple[str, str]]:
    return execute(dsn, """SELECT k.conname, k.confrelid::regclass::text FROM pg_constraint k
                           WHERE k.conrelid = 'identity.memberships'::regclass AND k.contype = 'f'
                             AND k.confrelid::regclass::text LIKE '%%tenants'""")


# --- one revision, the version check ----------------------------------------------------------------


def test_the_history_is_the_baseline_and_five_revisions_on_it_in_a_line():
    """#1214 adds ONE revision on #1339's history, leaving the baseline as it was (O11); #1163 adds one more, the six
    sign columns of the generation record (A24/r8.4); #1342 puts its jobs revision on #1163's, #1382 its uuid ids
    revision on that, #1343 its lease revision on that, and #1345 its mapping revision on that: a single line baseline
    -> #1214's -> #1163's -> #1342's -> #1382's -> #1343's -> #1345's, no branch. (The name predates the later revisions;
    the node id is kept.)"""
    from alembic.script import ScriptDirectory

    from defender.migrations import _config

    script = ScriptDirectory.from_config(_config())
    chain = [(r.revision, r.down_revision) for r in script.walk_revisions()]  # newest first
    assert len(chain) == 8  # #1414 D13: the merge-eligibility record's revision sits on #1345's
    [(head, _)] = chain[:1]
    assert [revision for revision, _ in chain][1:] == [
        "0007_alert_mapping", "0006_job_leases", "0005_uuid_ids", "0004_jobs", SIGN_LOGIN, TENANCY, BASELINE]
    assert [down for _, down in chain] == [
        "0007_alert_mapping", "0006_job_leases", "0005_uuid_ids", "0004_jobs", SIGN_LOGIN, TENANCY, BASELINE, None]
    assert script.get_heads() == [head], "the history branches"

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
    assert _tables(migrated_database, "tenancy") == {"tenants", "forge_wiring", "generations", "publish_status",
                                                     "alert_mappings",  # #1345 r5: the mapping is a tenant record
                                                     "merge_eligibility"}  # #1414 D13: the service's eligibility record
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
    assert execute(empty_database, "SELECT id, tenant_id, status FROM identity.memberships") == [("e1000000-0000-4000-8000-000000000001", LAB, "invited")]
    with pytest.raises(psycopg.errors.ForeignKeyViolation):  # a membership of a tenant that is not there
        execute(empty_database, """INSERT INTO identity.memberships (id, user_id, tenant_id, status, invited_by, created_at,
                                   notify_requested_seq, notify_sent_seq, notify_attempts)
                                   VALUES ('e1000000-0000-4000-8000-000000000002', 'd1000000-0000-4000-8000-000000000001', 'f1000000-0000-4000-8000-000000000009', 'invited', NULL, %s, 0, 0, 0)""", (CREATED,))
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
        execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at) VALUES ('f1000000-0000-4000-8000-000000000001', now())")


# --- #1163's revision: the six sign columns (A24/r8.4) ------------------------------------------------------


def _sign_values(tag: str) -> dict[str, str]:
    """Six values each longer than 40 characters; the secret file path is longer than 100."""
    return {name: f"{name}-{tag}-" + "x" * 40 for name in SIGN_COLUMNS} | {"sign_secret_file": "/srv/secrets/" + "d" * 120 + f"/{tag}"}


@pytest.mark.postgres
def test_the_third_revision_adds_exactly_the_six_sign_columns_as_nullable_text_with_no_default(empty_database):
    """Upgrading #1214's database to #1163's revision changes its catalog by exactly six `generations` columns: text,
    nullable, no server default, and nothing else (A24/r8.4 'the generation record gains six fields (a migration)').
    #1342's jobs revision follows #1163's, so the step is to `0003_sign_login`, not to head."""
    _upgrade_to(empty_database, TENANCY)
    before = catalog(empty_database)
    _upgrade_to(empty_database, SIGN_LOGIN)
    after = catalog(empty_database)
    added = [c for c in after["columns"] if c not in before["columns"]]
    assert [c for c in before["columns"] if c not in after["columns"]] == []
    assert sorted(added) == sorted(("tenancy", "generations", name, "text", False, None) for name in SIGN_COLUMNS)
    assert {k: v for k, v in after.items() if k != "columns"} == {k: v for k, v in before.items() if k != "columns"}


@pytest.mark.postgres
def test_a_generation_recorded_at_the_tenancy_revision_reads_back_with_the_six_null_after_the_upgrade(empty_database):
    """A row seeded at `0002_tenancy` keeps its other values through the upgrade and reads the six sign columns NULL, which
    is how a pre-r8 generation reads (A24/r8.4, r8.5 upgrade)."""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, TENANCY)
    fill_row(empty_database, "tenants", id=OTHER, state="active")
    fill_row(empty_database, "generations", tenant_id=OTHER, salt="old", status="live", bot_login="bot-old")
    upgrade(empty_database)
    cols = ", ".join(sorted(SIGN_COLUMNS))
    rows = execute(empty_database, f"SELECT bot_login, {cols} FROM tenancy.generations WHERE tenant_id = %s", (OTHER,))  # noqa: S608
    assert rows == [("bot-old", *([None] * 6))]


@pytest.mark.postgres
def test_the_upgrade_keeps_every_row_of_every_tenancy_table_and_only_adds_the_six_null_columns(empty_database):
    """Live, pending, retiring and destroyed generations (two tenants' rows) and the neighbouring tenancy tables' rows at
    `0002_tenancy` are all there after the upgrade, every old column unchanged, the six new ones NULL (A24/r8.4: the
    migration adds columns and removes nothing; r8.5: a pending generation survives to be completed)."""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, TENANCY)
    for tenant in (OTHER, THIRD):
        fill_row(empty_database, "tenants", id=tenant, state="active")
        fill_row(empty_database, "forge_wiring", tenant_id=tenant)
        fill_row(empty_database, "publish_status", tenant_id=tenant)
    for tenant, statuses in ((OTHER, ("live", "pending", "retiring", "destroyed")), (THIRD, ("live", "pending"))):
        for status in statuses:
            fill_row(empty_database, "generations", tenant_id=tenant, salt=f"{status}-1", status=status,
                     bot_login=f"bot-{tenant}-{status}", role_id=f"role-{status}")

    def rows() -> dict[str, list[dict[str, object]]]:
        tables = sorted(_tables(empty_database, "tenancy") - {"alembic_version", "alert_mappings",  # #1345: a table the head adds
                                                              "merge_eligibility"})  # #1414 D13: so is this
        return {t: sorted((r[0] for r in execute(empty_database, f"SELECT to_jsonb(x) FROM tenancy.{t} x")),  # noqa: S608
                          key=lambda row: json.dumps(row, sort_keys=True)) for t in tables}
    before = rows()
    assert {len(before[t]) for t in ("tenants", "forge_wiring", "publish_status")} == {2}, "control: the rows were seeded"
    assert len(before["generations"]) == 6, "control: live and pending generations were seeded"
    upgrade(empty_database)
    after = rows()

    assert after.keys() == before.keys()
    for table, old in before.items():
        new = after[table]
        assert len(new) == len(old), f"{table}: rows lost by the upgrade"
        if table == "generations":
            assert all({k: row[k] for k in SIGN_COLUMNS} == dict.fromkeys(SIGN_COLUMNS) for row in new)
            new = [{k: v for k, v in row.items() if k not in SIGN_COLUMNS} for row in new]
        assert new == old, f"{table}: a row changed"


@pytest.mark.postgres
def test_long_sign_values_round_trip_through_the_columns(migrated_database):
    """Six values over 40 characters, a secret file path over 100 among them, are stored and read back unchanged (A24/r8.4:
    text columns, no length limit)."""
    fill_row(migrated_database, "tenants", id=THIRD, state="active")
    values = _sign_values("long")
    fill_row(migrated_database, "generations", tenant_id=THIRD, salt="s", status="live", bot_login="bot-s", **values)
    names = sorted(values)
    [row] = execute(migrated_database, f"SELECT {', '.join(names)} FROM tenancy.generations WHERE tenant_id = %s", (THIRD,))  # noqa: S608
    assert dict(zip(names, row, strict=True)) == values


# --- the data model's constraints -------------------------------------------------------------------


def _tenant(dsn: str, state: str, action: str | None) -> bool:
    """Whether the database takes a tenant row in this state with this pending action."""
    import psycopg.errors

    try:
        execute(dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action)
                        VALUES (%s, now(), %s, %s)""", (f"f2000000-0000-4000-8000-{next(_ids):012d}", state, action))
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

    for tenant in ("aa000000-0000-4000-8000-00000000000a", "aa000000-0000-4000-8000-00000000000b"):
        execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, now(), 'active')", (tenant,))
    given = dict(tenant_id="aa000000-0000-4000-8000-00000000000a")
    fill_row(migrated_database, "generations", salt="s1", status="live", **given)
    for salt, status in (("s2", "retiring"), ("s3", "pending"), ("s4", "destroyed"), ("s5", "destroyed")):
        fill_row(migrated_database, "generations", salt=salt, status=status, **given)
    fill_row(migrated_database, "generations", tenant_id="aa000000-0000-4000-8000-00000000000b", salt="s6", status="live")
    with pytest.raises(psycopg.errors.UniqueViolation):
        fill_row(migrated_database, "generations", salt="s7", status="live", **given)
    execute(migrated_database, "UPDATE tenancy.generations SET status = 'retiring' WHERE salt = 's1'")
    fill_row(migrated_database, "generations", salt="s7", status="live", **given)  # control: the flip frees the slot


@pytest.mark.postgres
def test_a_generation_status_outside_the_model_is_refused(migrated_database):
    """Generation status is one of pending|live|retiring|destroyed (O11)."""
    import psycopg.errors

    execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES ('aa000000-0000-4000-8000-00000000000a', now(), 'active')")
    fill_row(migrated_database, "generations", tenant_id="aa000000-0000-4000-8000-00000000000a", salt="s1", status="pending")  # control
    with pytest.raises(psycopg.errors.CheckViolation):
        fill_row(migrated_database, "generations", tenant_id="aa000000-0000-4000-8000-00000000000a", salt="s2", status="paused")


@pytest.mark.postgres
@pytest.mark.parametrize("table", ["forge_wiring", "generations", "publish_status"])
def test_each_lifecycle_table_belongs_to_a_tenant(table, migrated_database):
    """forge_wiring, generations and publish_status rows need an existing tenant (foreign keys, O11)."""
    import psycopg.errors

    execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES ('aa000000-0000-4000-8000-00000000000a', now(), 'active')")
    extra = {"salt": "s1", "status": "pending"} if table == "generations" else {}
    fill_row(migrated_database, table, tenant_id="aa000000-0000-4000-8000-00000000000a", **extra)  # control
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        fill_row(migrated_database, table, tenant_id="f3000000-0000-4000-8000-000000000000", **(extra | {"salt": "s2"} if extra else {}))
