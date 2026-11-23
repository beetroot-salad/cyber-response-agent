"""#1592 migration 0027 (OD-5, OD-10, OD-6): it refuses, naming every tenant, while a tenant has a pending action or a
wiring other than `t-<T>/knowledge`; then adds the wiring CHECK, `identity.users.signed_out_at`,
`tenancy.forge_people_requests` and the request triggers, and drops `tenancy.merge_eligibility`.

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`). Model: the 0019 precedent,
`test_1366_system_records_migration.py`.
"""
from __future__ import annotations

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

PRIOR = "0026_host_requests"
PENDING = {"creating": ("create", "names", "service"), "rotating": ("rotate", "names", "service"),
           "offboarding": ("offboard", "offboard", "service"), "deleting": ("delete_repo", "delete_repo", "service")}
STATE = {"creating": "creating", "rotating": "active", "offboarding": "offboarding", "deleting": "offboarded"}
ORIGIN = "http://forge.test/x.git"


def _revision() -> str:
    """The revision numbered 0027 (the design fixes the number and its down-revision, not the rest of the name)."""
    found = [r.revision for r in revisions.scripts().walk_revisions() if r.revision.startswith("0027_")]
    assert len(found) == 1, f"expected one revision numbered 0027, found {found}"
    return found[0]


def _tenant(dsn: str, tenant: str, state: str = "active", job: tuple = (None, None, None), repo: str | None = None) -> None:
    execute(dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                    VALUES (%s, now(), %s, %s, %s, %s)""", (tenant, state, *job))
    if repo is not None:
        execute(dsn, "INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES (%s, %s, %s)", (tenant, repo, ORIGIN))


def _canonical(tenant: str) -> str:
    return f"t-{tenant}/knowledge"


def _version(dsn: str) -> list[tuple]:
    return execute(dsn, "SELECT version_num FROM alembic_version")


def _unchanged(dsn: str) -> None:
    """Nothing the revision adds is there and the version is still the prior one."""
    assert _version(dsn) == [(PRIOR,)]
    assert execute(dsn, "SELECT to_regclass('tenancy.forge_people_requests')::text") == [(None,)]
    assert execute(dsn, "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'identity' "
                        "AND table_name = 'users' AND column_name = 'signed_out_at'") == [(0,)]
    assert execute(dsn, "SELECT to_regclass('tenancy.merge_eligibility')::text") != [(None,)], "the table was dropped"
    assert execute(dsn, "SELECT count(*) FROM pg_constraint WHERE conrelid = 'tenancy.forge_wiring'::regclass "
                        "AND contype = 'c'") == [(0,)], "the CHECK was added"
    assert execute(dsn, "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN "
                        "('tenancy.tenants'::regclass, 'identity.memberships'::regclass, 'identity.users'::regclass)") == [(0,)]


def test_the_revision_sits_directly_on_the_host_requests_revision_and_is_the_head():
    """S1-19: 0027's down-revision is `0026_host_requests`, and it is the one head."""
    from defender.migrations import head, heads

    assert revisions.down_of(_revision()) == PRIOR
    assert heads() == (head(),)
    assert head() == _revision()


@pytest.mark.postgres
def test_a_pending_action_stops_the_upgrade_naming_every_tenant_and_changes_nothing(empty_database):
    """S1-20 (OD-5, 0019 pattern; Upgrade 1): a tenant with a pending create, rotate, offboard or delete_repo, failed or
    not, is named, each of them, and a quiet one is not; the revision, the tables and the constraints stay as they were."""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, PRIOR)
    busy = {name: fixture_uuid(f"tenant:1592-mig-{name}") for name in PENDING}
    failed = fixture_uuid("tenant:1592-mig-failed")  # a failed create is still the tenant's one pending action
    busy["failed create"] = failed
    quiet = fixture_uuid("tenant:1592-mig-quiet")
    for name, tenant in busy.items():
        if tenant != failed:
            _tenant(empty_database, tenant, STATE[name], PENDING[name], _canonical(tenant))
    _tenant(empty_database, failed, "creating", PENDING["creating"], _canonical(failed))
    execute(empty_database, "UPDATE tenancy.tenants SET failure = 'the forge refused the repository' WHERE id = %s", (failed,))
    _tenant(empty_database, quiet, "active", repo=_canonical(quiet))

    with pytest.raises(RuntimeError) as stopped:
        upgrade(empty_database)

    message = str(stopped.value)
    for name, tenant in busy.items():
        assert tenant in message, f"{name} is not named: {message}"
    assert quiet not in message, message
    _unchanged(empty_database)


@pytest.mark.postgres
def test_a_wiring_other_than_the_tenants_knowledge_repository_stops_the_upgrade_naming_every_tenant(empty_database):
    """S1-21 (OD-5): wiring `tenants/x` on two tenants (and another tenant's repository on a third) are each named; a
    tenant with the canonical wiring, and one with none, are not; nothing changes."""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, PRIOR)
    a, b, c, good, bare, fine = (fixture_uuid(f"tenant:1592-mig-w{n}") for n in range(6))
    _tenant(empty_database, fine, repo=_canonical(fine))
    _tenant(empty_database, a, repo="tenants/x")
    _tenant(empty_database, b, repo="tenants/y")
    _tenant(empty_database, c, repo=_canonical(good))  # canonical in form, another tenant's
    _tenant(empty_database, good, repo=_canonical(good))
    _tenant(empty_database, bare)

    with pytest.raises(RuntimeError) as stopped:
        upgrade(empty_database)

    message = str(stopped.value)
    for tenant in (a, b, c):
        assert tenant in message, message
    assert fine not in message, message
    assert bare not in message, message
    _unchanged(empty_database)


@pytest.mark.postgres
def test_canonical_wiring_and_nothing_pending_upgrades_to_head(empty_database):
    """S1-22: the control: with every tenant moved and idle the upgrade succeeds (and does not refuse everything)."""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, PRIOR)
    for n, state in enumerate(("active", "offboarded")):
        tenant = fixture_uuid(f"tenant:1592-mig-ok{n}")
        _tenant(empty_database, tenant, state, repo=_canonical(tenant))
    upgrade(empty_database)
    assert _version(empty_database) == [(_revision(),)]


@pytest.mark.postgres
def test_at_head_the_database_refuses_a_wiring_that_is_not_the_tenants_knowledge_repository(migrated_database):
    """S1-23 (OD-5): INSERT and UPDATE of any other repo are refused by the database; the canonical one is accepted."""
    import psycopg.errors

    dsn = migrated_database
    a, b = fixture_uuid("tenant:1592-chk-a"), fixture_uuid("tenant:1592-chk-b")
    _tenant(dsn, a)
    _tenant(dsn, b)
    for bad in (f"tenants/{a}", "tenants/x", _canonical(b), f"T-{a}/knowledge", f"t-{a}/knowledge/", f"t-{a}/other"):
        with pytest.raises(psycopg.errors.CheckViolation):
            execute(dsn, "INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES (%s, %s, %s)", (a, bad, ORIGIN))
    execute(dsn, "INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES (%s, %s, %s)", (a, _canonical(a), ORIGIN))
    for bad in ("tenants/x", _canonical(b)):
        with pytest.raises(psycopg.errors.CheckViolation):
            execute(dsn, "UPDATE tenancy.forge_wiring SET repo = %s WHERE tenant_id = %s", (bad, a))
    assert execute(dsn, "SELECT repo FROM tenancy.forge_wiring WHERE tenant_id = %s", (a,)) == [(_canonical(a),)]


@pytest.mark.postgres
def test_the_revision_adds_the_column_the_table_and_the_triggers_and_drops_merge_eligibility(empty_database):
    """S1-24 (OD-10, OD-6): `users.signed_out_at` (nullable timestamptz), `forge_people_requests` with its four columns
    and the at-least-one CHECK, the three triggers; `merge_eligibility` gone."""
    dsn = empty_database
    _upgrade_to(dsn, PRIOR)
    assert execute(dsn, "SELECT to_regclass('tenancy.merge_eligibility')::text") != [(None,)], "premise: it exists before"
    _upgrade_to(dsn, _revision())

    assert execute(dsn, "SELECT to_regclass('tenancy.merge_eligibility')::text") == [(None,)]
    assert execute(dsn, "SELECT data_type, is_nullable FROM information_schema.columns WHERE table_schema = 'identity' "
                        "AND table_name = 'users' AND column_name = 'signed_out_at'") == [("timestamp with time zone", "YES")]
    columns = {c: (t, n) for c, t, n in execute(dsn, "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                                                     "WHERE table_schema = 'tenancy' AND table_name = 'forge_people_requests'")}
    assert columns == {"id": ("uuid", "NO"), "user_id": ("uuid", "YES"), "tenant_id": ("uuid", "YES"),
                       "requested_at": ("timestamp with time zone", "NO")}
    assert execute(dsn, "SELECT count(*) FROM pg_constraint WHERE conrelid = 'tenancy.forge_people_requests'::regclass "
                        "AND contype = 'f' AND conkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = "
                        "'tenancy.forge_people_requests'::regclass AND attname = 'user_id')]") == [(0,)], "user_id has no FK"
    assert execute(dsn, "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN "
                        "('tenancy.tenants'::regclass, 'identity.memberships'::regclass, 'identity.users'::regclass)") == [(3,)]
