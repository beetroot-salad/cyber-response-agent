# ruff: noqa: PT018
"""#1546 A-O7: the per-tenant retention row (both values NOT NULL, checked 30-730 days, no default, one row per tenant) and
the revision (`<n>_retention_required`, pinned suffix), which adds the investigation insert's foreign key to that row
`NOT VALID` and refuses to apply while any tenant that is not offboarded (`creating` included) lacks one. One release (r9,
D16): there is no default and no backfill. Postgres-gated."""
from __future__ import annotations

import psycopg
import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.jobs._jobs1342 import T1, T2, register_tenant
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import execute

pytestmark = pytest.mark.postgres

THIRD = "9b0c7a52-1d3e-4c45-8f6a-2e1d0c9b8a77"
FOURTH = "4f8e2d10-7a6b-4c3d-9e5f-0a1b2c3d4e5f"


def _row(dsn: str, tenant: str, inv: int | None, learn: int | None) -> None:
    execute(dsn, "INSERT INTO tenancy.evidence_retention (tenant_id, investigation_days, learning_days) VALUES (%s, %s, %s)",
            (tenant, inv, learn))


@pytest.mark.parametrize(("days", "ok"), [(29, False), (30, True), (730, True), (731, False)])
@pytest.mark.parametrize("column", ["investigation_days", "learning_days"])
def test_each_retention_value_is_checked_30_to_730_days(migrated_database, days, ok, column):
    """Either value at 29 or 731 is refused by the database, at 30 and 730 accepted (the other value valid). (A-O7)"""
    register_tenant(migrated_database, T1, retention=None)  # no seeded row: the cases insert their own
    values = {"investigation_days": 100, "learning_days": 100, column: days}
    if ok:
        _row(migrated_database, T1, values["investigation_days"], values["learning_days"])
        assert execute(migrated_database, f"SELECT {column} FROM tenancy.evidence_retention", ()) == [(days,)]  # noqa: S608
        return
    with pytest.raises(psycopg.errors.CheckViolation):
        _row(migrated_database, T1, values["investigation_days"], values["learning_days"])


def test_a_retention_row_needs_both_values_has_no_default_and_is_the_tenants_only_one(migrated_database):
    """A row naming either value NULL, or naming none, is refused; a second row of one tenant is refused; a row for a tenant
    that does not exist is refused; a complete one is accepted (control). (A-O7)"""
    dsn = migrated_database
    register_tenant(dsn, T1, retention=None)
    for inv, learn in ((None, 90), (90, None)):
        with pytest.raises(psycopg.errors.NotNullViolation):
            _row(dsn, T1, inv, learn)
    with pytest.raises(psycopg.errors.NotNullViolation):
        execute(dsn, "INSERT INTO tenancy.evidence_retention (tenant_id) VALUES (%s)", (T1,))
    _row(dsn, T1, 90, 90)
    with pytest.raises(psycopg.errors.UniqueViolation):
        _row(dsn, T1, 100, 100)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _row(dsn, THIRD, 90, 90)


# --- the retention revision --------------------------------------------------------------------------------------------------------

def _revision() -> str:
    return revisions.by_suffix("_retention_required")


def _tenants(dsn: str) -> None:
    """At the revision before: an active tenant with a row (T1), an active one (T2) and a `creating` one (THIRD) without, and
    an offboarded one without (FOURTH)."""
    for tenant, state, job in ((T1, "active", None), (T2, "active", None), (THIRD, "creating", ("create", "names", "service")),
                               (FOURTH, "offboarded", None)):
        execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor) "
                     "VALUES (%s, now(), %s, %s, %s, %s)", (tenant, state, *(job or (None, None, None))))
    _row(dsn, T1, 90, 90)


def _fk(dsn: str) -> list[tuple[str, bool]]:
    return execute(dsn, "SELECT con.conname, con.convalidated FROM pg_constraint con "
                        "WHERE con.contype = 'f' AND con.conrelid = 'jobs.investigations'::regclass "
                        "AND con.confrelid = 'tenancy.evidence_retention'::regclass")  # type: ignore[return-value]


def test_the_upgrade_refuses_while_a_tenant_not_offboarded_has_no_retention_row_naming_it_and_changing_nothing(empty_database):
    """With an active and a `creating` tenant lacking a row (and an offboarded one and a tenant with a row, not named), the
    upgrade raises naming exactly those two, leaves the version as it was and adds no foreign key; once both have rows it
    applies. (A-O7 rollout, D16)"""
    from defender.migrations import upgrade

    dsn = empty_database
    _upgrade_to(dsn, revisions.down_of(_revision()))
    _tenants(dsn)
    before = execute(dsn, "SELECT version_num FROM public.alembic_version")
    with pytest.raises(RuntimeError) as stopped:
        upgrade(dsn)
    message = str(stopped.value)
    assert T2 in message and THIRD in message, message
    assert T1 not in message and FOURTH not in message, message
    assert execute(dsn, "SELECT version_num FROM public.alembic_version") == before
    assert _fk(dsn) == []
    _row(dsn, T2, 30, 30)
    _row(dsn, THIRD, 730, 730)
    upgrade(dsn)
    assert execute(dsn, "SELECT version_num FROM public.alembic_version") != before


def test_the_upgrade_applies_with_only_offboarded_tenants_lacking_a_row(empty_database):
    """With every tenant not offboarded holding a row, an offboarded tenant without one does not stop the upgrade. (A-O7, D16)"""
    from defender.migrations import upgrade

    dsn = empty_database
    _upgrade_to(dsn, revisions.down_of(_revision()))
    _tenants(dsn)
    _row(dsn, T2, 30, 30)
    _row(dsn, THIRD, 30, 30)
    before = execute(dsn, "SELECT version_num FROM public.alembic_version")
    upgrade(dsn)
    assert execute(dsn, "SELECT version_num FROM public.alembic_version") != before


def test_the_upgrade_adds_the_investigation_foreign_key_not_valid_so_old_rows_stay_and_new_inserts_need_a_row(empty_database):
    """After the upgrade a foreign key from `jobs.investigations` to the retention row exists and is `NOT VALID`; an
    investigation already stored for the offboarded tenant (no row) is untouched, a new investigation for a tenant with a
    row is accepted, and one for a tenant without is refused. (A-O7 rollout, D16)"""
    from defender.migrations import upgrade

    dsn = empty_database
    _upgrade_to(dsn, revisions.down_of(_revision()))
    _tenants(dsn)
    for tenant in (T2, THIRD):
        _row(dsn, tenant, 60, 60)
    for tenant in (T1, FOURTH):
        execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, raw) "
                     "VALUES (%s, %s, 'tickets', 'x', now(), now(), now(), '{}')",
                (f"00000000-0000-4000-8000-00000000000{1 if tenant == T1 else 2}", tenant))
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, cost_usd, "
                 "cost_is_lower_limit, update_ticket) VALUES ('00000000-0000-4000-8000-0000000000a2', %s, "
                 "'00000000-0000-4000-8000-000000000002', 'k', 1, 'queued', now(), 0, false, false)", (FOURTH,))
    upgrade(dsn)
    [(name, validated)] = _fk(dsn)
    assert validated is False, f"{name} is validated: the migration scanned the old rows"
    assert execute(dsn, "SELECT count(*) FROM jobs.investigations WHERE tenant_id = %s", (FOURTH,)) == [(1,)]
    insert = ("INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, cost_usd, "
              "cost_is_lower_limit, update_ticket) VALUES (%s, %s, %s, %s, 1, 'queued', now(), 0, false, false)")
    execute(dsn, insert, ("00000000-0000-4000-8000-0000000000a1", T1, "00000000-0000-4000-8000-000000000001", "k1"))
    execute(dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, raw) "
                 "VALUES ('00000000-0000-4000-8000-000000000003', %s, 'tickets', 'y', now(), now(), now(), '{}')", (FOURTH,))
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        execute(dsn, insert, ("00000000-0000-4000-8000-0000000000a3", FOURTH, "00000000-0000-4000-8000-000000000003", "k3"))
