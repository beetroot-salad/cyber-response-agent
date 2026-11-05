"""#1345 upgrade: the revision after `0006_job_leases` creates the alert-mapping table (no rows) beside the tenant records
in `tenancy` (r5 "Where it lives"), and makes `jobs.alerts.title` / `description` nullable and null (only development
rows exist).

Database cases are marked `postgres`; each runs on a database of its own (`conftest.py`).

Design-implied names (r5 names none): the table `tenancy.alert_mappings` (`MAPPING_TABLE`); one column per entry, named
as the entry, and `tenant_id uuid`.
"""
from __future__ import annotations

import datetime as _dt

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared._postgres1339 import execute

JOB_LEASES = "0006_job_leases"
CREATED = _dt.datetime(2026, 11, 1, 8, 0, tzinfo=_dt.UTC)
TENANT = "a3000000-0000-4000-8000-000000000001"
ALERT = "a3000000-0000-4000-8000-0000000000a1"
ENTRIES = ("signature", "event_time", "summary", "case_key", "title", "description")
MAPPING_TABLE = "alert_mappings"  # in `tenancy`, declared with the tenant records


def _columns(dsn: str, schema: str, table: str) -> dict[str, tuple[str, str]]:
    """column -> (data type, is_nullable) of `<schema>.<table>`."""
    return {c: (t, n) for c, t, n in execute(dsn, """SELECT column_name, data_type, is_nullable
        FROM information_schema.columns WHERE table_schema = %s AND table_name = %s""", (schema, table))}


@pytest.mark.postgres
def test_at_head_the_mapping_table_has_a_nullable_text_column_per_entry_and_alert_display_is_nullable(migrated_database):
    """The six entries are nullable text (null = unmapped); the alerts' display fields are nullable text. (#1345 data model)"""
    mapping = _columns(migrated_database, "tenancy", MAPPING_TABLE)
    assert {entry: mapping.get(entry) for entry in ENTRIES} == dict.fromkeys(ENTRIES, ("text", "YES"))
    assert mapping.get("tenant_id") == ("uuid", "NO")
    alerts = _columns(migrated_database, "jobs", "alerts")
    assert (alerts["title"], alerts["description"]) == (("text", "YES"), ("text", "YES"))


@pytest.mark.postgres
def test_the_upgrade_creates_no_mapping_and_nulls_existing_alert_display(empty_database):
    """From `0006_job_leases` with a tenant and a development alert: head has no mapping row and the alert's
    title and description are null; its other columns are kept. (#1345 Upgrade)"""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, JOB_LEASES)
    execute(empty_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')",
            (TENANT, CREATED))
    execute(empty_database, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, "
                            "received_at, title, description, raw) VALUES (%s, %s, 'v', 'V-1', %s, %s, %s, 'dev title', "
                            "'dev description', %s)", (ALERT, TENANT, CREATED, CREATED, CREATED, b"{}"))

    upgrade(empty_database)

    assert execute(empty_database, f"SELECT count(*) FROM tenancy.{MAPPING_TABLE}") == [(0,)]  # noqa: S608
    assert execute(empty_database, "SELECT title, description, vendor_ticket_id FROM jobs.alerts WHERE id = %s",
                   (ALERT,)) == [(None, None, "V-1")]


@pytest.mark.postgres
def test_at_head_a_tenant_has_at_most_one_mapping_row_and_only_a_tenant_that_exists_has_one(migrated_database):
    """The table is keyed by the tenant (one row each, replaced whole) and refuses a tenant that is not in
    `tenancy.tenants`; a row for an existing tenant, with unmapped entries null, is accepted (control). (#1345 data model)"""
    import psycopg

    execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')",
            (TENANT, CREATED))
    insert = f"INSERT INTO tenancy.{MAPPING_TABLE} (tenant_id, signature) VALUES (%s, 'rule.id')"  # noqa: S608
    execute(migrated_database, insert, (TENANT,))
    assert execute(migrated_database, f"SELECT signature, title FROM tenancy.{MAPPING_TABLE}") == [("rule.id", None)]  # noqa: S608
    with pytest.raises(psycopg.errors.UniqueViolation):
        execute(migrated_database, insert, (TENANT,))
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        execute(migrated_database, insert, ("a3000000-0000-4000-8000-0000000000ff",))


@pytest.mark.postgres
def test_at_head_an_alert_may_be_stored_with_a_null_title_and_description(migrated_database):
    """The nullable columns accept a row without display fields; the other required columns still do not
    take null (control). (#1345 data model)"""
    import psycopg

    execute(migrated_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')",
            (TENANT, CREATED))
    columns = ("id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, title, description, raw")
    insert = f"INSERT INTO jobs.alerts ({columns}) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"  # noqa: S608
    row = (ALERT, TENANT, "v", "V-1", CREATED, CREATED, CREATED, None, None, b"{}")
    execute(migrated_database, insert, row)
    assert execute(migrated_database, "SELECT title, description FROM jobs.alerts WHERE id = %s", (ALERT,)) == [(None, None)]
    with pytest.raises(psycopg.errors.NotNullViolation):
        execute(migrated_database, insert, (ALERT[:-1] + "b", TENANT, None, "V-2", CREATED, CREATED, CREATED, None, None, b"{}"))


@pytest.mark.postgres
def test_the_upgrade_nulls_every_existing_alerts_display_and_gives_no_tenant_a_mapping(empty_database):
    """Two tenants with several development alerts each: after the upgrade every alert's title and description are
    null, whichever tenant, and no tenant has a mapping. (#1345 Upgrade)"""
    from defender.migrations import upgrade

    _upgrade_to(empty_database, JOB_LEASES)
    other = "a3000000-0000-4000-8000-000000000002"
    for tenant in (TENANT, other):
        execute(empty_database, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')",
                (tenant, CREATED))
    for n, tenant in enumerate((TENANT, TENANT, other)):
        execute(empty_database, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, "
                                "received_at, title, description, raw) VALUES (%s, %s, 'v', %s, %s, %s, %s, 'dev', 'dev', %s)",
                (f"a3000000-0000-4000-8000-0000000000b{n}", tenant, f"V-{n}", CREATED, CREATED, CREATED, b"{}"))

    upgrade(empty_database)

    assert execute(empty_database, "SELECT count(*) FILTER (WHERE title IS NULL AND description IS NULL), count(*) "
                                   "FROM jobs.alerts") == [(3, 3)]
    assert execute(empty_database, f"SELECT count(*) FROM tenancy.{MAPPING_TABLE}") == [(0,)]  # noqa: S608
