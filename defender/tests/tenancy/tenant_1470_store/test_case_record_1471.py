"""#1471 r8 W7: the case record is a system and nothing else. Text that still carries `comment:` is refused naming it,
a stored record renders as text without it, and the store's version holds no template (its column is gone)."""
from __future__ import annotations

import uuid

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _records1470 as K
from defender.tests.support.tenancy import _systems1366 as R

BASE = R.declaration("http://ticket.test")


def _parse(text: str):
    from defender.tenancy.case_record import parse_case_record

    return parse_case_record(text, named="the case record")


def test_1471_w7_a_case_record_naming_only_its_system_parses():
    """Control: `system:` alone is a case record. (W7)"""
    assert _parse("system: ticket\n").system == "ticket"


@pytest.mark.parametrize("comment", [
    'comment:\n  body: "{disposition}"', "comment: {}", "comment:", "comment: just text", "comment: [a, b]",
    "comment:\n  body: ''\n  extra: 1"], ids=["body", "empty-map", "null", "string", "list", "empty-body"])
def test_1471_w7_a_case_record_that_still_carries_comment_is_refused_naming_the_removed_key(comment):
    """Whatever stands under `comment:`, the record is refused, and the fault names `comment`. (W7)"""
    from defender.tenancy.case_record import CaseTicketError

    with pytest.raises(CaseTicketError) as refused:
        _parse(f"system: ticket\n{comment}\n")
    assert "comment" in str(refused.value), str(refused.value)
    assert "the case record" in str(refused.value), str(refused.value)


def test_1471_w7_a_stored_case_record_renders_as_text_that_parses_and_names_no_comment():
    """The text of a stored record is its system alone; parsing it gives the system back. (W7)"""
    from defender.tenancy.case_record import case_record_text
    from defender.tenancy.models import CaseRecord

    text = case_record_text(CaseRecord(version=3, system_id="ticket"))
    assert "comment" not in text, text
    assert "body" not in text, text
    assert _parse(text).system == "ticket"



@pytest.mark.postgres
def test_1471_w7_the_store_keeps_a_case_version_without_a_template_and_the_column_is_gone(migrated_database):  # noqa: F811 — the imported fixture
    """`put_case` takes a system and an author; the version it writes has no template and the table has no
    `comment_body` column. (W7)"""
    tenant = str(uuid.uuid4())
    register_tenant(migrated_database, tenant, records=None)

    async def work(store):
        await store.put_system(tenant, "ticket", replaces=0, adapter="ticket", enabled=True,
                               settings=dict(R.FIXTURE_FOLDERS["ticket"][0]), access=BASE, author=K.SEED)
        return await store.put_case(tenant, replaces=0, system_id="ticket", author=K.SEED)

    written = K.run(migrated_database, work)
    assert (written.record.version, written.record.system_id) == (1, "ticket")
    columns = {c for (c,) in execute(migrated_database, "SELECT column_name FROM information_schema.columns "
                                     "WHERE table_schema = 'tenancy' AND table_name = 'case_versions'")}
    assert "comment_body" not in columns, columns
    assert {"tenant_id", "version", "system_id", "deleted", "author", "written_at"} <= columns, columns


@pytest.mark.postgres
def test_1471_w7_the_upgrade_drops_the_template_column_and_keeps_every_case_version():
    """From the revision before, a database holding a case version with its template upgrades to head with the row
    kept (system, version, tombstone) and the column gone. (W7)"""
    from defender.tests.migrations.test_1214_migrations import _upgrade_to
    from defender.tests.support.shared._postgres1339 import database

    with database(migrated=False) as dsn:
        _upgrade_to(dsn, "0019_drop_records_mark")
        tenant = str(uuid.uuid4())
        register_tenant(dsn, tenant, records=None)
        execute(dsn, "INSERT INTO tenancy.case_versions (tenant_id, version, system_id, comment_body, deleted, author, "
                     "written_at) VALUES (%s, 1, 'ticket', 'Hello {disposition}', false, 'x', now()), "
                     "(%s, 2, 'ticket', 'Hello', true, 'x', now())", (tenant, tenant))
        from defender.migrations import upgrade

        upgrade(dsn)
        columns = {c for (c,) in execute(dsn, "SELECT column_name FROM information_schema.columns "
                                         "WHERE table_schema = 'tenancy' AND table_name = 'case_versions'")}
        assert "comment_body" not in columns, columns
        rows = execute(dsn, "SELECT version, system_id, deleted FROM tenancy.case_versions WHERE tenant_id = %s "
                            "ORDER BY version", (tenant,))
        assert rows == [(1, "ticket", False), (2, "ticket", True)], rows
