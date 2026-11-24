"""#1618 D7: a revision after `0027_people_requests` (#1592) drops `tenancy.publish_status` and touches nothing else; no product
code is left that writes or reads the table (the launch's publish outcome is no longer recorded)."""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import pytest

from defender.tests.migrations.test_1214_migrations import _tables, _upgrade_to
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import execute

PRIOR = "0027_people_requests"
TENANT = "5b1c2d3e-4f50-4a61-8b72-9c83d4e5f601"
STAMP = dt.datetime(2026, 11, 1, 8, 0, tzinfo=dt.UTC)
DEFENDER = Path(__file__).resolve().parents[2]
#: The table's names; the migrations that made and kept it (and this change's drop) are history, not writers.
NAMES = re.compile(r"\b(?:publish_status|PublishStatus|record_publish_status)\b")


def _plant(dsn: str) -> None:
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state) VALUES (%s, %s, 'active')", (TENANT, STAMP))
    execute(dsn, "INSERT INTO tenancy.publish_status (tenant_id, recorded_by, published, refused, kind) "
                 "VALUES (%s, 'host', 'abc', NULL, NULL)", (TENANT,))


def test_one_revision_after_the_host_requests_revision_drops_the_publish_status_table_and_the_head_is_not_behind_it():
    """One line of history with a revision built after `0027_people_requests` (the head is not still there). (D7)"""
    from defender.migrations import head, heads

    assert heads() == (head(),)
    assert head() != PRIOR, "no revision follows 0027_people_requests"
    assert PRIOR in revisions.ancestors(head())


@pytest.mark.postgres
def test_the_table_is_there_at_the_prior_revision_and_gone_at_head_with_every_other_tenancy_table_as_it_was(empty_database):
    """`publish_status` exists at `0027_people_requests` (control) and not after the drop revision, nor at head; across the
    drop revision the other `tenancy` tables keep their columns. (D7; #1546 (r10 (g)): #1546's revisions follow the drop and
    add their own `tenancy` table and columns, so "touches nothing else" is the drop revision's own step, not the way to
    head)"""
    from defender.migrations import head

    dsn = empty_database
    shape = ("SELECT table_name, column_name, data_type FROM information_schema.columns "
             "WHERE table_schema = 'tenancy' AND table_name <> 'publish_status' ORDER BY 1, 2")
    drop = revisions.by_suffix("_drop_publish_status")
    assert revisions.down_of(drop) == PRIOR, "premise: the drop sits directly on 0027_people_requests"
    _upgrade_to(dsn, PRIOR)
    assert "publish_status" in _tables(dsn, "tenancy"), "control: the table exists before the revision"
    before = execute(dsn, shape)
    _upgrade_to(dsn, drop)
    assert "publish_status" not in _tables(dsn, "tenancy")
    assert execute(dsn, shape) == before
    _upgrade_to(dsn, head())
    assert "publish_status" not in _tables(dsn, "tenancy")


@pytest.mark.postgres
def test_a_tenant_with_a_recorded_publish_outcome_upgrades_with_its_tenant_row_intact(empty_database):
    """A row in the dropped table does not stop the upgrade, and the tenant it named keeps its row (no cascade). (D7;
    #1546 r9 B / r10 (g): past the drop, `*_retention_required` refuses an active tenant with no retention row, so the
    tenant's retention row is planted on the way, as creating a tenant writes it since #1546)"""
    from defender.tests.migrations._marked1470 import upgrade_with_retention

    dsn = empty_database
    _upgrade_to(dsn, PRIOR)
    _plant(dsn)
    assert execute(dsn, "SELECT count(*) FROM tenancy.publish_status") == [(1,)], "control: the outcome row is there"
    upgrade_with_retention(dsn)
    assert execute(dsn, "SELECT id, state FROM tenancy.tenants") == [(TENANT, "active")]
    assert "publish_status" not in _tables(dsn, "tenancy")


def test_no_product_code_names_the_publish_status_table_or_its_writers():
    """No module outside the migrations and the tests mentions `publish_status`, `PublishStatus` or `record_publish_status`:
    the table has no writer or reader left. (D7)"""
    skipped = {"tests", "migrations", ".venv", "__pycache__"}
    found: dict[str, list[str]] = {}
    for path in DEFENDER.rglob("*.py"):
        parts = path.relative_to(DEFENDER).parts
        if parts[0] in skipped or ".venv" in parts:
            continue
        hits = sorted(set(NAMES.findall(path.read_text(encoding="utf-8"))))
        if hits:
            found[path.relative_to(DEFENDER).as_posix()] = hits
    assert found == {}, found
    control = DEFENDER / "migrations" / "versions" / "0002_tenancy.py"
    assert NAMES.search(control.read_text(encoding="utf-8")), "control: the census pattern finds the table where it is made"
