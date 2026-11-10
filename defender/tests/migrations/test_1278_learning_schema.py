"""#1278 the `learning` schema's constraints the design names, observed as the database enforces them.

Rows go in by SQL, each with every required column filled by a type-driven sample and only the columns
under test chosen by the case, so the tests name no column the design does not (the tenant column, the
item key and the coalesce column are read off the catalog). Column names assumed from the design text:
`kind`, `lane`, `phase`, `outcome`, `status`. The tenant-active insert is behaviour, seen through the store.
"""
from __future__ import annotations

import itertools
import uuid
from typing import Any

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, LEAD_LANE, ONE, finding, learning_store
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = pytest.mark.postgres

BLUE = fixture_uuid("tenant:1278-schema-blue")
GREEN = fixture_uuid("tenant:1278-schema-green")
TABLES = ("work_items", "batches", "commits", "commit_changes")
_COUNTER = itertools.count(1)


@pytest.fixture
def db(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


# --- catalog reads -----------------------------------------------------------------------------------------------


def _foreign_keys(dsn: str, table: str) -> list[tuple[str, str, str]]:
    """(column, referenced `schema.table`, NOT NULL as text) of every single-column foreign key of `learning.<table>`."""
    rows = execute(dsn, """
        SELECT a.attname, rn.nspname || '.' || rt.relname, a.attnotnull::text
        FROM pg_constraint k JOIN pg_class t ON t.oid = k.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_class rt ON rt.oid = k.confrelid JOIN pg_namespace rn ON rn.oid = rt.relnamespace
        JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
        WHERE k.contype = 'f' AND array_length(k.conkey, 1) = 1 AND n.nspname = 'learning' AND t.relname = %s""", (table,))
    return [tuple(r) for r in rows]  # type: ignore[misc]


def _primary_key(dsn: str, table: str) -> list[str]:
    return [r[0] for r in execute(dsn, """
        SELECT a.attname FROM pg_constraint k JOIN pg_class t ON t.oid = k.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN LATERAL unnest(k.conkey) WITH ORDINALITY AS u(attnum, ord) ON true
        JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.attnum
        WHERE k.contype = 'p' AND n.nspname = 'learning' AND t.relname = %s ORDER BY u.ord""", (table,))]


def _partial_unique(dsn: str, table: str, *words: str) -> list[tuple[list[str], str]]:
    """(key columns, predicate) of each UNIQUE partial index on `learning.<table>` whose predicate mentions every word."""
    out = []
    for (definition,) in execute(
            dsn, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'learning' AND tablename = %s", (table,)):
        if "UNIQUE" in definition and " WHERE " in definition:
            head, predicate = definition.split(" WHERE ", 1)
            if all(w in predicate for w in words):
                columns = head.rsplit("(", 1)[1].rstrip(")").split(",")
                out.append(([c.strip().strip('"') for c in columns], predicate))
    return out


def _columns(dsn: str, table: str) -> dict[str, tuple[str, bool]]:
    """column -> (formatted type, required): nullable-less columns with no default."""
    return {name: (kind, required) for name, kind, required in execute(dsn, """
        SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull AND d.adbin IS NULL
        FROM pg_attribute a JOIN pg_class t ON t.oid = a.attrelid JOIN pg_namespace n ON n.oid = t.relnamespace
        LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE n.nspname = 'learning' AND t.relname = %s AND a.attnum > 0 AND NOT a.attisdropped""", (table,))}


def _tenant_column(dsn: str, table: str) -> str:
    [column] = [c for c, ref, _nn in _foreign_keys(dsn, table) if ref == "tenancy.tenants"]
    return column


# --- rows ---------------------------------------------------------------------------------------------------------


_SAMPLE = {"uuid": lambda n: str(uuid.uuid4()), "boolean": lambda n: "false", "jsonb": lambda n: "{}",
           "json": lambda n: "{}", "text": lambda n: f"{n}-{next(_COUNTER)}", "bytea": lambda n: "\\x00"}


def _sample(name: str, kind: str) -> str:
    if kind.startswith("timestamp"):
        return "2026-11-10T00:00:00Z"
    if kind in {"integer", "bigint", "smallint"}:
        return "0"
    if kind.startswith(("double", "numeric", "real")):
        return "0"
    return _SAMPLE.get(kind, _SAMPLE["text"])(name)


def insert(dsn: str, table: str, **given: Any) -> None:
    """One row of `learning.<table>`: `given` where named, a sample for every other required column. A required
    foreign key to a table the case did not set up cannot be sampled: that insert fails and the case says so."""
    columns = _columns(dsn, table)
    values = {name: given[name] for name in given}
    for name, (kind, required) in columns.items():
        if name not in values and required:
            values[name] = _sample(name, kind)
    names = list(values)
    placeholders = ", ".join(f"CAST(%s AS {columns[n][0]})" for n in names)
    execute(dsn, f'INSERT INTO learning.{table} ({", ".join(names)}) VALUES ({placeholders})',  # noqa: S608
            tuple(values[n] for n in names))


def item(dsn: str, tenant: str, kind: str, key: str, status: str, **more: Any) -> None:
    tenant_col = _tenant_column(dsn, "work_items")
    key_col = next(c for c in _primary_key(dsn, "work_items") if c not in {tenant_col, "kind"})
    insert(dsn, "work_items", **{tenant_col: tenant, "kind": kind, key_col: key, "status": status}, **more)


def batch(dsn: str, tenant: str, lane: str, phase: str, *, kind: str = "author", **more: Any) -> None:
    columns = _columns(dsn, "batches")
    given: dict[str, Any] = {_tenant_column(dsn, "batches"): tenant, "lane": lane, "kind": kind, "phase": phase}
    if phase == "ended":
        given["outcome"] = "abandoned"
    if phase == "working":  # a working batch holds a lease
        given.update({c: v for c, v in {"lease_owner": "holder", "lease_expiry": "2030-01-01T00:00:00Z",
                                        "fencing_token": "1"}.items() if c in columns})
    if phase == "in_review" and "pr_number" in columns:
        given["pr_number"] = str(next(_COUNTER) + 100)
    insert(dsn, "batches", **given, **more)


def refused(statement_runner) -> None:
    """The row is refused as a duplicate: PostgreSQL's unique violation, not a CHECK or a missing column."""
    import psycopg

    with pytest.raises(psycopg.errors.UniqueViolation):
        statement_runner()


# --- the census of what the cases rely on ----------------------------------------------------------------------


def test_every_learning_table_carries_the_tenant_and_the_columns_the_cases_name(db):
    """Each table has a foreign key to `tenancy.tenants` (repo convention, design Review-1 R1-SCH); batches and items have the design's enumerated columns. (Schema)"""
    for table in TABLES:
        assert [ref for _c, ref, _nn in _foreign_keys(db, table)].count("tenancy.tenants") == 1, table
    assert {"kind", "lane", "phase", "outcome"} <= set(_columns(db, "batches"))
    assert {"kind", "status"} <= set(_columns(db, "work_items"))
    assert ("learning.batches" in [ref for _c, ref, _nn in _foreign_keys(db, "commits")])
    assert ("learning.commits" in [ref for _c, ref, _nn in _foreign_keys(db, "commit_changes")])


# --- work_items --------------------------------------------------------------------------------------------------


def test_a_finding_id_is_unique_for_good_whatever_became_of_it(db):
    """One row per (tenant, kind, key) across every status; the same key on another kind or tenant is a different item. (Schema)"""
    key_cols = _primary_key(db, "work_items")
    assert len(key_cols) == 3
    assert {"kind", _tenant_column(db, "work_items")} < set(key_cols)

    item(db, BLUE, "finding", "f1", "published")
    for status in ("waiting", "published", "dead"):
        refused(lambda status=status: item(db, BLUE, "finding", "f1", status))
    item(db, BLUE, "questioner_finding", "f1", "waiting")
    item(db, GREEN, "finding", "f1", "waiting")


def test_a_request_case_is_unique_while_waiting_and_only_then(db):
    """Two waiting requests for one case are refused; a skipped or in-batch one beside a waiting one is not. (Schema, coalesce)"""
    [(columns, predicate)] = _partial_unique(db, "work_items", "waiting")
    coalesce = [c for c in columns if c not in {_tenant_column(db, "work_items"), "kind"}]
    assert len(coalesce) == 1, f"a unique partial index over {columns} where {predicate}"
    case = coalesce[0]

    item(db, BLUE, "curation_request", "run-1", "waiting", **{case: "case-1"})
    refused(lambda: item(db, BLUE, "curation_request", "run-2", "waiting", **{case: "case-1"}))
    item(db, BLUE, "curation_request", "run-3", "skipped", **{case: "case-1"})
    item(db, BLUE, "curation_request", "run-4", "in_batch", **{case: "case-1"})
    item(db, BLUE, "curation_request", "run-5", "waiting", **{case: "case-2"})
    item(db, GREEN, "curation_request", "run-6", "waiting", **{case: "case-1"})


# --- batches -----------------------------------------------------------------------------------------------------


def test_one_author_batch_not_ended_per_lane(db):
    """A second author batch in any not-ended phase on a lane is refused; ended ones, other lanes, tenants and reverts are not. (Schema)"""
    batch(db, BLUE, AUTHOR_LANE, "in_review")
    for phase in ("working", "in_review", "needs_person"):
        refused(lambda phase=phase: batch(db, BLUE, AUTHOR_LANE, phase))
    batch(db, BLUE, AUTHOR_LANE, "ended")
    batch(db, BLUE, AUTHOR_LANE, "ended")
    batch(db, BLUE, LEAD_LANE, "in_review")
    batch(db, GREEN, AUTHOR_LANE, "in_review")
    batch(db, BLUE, AUTHOR_LANE, "in_review", kind="revert")
    batch(db, BLUE, AUTHOR_LANE, "in_review", kind="revert")


def test_one_working_batch_per_lane_of_any_kind(db):
    """A revert working beside a working batch of the lane is refused, as is a second revert; in review beside it is fine. (Schema)"""
    batch(db, BLUE, AUTHOR_LANE, "working", kind="revert")
    refused(lambda: batch(db, BLUE, AUTHOR_LANE, "working", kind="revert"))
    refused(lambda: batch(db, BLUE, AUTHOR_LANE, "working", kind="author"))
    batch(db, BLUE, AUTHOR_LANE, "in_review", kind="revert")
    batch(db, BLUE, AUTHOR_LANE, "in_review", kind="author")
    batch(db, BLUE, LEAD_LANE, "working", kind="author")
    batch(db, GREEN, AUTHOR_LANE, "working", kind="revert")


# --- commits -----------------------------------------------------------------------------------------------------


def test_a_commit_row_may_have_no_batch_but_never_a_batch_that_does_not_exist(db):
    """Imported history has a null batch link; any other link must name a batch. (Schema, A2 D5)"""
    import psycopg

    [link] = [c for c, ref, _nn in _foreign_keys(db, "commits") if ref == "learning.batches"]
    assert _columns(db, "commits")[link][1] is False, "nullable: imported history has no batch"
    tenant = _tenant_column(db, "commits")
    insert(db, "commits", **{tenant: BLUE})
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        insert(db, "commits", **{tenant: BLUE, link: str(uuid.uuid4())})


# --- insert conditional on the tenant being active (through the store) ------------------------------------------


@pytest.mark.anyio
async def test_a_tenant_that_is_not_active_gets_no_new_batch_and_no_new_findings(db):
    """After the tenant moves to offboarding, `claim` and `publish_findings` raise `TenantInactive` and add no row. (Schema, D11)"""
    from defender.tests.support.learning.core._store1278 import store_mod

    async with learning_store(db) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        execute(db, """UPDATE tenancy.tenants SET state = 'offboarding', pending_action = 'offboard',
                       step = 'offboard', step_actor = 'service' WHERE id = %s""", (BLUE,))
        before = ([(i.kind, i.key, i.status) for i in await store.work(BLUE)], list(await store.batches(BLUE)))

        with pytest.raises(store_mod().TenantInactive):
            await store.claim(BLUE, AUTHOR_LANE, owner="holder", thresholds=ONE)
        with pytest.raises(store_mod().TenantInactive):
            await store.publish_findings(BLUE, "run-2", [finding("f2")], kind="finding")

        after = ([(i.kind, i.key, i.status) for i in await store.work(BLUE)], list(await store.batches(BLUE)))
    assert after == before
    assert before[0] == [("finding", "f1", "waiting")]
    assert before[1] == []
