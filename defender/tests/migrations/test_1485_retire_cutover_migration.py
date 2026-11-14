"""#1485 O5: the revision ending `_retire_learning_cutover` takes `learning_cutover` out of the two `tenancy.tenants`
pending-action constraints and stops, changing nothing, while a tenant row carries it; the one after it adds the two partial indexes."""
from __future__ import annotations

import datetime as _dt
import re

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.shared._retired1485 import RETIRED_ACTION as ACTION

LEARNING_STORE = "0013_learning_store"
CREATED = _dt.datetime(2026, 11, 1, 8, 0, tzinfo=_dt.UTC)
TENANTS = [f"a8000000-0000-4000-8000-00000000000{n}" for n in range(1, 5)]
CONSTRAINTS = ("ck_tenants_pending_action", "ck_tenants_state_allows_pending_action")

pytestmark = pytest.mark.postgres


def _constraints(dsn: str) -> dict[str, str]:
    return dict(execute(dsn, """SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
        WHERE conrelid = 'tenancy.tenants'::regclass AND conname = ANY(%s)""", (list(CONSTRAINTS),)))


def _tenant(dsn: str, tenant: str, action: str | None, step: str | None = None, actor: str | None = None,
            failure: str | None = None) -> None:
    execute(dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor, failure)
                    VALUES (%s, %s, 'active', %s, %s, %s, %s)""", (tenant, CREATED, action, step, actor, failure))


def _version(dsn: str) -> list[tuple]:
    return execute(dsn, "SELECT version_num FROM public.alembic_version")


def _rows(dsn: str) -> list[tuple]:
    return execute(dsn, "SELECT id, state, pending_action, step, step_actor, failure FROM tenancy.tenants ORDER BY id")


def test_o5_the_retirement_and_the_index_revision_follow_the_history_as_it_stands():
    """The retirement sits after 0015 and the index revision directly on it, found by suffix, so a later head is no obstacle. (O5, D9)"""
    retire = revisions.by_suffix(revisions.RETIRE_SUFFIX)
    indexes = revisions.by_suffix(revisions.INDEXES_SUFFIX)
    assert revisions.down_of(indexes) == retire
    assert {"0015_system_records", f"0014_{ACTION}_action", LEARNING_STORE} <= revisions.ancestors(retire)
    assert retire not in revisions.ancestors(revisions.down_of(retire))


#: Each way a tenant can still carry the action: queued at its first step, mid-way, failed at either actor.
_STATES = {
    "queued": ("import", "host", None),
    "failed at import": ("import", "host", "the import was refused: a row of an unknown category"),
    "resumable at cutover": ("cutover", "host", "the cutover could not remove the folder"),
    "failed on the service side": ("cutover", "service", "boom"),
}


@pytest.mark.parametrize("carriers", [1, 2])
@pytest.mark.parametrize("state", sorted(_STATES))
def test_o5_the_upgrade_stops_naming_the_count_while_a_tenant_carries_learning_cutover_and_changes_nothing(
        state, carriers, empty_database):
    """With `carriers` tenants at `learning_cutover` (and a rotating one beside), `upgrade` raises naming that count and an earlier revision; nothing changes. (O5)"""
    from defender.migrations import upgrade

    retire = revisions.by_suffix(revisions.RETIRE_SUFFIX)
    before_retire = revisions.down_of(retire)
    _upgrade_to(empty_database, before_retire)
    step, actor, failure = _STATES[state]
    for tenant in TENANTS[:carriers]:
        _tenant(empty_database, tenant, ACTION, step, actor, failure)
    _tenant(empty_database, TENANTS[3], "rotate", "names", "service")  # not a carrier: must not be counted
    _tenant(empty_database, TENANTS[2], None)
    constraints, rows = _constraints(empty_database), _rows(empty_database)
    assert all(ACTION in text for text in constraints.values() if "'rotate'" in text)

    with pytest.raises(RuntimeError) as stopped:
        upgrade(empty_database)
    assert _version(empty_database) == [(before_retire,)]
    assert _constraints(empty_database) == constraints
    assert _rows(empty_database) == rows
    assert re.search(rf"\b{carriers}\b", str(stopped.value)), str(stopped.value)
    assert re.search(r"(?i)(earlier|before|older|previous)\s+(revision|release|version)", str(stopped.value)) or re.search(
        r"(?i)\b(finish|resume)", str(stopped.value)), str(stopped.value)


def test_o5_with_no_such_row_the_upgrade_restores_the_0013_constraints_and_refuses_the_value(empty_database):
    """With no `learning_cutover` row (a rotating one beside), `upgrade` leaves both constraints as read at 0013; the database refuses the value, takes `rotate`. (O5)"""
    from defender.migrations import head, upgrade

    _upgrade_to(empty_database, LEARNING_STORE)
    at_0013 = _constraints(empty_database)
    assert set(at_0013) == set(CONSTRAINTS)
    assert all(ACTION not in text for text in at_0013.values())
    _upgrade_to(empty_database, revisions.down_of(revisions.by_suffix(revisions.RETIRE_SUFFIX)))
    assert all(ACTION in text for text in _constraints(empty_database).values() if "'rotate'" in text)
    _tenant(empty_database, TENANTS[0], "rotate", "names", "service")
    _tenant(empty_database, TENANTS[1], None)

    upgrade(empty_database)
    assert _version(empty_database) == [(head(),)]
    assert _constraints(empty_database) == at_0013
    execute(empty_database, "UPDATE tenancy.tenants SET pending_action = 'rotate', step = 'names', step_actor = 'service' WHERE id = %s",
            (TENANTS[1],))
    assert [r[2] for r in _rows(empty_database)] == ["rotate", "rotate"]
    for refused in (ACTION, "not_an_action"):  # the second is the control that a bad value is refused this way
        with pytest.raises(Exception, match=r"ck_tenants_pending_action"):  # noqa: PT011 — a CHECK violation, whichever driver class carries it
            _tenant(empty_database, TENANTS[2], refused, "import", "host")
    assert [r[0] for r in _rows(empty_database)] == TENANTS[:2]


def _partials(dsn: str, table: str) -> list[tuple[list[str], list[bool], str]]:
    """Each partial index of `learning.<table>`: its key columns, whether each is descending, its predicate."""
    found = []
    for oid, nkeys, options, predicate in execute(dsn, """SELECT i.indexrelid, i.indnkeyatts, i.indoption::text, pg_get_expr(i.indpred, i.indrelid)
        FROM pg_index i WHERE i.indrelid = %s::regclass AND i.indpred IS NOT NULL""", (f"learning.{table}",)):
        columns = [execute(dsn, "SELECT pg_get_indexdef(%s::oid, %s, true)", (oid, k))[0][0] for k in range(1, nkeys + 1)]
        flags = [int(o) & 1 == 1 for o in options.split()]
        found.append((columns, flags, predicate))
    return found


def test_o1_at_head_both_partial_indexes_exist_with_the_designed_shapes(migrated_database):
    """At head: `work_items (tenant_id, updated_at DESC, id DESC) WHERE status IN (held, dead)` and `batches (tenant_id, created_at DESC, id DESC) WHERE phase = needs_person`. (O1, O2)"""
    items = [p for p in _partials(migrated_database, "work_items") if p[0] == ["tenant_id", "updated_at", "id"]]
    assert [(flags, sorted(re.findall(r"'(\w+)'", predicate)), "status" in predicate) for _, flags, predicate in items] == [
        ([False, True, True], ["dead", "held"], True)]
    batches = [p for p in _partials(migrated_database, "batches") if p[0] == ["tenant_id", "created_at", "id"]]
    assert [(flags, re.findall(r"'(\w+)'", predicate), "phase" in predicate) for _, flags, predicate in batches] == [
        ([False, True, True], ["needs_person"], True)]
    # Control on the probe: the lane's existing partial unique index on `batches` is read, by another shape.
    assert any(columns != ["tenant_id", "created_at", "id"] for columns, _, _ in _partials(migrated_database, "batches"))


def _declared_index_objects(table: str) -> list:
    from defender.migrations.models import target_metadata

    [declared] = [t for t in target_metadata.tables.values() if t.schema == "learning" and t.name == table]
    return [index for index in declared.indexes if index.dialect_options["postgresql"]["where"] is not None]


def _declared_partials(table: str) -> list[tuple[list[str], str]]:
    return [([str(e) for e in index.expressions], str(index.dialect_options["postgresql"]["where"]))
            for index in _declared_index_objects(table)]


def test_o1_the_table_models_declare_both_indexes_and_autogenerate_exempts_none():
    """Both partial indexes are declared on the table models, and `include_object` still passes an index (no drift exemption). (O1, O2)"""
    from defender.migrations import include_object

    assert include_object(object(), "any_index", "index", False, None) is True
    new = [i for table in ("work_items", "batches") for i in _declared_index_objects(table)
           if [str(e).split(".")[-1].split()[0] for e in i.expressions] in (["tenant_id", "updated_at", "id"], ["tenant_id", "created_at", "id"])]
    assert len(new) == 2, "premise: both new partial indexes are declared"
    assert [include_object(i, i.name, "index", False, None) for i in new] == [True, True]
    items = [w for cols, w in _declared_partials("work_items") if [c.split(".")[-1].split()[0] for c in cols] == ["tenant_id", "updated_at", "id"]]
    assert [sorted(re.findall(r"'(\w+)'", w)) for w in items] == [["dead", "held"]]
    batches = [w for cols, w in _declared_partials("batches") if [c.split(".")[-1].split()[0] for c in cols] == ["tenant_id", "created_at", "id"]]
    assert [re.findall(r"'(\w+)'", w) for w in batches] == [["needs_person"]]
    declared = [cols for cols, _ in _declared_partials("work_items") if [c.split(".")[-1].split()[0] for c in cols] == ["tenant_id", "updated_at", "id"]]
    assert [[c.endswith("DESC") for c in cols] for cols in declared] == [[False, True, True]], "updated_at and id are declared descending"


def _id_column(dsn: str) -> tuple[str, bool, str | None]:
    """`learning.work_items.id`: its type, whether it is NOT NULL, and its default expression."""
    return execute(dsn, """SELECT format_type(a.atttypid, a.atttypmod), a.attnotnull, pg_get_expr(d.adbin, d.adrelid)
        FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE a.attrelid = 'learning.work_items'::regclass AND a.attname = 'id' AND NOT a.attisdropped""")[0]


def _unique_on(dsn: str, table: str, column: str) -> list[str]:
    """Names of the unique, non-partial indexes of `learning.<table>` whose only key column is `column`."""
    return [name for (name,) in execute(dsn, """SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
        WHERE i.indrelid = %s::regclass AND i.indisunique AND i.indpred IS NULL AND i.indnkeyatts = 1
          AND (SELECT attname FROM pg_attribute WHERE attrelid = i.indrelid AND attnum = i.indkey[0]) = %s""",
                                       (f"learning.{table}", column))]


def test_d12_at_head_work_items_id_is_a_required_unique_uuid_with_no_default(migrated_database):
    """At head `work_items.id` is uuid, NOT NULL, covered by a one-column unique index, and has no default. (D12)"""
    assert _id_column(migrated_database) == ("uuid", True, None)
    assert len(_unique_on(migrated_database, "work_items", "id")) == 1
    # Control on the probe: the same read finds the batches' id column unique and required, and the item's non-key
    # `source_run` neither.
    assert len(_unique_on(migrated_database, "batches", "id")) >= 1
    assert _unique_on(migrated_database, "work_items", "source_run") == []


def test_d12_rows_seeded_before_the_index_revision_get_distinct_non_null_ids_on_upgrade(empty_database):
    """Items inserted at the revision before the index revision (several tenants, kinds and statuses) each get a
    distinct id on upgrade, and none keeps a default behind. (D12)"""
    from defender.migrations import head, upgrade

    before = revisions.down_of(revisions.by_suffix(revisions.INDEXES_SUFFIX))
    _upgrade_to(empty_database, before)
    assert execute(empty_database, """SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'learning' AND table_name = 'work_items' AND column_name = 'id'""") == [(0,)], "premise: no id yet"
    _tenant(empty_database, TENANTS[0], None)
    _tenant(empty_database, TENANTS[1], None)
    seeded = [(t, kind, f"k{n}", status) for t in TENANTS[:2] for n, (kind, status) in enumerate(
        [("finding", "held"), ("finding", "dead"), ("pitfall", "waiting"), ("questioner_finding", "held"), ("curation_request", "waiting")])]
    for tenant, kind, key, status in seeded:
        execute(empty_database, """INSERT INTO learning.work_items (tenant_id, kind, item_key, payload, status, attempts, deferrals,
            offers_declined, enqueued_at, updated_at) VALUES (%s, %s, %s, '{}', %s, 0, 0, 0, %s, %s)""",
                (tenant, kind, key, status, CREATED, CREATED))

    upgrade(empty_database)
    assert _version(empty_database) == [(head(),)]
    rows = execute(empty_database, "SELECT tenant_id, kind, item_key, id FROM learning.work_items")
    assert sorted(r[:3] for r in rows) == sorted(s[:3] for s in seeded), "premise: every seeded row survived"
    ids = [r[3] for r in rows]
    assert None not in ids
    assert len(set(ids)) == len(seeded) == 10
    assert all(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", i) for i in ids)
    assert _id_column(empty_database) == ("uuid", True, None)
