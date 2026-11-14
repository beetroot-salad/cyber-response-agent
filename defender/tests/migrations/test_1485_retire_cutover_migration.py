"""#1485 O5: the revision ending `_retire_learning_cutover` takes `learning_cutover` out of the two `tenancy.tenants`
pending-action constraints and stops, changing nothing, while a tenant row carries it; the one after it adds the two partial indexes."""
from __future__ import annotations

import datetime as _dt
import re

import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import execute

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
    assert {"0015_system_records", "0014_learning_cutover_action", LEARNING_STORE} <= revisions.ancestors(retire)
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
        _tenant(empty_database, tenant, "learning_cutover", step, actor, failure)
    _tenant(empty_database, TENANTS[3], "rotate", "names", "service")  # not a carrier: must not be counted
    _tenant(empty_database, TENANTS[2], None)
    constraints, rows = _constraints(empty_database), _rows(empty_database)
    assert all("learning_cutover" in text for text in constraints.values() if "'rotate'" in text)

    with pytest.raises(RuntimeError) as stopped:
        upgrade(empty_database)
    assert re.search(rf"\b{carriers}\b", str(stopped.value)), str(stopped.value)
    assert re.search(r"(?i)earlier revision", str(stopped.value)), str(stopped.value)
    assert _version(empty_database) == [(before_retire,)]
    assert _constraints(empty_database) == constraints
    assert _rows(empty_database) == rows


def test_o5_with_no_such_row_the_upgrade_restores_the_0013_constraints_and_refuses_the_value(empty_database):
    """With no `learning_cutover` row (a rotating one beside), `upgrade` leaves both constraints as read at 0013; the database refuses the value, takes `rotate`. (O5)"""
    from defender.migrations import head, upgrade

    _upgrade_to(empty_database, LEARNING_STORE)
    at_0013 = _constraints(empty_database)
    assert set(at_0013) == set(CONSTRAINTS)
    assert all("learning_cutover" not in text for text in at_0013.values())
    _upgrade_to(empty_database, revisions.down_of(revisions.by_suffix(revisions.RETIRE_SUFFIX)))
    assert all("learning_cutover" in text for text in _constraints(empty_database).values() if "'rotate'" in text)
    _tenant(empty_database, TENANTS[0], "rotate", "names", "service")
    _tenant(empty_database, TENANTS[1], None)

    upgrade(empty_database)
    assert _version(empty_database) == [(head(),)]
    assert _constraints(empty_database) == at_0013
    execute(empty_database, "UPDATE tenancy.tenants SET pending_action = 'rotate', step = 'names', step_actor = 'service' WHERE id = %s",
            (TENANTS[1],))
    assert [r[2] for r in _rows(empty_database)] == ["rotate", "rotate"]
    for refused in ("learning_cutover", "not_an_action"):  # the second is the control that a bad value is refused this way
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
    """At head: `work_items (tenant_id, updated_at DESC) WHERE status IN (held, dead)` and `batches (tenant_id, created_at DESC, id DESC) WHERE phase = needs_person`. (O1, O2)"""
    items = [p for p in _partials(migrated_database, "work_items") if p[0] == ["tenant_id", "updated_at"]]
    assert [(flags, sorted(re.findall(r"'(\w+)'", predicate)), "status" in predicate) for _, flags, predicate in items] == [
        ([False, True], ["dead", "held"], True)]
    batches = [p for p in _partials(migrated_database, "batches") if p[0] == ["tenant_id", "created_at", "id"]]
    assert [(flags, re.findall(r"'(\w+)'", predicate), "phase" in predicate) for _, flags, predicate in batches] == [
        ([False, True, True], ["needs_person"], True)]
    # Control on the probe: the lane's existing partial unique index on `batches` is read, by another shape.
    assert any(columns != ["tenant_id", "created_at", "id"] for columns, _, _ in _partials(migrated_database, "batches"))


def _declared_partials(table: str) -> list[tuple[list[str], str]]:
    from defender.migrations.models import target_metadata

    [declared] = [t for t in target_metadata.tables.values() if t.schema == "learning" and t.name == table]
    return [([str(e) for e in index.expressions], str(index.dialect_options["postgresql"]["where"]))
            for index in declared.indexes if index.dialect_options["postgresql"]["where"] is not None]


def test_o1_the_table_models_declare_both_indexes_and_autogenerate_exempts_none():
    """Both partial indexes are declared on the table models, and `include_object` still passes an index (no drift exemption). (O1, O2)"""
    from defender.migrations import include_object

    assert include_object(object(), "any_index", "index", False, None) is True
    items = [w for cols, w in _declared_partials("work_items") if [c.split(".")[-1].split()[0] for c in cols] == ["tenant_id", "updated_at"]]
    assert [sorted(re.findall(r"'(\w+)'", w)) for w in items] == [["dead", "held"]]
    batches = [w for cols, w in _declared_partials("batches") if [c.split(".")[-1].split()[0] for c in cols] == ["tenant_id", "created_at", "id"]]
    assert [re.findall(r"'(\w+)'", w) for w in batches] == [["needs_person"]]
    assert any(c.endswith("DESC") for cols, _ in _declared_partials("work_items") for c in cols), "updated_at is declared descending"
