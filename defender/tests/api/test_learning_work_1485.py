"""#1485 O1-O3: `GET /tenants/{t}/learning/items` and `/learning/parked-batches` over the real adapter
(`StoreLearningWork`) on a real learning store. Rows are made only by the store's verbs; every expected value and order
is read back from the store's own views (`work()`, `batches()`, `parked()`) and sorted here, never taken from the code.
"""
from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any

import pytest

from defender.tests.support.api._mount1161 import API
from defender.tests.support.api._actions1537 import batch_row
from defender.tests.support.api._identity1306 import ANN, BOB, T1, T2
from defender.tests.support.api._learning1485 import (
    HOSTILE_REASON,
    INSTANT,
    LONG_KEY,
    QUESTIONER,
    LearningWorld,
    curator_held,
    dead_alone,
    held_together,
    in_review_author,
    instant,
    newest_first,
    on_store,
    parked_author,
    parked_registry,
    parked_revert,
    settled_mix,
    stored_batches,
    stored_items,
    tie_batches,
    walk,
    wire_item,
)
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import call

pytestmark = [pytest.mark.postgres]

ITEMS = "learning/items"
PARKED = "learning/parked-batches"
#: The wire's fields (Names, wire models): `item_id` included; no payload, fault, counters or lease.
#: #1537 O4, O5 (conflict, updated): items gain `cause`; parked batches gain `cause`, `parked_at`, `releasable`,
#: `abandon_requested_at` and `last_checked`.
ITEM_FIELDS = {"item_id", "kind", "key", "status", "reason", "cause", "source_run", "batch_id", "pr_number", "updated_at"}
BATCH_FIELDS = {"batch_id", "batch_kind", "lane", "blocks_lane", "branch", "pr_number", "reason", "cause", "parked_at",
                "releasable", "abandon_requested_at", "last_checked", "created_at", "items"}


def _cursors_after(got: list[dict], cursors: list[str], limit: int, tied: Callable[[dict], bool]) -> list[str]:
    """The cursors issued after a row of `got` for which `tied` holds: cursor `n` follows row `(n + 1) * limit - 1`."""
    return [c for n, c in enumerate(cursors) if tied(got[(n + 1) * limit - 1])]


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, T1)
    register_tenant(migrated_database, T2)
    return migrated_database


@pytest.fixture
def world(dsn):
    """Builds the world when called, after a case seeded the store (so a red lands in the API, not the fixture)."""
    built: list[LearningWorld] = []

    def build() -> LearningWorld:
        built.append(LearningWorld(dsn, tenants={T1: [ANN], T2: [BOB]}))
        return built[-1]
    yield build
    for w in built:
        w.close()


def _expected_items(dsn: str, tenant: str, *statuses: str) -> list[Any]:
    """The tenant's stored items in `statuses` in the list's order (updated_at, id), both descending, sorted here."""
    return newest_first(stored_items(dsn, tenant, *statuses), lambda i: i.updated_at, lambda i: i.id)


def _check_item(wire: dict[str, Any], stored: Any) -> None:
    assert set(wire) == ITEM_FIELDS
    assert {k: v for k, v in wire.items() if k != "updated_at"} == wire_item(stored)
    assert instant(wire["updated_at"]) == stored.updated_at
    assert wire["cause"] is not None, "#1537 PR1: a held or dead item has a cause"


# --- O1 ------------------------------------------------------------------------------------------------------------

async def _three_ways(store: Any, tenant: str) -> None:
    await dead_alone(store, tenant, "d1")
    await curator_held(store, tenant, "c1", HOSTILE_REASON)
    await held_together(store, tenant, [("finding", "h1")], pr=7)


def test_o1_items_list_held_and_dead_newest_first_with_the_stored_fields_verbatim(dsn, world):
    """Held and dead items list by (updated_at, id) descending, exactly the wire's fields, each as the store holds it (a
    `<script>` reason byte for byte, `item_id` the stored id, the batch's PR). (O1, P1, P2)"""
    on_store(dsn, _three_ways, T1)
    stored = {i.key: i for i in stored_items(dsn, T1, "held", "dead")}
    assert stored["c1"].reason == HOSTILE_REASON, "premise: the store kept the reason as given"
    assert len({i.updated_at for i in stored.values()}) == 3, "premise: three transactions, three times"
    expected = _expected_items(dsn, T1, "held", "dead")

    r = world().sign_in(ANN).get(f"{API}/tenants/{T1}/{ITEMS}")
    assert r.status_code == 200, r.text
    assert set(r.json()) == {"items", "next_cursor"}
    got = r.json()["items"]
    assert [i["item_id"] for i in got] == [str(i.id) for i in expected]
    for wire, item in zip(got, expected, strict=True):
        _check_item(wire, item)
    by_key = {i["key"]: i for i in got}
    assert by_key["c1"]["reason"] == HOSTILE_REASON
    assert '&lt;' not in r.text
    assert '\\u003c' not in r.text, 'a reason is plain text, never marked up'
    assert (by_key["h1"]["pr_number"], by_key["d1"]["pr_number"]) == (7, None), "control: a held item carries its batch's PR"
    assert by_key['d1']['status'] == 'dead'
    assert by_key['h1']['status'] == 'held'


def test_o1_status_narrows_to_held_or_dead_and_any_other_status_is_a_422(dsn, world):
    """`status=dead` lists only the dead and `status=held` only the held (control: no filter lists both); `waiting` and
    the other stored statuses are a 422. (O1, Names)"""
    on_store(dsn, _three_ways, T1)
    ann = world().sign_in(ANN)
    keys = {s: [i.key for i in _expected_items(dsn, T1, *s)] for s in (("dead",), ("held",), ("held", "dead"))}
    assert keys['dead',] == ['d1']
    assert keys['held',], 'premise: both statuses are held by someone'
    for params, want in (({"status": "dead"}, keys[("dead",)]), ({"status": "held"}, keys[("held",)]), ({}, keys[("held", "dead")])):
        r = ann.get(f"{API}/tenants/{T1}/{ITEMS}", params=params)
        assert r.status_code == 200, r.text
        assert [i["key"] for i in r.json()["items"]] == want, params
    for bad in ("waiting", "in_batch", "published", "skipped", "Held", "held,dead", ""):
        assert ann.get(f"{API}/tenants/{T1}/{ITEMS}", params={"status": bad}).status_code == 422, bad


def test_o1_only_held_and_dead_items_are_listed(dsn, world):
    """Published, skipped, in-batch and waiting items are not listed; the held and the dead one are (control). (O1, Non-obligations)"""
    on_store(dsn, settled_mix, T1)
    assert {i.status for i in stored_items(dsn, T1)} == {"published", "skipped", "dead", "held", "in_batch", "waiting"}, "premise"
    got = world().sign_in(ANN).get(f"{API}/tenants/{T1}/{ITEMS}").json()["items"]
    assert sorted(i["key"] for i in got) == ["dd", "hh"]


async def _twelve_tied(store: Any, tenant: str) -> None:
    await dead_alone(store, tenant, "early-dead")
    keys = [f"t{n:02d}" for n in range(11)] + [LONG_KEY]
    await held_together(store, tenant, [("finding", k) for k in keys])
    await curator_held(store, tenant, "late", "the curator held it")


@pytest.mark.parametrize("limit", [3, 1])
def test_o1_twelve_items_held_by_one_close_page_each_once_in_id_order_with_a_kilobyte_key_among_them(dsn, world, limit):
    """Twelve items tied on `updated_at` (one a ~1 KB key) between an older dead item and a newer held one, paged `limit`
    at a time: (updated_at, id) descending, each exactly once, every page full but the last, the key served whole and
    the cursor issued after it short. (O1, Paging, Scenarios)"""
    on_store(dsn, _twelve_tied, T1)
    stored = stored_items(dsn, T1, "held", "dead")
    tied = [i for i in stored if i.key not in ("early-dead", "late")]
    assert len(tied) == 12
    assert len({i.updated_at for i in tied}) == 1, 'premise: twelve share one updated_at'
    by_id = [i.key for i in sorted(tied, key=lambda i: str(i.id), reverse=True)]
    by_key = [i.key for i in sorted(tied, key=lambda i: i.key, reverse=True)]
    assert by_id != by_key, "premise: id order is not key order, so a (kind, key) order fails"
    expected = _expected_items(dsn, T1, "held", "dead")
    assert len(expected) == 14

    got, sizes, cursors = walk(world().sign_in(ANN), f"{API}/tenants/{T1}/{ITEMS}", limit=limit)

    assert [i["item_id"] for i in got] == [str(i.id) for i in expected]
    assert len({i["item_id"] for i in got}) == len(got), "an item came twice"
    assert [i["key"] for i in got if len(i["key"]) > 900] == [LONG_KEY]
    assert sizes[:-1] == [limit] * (len(sizes) - 1)
    assert 0 < sizes[-1] <= limit
    # A cursor holds a position and the names that bind it, never an item's key: after a row tied with the ~1 KB key it is
    # as long as after any other tied row (same instant, same id family).
    after_tied = _cursors_after(got, cursors, limit, lambda i: i["key"] not in ("early-dead", "late"))
    assert len(after_tied) >= 2, "premise: more than one cursor follows a tied item"
    assert len({len(c) for c in after_tied}) == 1, "a cursor grew with an item key"
    if limit == 1:
        after_long = cursors[[i["key"] for i in got].index(LONG_KEY)]
        assert after_long in after_tied, "premise: the cursor after the long key is one of those compared"
        assert LONG_KEY[:40].encode() not in base64.urlsafe_b64decode(after_long + "=" * (-len(after_long) % 4))


def test_o1_an_item_cursor_is_refused_by_the_parked_list_and_a_parked_cursor_by_the_item_list(dsn, world):
    """Each list's cursor pages its own list (control) and is a 422 on the other. (Paging)"""
    async def seed(store: Any) -> None:
        await held_together(store, T1, [("finding", "h1"), ("finding", "h2")])
        await parked_revert(store, T1)
        await parked_registry(store, T1)
    on_store(dsn, seed)
    ann = world().sign_in(ANN)
    cursors = {}
    for route in (ITEMS, PARKED):
        cursors[route] = ann.get(f"{API}/tenants/{T1}/{route}", params={"limit": 1}).json()["next_cursor"]
        assert cursors[route], route
        assert ann.get(f"{API}/tenants/{T1}/{route}", params={"limit": 1, "cursor": cursors[route]}).status_code == 200, route
    assert ann.get(f"{API}/tenants/{T1}/{PARKED}", params={"cursor": cursors[ITEMS]}).status_code == 422
    assert ann.get(f"{API}/tenants/{T1}/{ITEMS}", params={"cursor": cursors[PARKED]}).status_code == 422


# --- O2 ------------------------------------------------------------------------------------------------------------

#: Kind-then-key order differs from key-only order (A < B < Z < a < b in codepoints).
AUTHOR_ITEMS = [("finding", "b"), ("finding", "B"), ("finding", "a"), (QUESTIONER, "Z"), (QUESTIONER, "A")]


async def _parked_three(store: Any, tenant: str) -> tuple[Any, Any, Any, Any]:
    held = await held_together(store, tenant, [("finding", "h1")])
    author = await parked_author(store, tenant, AUTHOR_ITEMS)
    revert = await parked_revert(store, tenant)
    registry = await parked_registry(store, tenant)
    return held, author, revert, registry


def test_o2_parked_batches_list_newest_first_with_blocks_lane_items_and_every_field_as_stored(dsn, world):
    """A parked author, revert and registry batch list newest created first, each field as the store holds it; the author
    and the registry batch block their lane and the revert does not; the registry holds no items; the author's items
    are kind then key; no parked batch's item is in `items`. (O2, P1)"""
    _held, author, revert, registry = on_store(dsn, _parked_three, T1)
    views = stored_batches(dsn, T1, "needs_person")
    assert {str(v.id) for v in views} == {str(author), str(revert), str(registry)}, "premise: exactly these are parked"
    expected = newest_first(views, lambda b: b.created_at, lambda b: b.id)
    records = {str(v.id): v for v in call(dsn, "parked", T1, limit=50)}
    assert records[str(author)].items == tuple(sorted(AUTHOR_ITEMS)), "premise: the store record is kind then key, codepoint order"
    assert sorted(AUTHOR_ITEMS) != sorted(AUTHOR_ITEMS, key=lambda i: i[1]), "premise: kind-then-key differs from key order"

    ann = world().sign_in(ANN)
    r = ann.get(f"{API}/tenants/{T1}/{PARKED}")
    assert r.status_code == 200, r.text
    got = r.json()["items"]
    assert [b["batch_id"] for b in got] == [str(v.id) for v in expected]
    for wire, view in zip(got, expected, strict=True):
        assert set(wire) == BATCH_FIELDS
        assert (wire["batch_kind"], wire["lane"], wire["branch"], wire["pr_number"], wire["reason"]) == (
            view.kind, view.lane, view.branch, view.pr_number, view.reason)
        assert instant(wire["created_at"]) == view.created_at
        stored = batch_row(dsn, wire["batch_id"])  # #1537 O4, O5: cause, parked_at, request as stored; releasable by the design's rule
        assert stored["cause"] is not None, "premise: a parked batch has a cause"
        assert wire["cause"] == stored["cause"]
        assert (instant(wire["parked_at"]) if wire["parked_at"] else None) == stored["parked_at"]
        assert wire["abandon_requested_at"] is None
        assert wire["releasable"] is (stored["cause"] == "forge_credential_refused")
        assert wire["items"] == [{"kind": k, "key": key} for k, key in records[wire["batch_id"]].items]
        assert all(set(i) == {"kind", "key"} for i in wire["items"])
    by_id = {b["batch_id"]: b for b in got}
    assert [(by_id[str(x)]["batch_kind"], by_id[str(x)]["blocks_lane"]) for x in (author, revert, registry)] == [
        ("author", True), ("revert", False), ("registry", True)]
    assert by_id[str(registry)]["items"] == [], "a parked registry batch holds no items yet blocks the feedback lane"
    assert [(i["kind"], i["key"]) for i in by_id[str(author)]["items"]] == sorted(AUTHOR_ITEMS)
    assert by_id[str(author)]['pr_number'] == 9
    assert by_id[str(revert)]['pr_number'] is None
    assert [i["key"] for i in ann.get(f"{API}/tenants/{T1}/{ITEMS}").json()["items"]] == ["h1"], \
        "the parked batch's items are in_batch, not held (control: the held one lists)"


def test_o2_a_batch_in_review_is_not_listed(dsn, world):
    """Only phase `needs_person` lists: a batch in review is absent, a parked one beside it is present (control). (O2)"""
    async def seed(store: Any) -> Any:
        await in_review_author(store, T1, "f1")
        return await parked_revert(store, T1)
    revert = on_store(dsn, seed)
    assert len(stored_batches(dsn, T1, "in_review")) == 1, "premise"
    assert [b["batch_id"] for b in world().sign_in(ANN).get(f"{API}/tenants/{T1}/{PARKED}").json()["items"]] == [str(revert)]


async def _five_reverts(store: Any, tenant: str) -> list[Any]:
    return [await parked_revert(store, tenant, f"reason {n}") for n in range(5)]


@pytest.mark.parametrize("limit", [2, 1])
def test_o2_parked_batches_tied_on_creation_page_in_id_order_each_once(dsn, world, limit):
    """Five parked batches, three created at one instant between an older and a newer one, paged `limit` at a time:
    (created_at, id) descending, each once, every page full but the last. (O2, Paging)"""
    ids = on_store(dsn, _five_reverts, T1)
    tie_batches(dsn, ids[1:4])
    tie_batches(dsn, ids[:1], INSTANT.replace(hour=1))
    tie_batches(dsn, ids[4:], INSTANT.replace(hour=23))
    views = stored_batches(dsn, T1, "needs_person")
    assert len({v.created_at for v in views}) == 3, "premise: three instants, three of them one"
    expected = newest_first(views, lambda b: b.created_at, lambda b: b.id)

    got, sizes, cursors = walk(world().sign_in(ANN), f"{API}/tenants/{T1}/{PARKED}", limit=limit)

    assert [b["batch_id"] for b in got] == [str(v.id) for v in expected]
    assert sizes[:-1] == [limit] * (len(sizes) - 1)
    assert 0 < sizes[-1] <= limit
    after_tied = _cursors_after(got, cursors, limit, lambda b: b["created_at"] == got[1]["created_at"])
    assert len(after_tied) >= 2, "premise: more than one cursor follows a batch of the tied instant"
    assert len({len(c) for c in after_tied}) == 1, "a cursor grew with a batch's text"


# --- O3 ------------------------------------------------------------------------------------------------------------

async def _one_each(store: Any, tenant: str, key: str) -> Any:
    """One held item `key` and one parked revert batch of `tenant`; the batch id."""
    await held_together(store, tenant, [("finding", key)])
    return await parked_revert(store, tenant)


def test_o3_anonymous_is_401_another_tenants_member_404_and_each_tenant_sees_only_its_own_rows(dsn, world):
    """No sign-in is 401 and tenant B's member asking for tenant A is 404, on both routes; each member lists only its own
    tenant's items and batches (control: both lists non-empty). (O3, P3)"""
    a_batch = on_store(dsn, _one_each, T1, "a-only")
    b_batch = on_store(dsn, _one_each, T2, "b-only")
    w = world()
    ann, bob = w.sign_in(ANN), w.sign_in(BOB)
    for route in (ITEMS, PARKED):
        assert w.client().get(f"{API}/tenants/{T1}/{route}").status_code == 401, route
        assert bob.get(f"{API}/tenants/{T1}/{route}").status_code == 404, route
        assert ann.get(f"{API}/tenants/{T2}/{route}").status_code == 404, route
    assert [i["key"] for i in ann.get(f"{API}/tenants/{T1}/{ITEMS}").json()["items"]] == ["a-only"]
    assert [i["key"] for i in bob.get(f"{API}/tenants/{T2}/{ITEMS}").json()["items"]] == ["b-only"]
    assert [b["batch_id"] for b in ann.get(f"{API}/tenants/{T1}/{PARKED}").json()["items"]] == [str(a_batch)]
    assert [b["batch_id"] for b in bob.get(f"{API}/tenants/{T2}/{PARKED}").json()["items"]] == [str(b_batch)]
