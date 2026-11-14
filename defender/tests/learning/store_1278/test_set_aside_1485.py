"""#1485 O1: the learning store's `set_aside` read (held and dead items) on a real PostgreSQL. Every row is made by the
store's own verbs and `work()` is the oracle for each field, so no stored value is spelled here twice.
"""
from __future__ import annotations

import pytest

from defender.jobs.learning_models import STATUSES
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._set_aside1485 import (
    HOSTILE_REASON,
    dead_without_pr,
    held_by_close,
    open_work,
    page_through,
    settled_in_one_review,
)
from defender.tests.support.learning.core._store1278 import learning_store, store_mod
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1485-blue")
GREEN = fixture_uuid("tenant:1485-green")

#: Keys of the first test's world, newest change first: one batch closed with three items held (same transaction, so
#: kind then key descending breaks the tie), then the batch that settled `hh` and `dd`, then the oldest.
WORLD_ORDER = [("questioner_finding", "q1"), ("finding", "h2"), ("finding", "h1"), ("finding", "hh"), ("finding", "dd"),
               ("finding", "d1")]
TWELVE = ["run 1/f 01", "run 1/f 02", "run 1/f 10", "run 2/f 01", "a b", "a/b", "a-b", "a_b", "A b", "z", "Z/z", "é/1"]
#: TWELVE by kind then key, descending, in codepoint order.
TWELVE_DESC = ["é/1", "z", "run 2/f 01", "run 1/f 10", "run 1/f 02", "run 1/f 01", "a_b", "a/b", "a-b", "a b", "Z/z", "A b"]


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


async def _world(store, tenant):
    """Oldest first: `d1` dead with no PR; `dd` dead and `hh` held in PR 5 (beside published `p1`, skipped `s1`);
    `h1`, `h2`, `q1` held by one close of PR 7 with a hostile reason; then `b1` in a working batch and `w1` waiting."""
    d1 = await dead_without_pr(store, tenant, "d1")
    mixed = await settled_in_one_review(store, tenant)
    closed = await held_by_close(store, tenant, [("finding", "h1"), ("finding", "h2"), ("questioner_finding", "q1")],
                                 reason=HOSTILE_REASON)
    await open_work(store, tenant)
    return {"d1": d1, "mixed": mixed, "closed": closed}


async def test_o1_set_aside_lists_held_and_dead_items_as_the_stores_own_records_newest_change_first(dsn):
    """`set_aside` returns each held or dead item exactly as `work()` records it, ordered (updated_at, kind, key)
    descending, with its batch and that batch's PR (O1)."""
    async with learning_store(dsn) as store:
        batches = await _world(store, BLUE)
        work = {(i.kind, i.key): i for i in await store.work(BLUE)}
        assert {i.status for i in work.values()} == set(STATUSES), "premise: every status is stored"
        got = await store.set_aside(BLUE, limit=50)

    assert [(i.kind, i.key) for i in got] == WORLD_ORDER
    assert got == [work[k] for k in WORLD_ORDER], "each item is the store's own record of it"
    assert all(isinstance(i, store_mod().WorkItem) for i in got)
    assert [(i.status, i.batch_id, i.pr_number) for i in got] == [
        ("held", batches["closed"], 7), ("held", batches["closed"], 7), ("held", batches["closed"], 7),
        ("held", batches["mixed"], 5), ("dead", batches["mixed"], 5), ("dead", batches["d1"], None)]
    assert len({(i.updated_at) for i in got[:3]}) == 1, "control: the three tied items changed in one transaction"
    assert got[0].updated_at > got[3].updated_at > got[5].updated_at


async def test_o1_only_held_and_dead_items_are_listed_and_the_status_filter_narrows(dsn):
    """Waiting, in-batch, published and skipped items never appear; `status` narrows to held or dead. (O1)"""
    async with learning_store(dsn) as store:
        await _world(store, BLUE)
        every = {(i.kind, i.key): i.status for i in await store.work(BLUE)}
        assert [every[("finding", k)] for k in ("w1", "b1", "p1", "s1")] == ["waiting", "in_batch", "published", "skipped"]
        both = await store.set_aside(BLUE, status=None, limit=50)
        held = await store.set_aside(BLUE, status="held", limit=50)
        dead = await store.set_aside(BLUE, status="dead", limit=50)

    assert {i.key for i in both}.isdisjoint({"w1", "b1", "p1", "s1"})
    assert [i.key for i in held] == ["q1", "h2", "h1", "hh"]
    assert [i.key for i in dead] == ["dd", "d1"]


@pytest.mark.parametrize("status", [*(s for s in STATUSES if s not in {"held", "dead"}), "HELD", "", "held,dead"])
async def test_o1_any_other_status_is_a_value_error(dsn, status):
    """A status other than held, dead or None raises `ValueError` and reads nothing. (O1)"""
    async with learning_store(dsn) as store:
        assert await store.set_aside(BLUE, status="held", limit=5) == [], "control: a valid status is answered"
        with pytest.raises(ValueError):  # noqa: PT011 — the design names the type, not a text
            await store.set_aside(BLUE, status=status, limit=5)


async def test_o1_a_hostile_reason_comes_back_byte_for_byte(dsn):
    """A held reason with markup and quotes is the same text the store holds. (O1, P2)"""
    async with learning_store(dsn) as store:
        await held_by_close(store, BLUE, [("finding", "h1")], reason=HOSTILE_REASON)
        [got] = await store.set_aside(BLUE, limit=5)
        [stored] = await store.work(BLUE)
    assert got.reason == HOSTILE_REASON == stored.reason


async def test_o1_twelve_items_held_in_one_transaction_page_three_at_a_time_each_once_in_codepoint_order(dsn):
    """Twelve findings held by one close share one `updated_at`; paging three at a time returns each once, key
    descending in codepoint order. (O1, Paging)"""
    async with learning_store(dsn) as store:
        await held_by_close(store, BLUE, [("finding", k) for k in TWELVE])
        assert len({i.updated_at for i in await store.work(BLUE)}) == 1, "control: one transaction, one timestamp"
        got = await page_through(store, BLUE, limit=3)
    assert [i.key for i in got] == TWELVE_DESC


@pytest.mark.parametrize("limit", [1, 2, 4, 5, 6, 50])
async def test_o1_every_page_size_returns_the_same_items_in_the_same_order(dsn, limit):
    """Paging the mixed world at any `limit` returns the unpaged list, no page longer than `limit`. (O1)"""
    async with learning_store(dsn) as store:
        await _world(store, BLUE)
        whole = await store.set_aside(BLUE, limit=50)
        assert len(await store.set_aside(BLUE, limit=2)) == 2
        got = await page_through(store, BLUE, limit=limit)
    assert got == whole
    assert len(whole) == len(WORLD_ORDER)


async def test_control_this_databases_default_collation_orders_ab_and_a_dash_c_unlike_codepoints(dsn):
    """Positive control for the next case: here the default collation and codepoint order disagree on `ab` vs
    `a-c`, so a read that sorted by the default would fail it. (O1, Paging)"""
    [(default_desc,)] = execute(dsn, "SELECT array_agg(k ORDER BY k DESC) FROM (VALUES ('ab'), ('a-c')) v(k)")
    [(codepoint_desc,)] = execute(dsn, """SELECT array_agg(k ORDER BY k COLLATE "C" DESC) FROM (VALUES ('ab'), ('a-c')) v(k)""")
    assert codepoint_desc == ["ab", "a-c"]
    assert default_desc == ["a-c", "ab"], "this database's default collation agrees with codepoints: the next case is vacuous"


async def test_o1_keys_ab_and_a_dash_c_page_in_codepoint_order_without_a_skip_or_repeat(dsn):
    """Tied `ab` and `a-c` page one at a time, `ab` first, each once; `after` `ab` yields `a-c`, `after` `a-c`
    nothing. (O1, Paging)"""
    async with learning_store(dsn) as store:
        await held_by_close(store, BLUE, [("finding", "ab"), ("finding", "a-c")])
        [first, second] = await store.set_aside(BLUE, limit=5)
        paged = await page_through(store, BLUE, limit=1)
        after_ab = await store.set_aside(BLUE, after=(first.updated_at, "finding", "ab"), limit=5)
        after_dash = await store.set_aside(BLUE, after=(first.updated_at, "finding", "a-c"), limit=5)
    assert [i.key for i in (first, second)] == ["ab", "a-c"]
    assert [i.key for i in paged] == ["ab", "a-c"]
    assert [i.key for i in after_ab] == ["a-c"]
    assert after_dash == []


async def test_o1_after_is_strictly_after_the_whole_position_not_its_time(dsn):
    """`after` skips the position it names and everything newer or tied-and-greater, and nothing else: a smaller key
    of the same instant stays, an older item stays. (O1)"""
    async with learning_store(dsn) as store:
        await _world(store, BLUE)
        got = await store.set_aside(BLUE, limit=50)
        tied = got[0].updated_at
        everything_after_the_ties = await store.set_aside(BLUE, after=(tied, "finding", ""), limit=50)
        middle = await store.set_aside(BLUE, after=(tied, "finding", "h2"), limit=50)
        the_last = await store.set_aside(BLUE, after=(got[-1].updated_at, got[-1].kind, got[-1].key), limit=50)
        newer_than_all = await store.set_aside(BLUE, after=(got[0].updated_at.replace(year=9000), "", ""), limit=50)
    assert [(i.kind, i.key) for i in everything_after_the_ties] == WORLD_ORDER[3:]
    assert [(i.kind, i.key) for i in middle] == [("finding", "h1"), *WORLD_ORDER[3:]]
    assert the_last == []
    assert [(i.kind, i.key) for i in newer_than_all] == WORLD_ORDER


async def test_o1_a_tenant_reads_only_its_own_set_aside_items(dsn):
    """GREEN's held and dead items, under the same keys, never reach BLUE, and GREEN reads its own. (O1, P3)"""
    async with learning_store(dsn) as store:
        blue = await held_by_close(store, BLUE, [("finding", "h1")])
        await held_by_close(store, GREEN, [("finding", "g-only")], reason="GREEN's reason")
        await _world(store, GREEN)
        mine = await store.set_aside(BLUE, limit=50)
        theirs = await store.set_aside(GREEN, limit=50)
        mine_dead = await store.set_aside(BLUE, status="dead", limit=50)
        blue_work = await store.work(BLUE)
    assert [(i.key, i.batch_id) for i in mine] == [("h1", blue)]
    assert mine == blue_work
    assert mine_dead == []
    assert {i.key for i in theirs} >= {"h1", "g-only", "d1"}
