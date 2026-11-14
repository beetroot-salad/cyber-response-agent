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
    incompressible_key,
    newest_first,
    open_work,
    page_through,
    settled_in_one_review,
)
from defender.tests.support.learning.core._store1278 import claim, learning_store, publish, store_mod
from defender.tests.support.shared._fixture_uuid import fixture_uuid

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1485-blue")
GREEN = fixture_uuid("tenant:1485-green")

#: The first test's world by change group, newest first: one batch closed with three items held (same transaction, so
#: they tie and the id orders them), then `hh`, then `dd` (settled by an earlier batch), then the oldest.
WORLD_GROUPS = [{("finding", "h1"), ("finding", "h2"), ("questioner_finding", "q1")}, {("finding", "hh")},
                {("finding", "dd")}, {("finding", "d1")}]
TWELVE = ["run 1/f 01", "run 1/f 02", "run 1/f 10", "run 2/f 01", "a b", "a/b", "a-b", "a_b", "A b", "z", "Z/z", "é/1"]


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
    """`set_aside` returns each held or dead item exactly as `work()` records it, ordered (updated_at, id)
    descending, with its batch and that batch's PR (O1, D12)."""
    async with learning_store(dsn) as store:
        batches = await _world(store, BLUE)
        work = {(i.kind, i.key): i for i in await store.work(BLUE)}
        assert {i.status for i in work.values()} == set(STATUSES), "premise: every status is stored"
        got = await store.set_aside(BLUE, limit=50)

    assert got == newest_first([i for i in work.values() if i.status in {"held", "dead"}])
    assert [{(i.kind, i.key) for i in got[a:b]} for a, b in [(0, 3), (3, 4), (4, 5), (5, 6)]] == WORLD_GROUPS
    assert all(isinstance(i, store_mod().WorkItem) for i in got)
    assert [(i.status, i.batch_id, i.pr_number) for i in got] == [
        ("held", batches["closed"], 7), ("held", batches["closed"], 7), ("held", batches["closed"], 7),
        ("held", batches["mixed"], 5), ("dead", batches["mixed"], 5), ("dead", batches["d1"], None)]
    assert len({(i.updated_at) for i in got[:3]}) == 1, "control: the three tied items changed in one transaction"
    assert got[0].updated_at > got[3].updated_at > got[5].updated_at


async def test_o1_every_item_has_an_id_of_its_own_and_set_aside_and_work_agree_on_it(dsn):
    """`WorkItem.id` is a `WorkItemId`, distinct per item including waiting ones, and `set_aside` returns the
    same id `work()` does for each item. (D12)"""
    from defender.records.formats import WorkItemId

    async with learning_store(dsn) as store:
        await _world(store, BLUE)
        work = await store.work(BLUE)
        got = await store.set_aside(BLUE, limit=50)
    assert len(work) == 10, "premise: set-aside and other items alike"
    assert all(type(i.id) is WorkItemId for i in work)
    assert len({i.id for i in work}) == len(work)
    assert {(i.kind, i.key): i.id for i in got} == {(i.kind, i.key): i.id for i in work if i.status in {"held", "dead"}}


async def test_o1_only_held_and_dead_items_are_listed_and_the_status_filter_narrows(dsn):
    """Waiting, in-batch, published and skipped items never appear; `status` narrows to held or dead. (O1)"""
    async with learning_store(dsn) as store:
        await _world(store, BLUE)
        work = await store.work(BLUE)
        every = {(i.kind, i.key): i.status for i in work}
        assert [every[("finding", k)] for k in ("w1", "b1", "p1", "s1")] == ["waiting", "in_batch", "published", "skipped"]
        both = await store.set_aside(BLUE, status=None, limit=50)
        held = await store.set_aside(BLUE, status="held", limit=50)
        dead = await store.set_aside(BLUE, status="dead", limit=50)

    assert {i.key for i in both}.isdisjoint({"w1", "b1", "p1", "s1"})
    assert held == newest_first([i for i in work if i.status == "held"])
    assert [i.key for i in held][3:] == ["hh"]
    assert {i.key for i in held[:3]} == {"q1", "h2", "h1"}
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


async def test_o1_twelve_items_held_in_one_transaction_page_three_at_a_time_each_once_in_updated_at_id_order(dsn):
    """Twelve findings held by one close share one `updated_at`; paging three at a time returns each once, in
    (updated_at, id) descending order. (O1, Paging, D12)"""
    async with learning_store(dsn) as store:
        await held_by_close(store, BLUE, [("finding", k) for k in TWELVE])
        work = await store.work(BLUE)
        assert len({i.updated_at for i in work}) == 1, "control: one transaction, one timestamp"
        assert len({i.id for i in work}) == 12, "control: twelve distinct ids"
        got = await page_through(store, BLUE, limit=3)
    assert got == newest_first(work)
    assert sorted(i.key for i in got) == sorted(TWELVE)


async def test_o1_a_finding_with_a_kilobyte_key_is_published_held_and_listed(dsn):
    """A finding whose key is ~1 KB (incompressible) is stored, held, listed by `set_aside` and paged past, as a
    short-keyed one beside it is. (O1, Scenarios)"""
    key = incompressible_key(1024)
    assert len(key.encode()) >= 1000, "premise: well past the old 200-byte bound"
    async with learning_store(dsn) as store:
        await held_by_close(store, BLUE, [("finding", key), ("finding", "short")])
        got = await store.set_aside(BLUE, limit=50)
        paged = await page_through(store, BLUE, limit=1)
    assert sorted(i.key for i in got) == sorted([key, "short"])
    assert paged == got


async def test_o1_an_items_id_survives_a_republish_conflict_and_hold_release_hold(dsn):
    """Republishing a held item's key adds nothing and keeps its id; releasing it and holding it again keeps the
    same id. (D12)"""
    async with learning_store(dsn) as store:
        await held_by_close(store, BLUE, [("finding", "h1")])
        [first] = await store.set_aside(BLUE, limit=5)
        await publish(store, BLUE, "h1")
        [after_conflict] = await store.set_aside(BLUE, limit=5)
        assert [i.id for i in await store.work(BLUE)] == [first.id], "control: the conflict added no second item"

        await store.release_held(BLUE, "finding", "h1")
        assert await store.set_aside(BLUE, limit=5) == [], "control: released, it is no longer set aside"
        again = await claim(store, BLUE)
        await store.in_review(again, 8, {})
        assert await store.end_review(BLUE, again.batch_id, expect_phase="in_review", outcome="closed", published=[],
                                      held=[("finding", "h1")], reason="held again")
        held_again = next(i for i in await store.set_aside(BLUE, limit=5) if i.key == "h1")
    assert after_conflict.id == first.id
    assert held_again.id == first.id


@pytest.mark.parametrize("limit", [1, 2, 4, 5, 6, 50])
async def test_o1_every_page_size_returns_the_same_items_in_the_same_order(dsn, limit):
    """Paging the mixed world at any `limit` returns the unpaged list, no page longer than `limit`. (O1)"""
    async with learning_store(dsn) as store:
        await _world(store, BLUE)
        whole = await store.set_aside(BLUE, limit=50)
        assert len(await store.set_aside(BLUE, limit=2)) == 2
        got = await page_through(store, BLUE, limit=limit)
    assert got == whole
    assert len(whole) == sum(len(g) for g in WORLD_GROUPS)


async def test_o1_after_is_strictly_after_the_whole_position_not_its_time(dsn):
    """`after` an item's own (updated_at, id) skips it and everything newer or tied-and-greater, and nothing else: a
    tied item with a smaller id stays, an older item stays. (O1, D12)"""
    async with learning_store(dsn) as store:
        await _world(store, BLUE)
        got = await store.set_aside(BLUE, limit=50)
        assert len({i.updated_at for i in got[:3]}) == 1, "control: the first three are tied"
        after_the_ties = await store.set_aside(BLUE, after=(got[2].updated_at, got[2].id), limit=50)
        middle = await store.set_aside(BLUE, after=(got[1].updated_at, got[1].id), limit=50)
        the_last = await store.set_aside(BLUE, after=(got[-1].updated_at, got[-1].id), limit=50)
    assert after_the_ties == got[3:]
    assert middle == got[2:]
    assert the_last == []


async def test_o1_items_of_several_kinds_in_one_transaction_order_by_id_and_resume_from_every_position(dsn):
    """Findings and questioner findings held by one close share one `updated_at`; the list is the descending sort of
    (updated_at, id) whatever the kinds, and `after` each real item's position returns exactly the items sorted
    after it. (O1, Paging, D12)"""
    async with learning_store(dsn) as store:
        await dead_without_pr(store, BLUE, "old")
        await held_by_close(store, BLUE, [("finding", "z"), ("finding", "a"), ("finding", "é"), ("finding", "A-1"),
                                          ("questioner_finding", "a"), ("questioner_finding", "z"), ("questioner_finding", "B")])
        real = await store.set_aside(BLUE, limit=50)
        positions = [(i.updated_at, i.id) for i in real]
        expected = sorted(positions, reverse=True)
        assert len({p[0] for p in positions}) == 2, "control: the close's items tie, the dead one is older"
        assert {i.kind for i in real} == {"finding", "questioner_finding", }, "control: tied across kinds"
        resumed = [[(i.updated_at, i.id) for i in await store.set_aside(BLUE, after=p, limit=50)] for p in positions]
        paged = [(i.updated_at, i.id) for i in await page_through(store, BLUE, limit=2)]
    assert positions == expected
    assert paged == expected
    assert resumed == [expected[n + 1:] for n in range(len(expected))]


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
