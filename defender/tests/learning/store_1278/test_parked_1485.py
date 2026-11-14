"""#1485 O2: the learning store's `parked` read (batches in `needs_person`) on a real PostgreSQL. Batches are parked by
the store's own verbs (three refusals, `needs_person`); `batches()` is the oracle for each field.
"""
from __future__ import annotations

import dataclasses

import pytest

from defender.jobs.learning_models import AUTHORING_KINDS, STATUSES
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._set_aside1485 import held_by_close, page_parked, parked_set
from defender.tests.support.learning.core._store1278 import ONE, claim, learning_store, publish, store_mod
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1485-p-blue")
GREEN = fixture_uuid("tenant:1485-p-green")
VIEW_FIELDS = ["id", "kind", "lane", "blocks_lane", "branch", "pr_number", "reason", "created_at", "items"]
#: Created author, revert, lead, registry; so newest first is the reverse.
NEWEST_FIRST = ["registry", "lead", "revert", "author"]


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


async def test_o2_parked_view_is_a_frozen_record_of_exactly_these_fields(dsn):
    """`ParkedBatchView` is exported by the store, a frozen dataclass of the nine named fields. (O2, Names)"""
    S = store_mod()
    assert [f.name for f in dataclasses.fields(S.ParkedBatchView)] == VIEW_FIELDS
    async with learning_store(dsn) as store:
        await parked_set(store, BLUE)
        [first, *_] = await store.parked(BLUE, limit=1)
    assert isinstance(first, S.ParkedBatchView)
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.reason = "changed"  # type: ignore[misc]


async def test_o2_parked_lists_needs_person_batches_newest_created_first_with_the_stores_own_fields(dsn):
    """Four batches parked in another order list by creation, newest first, each with the fields `batches()` has. (O2)"""
    async with learning_store(dsn) as store:
        made = await parked_set(store, BLUE)
        views = {b.id: b for b in await store.batches(BLUE)}
        got = await store.parked(BLUE, limit=50)

    ids = made["ids"]
    assert [b.id for b in got] == [ids[name] for name in NEWEST_FIRST]
    for b in got:
        v = views[b.id]
        assert v.phase == "needs_person"
        assert (b.kind, b.lane, b.branch, b.pr_number, b.reason, b.created_at) == (
            v.kind, v.lane, v.branch, v.pr_number, v.reason, v.created_at)
    by = dict(zip(NEWEST_FIRST, got, strict=True))
    assert [(by[n].kind, by[n].pr_number) for n in NEWEST_FIRST] == [("registry", None), ("author", 8), ("revert", None), ("author", 7)]
    assert by["lead"].lane == "lead_author"
    assert by["registry"].lane == "feedback"
    assert by["revert"].reason == made["reasons"]["revert"]
    assert by["author"].reason is not None
    assert "403 Forbidden: <b>bad credentials</b>" in by["author"].reason, "the refusals' text, untouched"


async def test_o2_blocks_lane_is_true_for_authoring_kinds_and_false_for_a_revert(dsn):
    """A parked author and registry batch block their lane, a parked revert does not. (O2)"""
    async with learning_store(dsn) as store:
        made = await parked_set(store, BLUE)
        got = {b.id: b for b in await store.parked(BLUE, limit=50)}
    flags = {name: got[made["ids"][name]].blocks_lane for name in made["ids"]}
    assert flags == {"author": True, "lead": True, "revert": False, "registry": True}
    assert all(b.blocks_lane == (b.kind in AUTHORING_KINDS) for b in got.values())
    assert {b.kind for b in got.values()} == {"author", "revert", "registry"}, "control: every kind is parked"


async def test_o2_items_are_the_in_batch_items_sorted_by_kind_then_key_in_codepoint_order(dsn):
    """A parked batch lists its `in_batch` items as (kind, key) in codepoint order; a revert and a registry batch list
    none; other batches' items are not in it. (O2)"""
    keys = ["ab", "a-c", "B", "b"]
    async with learning_store(dsn) as store:
        await publish(store, BLUE, *keys)
        await publish(store, BLUE, "q1", kind="questioner_finding")
        author = await claim(store, BLUE)
        await store.in_review(author, 7, {})
        await store.needs_person(BLUE, author.batch_id, "by hand")
        await publish(store, BLUE, "later")
        [got] = await store.parked(BLUE, limit=5)
        waiting = await store.work(BLUE, statuses=["waiting"])
    assert got.id == author.batch_id
    assert got.items == (("finding", "B"), ("finding", "a-c"), ("finding", "ab"), ("finding", "b"), ("questioner_finding", "q1"))
    assert [i.key for i in waiting] == ["later"], "control: an item outside the batch exists and is not listed"


async def test_o2_a_parked_batch_shows_the_items_it_still_holds_and_a_registry_batch_none(dsn):
    """Items and an item-less registry batch come back together, the registry one with `items == ()`. (O2)"""
    async with learning_store(dsn) as store:
        made = await parked_set(store, BLUE)
        got = {b.id: b for b in await store.parked(BLUE, limit=50)}
    ids = made["ids"]
    assert got[ids["registry"]].items == ()
    assert got[ids["revert"]].items == ()
    assert got[ids["lead"]].items == (("pitfall", "p"),)
    assert got[ids["author"]].items == (("finding", "f1"), ("finding", "f2"), ("questioner_finding", "q1"))


async def test_o2_only_needs_person_batches_are_listed_and_parking_one_lists_it(dsn):
    """Ended (merged, closed, abandoned), working and in-review batches are not listed; each is listed once parked. (O2)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "m")
        merged = await claim(store, BLUE)
        await store.in_review(merged, 3, {})
        assert await store.end_review(BLUE, merged.batch_id, expect_phase="in_review", outcome="merged", published=[], held=[])
        await publish(store, BLUE, "a")
        abandoned = await claim(store, BLUE)
        await store.abandon(BLUE, abandoned.batch_id, by="person")
        closed = await held_by_close(store, BLUE, [("finding", "c")])
        await publish(store, BLUE, "p")
        in_review = await claim(store, BLUE)
        await store.in_review(in_review, 9, {})
        await store.add_pitfall(BLUE, {"schema_version": 1, "pitfall_id": "wk", "source_run": "r", "system": "elastic",
                                       "query_id": "elastic.esql", "goal": "g", "executed_query": "x",
                                       "stderr_digest": "exit=1; wk", "error_class": "agent-fixable"})
        working = await store.claim(BLUE, "lead_author", owner="host-a", thresholds=ONE)
        phases = {str(b.id): b.phase for b in await store.batches(BLUE)}
        assert sorted(phases.values()) == ["ended", "ended", "ended", "in_review", "working"], "premise: one of each phase"
        before = await store.parked(BLUE, limit=50)
        await store.needs_person(BLUE, in_review.batch_id, "parked")
        await store.needs_person(BLUE, working.batch_id, "parked")
        after = await store.parked(BLUE, limit=50)
    assert phases[str(closed)] == "ended"
    assert before == []
    assert {b.id for b in after} == {in_review.batch_id, working.batch_id}


async def test_o2_created_at_ties_break_by_id_descending(dsn):
    """Batches created in one instant list by id descending; `after` is strictly after (created_at, id). (O2)"""
    async with learning_store(dsn) as store:
        made = await parked_set(store, BLUE)
        execute(dsn, "UPDATE learning.batches SET created_at = '2026-01-01T00:00:00Z' WHERE tenant_id = %s", (BLUE,))
        got = await store.parked(BLUE, limit=50)
        ids = sorted((str(i) for i in made["ids"].values()), reverse=True)
        mid = got[1]
        after = await store.parked(BLUE, after=(mid.created_at, mid.id), limit=50)
        paged = await page_parked(store, BLUE, limit=1)
    assert [str(b.id) for b in got] == ids
    assert [str(b.id) for b in after] == ids[2:]
    assert [str(b.id) for b in paged] == ids


@pytest.mark.parametrize("limit", [1, 2, 3, 50])
async def test_o2_every_page_size_returns_the_same_batches_in_the_same_order(dsn, limit):
    """Paging at any `limit` returns the unpaged list in order, no page longer than `limit`. (O2)"""
    async with learning_store(dsn) as store:
        await parked_set(store, BLUE)
        whole = await store.parked(BLUE, limit=50)
        assert len(await store.parked(BLUE, limit=2)) == 2
        got = await page_parked(store, BLUE, limit=limit)
        resumed = [await store.parked(BLUE, after=(b.created_at, b.id), limit=50) for b in whole]
    assert got == whole
    assert len(whole) == 4
    assert [(b.created_at, str(b.id)) for b in whole] == sorted(((b.created_at, str(b.id)) for b in whole), reverse=True)
    assert resumed == [whole[n + 1:] for n in range(len(whole))], "`after` each real position returns what sorts after it"
    assert resumed[-1] == []


async def test_o2_a_tenant_reads_only_its_own_parked_batches(dsn):
    """GREEN's parked batches and their items never reach BLUE, which reads its own; GREEN reads its own. (O2, P3)"""
    async with learning_store(dsn) as store:
        mine = await parked_set(store, BLUE, tag="")
        theirs = await parked_set(store, GREEN, tag="-g")
        blue = await store.parked(BLUE, limit=50)
        green = await store.parked(GREEN, limit=50)
    assert {b.id for b in blue} == set(mine["ids"].values())
    assert {b.id for b in green} == set(theirs["ids"].values())
    assert not {key for b in blue for _k, key in b.items} & {"f1-g", "f2-g", "q1-g", "p-g"}
    assert {key for b in green for _k, key in b.items} == {"f1-g", "f2-g", "q1-g", "p-g"}


#: In the batch: `z` and `a` cross their kinds' order (a questioner finding `a` sorts before a finding `z`).
_IN_BATCH = [("finding", "z"), ("finding", "é"), ("finding", "A"), ("questioner_finding", "a"), ("questioner_finding", "B")]
_SET_ASIDE = {"held": ("finding", "h"), "dead": ("finding", "d"), "published": ("finding", "p"), "skipped": ("finding", "s"),
              "waiting": ("questioner_finding", "w")}


async def _batch_of_every_status(store, tenant):
    """One author batch parked while its items stand at every status that can keep its id (in_batch, held, dead,
    published, skipped) and one given back to waiting (which clears the id), by one review's outcomes, the rest still in the batch. Returns the batch id."""
    S = store_mod()
    for kind in ("finding", "questioner_finding"):
        await publish(store, tenant, *(k for kd, k in [*_IN_BATCH, *_SET_ASIDE.values()] if kd == kind), kind=kind)
    batch = await claim(store, tenant)
    taken = sorted((kind, key) for kind, key, _p in batch.items)
    assert taken == sorted([*_IN_BATCH, *_SET_ASIDE.values()]), "premise: the claim took every item"
    await store.in_review(batch, 7, {
        _SET_ASIDE["held"]: S.Outcome.held("a person must look"), _SET_ASIDE["dead"]: S.Outcome.dead("retired"),
        _SET_ASIDE["published"]: S.Outcome.published(), _SET_ASIDE["skipped"]: S.Outcome.skipped("not a lesson"),
        _SET_ASIDE["waiting"]: S.Outcome.waiting()})
    await store.needs_person(tenant, batch.batch_id, "by hand")
    return batch.batch_id


async def test_o2_a_parked_batch_lists_only_its_in_batch_items_whatever_other_statuses_carry_its_id_and_whoever_else_has_the_keys(dsn):
    """Items of the batch at every status that carries its id and another tenant's items under the same keys: only this tenant's `in_batch`
    items are listed, kind then key in Python's codepoint order. (O2, P3)"""
    async with learning_store(dsn) as store:
        mine = await _batch_of_every_status(store, BLUE)
        theirs = await _batch_of_every_status(store, GREEN)
        work = await store.work(BLUE)
        [got] = await store.parked(BLUE, limit=50)
        [other] = await store.parked(GREEN, limit=50)
    carried = {i.status for i in work if i.batch_id == mine}
    assert carried == set(STATUSES) - {"waiting"}, f"premise: the id stays on items at every status but waiting, not {sorted(carried)}"
    assert {i.status for i in work if (i.kind, i.key) == _SET_ASIDE["waiting"]} == {"waiting"}, "control: the given-back item waits"
    assert (got.id, other.id) == (mine, theirs)
    assert got.items == tuple(sorted(_IN_BATCH)) == other.items
