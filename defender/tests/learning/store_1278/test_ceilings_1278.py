"""#1278 every counter the store keeps has a ceiling, and the design names what happens there.

One generated case per counter and way of counting it: drive it one unit at a time with the ceiling at 2, 3 and 4,
and read the fate after each unit. Below the ceiling nothing happens; at it the item or batch takes the design's fate
(attempts: held for a person; deferrals and declined offers: dead; refusals: needs_person; generation: the feedback's
items held, no replacement). A new counter column with no driver here fails the census.
"""
from __future__ import annotations

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE, ONE, finding, lapse_lease, learning_store, store_mod)
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

TENANT = fixture_uuid("tenant:1278-ceilings")
ITEM = ("finding", "f1")


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, TENANT)
    return migrated_database


async def _claim(store):
    held = await store.claim(TENANT, AUTHOR_LANE, owner="host-a", thresholds=ONE)
    assert held is not None, "the item was not claimable"
    return held


async def _item(store):
    return {(i.kind, i.key): i for i in await store.work(TENANT)}[ITEM]


async def _batch(store, batch_id):
    return {b.id: b for b in await store.batches(TENANT)}[batch_id]


def _outcome(name):
    return getattr(store_mod().Outcome, name)()


# --- one driver per way of reaching a ceiling: each returns the label read after every unit ---------------------------


async def _attempts_unreported(store, dsn, ceiling):
    """Claims whose batch ends with nothing committed and the item named no outcome: back to waiting, the attempt kept."""
    fates = []
    for _ in range(ceiling):
        await store.end_no_commits(await _claim(store), {})
        fates.append((await _item(store)).status)
    return fates


async def _attempts_reported_waiting(store, dsn, ceiling):
    fates = []
    for _ in range(ceiling):
        await store.end_no_commits(await _claim(store), {ITEM: _outcome("waiting")})
        fates.append((await _item(store)).status)
    return fates


async def _attempts_in_review(store, dsn, ceiling):
    """The batch reaches review with the item reported as waiting."""
    fates = []
    for n in range(ceiling):
        held = await _claim(store)
        await store.in_review(held, 7 + n, {ITEM: _outcome("waiting")})
        fates.append((await _item(store)).status)
        if n + 1 < ceiling:
            await store.abandon(TENANT, held.batch_id, by="person")  # the batch leaves review; the item is already waiting
    return fates


async def _attempts_recovered(store, dsn, ceiling):
    """The holder crashed: a recovery abandon returns the item with the attempt counted."""
    fates = []
    for _ in range(ceiling):
        held = await _claim(store)
        lapse_lease(dsn, held.batch_id)
        await store.abandon(TENANT, held.batch_id, by="recovery")
        fates.append((await _item(store)).status)
    return fates


async def _attempts_crashed_alone(store, dsn, ceiling):
    fates = []
    for _ in range(ceiling):
        await store.abandon_crashed(await _claim(store))
        fates.append((await _item(store)).status)
    return fates


async def _deferrals(store, dsn, ceiling):
    fates = []
    for _ in range(ceiling):
        await store.end_no_commits(await _claim(store), {ITEM: _outcome("deferred")})
        fates.append((await _item(store)).status)
    return fates


async def _offers_declined(store, dsn, ceiling):
    fates = []
    for _ in range(ceiling):
        await store.end_no_commits(await _claim(store), {ITEM: _outcome("declined")})
        fates.append((await _item(store)).status)
    return fates


async def _refusals(store, dsn, ceiling):
    held = await _claim(store)
    await store.in_review(held, 7, {})
    fates = []
    for _ in range(ceiling):
        await store.note_refusal(TENANT, held.batch_id, "the forge said no")
        fates.append((await _batch(store, held.batch_id)).phase)
    return fates


async def _generation(store, dsn, ceiling):
    """The batch of generation g closes with feedback: a replacement while g is below the ceiling, the items held at it."""
    held = await _claim(store)
    await store.in_review(held, 7, {})
    fates = []
    for generation in range(ceiling + 1):
        assert (await _batch(store, held.batch_id)).generation == generation
        assert await store.end_review(TENANT, held.batch_id, expect_phase="in_review", outcome="closed",
                                      published=[], held=[])
        replacement = await store.claim(TENANT, AUTHOR_LANE, owner="host-a", thresholds=ONE)
        if replacement is None:
            fates.append(f"items {(await _item(store)).status}")
            break
        fates.append("replaced")
        held = replacement
        await store.in_review(held, 8 + generation, {})
    return fates


def _held_at(ceiling, below="waiting", at="held"):
    return [below] * (ceiling - 1) + [at]


#: counter -> (the way it is counted, the driver, the fates it must show for a ceiling c).
DRIVERS = {
    ("attempts", "a batch ended with no commits, the item unreported"): (
        _attempts_unreported, lambda c: _held_at(c)),
    ("attempts", "a batch ended with no commits, the item reported waiting"): (
        _attempts_reported_waiting, lambda c: _held_at(c)),
    ("attempts", "a batch in review, the item reported waiting"): (
        _attempts_in_review, lambda c: _held_at(c)),
    ("attempts", "a recovery abandon of a lapsed batch"): (_attempts_recovered, lambda c: _held_at(c)),
    ("attempts", "the holder's own crash"): (_attempts_crashed_alone, lambda c: _held_at(c)),
    ("deferrals", "a deferred item"): (_deferrals, lambda c: _held_at(c, at="dead")),
    ("offers_declined", "a declined offer"): (_offers_declined, lambda c: _held_at(c, at="dead")),
    ("refusals", "a forge refusal of a batch in review"): (
        _refusals, lambda c: _held_at(c, below="in_review", at="needs_person")),
    ("generation", "a replacement closed with feedback"): (
        _generation, lambda c: ["replaced"] * c + ["items held"]),
}


@pytest.mark.parametrize("ceiling", [2, 3, 4])
@pytest.mark.parametrize("counter", list(DRIVERS), ids=[f"{c}:{way}" for c, way in DRIVERS])
async def test_each_counter_does_nothing_below_its_ceiling_and_takes_the_designs_fate_at_it(dsn, counter, ceiling):
    """After ceiling-1 units the item or batch carries on; at the ceiling it is held, dead, handed to a person or its feedback held. (D8, H15)"""
    drive, fates = DRIVERS[counter]
    knobs = {"max_attempts": ceiling, "refusal_ceiling": ceiling, "generation_ceiling": ceiling}
    async with learning_store(dsn, **knobs) as store:
        await store.publish_findings(TENANT, "run-1", [finding("f1")], kind="finding")
        assert await drive(store, dsn, ceiling) == fates(ceiling)


@pytest.mark.parametrize("ceiling", [2, 3])
async def test_an_item_held_at_its_attempt_ceiling_is_claimed_by_no_one(dsn, ceiling):
    """Control: a held item is out of the queue until a person releases it, then it is claimed again. (D8, O7)"""
    async with learning_store(dsn, max_attempts=ceiling) as store:
        await store.publish_findings(TENANT, "run-1", [finding("f1")], kind="finding")
        for _ in range(ceiling):
            await store.end_no_commits(await _claim(store), {})
        assert (await _item(store)).status == "held"
        assert await store.claim(TENANT, AUTHOR_LANE, owner="host-a", thresholds=ONE) is None
        await store.release_held(TENANT, *ITEM)
        assert await store.claim(TENANT, AUTHOR_LANE, owner="host-a", thresholds=ONE) is not None


#: Integer columns that are not ceilinged counters.
NOT_COUNTERS = {("batches", "fencing_token"), ("batches", "pr_number"), ("commit_changes", "ordinal"),
                # The feedback tables (A4): forge ids and a lease token, not counts.
                ("feedback_comments", "comment_id"), ("feedback_issues", "issue_number"), ("feedback_tick", "fencing_token")}
#: A counter whose ceiling is not a store fate: the store only counts a comment's failed answers (`count_failed_answer`,
#: test_feedback_1278.py::test_p8_failed_answers_are_counted_one_by_one_per_comment); the feedback tick applies the ceiling
#: (tests/learning/feedback_1414/test_1414_feedback_tick.py), and no row changes state here.
COUNTED_FOR_THE_TICK = {("feedback_comments", "attempts")}
COUNTER_COLUMNS = {("work_items", "attempts"), ("work_items", "deferrals"), ("work_items", "offers_declined"),
                   ("batches", "refusals"), ("batches", "generation")}


def test_every_integer_column_of_the_schema_is_a_driven_counter_or_named_as_none(dsn):
    """A new counter column fails here until it has a driver above and its ceiling's fate. (census of the schema)"""
    columns = {(table, column) for table, column in execute(
        dsn, "SELECT table_name, column_name FROM information_schema.columns "
             "WHERE table_schema = 'learning' AND data_type IN ('integer', 'bigint', 'smallint')")}
    assert columns == COUNTER_COLUMNS | NOT_COUNTERS | COUNTED_FOR_THE_TICK
    assert {counter for counter, _way in DRIVERS} == {column for _table, column in COUNTER_COLUMNS}
