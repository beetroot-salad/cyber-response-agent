"""#1278 the learning store's own promises, driven through its verbs on a real PostgreSQL.

Batch identity (D5), claim scope and the claim's one transaction (P2', D8), one working batch per lane
(O3), the lease, its grace and the fencing token (P6), clean versus crash abandon and attempts (D8), a
person's exits (O7), replacement claims and generations (D8), reverts (Reverts), the commit record (D5),
the active-tenant condition and cancel (O6), the per-tenant view (O2).
"""
from __future__ import annotations

import contextlib
import uuid

import anyio
import pytest

from defender.tests.support.jobs._jobs1342 import move_tenant, register_tenant
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    FINDING,
    LEAD_LANE,
    ONE,
    QUESTIONER,
    changes_of,
    claim,
    lapse_lease,
    lease_seconds_left,
    learning_store,
    oid,
    publish,
    store_mod,
)
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1278-blue")
GREEN = fixture_uuid("tenant:1278-green")
#: A lease and grace far longer than any test, so only `lapse_lease` ends a lease and "within grace" is a fact.
KNOBS = {"lease": 600.0, "grace": 300.0}


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


async def _work(store, tenant):
    return {(i.kind, i.key): i for i in await store.work(tenant)}


async def _batch(store, tenant, batch_id):
    [one] = [b for b in await store.batches(tenant) if b.id == batch_id]
    return one


async def _in_review(store, tenant, *ids, pr=7):
    """An author batch holding `ids`, in review as PR `pr`."""
    await publish(store, tenant, *ids)
    held = await claim(store, tenant)
    await store.in_review(held, pr_number=pr, outcomes={})
    return held


# --- findings: unique for good (O14) -----------------------------------------------------------------------


async def test_flow1_a_finding_id_is_unique_for_good_past_its_claim_O14(dsn):
    """A republished finding id adds nothing, whether waiting or already claimed; a new id is queued. (O14, r8 work_items)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        await publish(store, BLUE, "f1")
        assert [(i.key, i.status) for i in await store.work(BLUE)] == [("f1", "waiting")]

        held = await claim(store, BLUE)
        await publish(store, BLUE, "f1", "f2")

        items = await _work(store, BLUE)
        assert sorted(items) == [(FINDING, "f1"), (FINDING, "f2")], items
        assert (items[FINDING, "f1"].status, items[FINDING, "f1"].batch_id) == ("in_batch", held.batch_id)
        assert items[FINDING, "f2"].status == "waiting", "control: a new id is still queued"


async def test_d5_the_same_key_in_two_kinds_is_two_items(dsn):
    """A finding and a questioner finding sharing an id are two items, each claimed, each given its own outcome. (r8 work_items key)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "x", kind=FINDING)
        await publish(store, BLUE, "x", kind=QUESTIONER)
        items = await _work(store, BLUE)
        assert sorted(items) == [(FINDING, "x"), (QUESTIONER, "x")], "the second kind's row was taken for a duplicate"

        held = await claim(store, BLUE)
        assert sorted((k, key) for k, key, _payload in held.items) == [(FINDING, "x"), (QUESTIONER, "x")]
        await store.in_review(held, pr_number=3, outcomes={(FINDING, "x"): S.Outcome.waiting()})

        items = await _work(store, BLUE)
        assert items[FINDING, "x"].status == "waiting", "the outcome of one kind moved the other"
        assert items[QUESTIONER, "x"].status == "in_batch"


# --- identity (D5) ------------------------------------------------------------------------------------------


async def test_d5_the_batch_id_is_a_uuid_and_the_branch_is_its_own_column_never_rederived(dsn):
    """The id parses as a uuid; the branch is set at claim, differs per batch, and a takeover returns the stored one. (D5, P2')"""
    async with learning_store(dsn, **KNOBS) as store:
        await publish(store, BLUE, "f1")
        first = await claim(store, BLUE)
        assert str(uuid.UUID(str(first.batch_id))) == str(first.batch_id)
        batch = await _batch(store, BLUE, first.batch_id)
        assert batch.branch == first.branch
        assert batch.branch
        assert batch.branch != str(batch.id)

        execute(dsn, "UPDATE learning.batches SET branch = %s WHERE id = %s", ("lessons/named-by-hand", first.batch_id))
        lapse_lease(dsn, first.batch_id)
        taken = await store.take_over(BLUE, first.batch_id, owner="host-b")
        assert taken.branch == "lessons/named-by-hand", "the takeover re-derived the branch from the id"
        assert (await _batch(store, BLUE, first.batch_id)).branch == "lessons/named-by-hand"

        await store.abandon_clean(taken)
        await publish(store, BLUE, "f2")
        second = await claim(store, BLUE)
        assert second.batch_id != first.batch_id
        assert second.branch != first.branch


async def test_d5_base_and_start_are_set_with_the_first_commit_row_and_every_row_carries_them(dsn):
    """No base before the first commit; the first record_commit sets base and start; each row carries branch, base, start, batch. (D5)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        held = await claim(store, BLUE)
        batch = await _batch(store, BLUE, held.batch_id)
        assert batch.base is None
        assert await store.commit_record(BLUE) == []

        await store.record_commit(held, oid(1), oid(10), "start-a", changes_of("agent/lessons/a.md"))
        assert (await _batch(store, BLUE, held.batch_id)).base == oid(10)
        await store.record_commit(held, oid(2), oid(10), "start-a", changes_of("agent/lessons/b.md"))

        rows = await store.commit_record(BLUE)
        assert [(r.commit, r.branch, r.base, r.start, str(r.batch_id)) for r in rows] == [
            (oid(1), held.branch, oid(10), "start-a", str(held.batch_id)),
            (oid(2), held.branch, oid(10), "start-a", str(held.batch_id))]
        assert [[change[0] for change in r.changes] for r in rows] == [["agent/lessons/a.md"], ["agent/lessons/b.md"]]


# --- claim: scope, one transaction, one working batch per lane ------------------------------------------------


async def test_p2_a_claim_inserts_its_batch_working_and_marks_its_items_in_it_with_their_payloads(dsn):
    """The claim alone leaves a working author batch holding the due items, each as (kind, key, payload). (P2', O3, D1)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1", "f2")
        held = await claim(store, BLUE)

        assert sorted((k, key) for k, key, _payload in held.items) == [(FINDING, "f1"), (FINDING, "f2")]
        assert all(payload["finding_id"] == key for _k, key, payload in held.items), "the payload is the published row"
        [batch] = await store.batches(BLUE)
        assert (batch.id, batch.lane, batch.kind, batch.phase) == (held.batch_id, AUTHOR_LANE, "author", "working")
        assert {k: (i.status, i.batch_id, i.attempts) for k, i in (await _work(store, BLUE)).items()} == {
            (FINDING, "f1"): ("in_batch", held.batch_id, 1), (FINDING, "f2"): ("in_batch", held.batch_id, 1)}, (
            "an attempt is stamped at claim")


async def test_d8_the_claim_takes_each_kind_at_or_over_its_own_threshold_and_nothing_below(dsn):
    """A kind under its threshold stays waiting and starts no batch; the kind at its threshold is claimed alone; both once due. (D8)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        assert await claim(store, BLUE, thresholds={**ONE, FINDING: 2, QUESTIONER: 2}) is None
        assert await store.batches(BLUE) == [], "nothing due and a batch was inserted"

        await publish(store, BLUE, "q1", kind=QUESTIONER)
        held = await claim(store, BLUE, thresholds={**ONE, FINDING: 2})
        assert [(k, key) for k, key, _p in held.items] == [(QUESTIONER, "q1")]
        assert (await _work(store, BLUE))[FINDING, "f1"].status == "waiting"
        await store.abandon_clean(held)

        await publish(store, BLUE, "f2")
        held = await claim(store, BLUE, thresholds={**ONE, FINDING: 2})
        assert sorted(key for _k, key, _p in held.items) == ["f1", "f2", "q1"]


async def test_o3_a_second_claim_on_a_lane_with_a_not_ended_author_batch_is_refused(dsn):
    """Working or in review, the author batch refuses a second claim and inserts nothing. (O3, H4, D6)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        first = await claim(store, BLUE)
        await publish(store, BLUE, "f2", run="run-2")

        with pytest.raises(S.LaneBusy):
            await claim(store, BLUE, owner="host-b")
        assert [b.id for b in await store.batches(BLUE)] == [first.batch_id]
        assert (await _work(store, BLUE))[FINDING, "f2"].status == "waiting"

        await store.in_review(first, pr_number=4, outcomes={})
        with pytest.raises(S.LaneBusy):
            await claim(store, BLUE, owner="host-b")
        assert (await _batch(store, BLUE, first.batch_id)).phase == "in_review", "control: refusal changed nothing"


async def test_o3_two_claims_at_once_make_one_batch(dsn):
    """Raced claims on one lane: exactly one gets a batch, the other is told the lane is busy. (O3, the unique rule)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        async with learning_store(dsn) as other:
            outcomes = []

            async def attempt(which):
                try:
                    outcomes.append(await claim(which, BLUE))
                except S.LaneBusy as busy:
                    outcomes.append(busy)

            async with anyio.create_task_group() as group:
                group.start_soon(attempt, store)
                group.start_soon(attempt, other)
        assert sorted(type(o).__name__ for o in outcomes).count("LaneBusy") == 1, outcomes
        assert len(await store.batches(BLUE)) == 1


# --- the lease, its grace, the token (O3, P6) -----------------------------------------------------------------


HOLDER_VERBS = {
    "renew": lambda store, held: store.renew(held),
    "record_commit": lambda store, held: store.record_commit(held, oid(1), oid(10), "s", changes_of("agent/lessons/a.md")),
    "in_review": lambda store, held: store.in_review(held, pr_number=5, outcomes={}),
    "end_no_commits": lambda store, held: store.end_no_commits(held, {}),
    "abandon_clean": lambda store, held: store.abandon_clean(held),
    "expire_own": lambda store, held: store.expire_own(held),
}


@pytest.mark.parametrize("past_grace", [False, True], ids=["lapsed-within-grace", "lapsed-past-grace"])
@pytest.mark.parametrize("verb", sorted(HOLDER_VERBS))
async def test_p6_a_holder_whose_lease_lapsed_changes_nothing_in_grace_or_after(dsn, verb, past_grace):
    """Once the lease is past, even within grace, no holder verb is accepted and the batch, items and record are untouched. (O3, P6)"""
    S = store_mod()
    async with learning_store(dsn, **KNOBS) as store:
        await publish(store, BLUE, "f1")
        held = await claim(store, BLUE)
        lapse_lease(dsn, held.batch_id, past_grace=past_grace)
        before = (await _batch(store, BLUE, held.batch_id), await _work(store, BLUE))

        with pytest.raises(S.LeaseLost):
            await HOLDER_VERBS[verb](store, held)

        assert (await _batch(store, BLUE, held.batch_id), await _work(store, BLUE)) == before
        assert await store.commit_record(BLUE) == []
        assert lease_seconds_left(dsn, held.batch_id) < 0, "a late call revived the lease"


async def test_p6_a_successful_renew_extends_the_lease_and_the_default_lease_outlasts_a_stop_grace(dsn):
    """Renew pushes the lease end out by the lease; with no knob a fresh claim holds over 30 s (the worker's stop grace). (P6, Renewal and stop)"""
    async with learning_store(dsn, **KNOBS) as store:
        await publish(store, BLUE, "f1")
        held = await claim(store, BLUE)
        execute(dsn, "UPDATE learning.batches SET lease_expiry = now() + interval '5 seconds' WHERE id = %s", (held.batch_id,))
        assert lease_seconds_left(dsn, held.batch_id) < 10, "premise: the lease is nearly out"

        await store.renew(held)

        assert lease_seconds_left(dsn, held.batch_id) > 100, "a renewal that left the lease where it was lets a live holder lapse"
    async with learning_store(dsn) as store:
        await store.abandon_clean(held)
        await publish(store, BLUE, "f2")
        fresh = await claim(store, BLUE)
        assert lease_seconds_left(dsn, fresh.batch_id) > 30, "the default lease must outlast the stop grace"


async def test_p6_lease_lost_is_a_stop():
    """The lost lease raises the one stop the step already unwinds on. (P6, Renewal and stop)"""
    S = store_mod()
    assert issubclass(S.LeaseLost, S.Stop)


async def test_o1_within_grace_there_is_no_takeover_and_past_it_the_takeover_fences_the_old_token(dsn):
    """Lapsed within grace: take_over is refused, the row and token unchanged. Past grace: it succeeds with a new token and the old one is dead. (O1, P6)"""
    S = store_mod()
    async with learning_store(dsn, **KNOBS) as store:
        await publish(store, BLUE, "f1")
        held = await claim(store, BLUE)
        with pytest.raises(S.NotLapsed):  # control: a live lease cannot be taken over
            await store.take_over(BLUE, held.batch_id, owner="host-b")

        lapse_lease(dsn, held.batch_id, past_grace=False)
        with pytest.raises(S.NotLapsed):
            await store.take_over(BLUE, held.batch_id, owner="host-b")
        assert (await _batch(store, BLUE, held.batch_id)).phase == "working"

        lapse_lease(dsn, held.batch_id, past_grace=True)
        taken = await store.take_over(BLUE, held.batch_id, owner="host-b")
        assert taken.batch_id == held.batch_id
        assert taken.token != held.token
        assert lease_seconds_left(dsn, held.batch_id) > 0
        for verb in ("renew", "record_commit", "in_review"):
            with pytest.raises(S.LeaseLost):
                await HOLDER_VERBS[verb](store, held)
        assert await store.commit_record(BLUE) == [], "the old token recorded a commit after the takeover"
        await store.record_commit(taken, oid(1), oid(10), "s", changes_of("agent/lessons/a.md"))
        assert [r.commit for r in await store.commit_record(BLUE)] == [oid(1)]


async def test_p6_a_clean_stopped_holder_with_commits_expires_its_own_lease_so_takeover_need_not_wait(dsn):
    """expire_own ends the lease now: take_over works at once with a long grace, the holder is fenced; without it it is refused. (D4, Renewal and stop)"""
    S = store_mod()
    async with learning_store(dsn, **KNOBS) as store:
        await publish(store, BLUE, "f1")
        held = await claim(store, BLUE)
        await store.record_commit(held, oid(1), oid(10), "s", changes_of("agent/lessons/a.md"))
        with pytest.raises(S.NotLapsed):
            await store.take_over(BLUE, held.batch_id, owner="host-b")

        await store.expire_own(held)
        taken = await store.take_over(BLUE, held.batch_id, owner="host-b")
        assert taken.token != held.token
        with pytest.raises(S.LeaseLost):
            await store.renew(held)
        assert (await _work(store, BLUE))[FINDING, "f1"].batch_id == held.batch_id


# --- abandon: clean, crash, person; attempts (D8, O7) --------------------------------------------------------


async def test_d8_a_clean_stop_forgives_the_attempt_and_never_reaches_the_ceiling(dsn):
    """Claim then clean abandon, three times over a ceiling of two: the item stays waiting with no attempt used. (D8, r8 attempts)"""
    async with learning_store(dsn, max_attempts=2) as store:
        await publish(store, BLUE, "f1")
        for _ in range(3):
            held = await claim(store, BLUE)
            await store.abandon_clean(held)
            item = (await _work(store, BLUE))[FINDING, "f1"]
            assert (item.status, item.attempts) == ("waiting", 0)
            assert (await _batch(store, BLUE, held.batch_id)).phase == "ended"


async def test_d8_a_recovery_abandon_keeps_the_attempt_and_the_ceiling_holds_the_item_for_a_person(dsn):
    """Crash abandons return the item with its attempt used; the one that reaches max_attempts holds it with a reason. (D8, P3)"""
    async with learning_store(dsn, max_attempts=2, **KNOBS) as store:
        await publish(store, BLUE, "f1")
        first = await claim(store, BLUE)
        lapse_lease(dsn, first.batch_id)
        await store.abandon(BLUE, first.batch_id, by="recovery")
        item = (await _work(store, BLUE))[FINDING, "f1"]
        assert (item.status, item.attempts) == ("waiting", 1)
        assert (await _batch(store, BLUE, first.batch_id)).outcome == "abandoned"

        second = await claim(store, BLUE)
        lapse_lease(dsn, second.batch_id)
        await store.abandon(BLUE, second.batch_id, by="recovery")
        item = (await _work(store, BLUE))[FINDING, "f1"]
        assert (item.status, item.attempts) == ("held", 2)
        assert item.reason, "a held item says why"
        assert await claim(store, BLUE) is None


@pytest.mark.parametrize("phase", ["working", "in_review", "needs_person"])
async def test_o7_a_person_abandons_any_not_ended_batch_and_its_items_are_held_then_released(dsn, phase):
    """Whatever the phase, a person's abandon ends the batch abandoned and holds its items; a holder is fenced; release_held returns an item to waiting. (O7)"""
    S = store_mod()
    async with learning_store(dsn, **KNOBS) as store:
        await publish(store, BLUE, "f1")
        held = await claim(store, BLUE)
        if phase == "in_review":
            await store.in_review(held, pr_number=6, outcomes={})
        if phase == "needs_person":
            await store.needs_person(BLUE, held.batch_id, "a hand-made PR is on the prefix")

        await store.abandon(BLUE, held.batch_id, by="person")

        batch = await _batch(store, BLUE, held.batch_id)
        assert (batch.phase, batch.outcome) == ("ended", "abandoned")
        item = (await _work(store, BLUE))[FINDING, "f1"]
        assert (item.status, item.batch_id) == ("held", held.batch_id)
        if phase == "working":
            with pytest.raises(S.LeaseLost):
                await store.renew(held)

        await store.release_held(BLUE, FINDING, "f1")
        assert (await _work(store, BLUE))[FINDING, "f1"].status == "waiting"
        assert await claim(store, BLUE) is not None, "control: the lane is free and the released item is claimable"


# --- replacement claims: due items, generations, exits (D8, Feedback) -------------------------------------------


async def _closed_with_feedback(store, tenant, *ids, hold=(), pr=7):
    """Batch A over `ids`, in review as `pr`, then closed with feedback: its items but `hold` stay in_batch (replacement due)."""
    first = await _in_review(store, tenant, *ids, pr=pr)
    await store.end_review(tenant, first.batch_id, expect_phase="in_review", outcome="closed",
                           published=[], held=[(FINDING, key) for key in hold])
    return first


async def test_d8_a_replacement_claim_takes_only_the_due_items_names_what_it_replaces_and_counts_at_its_pr(dsn):
    """Due items go to a new batch that `replaces` the closed one, others wait; the generation counts when its PR opens. (D8, H3)"""
    async with learning_store(dsn) as store:
        old = await _closed_with_feedback(store, BLUE, "f1", "f2", hold=["f2"])
        await publish(store, BLUE, "f9", run="run-2")

        new = await claim(store, BLUE)
        assert (new.replaces, new.feedback_pr) == (old.batch_id, 7)
        assert [key for _k, key, _p in new.items] == ["f1"], "a replacement took what was not due"
        items = await _work(store, BLUE)
        assert (items[FINDING, "f1"].status, items[FINDING, "f1"].batch_id) == ("in_batch", new.batch_id)
        assert (items[FINDING, "f2"].status, items[FINDING, "f9"].status) == ("held", "waiting")
        assert (await _batch(store, BLUE, new.batch_id)).generation == 0, "generation counted before a PR opened"

        await store.in_review(new, pr_number=8, outcomes={})
        batch = await _batch(store, BLUE, new.batch_id)
        assert (batch.replaces, batch.generation, batch.pr_number) == (old.batch_id, 1, 8)


@pytest.mark.parametrize("how", ["clean", "recovery"])
async def test_d8_a_replacement_abandoned_by_stop_or_crash_before_its_pr_leaves_its_items_due_unchanged(dsn, how):
    """Clean or crash abandon of a replacement returns its items to the closed batch; the next claim replaces that one, generation unchanged. (D8, Feedback)"""
    async with learning_store(dsn, **KNOBS) as store:
        old = await _closed_with_feedback(store, BLUE, "f1")
        new = await claim(store, BLUE)
        if how == "clean":
            await store.abandon_clean(new)
        else:
            lapse_lease(dsn, new.batch_id)
            await store.abandon(BLUE, new.batch_id, by="recovery")

        item = (await _work(store, BLUE))[FINDING, "f1"]
        assert (item.status, item.batch_id) == ("in_batch", old.batch_id), "an ended non-closed batch still holds items"
        assert (await _batch(store, BLUE, new.batch_id)).generation == 0
        again = await claim(store, BLUE)
        assert (again.replaces, [key for _k, key, _p in again.items]) == (old.batch_id, ["f1"])
        assert again.batch_id != new.batch_id


async def test_o7_a_person_abandoning_a_replacement_holds_its_items(dsn):
    """A person's abandon of the replacement holds the items; it does not leave them due. (O7, Feedback)"""
    async with learning_store(dsn) as store:
        await _closed_with_feedback(store, BLUE, "f1")
        new = await claim(store, BLUE)
        await store.abandon(BLUE, new.batch_id, by="person")
        assert (await _work(store, BLUE))[FINDING, "f1"].status == "held"
        assert await claim(store, BLUE) is None


async def test_d8_a_replacement_that_ends_with_no_commits_holds_its_items(dsn):
    """A replacement whose curator committed nothing ends with its items held, not due again: the same feedback cannot loop. (G-F4, G-C2, Feedback)"""
    async with learning_store(dsn) as store:
        await _closed_with_feedback(store, BLUE, "f1")
        new = await claim(store, BLUE)
        await store.end_no_commits(new, {})

        batch = await _batch(store, BLUE, new.batch_id)
        assert (batch.phase, batch.replaces is not None) == ("ended", True)
        assert (await _work(store, BLUE))[FINDING, "f1"].status == "held"
        assert await claim(store, BLUE) is None, "held items are not claimed again"


async def test_o7_a_persons_abandon_of_the_closed_batch_holds_the_items_a_replacement_is_due_for(dsn):
    """Before any replacement is claimed, a person abandons the closed batch: its due items are held and nothing claims them. (G-C1, O7)"""
    async with learning_store(dsn) as store:
        old = await _closed_with_feedback(store, BLUE, "f1", "f2", hold=["f2"])
        await store.abandon(BLUE, old.batch_id, by="person")

        items = await _work(store, BLUE)
        assert (items[FINDING, "f1"].status, items[FINDING, "f2"].status) == ("held", "held")
        assert await claim(store, BLUE) is None


async def test_o7_release_held_starts_the_item_afresh_attempts_and_deferrals_both(dsn):
    """A released item has no attempts and no deferrals counted, so the ceiling does not hold it again at its next claim. (G-C3, G-T4, O7)"""
    S = store_mod()
    async with learning_store(dsn, max_attempts=5) as store:
        await publish(store, BLUE, "f1")
        for _ in range(2):
            held = await claim(store, BLUE)
            await store.end_no_commits(held, {(FINDING, "f1"): S.Outcome.deferred()})
        crashed = await claim(store, BLUE)
        lapse_lease(dsn, crashed.batch_id)
        await store.abandon(BLUE, crashed.batch_id, by="recovery")
        again = await claim(store, BLUE)
        await store.in_review(again, pr_number=7, outcomes={})
        await store.abandon(BLUE, again.batch_id, by="person")
        item = (await _work(store, BLUE))[FINDING, "f1"]
        assert (item.status, item.deferrals, item.attempts > 0) == ("held", 2, True), "premise: held with both counters up"

        await store.release_held(BLUE, FINDING, "f1")

        item = (await _work(store, BLUE))[FINDING, "f1"]
        assert (item.status, item.attempts, item.deferrals) == ("waiting", 0, 0)


async def test_d8_a_replacement_past_the_generation_ceiling_holds_its_items_for_a_person(dsn):
    """With a ceiling of one replacement PR, feedback on that replacement holds the items instead of a second replacement. (D8, r8 batches.generation)"""
    async with learning_store(dsn, generation_ceiling=1) as store:
        await _closed_with_feedback(store, BLUE, "f1")
        second = await claim(store, BLUE)
        await store.in_review(second, pr_number=8, outcomes={})
        await store.end_review(BLUE, second.batch_id, expect_phase="in_review", outcome="closed", published=[], held=[])

        assert await claim(store, BLUE) is None
        assert (await _work(store, BLUE))[FINDING, "f1"].status == "held"


# --- in_review and end_no_commits apply the curator's outcomes (D1, Tick) ---------------------------------------


async def test_tick_in_review_returns_items_the_batch_did_not_cite_and_keeps_the_rest(dsn):
    """Entering review, an item outcome `waiting` goes back to waiting; the others stay in the batch, now with its PR. (Tick flow, D1)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1", "f2")
        held = await claim(store, BLUE)
        await store.in_review(held, pr_number=9, outcomes={(FINDING, "f2"): S.Outcome.waiting()})

        items = await _work(store, BLUE)
        assert (items[FINDING, "f1"].status, items[FINDING, "f1"].pr_number) == ("in_batch", 9)
        assert items[FINDING, "f2"].status == "waiting"
        assert (await _batch(store, BLUE, held.batch_id)).phase == "in_review"


async def test_tick_no_commits_ends_the_batch_and_returns_items_with_their_outcomes(dsn):
    """A batch with no commits ends: a skipped item is skipped with its reason, the rest wait, the lane is free. (Tick flow, D1)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1", "f2")
        held = await claim(store, BLUE)
        await store.end_no_commits(held, {(FINDING, "f1"): S.Outcome.skipped("already known")})

        items = await _work(store, BLUE)
        assert (items[FINDING, "f1"].status, items[FINDING, "f1"].reason) == ("skipped", "already known")
        assert items[FINDING, "f2"].status == "waiting"
        assert (await _batch(store, BLUE, held.batch_id)).phase == "ended"
        assert await claim(store, BLUE) is not None


# --- reverts (Reverts) ---------------------------------------------------------------------------------------


async def test_reverts_a_working_batch_blocks_a_revert_an_open_author_pr_does_not_and_an_open_revert_pr_blocks_authoring(dsn):
    """A running tick or revert blocks claim_revert; an author batch in review does not; a revert in review blocks the author claim. (Reverts, O3)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        running = await claim(store, BLUE)
        with pytest.raises(S.LaneBusy):
            await store.claim_revert(BLUE, owner="cli")
        await store.in_review(running, pr_number=4, outcomes={})

        revert = await store.claim_revert(BLUE, owner="cli")
        batch = await _batch(store, BLUE, revert.batch_id)
        assert (batch.kind, batch.lane, batch.phase, list(revert.items)) == ("revert", AUTHOR_LANE, "working", [])
        with pytest.raises(S.LaneBusy):
            await store.claim_revert(BLUE, owner="cli-2")

        await store.in_review(revert, pr_number=5, outcomes={})
        await store.end_review(BLUE, running.batch_id, expect_phase="in_review", outcome="merged", published=[(FINDING, "f1")], held=[])
        await publish(store, BLUE, "f2", run="run-2")
        with pytest.raises(S.LaneBusy):
            await claim(store, BLUE)
        assert (await _work(store, BLUE))[FINDING, "f2"].status == "waiting"

        await store.end_review(BLUE, revert.batch_id, expect_phase="in_review", outcome="merged", published=[], held=[])
        assert await claim(store, BLUE) is not None, "control: a revert PR that ended frees authoring"


async def test_d5_a_reverts_commits_are_in_the_tenants_record_with_the_revert_batch_and_what_they_undo(dsn):
    """The revert batch records through record_commit; its rows carry its batch and the change undone; the record is per tenant. (D5, Reverts)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        authored = await claim(store, BLUE)
        await store.record_commit(authored, oid(1), oid(10), "s1", changes_of("agent/lessons/a.md"))
        await store.in_review(authored, pr_number=4, outcomes={})
        await publish(store, GREEN, "g1")
        green = await claim(store, GREEN)
        await store.record_commit(green, oid(7), oid(70), "sg", changes_of("agent/lessons/g.md"))

        revert = await store.claim_revert(BLUE, owner="cli")
        await store.record_commit(revert, oid(2), oid(11), "s2", [("agent/lessons/a.md", oid(900), None)],
                                  reverts=(authored.batch_id, "agent/lessons/a.md"))
        await store.in_review(revert, pr_number=5, outcomes={})

        rows = await store.commit_record(BLUE)
        assert [(r.commit, str(r.batch_id)) for r in rows] == [(oid(1), str(authored.batch_id)), (oid(2), str(revert.batch_id))]
        assert not rows[0].reverts
        assert "agent/lessons/a.md" in str(rows[1].reverts)
        assert str(authored.batch_id) in str(rows[1].reverts)
        assert (rows[1].branch, rows[1].base) == (revert.branch, oid(11))
        assert [r.commit for r in await store.commit_record(GREEN)] == [oid(7)], "another tenant's commits show"


# --- offboarding (O6), view (O2) ----------------------------------------------------------------------------


async def test_o6_a_tenant_off_active_gets_no_batch_and_its_working_batch_is_told_to_stop(dsn):
    """Off active, claim and claim_revert insert nothing; cancel on a working batch makes its renewal a stop. (O6, Offboarding)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        await publish(store, GREEN, "g1")
        working = await claim(store, GREEN, owner="host-a")  # control: an active tenant claims

        move_tenant(dsn, BLUE, state="offboarding")
        with pytest.raises(S.TenantInactive):
            await claim(store, BLUE)
        with pytest.raises(S.TenantInactive):
            await store.claim_revert(BLUE, owner="cli")
        assert await store.batches(BLUE) == []
        assert (await _work(store, BLUE))[FINDING, "f1"].status == "waiting"

        await store.renew(working)  # control: no cancel yet
        await store.request_cancel(GREEN)
        [batch] = await store.batches(GREEN)
        assert batch.cancel_requested is True
        with pytest.raises(S.Stop):
            await store.renew(working)


async def test_o2_the_view_names_each_items_status_batch_and_pr_per_tenant(dsn):
    """Per tenant: each item's status, batch and PR; another tenant's items never show. (O2, O6)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        await publish(store, GREEN, "g1")
        held = await claim(store, BLUE)
        await store.in_review(held, pr_number=7, outcomes={})

        blue = await store.work(BLUE)
        assert [(i.kind, i.key, i.status, i.batch_id, i.pr_number) for i in blue] == [
            ("finding", "f1", "in_batch", held.batch_id, 7)]
        assert [(i.key, i.status, i.batch_id, i.pr_number) for i in await store.work(GREEN)] == [
            ("g1", "waiting", None, None)]
        [batch] = await store.batches(BLUE)
        assert (batch.phase, batch.pr_number, batch.branch) == ("in_review", 7, held.branch)


@pytest.mark.parametrize("outcome", ["merged", "closed"])
async def test_d7_end_review_with_a_phase_that_is_no_longer_the_batchs_changes_nothing(dsn, outcome):
    """A stale reconcile (the person abandoned the batch first) ends nothing and publishes nothing: the compare-and-set on phase. (D7, O7)"""
    async with learning_store(dsn, **KNOBS) as store:
        held = await _in_review(store, BLUE, "f1")
        await store.abandon(BLUE, held.batch_id, by="person")
        after_abandon = (await _batch(store, BLUE, held.batch_id), await _work(store, BLUE))
        assert (after_abandon[0].phase, after_abandon[0].outcome) == ("ended", "abandoned"), "premise: the batch already ended"
        published = [(FINDING, "f1")] if outcome == "merged" else []

        with contextlib.suppress(Exception):  # refusing is as good as ignoring
            await store.end_review(BLUE, held.batch_id, expect_phase="in_review", outcome=outcome, published=published, held=[])

        batch = await _batch(store, BLUE, held.batch_id)
        assert (batch.phase, batch.outcome) == ("ended", "abandoned")
        assert await _work(store, BLUE) == after_abandon[1], "a stale end_review moved an item"


@pytest.mark.parametrize("words", [False, True], ids=["closed-without-words", "closed-with-words"])
async def test_d9_a_lead_batchs_curation_requests_keep_their_own_fate_until_the_batch_ends(dsn, words):
    """A request the curator skipped stays skipped when the lead PR closes; the rest are held when it closed without words, and stay due when it closed with. (D9, H2)"""
    S = store_mod()
    async with learning_store(dsn, **KNOBS) as store:
        await store.enqueue_request(BLUE, "run-1", "case-A", {"n": 1})
        await store.enqueue_request(BLUE, "run-2", "case-B", {"n": 2})
        await store.add_pitfall(BLUE, {"schema_version": 1, "pitfall_id": "p1", "source_run": "r", "system": "elastic",
                                       "query_id": "elastic.esql", "goal": "g", "executed_query": "x",
                                       "stderr_digest": "exit=1; digest", "error_class": "agent-fixable"})
        held = await store.claim(BLUE, LEAD_LANE, owner="host-a", thresholds=ONE)
        assert len(held.items) == 3
        await store.in_review(held, pr_number=9, outcomes={("curation_request", "run-1"): S.Outcome.skipped("names no system")})
        items = await _work(store, BLUE)
        assert items["curation_request", "run-1"].status == "skipped", "premise: the curator's fate for one request"
        assert {items["curation_request", "run-2"].status, items["pitfall", "p1"].status} == {"in_batch"}, "premise: committed items wait for the PR"

        await store.end_review(BLUE, held.batch_id, expect_phase="in_review", outcome="closed", published=[],
                               held=[] if words else [("curation_request", "run-2"), ("pitfall", "p1")])

        items = await _work(store, BLUE)
        assert (items["curation_request", "run-1"].status, "names no system" in (items["curation_request", "run-1"].reason or "")) \
            == ("skipped", True), "a batch's end rewrote a request's own fate"
        rest = {items["curation_request", "run-2"].status, items["pitfall", "p1"].status}
        assert rest == ({"in_batch"} if words else {"held"})
