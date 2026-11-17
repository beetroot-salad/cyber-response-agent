"""#1537 (design r3): a person's release of held items and credential-parked batches, the request to abandon a parked batch,
the causes the database holds, and the parked list's fields, on the learning store over a real PostgreSQL.

Rows are made by store verbs; the one state they cannot reach without a guessed signature (a batch parked for a named cause)
is set by `_release1537.park` through the columns the design names. The settle of a request is the loop's and is driven end
to end in `tenancy/tenant_1108_p4/test_abandon_1537.py`. Verb names and argument shapes are fixed in `_release1537`.
"""
from __future__ import annotations

import datetime as _dt

import pytest
from psycopg import errors

from defender.jobs.errors import Conflict, NotFound
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._release1537 import (
    CREDENTIAL,
    item_row,
    park,
    release_batch,
    release_item,
    request_abandon,
    row,
    why,
    set_held,
)
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    claim,
    lapse_lease,
    learning_store,
    publish,
    store_mod,
)
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1537-blue")
GREEN = fixture_uuid("tenant:1537-green")
ACTOR = "u-1537"
EPOCH = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)
#: Parked batch causes that are not a credential refusal (design: the closed list's park entries).
OTHER_PARK_CAUSES = ["forge_refused", "delivery_unavailable", "foreign_commits_remote", "foreign_commits_local",
                     "foreign_pr", "unrecorded"]


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


async def _held_at_ceiling(dsn: str, tenant: str, key: str) -> None:
    """One finding held by the store itself: claimed once under a one-attempt ceiling, its batch merged without it."""
    async with learning_store(dsn, max_attempts=1) as store:
        await publish(store, tenant, key)
        batch = await claim(store, tenant)
        await store.in_review(batch, 4, {})
        assert await store.end_review(tenant, batch.batch_id, expect_phase="in_review", outcome="merged",
                                      published=[], held=[])


async def _review_parked(store, dsn, tenant, *keys, pr=9, cause=CREDENTIAL):
    """An author batch over `keys` in review as `pr`, then parked for `cause`: its id."""
    await publish(store, tenant, *keys)
    batch = await claim(store, tenant)
    await store.in_review(batch, pr, {})
    park(dsn, batch.batch_id, cause=cause)
    return batch


async def _working_parked(store, dsn, tenant, *keys, cause=CREDENTIAL):
    """An author batch over `keys` that never reached a PR, parked for `cause`."""
    await publish(store, tenant, *keys)
    batch = await claim(store, tenant)
    park(dsn, batch.batch_id, cause=cause)
    return batch


def _same(dsn, batch_id, before):
    assert row(dsn, batch_id) == before, "a refused action changed the batch"


# --- O1: release an item --------------------------------------------------------------------------------------------


async def test_o1_release_starts_a_held_item_afresh_clears_its_cause_and_detail_and_it_is_claimable(dsn):
    """A held item released by id waits, attempts and deferrals 0, cause and detail NULL, and the next claim takes it. (O1)"""
    await _held_at_ceiling(dsn, BLUE, "h1")
    before = item_row(dsn, BLUE, "h1")
    assert (before["status"], before["cause"], before["attempts"]) == ("held", "attempt_ceiling", 1), "premise: the store's own hold"
    assert before["reason"] is not None
    async with learning_store(dsn, max_attempts=1) as store:
        [item] = await store.work(BLUE)
        await release_item(store, BLUE, item.id)
        after = item_row(dsn, BLUE, "h1")
        taken = await claim(store, BLUE)
    assert (after["status"], after["cause"], after["reason"], after["attempts"], after["deferrals"]) == (
        "waiting", None, None, 0, 0)
    assert [key for _k, key, _p in taken.items] == ["h1"]


@pytest.mark.parametrize("fresher", [True, False])
async def test_o1_a_held_request_with_a_fresher_one_waiting_is_skipped_as_superseded_else_it_waits(dsn, fresher):
    """Released, a held curation request is `skipped` with cause `superseded` when a fresher request for its case waits; with none it waits. (O1)"""
    async with learning_store(dsn) as store:
        await store.enqueue_request(BLUE, "run-r1", "case-1", {"case": "a"})
        set_held(dsn, BLUE, "run-r1")
        if fresher:
            await store.enqueue_request(BLUE, "run-r2", "case-1", {"case": "a"})
        [old] = [i for i in await store.work(BLUE) if i.key == "run-r1"]
        await release_item(store, BLUE, old.id)
    got = item_row(dsn, BLUE, "run-r1")
    want = ("skipped", "superseded") if fresher else ("waiting", None)
    assert (got["status"], got["cause"]) == want


async def test_o1_another_tenants_item_and_an_unknown_id_are_not_found_and_nothing_changes_while_its_own_is_released(dsn):
    """GREEN's held item through BLUE, and an id no one holds, raise NotFound; GREEN's stays held; BLUE's own releases. (O1)"""
    await _held_at_ceiling(dsn, GREEN, "g1")
    await _held_at_ceiling(dsn, BLUE, "b1")
    before = item_row(dsn, GREEN, "g1")
    async with learning_store(dsn) as store:
        [theirs] = await store.work(GREEN)
        [mine] = await store.work(BLUE)
        with pytest.raises(NotFound):
            await release_item(store, BLUE, theirs.id)
        with pytest.raises(NotFound):
            await release_item(store, BLUE, fixture_uuid("item:1537-none"))
        assert item_row(dsn, GREEN, "g1") == before
        await release_item(store, BLUE, mine.id)
    assert item_row(dsn, BLUE, "b1")["status"] == "waiting"


@pytest.mark.parametrize("state", ["waiting", "in_batch", "published"])
async def test_o1_an_item_that_is_not_held_is_a_conflict_naming_its_status_and_a_held_one_is_released(dsn, state):
    """A waiting, in-batch or published item raises Conflict naming its status and changes nothing; the held control releases. (O1, PR3)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "x1", "x2")
        if state != "waiting":
            batch = await claim(store, BLUE)
            if state == "published":
                await store.in_review(batch, 3, {("finding", "x1"): store_mod().Outcome.published()})
        [first, *_] = sorted(await store.work(BLUE), key=lambda i: i.key)
        before = item_row(dsn, BLUE, "x1")
        assert before["status"] == state, "premise"
        with pytest.raises(Conflict, match=state):
            await release_item(store, BLUE, first.id)
        assert item_row(dsn, BLUE, "x1") == before
        set_held(dsn, BLUE, "x2")
        [second] = [i for i in await store.work(BLUE) if i.key == "x2"]
        await release_item(store, BLUE, second.id)
    assert item_row(dsn, BLUE, "x2")["status"] in ("waiting", "in_batch")


# --- O2: release a batch --------------------------------------------------------------------------------------------


async def test_o2_a_credential_parked_batch_with_a_pr_goes_back_to_review_with_its_refusals_and_parked_fields_cleared(dsn):
    """Parked while in review, released: `in_review` on the same PR, refusals 0, cause, detail and `parked_at` NULL, its items still in it, its lane still held. (O2)"""
    async with learning_store(dsn) as store:
        batch = await _review_parked(store, dsn, BLUE, "f1", "f2")
        await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
        got = row(dsn, batch.batch_id)
        items = {i.key: i.status for i in await store.work(BLUE)}
        lane = await store.lane_work(BLUE, AUTHOR_LANE, thresholds={"finding": 1})
    assert (got["phase"], got["pr_number"], got["refusals"]) == ("in_review", 9, 0)
    assert (got["cause"], got["reason"], got["parked_at"], got["lease_owner"], got["lease_expiry"]) == (None,) * 5
    assert items == {"f1": "in_batch", "f2": "in_batch"}
    assert lane.busy is True


async def test_o2_a_credential_parked_batch_with_no_pr_goes_back_to_working_on_a_lease_that_is_the_epoch_whatever_the_grace(dsn):
    """Parked while working, released by a default-grace store: `working`, owner `released:<actor>`, expiry exactly 1970-01-01 UTC, the token moved, refusals 0; another store with a grace of about 1.5e9 s still finds it lapsed and takes it over, and the old holder is fenced. (O2, C14)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        batch = await _working_parked(store, dsn, BLUE, "f1")
        parked = row(dsn, batch.batch_id)
        await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
        got = row(dsn, batch.batch_id)
    async with learning_store(dsn, grace=1_500_000_000) as wide:
        [view] = [b for b in await wide.batches(BLUE) if b.id == batch.batch_id]
        taken = await wide.take_over(BLUE, str(batch.batch_id), owner="host-b")
        with pytest.raises(S.LeaseLost):
            await wide.renew(batch)
    assert (got["phase"], got["pr_number"], got["refusals"], got["lease_owner"]) == ("working", None, 0, f"released:{ACTOR}")
    assert got["lease_expiry"] == EPOCH
    assert got["fencing_token"] > parked["fencing_token"]
    assert (got["cause"], got["reason"], got["parked_at"]) == (None, None, None)
    assert view.lapsed is True
    assert taken.token > got["fencing_token"]
    assert [k for _kind, k, _p in taken.items] == ["f1"]


async def test_o2_a_released_working_batch_is_ended_by_recovery_like_any_lapsed_one(dsn):
    """A batch released to working can be ended by the recovery abandon (offboarding's way): ended abandoned, its items back, no `NotLapsed`. (O2)"""
    async with learning_store(dsn) as store:
        batch = await _working_parked(store, dsn, BLUE, "f1")
        await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
        await store.abandon(BLUE, str(batch.batch_id), by="recovery")
        got = row(dsn, batch.batch_id)
        [item] = await store.work(BLUE)
    assert (got["phase"], got["outcome"]) == ("ended", "abandoned")
    assert item.status == "waiting"


@pytest.mark.parametrize("cause", OTHER_PARK_CAUSES)
async def test_o2_a_batch_parked_for_another_cause_is_a_conflict_naming_the_cause_and_changes_nothing(dsn, cause):
    """Any park cause but a credential refusal is refused naming it; the credential-parked control is released. (O2, PR3)"""
    async with learning_store(dsn) as store:
        other = await _review_parked(store, dsn, BLUE, "f1", cause=cause)
        before = row(dsn, other.batch_id)
        with pytest.raises(Conflict, match=cause):
            await release_batch(store, BLUE, other.batch_id, actor=ACTOR)
        _same(dsn, other.batch_id, before)
        park(dsn, other.batch_id, cause=CREDENTIAL)
        await release_batch(store, BLUE, other.batch_id, actor=ACTOR)
    assert row(dsn, other.batch_id)["phase"] == "in_review"


async def test_o2_a_batch_that_is_not_parked_is_a_conflict_naming_its_phase(dsn):
    """A working, an in-review and an ended batch are refused naming their phase and change nothing. (O2, PR3)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "w1")
        held = await claim(store, BLUE)
        steps = [("working", None)]
        for phase, move in (("in_review", store.in_review(held, 5, {})),
                            ("ended", store.end_review(BLUE, held.batch_id, expect_phase="in_review", outcome="closed",
                                                       published=[], held=[("finding", "w1")], items_why=why("closed_without_feedback", "the PR closed without feedback")))):
            steps.append((phase, move))
        for phase, move in steps:
            if move is not None:
                await move
            before = row(dsn, held.batch_id)
            assert before["phase"] == phase, "premise"
            with pytest.raises(Conflict, match=phase):
                await release_batch(store, BLUE, held.batch_id, actor=ACTOR)
            _same(dsn, held.batch_id, before)


async def test_o2_a_pending_abandon_request_refuses_the_release_and_the_request_refuses_a_second_one(dsn):
    """With a request recorded, release and a second request are Conflicts and change nothing; before it, both are accepted on another batch. (O2, O3, PR3)"""
    async with learning_store(dsn) as store:
        batch = await _review_parked(store, dsn, BLUE, "f1")
        await request_abandon(store, BLUE, batch.batch_id, actor=ACTOR)
        before = row(dsn, batch.batch_id)
        with pytest.raises(Conflict):
            await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
        with pytest.raises(Conflict):
            await request_abandon(store, BLUE, batch.batch_id, actor="u-other")
        _same(dsn, batch.batch_id, before)
        assert before["abandon_requested_by"] == ACTOR, "the second request did not replace the first's actor"


async def test_o2_a_working_release_beside_another_working_batch_on_the_lane_is_refused_and_released_once_it_is_gone(dsn):
    """A working-parked author batch with a revert working on the lane: Conflict "another batch is working"; the release goes through once the revert ends. (O2, C11)"""
    async with learning_store(dsn) as store:
        batch = await _working_parked(store, dsn, BLUE, "f1")
        revert = await store.claim_revert(BLUE, owner="host-r")
        before = row(dsn, batch.batch_id)
        with pytest.raises(Conflict, match="working"):
            await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
        _same(dsn, batch.batch_id, before)
        await store.abandon_clean(revert)
        await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
    assert row(dsn, batch.batch_id)["phase"] == "working"


async def test_o2_an_author_batch_parked_in_review_is_not_released_beside_a_working_revert_and_is_once_it_is_gone(dsn):
    """An author batch parked from review with a revert working on its lane: Conflict naming the lane's working batch, still parked; with the revert gone, it returns to review (control). (O2, C13)"""
    async with learning_store(dsn) as store:
        batch = await _review_parked(store, dsn, BLUE, "f1")
        revert = await store.claim_revert(BLUE, owner="host-r")
        before = row(dsn, batch.batch_id)
        with pytest.raises(Conflict, match="working"):
            await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
        _same(dsn, batch.batch_id, before)
        await store.abandon_clean(revert)
        await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
    assert row(dsn, batch.batch_id)["phase"] == "in_review"


async def test_o2_a_revert_released_into_review_beside_a_working_author_batch_is_refused(dsn):
    """A parked revert (with its PR) with an author batch working on the lane: Conflict; once the author batch ends the revert returns to review. (O2, C13)"""
    async with learning_store(dsn) as store:
        revert = await store.claim_revert(BLUE, owner="host-r")
        await store.in_review(revert, 5, {})
        park(dsn, revert.batch_id)
        await publish(store, BLUE, "f1")
        author = await claim(store, BLUE)
        before = row(dsn, revert.batch_id)
        with pytest.raises(Conflict, match="working"):
            await release_batch(store, BLUE, revert.batch_id, actor=ACTOR)
        _same(dsn, revert.batch_id, before)
        await store.abandon_clean(author)
        await release_batch(store, BLUE, revert.batch_id, actor=ACTOR)
    assert row(dsn, revert.batch_id)["phase"] == "in_review"


async def test_o2_another_tenants_batch_and_an_unknown_one_are_not_found_for_every_batch_verb(dsn):
    """GREEN's parked batch through BLUE, and an unknown id, raise NotFound for release and for the request; GREEN's batch is unchanged. (O2, O3)"""
    async with learning_store(dsn) as store:
        theirs = await _review_parked(store, dsn, GREEN, "g1")
        before = row(dsn, theirs.batch_id)
        for verb in (release_batch, request_abandon):
            with pytest.raises(NotFound):
                await verb(store, BLUE, theirs.batch_id, actor=ACTOR)
            with pytest.raises(NotFound):
                await verb(store, BLUE, fixture_uuid("batch:1537-none"), actor=ACTOR)
        _same(dsn, theirs.batch_id, before)


# --- O3: request an abandon (the store side) ------------------------------------------------------------------------


async def test_o3_a_request_is_recorded_with_its_time_and_actor_and_decides_nothing_else(dsn):
    """On a parked batch: `abandon_requested_at` and `_by` set, the batch still parked with its cause, its items still in it, its lane still held. (O3, PR2)"""
    async with learning_store(dsn) as store:
        batch = await _review_parked(store, dsn, BLUE, "f1", "f2")
        before = row(dsn, batch.batch_id)
        [(now_before,)] = execute(dsn, "SELECT clock_timestamp()")
        await request_abandon(store, BLUE, batch.batch_id, actor=ACTOR)
        [(now_after,)] = execute(dsn, "SELECT clock_timestamp()")
        got = row(dsn, batch.batch_id)
        items = {i.key: i.status for i in await store.work(BLUE)}
        lane = await store.lane_work(BLUE, AUTHOR_LANE, thresholds={"finding": 1})
    assert before["abandon_requested_at"] is None, "premise"
    assert now_before <= got["abandon_requested_at"] <= now_after
    assert got["abandon_requested_by"] == ACTOR
    assert {k: v for k, v in got.items() if not k.startswith("abandon_requested")} == {
        k: v for k, v in before.items() if not k.startswith("abandon_requested")}
    assert items == {"f1": "in_batch", "f2": "in_batch"}
    assert lane.busy is True


async def test_o3_a_batch_that_is_not_parked_is_a_conflict_naming_its_phase_and_a_parked_one_is_accepted(dsn):
    """A working batch and an in-review batch are refused naming their phase; nothing is recorded; the parked control is accepted. (O3, PR3)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "w1")
        held = await claim(store, BLUE)
        before = row(dsn, held.batch_id)
        with pytest.raises(Conflict, match="working"):
            await request_abandon(store, BLUE, held.batch_id, actor=ACTOR)
        await store.in_review(held, 5, {})
        before = row(dsn, held.batch_id)
        with pytest.raises(Conflict, match="in_review"):
            await request_abandon(store, BLUE, held.batch_id, actor=ACTOR)
        _same(dsn, held.batch_id, before)
        park(dsn, held.batch_id, cause="foreign_pr")
        await request_abandon(store, BLUE, held.batch_id, actor=ACTOR)
    assert row(dsn, held.batch_id)["abandon_requested_at"] is not None, "a request is accepted whatever the park cause"


# --- O4: causes -----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["stopped", "holder_crashed", "holder_lost", "no_commits"])
async def test_o4_a_batch_the_store_ends_abandoned_carries_the_cause_of_how(dsn, how):
    """The holder's clean stop, its crash, a recovery abandon and an end with no commits each leave the batch ended `abandoned` with its own cause. (O4, PR1)"""
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "f1")
        held = await claim(store, BLUE)
        if how == "stopped":
            await store.abandon_clean(held)
        elif how == "holder_crashed":
            await store.abandon_crashed(held)
        elif how == "no_commits":
            await store.end_no_commits(held, {})
        else:
            lapse_lease(dsn, held.batch_id)
            await store.abandon(BLUE, str(held.batch_id), by="recovery")
    got = row(dsn, held.batch_id)
    assert (got["phase"], got["outcome"], got["cause"]) == ("ended", "abandoned", how)
    assert got["reason"] is not None, "the detail text stays beside the cause"


async def test_o4_a_batch_ended_merged_or_closed_has_no_cause_and_a_return_to_waiting_clears_an_items(dsn):
    """Merged and closed endings carry no cause or detail from a park; an item held then released has none. (O4, PR1)"""
    async with learning_store(dsn) as store:
        batch = await _review_parked(store, dsn, BLUE, "f1")
        await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
        assert await store.end_review(BLUE, batch.batch_id, expect_phase="in_review", outcome="merged",
                                      published=[("finding", "f1")], held=[])
    got = row(dsn, batch.batch_id)
    assert (got["phase"], got["outcome"], got["cause"], got["reason"], got["parked_at"]) == ("ended", "merged", None, None, None)


_BAD = {  # the database refuses, naming the check: (setup, statement, params)
    "item held without a cause": ("item", "UPDATE learning.work_items SET status = 'held', reason = 'x' WHERE item_key = 'c1'", ()),
    "item dead without a cause": ("item", "UPDATE learning.work_items SET status = 'dead' WHERE item_key = 'c1'", ()),
    "item skipped without a cause": ("item", "UPDATE learning.work_items SET status = 'skipped' WHERE item_key = 'c1'", ()),
    "waiting item with a cause": ("item", "UPDATE learning.work_items SET cause = 'curator_held' WHERE item_key = 'c1'", ()),
    "item cause outside its list": ("item", "UPDATE learning.work_items SET status = 'held', cause = 'forge_refused' WHERE item_key = 'c1'", ()),
    "item cause not a word of the list": ("item", "UPDATE learning.work_items SET status = 'held', cause = 'bogus' WHERE item_key = 'c1'", ()),
    "working batch with a cause": ("working", "UPDATE learning.batches SET cause = 'stopped' WHERE id = %s", ("id",)),
    "in-review batch with a cause": ("review", "UPDATE learning.batches SET cause = 'forge_refused' WHERE id = %s", ("id",)),
    "parked batch without a cause": ("parked", "UPDATE learning.batches SET cause = NULL WHERE id = %s", ("id",)),
    "parked batch cause outside its list": ("parked", "UPDATE learning.batches SET cause = 'attempt_ceiling' WHERE id = %s", ("id",)),
    "abandoned batch without a cause": ("working", "UPDATE learning.batches SET phase = 'ended', outcome = 'abandoned', ended_at = now(), lease_owner = NULL, lease_expiry = NULL WHERE id = %s", ("id",)),
    "merged batch with a cause": ("review", "UPDATE learning.batches SET phase = 'ended', outcome = 'merged', ended_at = now(), cause = 'stopped' WHERE id = %s", ("id",)),
    "closed batch with a cause": ("review", "UPDATE learning.batches SET phase = 'ended', outcome = 'closed', ended_at = now(), cause = 'stopped' WHERE id = %s", ("id",)),
    "parked_at on a working batch": ("working", "UPDATE learning.batches SET parked_at = now() WHERE id = %s", ("id",)),
    "parked_at on an in-review batch": ("review", "UPDATE learning.batches SET parked_at = now() WHERE id = %s", ("id",)),
    "request on a working batch": ("working", "UPDATE learning.batches SET abandon_requested_at = now(), abandon_requested_by = 'u' WHERE id = %s", ("id",)),
    "request on an in-review batch": ("review", "UPDATE learning.batches SET abandon_requested_at = now(), abandon_requested_by = 'u' WHERE id = %s", ("id",)),
}
_GOOD = {  # the same rows, a statement the checks allow
    "item": "UPDATE learning.work_items SET status = 'held', cause = 'curator_held', reason = 'x' WHERE item_key = 'c1'",
    "working": "UPDATE learning.batches SET phase = 'ended', outcome = 'abandoned', ended_at = now(), cause = 'stopped', lease_owner = NULL, lease_expiry = NULL WHERE id = %s",
    "review": "UPDATE learning.batches SET phase = 'ended', outcome = 'merged', ended_at = now() WHERE id = %s",
    "parked": "UPDATE learning.batches SET abandon_requested_at = now(), abandon_requested_by = 'u' WHERE id = %s",
}


@pytest.mark.parametrize("name", sorted(_BAD))
async def test_o4_the_database_refuses_a_cause_without_its_state_and_a_state_without_its_cause(dsn, name):
    """Each way a row's cause and state disagree, or a parked/request field sits in a phase it does not belong to, is a check violation; the same row takes the allowed statement. (O4, PR1, O5)"""
    setup, statement, params = _BAD[name]
    async with learning_store(dsn) as store:
        await publish(store, BLUE, "c1")
        if setup == "item":
            target = None
        else:
            held = await claim(store, BLUE)
            target = str(held.batch_id)
            if setup in ("review", "parked"):
                await store.in_review(held, 5, {})
            if setup == "parked":
                park(dsn, held.batch_id)
        args = (target,) if params else ()
        with pytest.raises(errors.CheckViolation):
            execute(dsn, statement, args)
        good = _GOOD[setup]
        execute(dsn, good, (target,) if "%s" in good else ())


# --- O5: the parked list's fields -----------------------------------------------------------------------------------


async def test_o5_the_parked_view_carries_cause_parked_at_releasable_the_request_and_last_checked(dsn):
    """A credential-parked batch lists releasable with its cause, `parked_at` and `last_checked` as stored; a request makes it not releasable and shows when; another cause is not releasable. (O5)"""
    async with learning_store(dsn) as store:
        mine = await _review_parked(store, dsn, BLUE, "f1")
        got = {v.id: v for v in await store.parked(BLUE, limit=5)}[mine.batch_id]
        stored = row(dsn, mine.batch_id)
        assert (got.cause, got.releasable, got.abandon_requested_at) == (CREDENTIAL, True, None)
        assert (got.parked_at, got.last_checked) == (stored["parked_at"], stored["last_checked"])
        await request_abandon(store, BLUE, mine.batch_id, actor=ACTOR)
        asked = {v.id: v for v in await store.parked(BLUE, limit=5)}[mine.batch_id]
        assert (asked.releasable, asked.abandon_requested_at) == (False, row(dsn, mine.batch_id)["abandon_requested_at"])
        other = await store.claim_revert(BLUE, owner="host-r")
        park(dsn, other.batch_id, cause="forge_refused")
        views = {v.id: v for v in await store.parked(BLUE, limit=5)}
    assert (views[other.batch_id].cause, views[other.batch_id].releasable) == ("forge_refused", False)


async def test_o5_every_parked_row_has_a_parked_at_not_before_it_was_created_and_a_released_one_has_none(dsn):
    """`parked_at` is set for a parked batch, never before `created_at`; released, it is NULL. (O5)"""
    async with learning_store(dsn) as store:
        batch = await _review_parked(store, dsn, BLUE, "f1")
        parked = row(dsn, batch.batch_id)
        [(created,)] = execute(dsn, "SELECT created_at FROM learning.batches WHERE id = %s", (str(batch.batch_id),))
        await release_batch(store, BLUE, batch.batch_id, actor=ACTOR)
    assert parked["parked_at"] >= created
    assert row(dsn, batch.batch_id)["parked_at"] is None


# --- paging: the cursors stay valid ---------------------------------------------------------------------------------


async def test_paging_an_item_cursor_stays_valid_across_a_release_after_it_and_a_new_hold_above_it(dsn):
    """Page one of the held list, release an item after the cursor and hold a new one: the next page is the rows after the cursor less the released one; the new row is only above it. (Paging)"""
    for key in ("i1", "i2", "i3", "i4"):
        await _held_at_ceiling(dsn, BLUE, key)
    async with learning_store(dsn) as store:
        page = await store.set_aside(BLUE, status="held", limit=2)
        assert [i.key for i in page] == ["i4", "i3"], "premise: one transaction each, newest first"
        cursor = (page[-1].updated_at, page[-1].id)
        [released] = [i for i in await store.work(BLUE) if i.key == "i1"]
        await release_item(store, BLUE, released.id)
        await _held_at_ceiling(dsn, BLUE, "i5")
        rest = await store.set_aside(BLUE, status="held", after=cursor, limit=50)
        whole = await store.set_aside(BLUE, status="held", limit=50)
    assert [i.key for i in rest] == ["i2"]
    assert [i.key for i in whole] == ["i5", "i4", "i3", "i2"]


async def test_paging_a_parked_cursor_stays_valid_across_a_release_after_it_and_a_re_park_keeps_its_place(dsn):
    """Three parked reverts, page one of two, release the oldest: the next page is the middle one alone; parked again, the oldest is back last, by `created_at`. (Paging, accepted trade-off)"""
    async with learning_store(dsn) as store:
        ids = []
        for _ in range(3):
            revert = await store.claim_revert(BLUE, owner="host-a")
            park(dsn, revert.batch_id)
            ids.append(revert.batch_id)
        [newest] = await store.parked(BLUE, limit=1)
        assert newest.id == ids[2], "premise: newest created first"
        await release_batch(store, BLUE, ids[0], actor=ACTOR)
        rest = await store.parked(BLUE, after=(newest.created_at, newest.id), limit=50)
        assert [b.id for b in rest] == [ids[1]]
        park(dsn, ids[0])
        again = await store.parked(BLUE, limit=50)
    assert [b.id for b in again] == [ids[2], ids[1], ids[0]]
