"""#1278 A4: #1414's feedback subsystem on the store: its three tables, the tick lease, the item-less registry batch of lane
`feedback`, offboarding, and the cutover's refusal while a feedback record exists.

The store verbs on a real PostgreSQL, named as A4's interface requests: `enqueue_feedback_issue`, `begin_feedback_tick` /
`renew_feedback_tick` / `end_feedback_tick` (`FeedbackHeld`), `record_feedback_issue`, `judge_comments`,
`advance_comment_cursor`, `feedback_issues`, `feedback_comments`, `count_failed_answer`, `record_decision`, `settle_entry`,
`mark_settled`, `claim_registry`. Each case reads the rows back through the store's views or the catalog. What the tick
does with these verbs is `tests/learning/feedback_1414/`.
"""
from __future__ import annotations

import contextlib

import pytest

from defender.tests.learning.store_1278.test_offboarding_1278 import (  # noqa: F401 — fixtures and helpers
    _learning_rows_of,
    _offboard,
    lifecycle,
)
from defender.tests.support.jobs._jobs1342 import move_tenant, register_tenant
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    ONE,
    changes_of,
    finding,
    lapse_lease,
    learning_store,
    oid,
    store_mod,
)
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1278-fb-blue")
GREEN = fixture_uuid("tenant:1278-fb-green")
FEEDBACK_LANE = "feedback"
THREE_TABLES = ("feedback_issues", "feedback_comments", "feedback_tick")
ALL_KINDS = {**ONE, "feedback_instruction": 1}


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


def comment(cid: int, *, author: str = "ann", body: str = "check the VPN log first") -> dict:
    return {"comment_id": cid, "author": author, "created": "2026-11-10T10:00:00Z", "body": body,
            "issue_url": "https://forge.invalid/issues/7"}


def decision(*, instruction: str | None = None, approved: tuple = ()) -> dict:
    return {"approved": list(approved), "review_by": None, "instruction": instruction, "no_change": None,
            "unapprovable": None}


def entry(index: int, issue: int, cid: int) -> dict:
    return {"index": index, "lookup": {"actor": "a", "host": "h", "pattern": "p"}, "id": f"fb-{issue}-{cid}-{index + 1}",
            "settled": None}


async def tick(store, tenant=BLUE, owner="host-a"):
    held = await store.begin_feedback_tick(tenant, owner=owner)
    assert held is not None
    return held


async def with_issue(store, tenant=BLUE, run="run-1", number=7):
    """A tick lease, a request filed and its issue recorded: `(held, run id)`."""
    await store.enqueue_feedback_issue(tenant, run, "case-1", outcome="inconclusive", lookups=[])
    held = await tick(store, tenant)
    assert await store.record_feedback_issue(held, run, number) is True
    return held, run


def instruction_row(cid: int, text: str = "check the VPN log first") -> dict:
    return {"comment_id": str(cid), "issue": 7, "author": "ann", "case_id": "case-1", "instruction": text}


# --- the tables (A4 data model) --------------------------------------------------------------------------------------


@pytest.mark.parametrize("table", THREE_TABLES)
async def test_o11_each_feedback_table_carries_the_tenant_as_a_foreign_key_and_leads_its_primary_key_with_it(dsn, table):
    """`feedback_issues`, `feedback_comments` and `feedback_tick` each have a `tenant_id` foreign key to `tenancy.tenants` and the tenant first in the primary key. (O11, R1-SCH)"""
    fks = execute(dsn, """
        SELECT a.attname FROM pg_constraint k JOIN pg_class t ON t.oid = k.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace JOIN pg_class rt ON rt.oid = k.confrelid
        JOIN pg_namespace rn ON rn.oid = rt.relnamespace
        JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
        WHERE k.contype = 'f' AND n.nspname = 'learning' AND t.relname = %s AND rn.nspname || '.' || rt.relname = 'tenancy.tenants'""",
                  (table,))
    assert [c for (c,) in fks] == ["tenant_id"], table
    [(pk_first,)] = execute(dsn, """
        SELECT a.attname FROM pg_constraint k JOIN pg_class t ON t.oid = k.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
        WHERE k.contype = 'p' AND n.nspname = 'learning' AND t.relname = %s""", (table,))
    assert pk_first == "tenant_id"


async def test_o11_the_feedback_lane_and_the_registry_kind_are_admitted_by_the_batch_constraints(dsn):
    """A registry batch of lane `feedback` can exist (the lane and kind checks admit them); an unknown lane or kind still cannot. (O11, Schema)"""
    async with learning_store(dsn) as store:
        held = await tick(store)
        registry = await store.claim_registry(held)
    [batch] = [b for b in (await _batches(dsn, BLUE))]
    assert (batch.lane, batch.kind, batch.id) == (FEEDBACK_LANE, "registry", registry.batch_id)
    with pytest.raises(Exception):  # noqa: B017, PT011 — a constraint violation, whichever driver class carries it
        execute(dsn, "UPDATE learning.batches SET lane = 'no-such-lane' WHERE id = %s", (registry.batch_id,))
    with pytest.raises(Exception):  # noqa: B017, PT011
        execute(dsn, "UPDATE learning.batches SET kind = 'no-such-kind' WHERE id = %s", (registry.batch_id,))


async def _batches(dsn, tenant):
    async with learning_store(dsn) as store:
        return list(await store.batches(tenant))


# --- run end's request ---------------------------------------------------------------------------------------------------


async def test_f1_a_request_is_a_row_with_no_issue_filed_once_per_run_and_kept_per_tenant(dsn):
    """`enqueue_feedback_issue` inserts a row with `issue_number` None and answers True; the same run again answers False and changes nothing; another tenant's identical run id is its own row. (F1, P8)"""
    lookups = [{"actor": "svc", "host": "db", "pattern": "p"}]
    async with learning_store(dsn) as store:
        assert await store.enqueue_feedback_issue(BLUE, "run-1", "case-1", outcome="aborted", lookups=lookups) is True
        [row] = await store.feedback_issues(BLUE)
        assert (row.run_id, row.case_id, row.outcome, row.issue_number, list(row.lookups)) == (
            "run-1", "case-1", "aborted", None, lookups)
        assert await store.enqueue_feedback_issue(BLUE, "run-1", "case-OTHER", outcome="benign", lookups=[]) is False
        assert await store.feedback_issues(BLUE) == [row]
        assert await store.enqueue_feedback_issue(GREEN, "run-1", "case-1", outcome="aborted", lookups=lookups) is True
        assert len(await store.feedback_issues(GREEN)) == 1
        assert await store.feedback_issues(BLUE) == [row]


@pytest.mark.parametrize("state", ["offboarding", "offboarded"])
async def test_o6_a_tenant_off_active_takes_no_new_feedback_request_and_an_active_one_beside_it_does(dsn, state):
    """Off active, `enqueue_feedback_issue` raises `TenantInactive` and inserts no row. (O6, F1)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        move_tenant(dsn, BLUE, state=state)
        with pytest.raises(S.TenantInactive):
            await store.enqueue_feedback_issue(BLUE, "run-1", "case-1", outcome="aborted", lookups=[])
        assert await store.feedback_issues(BLUE) == []
        assert await store.enqueue_feedback_issue(GREEN, "run-1", "case-1", outcome="aborted", lookups=[]) is True


async def test_f1_a_request_the_store_cannot_hold_is_refused_whole(dsn):
    """A lookup with U+0000 (jsonb refuses it) raises `ItemRefused` and files nothing. (F1, A4 'text the store cannot hold')"""
    S = store_mod()
    async with learning_store(dsn) as store:
        with pytest.raises(S.ItemRefused):
            await store.enqueue_feedback_issue(BLUE, "run-1", "case-1", outcome="aborted",
                                               lookups=[{"actor": "a", "host": "h", "pattern": "x\x00y"}])
        assert await store.feedback_issues(BLUE) == []


# --- the tick lease (O12) ------------------------------------------------------------------------------------------------


async def test_o12_one_tick_per_tenant_a_live_holder_keeps_it_and_another_tenant_is_independent(dsn):
    """A second `begin_feedback_tick` for the tenant answers None while the first lease is live; another tenant begins at once; after the clean end the next begins. (O12)"""
    async with learning_store(dsn) as store:
        first = await store.begin_feedback_tick(BLUE, owner="host-a")
        assert first is not None
        assert await store.begin_feedback_tick(BLUE, owner="host-b") is None
        assert await store.begin_feedback_tick(GREEN, owner="host-b") is not None
        await store.renew_feedback_tick(first)
        await store.end_feedback_tick(first)
        assert await store.begin_feedback_tick(BLUE, owner="host-b") is not None, "a clean end releases at once"


async def test_o12_a_lapsed_tick_is_taken_over_only_after_lease_and_grace_and_the_old_holder_is_fenced(dsn):
    """Within grace the lease is still not takeable; past it a new holder gets token + 1, and the old holder's renewal and every write raise `LeaseLost` and change nothing. (O12, G-T1)"""
    S = store_mod()
    async with learning_store(dsn, lease=60, grace=60) as store:
        old, run = await with_issue(store)
        execute(dsn, "UPDATE learning.feedback_tick SET lease_expiry = now() - interval '1 second' WHERE tenant_id = %s", (BLUE,))
        assert await store.begin_feedback_tick(BLUE, owner="host-b") is None, "taken over within the grace"
        execute(dsn, "UPDATE learning.feedback_tick SET lease_expiry = now() - interval '1 hour' WHERE tenant_id = %s", (BLUE,))
        new = await store.begin_feedback_tick(BLUE, owner="host-b")
        assert new is not None
        assert new.token == old.token + 1

        before = (await store.feedback_issues(BLUE), await store.feedback_comments(BLUE), await store.work(BLUE))
        stale_calls = [
            lambda: store.renew_feedback_tick(old),
            lambda: store.record_feedback_issue(old, run, 99),
            lambda: store.judge_comments(old, run, taken=[comment(1)], judged=[1]),
            lambda: store.advance_comment_cursor(old, "2026-11-11T00:00:00Z"),
            lambda: store.count_failed_answer(old, 1),
            lambda: store.record_decision(old, 1, decision(instruction="x"), instruction=instruction_row(1, "x")),
            lambda: store.settle_entry(old, 1, "fb-7-1-1", {"how": "covered", "by": "tk-1"}),
            lambda: store.mark_settled(old, 1),
            lambda: store.claim_registry(old),
        ]
        for stale in stale_calls:
            with pytest.raises(S.LeaseLost):
                await stale()
        assert (await store.feedback_issues(BLUE), await store.feedback_comments(BLUE), await store.work(BLUE)) == before
        assert await store.batches(BLUE) == []
        with contextlib.suppress(S.LeaseLost):
            await store.end_feedback_tick(old)  # a stale holder's clean end is no release of the new holder's lease
        await store.renew_feedback_tick(new)  # control: the new holder goes on


async def test_o12_a_cancel_is_a_stop_for_the_holder_and_for_nobody_else(dsn):
    """`request_cancel` sets the tenant's tick cancel: the holder's next `renew_feedback_tick` raises `Stop` (not a lost lease), another tenant's holder goes on, and a clean end then lets the next tick begin. (O12, P9, Offboarding)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        mine = await tick(store, BLUE)
        other = await tick(store, GREEN)
        await store.request_cancel(BLUE)

        with pytest.raises(S.Stop) as stop:
            await store.renew_feedback_tick(mine)
        assert not isinstance(stop.value, S.LeaseLost)
        await store.renew_feedback_tick(other)
        await store.end_feedback_tick(mine)
        move_tenant(dsn, BLUE, state="offboarding")
        with pytest.raises(S.TenantInactive):
            await store.begin_feedback_tick(BLUE, owner="host-b")


async def test_o12_a_tenant_off_active_gets_no_feedback_lease(dsn):
    """`begin_feedback_tick` for a tenant off active raises `TenantInactive` and takes no lease row. (O12, O6)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        move_tenant(dsn, BLUE, state="offboarding")
        with pytest.raises(S.TenantInactive):
            await store.begin_feedback_tick(BLUE, owner="host-a")
    assert execute(dsn, "SELECT count(*) FROM learning.feedback_tick WHERE tenant_id = %s", (BLUE,)) == [(0,)]


# --- issues, comments, decisions: one fact is one row that moves forward (P8) -------------------------------------------


async def test_p8_an_issue_is_recorded_by_compare_and_set_and_its_comments_are_judged_in_one_transaction(dsn):
    """`record_feedback_issue` answers True once and False after (the number stays); `judge_comments` stores the comments taken in, adds every judged id (taken or passed over) and sets `listed`, in (issue, comment id) order; a repeat adds nothing. (F2, P8)"""
    async with learning_store(dsn) as store:
        held, run = await with_issue(store, number=7)
        assert await store.record_feedback_issue(held, run, 8) is False
        [row] = await store.feedback_issues(BLUE)
        assert (row.issue_number, row.listed, list(row.judged_comment_ids)) == (7, False, [])

        await store.judge_comments(held, run, taken=[comment(30), comment(10)], judged=[10, 20, 30], listed=True)
        [row] = await store.feedback_issues(BLUE)
        assert (row.listed, sorted(row.judged_comment_ids)) == (True, [10, 20, 30])
        got = await store.feedback_comments(BLUE)
        assert [c.comment_id for c in got] == [10, 30], "comment 20 was passed over: only its id is kept"
        assert (got[0].run_id, got[0].author, got[0].body, got[0].attempts, got[0].decision, got[0].settled) == (
            run, "ann", "check the VPN log first", 0, None, False)

        await store.judge_comments(held, run, taken=[comment(10, body="rewritten")], judged=[10])
        again = await store.feedback_comments(BLUE)
        assert [(c.comment_id, c.body) for c in again] == [(10, "check the VPN log first"), (30, "check the VPN log first")], \
            "a comment already taken in was taken in again"


async def test_p8_the_cursor_moves_forward_and_the_next_tick_begins_from_it(dsn):
    """`advance_comment_cursor` is what the next `begin_feedback_tick` reports as `comments_since`; it never moves back. (F2 step 2)"""
    async with learning_store(dsn) as store:
        first = await tick(store)
        assert first.comments_since is None
        await store.advance_comment_cursor(first, "2026-11-10T12:00:00Z")
        await store.advance_comment_cursor(first, "2026-11-10T09:00:00Z")
        await store.end_feedback_tick(first)
        second = await tick(store)
        assert str(second.comments_since).startswith("2026-11-10T12:00:00") or "2026-11-10 12:00:00" in str(second.comments_since)


async def test_p8_failed_answers_are_counted_one_by_one_per_comment(dsn):
    """`count_failed_answer` answers 1, 2, 3 for one comment and counts another comment apart; the row's `attempts` follows. (A4 ceiling, O9)"""
    async with learning_store(dsn) as store:
        held, run = await with_issue(store)
        await store.judge_comments(held, run, taken=[comment(1), comment(2)], judged=[1, 2])
        assert [await store.count_failed_answer(held, 1) for _ in range(3)] == [1, 2, 3]
        assert await store.count_failed_answer(held, 2) == 1
        assert {c.comment_id: c.attempts for c in await store.feedback_comments(BLUE)} == {1: 3, 2: 1}


async def test_p8_a_decision_and_its_instruction_row_are_one_transaction(dsn):
    """`record_decision` with instruction text stores the decision and one `feedback_instruction` item keyed by the comment id, waiting, citing the framing run; with none it stores only the decision; a second recording adds no second item. (F2 step 3, D11)"""
    async with learning_store(dsn) as store:
        held, run = await with_issue(store)
        await store.judge_comments(held, run, taken=[comment(1), comment(2)], judged=[1, 2])
        await store.record_decision(held, 1, decision(instruction="do x", approved=(entry(0, 7, 1),)),
                                    instruction=instruction_row(1, "do x"))
        await store.record_decision(held, 2, decision(), instruction=None)

        by = {c.comment_id: c for c in await store.feedback_comments(BLUE)}
        assert by[1].decision["instruction"] == "do x"
        assert by[1].decision["approved"][0]["id"] == "fb-7-1-1"
        assert by[2].decision is not None
        items = {i.key: i for i in await store.work(BLUE) if i.kind == "feedback_instruction"}
        assert list(items) == ["1"]
        assert (items["1"].status, dict(items["1"].payload)) == ("waiting", instruction_row(1, "do x"))

        await store.record_decision(held, 1, decision(instruction="do x"), instruction=instruction_row(1, "do x"))
        assert [i.key for i in await store.work(BLUE) if i.kind == "feedback_instruction"] == ["1"]


async def test_p8_an_instruction_item_is_claimed_into_an_author_batch_at_one_item_and_no_other_tenant_sees_it(dsn):
    """A waiting `feedback_instruction` item is claimed by the author lane at threshold 1, and only for its tenant. (D11, D8)"""
    async with learning_store(dsn) as store:
        held, run = await with_issue(store)
        await store.judge_comments(held, run, taken=[comment(1)], judged=[1])
        await store.record_decision(held, 1, decision(instruction="do x"), instruction=instruction_row(1, "do x"))
        assert await store.claim(GREEN, AUTHOR_LANE, owner="host-b", thresholds=ALL_KINDS) is None
        claim = await store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ALL_KINDS)
        assert [(k, key) for k, key, _p in claim.items] == [("feedback_instruction", "1")]


async def test_p8_an_entry_is_settled_by_compare_and_set_and_a_reply_by_mark_settled(dsn):
    """`settle_entry` answers True the first time and False after (the first settlement stays); `mark_settled` sets the comment's `settled`. (F2 steps 4-5, P6)"""
    async with learning_store(dsn) as store:
        held, run = await with_issue(store)
        await store.judge_comments(held, run, taken=[comment(1)], judged=[1])
        await store.record_decision(held, 1, decision(approved=(entry(0, 7, 1),)), instruction=None)
        assert await store.settle_entry(held, 1, "fb-7-1-1", {"how": "drafted", "pr": 5}) is True
        assert await store.settle_entry(held, 1, "fb-7-1-1", {"how": "not-draftable", "why": "later"}) is False
        [c] = await store.feedback_comments(BLUE)
        assert c.decision["approved"][0]["settled"] == {"how": "drafted", "pr": 5}
        assert c.settled is False
        await store.mark_settled(held, 1)
        [c] = await store.feedback_comments(BLUE)
        assert c.settled is True


@pytest.mark.parametrize("verb", ["judge_comments", "record_decision"])
async def test_o6_a_tenant_that_went_off_active_during_the_tick_gets_no_new_comment_and_no_instruction_row(dsn, verb):
    """With the tenant off active after the lease was taken, `judge_comments` and `record_decision` (with its instruction) raise `TenantInactive` and insert no comment, decision or item. (O6, A4 offboarding)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        held, run = await with_issue(store)
        await store.judge_comments(held, run, taken=[comment(1)], judged=[1])
        before = (await store.feedback_comments(BLUE), await store.work(BLUE))
        move_tenant(dsn, BLUE, state="offboarding")
        attempt = (store.judge_comments(held, run, taken=[comment(2)], judged=[2]) if verb == "judge_comments"
                   else store.record_decision(held, 1, decision(instruction="x"), instruction=instruction_row(1, "x")))
        with pytest.raises(S.TenantInactive):
            await attempt
        assert (await store.feedback_comments(BLUE), await store.work(BLUE)) == before


# --- tenant scope --------------------------------------------------------------------------------------------------------


async def test_o2_one_tenants_feedback_verbs_never_show_or_touch_another_tenants_rows(dsn):
    """With both tenants holding issues, comments and decisions, every feedback view of BLUE shows only BLUE's rows and a GREEN holder's writes leave BLUE's byte-identical. (O2, tenant scope)"""
    async with learning_store(dsn) as store:
        blue, brun = await with_issue(store, BLUE, "run-1", 7)
        green, grun = await with_issue(store, GREEN, "run-1", 7)
        await store.judge_comments(blue, brun, taken=[comment(1)], judged=[1])
        await store.judge_comments(green, grun, taken=[comment(1, body="green")], judged=[1])
        before = (await store.feedback_issues(BLUE), await store.feedback_comments(BLUE))

        await store.record_decision(green, 1, decision(instruction="g"), instruction=instruction_row(1, "g"))
        await store.count_failed_answer(green, 1)
        await store.mark_settled(green, 1)

        assert (await store.feedback_issues(BLUE), await store.feedback_comments(BLUE)) == before
        assert [i.key for i in await store.work(BLUE) if i.kind == "feedback_instruction"] == []
        assert [c.body for c in await store.feedback_comments(GREEN)] == ["green"]


# --- the registry batch: lane `feedback`, kind `registry`, no items ---------------------------------------------------------


async def test_p6_a_registry_batch_is_item_less_holds_its_lane_and_leaves_the_author_lane_alone(dsn):
    """`claim_registry` makes a batch of lane `feedback`, kind `registry`, with no items; a second is `LaneBusy`; an author claim beside it still works; once the registry batch ends the lane is free. (P6, A4 lane)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        held = await tick(store)
        registry = await store.claim_registry(held)
        assert list(registry.items) == []
        [batch] = await store.batches(BLUE)
        assert (batch.lane, batch.kind, batch.phase) == (FEEDBACK_LANE, "registry", "working")
        with pytest.raises(S.LaneBusy):
            await store.claim_registry(held)
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        assert await store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ONE) is not None, "the registry batch blocked the author lane"

        await store.end_no_commits(registry, {})
        again = await store.claim_registry(held)
        assert again.batch_id != registry.batch_id


async def test_p6_a_registry_batch_needs_a_live_tick_lease_and_an_active_tenant(dsn):
    """`claim_registry` raises `LeaseLost` once the tick lease is gone (ended, or taken over) and `TenantInactive` off active, and inserts no batch. (P6, P2', O12)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        held = await tick(store)
        await store.end_feedback_tick(held)
        with pytest.raises(S.LeaseLost):
            await store.claim_registry(held)
        live = await tick(store)
        move_tenant(dsn, BLUE, state="offboarding")
        with pytest.raises(S.TenantInactive):
            await store.claim_registry(live)
        assert await store.batches(BLUE) == []


async def test_p6_a_registry_batch_follows_the_ordinary_holder_and_reconcile_verbs(dsn):
    """Commit, review, merge: `record_commit`, `in_review(held, pr, {})` and `end_review(published=(), held=())` carry a registry batch to ended/merged; a closed PR ends it `closed` and never revives anything. (P6, r8 reconcile)"""
    async with learning_store(dsn) as store:
        held = await tick(store)
        registry = await store.claim_registry(held)
        await store.record_commit(registry, oid(1), oid(2), oid(3), changes_of("agent/skills/tacit-knowledge/registry.yaml"))
        await store.in_review(registry, 11, {})
        [batch] = await store.batches(BLUE)
        assert (batch.phase, batch.pr_number) == ("in_review", 11)
        await store.end_review(BLUE, registry.batch_id, expect_phase="in_review", outcome="merged", published=[], held=[])
        [batch] = await store.batches(BLUE)
        assert (batch.phase, batch.outcome) == ("ended", "merged")
        second = await store.claim_registry(held)
        await store.record_commit(second, oid(4), oid(2), oid(3), changes_of("agent/skills/tacit-knowledge/registry.yaml"))
        await store.in_review(second, 12, {})
        await store.end_review(BLUE, second.batch_id, expect_phase="in_review", outcome="closed", published=[], held=[])
        assert {(b.pr_number, b.outcome) for b in await store.batches(BLUE)} == {(11, "merged"), (12, "closed")}
        assert [b.replaces for b in await store.batches(BLUE)] == [None, None], "a closed registry PR made a replacement"


async def test_p6_a_lapsed_registry_batch_is_taken_over_only_after_lease_and_grace_and_a_clean_stop_without_commits_frees_the_lane(dsn):
    """A lapsed working registry batch: `take_over` raises `NotLapsed` while live, succeeds after lease + grace; `abandon_clean` with no commits ends it abandoned and frees the lane at once. (P6, r8 recovery)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        held = await tick(store)
        registry = await store.claim_registry(held)
        with pytest.raises(S.NotLapsed):
            await store.take_over(BLUE, registry.batch_id, owner="host-b")
        lapse_lease(dsn, registry.batch_id)
        taken = await store.take_over(BLUE, registry.batch_id, owner="host-b")
        assert taken.batch_id == registry.batch_id
        await store.abandon_clean(taken)
        [batch] = await store.batches(BLUE)
        assert (batch.phase, batch.outcome) == ("ended", "abandoned")
        assert (await store.claim_registry(held)).batch_id != registry.batch_id


async def test_o6_a_cancel_stops_a_registry_batch_holder_like_any_other(dsn):
    """`request_cancel` marks the tenant's working registry batch too; its holder's next `renew` is a stop. (Offboarding, O3)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        held = await tick(store)
        registry = await store.claim_registry(held)
        await store.request_cancel(BLUE)
        assert [b.cancel_requested for b in await store.batches(BLUE)] == [True]
        with pytest.raises(S.Stop):
            await store.renew(registry)


# --- offboarding (O6) -----------------------------------------------------------------------------------------------------


async def _populate_feedback(store, tenant: str, tag: str) -> None:
    held = await tick(store, tenant, owner=f"host-{tag}")
    run = f"run-{tag}"
    await store.enqueue_feedback_issue(tenant, f"queued-{tag}", f"case-q-{tag}", outcome="aborted", lookups=[])
    await store.enqueue_feedback_issue(tenant, run, f"case-{tag}", outcome="aborted", lookups=[])
    await store.record_feedback_issue(held, run, 7)
    await store.judge_comments(held, run, taken=[comment(1), comment(2)], judged=[1, 2, 3], listed=True)
    await store.advance_comment_cursor(held, "2026-11-10T12:00:00Z")
    await store.record_decision(held, 1, decision(instruction="do x", approved=(entry(0, 7, 1),)),
                                instruction=instruction_row(1, "do x"))
    await store.claim_registry(held)


async def test_o6_purge_removes_every_feedback_row_of_the_tenant_and_none_of_another(dsn):
    """After `purge` BLUE has no row in `feedback_issues`, `feedback_comments` or `feedback_tick` (comments before issues: the foreign key), nor any instruction item or registry batch; GREEN's are as they were. (O6, A4 Offboarding)"""
    async with learning_store(dsn) as store:
        await _populate_feedback(store, BLUE, "b")
        await _populate_feedback(store, GREEN, "g")
        before = _learning_rows_of(dsn, GREEN)
        mine = _learning_rows_of(dsn, BLUE)
        assert all(mine[t] > 0 for t in THREE_TABLES), f"premise: the scene plants every feedback table ({mine})"
        green_view = ([(c.comment_id, c.body) for c in await store.feedback_comments(GREEN)],
                      [(i.run_id, i.issue_number) for i in await store.feedback_issues(GREEN)])

        await store.purge(BLUE)

        after = _learning_rows_of(dsn, BLUE)
        assert sum(after.values()) == 0, after
        assert await store.feedback_issues(BLUE) == []
        assert await store.feedback_comments(BLUE) == []
        assert _learning_rows_of(dsn, GREEN) == before
        assert ([(c.comment_id, c.body) for c in await store.feedback_comments(GREEN)],
                [(i.run_id, i.issue_number) for i in await store.feedback_issues(GREEN)]) == green_view


def _seed_tick_lease(dsn: str, tenant: str):
    import anyio

    async def go():
        async with learning_store(dsn) as store:
            return await tick(store, tenant, owner="live-host")
    return anyio.run(go)


def test_offboarding_a_live_feedback_tick_is_told_to_stop_and_the_purge_waits_for_its_clean_stop(lifecycle, dsn):  # noqa: F811 — the imported fixture
    """A feedback tick renewing its lease sees the cancel as a stop and ends; only then are the rows purged, within the teardown wait. (O12, O6, G-T2)"""
    import threading
    import time

    import anyio

    world = lifecycle
    tenant = world.active_tenant()
    register_tenant(dsn, tenant)
    held = _seed_tick_lease(dsn, tenant)
    stopped = threading.Event()
    ended: list[str] = []

    def holder() -> None:
        async def run() -> None:
            S = store_mod()
            async with learning_store(dsn) as store:
                while not stopped.is_set():
                    try:
                        await store.renew_feedback_tick(held)
                    except S.LeaseLost:
                        return
                    except S.Stop:
                        await store.end_feedback_tick(held)
                        ended.append("clean")
                        return
                    await anyio.sleep(0.05)
        anyio.run(run)

    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        _offboard(world, dsn, tenant)
        assert time.monotonic() - started < 30
    finally:
        stopped.set()
        thread.join(timeout=10)

    assert ended == ["clean"], "the feedback tick never saw the cancel before its rows went"
    assert sum(_learning_rows_of(dsn, tenant).values()) == 0


def test_offboarding_a_feedback_tick_that_ignores_the_stop_past_the_time_limit_fails_the_step_and_nothing_is_purged(lifecycle, dsn, tmp_path, data_root):  # noqa: F811 — the imported fixture
    """A feedback holder that keeps renewing through the cancel outlasts `teardown_wait`: the step fails, the rows stay; once it is gone and its lease lapsed the retry purges. (G-T2, O6)"""
    import contextlib
    import threading

    import anyio

    from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config

    world = lifecycle
    world.host_actor = world.new_host(world.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=1.0))
    tenant = world.active_tenant()
    register_tenant(dsn, tenant)
    held = _seed_tick_lease(dsn, tenant)
    stopped = threading.Event()

    def stubborn() -> None:
        async def run() -> None:
            S = store_mod()
            async with learning_store(dsn) as store:
                while not stopped.is_set():
                    try:
                        await store.renew_feedback_tick(held)
                    except S.Stop:
                        pass
                    except S.LeaseLost:
                        return
                    await anyio.sleep(0.05)
        anyio.run(run)

    thread = threading.Thread(target=stubborn, daemon=True)
    thread.start()
    try:
        asked = world.ops.post(f"/admin/tenants/{tenant}/offboard")
        assert asked.status_code == 202, asked.text
        move_tenant(dsn, tenant, state="offboarding")
        with contextlib.suppress(Exception):
            world.drive(limit=8)
        assert world.record(tenant).state != "offboarded", "the offboarding finished under a live feedback lease"
        assert sum(_learning_rows_of(dsn, tenant).values()) > 0, "rows purged under a live feedback lease"
    finally:
        stopped.set()
        thread.join(timeout=10)

    execute(dsn, "UPDATE learning.feedback_tick SET lease_expiry = now() - interval '1 hour' WHERE tenant_id = %s", (tenant,))
    world.drive()
    assert world.record(tenant).state == "offboarded"
    assert sum(_learning_rows_of(dsn, tenant).values()) == 0


async def test_d5_the_same_key_in_a_finding_and_a_feedback_instruction_is_two_items_each_with_its_own_fate(dsn):
    """Finding `101` and instruction `101` are two rows, claimed together; an outcome for one kind moves only that kind's row. (A2 D7/H16 extended: matched per (kind, key), never by key alone)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("101")], kind="finding")
        held, run = await with_issue(store)
        await store.judge_comments(held, run, taken=[comment(101)], judged=[101])
        await store.record_decision(held, 101, decision(instruction="do x"), instruction=instruction_row(101, "do x"))
        assert sorted((i.kind, i.key) for i in await store.work(BLUE)) == [("feedback_instruction", "101"), ("finding", "101")]

        claim = await store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ALL_KINDS)
        assert sorted((k, key) for k, key, _p in claim.items) == [("feedback_instruction", "101"), ("finding", "101")]
        await store.in_review(claim, 3, {("finding", "101"): S.Outcome.waiting()})

        by = {(i.kind, i.key): i.status for i in await store.work(BLUE)}
        assert by[("finding", "101")] == "waiting", "the outcome of one kind moved the other"
        assert by[("feedback_instruction", "101")] == "in_batch"
