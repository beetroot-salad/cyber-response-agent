"""#1278 work items in the learning store: kinds, keys, dedup, coalescing, attempts and a person's exit.

Driven through the store's verbs on a real PostgreSQL (`interface.md`): the rows `work(tenant)` shows are
the observation. Outcomes are applied by the holder verbs the curators' fates reach (D1); what each real
curator decides is `test_1278_curator_fates.py`.
"""
from __future__ import annotations

import contextlib

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE, LEAD_LANE, ONE, finding, lapse_lease, learning_store, store_mod, world_finding)
from defender.tests.support.shared._fixture_uuid import fixture_uuid

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1278-items-blue")
GREEN = fixture_uuid("tenant:1278-items-green")


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


def outcome(name: str, *reason: str):
    """`Outcome.<name>(reason?)`: the store's outcome values (interface request: callable constructors)."""
    return getattr(store_mod().Outcome, name)(*reason)


def pitfall(pid: str, **extra):
    return {"schema_version": 1, "pitfall_id": pid, "source_run": "r", "system": "elastic", "query_id": "elastic.esql",
            "goal": "g", "executed_query": "bad pipe", "stderr_digest": "exit=1; mismatched input",
            "error_class": "agent-fixable", **extra}


async def items(store, tenant=BLUE):
    return {(i.kind, i.key): i for i in await store.work(tenant)}


def keys(claim) -> list[tuple[str, str]]:
    return sorted((kind, key) for kind, key, _payload in claim.items)


async def claim_author(store, owner="host-a", tenant=BLUE):
    return await store.claim(tenant, AUTHOR_LANE, owner=owner, thresholds=ONE)


# --- kinds, keys, lanes ---------------------------------------------------------------------------------------


async def test_kinds_a_kind_has_its_lane_and_a_claim_takes_only_its_lanes_kinds(dsn):
    """Findings and questioner findings are the author lane's; pitfalls and requests the lead lane's. (work_items kinds)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        await store.publish_findings(BLUE, "run-1", [world_finding("q1")], kind="questioner_finding")
        await store.add_pitfall(BLUE, pitfall("p1"))
        await store.enqueue_request(BLUE, "run-9", "case-9", {"case": "case-9"})
        assert sorted(items_ := await items(store)) == [
            ("curation_request", "run-9"), ("finding", "f1"), ("pitfall", "p1"), ("questioner_finding", "q1")], items_

        author = await claim_author(store)
        assert keys(author) == [("finding", "f1"), ("questioner_finding", "q1")]
        lead = await store.claim(BLUE, LEAD_LANE, owner="host-a", thresholds=ONE)
        assert keys(lead) == [("curation_request", "run-9"), ("pitfall", "p1")], "the lead lane takes its own kinds"


async def test_kinds_one_id_in_two_kinds_is_two_rows(dsn):
    """The item key is unique within its kind, not across kinds. (work_items primary key)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("same")], kind="finding")
        counts = await store.publish_findings(BLUE, "run-1", [world_finding("same")], kind="questioner_finding")
        assert tuple(counts) == (1, 0), "a questioner finding is not a duplicate of the defender finding with its id"
        assert sorted(await items(store)) == [("finding", "same"), ("questioner_finding", "same")]


async def test_items_tenants_keep_their_own_rows_for_one_key(dsn):
    """The same finding id in two tenants is two rows; neither sees the other's. (work_items primary key, O6)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        assert tuple(await store.publish_findings(GREEN, "run-2", [finding("f1")], kind="finding")) == (1, 0)
        assert [i.key for i in await store.work(BLUE)] == [i.key for i in await store.work(GREEN)] == ["f1"]


# --- finding ids are unique for good ------------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["published", "skipped", "dead"])
async def test_a_finding_id_is_unique_for_good_past_published_skipped_and_dead(dsn, how):
    """Past any end it can reach, a republished finding id adds nothing and changes no row. (work_items, O14)"""
    reason = {"published": (), "skipped": ("duplicate",), "dead": ("unkeyable",)}[how]
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        claim = await claim_author(store)
        await store.end_no_commits(claim, {("finding", "f1"): outcome(how, *reason)})
        before = (await items(store))[("finding", "f1")]
        assert before.status == how, "premise: the item reached its end"

        counts = await store.publish_findings(BLUE, "run-2", [finding("f1"), finding("f2")], kind="finding")

        assert tuple(counts) == (1, 1)
        after = await items(store)
        assert (after[("finding", "f1")].status, after[("finding", "f1")].reason) == (before.status, before.reason)
        assert after[("finding", "f2")].status == "waiting", "control: a new id is still queued"


async def test_a_finding_published_by_a_merged_batch_stays_unique(dsn):
    """A finding published by a merge is not queued again by a republish. (work_items, O14)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        claim = await claim_author(store)
        await store.in_review(claim, 7, {})
        await store.end_review(BLUE, claim.batch_id, expect_phase="in_review", outcome="merged",
                               published=[("finding", "f1")], held=[])
        assert tuple(await store.publish_findings(BLUE, "run-2", [finding("f1")], kind="finding")) == (0, 1)
        assert (await items(store))[("finding", "f1")].status == "published"


# --- pitfalls and the digest key -------------------------------------------------------------------------------


async def test_a_repeated_pitfall_id_is_ignored_but_one_mistake_is_a_row_per_occurrence(dsn):
    """The same pitfall id adds nothing; two ids for one mistake are two rows. (work_items pitfalls)"""
    async with learning_store(dsn) as store:
        await store.add_pitfall(BLUE, pitfall("p1"))
        await store.add_pitfall(BLUE, pitfall("p1", goal="changed"))
        await store.add_pitfall(BLUE, pitfall("p2"))  # the same system and error digest: the same mistake
        pits = {k: i for k, i in (await items(store)).items() if k[0] == "pitfall"}
        assert sorted(pits) == [("pitfall", "p1"), ("pitfall", "p2")]
        assert {i.status for i in pits.values()} == {"waiting"}


async def test_a_row_with_no_key_takes_a_key_from_its_digest(dsn):
    """A keyless pitfall twice is one row; a different keyless pitfall is another. (work_items item key)"""
    keyless = {k: v for k, v in pitfall("x").items() if k != "pitfall_id"}
    other = {**keyless, "goal": "another goal"}
    async with learning_store(dsn) as store:
        await store.add_pitfall(BLUE, keyless)
        await store.add_pitfall(BLUE, dict(keyless))
        assert len(await store.work(BLUE)) == 1
        await store.add_pitfall(BLUE, other)
        rows = await store.work(BLUE)
        assert len(rows) == 2
        assert all(isinstance(r.key, str) and r.key for r in rows)
        assert len({r.key for r in rows}) == 2


# --- the columns: mistake key, source run -------------------------------------------------------------------------


async def test_columns_a_pitfall_keeps_its_source_run_and_its_repeats_share_a_mistake_key(dsn):
    """Same system and error digest -> equal mistake keys; another digest or system -> another; source runs are stored. (input 23, 24)"""
    async with learning_store(dsn) as store:
        await store.add_pitfall(BLUE, pitfall("p1", source_run="run-a"))
        await store.add_pitfall(BLUE, pitfall("p2", source_run="run-b", goal="another goal"))
        await store.add_pitfall(BLUE, pitfall("p3", stderr_digest="exit=1; unexpected token"))
        await store.add_pitfall(BLUE, pitfall("p4", system="wazuh", query_id="wazuh.q"))
        await store.publish_findings(BLUE, "run-7", [finding("f1")], kind="finding")
        await store.publish_findings(BLUE, "run-8", [world_finding("q1")], kind="questioner_finding")
        await store.enqueue_request(BLUE, "run-9", "case-9", {"case": "case-9"})
        got = await items(store)

    mistake = {n: got[("pitfall", n)].mistake_key for n in ("p1", "p2", "p3", "p4")}
    assert mistake["p1"], "a pitfall is stored with a mistake key"
    assert mistake["p1"] == mistake["p2"], "one mistake, two occurrences: one key"
    assert len({mistake["p1"], mistake["p3"], mistake["p4"]}) == 3, "another digest or another system is another mistake"
    assert (got[("pitfall", "p1")].source_run, got[("pitfall", "p2")].source_run) == ("run-a", "run-b")
    assert (got[("finding", "f1")].source_run, got[("questioner_finding", "q1")].source_run) == ("run-7", "run-8")
    assert got[("curation_request", "run-9")].source_run == "run-9"


LEAD_THRESHOLD = {**ONE, "pitfall": 3}


def _mistakes(*digests: str, system: str = "elastic", **extra):
    """One pitfall row per digest; a repeated digest is a repeat of one mistake."""
    return [pitfall(f"p{n}", system=system, stderr_digest=d, **extra) for n, d in enumerate(digests)]


def _reducer_rows(n: int):
    from defender.knowledge import BASH_SHIM_QUERY_ID

    return [pitfall(f"p{k}", query_id=BASH_SHIM_QUERY_ID, stderr_digest="exit=1; one unchanging error") for k in range(n)]


@pytest.mark.parametrize(("rows", "opens"), [
    pytest.param(_mistakes("exit=1; same", "exit=1; same", "exit=1; same"), False, id="three rows of one mistake"),
    pytest.param(_mistakes("exit=1; one", "exit=1; one", "exit=1; two"), False, id="three rows of two mistakes"),
    pytest.param(_reducer_rows(3), False, id="three rows of one reducer mistake"),
    pytest.param(_mistakes("exit=1; one", "exit=1; two"), False, id="two mistakes"),
    pytest.param(_mistakes("exit=1; one", "exit=1; two", "exit=1; three"), True, id="three mistakes"),
    pytest.param(_mistakes("exit=1; one", "exit=1; one", "exit=1; two", "exit=1; three"), True, id="four rows of three mistakes"),
])
async def test_columns_the_pitfall_threshold_counts_mistakes_not_rows(dsn, rows, opens):
    """A threshold-3 lead lane opens on three distinct mistakes and on nothing less, however many rows repeat them. (input 56, ruling)"""
    async with learning_store(dsn) as store:
        for row in rows:
            await store.add_pitfall(BLUE, row)

        claim = await store.claim(BLUE, LEAD_LANE, owner="host-a", thresholds=LEAD_THRESHOLD)

        if opens:
            assert sorted(key for kind, key, _payload in claim.items) == sorted(r["pitfall_id"] for r in rows)
        else:
            assert claim is None, "mistakes below the threshold open no lane, however many rows they are"
            assert {i.status for i in await store.work(BLUE)} == {"waiting"}, "and the rows stay queued"


# --- a finding's key is the judge's finding_id ----------------------------------------------------------------


_NO_ID = object()


@pytest.mark.parametrize("kind", ["finding", "questioner_finding"])
@pytest.mark.parametrize("bad", [_NO_ID, None, 5, 5.5, True, "", "   ", ["f1"]],
                         ids=["missing", "null", "int", "float", "bool", "empty", "blank", "list"])
async def test_a_finding_with_no_string_id_is_refused_before_anything_is_inserted(dsn, kind, bad):
    """A missing, null, numeric, boolean, empty or listed finding_id refuses the whole publish; the good row beside it is not queued. (input 09)"""
    make = finding if kind == "finding" else world_finding
    row = {k: v for k, v in make("bad").items() if k != "finding_id"}
    if bad is not _NO_ID:
        row["finding_id"] = bad
    async with learning_store(dsn) as store:
        with pytest.raises(store_mod().ItemRefused):
            await store.publish_findings(BLUE, "run-1", [make("good"), row], kind=kind)
        assert await store.work(BLUE) == [], "nothing of the refused job was inserted"
        assert tuple(await store.publish_findings(BLUE, "run-1", [make("good")], kind=kind)) == (1, 0), "control: a keyed row is queued"


# --- a NUL is refused for the whole job, wherever it hides ------------------------------------------------------


def _nul_in(where: str):
    """A row for `kind`'s verb with a NUL at `where`: a top value, a nested value, a list item, a key, a deep key."""
    nul = "a\x00b"
    return {"top": {"goal": nul}, "nested": {"goal": {"deep": nul}}, "list": {"goal": ["ok", [nul]]},
            "key": {nul: "v"}, "deep_key": {"goal": {nul: 1}}}[where]


@pytest.mark.parametrize("where", ["top", "nested", "list", "key", "deep_key"])
@pytest.mark.parametrize("verb", ["finding", "questioner_finding", "pitfall", "request"])
async def test_a_nul_anywhere_refuses_the_whole_job_and_queues_nothing(dsn, verb, where):
    """A NUL at any depth, in any key or value, of any kind's row refuses the job; rows beside it are not queued. (input 10)"""
    async with learning_store(dsn) as store:
        refused = store_mod().ItemRefused
        if verb in ("finding", "questioner_finding"):
            make = finding if verb == "finding" else world_finding
            with pytest.raises(refused):
                await store.publish_findings(BLUE, "run-1", [make("good"), {**make("bad"), **_nul_in(where)}], kind=verb)
        elif verb == "pitfall":
            with pytest.raises(refused):
                await store.add_pitfall(BLUE, pitfall("bad", **_nul_in(where)))
        else:
            with pytest.raises(refused):
                await store.enqueue_request(BLUE, "run-1", "case-1", _nul_in(where))
        assert await store.work(BLUE) == []


# --- the same arrival twice is one ------------------------------------------------------------------------------


async def test_a_request_arriving_twice_is_one_arrival(dsn):
    """Re-enqueueing a run's request leaves what the first left, whether it waits, was superseded or is claimed. (input 25)"""
    async with learning_store(dsn) as store:
        await store.enqueue_request(BLUE, "run-1", "case-A", {"n": 1})
        once = {k: (i.status, i.reason) for k, i in (await items(store)).items()}
        assert await store.enqueue_request(BLUE, "run-1", "case-A", {"n": 1}) is False
        assert {k: (i.status, i.reason) for k, i in (await items(store)).items()} == once
        assert once == {("curation_request", "run-1"): ("waiting", None)}, "premise: the first arrival waits"

        await store.enqueue_request(BLUE, "run-2", "case-A", {"n": 2})
        superseded = {k: (i.status, i.reason) for k, i in (await items(store)).items()}
        await store.enqueue_request(BLUE, "run-1", "case-A", {"n": 1})
        assert {k: (i.status, i.reason) for k, i in (await items(store)).items()} == superseded
        assert superseded[("curation_request", "run-1")][0] == "skipped"
        assert superseded[("curation_request", "run-2")][0] == "waiting"

        assert await store.claim(BLUE, LEAD_LANE, owner="host-a", thresholds=ONE) is not None
        claimed = {k: i.status for k, i in (await items(store)).items()}
        await store.enqueue_request(BLUE, "run-2", "case-A", {"n": 2})
        assert {k: i.status for k, i in (await items(store)).items()} == claimed
        assert claimed[("curation_request", "run-2")] == "in_batch"


# --- coalescing ---------------------------------------------------------------------------------------------------


async def test_a_later_request_for_one_case_supersedes_the_waiting_one(dsn):
    """Two waiting requests for a case cannot coexist: the later run waits, the older is skipped as superseded. (coalesce key)"""
    async with learning_store(dsn) as store:
        await store.enqueue_request(BLUE, "run-1", "case-A", {"n": 1})
        await store.enqueue_request(BLUE, "run-2", "case-A", {"n": 2})
        await store.enqueue_request(BLUE, "run-3", "case-B", {"n": 3})
        got = await items(store)
        assert got[("curation_request", "run-2")].status == "waiting"
        assert got[("curation_request", "run-1")].status == "skipped"
        assert "supersed" in (got[("curation_request", "run-1")].reason or "")
        assert got[("curation_request", "run-3")].status == "waiting", "control: another case is untouched"


@pytest.mark.parametrize("exit_", ["end_no_commits", "abandon_clean"])
async def test_a_request_returning_to_waiting_beside_a_fresher_one_is_superseded(dsn, exit_):
    """Run-1's request returns to waiting after run-2's arrived: the older is skipped at that very call, never two waiting. (coalesce key, runtime)"""
    async with learning_store(dsn) as store:
        await store.enqueue_request(BLUE, "run-1", "case-A", {"n": 1})
        claim = await store.claim(BLUE, LEAD_LANE, owner="host-a", thresholds=ONE)
        assert keys(claim) == [("curation_request", "run-1")]
        await store.enqueue_request(BLUE, "run-2", "case-A", {"n": 2})
        assert (await items(store))[("curation_request", "run-2")].status == "waiting", "premise: a claimed request leaves the case free"

        if exit_ == "end_no_commits":
            await store.end_no_commits(claim, {("curation_request", "run-1"): outcome("waiting")})
        else:
            await store.abandon_clean(claim)

        got = await items(store)
        waiting = [k for k, i in got.items() if i.status == "waiting"]
        assert waiting == [("curation_request", "run-2")], got
        assert got[("curation_request", "run-1")].status == "skipped"
        assert "supersed" in (got[("curation_request", "run-1")].reason or "")


# --- attempts ---------------------------------------------------------------------------------------------------


async def test_an_attempt_is_stamped_at_claim_and_forgiven_only_by_a_clean_stop(dsn):
    """The claim counts an attempt; a clean-stop abandon forgives it, a recovery abandon does not. (attempts, D8)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        claim = await claim_author(store)
        assert (await items(store))[("finding", "f1")].attempts == 1
        await store.abandon_clean(claim)
        got = (await items(store))[("finding", "f1")]
        assert (got.status, got.attempts) == ("waiting", 0), "a deploy costs nothing"

        crashed = await claim_author(store)
        lapse_lease(dsn, crashed.batch_id)
        await store.abandon(BLUE, crashed.batch_id, by="recovery")
        got = (await items(store))[("finding", "f1")]
        assert (got.status, got.attempts) == ("waiting", 1), "a crash is counted"


async def test_crashes_to_the_ceiling_hold_the_item_for_a_person(dsn):
    """After `max_attempts` crashed claims the item is held, claimable by no one; clean stops never reach it. (attempts, O7)"""
    async with learning_store(dsn, max_attempts=3) as store:
        await store.publish_findings(BLUE, "run-1", [finding("clean"), finding("crashing")], kind="finding")
        for _ in range(5):  # clean stops: bounded by nothing
            await store.abandon_clean(await claim_author(store))
        assert {i.status for i in (await store.work(BLUE))} == {"waiting"}

        for _ in range(3):
            claim = await store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ONE)
            assert claim is not None
            lapse_lease(dsn, claim.batch_id)
            await store.abandon(BLUE, claim.batch_id, by="recovery")

        assert await store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ONE) is None
        assert {i.status for i in (await store.work(BLUE))} == {"held"}


async def test_a_person_abandon_does_not_forgive_an_attempt(dsn):
    """Only a clean stop forgives: a person's abandon holds the items, attempt still counted. (D8, O7, design Review-1 R1-F1)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        claim = await claim_author(store)
        await store.abandon(BLUE, claim.batch_id, by="person")
        got = (await items(store))[("finding", "f1")]
        assert (got.status, got.attempts) == ("held", 1), "a person's abandon always holds; stop and crash abandons (above) return items to waiting"


async def test_o7_a_persons_abandon_of_a_batch_in_review_holds_its_items(dsn):
    """A person abandons a batch that reached review: the batch ends abandoned and its items are held for a person. (O7, D8)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        claim = await claim_author(store)
        await store.in_review(claim, 7, {})
        await store.abandon(BLUE, claim.batch_id, by="person")
        [batch] = await store.batches(BLUE)
        assert (batch.phase, batch.outcome) == ("ended", "abandoned")
        assert (await items(store))[("finding", "f1")].status == "held"


# --- deferral and the item exits a holder applies -------------------------------------------------------------------------


async def test_a_deferred_item_waits_with_a_deferral_counted_and_dies_at_the_ceiling(dsn):
    """`deferred` returns the item to waiting, +1 deferral; at `max_attempts` deferrals it is dead. (D1, deferrals)"""
    async with learning_store(dsn, max_attempts=3) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        for n in (1, 2):
            claim = await claim_author(store)
            await store.end_no_commits(claim, {("finding", "f1"): outcome("deferred")})
            got = (await items(store))[("finding", "f1")]
            assert (got.status, got.deferrals) == ("waiting", n)
        claim = await claim_author(store)
        await store.end_no_commits(claim, {("finding", "f1"): outcome("deferred")})
        got = (await items(store))[("finding", "f1")]
        assert (got.status, got.deferrals) == ("dead", 3)
        assert got.reason, "a dead item names why"


async def test_deferrals_and_attempts_are_separate_counters_with_the_deferral_ceiling_of_its_own(dsn):
    """A crashed attempt between two deferrals counts toward neither ceiling's other: only the third deferral kills the item. (G-T5, schema counters)"""
    async with learning_store(dsn, max_attempts=3) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        await store.end_no_commits(await claim_author(store), {("finding", "f1"): outcome("deferred")})
        crashed = await claim_author(store)
        lapse_lease(dsn, crashed.batch_id)
        await store.abandon(BLUE, crashed.batch_id, by="recovery")
        got = (await items(store))[("finding", "f1")]
        assert (got.status, got.attempts, got.deferrals) == ("waiting", 1, 1), "a crash is no deferral and a deferral no attempt"

        await store.end_no_commits(await claim_author(store), {("finding", "f1"): outcome("deferred")})
        got = (await items(store))[("finding", "f1")]
        assert (got.status, got.attempts, got.deferrals) == ("waiting", 1, 2), "two deferrals and one crash: nothing at a ceiling of 3"

        await store.end_no_commits(await claim_author(store), {("finding", "f1"): outcome("deferred")})
        got = (await items(store))[("finding", "f1")]
        assert (got.status, got.deferrals) == ("dead", 3)


@pytest.mark.parametrize(("name", "reason", "status"), [
    ("skipped", ("duplicate",), "skipped"), ("held", ("missing_field(contrast_evidence)",), "held"),
    ("dead", ("unkeyable",), "dead"), ("published", (), "published"), ("waiting", (), "waiting")])
async def test_each_outcome_a_holder_reports_becomes_its_status_and_reason(dsn, name, reason, status):
    """Every outcome value lands as the status of the same name, a reason where it carries one. (D1)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        claim = await claim_author(store)
        await store.end_no_commits(claim, {("finding", "f1"): outcome(name, *reason)})
        got = (await items(store))[("finding", "f1")]
        assert got.status == status
        assert all(r in (got.reason or "") for r in reason)
        [batch] = await store.batches(BLUE)
        assert batch.phase == "ended", "no commits: the batch ends with its items' outcomes"


async def test_an_item_the_holder_names_no_outcome_for_returns_to_waiting(dsn):
    """An item in the claim that the holder reports nothing for goes back to waiting when the batch ends. (D8 invariant)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1"), finding("f2")], kind="finding")
        claim = await claim_author(store)
        await store.end_no_commits(claim, {("finding", "f1"): outcome("skipped", "duplicate")})
        got = await items(store)
        assert (got[("finding", "f1")].status, got[("finding", "f2")].status) == ("skipped", "waiting")
        assert all(i.status != "in_batch" for i in got.values()), "an ended batch leaves nothing in_batch"


# --- O7: a person's exit for a held item ------------------------------------------------------------------------------


async def test_o7_a_person_releases_a_held_item_and_the_next_claim_takes_it(dsn):
    """`release_held` returns a held item to waiting, claimable and not held again by what held it. (O7)"""
    async with learning_store(dsn, max_attempts=2) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        for _ in range(2):
            claim = await claim_author(store)
            lapse_lease(dsn, claim.batch_id)
            await store.abandon(BLUE, claim.batch_id, by="recovery")
        assert (await items(store))[("finding", "f1")].status == "held", "premise: held at the ceiling"

        await store.release_held(BLUE, "finding", "f1")

        assert (await items(store))[("finding", "f1")].status == "waiting"
        claim = await claim_author(store)
        assert claim is not None
        assert keys(claim) == [("finding", "f1")]
        await store.abandon_clean(claim)
        assert (await items(store))[("finding", "f1")].status == "waiting"


async def test_o7_releasing_an_item_that_is_not_held_changes_nothing(dsn):
    """A released key that is waiting, in a batch, published or absent is refused or ignored and moves nothing. (O7)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1"), finding("f2")], kind="finding")
        claim = await store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds={**ONE, "finding": 2})
        assert keys(claim) == [("finding", "f1"), ("finding", "f2")]
        before = {k: (i.status, i.batch_id, i.attempts) for k, i in (await items(store)).items()}
        for kind, key in (("finding", "f1"), ("finding", "nope")):
            with contextlib.suppress(Exception):  # refusing is as good as ignoring
                await store.release_held(BLUE, kind, key)
        assert {k: (i.status, i.batch_id, i.attempts) for k, i in (await items(store)).items()} == before
