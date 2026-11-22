"""#1546 PR9, A-O3, A-O4, D8, D9, D10, D15: every ending of a job row goes through `apply` and, by the same rules, leaves
an evidence state, promotes only what the rules say, runs its follow-ons and stores a decided learning job's findings.
Real store, real Postgres; the helper's staging is planted by SQL under the row's claim token."""
from __future__ import annotations


import pytest

from defender.tests.support.evidence._facts1546 import inv_progress, roster, staged_page
from defender.tests.support.jobs import _findings1487 as F
from defender.tests.support.jobs._ending1546 import (
    BUNDLE,
    EPISODE_PAGE,
    KNOWLEDGE,
    REFUSED,
    RUN_PAGE,
    STARTED,
    accepted,
    alerts_rows,
    end_row,
    findings_screened,
    host_row,
    inv_outcome,
    inv_row,
    learn_row,
    learning_jobs_of,
    learning_outcome,
    plant_complete_source,
    plant_facts,
    plant_uploads,
    queue_learning_job,
    token_of,
    up,
)
from defender.tests.support.jobs._jobs1342 import T1, T2, job_store, lapse_lease, register_tenant
from defender.tests.support.jobs._worker1342 import _queued
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

DONE = {"started": STARTED, "knowledge": KNOWLEDGE, "page": staged_page(), "outcome": inv_outcome()}
BOTH = {BUNDLE: up(), RUN_PAGE: up()}


async def _running(store, dsn):
    inv = await _queued(store)
    claim = await store.claim()
    assert claim is not None
    assert claim.record.investigation_id == inv
    return inv, token_of(dsn, "investigation", inv)


async def _running_job(store, dsn, tenant=T1):
    alert, source = await plant_complete_source(dsn, store, tenant)
    job = await queue_learning_job(dsn, tenant, alert.alert_id, source)
    assert await store.claim_learning_job() is not None
    return job, token_of(dsn, "learning", job), source


def _checks(dsn):
    return execute(dsn, "SELECT tenant_id FROM jobs.learning_checks")


async def test_apply_ends_a_complete_run_once_with_its_verdict_promotes_its_objects_and_runs_its_follow_ons(migrated_database):
    """Facts and uploads become the row's verdict, cost, knowledge, scrub and `complete`; both objects are promoted;
    the auto learning job, the alert outcome and the check clock follow; a second apply changes nothing. (PR9, A-O3)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        plant_facts(dsn, token, DONE)
        plant_uploads(dsn, token, {**BOTH, "page/other": up(REFUSED)})
        _, record = await end_row(store, dsn, kind="investigation", tenant=T1, owner=inv, token=token, by="exited")
        assert record is not None
        again = await end_row(store, dsn, kind="investigation", tenant=T1, owner=inv, token=token, by="exited")
    assert inv_row(dsn, inv) == {"stage": "completed", "failure_reason": None, "disposition": "benign", "cost_usd": 0.42,
                                 "cost_is_lower_limit": False, "knowledge": KNOWLEDGE, "scrub": "clean",
                                 "evidence_state": "complete"}
    assert accepted(dsn, token) == [BUNDLE, RUN_PAGE], "a refused row is never promoted"
    assert again[1] is None
    assert learning_jobs_of(dsn, inv) == 1
    assert execute(dsn, "SELECT outcome FROM jobs.alerts WHERE id = (SELECT alert_id FROM jobs.investigations "
                        "WHERE id = %s)", (inv,)) == [("benign",)]
    assert _checks(dsn) == [(T1,)]


async def test_a_completed_run_whose_page_was_refused_is_lost_keeps_its_verdict_promotes_the_bundle_and_queues_nothing(
        migrated_database):
    """A must-push object not uploaded: `lost`, the verdict kept, the uploaded bundle promoted, no learning job. (rule 5)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        plant_facts(dsn, token, DONE)
        plant_uploads(dsn, token, {BUNDLE: up(), RUN_PAGE: up(REFUSED)})
        await end_row(store, dsn, kind="investigation", tenant=T1, owner=inv, token=token, by="exited")
    got = inv_row(dsn, inv, "stage", "disposition", "evidence_state")
    assert got == {"stage": "completed", "disposition": "benign", "evidence_state": "lost"}
    assert accepted(dsn, token) == [BUNDLE]
    assert learning_jobs_of(dsn, inv) == 0


async def test_a_tainted_run_ends_failed_partial_with_its_bundle_accepted_and_no_job(migrated_database):
    """`scrub = tainted` is failed/no_report, evidence `partial`, bundle (and page) accepted, no learning job. (D2, D9)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        plant_facts(dsn, token, {**DONE, "outcome": inv_outcome(scrub="tainted")})
        plant_uploads(dsn, token, BOTH)
        await end_row(store, dsn, kind="investigation", tenant=T1, owner=inv, token=token, by="exited")
    assert inv_row(dsn, inv, "stage", "scrub", "evidence_state") == {"stage": "failed", "scrub": "tainted",
                                                                     "evidence_state": "partial"}
    assert accepted(dsn, token) == [BUNDLE, RUN_PAGE]
    assert learning_jobs_of(dsn, inv) == 0


@pytest.mark.parametrize("by", ["cancel", "offboard"])
async def test_a_staged_outcome_does_not_survive_a_cancel_or_offboard_and_nothing_is_promoted(migrated_database, by):
    """Cancel and offboard end the row `aborted`, evidence `none`, `scrub = not_run`, uploads unpromoted, and the cost is
    the last staged progress as a lower limit. (rule 2, D15)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        plant_facts(dsn, token, {**DONE, "progress": inv_progress(0.17)})
        plant_uploads(dsn, token, BOTH)
        if by == "cancel":
            await store.cancel_investigation(T1, inv, actor="u-1")
        else:
            await store.offboard_tenant(T1, actor="u-1")
    got = inv_row(dsn, inv, "stage", "evidence_state", "scrub", "cost_usd", "cost_is_lower_limit", "disposition")
    assert got == {"stage": "aborted", "evidence_state": "none", "scrub": "not_run", "cost_usd": 0.17,
                   "cost_is_lower_limit": True, "disposition": None}
    assert accepted(dsn, token) == []


async def test_a_cancelled_queued_row_has_no_evidence_and_nothing_staged(migrated_database):
    """A row cancelled before any claim ends `none`/`not_run` as well (no started fact). (rule 1, A-O4)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv = await _queued(store)
        await store.cancel_investigation(T1, inv, actor="u-1")
    assert inv_row(dsn, inv, "stage", "evidence_state", "scrub") == {"stage": "aborted", "evidence_state": "none",
                                                                     "scrub": "not_run"}


# --- take-over (D8, D9, D10) -------------------------------------------------------------------------------------


@pytest.mark.parametrize(("facts", "uploads", "stage", "state", "promoted", "retried", "jobs"), [
    pytest.param(DONE, BOTH, "completed", "complete", [BUNDLE, RUN_PAGE], False, 1, id="decided-uploads-finished"),
    pytest.param(DONE, {BUNDLE: up(), RUN_PAGE: up("pending")}, "completed", "lost", [BUNDLE], False, 0,
                 id="decided-uploads-cut-off"),
    pytest.param({**DONE, "outcome": inv_outcome(scrub="tainted")}, BOTH, "failed", "partial", [BUNDLE, RUN_PAGE],
                 False, 0, id="tainted-is-never-rerun"),
    pytest.param({"started": STARTED}, {BUNDLE: up()}, "failed", "none", [], True, 0, id="undecided-retries"),
    pytest.param({"started": STARTED, "outcome": inv_outcome(scrub="not_run")}, {BUNDLE: up()}, "failed", "none", [],
                 True, 0, id="unrun-scrub-after-close-is-undecided"),
])
async def test_take_over_keeps_a_decided_verdict_by_the_ordinary_rules_and_retries_only_an_undecided_run(
        migrated_database, facts, uploads, stage, state, promoted, retried, jobs):
    """A lapsed run that decided keeps its verdict and evidence state by rules 4-6 (uploads that finished are promoted),
    a tainted one stays failed, an undecided one lapses `none` and is retried. (D8, D9, rule 3)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        plant_facts(dsn, token, facts)
        plant_uploads(dsn, token, uploads)
        lapse_lease(dsn, inv)
        assert await store.take_over() == [inv]
    row = inv_row(dsn, inv, "stage", "evidence_state", "failure_reason")
    assert (row["stage"], row["evidence_state"]) == (stage, state)
    if retried:
        assert row["failure_reason"] == "lease_lapsed"
    assert accepted(dsn, token) == promoted
    assert (len(alerts_rows(dsn, inv)) == 2) is retried
    assert learning_jobs_of(dsn, inv) == jobs


async def test_a_taken_over_run_ends_with_the_last_progress_as_its_cost_and_a_row_with_no_started_fact_reads_none(migrated_database):
    """A lapsed run's cost is its last staged progress, a lower limit; no `started` fact reads `none`/`not_run` whatever
    else was staged. (D15, rule 1)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        plant_facts(dsn, token, {"progress": inv_progress(0.31), "outcome": inv_outcome()})
        plant_uploads(dsn, token, BOTH)
        lapse_lease(dsn, inv)
        await store.take_over()
    assert inv_row(dsn, inv, "evidence_state", "scrub", "cost_usd", "cost_is_lower_limit") == {
        "evidence_state": "none", "scrub": "not_run", "cost_usd": 0.31, "cost_is_lower_limit": True}
    assert accepted(dsn, token) == []


async def test_a_decided_learning_take_over_stores_the_screened_findings_and_is_not_rerun(migrated_database):
    """The job staged a completed outcome with a screened finding and finished its uploads; its lease lapsed: the
    finding is stored (`waiting`), `publish_state = done`, evidence `complete`, objects promoted, no retry. (D10, D8)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        job, token, _ = await _running_job(store, dsn)
        row = F.defender_row(job, 0)
        plant_facts(dsn, token, {"started": STARTED, "arms": roster(),
                                 "outcome": learning_outcome(findings=findings_screened(row))})
        plant_uploads(dsn, token, {BUNDLE: up(), EPISODE_PAGE: up()})
        execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s", (job,))
        assert await store.take_over() == [job]
    assert learn_row(dsn, job, "status", "publish_state", "evidence_state") == {
        "status": "completed", "publish_state": "done", "evidence_state": "complete"}
    assert F.work_items(dsn, job) == [(T1, "finding", f"{job}/w-b/0/0", "waiting")]
    assert accepted(dsn, token) == [BUNDLE, EPISODE_PAGE]
    [(n,)] = execute(dsn, "SELECT count(*) FROM jobs.learning_jobs WHERE request_key = 'k-learn'")
    assert n == 1


async def test_a_handed_back_decided_learning_job_has_no_state_until_its_take_over_gives_it_one(migrated_database):
    """A `HandBack` leaves the row `running` with no evidence state (not terminal); the take-over then ends it by the
    ordinary rules (here `lost`: its episode page never finished), storing its finding. (PR9, A-O4, D10)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        job, token, _ = await _running_job(store, dsn)
        plant_facts(dsn, token, {"started": STARTED, "arms": roster(),
                                 "outcome": learning_outcome(findings=findings_screened(F.defender_row(job, 0)))})
        plant_uploads(dsn, token, {BUNDLE: up()})
        hand = await end_row(store, dsn, kind="learning", tenant=T1, owner=job, token=token, by="stopped")
        assert type(hand[0]).__name__ == "End"  # decided: a stop does not hand it back
        # An undecided stop is a hand-back: no state, still running.
        job2, token2, _ = await _running_job(store, dsn)
        plant_facts(dsn, token2, {"started": STARTED, "progress": {"stage": "judge", "fork_message_id": "m",
                                                                    "sibling_cost_usd": 1.0}})
        decision, record = await end_row(store, dsn, kind="learning", tenant=T1, owner=job2, token=token2, by="stopped")
        assert type(decision).__name__ == "HandBack"
        assert record is not None
        assert learn_row(dsn, job2, "status", "evidence_state") == {"status": "running", "evidence_state": None}
        execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s", (job2,))
        assert await store.take_over() == [job2]
    assert learn_row(dsn, job2, "status", "reason", "evidence_state") == {
        "status": "failed", "reason": "lease_lapsed", "evidence_state": "none"}
    assert learn_row(dsn, job, "status", "evidence_state") == {"status": "completed", "evidence_state": "lost"}


async def test_a_handed_back_investigation_is_not_terminal_and_is_then_taken_over_with_its_progress_cost(migrated_database):
    """HandBack: the lease lapses at once, the row stays `running` with no state; the take-over retries it. (PR9)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        plant_facts(dsn, token, {"started": STARTED, "progress": inv_progress(0.5)})
        decision, record = await end_row(store, dsn, kind="investigation", tenant=T1, owner=inv, token=token, by="stopped")
        assert type(decision).__name__ == "HandBack"
        assert record is not None
        assert inv_row(dsn, inv, "stage", "evidence_state", "scrub") == {"stage": "running", "evidence_state": None,
                                                                         "scrub": None}
        assert await store.take_over() == [inv]
    assert inv_row(dsn, inv, "stage", "evidence_state", "cost_usd") == {"stage": "failed", "evidence_state": "none",
                                                                        "cost_usd": 0.5}


async def test_a_learning_job_expired_in_the_queue_and_one_offboarded_end_with_no_evidence(migrated_database):
    """Queue expiry (`skipped/expired`) and offboarding (`skipped/tenant_offboarded`) leave `none`, so the schema's
    terminal-has-a-state check holds for the claim's own sweep. (A-O4, rule 1)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    register_tenant(dsn, T2)
    async with job_store(dsn, learning_max_age=60) as store:
        alert, source = await plant_complete_source(dsn, store, T1)
        old = await queue_learning_job(dsn, T1, alert.alert_id, source, key="k-old")
        execute(dsn, "UPDATE jobs.learning_jobs SET created_at = now() - interval '1 day' WHERE id = %s", (old,))
        assert await store.claim_learning_job() is None
        alert2, source2 = await plant_complete_source(dsn, store, T2)
        waiting = await queue_learning_job(dsn, T2, alert2.alert_id, source2, key="k-wait")
        await store.offboard_tenant(T2, actor="u-1")
    assert learn_row(dsn, old, "status", "reason", "evidence_state") == {"status": "skipped", "reason": "expired",
                                                                         "evidence_state": "none"}
    assert learn_row(dsn, waiting, "status", "reason", "evidence_state") == {
        "status": "skipped", "reason": "tenant_offboarded", "evidence_state": "none"}


@pytest.mark.parametrize(("facts", "stage", "reason", "has_result"), [
    ({"result": {"outcome": "ready"}}, "completed", None, True),
    ({}, "failed", "worker_lost", False),
])
async def test_a_lapsed_readiness_request_keeps_a_staged_result_and_otherwise_ends_worker_lost_never_retried(
        migrated_database, facts, stage, reason, has_result):
    """A host request is decided by its staged `result`: a lapsed one that has it completes, else `worker_lost`; no
    retry either way. (Decided, host requests)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        rec, _ = await store.create_readiness(T1, actor="u-1")
        assert await store.claim_host_request() is not None
        token = token_of(dsn, "readiness", rec.request_id)
        plant_facts(dsn, token, facts)
        execute(dsn, "UPDATE jobs.host_requests SET lease_expires_at = now() - interval '1 second' WHERE id = %s",
                (rec.request_id,))
        assert await store.take_over() == [rec.request_id]
    got = host_row(dsn, rec.request_id)
    assert (got["stage"], got["failure_reason"]) == (stage, reason)
    assert (got["result"] is not None) is has_result
    if has_result:
        assert got["result"]["outcome"] == "ready"
    assert execute(dsn, "SELECT count(*) FROM jobs.host_requests") == [(1,)]


async def test_a_refused_apply_is_retried_with_a_lesser_end_that_still_ends_the_row(migrated_database):
    """The database refuses the end as decided (a real trigger fault on the knowledge written); the caller applies
    `lesser(decision)` and the row ends, evidence re-derived for the lesser stage, with its bundle promoted. (PR9)"""
    from defender.jobs import ending, is_refusal

    dsn = migrated_database
    register_tenant(dsn, T1)
    F.trigger_fault(dsn, "jobs.investigations", "23514", when="NEW.knowledge ->> 'status' = 'current'")
    async with job_store(dsn) as store:
        inv, token = await _running(store, dsn)
        plant_facts(dsn, token, DONE)
        plant_uploads(dsn, token, BOTH)
        decision = ending.decide(DONE, {BUNDLE: up(), RUN_PAGE: up()}, ending.Exited(0), kind="investigation")
        with pytest.raises(Exception) as refused:  # noqa: PT011 - narrowed by is_refusal below
            await store.apply(T1, inv, decision)
        assert is_refusal(refused.value)
        assert inv_row(dsn, inv, "stage")["stage"] == "running", "the refused end changed nothing"
        assert accepted(dsn, token) == []
        weaker = ending.lesser(decision)
        for _ in range(3):
            try:
                applied = await store.apply(T1, inv, weaker)
            except Exception as again:  # noqa: BLE001 - the ladder: keep weakening while the store refuses
                refused_again = again
            else:
                assert applied is not None
                break
            assert is_refusal(refused_again)
            weaker = ending.lesser(weaker)
    got = inv_row(dsn, inv, "stage", "knowledge", "evidence_state")
    assert got["stage"] in {"completed", "failed"}
    assert got["knowledge"] != KNOWLEDGE
    assert got["evidence_state"] in ({"complete", "lost"} if got["stage"] == "completed" else {"partial"})
    assert BUNDLE in accepted(dsn, token)


# --- A-O4: the schema's own guard --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("table", ["investigations", "learning_jobs"])
async def test_a_terminal_row_without_an_evidence_state_is_refused_by_the_schema_and_a_handed_back_one_is_not_terminal(
        migrated_database, table):
    """Check constraint keyed on terminal status: a terminal row needs one of the five states (and, for an investigation,
    a scrub); a value outside them is refused; `finished_at` on a running row is not terminal. (A-O4)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        if table == "investigations":
            row_id, _ = await _running(store, dsn)
            end = ("UPDATE jobs.investigations SET stage = 'failed', failure_reason = 'worker_error', finished_at = now(), "
                   "evidence_state = {state}, scrub = 'not_run' WHERE id = %s")
            handed = "UPDATE jobs.investigations SET finished_at = now() WHERE id = %s"
        else:
            row_id, _, _ = await _running_job(store, dsn)
            end = ("UPDATE jobs.learning_jobs SET status = 'failed', reason = 'worker_error', finished_at = now(), "
                   "lease_expires_at = NULL, evidence_state = {state} WHERE id = %s")
            handed = "UPDATE jobs.learning_jobs SET finished_at = now() WHERE id = %s"
    execute(dsn, handed, (row_id,))  # control: a non-terminal row needs no state
    for bad in ("NULL", "'gone'"):
        with pytest.raises(Exception, match="check"):
            execute(dsn, end.format(state=bad), (row_id,))
    execute(dsn, end.format(state="'complete'"), (row_id,))
    for good in ("partial", "none", "lost", "expired"):
        execute(dsn, f"UPDATE jobs.{table} SET evidence_state = %s WHERE id = %s", (good, row_id))  # noqa: S608
        assert execute(dsn, f"SELECT evidence_state FROM jobs.{table} WHERE id = %s", (row_id,)) == [(good,)]  # noqa: S608
