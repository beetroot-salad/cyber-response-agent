"""#1546 sketch (r6), the end function on the store's other ending paths (take-over, hand-back), through `JobStore`:
take-over keeps a verdict only when the run decided one (Decisions 2, 3), promotes nothing, and an ended row always
has an evidence state while a handed-back one does not (A-O3, A-O4).

The helper's staging is SQL under the row's claim token (`_support`). No worker: `store.take_over()` is the entry.
"""
from __future__ import annotations

import uuid

import pytest

from defender.tests.evidence_1546._support import (
    EPISODE_PAGE,
    RUN_PAGE,
    STARTED,
    accepted,
    claim_token,
    inv_outcome,
    learning_outcome,
    owner,
    stage_fact,
    stage_upload,
)
from defender.tests.support.jobs import _findings1487 as F
from defender.tests.support.jobs._jobs1342 import T1, an_alert, job_store, lapse_lease, register_tenant
from defender.tests.support.jobs._worker1342 import _queued
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


def _rows_of_alert(dsn: str, inv: str) -> list[tuple[str, str]]:
    return [(str(i), s) for i, s in execute(
        dsn, "SELECT id, stage FROM jobs.investigations WHERE alert_id = (SELECT alert_id FROM jobs.investigations "
             "WHERE id = %s) ORDER BY attempt", (inv,))]


async def _claimed(store, dsn: str) -> tuple[str, str]:
    inv = await _queued(store)
    claim = await store.claim()
    assert claim is not None and claim.record.investigation_id == inv
    token = claim_token(dsn, "investigations", inv)
    assert token, "the claim stored no claim token on the row"
    return inv, token


async def test_a_takeover_of_a_decided_investigation_keeps_its_verdict_reads_lost_and_promotes_nothing(
        migrated_database):
    """The helper staged a completed outcome and uploaded bundle and page; the lease lapsed before the worker's end.
    Take-over: the row ends `completed` with the staged verdict and cost, evidence `lost`, nothing promoted, no retry
    row and no learning job. (Stage: take-over, decided; Evidence rule 3; Promotion on `end` only)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _claimed(store, dsn)
        stage_fact(dsn, token, "started", STARTED)
        stage_fact(dsn, token, "outcome", inv_outcome())
        stage_upload(dsn, token, "bundle", b"bundle")
        stage_upload(dsn, token, RUN_PAGE, b"page")
        lapse_lease(dsn, inv)
        assert await store.take_over() == [inv]

    assert owner(dsn, "investigations", inv, "stage", "disposition", "evidence_state", "scrub") == (
        "completed", "benign", "lost", "clean")
    assert owner(dsn, "investigations", inv, "cost_usd")[0] == pytest.approx(0.42)
    assert accepted(dsn, token) == []
    assert _rows_of_alert(dsn, inv) == [(inv, "completed")], "a decided run was retried"
    [(jobs,)] = execute(dsn, "SELECT count(*) FROM jobs.learning_jobs WHERE investigation_id = %s", (inv,))
    assert jobs == 0


async def test_a_takeover_of_a_tainted_investigation_keeps_it_failed_not_rerun(migrated_database):
    """Decision 2: `scrub = tainted` is a decided failure; take-over keeps it failed (`lost`), no retry."""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _claimed(store, dsn)
        stage_fact(dsn, token, "started", STARTED)
        stage_fact(dsn, token, "outcome", inv_outcome(scrub="tainted"))
        stage_upload(dsn, token, "bundle", b"bundle")
        lapse_lease(dsn, inv)
        await store.take_over()
    assert owner(dsn, "investigations", inv, "stage", "scrub", "evidence_state") == ("failed", "tainted", "lost")
    assert len(_rows_of_alert(dsn, inv)) == 1


async def test_a_takeover_of_an_undecided_investigation_lapses_and_retries_as_today(migrated_database):
    """Started, nothing decided: failed `lease_lapsed`, evidence `none`, `scrub = not_run`, its upload unpromoted
    (left for the grace sweep), retried as a new row whose claim token is its own once claimed. (rule 3, PR7)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        inv, token = await _claimed(store, dsn)
        stage_fact(dsn, token, "started", STARTED)
        stage_upload(dsn, token, "bundle", b"bundle")
        lapse_lease(dsn, inv)
        await store.take_over()
        again = await store.claim()
    assert owner(dsn, "investigations", inv, "stage", "failure_reason", "evidence_state", "scrub") == (
        "failed", "lease_lapsed", "none", "not_run")
    assert accepted(dsn, token) == []
    [(_, first), (retry, _)] = _rows_of_alert(dsn, inv)
    assert first == "failed"
    assert again is not None and again.record.investigation_id == retry
    assert claim_token(dsn, "investigations", retry) not in (None, token)


async def _claimed_learning_job(store, dsn: str) -> tuple[str, str]:
    """A complete investigation of T1 (rows by SQL: its end is `test_investigation_end`'s) and its queued learning job,
    claimed by the store's real claim; (job id, its claim token)."""
    alert = await an_alert(store, T1, ticket=f"T-{uuid.uuid4().hex[:6]}")
    inv, _ = await store.create_investigation(T1, alert.alert_id, "k-src", actor="u-1")
    source = inv.investigation_id
    execute(dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', finished_at = now(), "
                 "evidence_state = 'complete', scrub = 'clean' WHERE id = %s", (source,))
    job = str(uuid.uuid4())
    execute(dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, "
                 "trigger, status, created_at, sibling_cost_usd, publish_state) VALUES (%s, %s, %s, %s, 'k-learn', 1, "
                 "'auto', 'queued', now(), 0, 'none')", (job, T1, alert.alert_id, source))
    claimed = await store.claim_learning_job()
    assert claimed is not None
    token = claim_token(dsn, "learning_jobs", job)
    assert token, "the learning claim stored no claim token on the row"
    return job, token


async def test_a_handed_back_decided_learning_job_has_no_state_then_takeover_stores_its_findings(migrated_database):
    """The job staged a completed outcome with one finding and pushed its objects; the stopping worker handed it back:
    the row is still `running`, `finished_at` set, evidence state NULL (A-O4: keyed on terminal status). The next
    take-over keeps the decided verdict: `completed`, its screened finding stored as #1487's row (`waiting`),
    `publish_state = done`, evidence `lost`, nothing promoted, no retry. (Decision 3, changing #1487 O3)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        job, token = await _claimed_learning_job(store, dsn)
        stage_fact(dsn, token, "started", STARTED)
        stage_fact(dsn, token, "arms", {"roster": []})
        stage_fact(dsn, token, "outcome", learning_outcome(findings=F.ok([F.defender_row(job, 0)])))
        stage_upload(dsn, token, "bundle", b"bundle")
        stage_upload(dsn, token, EPISODE_PAGE, b"episode")
        assert await store.hand_back_learning_job(T1, job) is not None
        assert owner(dsn, "learning_jobs", job, "status", "evidence_state") == ("running", None)
        assert await store.take_over() == [job]

    assert owner(dsn, "learning_jobs", job, "status", "publish_state", "evidence_state") == (
        "completed", "done", "lost")
    assert F.work_items(dsn, job) == [(T1, "finding", f"{job}/w-b/0/0", "waiting")]
    assert accepted(dsn, token) == []
    [(n,)] = execute(dsn, "SELECT count(*) FROM jobs.learning_jobs WHERE request_key = 'k-learn'")
    assert n == 1, "a decided learning job was retried"


@pytest.mark.parametrize("table", ["investigations", "learning_jobs"])
async def test_a_terminal_row_without_an_evidence_state_is_refused_by_the_schema(migrated_database, table):
    """The check constraint: a terminal row with a NULL evidence state cannot be written by any writer; the same end
    with `none` (and, for an investigation, `scrub = not_run`) is. The migration backfills `none` / `not_run` on
    already-terminal rows. (A-O4)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    async with job_store(dsn) as store:
        if table == "investigations":
            row_id = await _queued(store)
            end = ("UPDATE jobs.investigations SET stage = 'failed', failure_reason = 'worker_error', "
                   "finished_at = now(), evidence_state = {state}, scrub = {scrub} WHERE id = %s")
        else:
            row_id, _ = await _claimed_learning_job(store, dsn)
            end = ("UPDATE jobs.learning_jobs SET status = 'failed', reason = 'worker_error', finished_at = now(), "
                   "lease_expires_at = NULL, evidence_state = {state} WHERE id = %s")
    with pytest.raises(Exception, match="check"):  # psycopg's CheckViolation; the constraint's name is the design's
        execute(dsn, end.format(state="NULL", scrub="'not_run'"), (row_id,))
    execute(dsn, end.format(state="'none'", scrub="'not_run'"), (row_id,))
    assert owner(dsn, table, row_id, "evidence_state") == ("none",)
