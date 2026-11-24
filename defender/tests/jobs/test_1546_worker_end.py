"""#1546 (design r8) the worker's end of an investigation, a learning job and a post-step, from staged rows only. The child
is a scripted stand-in for the helper (`Staging` stages facts and upload rows under the claim row the worker's claim made,
and the child leaves contradicting files); the worker decides from the rows. Obligations: A-O1..A-O4, A-O10, PR7-PR9, D9,
D10, D14. Per-rule cases of the end are slice SA's; these are the flows through the worker's wiring."""
from __future__ import annotations

import asyncio
import os
import signal

import pytest

from defender.tests.jobs.test_1344_learning_jobs import (
    job_child,
    job_row,
    learning_worker,
    post_child,
)
from defender.tests.support.evidence._facts1546 import UP, arm_facts, arm_page, staged_arm, staged_page, up
from defender.tests.support.jobs._evidence_flows1546 import (
    EPISODE_PAGE,
    INPUTS,
    KNOWLEDGE,
    ROOTS,
    RUN_PAGE,
    SPOOL,
    STARTED,
    Staging,
    accepted,
    attempts_of,
    audited,
    claim_of,
    claim_row,
    files_opened_under,
    inv_outcome,
    job_written_places,
    learning_jobs_of,
    learning_outcome,
    owner,
    screened,
    stage_fact,
    stage_upload,
)
from defender.tests.support.jobs._ending1546 import plant_claim, plant_complete_source, plant_uploads, queue_learning_job
from defender.tests.support.jobs._jobs1342 import T1, T2, job_end, job_store, lapse_lease, row
from defender.tests.support.jobs._worker1342 import _child, _FAST, _queued, _until, _worker
from defender.tests.support.jobs import _worker1342 as _shared
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment

BUNDLE = b"bundle bytes (opaque to the worker)"
PAGE = b"<html>the renderer's page</html>"
#: What a job leaves in the tenant's runs folder that contradicts its staged rows (the worker must read none of it). No
#: `report.md` decoy: #1534 retired the file (nothing writes or reads it, `verdict_1534/test_report_file_gone.py` holds
#: every product and test file to that), and the closing record it stood for is the staged `outcome`'s `closing` here.
DECOYS = {"{id}.job-end.json": job_end(report_committed=False),
          "{id}.knowledge-source.json": '{"kind": "stale", "commit": "' + "d" * 40 + '", "stale_kind": "operator", "reason": "x"}'}


def _staging(world, child, *, outcome=None, page="rendered", objects=None, extra=None, **kw) -> Staging:
    staged = {"started": STARTED, "knowledge": KNOWLEDGE, **(extra or {})}
    if outcome is not None:
        staged["outcome"] = outcome
    if page is not None:
        staged["page"] = staged_page(page)
    return Staging(world["dsn"], world["root"], "investigation", lambda launch: launch.investigation_id, child,
                   staged=staged, objects={"bundle": BUNDLE, RUN_PAGE: PAGE} if objects is None else objects, **kw)


async def _drain(world, staging: Staging) -> tuple[str, dict]:
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await _worker(world, store, staging).drain()
    staging.assert_ran()
    return inv, row(world["dsn"], inv)


async def test_a_normal_end_is_complete_clean_and_accepts_exactly_its_claims_uploads(world):
    """Outcome completed/benign/0.42, `page = rendered`, bundle and page uploaded: the row ends from the rows, evidence
    `complete`, exactly the two uploads promoted, one learning job queued, the child handed the claim's own token.
    (A-O3, A-O4, A-O10, PR7: one minter)"""
    staging = _staging(world, _child(world, files=dict(DECOYS)), outcome=inv_outcome())
    inv, stored = await _drain(world, staging)

    assert (stored["stage"], stored["disposition"], stored["failure_reason"]) == ("completed", "benign", None), stored
    assert stored["cost_usd"] == pytest.approx(0.42)
    assert stored["knowledge"] == KNOWLEDGE
    assert owner(world["dsn"], "investigations", inv, "scrub", "evidence_state") == ("clean", "complete")
    assert accepted(world["dsn"], staging.token) == sorted(["bundle", RUN_PAGE])
    claim = claim_row(world["dsn"], staging.token)
    assert (claim["tenant_id"], claim["kind"], claim["investigation_id"]) == (T1, "investigation", inv)
    assert staging.child.seen()["claim"] == staging.token, "the child's claim is not the store's claim token"
    assert learning_jobs_of(world["dsn"], inv) == 1


async def test_a_render_failure_costs_only_the_page_and_still_queues_learning(world):
    """`page = render_failed`, bundle alone uploaded: complete, one learning job; the paired control owes the page, whose
    upload the store refused: `lost`, the verdict kept, no learning job. (D14, PR8, A-O4 rules 4-5)"""
    failed = _staging(world, _child(world), outcome=inv_outcome(), page="render_failed", objects={"bundle": BUNDLE})
    inv, stored = await _drain(world, failed)
    assert (stored["stage"], stored["disposition"]) == ("completed", "benign"), stored
    assert owner(world["dsn"], "investigations", inv, "evidence_state")[0] == "complete"
    assert accepted(world["dsn"], failed.token) == ["bundle"]
    assert learning_jobs_of(world["dsn"], inv) == 1


async def test_a_page_the_store_refused_reads_lost_keeps_the_verdict_and_queues_no_learning_job(world):
    """`page = rendered` but the page's upload was refused: evidence `lost`, bundle alone promoted, no learning job. (D14
    control, PR8, A-O4 rule 5)"""
    refused = _staging(world, _child(world), outcome=inv_outcome(), objects={"bundle": BUNDLE, RUN_PAGE: None})
    inv, stored = await _drain(world, refused)
    assert (stored["stage"], stored["disposition"]) == ("completed", "benign"), stored
    assert owner(world["dsn"], "investigations", inv, "evidence_state")[0] == "lost"
    assert accepted(world["dsn"], refused.token) == ["bundle"]
    assert learning_jobs_of(world["dsn"], inv) == 0


async def test_a_tainted_investigation_ends_failed_no_report_partial_with_its_bundle_accepted_and_queues_no_learning(world):
    """`scrub = tainted` with a committed close: failed / no_report, no verdict on the row, `scrub = tainted`, evidence
    `partial`, the bundle accepted, no learning job. (D2, D9, A-O10, PR6)"""
    staging = _staging(world, _child(world), outcome=inv_outcome(scrub="tainted"), page="none",
                       objects={"bundle": BUNDLE})
    inv, stored = await _drain(world, staging)
    assert (stored["stage"], stored["failure_reason"], stored["disposition"]) == ("failed", "no_report", None), stored
    assert owner(world["dsn"], "investigations", inv, "scrub", "evidence_state") == ("tainted", "partial")
    assert accepted(world["dsn"], staging.token) == ["bundle"]
    assert learning_jobs_of(world["dsn"], inv) == 0


async def test_a_takeover_by_a_serving_worker_does_not_rerun_a_tainted_run_but_retries_an_undecided_one(world):
    """Two running rows whose leases lapsed: the one with a staged `tainted` outcome ends failed with no retry row; the one
    with nothing decided lapses and is retried as a new row (the control). (D9, D8)"""
    dsn = world["dsn"]
    child = _child(world, files={})
    async with job_store(dsn) as store:
        await _queued(store, ticket="T-1", key="k1")
        await _queued(store, ticket="T-2", key="k2")
        tainted, undecided = [(await store.claim()).record.investigation_id for _ in range(2)]  # the fixed clock leaves their order open
        stage_fact(dsn, claim_of(dsn, "investigation", tainted), "started", STARTED)
        stage_fact(dsn, claim_of(dsn, "investigation", tainted), "outcome", inv_outcome(scrub="tainted"))
        stage_upload(dsn, claim_of(dsn, "investigation", tainted), "bundle", BUNDLE)
        stage_fact(dsn, claim_of(dsn, "investigation", undecided), "started", STARTED)
        for inv in (tainted, undecided):
            lapse_lease(dsn, inv)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: len(attempts_of(dsn, undecided)) == 2, "the undecided row's retry", timeout=30)
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)

    assert row(dsn, tainted)["stage"] == "failed"
    assert owner(dsn, "investigations", tainted, "scrub")[0] == "tainted"
    assert len(attempts_of(dsn, tainted)) == 1, "a tainted run was rerun"


async def test_a_staged_outcome_wins_over_every_file_the_job_leaves(world):
    """The job leaves a contradicting job-end record, a malicious report and a knowledge record in the runs folder: the row
    follows the staged rows. (A-O2, PR4)"""
    staging = _staging(world, _child(world, files=dict(DECOYS)), outcome=inv_outcome())
    _, stored = await _drain(world, staging)
    assert (stored["stage"], stored["disposition"], stored["knowledge"]) == ("completed", "benign", KNOWLEDGE)


async def test_the_worker_opens_no_file_under_a_job_root_or_a_tenant_folder_and_no_sqlite_database(world):
    """Over a whole investigation: nothing is opened as a file under the claims' roots, inputs and spool or either tenant's
    folder (the planted decoys and a session database included); the audit sees a planted file and a database opened the way
    the store opens them (positive control). (A-O2, A-O1)"""
    from defender.records.session_store._write import _connect_existing
    from defender.tests.support.jobs._evidence_flows1546 import write_outside

    places = job_written_places(world["root"], T1, T2)
    probe = world["root"] / T1 / "control.txt"
    database = world["root"] / T1 / "sessions" / "control.db"
    write_outside({probe: b"x"})
    import sqlite3

    sqlite3.connect(database).close()  # outside the audit window: made, not read
    staging = _staging(world, _child(world, files=dict(DECOYS)), outcome=inv_outcome(), folders=True,
                       plant=lambda token: {world["root"] / ROOTS / token / T1 / "sessions" / "a1.db": b"",
                                            world["root"] / ROOTS / token / T1 / "runs" / "x.job-end.json": b"{}"})
    with audited() as seen:
        probe.read_bytes()
        _connect_existing(database).close()
        controls = files_opened_under(seen, *places)
    assert controls == sorted({os.path.realpath(probe), os.path.realpath(database)}), "control: the audit missed an open"

    with audited() as seen:
        await _drain(world, staging)
        opened = files_opened_under(seen, *places)
    assert opened == [], f"the worker opened job-written files: {opened}"


async def test_the_claims_root_inputs_and_spool_are_gone_after_the_end(world):
    """The helper left the claim's root, inputs and spool: after the child and the end, nothing of the job remains. (A-O1,
    A-O2)"""
    staging = _staging(world, _child(world), outcome=inv_outcome(), folders=True)
    await _drain(world, staging)
    for base in (ROOTS, INPUTS, SPOOL):
        folder = world["root"] / base / staging.token
        assert not folder.exists(), f"{folder} outlived the job"


async def test_another_claims_uploads_for_the_same_owner_are_never_promoted(world):
    """Another claim of the tenant (an ended row's: a row is claimed at most once) has an uploaded, unpromoted bundle: the end
    promotes only the row's own claim's. (A-O3)"""
    async with job_store(world["dsn"]) as store:
        _, other = await plant_complete_source(world["dsn"], store, T1)
    stale = plant_claim(world["dsn"], tenant=T1, kind="investigation", ref=other)
    stage_upload(world["dsn"], stale, "bundle", b"another claim's bundle")

    staging = _staging(world, _child(world), outcome=inv_outcome())
    await _drain(world, staging)
    assert accepted(world["dsn"], stale) == []
    assert accepted(world["dsn"], staging.token) == sorted(["bundle", RUN_PAGE])


# --- learning job ------------------------------------------------------------------------------------------------------

async def _queued_learning(world, store, ticket: str = "J-1") -> tuple[str, str]:
    """A `complete` source with its facts-free rows planted and one queued learning job: `(job id, source id)`. Not
    `queued_job`: that finishes a source with no facts, which under r8 reads `none` and queues nothing."""
    dsn = world["dsn"]
    alert, source = await plant_complete_source(dsn, store, T1, ticket=ticket)
    token = plant_claim(dsn, tenant=T1, kind="investigation", ref=source)  # the source's own claim and its accepted bundle
    plant_uploads(dsn, token, {"bundle": up(UP, "clean")})
    execute(dsn, "UPDATE jobs.uploads SET accepted_at = now() WHERE token = %s", (token,))
    return await queue_learning_job(dsn, T1, alert.alert_id, source), source


async def _learning(world, outcome, *, objects=None, **child):
    """One complete source and its queued job (planted rows, as a #1546 complete end leaves them); the worker runs it."""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job, source = await _queued_learning(world, store)
        staging = Staging(dsn, world["root"], "learning", lambda launch: launch.job_id, job_child(world, **child),
                          staged={"started": STARTED, "outcome": outcome},
                          objects={EPISODE_PAGE: PAGE, "bundle": BUNDLE} if objects is None else objects,
                          folders=True)
        await learning_worker(world, store, job=staging, post=post_child(world)).drain()
    staging.assert_ran()
    return job, source, staging


async def test_a_learning_job_ends_from_its_staged_outcome_and_its_claim_names_the_sources_bundle(world):
    """The source is `complete`: the job's claim has the source's `bundle` as its one input; its end and findings come from
    the staged outcome though the job's end record says `failed`; evidence `complete`, both objects promoted, the root,
    inputs and spool gone. (A-O6, A-O2, D1, A-O1)"""
    job, source, staging = await _learning(
        world, learning_outcome(), files={"{id}.learning-end.json": '{"status": "failed", "reason": "entry_error"}'})
    stored = job_row(world["dsn"], job)
    assert (stored["status"], stored["publish_state"]) == ("completed", "done"), stored
    assert [(i["owner"], i["object"]) if isinstance(i, dict) else tuple(i) for i in staging.inputs] == [(source, "bundle")]
    assert owner(world["dsn"], "learning_jobs", job, "evidence_state")[0] == "complete"
    assert accepted(world["dsn"], staging.token) == sorted([EPISODE_PAGE, "bundle"])
    for base in (ROOTS, INPUTS, SPOOL):
        assert not (world["root"] / base / staging.token).exists()


async def test_findings_the_helper_refused_read_publish_state_refused_and_the_ending_stands(world):
    """`findings = refused{reason}` in a valid outcome: the job is `completed`, `publish_state = refused`, no store rows
    (#1487 O2 through D11)."""
    job, _, _ = await _learning(world, learning_outcome(findings={"state": "refused", "reason": "over the cap"}))
    stored = job_row(world["dsn"], job)
    assert (stored["status"], stored["publish_state"]) == ("completed", "refused"), stored
    assert execute(world["dsn"], "SELECT count(*) FROM learning.work_items")[0][0] == 0


async def test_screened_findings_are_stored_with_the_ending(world):
    """`findings = screened{rows}`: both channels' rows are stored `waiting` with the ending, from the row not a file.
    (D10, D11, #1487 O1)"""
    from defender.tests.support.jobs import _findings1487 as F

    # a row id is the job's: the job id is only known once queued, so stage after it is known (rewrite the outcome fact)
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job, _ = await _queued_learning(world, store)

        def stage(token: str) -> None:
            return None

        outcome = learning_outcome(findings=screened(F.defender_row(job, 0), questioner=(F.world_row(job, 0),)))
        staging = Staging(dsn, world["root"], "learning", lambda launch: launch.job_id, job_child(world),
                          staged={"started": STARTED, "outcome": outcome}, objects={EPISODE_PAGE: PAGE, "bundle": BUNDLE})
        await learning_worker(world, store, job=staging, post=post_child(world)).drain()
    staging.assert_ran()
    stored = job_row(dsn, job)
    assert (stored["status"], stored["publish_state"]) == ("completed", "done"), stored
    assert F.work_items(dsn, job) == [(T1, "finding", f"{job}/w-b/0/0", "waiting"),
                                      (T1, "questioner_finding", f"{job}/w-c/0/0", "waiting")]


async def test_a_learning_jobs_arms_databases_ride_in_its_bundle_and_a_non_clean_arm_is_never_lost(world):
    """The job's outcome stays `completed` and the evidence `complete` when an arm's page was `render_failed` (its fact says
    so, the page owed is only the rendered arms'); an arm with `scrub = tainted` is left out, not `lost`. (D3, D12, D14,
    PR8)"""
    arms = arm_facts(**{"a-1": staged_arm("clean", "rendered"), "a-2": staged_arm("clean", "render_failed"),
                        "a-3": staged_arm("tainted", "none")})
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job, _ = await _queued_learning(world, store)
        staging = Staging(dsn, world["root"], "learning", lambda launch: launch.job_id, job_child(world),
                          staged={"started": STARTED, **arms, "outcome": learning_outcome()},
                          objects={EPISODE_PAGE: PAGE, "bundle": BUNDLE, arm_page("a-1"): PAGE})
        await learning_worker(world, store, job=staging, post=post_child(world)).drain()
    staging.assert_ran()
    assert owner(dsn, "learning_jobs", job, "evidence_state")[0] == "complete"
    assert accepted(dsn, staging.token) == sorted([EPISODE_PAGE, "bundle", arm_page("a-1")])


# --- post-step ---------------------------------------------------------------------------------------------------------

async def test_a_post_step_claims_with_empty_inputs_and_its_hold_token_is_its_claim_token(world):
    """The post-step's claim has no inputs; the hold row's `holder`, the claim's token and the claim the child was handed are
    one value; the work-waits answer stays the helper's exit status. (PR7, A-O6, G7)"""
    dsn = world["dsn"]
    post = post_child(world, exit=0, answers=False)
    seen: dict = {}

    class Recording(Staging):
        def _launch(self, launch):
            seen["holder"] = execute(dsn, "SELECT holder FROM jobs.learning_checks WHERE tenant_id = %s",
                                     (launch.tenant_id,))
            return super()._launch(launch)

    async with job_store(dsn) as store:
        job, _ = await _queued_learning(world, store)
        staging = Recording(dsn, world["root"], "post-step", lambda launch: launch.tenant_id, post)
        await learning_worker(world, store, job=job_child(world, files={}), post=staging).drain()
    staging.assert_ran()
    assert staging.inputs == []
    assert [h[0] for h in seen["holder"]] == [staging.token]
    assert post.seen()["claim"] == staging.token
    assert job_row(dsn, job)["status"]
