"""#1487 (design r5): the worker's end write stores a completed learning job's findings with its ending (O1, P3), refuses
them whole when the store or the tenant says so while the decided ending stands (O2, P4), and retries on an outage
(O3). Real database; faults are real triggers and statement hooks (`_findings1487`). #1546 (A-O2, PR2, D11): the learning
child plays the helper and stages the job's `outcome` with its findings already screened (`screened{rows}` or
`refused{reason}`); the worker reads only that row. The screen and its cap moved to the helper on receipt (D11): its
rules are `learning/judge/test_1487_screen_findings.py`'s, its staging `test_1546_helper_records.py`'s, so the cases
whose subject was the worker's own screen of the job's text retired here."""
from __future__ import annotations

import asyncio
import json
import sys
import threading
import time

import pytest

from defender.tests.jobs.test_1344_learning_jobs import (
    JobChild,
    jobs_of,
    job_row,
    learning_worker,
    queued_job,
    world,  # noqa: F401 — fixture
)
from defender.tests.support.evidence._facts1546 import EPISODE_PAGE, findings_refused, screened
from defender.tests.support.evidence._facts1546 import staged_learning_outcome as outcome
from defender.tests.support.jobs import _findings1487 as F
from defender.tests.support.jobs._jobs1342 import T1, JobsAudit, job_store, move_tenant
from defender.tests.support.learning.core._store1278 import call
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

ITEMS = "learning.work_items"


class _StagingChild(JobChild):
    """A learning child that plays the helper (#1546 PR2): for each launch it stages `started`, the `outcome` in
    `.records[job id]` (a staged body, findings screened), the bundle and the episode page under the worker's claim, one
    spec file per launch (so concurrent launches never read each other's)."""

    records: dict

    def __call__(self, launch):
        from defender.tests.support.shared.filesystem._handoff import write_whole

        self.staged = {"outcome": self.records[launch.job_id]}
        spec = self.spec_dict()
        path = self.where / f"spec-{launch.job_id}.json"
        write_whole(path, json.dumps(spec))
        return [sys.executable, str(self.script), str(path), "--job", launch.job_id,
                "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]


def _staging_child(world, **kw) -> _StagingChild:  # noqa: F811 — the fixture's value
    child = _StagingChild(world["tmp"] / "job", world["runs"], dsn=world["dsn"], stage_kind="learning",
                          objects={"bundle": "bundle bytes", EPISODE_PAGE: "<html>episode</html>"}, **kw)
    child.records = {}
    return child


async def _run(world, jobs_with, *, children=None, slots=1, ticket="J", **kw):  # noqa: F811
    """Queue one job per `jobs_with(job_id) -> staged outcome`, run the worker to the end of them all; the job ids."""
    child = _staging_child(world)
    post = F.quiet_post_class()(world["tmp"] / "post", world["runs"])
    ids = []
    async with job_store(world["dsn"]) as store:
        for n, make in enumerate(jobs_with):
            job = await queued_job(world, store, ticket=f"{ticket}-{n}")
            child.records[job] = make(job)
            ids.append(job)
        worker = learning_worker(world, store, job=child, post=post, slots=slots + 1, learning_slots=slots, **kw)
        await asyncio.wait_for(worker.drain(), timeout=180)
    return ids


def _stored(dsn: str, job: str):
    return F.work_items(dsn, job)


def _refused_whole(dsn: str, job: str) -> None:
    row = job_row(dsn, job)
    assert (row["status"], row["reason"], row["publish_state"]) == ("completed", None, "refused"), row
    assert _stored(dsn, job) == [], "a refused job's findings were stored"
    assert len(jobs_of(dsn, _inv(dsn, job))) == 1, "the ending was retried as a new attempt"


def _inv(dsn: str, job: str) -> str:
    return execute(dsn, "SELECT investigation_id FROM jobs.learning_jobs WHERE id = %s", (job,))[0][0]


def _both(job: str):
    return outcome(findings=screened(F.defender_row(job, 0), F.defender_row(job, 1), questioner=(F.world_row(job, 0),)))


# --- O1, P3 --------------------------------------------------------------------------------------------------


async def test_o1_a_completed_jobs_findings_are_stored_waiting_for_its_tenant_with_its_ending(world):  # noqa: F811
    """Both channels' staged rows land `waiting`, tenant and `source_run` the job's, publish state `done`. (O1, Flow 1
    step 3)"""
    dsn = world["dsn"]
    [job] = await _run(world, [_both])
    row = job_row(dsn, job)
    assert (row["status"], row["publish_state"]) == ("completed", "done"), row
    assert _stored(dsn, job) == [(T1, "finding", f"{job}/w-b/0/0", "waiting"), (T1, "finding", f"{job}/w-b/0/1", "waiting"),
                                 (T1, "questioner_finding", f"{job}/w-c/0/0", "waiting")]
    [(payload,)] = execute(dsn, "SELECT payload FROM learning.work_items WHERE item_key = %s", (f"{job}/w-c/0/0",))
    assert payload == F.world_row(job, 0)


async def test_o1_zero_findings_read_done_and_store_nothing(world):  # noqa: F811
    """`screened` with both channels empty: `done`, no rows. (O1)"""
    [job] = await _run(world, [lambda j: outcome()])
    row = job_row(world["dsn"], job)
    assert (row["status"], row["publish_state"]) == ("completed", "done")
    assert _stored(world["dsn"], job) == []


async def test_1589_the_finish_audit_names_how_many_rows_the_end_added(world, caplog):  # noqa: F811
    """With the row's count gone (#1589), the number of rows the end write added is in the store's own finish event:
    three rows of a job with three, none of a job with none, and no count for one whose findings the helper refused."""
    audit = JobsAudit(caplog)
    [first] = await _run(world, [_both])
    [again] = await _run(world, [lambda j: outcome()], ticket="again")
    [refused] = await _run(world, [lambda j: outcome(findings=findings_refused())], ticket="refused")
    details = {e.target: e.detail for e in audit.events() if e.action == "learning_job.finish"}
    assert details[first] == "status=completed findings=done added=3", details
    assert details[again] == "status=completed findings=done added=0", details
    assert details[refused] == "status=completed findings=refused", details


@pytest.mark.parametrize("status", ["failed", "skipped"])
async def test_o1_another_ending_ignores_findings_it_carries(world, status):  # noqa: F811
    """A failed or skipped outcome carrying screened findings (or refused ones) stores nothing and stays `none`. (Data
    model)"""
    dsn = world["dsn"]
    reason, extra = ("judge_failed", {}) if status == "failed" else ("no_fork_point", {})
    make = lambda found: (lambda j: outcome(status, reason=reason, findings=found(j)))  # noqa: E731
    good, junk = await _run(world, [make(lambda j: screened(F.defender_row(j))), make(lambda j: findings_refused())])
    for job in (good, junk):
        row = job_row(dsn, job)
        assert (row["status"], row["reason"], row["publish_state"]) == (status, reason, "none"), row
        assert _stored(dsn, job) == []


async def test_o1_a_stored_finding_id_is_not_stored_again_nor_revived(world):  # noqa: F811
    """A finding id already held (an earlier try's commit, a merged item) stays as it is: still one row, its status kept,
    the job `done`. (Flow 1 step 5: ids are unique for good)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        row = F.defender_row(job)
        call(dsn, "publish_findings", T1, "earlier-try", [row], kind="finding")
        execute(dsn, "UPDATE learning.work_items SET status = 'published' WHERE item_key = %s", (row["finding_id"],))
        child.records[job] = outcome(findings=screened(row))
        await learning_worker(world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
                              slots=2, learning_slots=1).drain()
    assert job_row(dsn, job)["publish_state"] == "done"
    assert F.all_items(dsn) == [(T1, "finding", row["finding_id"])]
    assert execute(dsn, "SELECT status FROM learning.work_items") == [("published",)]


async def test_1565_a_different_finding_at_a_held_id_refuses_the_jobs_findings_and_the_ending_stands(world):  # noqa: F811
    """A held id arriving with different content is a collision: the job's findings are refused whole (none stored, the
    held row unchanged), the job still `completed`. (#1565 item 1)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        held = F.defender_row(job)
        call(dsn, "publish_findings", T1, "earlier-try", [held], kind="finding")
        child.records[job] = outcome(findings=screened(dict(held, finding="a different narrative"),
                                                       F.defender_row(job, 1)))
        await learning_worker(world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
                              slots=2, learning_slots=1).drain()
    row = job_row(dsn, job)
    assert (row["status"], row["publish_state"]) == ("completed", "refused"), row
    assert F.all_items(dsn) == [(T1, "finding", held["finding_id"])], "a refused job's findings were stored"
    assert execute(dsn, "SELECT payload->>'finding' FROM learning.work_items") == [(held["finding"],)]


@pytest.mark.parametrize("second", ["same", "other"])
async def test_1565_the_episodes_repeats_are_decided_at_the_jobs_end(world, second):  # noqa: F811
    """The episode holds every row as given; the job's end decides: an identical repeat is stored once, two contents at
    one id refuse the job's findings whole, the job still `completed`. (#1565)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        first = F.defender_row(job)
        again = dict(first) if second == "same" else dict(first, finding="a different narrative")
        child.records[job] = outcome(findings=screened(first, again, F.defender_row(job, 1)))
        await learning_worker(world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
                              slots=2, learning_slots=1).drain()
    row = job_row(dsn, job)
    if second == "same":
        assert (row["status"], row["publish_state"]) == ("completed", "done"), row
        assert sorted(F.all_items(dsn)) == sorted(
            [(T1, "finding", first["finding_id"]), (T1, "finding", F.defender_row(job, 1)["finding_id"])])
    else:
        assert (row["status"], row["publish_state"]) == ("completed", "refused"), row
        assert F.all_items(dsn) == [], "a refused job's findings were stored"


@pytest.mark.parametrize(("table", "when"), [(ITEMS, "TRUE"), ("jobs.learning_jobs", "NEW.status = 'completed'")],
                         ids=["fails-at-the-insert", "fails-at-the-completed-update"])
async def test_p3_the_ending_and_its_findings_become_visible_together_across_an_outage(world, table, when):  # noqa: F811
    """A deadlock at the insert rolls the whole end write back: sampled throughout, no instant shows the job `completed`
    without its findings; the retry lands both, one attempt. (P3, O3)"""
    dsn = world["dsn"]
    samples: list[tuple] = []
    stop = threading.Event()

    def sample():
        while not stop.is_set():
            rows = execute(dsn, "SELECT status, publish_state, (SELECT count(*) FROM learning.work_items) "
                                "FROM jobs.learning_jobs")
            samples.extend(rows)
            time.sleep(0.02)

    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        child.records[job] = _both(job)
        F.trigger_fault(dsn, table, "40P01", once=True, when=when)
        watcher = threading.Thread(target=sample, daemon=True)
        watcher.start()
        try:
            await asyncio.wait_for(learning_worker(
                world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
                slots=2, learning_slots=1).drain(), timeout=120)
        finally:
            stop.set()
            watcher.join()
    assert F.fault_fired(dsn), "premise: the insert met the deadlock"
    assert any(s[0] == "running" for s in samples), "premise: sampled before the end"
    assert not [s for s in samples if (s[0] == "completed") != (s[2] == 3)], samples
    row = job_row(dsn, job)
    assert (row["status"], row["publish_state"], row["attempt"] if "attempt" in row else 1) == ("completed", "done", 1)  # noqa: SIM401
    assert len(_stored(dsn, job)) == 3, "the retry stored the findings once"


# --- O3 -----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("sqlstate", F.OUTAGE_SQLSTATES, ids=F.OUTAGE_IDS)
async def test_o3_an_outage_at_the_insert_retries_and_never_refuses(world, sqlstate):  # noqa: F811
    """The first insert dies of an outage-class error; the end write is retried and the findings are stored, `done`.
    (O3, P4: `is_outage` retries)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        child.records[job] = _both(job)
        F.trigger_fault(dsn, ITEMS, sqlstate, once=True)
        await asyncio.wait_for(learning_worker(
            world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
            slots=2, learning_slots=1).drain(), timeout=120)
    assert F.fault_fired(dsn)
    assert job_row(dsn, job)["publish_state"] == "done"
    assert len(_stored(dsn, job)) == 3


@pytest.mark.parametrize("make", F.OUTAGE_FAULTS, ids=F.OUTAGE_FAULT_IDS)
async def test_o3_an_outage_with_no_sqlstate_at_the_insert_retries_and_never_refuses(world, make):  # noqa: F811
    """A lost or closed connection, an interface error, a pool timeout or an invalidated connection, none carrying a
    SQLSTATE, at the first insert: the end write is retried and the findings are stored, `done`, one attempt. (O3, P4:
    `is_outage` names these, whatever their SQLSTATE)"""
    fault = make()
    assert getattr(getattr(fault, "orig", None), "sqlstate", None) is None, "premise: no SQLSTATE"
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        child.records[job] = _both(job)
        with F.statement_fault(fault, once=True) as hit:
            await asyncio.wait_for(learning_worker(
                world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
                slots=2, learning_slots=1).drain(), timeout=120)
    assert hit, "premise: the insert met the fault"
    row = job_row(dsn, job)
    assert (row["status"], row["publish_state"]) == ("completed", "done"), row
    assert len(_stored(dsn, job)) == 3
    assert len(jobs_of(dsn, _inv(dsn, job))) == 1, "the retry was a new attempt"


# #1546 D11 retired `test_o2_a_refusal_is_logged_with_the_job_it_refused`: the kinds it logged (text that is not an object,
# a row failing its rule) are the screen's, which now runs in the helper on receipt; the worker sees only `refused{reason}`.


# --- O2, P4: refusals; the ending stands -----------------------------------------------------------------------


async def test_o2_a_job_ending_refused_does_not_pause_the_workers_claims(world):  # noqa: F811
    """One job's findings are refused at the insert (SQLSTATE class 54, which the driver calls an operational error);
    the next job, queued behind it with one learning slot, is claimed, ends and stores its findings in the same drain.
    (O2, P4 order: class 54 refuses before `is_outage` retries)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        a = await queued_job(world, store, ticket="J-1")
        b = await queued_job(world, store, ticket="J-2")
        execute(dsn, "UPDATE jobs.learning_jobs SET created_at = created_at - interval '1 hour' WHERE id = %s", (a,))
        child.records[a], child.records[b] = _both(a), _both(b)
        F.trigger_fault(dsn, ITEMS, "54000", when=f"NEW.source_run = '{a}'")
        await asyncio.wait_for(learning_worker(
            world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
            slots=2, learning_slots=1).drain(), timeout=120)
    _refused_whole(dsn, a)
    assert job_row(dsn, b)["publish_state"] == "done" and len(_stored(dsn, b)) == 3  # noqa: PT018


@pytest.mark.parametrize("sqlstate", F.REFUSED_SQLSTATES)
async def test_o2_p4_an_insert_error_the_content_causes_refuses_the_findings(world, sqlstate):  # noqa: F811
    """Data (22), integrity (23), limits (54): the findings are refused whole, the completed ending stands, no retry.
    (O2, P4)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        child.records[job] = _both(job)
        F.trigger_fault(dsn, ITEMS, sqlstate)
        await asyncio.wait_for(learning_worker(
            world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
            slots=2, learning_slots=1).drain(), timeout=120)
    _refused_whole(dsn, job)


def _stored_in_place(dsn: str, job: str) -> None:
    """The findings stored, `done`, by the job's first and only attempt: the end write was retried, not the job."""
    row = job_row(dsn, job)
    assert (row["status"], row["publish_state"]) == ("completed", "done"), row
    assert len(_stored(dsn, job)) == 3
    assert len(jobs_of(dsn, _inv(dsn, job))) == 1, "the job was run again, not its end write retried"


@pytest.mark.parametrize("sqlstate", F.UNSTORED_SQLSTATES)
async def test_r53_a_database_error_neither_content_nor_outage_retries_the_end_in_place(world, sqlstate, caplog):  # noqa: F811
    """A permission error at the first insert says nothing about the findings: they are not refused, the job is not
    run again; its end write is retried in place, logged as an error, and stores them. (Amendment r5.3)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        child.records[job] = _both(job)
        F.trigger_fault(dsn, ITEMS, sqlstate, once=True)
        await asyncio.wait_for(learning_worker(
            world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
            slots=2, learning_slots=1).drain(), timeout=120)
    assert F.fault_fired(dsn)
    _stored_in_place(dsn, job)
    assert any(r.levelname == "ERROR" and "could not be stored" in r.getMessage() for r in caplog.records), caplog.text


@pytest.mark.parametrize("exc", F.UNSTORED_EXCEPTIONS, ids=lambda e: type(e).__name__)
async def test_r53_an_exception_in_the_insert_retries_the_end_in_place(world, exc):  # noqa: F811
    """A non-database error raised in the insert path at the first try: not refused, not a new attempt; the end write
    is retried and the findings stored. (Amendment r5.3)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        child.records[job] = _both(job)
        with F.statement_fault(exc, once=True) as hit:
            await asyncio.wait_for(learning_worker(
                world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
                slots=2, learning_slots=1).drain(), timeout=120)
    assert hit, "premise: the insert statement was reached"
    _stored_in_place(dsn, job)


def _blocked_on_items(dsn: str) -> bool:
    return bool(execute(dsn, "SELECT 1 FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                             "AND query ILIKE '%INSERT INTO learning.work_items%' AND pid <> pg_backend_pid()"))


async def test_p4_o3_a_worker_cut_off_at_the_insert_never_commits_a_refusal_and_the_job_reruns(world):  # noqa: F811
    """The insert is held on a table lock and the worker is cancelled there (real cancellation, a `BaseException`): the
    row stays `running` with nothing stored and no publish state; its lease then lapses and a take-over reruns the job
    as attempt 2, the first run's findings not stored. (P4: never caught; O3)"""
    import psycopg

    from defender.tests.jobs.test_1344_learning_jobs import _lapse

    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        child.records[job] = _both(job)
        inv = _inv(dsn, job)
        holder = psycopg.connect(dsn, autocommit=False)
        try:
            holder.execute("LOCK TABLE learning.work_items IN ACCESS EXCLUSIVE MODE")
            draining = asyncio.create_task(learning_worker(
                world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
                slots=2, learning_slots=1, renewal_interval=0.2).drain())
            for _ in range(400):
                if _blocked_on_items(dsn):
                    break
                await asyncio.sleep(0.05)
            else:
                pytest.fail("premise: the end write never reached the insert")
            # One cancel only starts the worker's stop, which waits for its row tasks; only a cancel that lands during
            # that wait leaves now (`Worker._leave`). Cancel again until the drain is done.
            for _ in range(100):
                draining.cancel()
                await asyncio.wait([draining], timeout=0.3)
                if draining.done():
                    break
            else:
                pytest.fail("the worker did not leave after repeated cancels")
            await asyncio.gather(draining, return_exceptions=True)
        finally:
            holder.rollback()
            holder.close()
        row = job_row(dsn, job)
        assert (row["status"], row["publish_state"]) == ("running", "none"), row
        assert _stored(dsn, job) == []
        _lapse(dsn, job)
        await store.take_over()
    old, new = jobs_of(dsn, inv)
    assert (old["status"], old["reason"], new["attempt"], new["status"]) == ("failed", "lease_lapsed", 2, "queued")
    assert _stored(dsn, job) == []


# #1546 D11 retired `test_o2_p4_an_exception_in_the_screen_refuses_the_findings_and_the_ending_stands`: the worker runs no
# screen (its `screen_findings=` seam went with it); a screen that fails in the helper stages `refused{reason}`.


async def test_o2_a_deterministic_failure_on_the_jobs_update_steps_the_lesser_end_chain_down(world):  # noqa: F811
    """Chain: as decided (`done`) refused by the database -> `completed` with findings refused -> `failed:
    worker_error`. First the job row refuses only a `done` state; then it refuses any `completed`. (Flow 1 step 4)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        a = await queued_job(world, store, ticket="J-1")
        child.records[a] = _both(a)
        F.trigger_fault(dsn, "jobs.learning_jobs", "22001", when="NEW.publish_state = 'done'")
        await asyncio.wait_for(learning_worker(
            world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
            slots=2, learning_slots=1).drain(), timeout=120)
    _refused_whole(dsn, a)


async def test_o2_a_refused_whole_ending_that_the_job_row_also_refuses_is_failed_worker_error(world):  # noqa: F811
    """The last step: any `completed` write refused -> `failed`/`worker_error`, nothing stored. (Flow 1 step 4)"""
    dsn = world["dsn"]
    child = _staging_child(world)
    async with job_store(dsn) as store:
        a = await queued_job(world, store, ticket="J-1")
        child.records[a] = _both(a)
        F.trigger_fault(dsn, "jobs.learning_jobs", "22001", when="NEW.status = 'completed'")
        await asyncio.wait_for(learning_worker(
            world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
            slots=2, learning_slots=1).drain(), timeout=120)
    row = job_row(dsn, a)
    assert (row["status"], row["reason"]) == ("failed", "worker_error"), row
    assert _stored(dsn, a) == []


@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
async def test_o2_a_tenant_not_active_at_the_end_refuses_the_findings_and_the_ending_stands(world, state):  # noqa: F811
    """The tenant moves out of `active` while the family runs: `completed`, publish `refused`, nothing stored, no raise
    and no retry. (O2, Flow 1 step 3)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release"
    child = _staging_child(world, wait_for=release)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        child.records[job] = _both(job)
        draining = asyncio.create_task(learning_worker(
            world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
            slots=2, learning_slots=1, renewal_interval=0.2).drain())
        try:
            for _ in range(200):
                if child.seen(job):
                    break
                await asyncio.sleep(0.05)
            move_tenant(dsn, T1, state=state)
        finally:
            release.touch()
        await asyncio.wait_for(draining, timeout=120)
    _refused_whole(dsn, job)


def _end_write_waits_on_a_lock(dsn: str, holder_pid: int) -> bool:
    """Whether a backend of this database other than the offboard's waits on a lock on the tenants table."""
    return bool(execute(dsn, "SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' "
                             "AND pid NOT IN (%s, pg_backend_pid()) AND query ILIKE '%%tenancy.tenants%%'", (holder_pid,)))


@pytest.mark.parametrize("ends_the_row", [False, True], ids=["offboard-commits", "offboard-then-ends-the-job-row"])
async def test_o2_the_end_write_takes_the_tenant_lock_first_waiting_out_an_offboard_and_never_deadlocking_it(
        world, ends_the_row):  # noqa: F811
    """An offboard's transaction holds the tenant row (moved to `offboarding`, not committed) as the job's completed
    record lands: the end write waits on the tenant lock, holding nothing the offboard needs. Committed alone, the end
    write then reads the tenant not active and refuses the findings; when the offboard first ends the job row as it
    does, that statement runs at once, no deadlock, and the end write finds its row moved. (Flow 1 step 3: the tenant
    share lock first; tenancy's lock rule, G13)"""
    import psycopg

    from defender.tests.support.tenancy._active1214 import _JOB

    dsn = world["dsn"]
    release = world["tmp"] / "release"
    child = _staging_child(world, wait_for=release)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        child.records[job] = _both(job)
        draining = asyncio.create_task(learning_worker(
            world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
            slots=2, learning_slots=1, renewal_interval=0.2).drain())
        holder = psycopg.connect(dsn, autocommit=False)
        try:
            for _ in range(400):
                if child.seen(job):
                    break
                await asyncio.sleep(0.05)
            else:
                pytest.fail("premise: the job's child started")
            action, step, actor = _JOB["offboarding"]
            holder.execute("SET lock_timeout = '20s'")
            holder.execute("UPDATE tenancy.tenants SET state = 'offboarding', pending_action = %s, step = %s, "
                           "step_actor = %s WHERE id = %s", (action, step, actor, T1))
            holder_pid = holder.info.backend_pid
            release.touch()
            for _ in range(600):
                if _end_write_waits_on_a_lock(dsn, holder_pid) or job_row(dsn, job)["status"] != "running":
                    break
                await asyncio.sleep(0.05)
            # Past the deadlock timeout (1 s), so a cycle the next statement closes is found by the offboard's own wait.
            await asyncio.sleep(1.5)
            assert _end_write_waits_on_a_lock(dsn, holder_pid), "the end write did not wait for the offboard's tenant lock"
            assert (job_row(dsn, job)["status"], _stored(dsn, job)) == ("running", []), "the end write went past the offboard"
            if ends_the_row:
                try:
                    await asyncio.to_thread(
                        holder.execute, "UPDATE jobs.learning_jobs SET status = 'skipped', reason = 'tenant_offboarded', "
                        "message = 'offboarded', finished_at = now(), lease_expires_at = NULL WHERE id = %s "
                        "AND status = 'running'", (job,))
                except psycopg.errors.DeadlockDetected:
                    pytest.fail("the offboard ending the job row deadlocked with the end write: it holds the row")
                assert _end_write_waits_on_a_lock(dsn, holder_pid), "the end write stopped waiting before the commit"
            holder.commit()
        finally:
            holder.close()
            release.touch()
        await asyncio.wait_for(draining, timeout=120)
    if ends_the_row:
        row = job_row(dsn, job)
        assert (row["status"], row["reason"], row["publish_state"]) == ("skipped", "tenant_offboarded", "none"), row
        assert _stored(dsn, job) == []
        assert len(jobs_of(dsn, _inv(dsn, job))) == 1
    else:
        _refused_whole(dsn, job)


# --- O2: generated findings content -------------------------------------------------------------------------------
# #1546 D11 retired the worker-side screen cases: generated bad content, one bad row beside valid ones, the 8 MiB cap, the
# multibyte row bound and cap, and the row and id bounds. The helper screens on receipt with #1487's unchanged rules
# (`learning/judge/test_1487_screen_findings.py` holds the bounds, caps, failing rows and non-list rows;
# `test_1546_helper_records.py::test_findings_that_fail_the_screen_or_the_cap_are_staged_refused_inside_a_valid_outcome`
# the staging), and the worker's half, `refused{reason}` -> `publish_state = refused` with the ending standing, is
# `test_1546_worker_end.py::test_findings_the_helper_refused_read_publish_state_refused_and_the_ending_stands`.
