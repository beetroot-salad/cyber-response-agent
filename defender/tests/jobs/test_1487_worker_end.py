"""#1487 (design r5): the worker's end write stores a completed learning job's findings with its ending (O1, P3), refuses
them whole when their content or the tenant says so while the decided ending stands (O2, P4), and retries on an outage
(O3). Real database; the learning child is scripted and leaves the end record a case names; faults are real triggers
and statement hooks (`_findings1487`)."""
from __future__ import annotations

import asyncio
import json
import random
import threading
import time

import pytest

from defender.tests.jobs.test_1344_learning_jobs import (
    jobs_of,
    job_row,
    learning_worker,
    queued_job,
    world,  # noqa: F401 — fixture
)
from defender.tests.support.jobs import _findings1487 as F
from defender.tests.support.jobs._jobs1342 import T1, JobsAudit, job_store, move_tenant
from defender.tests.support.learning.core._store1278 import call
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

ITEMS = "learning.work_items"


async def _run(world, jobs_with, *, children=None, slots=1, ticket="J", **kw):  # noqa: F811
    """Queue one job per `jobs_with(job_id) -> record text`, run the worker to the end of them all; the job ids."""
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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
    return F.record(findings=F.ok([F.defender_row(job, 0), F.defender_row(job, 1)], [F.world_row(job, 0)]), count=99)


# --- O1, P3 --------------------------------------------------------------------------------------------------


async def test_o1_a_completed_jobs_findings_are_stored_waiting_for_its_tenant_with_its_ending(world):  # noqa: F811
    """Both channels' rows land `waiting`, tenant and `source_run` the job's, publish state `done` (the record's
    old count of 99 ignored, #1589). (O1, Flow 1 step 3)"""
    dsn = world["dsn"]
    [job] = await _run(world, [_both])
    row = job_row(dsn, job)
    assert (row["status"], row["publish_state"]) == ("completed", "done"), row
    assert _stored(dsn, job) == [(T1, "finding", f"{job}/w-b/0/0", "waiting"), (T1, "finding", f"{job}/w-b/0/1", "waiting"),
                                 (T1, "questioner_finding", f"{job}/w-c/0/0", "waiting")]
    [(payload,)] = execute(dsn, "SELECT payload FROM learning.work_items WHERE item_key = %s", (f"{job}/w-c/0/0",))
    assert payload == F.world_row(job, 0)


async def test_o1_zero_findings_read_done_and_store_nothing(world):  # noqa: F811
    """`ok` with both channels empty: `done`, no rows. (O1)"""
    [job] = await _run(world, [lambda j: F.record(findings=F.ok(), count=5)])
    row = job_row(world["dsn"], job)
    assert (row["status"], row["publish_state"]) == ("completed", "done")
    assert _stored(world["dsn"], job) == []


async def test_1589_the_finish_audit_names_how_many_rows_the_end_added(world, caplog):  # noqa: F811
    """With the row's count gone (#1589), the number of rows the end write added is in the store's own finish event:
    three rows of a job with three, none of a job with none (its record's old count, not even a number, ignored), and no count
    for a refused one."""
    audit = JobsAudit(caplog)
    [first] = await _run(world, [_both])
    [again] = await _run(world, [lambda j: F.record(findings=F.ok(), count="not a count")], ticket="again")
    [refused] = await _run(world, [lambda j: F.record(findings={"state": "malformed"})], ticket="refused")
    details = {e.target: e.detail for e in audit.events() if e.action == "learning_job.finish"}
    assert details[first] == "status=completed findings=done added=3", details
    assert details[again] == "status=completed findings=done added=0", details
    assert details[refused] == "status=completed findings=refused", details


@pytest.mark.parametrize("status", ["failed", "skipped"])
async def test_o1_another_ending_ignores_findings_it_carries(world, status):  # noqa: F811
    """A failed or skipped record carrying valid `ok` findings (or garbage) stores nothing and stays `none`. (Data model)"""
    dsn = world["dsn"]
    reason, extra = ("judge_failed", {}) if status == "failed" else ("no_fork_point", {})
    make = lambda found: (lambda j: F.record(status, reason, message="m", findings=found(j)))  # noqa: E731
    good, junk = await _run(world, [make(lambda j: F.ok([F.defender_row(j)])), make(lambda j: "garbage")])
    for job in (good, junk):
        row = job_row(dsn, job)
        assert (row["status"], row["reason"], row["publish_state"]) == (status, reason, "none"), row
        assert _stored(dsn, job) == []


async def test_o1_a_stored_finding_id_is_not_stored_again_nor_revived(world):  # noqa: F811
    """A finding id already held (an earlier try's commit, a merged item) stays as it is: still one row, its status kept,
    the job `done`. (Flow 1 step 5: ids are unique for good)"""
    dsn = world["dsn"]
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        row = F.defender_row(job)
        call(dsn, "publish_findings", T1, "earlier-try", [row], kind="finding")
        execute(dsn, "UPDATE learning.work_items SET status = 'published' WHERE item_key = %s", (row["finding_id"],))
        child.records[job] = F.record(findings=F.ok([row]))
        await learning_worker(world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
                              slots=2, learning_slots=1).drain()
    assert job_row(dsn, job)["publish_state"] == "done"
    assert F.all_items(dsn) == [(T1, "finding", row["finding_id"])]
    assert execute(dsn, "SELECT status FROM learning.work_items") == [("published",)]


async def test_1565_a_different_finding_at_a_held_id_refuses_the_jobs_findings_and_the_ending_stands(world):  # noqa: F811
    """A held id arriving with different content is a collision: the job's findings are refused whole (none stored, the
    held row unchanged), the job still `completed`. (#1565 item 1)"""
    dsn = world["dsn"]
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        held = F.defender_row(job)
        call(dsn, "publish_findings", T1, "earlier-try", [held], kind="finding")
        child.records[job] = F.record(findings=F.ok([dict(held, finding="a different narrative"),
                                                     F.defender_row(job, 1)]))
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
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        first = F.defender_row(job)
        again = dict(first) if second == "same" else dict(first, finding="a different narrative")
        child.records[job] = F.record(findings=F.ok([first, again, F.defender_row(job, 1)]))
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

    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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


async def test_o2_a_refusal_is_logged_with_the_job_it_refused(world, caplog):  # noqa: F811
    """Each refused job's findings leave a log line carrying its job id and the refusal's kind: two jobs refused for
    different kinds (text that is not an object, a row failing its rule) log lines that differ once the job id is
    removed, and neither line names the other job. "Counted" is the stored `refused` row, pinned by `_refused_whole`.
    (O2, amendment r5.1 item 3; the design fixes no wording for a kind)"""
    import logging

    caplog.set_level(logging.INFO)
    shape = lambda j: F.record(findings={"state": "ok", "text": json.dumps([1, 2])})  # noqa: E731
    rule = lambda j: F.record(findings=F.ok([dict(F.defender_row(j), type="not-a-type")]))  # noqa: E731
    a, b = await _run(world, [shape, rule], slots=2)
    kinds = {}
    for job, other in ((a, b), (b, a)):
        _refused_whole(world["dsn"], job)
        lines = [r.getMessage() for r in caplog.records if job in r.getMessage() and "refus" in r.getMessage().lower()]
        assert lines, f"no log line names the refused job {job}"
        assert not [line for line in lines if other in line], "a refusal's line names another job"
        kinds[job] = sorted(line.replace(job, "<job>") for line in lines)
    assert kinds[a] != kinds[b], f"two kinds of refusal logged alike: {kinds[a]}"


# --- O2, P4: refusals; the ending stands -----------------------------------------------------------------------


async def test_o2_a_job_ending_refused_does_not_pause_the_workers_claims(world):  # noqa: F811
    """One job's findings are refused at the insert (SQLSTATE class 54, which the driver calls an operational error);
    the next job, queued behind it with one learning slot, is claimed, ends and stores its findings in the same drain.
    (O2, P4 order: class 54 refuses before `is_outage` retries)"""
    dsn = world["dsn"]
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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


@pytest.mark.parametrize("exc", [RuntimeError("boom"), ValueError("v"), OSError("disk")], ids=lambda e: type(e).__name__)
async def test_o2_p4_an_exception_in_the_screen_refuses_the_findings_and_the_ending_stands(world, exc):  # noqa: F811
    """The row screen raising anything: refused, completed, nothing stored. The screen is the worker's injected
    collaborator (`screen_findings=` on `Worker`, default `learning.judge.enqueue.screen_findings`). (O2, P4: screening
    is total; amendment r5.1 item 6)"""
    screen = F.raising_screen(exc)
    [job] = await _run(world, [_both], screen_findings=screen)
    assert screen.called, "premise: the screen was reached"
    _refused_whole(world["dsn"], job)


async def test_o2_a_deterministic_failure_on_the_jobs_update_steps_the_lesser_end_chain_down(world):  # noqa: F811
    """Chain: as decided (`done`) refused by the database -> `completed` with findings refused -> `failed:
    worker_error`. First the job row refuses only a `done` state; then it refuses any `completed`. (Flow 1 step 4)"""
    dsn = world["dsn"]
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
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
    child = F.child_class()(world["tmp"] / "job", world["runs"], wait_for=release)
    child.records = {}
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
    child = F.child_class()(world["tmp"] / "job", world["runs"], wait_for=release)
    child.records = {}
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


# --- O2: generated findings content ---------------------------------------------------------------------------------


def _json_value(rng: random.Random, depth: int = 0):
    kinds = ["null", "bool", "int", "float", "str"] + ([] if depth > 3 else ["list", "dict"])
    kind = rng.choice(kinds)
    if kind == "null":
        return None
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "int":
        return rng.choice([0, -1, 7, 2**63, -(2**70), rng.randrange(-10**6, 10**6)])
    if kind == "float":
        return rng.choice([0.0, 1.5, -2.25e10, 1e-300])
    if kind == "str":
        return "".join(chr(rng.choice([rng.randrange(32, 127), 0, 0xD800, 0xE9, 0x1F600, 0x2028]))
                       for _ in range(rng.randrange(0, 12)))
    if kind == "list":
        return [_json_value(rng, depth + 1) for _ in range(rng.randrange(0, 4))]
    return {_json_value(rng, 9) if rng.random() < 0.1 else "k%d" % rng.randrange(5): _json_value(rng, depth + 1)  # noqa: UP031
            for _ in range(rng.randrange(0, 4))}


def _non_list(rng):
    while True:
        v = _json_value(rng)
        if not isinstance(v, list):
            return v


def _non_dict(rng):
    while True:
        v = _json_value(rng)
        if not isinstance(v, dict):
            return v


def _bad_cases(job: str, other: str, seed: int):
    """`(label, findings field)`: every one a content class the design says is refused whole."""
    rng = random.Random(seed)
    good, world_good = F.defender_row(job, 0), F.world_row(job, 0)
    cases = []
    for n in range(3):
        v = _non_dict(rng)
        cases.append((f"non-object-text-{n}", {"state": "ok", "text": json.dumps(v)}))
    for n in range(3):
        raw = "".join(chr(rng.choice([rng.randrange(0, 0x80), 0xD800, rng.randrange(0x80, 0x3000), 0])) for _ in range(40))
        cases.append((f"not-json-{n}", {"state": "ok", "text": raw}))
    for n in range(3):
        cases.append((f"non-list-channel-{n}", {"state": "ok", "text": json.dumps(
            {F.FINDING: _non_list(rng), F.QUESTIONER: []})}))
        cases.append((f"non-list-questioner-{n}", {"state": "ok", "text": json.dumps(
            {F.FINDING: [good], F.QUESTIONER: _non_list(rng)})}))
    for n in range(4):
        cases.append((f"non-dict-row-{n}", {"state": "ok", "text": json.dumps(
            {F.FINDING: [good, _non_dict(rng)], F.QUESTIONER: [world_good]})}))
    ids = [f"{other}/w-b/0/0", job, f"{job}x/w-b/0/0", "", f"/{job}/w-b/0/0", f"{job.upper()}/w-b/0/0", 5, None, [job]]
    for n, bad in enumerate(ids):
        cases.append((f"foreign-id-{n}", {"state": "ok", "text": json.dumps(
            {F.FINDING: [good, dict(F.defender_row(job, 1), finding_id=bad)], F.QUESTIONER: [world_good]})}))
        cases.append((f"foreign-id-questioner-{n}", {"state": "ok", "text": json.dumps(
            {F.FINDING: [good], F.QUESTIONER: [dict(world_good, finding_id=bad)]})}))
    from defender.learning.judge.enqueue import FINDING_ID_MAX_BYTES, FINDING_ROW_MAX_BYTES

    by_bytes_only = [(f"id-chars-within-bytes-over-{len(filler.encode())}b",
                      F.id_over_in_bytes_only(job, FINDING_ID_MAX_BYTES, filler)) for filler in F.MULTIBYTE_FILLERS]
    for label, long_id in (("id-one-over", F.id_of_utf8_bytes(job, FINDING_ID_MAX_BYTES + 1)), *by_bytes_only,
                           ("id-long", f"{job}/" + "x" * 100_000)):
        cases.append((label, {"state": "ok", "text": json.dumps(
            {F.FINDING: [dict(good, finding_id=long_id)], F.QUESTIONER: []})}))
    cases.append(("row-one-over", {"state": "ok", "text": json.dumps(
        {F.FINDING: [F.row_of_json_bytes(good, FINDING_ROW_MAX_BYTES + 1, compact=True)], F.QUESTIONER: []})}))
    cases.append(("row-huge", {"state": "ok", "text": json.dumps(
        {F.FINDING: [dict(good, finding=("y" * (6 * 1024 * 1024)))], F.QUESTIONER: []})}))
    cases.append(("lone-surrogate-in-id", {"state": "ok", "text": json.dumps(
        {F.FINDING: [dict(good, finding_id=f"{job}/w-b/0/\ud800")], F.QUESTIONER: []})}))
    for key in ("finding", "subject_anchor"):
        cases.append((f"nul-in-value-{key}", {"state": "ok", "text": json.dumps(
            {F.FINDING: [dict(good, **{key: "a\x00b"})], F.QUESTIONER: [world_good]})}))
    cases.append(("nul-in-key", {"state": "ok", "text": json.dumps(
        {F.FINDING: [dict(good, **{"x\x00": 1})], F.QUESTIONER: []})}))
    cases.append(("lone-surrogate", {"state": "ok", "text": json.dumps(
        {F.FINDING: [dict(good, finding="\ud800")], F.QUESTIONER: []})}))
    cases.append(("missing-id", {"state": "ok", "text": json.dumps(
        {F.FINDING: [{k: v for k, v in good.items() if k != "finding_id"}], F.QUESTIONER: []})}))
    cases.append(("defender-row-in-questioner-channel", {"state": "ok", "text": json.dumps(
        {F.FINDING: [], F.QUESTIONER: [good]})}))
    for depth in (101, 150, 2000, 200_000):
        cases.append((f"nested-text-{depth}", {"state": "ok", "text": "[" * depth + "]" * depth}))
    cases.append(("nested-in-row", {"state": "ok", "text": F.text_of([good]).replace(
        '"finding": "narrative"', '"finding": ' + "[" * 150 + "]" * 150)}))
    cases.append(("over-cap-9mib-padding", {"state": "ok", "text": F.text_of() + " " * (9 * 1024 * 1024)}))
    cases.append(("state-over-cap", {"state": "over_cap"}))
    cases.append(("state-unreadable", {"state": "unreadable"}))
    cases.append(("state-malformed", {"state": "malformed"}))
    good_text = F.text_of([good])
    for label, found in (("over-cap-with-text", {"state": "over_cap", "text": good_text}),
                         ("unreadable-with-text", {"state": "unreadable", "text": good_text}),
                         ("malformed-with-text", {"state": "malformed", "text": good_text}),
                         ("ok-no-text", {"state": "ok"}), ("ok-null-text", {"state": "ok", "text": None}),
                         ("ok-int-text", {"state": "ok", "text": 5}), ("ok-list-text", {"state": "ok", "text": [good]}),
                         ("ok-object-text", {"state": "ok", "text": {F.FINDING: [good]}}),
                         ("state-case", {"state": "OK", "text": good_text}), ("state-padded", {"state": "ok ", "text": good_text}),
                         ("state-empty", {"state": "", "text": good_text}), ("state-int", {"state": 1, "text": good_text}),
                         ("state-unknown", {"state": "published", "text": good_text}), ("empty-object", {}),
                         ("no-state", {"text": good_text}), ("string", "ok"), ("list", [good]), ("null", None),
                         ("int", 7)):
        cases.append((label, found))
    return cases


async def test_o2_p4_generated_bad_findings_content_is_refused_whole_and_the_completed_ending_stands(world):  # noqa: F811
    """Each content class (bad text, shape, id, size, nesting, state; arbitrary JSON values and characters): the job
    reads `completed`, publish `refused`, nothing of it stored, no retry; the positive control beside them stores. A
    record with no `findings` at all reads refused too. (O2, P4)"""
    dsn = world["dsn"]
    child = F.child_class()(world["tmp"] / "job", world["runs"])
    child.records = {}
    labels: dict[str, str] = {}
    async with job_store(dsn) as store:
        control = await queued_job(world, store, ticket="C-0")
        child.records[control] = _both(control)
        absent = await queued_job(world, store, ticket="A-0")
        child.records[absent] = F.record()
        other = await queued_job(world, store, ticket="O-0")
        child.records[other] = F.record("failed", "judge_failed", message="m")
        count = len(_bad_cases("J", other, 1487))
        for n in range(count):
            job = await queued_job(world, store, ticket=f"B-{n}")
            label, found = _bad_cases(job, other, 1487)[n]
            labels[job] = label
            child.records[job] = F.record(findings=found)
        worker = learning_worker(world, store, job=child, post=F.quiet_post_class()(world["tmp"] / "post", world["runs"]),
                                 slots=8, learning_slots=7)
        await asyncio.wait_for(worker.drain(), timeout=900)
    assert job_row(dsn, control)["publish_state"] == "done" and len(_stored(dsn, control)) == 3, "control"  # noqa: PT018
    _refused_whole(dsn, absent)
    bad = [j for j in labels]
    assert len(bad) > 60, "premise: the generated classes"
    failures = []
    for job in bad:
        row = job_row(dsn, job)
        if (row["status"], row["reason"], row["publish_state"]) != ("completed", None, "refused") or _stored(dsn, job):
            failures.append((labels[job], row["status"], row["reason"], row["publish_state"]))
    assert not failures, failures


async def test_o2_generated_valid_content_beside_it_is_stored_and_one_bad_row_takes_the_whole_job_down(world):  # noqa: F811
    """Two jobs differing only in one extra row failing its rule: the one with only valid rows stores all of them; the
    other stores none of them, in either channel. (O2: "stores nothing of that job in either channel")"""
    dsn = world["dsn"]

    def mixed(job):
        bad = dict(F.world_row(job, 1), type="not-a-bucket")
        return F.record(findings=F.ok([F.defender_row(job, 0)], [F.world_row(job, 0), bad]))

    clean, dirty = await _run(world, [_both, mixed], slots=2)
    assert job_row(dsn, clean)["publish_state"] == "done" and len(_stored(dsn, clean)) == 3  # noqa: PT018
    _refused_whole(dsn, dirty)


async def test_o2_findings_over_the_cap_are_refused_at_the_cap_not_before_and_never_unread_the_ending(world):  # noqa: F811
    """Whitespace-padded text of exactly `FINDINGS_CAP_BYTES` is stored; one byte more is refused, and a 12 MiB text
    inside the envelope's own limit is a refusal too, not "no readable end record". (O2, Data model: 8 MiB of text)"""
    from defender.records.job_lane import FINDINGS_CAP_BYTES, findings_text_bytes

    def padded(extra: int):
        def make(job):
            base = F.text_of([F.defender_row(job)])
            text = base + " " * (FINDINGS_CAP_BYTES - findings_text_bytes(base) + extra)
            return F.record(findings={"state": "ok", "text": text})
        return make

    at, over, far = await _run(world, [padded(0), padded(1), padded(4 * 1024 * 1024)], slots=3)
    dsn = world["dsn"]
    assert job_row(dsn, at)["publish_state"] == "done" and len(_stored(dsn, at)) == 1  # noqa: PT018
    _refused_whole(dsn, over)
    _refused_whole(dsn, far)


@pytest.mark.parametrize("filler", F.MULTIBYTE_FILLERS, ids=["2-byte", "3-byte", "4-byte"])
async def test_o2_multibyte_findings_at_the_row_bound_and_the_cap_are_stored_and_one_byte_over_refuses_the_job(
        world, filler):  # noqa: F811
    """One encoding, UTF-8 bytes (owner, 2026-11-19), through the worker's end write: a row of 2-, 3- or 4-byte
    characters whose JSON written as UTF-8 is exactly `FINDING_ROW_MAX_BYTES` is stored, one byte more refuses the job;
    raw UTF-8 findings text of such characters exactly `FINDINGS_CAP_BYTES` long is stored, one byte more is refused.
    (O2; Data model: the cap; amendment r5.1 item 2)"""
    from defender.learning.judge.enqueue import FINDING_ROW_MAX_BYTES
    from defender.records.job_lane import FINDINGS_CAP_BYTES, findings_text_bytes

    def row_at(size):
        def make(job):
            row = F.row_of_json_bytes(F.defender_row(job, 0), size, filler=filler)
            assert findings_text_bytes(json.dumps(row)) > FINDING_ROW_MAX_BYTES, "premise: over the bound in escapes"
            return F.record(findings=F.ok([row]))
        return make

    rows_in_text = 27  # each 300 000 UTF-8 bytes, within the row bound by any measure; together just under the cap

    def text_at(extra):
        def make(job):
            base = F.text_of([F.row_of_json_bytes(F.defender_row(job, n), 300_000, filler=filler)
                              for n in range(rows_in_text)])
            text = base + " " * (FINDINGS_CAP_BYTES - findings_text_bytes(base) + extra)
            assert filler in text, "premise: the text is raw UTF-8"
            assert "\\u" not in text, "premise: the text holds no escapes"
            assert len(text) < FINDINGS_CAP_BYTES, "premise: within the cap in characters"
            return F.record(findings={"state": "ok", "text": text})
        return make

    at_row, over_row, at_cap, over_cap = await _run(
        world, [row_at(FINDING_ROW_MAX_BYTES), row_at(FINDING_ROW_MAX_BYTES + 1), text_at(0), text_at(1)], slots=4)
    dsn = world["dsn"]
    assert (job_row(dsn, at_row)["publish_state"], len(_stored(dsn, at_row))) == ("done", 1)
    _refused_whole(dsn, over_row)
    assert (job_row(dsn, at_cap)["publish_state"], len(_stored(dsn, at_cap))) == ("done", rows_in_text)
    _refused_whole(dsn, over_cap)


async def test_o2_a_row_and_an_id_at_their_bounds_are_stored_and_one_byte_over_refuses_the_job(world):  # noqa: F811
    """Through the worker's end write: a job whose rows are an id of exactly `FINDING_ID_MAX_BYTES` UTF-8 bytes
    (ASCII, and 2-, 3- and 4-byte characters) and a row whose JSON is exactly `FINDING_ROW_MAX_BYTES` stores all of them in
    both channels; one byte over either bound refuses the whole job. (O2, amendment r5.1 item 2)"""
    from defender.learning.judge.enqueue import FINDING_ID_MAX_BYTES, FINDING_ROW_MAX_BYTES

    def id_row(make, job, n, size, filler="x"):
        return dict(make(job, n), finding_id=F.id_of_utf8_bytes(job, size, filler))

    def at(job):
        return F.record(findings=F.ok(
            [id_row(F.defender_row, job, 0, FINDING_ID_MAX_BYTES),
             *(id_row(F.defender_row, job, n, FINDING_ID_MAX_BYTES, filler)
               for n, filler in enumerate(F.MULTIBYTE_FILLERS, 1)),
             F.row_of_json_bytes(F.defender_row(job, 4), FINDING_ROW_MAX_BYTES)],
            [id_row(F.world_row, job, 0, FINDING_ID_MAX_BYTES),
             F.row_of_json_bytes(F.world_row(job, 1), FINDING_ROW_MAX_BYTES)]))

    over = [lambda j: F.record(findings=F.ok([id_row(F.defender_row, j, 0, FINDING_ID_MAX_BYTES + 1)])),
            lambda j: F.record(findings=F.ok([], [id_row(F.world_row, j, 0, FINDING_ID_MAX_BYTES + 1)])),
            lambda j: F.record(findings=F.ok([F.defender_row(j, 0), F.row_of_json_bytes(
                F.defender_row(j, 1), FINDING_ROW_MAX_BYTES + 1, compact=True)])),
            lambda j: F.record(findings=F.ok([], [F.row_of_json_bytes(
                F.world_row(j, 0), FINDING_ROW_MAX_BYTES + 1, compact=True)]))]
    first, *refused = await _run(world, [at, *over], slots=len(over) + 1)
    dsn = world["dsn"]
    assert job_row(dsn, first)["publish_state"] == "done" and len(_stored(dsn, first)) == 7  # noqa: PT018
    for job in refused:
        _refused_whole(dsn, job)
