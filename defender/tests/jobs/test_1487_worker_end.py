"""#1487 sketch (design r1; D1 (a) staged findings, D2 adopted): the worker's side. The end write of a `completed`
learning job makes that job's staged findings claimable and sets its publish state from the helper's answer, in one
transaction; any other ending deletes them. After a post-step, the worker decides from the store itself whether the
tenant's check clock keeps running: the post-step writes no record and the worker reads none. Real database; the
worker's children are scripted, as `test_1344_learning_jobs.py`."""
from __future__ import annotations

import json

import pytest

from defender.tests.jobs.test_1344_learning_jobs import (
    END,
    completed_investigation,
    job_child,
    job_row,
    learning_end,
    learning_worker,
    post_child,
    queued_job,
    world,  # noqa: F401 — fixture
)
from defender.tests.support.jobs._jobs1342 import T1, job_store
from defender.tests.support.learning.core._store1278 import call, finding
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


def _statuses(dsn: str, run_id: str) -> list[str]:
    return sorted(i.status for i in call(dsn, "work", T1) if i.source_run == run_id)


async def test_o1_d1a_the_completed_end_write_makes_the_jobs_staged_findings_waiting_and_another_ending_drops_them(
        world):  # noqa: F811 — the imported fixture
    """Two running jobs each hold a staged finding (as the helper's hand-in leaves it). A's end write `completed`, the
    helper's answer `done`, makes A's row `done` and its finding `waiting`; B's `failed` end leaves its row `none` and
    deletes its staged finding. (O1, D1 a, Flow 1 step 4)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        await completed_investigation(store, ticket="J-1", key="k1")
        await completed_investigation(store, ticket="J-2", key="k2")
        a = (await store.claim_learning_job()).record.learning_job_id
        b = (await store.claim_learning_job()).record.learning_job_id
        for job in (a, b):
            call(dsn, "publish_findings", T1, job, [finding(f"{job}/w-b/0/0", run_id=job)], kind="finding", staged=True)
        assert _statuses(dsn, a) == ["staged"], "premise: A's finding is staged"

        await store.finish_learning_job(T1, a, status="completed", reason=None, message="m", progress=None,
                                        findings_count=1, publish_state="done")
        await store.finish_learning_job(T1, b, status="failed", reason="judge_failed", message="m", progress=None)

    assert job_row(dsn, a)["publish_state"] == "done"
    assert _statuses(dsn, a) == ["waiting"]
    assert job_row(dsn, b)["publish_state"] == "none"
    assert _statuses(dsn, b) == [], "a job that did not complete left its staged findings"


def _check_clock(dsn: str) -> bool:
    [(idle,)] = execute(dsn, "SELECT idle FROM jobs.learning_checks WHERE tenant_id = %s", (T1,))
    return bool(idle)


@pytest.mark.parametrize(("work_waits", "record"), [
    (False, None),
    (True, {"published": ["<job>"], "refused": [], "waiting": False}),
], ids=["nothing-waits-no-record", "work-waits-a-record-saying-none"])
async def test_o7_after_a_post_step_the_worker_decides_waiting_from_the_store_and_reads_no_record(
        world, monkeypatch, work_waits, record):  # noqa: F811 — the imported fixture
    """A job ends `completed` and its post-step exits 0. With nothing waiting in the store and no record left, the
    tenant's check clock goes idle; with a finding at the author threshold waiting, it keeps running, though the
    post-step left a record saying nothing waits (the worker reads no file it wrote). (O7, D2)"""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")  # the worker's own threshold: one finding opens the gate
    dsn = world["dsn"]
    if work_waits:
        call(dsn, "publish_findings", T1, "run-earlier", [finding("earlier/w-b/0/0")], kind="finding")
    jobs = job_child(world, files={END: learning_end("completed", findings=0)})
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        # Today's record names the job published, so only `waiting` can keep the clock running.
        text = None if record is None else json.dumps({**record, "published": [job]})
        post = post_child(world, recording=record is not None, record_text=text)
        await learning_worker(world, store, job=jobs, post=post).drain()

    assert post.seen(job), "premise: the post-step ran"
    assert job_row(dsn, job)["status"] == "completed"
    assert _check_clock(dsn) is (not work_waits), "the check clock does not follow the store"
