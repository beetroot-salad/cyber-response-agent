"""#1487 O7 and Flow 3: "work still waiting" is the worker's own question. After a post-step's container exits the worker
answers the waiting predicate from its store (`defender.learning_store.tick.lane_waiting`, the reconcile lanes and the
thresholds from the worker's own environment); the post-step writes no record and the worker reads none, a failed
predicate leaves the tenant's clock not idle, and the pending set, its hand-over and the record retire. The predicate's own
truth table is `tests/learning/branch/test_1344_amend_post_step.py`; the armed-while-held mark is
`test_1344_amend_checks.py`. Real database, scripted children as `test_1344_learning_jobs.py`; the worker reaches the
learning schema in the database its job store is on."""
from __future__ import annotations

import asyncio
import json

import pytest

from defender.tests.jobs.test_1344_amend_wake import CheckChild, _either, _idle, _serve_until
from defender.tests.jobs.test_1344_learning_jobs import (
    END,
    job_child,
    job_row,
    learning_end,
    learning_worker,
    post_child,
    queued_job,
    world,  # noqa: F401 — fixture
)
from defender.tests.support.jobs._jobs1342 import T1, job_store
from defender.tests.support.jobs._worker1342 import _until
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, ONE, call, finding
from defender.tests.support.shared._postgres1339 import execute

pytestmark = pytest.mark.anyio
pg = pytest.mark.postgres  # the retirement test below needs no database

FAILED = learning_end("failed", "judge_failed", message="the judge failed")
#: What the retired record said: the worker must not read it, whichever way it points.
OLD_RECORD = {"waiting-false": {"published": [], "refused": [], "waiting": False},
              "no-flag": {"published": [], "refused": []}}


def _finding_waits(dsn: str, *ids: str) -> None:
    call(dsn, "publish_findings", T1, "run-earlier", [finding(i) for i in ids], kind="finding")


def _batch_in_review(dsn: str) -> None:
    _finding_waits(dsn, "earlier/w-b/0/0")
    claim = call(dsn, "claim", T1, AUTHOR_LANE, owner="host-a", thresholds=ONE)
    call(dsn, "in_review", claim, 7, {})


#: Store state the worker meets after a post-step, with the worker's `LEARNING_AUTHOR_THRESHOLD`, and whether work waits.
_STATES = {
    "nothing-in-the-store": (lambda dsn: None, "1", False),
    "one-finding-at-threshold-1": (lambda dsn: _finding_waits(dsn, "a/w-b/0/0"), "1", True),
    "one-finding-below-threshold-2": (lambda dsn: _finding_waits(dsn, "a/w-b/0/0"), "2", False),
    "two-findings-at-threshold-2": (lambda dsn: _finding_waits(dsn, "a/w-b/0/0", "a/w-b/0/1"), "2", True),
    "a-batch-in-review": (lambda dsn: _batch_in_review(dsn), "5", True),
}


@pytest.mark.parametrize("state", _STATES)
@pg
async def test_o7_after_a_jobs_post_step_the_clock_goes_idle_exactly_when_the_store_holds_nothing_waiting(
        world, monkeypatch, state):  # noqa: F811 — the imported fixture
    """The job ends and its post-step exits 0, leaving no record: the tenant's clock is idle exactly when the
    predicate over the store, with the worker's own thresholds, says nothing waits. (O7, Flow 3)"""
    prepare, threshold, waits = _STATES[state]
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", threshold)
    dsn = world["dsn"]
    prepare(dsn)
    post = post_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        await learning_worker(world, store, job=job_child(world, files={END: FAILED}), post=post).drain()

    assert post.handed == [(job, "failed")], "premise: the post-step ran"
    assert _idle(dsn) is (not waits)


#: What a post-step's tick leaves in the store while its container runs, its worker's threshold, and whether work waits.
_LEFT_BY_THE_POST_STEP = {
    "a-finding-it-published": (lambda dsn: _finding_waits(dsn, "a/w-b/0/0"), "1", True),
    "a-batch-it-left-in-review": (_batch_in_review, "5", True),
    "nothing": (lambda dsn: None, "1", False),
}


@pytest.mark.parametrize("left", _LEFT_BY_THE_POST_STEP)
@pg
async def test_o7_the_question_is_asked_after_the_post_step_exits_and_sees_what_it_left(
        world, monkeypatch, left):  # noqa: F811 — the imported fixture
    """The post-step's container runs (held open); while it runs, the store gains what its tick would leave (a finding
    published, a batch left in review); then it exits. The worker's answer reads the store as the container left it: not
    idle. The control leaves nothing: idle. (O7, Flow 3: "after a post-step's container exits, the worker answers")"""
    leave, threshold, waits = _LEFT_BY_THE_POST_STEP[left]
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", threshold)
    dsn = world["dsn"]
    release = world["tmp"] / "release-post"
    post = post_child(world, wait_for=release)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        draining = asyncio.create_task(
            learning_worker(world, store, job=job_child(world, files={END: FAILED}), post=post).drain())
        try:
            await _until(lambda: ("start", job) in post.events(), "the post-step's container to start")
            leave(dsn)
        finally:
            release.touch()
            await asyncio.wait_for(draining, timeout=60)

    assert post.handed == [(job, "failed")], "premise: the post-step ran"
    assert ("end", job) in post.events(), "premise: the post-step ran to its end"
    assert _idle(dsn) is (not waits), "the answer did not read the store as the post-step left it"


@pg
async def test_o7_the_worker_asks_one_learning_store_made_once_and_closed_when_it_stops(world):  # noqa: F811
    """Two jobs, two post-steps, two answers: the worker builds one learning store for them all and closes it once its
    drain ends. (Data model: "the worker keeps one long-lived `LearningStore`")"""
    from defender.learning.core.store_tick import thresholds
    from defender.learning_store import LearningStore
    from defender.tests.support.tenancy._host1214 import counting_calls

    dsn = world["dsn"]
    post = post_child(world)
    async with job_store(dsn) as store:
        jobs = [await queued_job(world, store, ticket=f"J-{n}") for n in (1, 2)]
        worker = learning_worker(world, store, job=job_child(world, files={END: FAILED}), post=post)
        with counting_calls(built=LearningStore.__init__, closed=LearningStore.close, asked=thresholds) as calls:
            await worker.drain()

    assert sorted(h[0] for h in post.handed) == sorted(jobs), "premise: both post-steps ran"
    # the thresholds are read once per question (Amendment r5.1 item 10); `close` is a coroutine, whose every resumption
    # the profile hook also counts, so the stores it closed are told apart by the store itself
    assert calls.counts["asked"] >= 2, "premise: the worker asked after each post-step"
    assert calls.counts["built"] == 1, "a learning store was built per question, not kept"
    [kept] = [seen["self"] for seen in calls.locals["built"]]
    closed = {id(seen["self"]) for seen in calls.locals["closed"]}
    assert closed == {id(kept)}, "the worker's one learning store was not closed when its drain ended"


@pytest.mark.parametrize("record", OLD_RECORD)
@pytest.mark.parametrize("waits", [True, False], ids=["work-waits", "nothing-waits"])
@pg
async def test_o7_a_record_the_post_step_leaves_is_not_read(world, monkeypatch, record, waits):  # noqa: F811
    """A post-step that leaves a file in the old record's name, saying whatever, moves nothing: the clock follows the
    store. (O7: the post-step writes no record and the worker reads none)"""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    dsn = world["dsn"]
    if waits:
        _finding_waits(dsn, "a/w-b/0/0")
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        post = post_child(world, files={"{id}.post-step.json": json.dumps(OLD_RECORD[record])})
        await learning_worker(world, store, job=job_child(world, files={END: FAILED}), post=post).drain()

    assert post.handed == [(job, "failed")]
    assert _idle(dsn) is (not waits)


@pg
async def test_o7_a_predicate_that_fails_leaves_the_clock_not_idle_and_the_ending_standing(world):  # noqa: F811
    """The learning tables cannot be read when the question is asked: the tenant's clock is not idle (a later check asks
    again) and the job's ending is untouched. The control, the same flow with the tables intact and nothing waiting,
    goes idle. (O7, Flow 3: a failed predicate leaves the clock not idle)"""
    dsn = world["dsn"]
    execute(dsn, "ALTER TABLE learning.batches RENAME TO batches_unreadable")
    post = post_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        await learning_worker(world, store, job=job_child(world, files={END: FAILED}), post=post).drain()
    assert post.handed == [(job, "failed")]
    assert job_row(dsn, job)["status"] == "failed", "a failed predicate changed the job's ending"
    assert _idle(dsn) is False, "an unknown answer was read as nothing waiting"

    execute(dsn, "ALTER TABLE learning.batches_unreadable RENAME TO batches")
    execute(dsn, "UPDATE jobs.learning_checks SET idle = FALSE WHERE tenant_id = %s", (T1,))
    control = post_child(world, name="control")
    async with job_store(dsn) as store:
        await queued_job(world, store, ticket="J-2")
        await learning_worker(world, store, job=job_child(world, name="again", files={END: FAILED}), post=control).drain()
    assert _idle(dsn) is True, "control: with the tables readable the same flow ends idle"


@pytest.mark.parametrize("waits", [True, False], ids=["work-waits", "nothing-waits"])
@pg
async def test_o7_a_family_less_check_asks_the_same_question(world, monkeypatch, waits):  # noqa: F811
    """The worker's check of a tenant (no job) is the same post-step: after it exits, the clock is idle exactly when
    nothing waits in the store. (O7: the family-less check is the same post-step)"""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    dsn = world["dsn"]
    if waits:
        _finding_waits(dsn, "a/w-b/0/0")
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        execute(dsn, "UPDATE jobs.learning_jobs SET status = 'failed', reason = 'judge_failed', message = 'm', "
                     "finished_at = now(), lease_expires_at = NULL WHERE id = %s", (job,))
        worker = learning_worker(world, store, job=job_child(world), post=_either(post_child(world), check),
                                 learning_check_interval=0.5)
        await _serve_until(worker, lambda: check.handed and ("end", T1) in check.events() and _released(dsn), "the check's end")

    assert _idle(dsn) is (not waits)


def _released(dsn: str) -> bool:
    """The check's hold has been let go (the worker's end of it has landed)."""
    [(holder,)] = execute(dsn, "SELECT holder FROM jobs.learning_checks WHERE tenant_id = %s", (T1,))
    return holder is None


def test_o7_the_pending_set_its_hand_over_and_the_record_are_gone():
    """The jobs store has no pending set, the worker's launch no pending list, the job lane no post-step record or
    hand-over, and the layout accepts neither file. (#1487 retirements: Data model, decision 6)"""
    import dataclasses

    from defender.jobs import JobStore
    from defender.records import _layout, job_lane
    from defender.worker import PostStepLaunch, Worker

    assert not hasattr(JobStore, "pending_publish")
    assert not hasattr(JobStore, "record_publish")
    assert not hasattr(Worker, "_hand_pending")
    assert [f.name for f in dataclasses.fields(PostStepLaunch)] == ["job_id", "tenant_id", "parent_pid"]
    for name in ("PostStepRecord", "post_step_key"):
        assert not hasattr(job_lane, name), name
    for name in ("write_post_step", "read_post_step", "write_post_step_pending", "read_post_step_pending"):
        assert not hasattr(job_lane.JobLane, name), name
    assert not {".post-step.json", ".post-step-pending.json"} & set(_layout.ACCEPTED_SIDECAR_SUFFIXES)
