"""#1487 O7 and Flow 3, as Amendment r5.2 places the question: "work still waiting" is answered by the post-step's helper,
which asks the learning store it bound once the container exits and says it by its exit status (`job_host.NOTHING_WAITS`,
`WORK_WAITS`); the worker reads that status and opens no learning store. The post-step writes no record and the worker
reads none, any other status (a failed question, a stop) leaves the tenant's clock not idle, and the pending set, its
hand-over and the record retire. The predicate's own truth table is `tests/learning/branch/test_1344_amend_post_step.py`;
the helper's answer over a real store is `test_1487_helper_waiting.py`; the armed-while-held mark is
`test_1344_amend_checks.py`. Real database, scripted children as `test_1344_learning_jobs.py`: the post-step's stand-in
answers as the helper does, from the store, unless a case sets its status."""
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
    """The job ends and its post-step exits with its answer, leaving no record: the tenant's clock is idle exactly when
    the predicate over the store, with the thresholds of the worker's environment, says nothing waits. (O7, Flow 3)"""
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
    published, a batch left in review); then it exits. The answer reads the store as the container left it: not idle.
    The control leaves nothing: idle. (O7, Flow 3, r5.2: the question is asked once the post-step's container exited)"""
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
async def test_r52_the_worker_opens_no_learning_store(world):  # noqa: F811 — the imported fixture
    """Two jobs, two post-steps, two answers: the worker builds no learning store for them; the answers are its helpers'.
    (Amendment r5.2: the worker keeps no long-lived `LearningStore`)"""
    from defender.learning_store import LearningStore
    from defender.tests.support.tenancy._host1214 import counting_calls

    dsn = world["dsn"]
    post = post_child(world)
    async with job_store(dsn) as store:
        jobs = [await queued_job(world, store, ticket=f"J-{n}") for n in (1, 2)]
        worker = learning_worker(world, store, job=job_child(world, files={END: FAILED}), post=post)
        with counting_calls(built=LearningStore.__init__) as calls:
            await worker.drain()

    assert sorted(h[0] for h in post.handed) == sorted(jobs), "premise: both post-steps ran"
    assert calls.counts["built"] == 0, "the worker built a learning store of its own"


#: The helper's exit status, whether the store holds work, and whether the clock goes idle: the status alone decides.
_STATUSES = {
    "nothing-waits-over-a-store-with-work": ("NOTHING_WAITS", True, True),
    "work-waits-over-an-empty-store": ("WORK_WAITS", False, False),
    "served-without-an-answer": (0, False, False),
    "a-failed-helper": (1, False, False),
}


@pytest.mark.parametrize("case", _STATUSES)
@pg
async def test_r52_the_clock_goes_idle_exactly_when_the_helper_exits_saying_nothing_waits(
        world, monkeypatch, case):  # noqa: F811 — the imported fixture
    """The worker reads the helper's exit status, never the store: `NOTHING_WAITS` makes the clock idle though the store
    holds work; `WORK_WAITS`, a plain 0 or a failure leaves it not idle though the store holds none. (Amendment r5.2,
    O7: an unknown answer is never "nothing waits")"""
    from defender import job_host

    status, store_has_work, idle = _STATUSES[case]
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    dsn = world["dsn"]
    if store_has_work:
        _finding_waits(dsn, "a/w-b/0/0")
    post = post_child(world, exit=getattr(job_host, status) if isinstance(status, str) else status)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        await learning_worker(world, store, job=job_child(world, files={END: FAILED}), post=post).drain()

    assert post.handed == [(job, "failed")], "premise: the post-step ran"
    assert _idle(dsn) is idle


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


@pg
async def test_r54_a_post_step_past_its_limit_is_ended_and_leaves_the_clock_not_idle(world, caplog):  # noqa: F811
    """A post-step that hangs (it waits a minute for a file that never comes) is ended once it has run the worker's
    `post_step_limit`, logged as an error, and its tenant's clock is not idle though nothing waits in the store. The
    control, the same post-step with no hang, goes idle. (Amendment r5.4)"""
    dsn = world["dsn"]
    post = post_child(world, wait_for=world["tmp"] / "never")
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        started = asyncio.get_running_loop().time()
        await asyncio.wait_for(learning_worker(
            world, store, job=job_child(world, files={END: FAILED}), post=post, post_step_limit=1.0, stop_grace=2).drain(),
            timeout=40)
        took = asyncio.get_running_loop().time() - started

    assert post.handed == [(job, "failed")], "premise: the post-step ran"
    assert took < 30, f"the post-step ran {took:.1f}s, past its 1s limit and the stop grace"
    assert _idle(dsn) is False, "a post-step ended at its limit was read as nothing waiting"
    assert any(r.levelname == "ERROR" and "past its limit" in r.getMessage() for r in caplog.records), caplog.text

    execute(dsn, "UPDATE jobs.learning_checks SET idle = FALSE WHERE tenant_id = %s", (T1,))
    control = post_child(world, name="control")
    async with job_store(dsn) as store:
        await queued_job(world, store, ticket="J-2")
        await learning_worker(world, store, job=job_child(world, name="again", files={END: FAILED}), post=control,
                              post_step_limit=30.0).drain()
    assert _idle(dsn) is True, "control: the same post-step within its limit answers, and nothing waits"


def test_r54_the_post_step_limit_is_a_positive_setting_defaulting_to_four_hours(tmp_path):
    """`DEFENDER_WORKER_POST_STEP_SECONDS`: default 14400; 0, negative or not a number refuses the start; a worker
    refuses a limit of 0 or below. (Amendment r5.4)"""
    from types import SimpleNamespace

    from defender.tests.support.jobs._jobs1342 import FRONTEND_ORIGIN, NOW
    from defender.worker import Worker, WorkerStartRefused
    from defender.worker._start import read_settings

    environ = {"DEFENDER_BUILD_COMMIT": "c" * 40, "DEFENDER_DATABASE_DSN": "postgresql://x/y",
               "DEFENDER_DATA_ROOT": str(tmp_path), "DEFENDER_API_FRONTEND_ORIGIN": FRONTEND_ORIGIN}
    assert read_settings(environ).post_step_seconds == 4 * 3600
    assert read_settings({**environ, "DEFENDER_WORKER_POST_STEP_SECONDS": "90"}).post_step_seconds == 90
    for raw in ("0", "-5", "soon"):
        with pytest.raises(WorkerStartRefused, match="POST_STEP"):
            read_settings({**environ, "DEFENDER_WORKER_POST_STEP_SECONDS": raw})
    with pytest.raises(ValueError, match="post-step limit"):
        Worker(SimpleNamespace(), data_root=tmp_path, clock=lambda: NOW, post_step_limit=0,
               frontend_origin=FRONTEND_ORIGIN)


#: Why the worker signals a post-step: its own stop, or the post-step running past `post_step_limit`.
_SIGNALLED_BY = ("the-workers-stop", "the-post-step-limit")


@pytest.mark.parametrize("status", ["NOTHING_WAITS", "WORK_WAITS"])
@pytest.mark.parametrize("reason", _SIGNALLED_BY)
@pg
async def test_g8_a_signalled_post_step_leaves_the_clock_not_idle_whatever_it_answers(
        world, reason, status):  # noqa: F811 — the imported fixture
    """The post-step hangs; the worker signals it (its own stop, or the post-step past its limit), and the helper's
    stand-in catches the SIGTERM and exits with an answer status, either one. Its answer predates nothing it was told,
    so it is not read: the tenant's clock is not idle, though nothing waits in the store. (Flow 3: a stop leaves the
    clock not idle; Amendment r5.4: so does a post-step ended at its limit)"""
    from defender import job_host
    from defender.tests.jobs.test_1344_learning_jobs import _stop_serving
    from defender.tests.support.jobs._worker1342 import _FAST

    dsn = world["dsn"]
    termed = world["tmp"] / "termed"
    post = post_child(world, wait_for=world["tmp"] / "never", term="exit", term_mark=str(termed),
                      exit=getattr(job_host, status))
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        if reason == "the-post-step-limit":
            await asyncio.wait_for(learning_worker(
                world, store, job=job_child(world, files={END: FAILED}), post=post, post_step_limit=3.0,
                stop_grace=20).drain(), timeout=60)
        else:
            serving = asyncio.create_task(learning_worker(
                world, store, job=job_child(world, files={END: FAILED}), post=post, **_FAST).serve())
            try:
                await _until(lambda: ("start", job) in post.events(), "the post-step's container to start")
            finally:
                _stop_serving(serving)
                await asyncio.wait_for(serving, timeout=60)

    assert post.handed == [(job, "failed")], "premise: the post-step ran"
    assert termed.exists(), "premise: the stand-in caught the SIGTERM and exited with its answer"
    assert _idle(dsn) is False, "a signalled post-step's answer was read"
