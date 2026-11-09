"""#1344 amendment 3 (from the third review of #1446): a tenant's family-less check clock is a row in the store.

`jobs.learning_checks` holds, per tenant, when its last post-step ended (or when a queued job armed it), whether that
post-step left nothing waiting (`idle`), and which post-step holds it now. A worker claims a due tenant in one
skip-locked statement, a job's own post-step holds the same row, and the hold is renewed with the leases, so no two
post-steps of one tenant ever run together, on one worker or two. Real database, scripted children, as
`test_1344_amend_wake`."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from defender.records.job_lane import PostStepRecord
from defender.tests.jobs.test_1344_amend_wake import CheckChild, _either, _strand, _tenant_dirs
from defender.tests.jobs.test_1344_learning_jobs import (
    END,
    _stop_serving,
    job_child,
    job_row,
    learning_end,
    learning_worker,
    post_child,
    queued_job,
)
from defender.tests.jobs.test_worker import _FAST, _until
from defender.tests.support.jobs._jobs1342 import T1, job_store, register_tenant
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

HOUR = 3600.0


@pytest.fixture
def world(migrated_database: str, tmp_path: Path) -> dict:
    """The wake tests' world: tenant T1 and its folders."""
    register_tenant(migrated_database, T1)
    root = tmp_path / "data"
    _tenant_dirs(root, T1)
    return {"dsn": migrated_database, "root": root, "runs": root / T1 / "runs", "tmp": tmp_path}


def _clock(dsn: str, tenant: str = T1) -> dict | None:
    rows = execute(dsn, "SELECT idle, checking_until IS NOT NULL, holder FROM jobs.learning_checks WHERE tenant_id = %s",
                   (tenant,))
    return None if not rows else dict(zip(("idle", "held", "holder"), rows[0], strict=True))


def _age(dsn: str, seconds: float, tenant: str = T1) -> None:
    """Move the tenant's clock `seconds` into the past, as that much time passing would."""
    execute(dsn, "UPDATE jobs.learning_checks SET checked_at = checked_at - make_interval(secs => %s) "
                 "WHERE tenant_id = %s", (seconds, tenant))


def _lapse(dsn: str, tenant: str = T1) -> None:
    execute(dsn, "UPDATE jobs.learning_checks SET checking_until = now() - interval '1 second' WHERE tenant_id = %s",
            (tenant,))


# -- the store ---------------------------------------------------------------------------------------------------


async def test_a3_a_queued_job_arms_its_tenant_s_clock_and_a_new_worker_reads_the_same_clock(world):
    """Queuing a job creates the tenant's clock, not idle, from now: not due within the interval, due after it, and a
    store opened later (a restarted worker) sees it due at once, with no interval of its own. (amendment 3)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        assert _clock(dsn) is None
        await queued_job(world, store, ticket="J-1")
        assert _clock(dsn) == {"idle": False, "held": False, "holder": None}
        assert await store.claim_learning_check(HOUR, "h1") is None, "due before its interval passed"
        _age(dsn, 2 * HOUR)
    async with job_store(dsn) as restarted:
        assert await restarted.claim_learning_check(HOUR, "h2") == T1
    assert _clock(dsn) == {"idle": False, "held": True, "holder": "h2"}


async def test_a3_two_workers_claiming_at_once_never_both_hold_one_tenant(world):
    """Two stores claim the one due tenant at the same moment: one holds it, the other gets nothing; a job's post-step
    cannot hold it either while it is held. (amendment 3: the overlap)"""
    dsn = world["dsn"]
    async with job_store(dsn) as one, job_store(dsn) as two:
        await queued_job(world, one, ticket="J-1")
        _age(dsn, 2 * HOUR)
        claims = await asyncio.gather(*(s.claim_learning_check(HOUR, h) for s, h in ((one, "h1"), (two, "h2"))))
        assert sorted(claims, key=str) == sorted([T1, None], key=str)
        assert await one.hold_learning_check(T1, "h3") is False
        assert await two.claim_learning_check(HOUR, "h4") is None


async def test_a3_an_idle_end_stops_the_clock_until_a_job_arms_it_again(world):
    """A post-step that left nothing waiting stops its tenant's checks however long passes; the tenant's next queued job
    arms the clock again. (amendment 3)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        await queued_job(world, store, ticket="J-1")
        _age(dsn, 2 * HOUR)
        assert await store.claim_learning_check(HOUR, "h1") == T1
        assert await store.end_learning_check(T1, "h1", idle=True, handed=()) is True
        _age(dsn, 100 * HOUR)
        assert await store.claim_learning_check(HOUR, "h2") is None, "an idle tenant was checked"
        await queued_job(world, store, ticket="J-2")
        assert _clock(dsn)["idle"] is False
        assert await store.claim_learning_check(HOUR, "h3") == T1


async def test_a3_an_end_that_finds_a_pending_job_it_was_not_handed_makes_the_tenant_due_at_once(world):
    """A job ended with findings while a check of its tenant ran: the check's end, though its own record says nothing
    waits, leaves the tenant due at once and not idle, so that job is not stranded. (amendment 3)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        _age(dsn, 2 * HOUR)
        assert await store.claim_learning_check(HOUR, "h1") == T1
        _strand(dsn, job)  # ended `completed`, findings `pending`, after the check was handed its list
        assert await store.end_learning_check(T1, "h1", idle=True, handed=()) is True
        assert _clock(dsn)["idle"] is False
        assert await store.claim_learning_check(HOUR, "h2") == T1, "not due at once"
        assert await store.end_learning_check(T1, "h2", idle=True, handed=(job,)) is True
        assert _clock(dsn)["idle"] is True, "control: a job it was handed does not hold the clock open"


async def test_a3_only_the_holder_renews_or_lets_go_and_a_late_renewal_nobody_overtook_succeeds(world):
    """A lapsed hold nobody took is renewed late (B1); once another claim takes the lapsed hold, the old holder's
    renewal misses it and its end changes nothing. (amendment 3)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        await queued_job(world, store, ticket="J-1")
        _age(dsn, 2 * HOUR)
        assert await store.claim_learning_check(HOUR, "h1") == T1
        _lapse(dsn)
        assert await store.renew((), checks={"h1"}) == ["h1"]
        _lapse(dsn)
        assert await store.claim_learning_check(HOUR, "h2") == T1
        assert await store.renew((), checks={"h1", "h2"}) == ["h2"]
        assert await store.end_learning_check(T1, "h1", idle=True, handed=()) is False
        assert _clock(dsn) == {"idle": False, "held": True, "holder": "h2"}
        assert await store.end_learning_check(T1, "h2", idle=False, handed=()) is True
        assert _clock(dsn) == {"idle": False, "held": False, "holder": None}


@pytest.mark.parametrize(("text", "waiting"), [
    ('{"published": [], "refused": []}', True),
    ('{"published": [], "refused": [], "waiting": false}', False),
    ('{"published": [], "refused": [], "waiting": true}', True),
    ('{"published": [], "refused": [], "waiting": 0}', None),
])
def test_a3_a_post_step_record_without_waiting_says_work_may_wait(text, waiting):
    """An absent `waiting` is the safe reading (work may wait); a non-boolean one is no record. (amendment 3)"""
    record = PostStepRecord.parse(text)
    assert (None if record is None else record.waiting) == waiting


# -- the worker --------------------------------------------------------------------------------------------------


async def test_a3_a_job_ending_during_its_tenant_s_check_starts_no_second_post_step_and_the_next_check_publishes_it(
        world):
    """L=2. A check of T1 runs (held open); T1's job J runs in the other slot and ends with findings. J's own post-step
    does not start beside the check; once the check ends, the next claim checks T1 again, handed J. (amendment 3)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release-check"
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn, wait_for=release)
    follow = post_child(world)
    async with job_store(dsn) as store:
        stranded = await queued_job(world, store, ticket="J-0")
        _strand(dsn, stranded)
        worker = learning_worker(world, store, job=job_child(world, files={END: learning_end("completed", findings=1)}),
                                 post=_either(follow, check), learning_check_interval=0.5, learning_slots=2, **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await _until(lambda: check.handed, "the first check")
            job = await queued_job(world, store, ticket="J-1")
            await _until(lambda: job_row(dsn, job)["status"] == "completed", "job J's end")
            await asyncio.sleep(1.0)
            assert follow.handed == [], "J's post-step started beside its tenant's check"
            assert len(check.handed) == 1
            release.touch()
            await _until(lambda: job_row(dsn, job)["publish_state"] == "done", "J published by the next check")
        finally:
            release.touch()
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert check.handed[0] == (None, [stranded], T1)
    assert check.handed[1] == (None, [job], T1)
    assert follow.handed == []


async def test_a3_a_post_step_that_leaves_nothing_waiting_stops_its_tenant_s_checks(world):
    """A job's post-step answers `waiting: false` and publishes all it was handed: no family-less check follows,
    however many intervals pass. (amendment 3; `test_a1_a_job_s_own_post_step_restarts_its_tenant_s_clock` is the
    control, its record without the flag)"""
    dsn = world["dsn"]
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        follow = post_child(world, record_text=json.dumps({"published": [job], "refused": [], "waiting": False}))
        worker = learning_worker(world, store, job=job_child(world, files={END: learning_end("completed", findings=1)}),
                                 post=_either(follow, check), learning_check_interval=0.3, **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await _until(lambda: job_row(dsn, job)["publish_state"] == "done", "the job's own post-step")
            await asyncio.sleep(1.5)
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert check.handed == []
    assert _clock(dsn) == {"idle": True, "held": False, "holder": None}


async def test_a3_a_post_step_that_leaves_a_handed_job_pending_keeps_its_tenant_s_checks(world):
    """`waiting: false`, but a job it was handed is in neither list (a queue-level failure): the tenant is not idle,
    and a check follows within the interval. (amendment 3)"""
    dsn = world["dsn"]
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        follow = post_child(world, record_text=json.dumps({"published": [], "refused": [], "waiting": False}))
        worker = learning_worker(world, store, job=job_child(world, files={END: learning_end("completed", findings=1)}),
                                 post=_either(follow, check), learning_check_interval=0.3, **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await _until(lambda: check.handed, "the family-less check")
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert check.handed[0] == (None, [job], T1)


async def test_a3_the_worker_renews_a_running_check_s_hold_so_no_second_check_starts_beside_it(world):
    """A one-second lease, two learning slots, and a check held open for several leases: the worker renews the hold, so
    the tenant is never claimed again while the check runs, and the check is not fenced. (amendment 3)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release-check"
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn, wait_for=release)
    async with job_store(dsn, lease=1.0) as store:
        stranded = await queued_job(world, store, ticket="J-0")
        _strand(dsn, stranded)
        worker = learning_worker(world, store, job=job_child(world), post=_either(post_child(world), check),
                                 learning_check_interval=0.3, learning_slots=2, **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await _until(lambda: check.handed, "the check")
            await asyncio.sleep(3.5)
            assert len(check.handed) == 1, "a second check started beside the first: its hold lapsed"
            assert [kind for kind, _ in check.events()] == ["start"], "the running check was ended"
            assert _clock(dsn)["held"] is True
        finally:
            release.touch()
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
