"""#1344 amendment 1 (from #1278, owner-approved 2026-11-07): a worker wakes a tenant without a family.

A worker with learning slots, not stopping, starts a family-less post-step for an `active` tenant with learning jobs
once that tenant has gone `learning_check_interval` without a post-step (amendment 3: its clock is a row in the store,
started by the tenant's first queued job, and stops while the tenant's last post-step left nothing waiting). The
check is learning-class, is picked before a queued job, and is handed the tenant's `pending` jobs; its record is
`<tenant id>.post-step.json`. Real database, scripted children, as `test_1344_learning_jobs`."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.tests.jobs.test_1344_learning_jobs import (
    END,
    PostStepChild,
    _stop_serving,
    job_child,
    job_row,
    learning_end,
    learning_worker,
    post_child,
    queued_job,
)
from defender.tests.support.jobs._worker1342 import _FAST, _until, _worker
from defender.tests.support.jobs._jobs1342 import NOW, T1, T2, JobsAudit, job_store, move_tenant, register_tenant
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.shared.filesystem._handoff import write_whole

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


class CheckChild(PostStepChild):
    """`post_step_argv` for a family-less post-step (no job): records `(None, pending, tenant)` and answers through
    the tenant-keyed record (its script's `--job` names the file it writes, so it is handed the tenant id)."""

    def __call__(self, launch) -> list[str]:
        assert launch.job_id is None, "premise: this stand-in only serves family-less launches"
        pending = sorted(launch.pending_job_ids)
        self.handed.append((None, pending, launch.tenant_id))
        self.files = {"{id}.post-step.json": json.dumps({"published": pending, "refused": []})}
        write_whole(self.spec, json.dumps(self.spec_dict()))
        return [sys.executable, str(self.script), str(self.spec), "--job", launch.tenant_id,
                "--tenant", launch.tenant_id, "--parent-pid", str(launch.parent_pid)]


def _either(follow, check):
    """One `post_step_argv` that routes a family-less launch to `check` and a job's to `follow`."""
    return lambda launch: (check if launch.job_id is None else follow)(launch)


def _strand(dsn: str, job: str) -> None:
    """End `job` `completed` with its findings `pending`, as a lost post-step leaves it."""
    execute(dsn, "UPDATE jobs.learning_jobs SET status = 'completed', publish_state = 'pending', findings_count = 1, "
                 "finished_at = %s, lease_expires_at = NULL WHERE id = %s", (NOW, job))


def _tenant_dirs(root: Path, tenant: str) -> None:
    (root / tenant / "runs").mkdir(parents=True, exist_ok=True)
    (root / tenant / "sessions").mkdir(exist_ok=True)


async def _serve_until(worker, condition, what: str) -> None:
    serving = asyncio.create_task(worker.serve())
    try:
        await _until(condition, what)
    finally:
        _stop_serving(serving)
        await asyncio.wait_for(serving, timeout=15)


@pytest.fixture
def world(migrated_database: str, tmp_path: Path) -> dict:
    register_tenant(migrated_database, T1)
    root = tmp_path / "data"
    _tenant_dirs(root, T1)
    return {"dsn": migrated_database, "root": root, "runs": root / T1 / "runs", "tmp": tmp_path}


async def test_a1_a_tenant_no_family_follows_is_checked_and_its_stranded_job_published(world, caplog):
    """A stranded `pending` job and nothing queued: after the interval a family-less post-step is handed it, the worker
    records `done` from `<tenant>.post-step.json`, and announces one `learning_post_step` for the tenant. (amendment 1, O14)"""
    audit = JobsAudit(caplog)
    dsn = world["dsn"]
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        _strand(dsn, job)
        worker = learning_worker(world, store, job=job_child(world), post=_either(post_child(world), check),
                                 learning_check_interval=0.5, **_FAST)
        await _serve_until(worker, lambda: job_row(dsn, job)["publish_state"] == "done", "the stranded job published")

    assert check.handed[0] == (None, [job], T1)
    assert json.loads((world["runs"] / f"{T1}.post-step.json").read_text(encoding="utf-8")) == {
        "published": [job], "refused": []}
    events = [e for e in audit.events() if e.action == "learning_post_step"]
    assert events, "no learning_post_step event"
    assert (events[0].actor, events[0].tenant_id, events[0].target) == ("system", T1, T1)


async def test_a1_the_check_clock_starts_with_the_tenant_s_first_job(world):
    """With an interval longer than the serve, no family-less post-step starts, so a stranded job waits for it.
    (amendment 3: a tenant's clock starts with its first queued job, not with the worker; amendment 1)"""
    dsn = world["dsn"]
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        _strand(dsn, job)
        worker = learning_worker(world, store, job=job_child(world), post=_either(post_child(world), check),
                                 learning_check_interval=600, **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await asyncio.sleep(2.0)
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)

    assert check.handed == []
    assert job_row(dsn, job)["publish_state"] == "pending"


async def test_a1_a_job_s_own_post_step_restarts_its_tenant_s_clock(world):
    """A job runs and its post-step follows at once; within the interval after it no family-less one starts. (amendment 1)"""
    dsn = world["dsn"]
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn)
    follow = post_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        worker = learning_worker(world, store, job=job_child(world, files={END: learning_end("completed", findings=1)}),
                                 post=_either(follow, check), learning_check_interval=3.0, **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await _until(lambda: job_row(dsn, job)["publish_state"] == "done", "the job's own post-step")
            await asyncio.sleep(1.5)
            assert check.handed == [], "a family-less check followed a post-step within the interval"
            await _until(lambda: check.handed, "the family-less check once the interval passed")
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert [h[0] for h in follow.handed] == [job]
    assert check.handed[0] == (None, [], T1), "nothing was left pending, and the check still ran the gate"


async def test_a1_an_overdue_check_is_picked_before_a_queued_job(world):
    """L=1. Tenant T1's check falls due while T2's job A holds the slot; job B (T2) queues meanwhile. When A's slot frees,
    T1's check is claimed first and B waits for it. (amendment 1: an overdue check before a new family)"""
    dsn = world["dsn"]
    register_tenant(dsn, T2)
    _tenant_dirs(world["root"], T2)
    t2_runs = world["root"] / T2 / "runs"
    release_a, release_check = world["tmp"] / "release-a", world["tmp"] / "release-check"
    a_child = job_child(world, name="a", files={END: learning_end("completed")}, wait_for=release_a)
    a_child.runs = t2_runs
    b_child = job_child(world, name="b", files={END: learning_end("completed")})
    b_child.runs = t2_runs
    follow = PostStepChild(world["tmp"] / "follow", t2_runs, dsn=dsn)
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn, wait_for=release_check)
    async with job_store(dsn) as store:
        seed = await queued_job(world, store, ticket="J-0")
        execute(dsn, "UPDATE jobs.learning_jobs SET status = 'skipped', reason = 'no_fork_point', message = 'm', "
                     "finished_at = %s WHERE id = %s", (NOW, seed))  # T1 has learning jobs, none queued
        a = await queued_job(world, store, ticket="J-1", tenant=T2)

        def jobs(launch):
            return (a_child if launch.job_id == a else b_child)(launch)

        worker = learning_worker(world, store, job=jobs, post=_either(follow, check), learning_check_interval=1.0,
                                 **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await _until(lambda: a_child.seen(a), "job A's child")
            b = await queued_job(world, store, ticket="J-2", tenant=T2)
            await asyncio.sleep(1.5)  # T1's check is overdue now; T2's clock restarts with A's post-step
            release_a.touch()
            await _until(lambda: check.handed, "T1's family-less check")
            await asyncio.sleep(1.0)
            assert b_child.seen(b) is None, "a queued job started before the overdue check"
            assert job_row(dsn, b)["status"] == "queued"
            release_check.touch()
            await _until(lambda: job_row(dsn, b)["status"] == "completed", "job B, after the check")
        finally:
            release_a.touch()
            release_check.touch()
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert check.handed[0] == (None, [], T1)


async def test_a1_a_worker_with_no_learning_slots_checks_nothing(world):
    """L=0 is no learning: no family-less post-step, and a stranded job stays pending. (amendment 1)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        _strand(dsn, job)
        worker = _worker(world, store, job_child(world, name="inv"), slots=2, learning_check_interval=0.2, **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await asyncio.sleep(1.5)
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert job_row(dsn, job)["publish_state"] == "pending"
    assert not (world["runs"] / f"{T1}.post-step.json").exists()


async def test_a1_a_stopping_worker_signals_its_family_less_post_step(world):
    """The check is in the one supervision registry: a stop signals it, and its job stays pending. (amendment 1, O9)"""
    dsn = world["dsn"]
    mark = world["tmp"] / "check-termed"
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn, term="mark", term_mark=str(mark),
                       wait_for=world["tmp"] / "never")
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        _strand(dsn, job)
        worker = learning_worker(world, store, job=job_child(world), post=_either(post_child(world), check),
                                 learning_check_interval=0.3, stop_grace=30, **_FAST)
        await _serve_until(worker, lambda: check.events(), "the family-less post-step")
    assert mark.exists(), "the family-less post-step was not told to stop"
    assert job_row(dsn, job)["publish_state"] == "pending"


async def test_a1_only_active_tenants_with_learning_jobs_are_checked(world):
    """The store claims a check only for an `active` tenant whose queued job armed its clock. (amendments 1, 3)"""
    dsn = world["dsn"]
    register_tenant(dsn, T2)
    async with job_store(dsn) as store:
        assert await store.claim_learning_check(0.01, "h0") is None, "no tenant has a learning job"
        await queued_job(world, store, ticket="J-1")
        await queued_job(world, store, ticket="J-2", tenant=T2)
        move_tenant(dsn, T2, state="offboarding")
        await asyncio.sleep(0.05)
        assert await store.claim_learning_check(0.01, "h1") == T1
        assert await store.claim_learning_check(0.01, "h2") is None, "T2 is not active, and T1 is held"


@pytest.mark.parametrize("bad", [0, -1])
def test_a1_the_check_interval_must_be_positive(tmp_path, bad):
    """A worker refuses an interval of 0 or below, before it reads anything off its store. (amendment 1)"""
    from defender.worker import Worker

    with pytest.raises(ValueError, match="interval"):
        Worker(SimpleNamespace(), data_root=tmp_path, clock=lambda: NOW, learning_check_interval=bad)


@pytest.mark.parametrize(("raw", "seconds"), [(None, 300), ("45", 45)])
def test_a1_the_deployed_setting_defaults_to_five_minutes(tmp_path, raw, seconds):
    """`DEFENDER_WORKER_LEARNING_CHECK_SECONDS`, default 300. (amendment 1)"""
    from defender.worker._start import read_settings

    environ = {"DEFENDER_BUILD_COMMIT": "c" * 40, "DEFENDER_DATABASE_DSN": "postgresql://x/y",
               "DEFENDER_DATA_ROOT": str(tmp_path)}
    if raw is not None:
        environ["DEFENDER_WORKER_LEARNING_CHECK_SECONDS"] = raw
    assert read_settings(environ).learning_check_seconds == seconds


@pytest.mark.parametrize("raw", ["0", "-5", "soon"])
def test_a1_a_bad_check_setting_refuses_the_start(tmp_path, raw):
    from defender.worker import WorkerStartRefused
    from defender.worker._start import read_settings

    environ = {"DEFENDER_BUILD_COMMIT": "c" * 40, "DEFENDER_DATABASE_DSN": "postgresql://x/y",
               "DEFENDER_DATA_ROOT": str(tmp_path), "DEFENDER_WORKER_LEARNING_CHECK_SECONDS": raw}
    with pytest.raises(WorkerStartRefused, match="LEARNING_CHECK"):
        read_settings(environ)
