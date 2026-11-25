"""#1344 amendment 3 (from the third review of #1446): a tenant's family-less check clock is a row in the store.

`jobs.learning_checks` holds, per tenant, when its last post-step ended (or when a queued job armed it), whether that
post-step left nothing waiting (`idle`), and which post-step holds it now. A worker claims a due tenant in one
skip-locked statement, a job's own post-step holds the same row, and the hold is renewed with the leases, so no two
post-steps of one tenant ever run together, on one worker or two. Real database, scripted children, as
`test_1344_amend_wake`."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from defender.tests.jobs.test_1344_amend_wake import CheckChild, _either, _end_completed, _idle, _tenant_dirs, _work_waits
from defender.tests.jobs.test_1344_learning_jobs import (
    END,
    _stop_serving,
    completed_investigation,
    ended_child,
    investigation_of,
    job_child,
    job_row,
    learning_end,
    learning_worker,
    post_child,
    queued_job,
)
from defender.tests.support.jobs._worker1342 import _FAST, _until
from defender.tests.support.jobs._jobs1342 import T1, T2, job_store, move_tenant, register_tenant
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


def _no_check_until_a_post_step_ends(dsn: str, tenant: str = T1) -> None:
    """Park the tenant's clock an hour ahead, so no family-less check is due until a post-step ends and restarts it.

    Queueing a job arms the clock at that moment, and the worker claims an overdue check before a queued job. With a
    0.3 s interval, any pause between queueing and the worker's first claim (building the worker, a loaded runner)
    made an empty check run first: it held the clock, so the job's own post-step was refused, or it took the place of
    the check the test waits for. A post-step's end sets the clock to now, so the check the test is about still follows
    it within the interval."""
    execute(dsn, "UPDATE jobs.learning_checks SET checked_at = now() + interval '1 hour' WHERE tenant_id = %s", (tenant,))


def _age(dsn: str, seconds: float, tenant: str = T1) -> None:
    """Move the tenant's clock `seconds` into the past, as that much time passing would."""
    execute(dsn, "UPDATE jobs.learning_checks SET checked_at = checked_at - make_interval(secs => %s) "
                 "WHERE tenant_id = %s", (seconds, tenant))


def _lapse(dsn: str, tenant: str = T1) -> None:
    execute(dsn, "UPDATE jobs.learning_checks SET checking_until = now() - interval '1 second' WHERE tenant_id = %s",
            (tenant,))


async def _claim(store, interval: float = HOUR):
    """The store's claim of a due tenant's check: `LearningCheckClaim(tenant_id, token)` (the store mints the token, PR7),
    or None."""
    return await store.claim_learning_check(interval)


# -- the store ---------------------------------------------------------------------------------------------------


async def test_a3_a_queued_job_arms_its_tenant_s_clock_and_a_new_worker_reads_the_same_clock(world):
    """Queuing a job creates the tenant's clock, not idle, from now: not due within the interval, due after it, and a
    store opened later (a restarted worker) sees it due at once, with no interval of its own. (amendment 3)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        assert _clock(dsn) is None
        await queued_job(world, store, ticket="J-1")
        assert _clock(dsn) == {"idle": False, "held": False, "holder": None}
        assert await store.claim_learning_check(HOUR) is None, "due before its interval passed"
        _age(dsn, 2 * HOUR)
    async with job_store(dsn) as restarted:
        claim = await _claim(restarted)
    assert getattr(claim, "tenant_id", None) == T1
    assert _clock(dsn) == {"idle": False, "held": True, "holder": claim.token}


async def test_a3_two_workers_claiming_at_once_never_both_hold_one_tenant(world):
    """Two stores claim the one due tenant at the same moment: one holds it, the other gets nothing; a job's post-step
    cannot hold it either while it is held. (amendment 3: the overlap)"""
    dsn = world["dsn"]
    async with job_store(dsn) as one, job_store(dsn) as two:
        await queued_job(world, one, ticket="J-1")
        _age(dsn, 2 * HOUR)
        claims = await asyncio.gather(one.claim_learning_check(HOUR), two.claim_learning_check(HOUR))
        assert sorted(c.tenant_id if c else "" for c in claims) == ["", T1]
        assert await one.hold_learning_check(T1) is None
        assert await two.claim_learning_check(HOUR) is None


async def test_a3_an_idle_end_stops_the_clock_until_a_job_arms_it_again(world):
    """A post-step that left nothing waiting stops its tenant's checks however long passes; the tenant's next queued job
    arms the clock again. (amendment 3)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        await queued_job(world, store, ticket="J-1")
        _age(dsn, 2 * HOUR)
        first = await _claim(store)
        assert first.tenant_id == T1
        assert await store.end_learning_check(T1, first.token, idle=True) is True
        _age(dsn, 100 * HOUR)
        assert await store.claim_learning_check(HOUR) is None, "an idle tenant was checked"
        await queued_job(world, store, ticket="J-2")
        assert _clock(dsn)["idle"] is False
        assert (await _claim(store)).tenant_id == T1


async def _running_job(store, *, ticket: str) -> str:
    """A learning job of T1 claimed by the store's own claim, so it is running."""
    await completed_investigation(store, ticket=ticket, key=ticket)
    return (await store.claim_learning_job()).record.learning_job_id


async def _finish(dsn: str, store, job: str, status: str) -> None:
    """The job's one end write through the store, as the worker makes it (#1546 PR9): the facts its end record becomes are
    staged under its claim, then `decide` and `apply`."""
    from defender.tests.jobs.test_1344_learning_jobs import stage_end
    from defender.tests.support.jobs._ending1546 import end_row, token_of

    reason = {"completed": None, "failed": "judge_failed", "skipped": "no_fork_point"}[status]
    stage_end(dsn, job, learning_end(status, reason, message=None if status == "completed" else "m"))
    _, record = await end_row(store, dsn, kind="learning", tenant=T1, owner=job, token=token_of(dsn, "learning", job),
                              by="exited")
    assert record is not None, "premise: the job's end was applied"


async def _held_by(world, store) -> tuple[str, str]:
    """A running job of T1 and the token of the check that holds the tenant's clock (claimed after the interval)."""
    job = await _running_job(store, ticket="J-1")
    _age(world["dsn"], 2 * HOUR)
    claim = await _claim(store)
    assert getattr(claim, "tenant_id", None) == T1, "premise: the check was claimed"
    return job, claim.token


async def test_o7_an_end_of_a_hold_that_a_completed_job_ended_beside_makes_the_tenant_due_at_once_not_idle(world):
    """A job ends `completed` while a check holds its tenant's clock: the hold's end, though it says idle, leaves the
    tenant not idle and due at once, and the mark is spent (the next hold's idle end stands). (O7, armed-while-held mark)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job, hold = await _held_by(world, store)
        await _finish(dsn, store, job, "completed")

        assert await store.end_learning_check(T1, hold, idle=True) is True
        assert _clock(dsn) == {"idle": False, "held": False, "holder": None}
        again = await _claim(store)
        assert getattr(again, "tenant_id", None) == T1, "not due at once"
        assert await store.end_learning_check(T1, again.token, idle=True) is True
        assert _clock(dsn)["idle"] is True, "the mark outlived the hold it was set for"


async def test_o7_a_completed_end_with_no_hold_sets_no_mark(world):
    """The control of the case above: the job ends `completed` while nothing holds the clock; the next check's idle end
    stands. (O7)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job = await _running_job(store, ticket="J-1")
        await _finish(dsn, store, job, "completed")
        assert _clock(dsn)["idle"] is False, "a completed end arms the clock"
        _age(dsn, 2 * HOUR)
        claim = await _claim(store)
        assert claim.tenant_id == T1
        assert await store.end_learning_check(T1, claim.token, idle=True) is True
        assert _clock(dsn)["idle"] is True


async def test_o7_a_completed_end_after_the_hold_ended_idle_arms_the_clock_again(world):
    """The hold ends idle first, the job ends `completed` after it: the clock is not idle again. (O7)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job, hold = await _held_by(world, store)
        assert await store.end_learning_check(T1, hold, idle=True) is True
        assert _clock(dsn)["idle"] is True, "premise"
        await _finish(dsn, store, job, "completed")
    assert _clock(dsn)["idle"] is False


@pytest.mark.parametrize("status", ["failed", "skipped"])
async def test_o7_only_a_completed_end_sets_the_mark(world, status):
    """A job ending `failed` or `skipped` beside a check sets no mark: the hold's idle end stands. (O7)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job, hold = await _held_by(world, store)
        await _finish(dsn, store, job, status)
        assert await store.end_learning_check(T1, hold, idle=True) is True
    assert _clock(dsn)["idle"] is True


async def test_o7_a_lapsed_hold_still_takes_the_mark_and_its_late_end_makes_the_tenant_due(world):
    """The hold's lease lapsed and nobody took it: a job ending `completed` still sets the mark, and the holder's late
    end leaves the tenant not idle. (O7: set when the check row has a holder, live or lapsed)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job, hold = await _held_by(world, store)
        _lapse(dsn)
        await _finish(dsn, store, job, "completed")

        assert await store.end_learning_check(T1, hold, idle=True) is True
    assert _clock(dsn)["idle"] is False


@pytest.mark.parametrize("taken_by", ["a family-less claim", "a job's own hold"])
async def test_o7_a_new_hold_clears_the_mark(world, taken_by):
    """The mark was set under a hold that lapsed; the next post-step takes the clock afresh and reads the store itself,
    so its idle end stands. (O7: cleared on a new hold)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job, hold = await _held_by(world, store)
        await _finish(dsn, store, job, "completed")
        _lapse(dsn)
        if taken_by == "a family-less claim":
            claim = await _claim(store)
            assert claim.tenant_id == T1
            second = claim.token
        else:
            second = await store.hold_learning_check(T1)
            assert second is not None
        assert second != hold, "premise: a new hold, a new token"
        assert await store.end_learning_check(T1, hold, idle=True) is False, "the lapsed holder's end changed the clock"
        assert await store.end_learning_check(T1, second, idle=True) is True
    assert _clock(dsn)["idle"] is True


@pytest.mark.parametrize("arm", ["a job queued", "a take-over retry", "an explicit start"])
async def test_o7_the_queue_time_arms_do_not_set_the_mark(world, arm):
    """While a check holds the clock, a job queued, a lapsed job's take-over retry or an explicit start arm the clock
    but set no mark: the hold's idle end stands. (O7: queue-time arms do not set it)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job, hold = await _held_by(world, store)
        if arm == "a job queued":
            await completed_investigation(store, ticket="J-2", key="k2")
        elif arm == "a take-over retry":
            execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s", (job,))
            assert await store.take_over() == [job]
        else:
            await store.create_learning_job(T1, investigation_of(dsn, job), "req-1", actor="u-1")
        assert await store.end_learning_check(T1, hold, idle=True) is True
    assert _clock(dsn)["idle"] is True, f"{arm} set the mark"


@pytest.mark.parametrize("arm", ["a job queued", "a take-over retry", "an explicit start"])
async def test_o7_a_queue_time_arm_after_the_mark_leaves_it_for_the_hold_s_end(world, arm):
    """A job ended `completed` while a check held the clock (the mark is set); then a job is queued, a lapsed job is
    retried, or a job is started explicitly: none of these spends the mark, so the hold's idle end still leaves the
    tenant not idle and due at once. (O7: only a hold's end spends the mark; queue-time arms leave it)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        job = await _running_job(store, ticket="J-1")
        other = await _running_job(store, ticket="J-2")
        _age(dsn, 2 * HOUR)
        hold = (await _claim(store)).token
        await _finish(dsn, store, job, "completed")
        if arm == "a job queued":
            await completed_investigation(store, ticket="J-3", key="k3")
        elif arm == "a take-over retry":
            execute(dsn, "UPDATE jobs.learning_jobs SET lease_expires_at = now() - interval '1 second' WHERE id = %s",
                    (other,))
            assert await store.take_over() == [other], "premise: the lapsed job was retried"
        else:
            await store.create_learning_job(T1, investigation_of(dsn, other), "req-1", actor="u-1")

        assert await store.end_learning_check(T1, hold, idle=True) is True
        assert _clock(dsn) == {"idle": False, "held": False, "holder": None}, f"{arm} spent the mark"
        after = await _claim(store)
        assert getattr(after, "tenant_id", None) == T1, f"after {arm} the tenant was not due at once"


def _finish_elsewhere(dsn: str, job: str) -> None:
    """`job`'s `completed` end write through a store of its own, on a thread and event loop of its own: another
    worker's end write, run to its commit while the caller waits. Bounded, so a wait on a lock fails rather than hangs."""
    import threading

    failed: list[BaseException] = []

    async def go() -> None:
        async with job_store(dsn) as elsewhere:
            await _finish(dsn, elsewhere, job, "completed")

    def run() -> None:
        try:
            asyncio.run(go())
        except BaseException as fault:  # noqa: BLE001 — carried to the caller
            failed.append(fault)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=30)
    assert not thread.is_alive(), "the other worker's completed end did not finish within 30 s (it waited on a lock)"
    assert not failed, failed


async def test_o7_a_completed_end_that_lands_while_the_hold_ends_is_never_lost(world):
    """Another worker's `completed` end commits just before the hold's end writes the clock (after anything the hold's
    end read first): the clock is not idle and the tenant due at once. The mark is read and the clock written in one
    statement on the locked row, so no read can go stale between them. (O7, data model: one statement)"""
    import threading

    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    dsn = world["dsn"]
    caller = threading.get_ident()
    injected: list[str] = []

    def before(_conn, _cursor, statement, _parameters, _context, _many):
        # the hold's end writes the clock row; the completed end lands just before that write, as a race would put it
        if (threading.get_ident() == caller and not injected
                and statement.lstrip().startswith("UPDATE jobs.learning_checks") and "holder" in statement):
            injected.append(statement)
            _finish_elsewhere(dsn, job)

    async with job_store(dsn) as store:
        job, hold = await _held_by(world, store)
        event.listen(Engine, "before_cursor_execute", before)
        try:
            assert await store.end_learning_check(T1, hold, idle=True) is True
        finally:
            event.remove(Engine, "before_cursor_execute", before)
        assert injected, "premise: the completed end was injected before the hold's end wrote the clock"
        assert job_row(dsn, job)["status"] == "completed", "premise: the other worker's end landed"
        assert _clock(dsn) == {"idle": False, "held": False, "holder": None}, "the completed end's wake was lost"
        again = await _claim(store)
        assert getattr(again, "tenant_id", None) == T1, "not due at once"


def _clock_row(dsn: str, tenant: str = T1) -> tuple | None:
    """The tenant's whole clock row, or None."""
    rows = execute(dsn, "SELECT checked_at, idle, checking_until, holder FROM jobs.learning_checks WHERE tenant_id = %s",
                   (tenant,))
    return rows[0] if rows else None


@pytest.mark.parametrize("state", ["offboarding", "offboarded"])
async def test_1360_o6_a_tenant_being_removed_is_refused_the_hold_and_its_idle_clock_is_left_as_it_is(world, state):
    """Refused for `offboarding`/`offboarded`; an idle clock stays idle, unheld, same time; an active tenant's is granted. (#1360 O6)"""
    dsn = world["dsn"]
    register_tenant(dsn, T2)
    async with job_store(dsn) as store:
        for tenant in (T1, T2):
            await queued_job(world, store, ticket=f"J-{tenant[:4]}", tenant=tenant)
            _age(dsn, 2 * HOUR, tenant)
            execute(dsn, "UPDATE jobs.learning_checks SET idle = TRUE WHERE tenant_id = %s", (tenant,))
        move_tenant(dsn, T1, state=state)
        before, other_before = _clock_row(dsn), _clock_row(dsn, T2)
        assert before[1] is True, "premise: the clock is idle"

        assert await store.hold_learning_check(T1) is None, "a post-step was let start for a removed tenant"
        assert _clock_row(dsn) == before, "a refused hold armed or extended the clock"
        token = await store.hold_learning_check(T2)
        assert token is not None
        after = _clock_row(dsn, T2)
        assert (after[1], after[3]) == (False, token)
        assert after[2] is not None
        assert after[0] == other_before[0], "control: a hold leaves the clock's time as it was"


@pytest.mark.parametrize("state", ["offboarding", "offboarded"])
async def test_1360_o6_a_refused_hold_creates_no_clock_for_a_tenant_that_has_none(world, state):
    """A tenant being removed with no clock row is refused and still has none. (#1360 O6)"""
    dsn = world["dsn"]
    register_tenant(dsn, T2)
    move_tenant(dsn, T2, state=state)
    async with job_store(dsn) as store:
        assert await store.hold_learning_check(T2) is None
        assert _clock_row(dsn, T2) is None, "a refused hold created the tenant's clock"
        token = await store.hold_learning_check(T1)
        assert token is not None
        assert _clock_row(dsn)[3] == token, "control: an active tenant's hold creates and holds its clock"


async def test_1360_o6_a_tenant_still_being_created_holds_the_clock_as_before(world):
    """`creating` is not refused (D7): the hold is granted and the clock armed. (#1360 O6, D7)"""
    dsn = world["dsn"]
    register_tenant(dsn, T2, state="active")
    move_tenant(dsn, T2, state="creating")
    async with job_store(dsn) as store:
        token = await store.hold_learning_check(T2)
        assert token is not None
        assert _clock(dsn, T2) == {"idle": False, "held": True, "holder": token}


async def test_a3_only_the_holder_renews_or_lets_go_and_a_late_renewal_nobody_overtook_succeeds(world):
    """A lapsed hold nobody took is renewed late (B1); once another claim takes the lapsed hold, the old holder's
    renewal misses it and its end changes nothing. (amendment 3)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        await queued_job(world, store, ticket="J-1")
        _age(dsn, 2 * HOUR)
        first = (await _claim(store)).token
        _lapse(dsn)
        assert await store.renew((), checks={first}) == [first]
        _lapse(dsn)
        second = (await _claim(store)).token
        assert second != first
        assert await store.renew((), checks={first, second}) == [second]
        assert await store.end_learning_check(T1, first, idle=True) is False
        assert _clock(dsn) == {"idle": False, "held": True, "holder": second}
        assert await store.end_learning_check(T1, second, idle=False) is True
        assert _clock(dsn) == {"idle": False, "held": False, "holder": None}


# -- the worker --------------------------------------------------------------------------------------------------


async def test_a3_a_job_ending_during_its_tenant_s_check_starts_no_second_post_step_and_the_next_check_follows_it(world):
    """L=2. A check of T1 runs (held open); T1's job J runs in the other slot and ends `completed`. J's own post-step
    does not start beside the check; once the check ends, its tenant is due at once and not idle though the store holds
    nothing waiting (the armed-while-held mark), so a second check follows. (amendment 3, O7)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release-check"
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn, wait_for=release)
    follow = post_child(world)
    async with job_store(dsn) as store:
        earlier = await queued_job(world, store, ticket="J-0")
        _end_completed(dsn, earlier)
        worker = learning_worker(world, store, job=ended_child(world, files={END: learning_end("completed")}),
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
            await _until(lambda: len(check.handed) == 2, "the next check, after the held one ended")
        finally:
            release.touch()
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert check.handed == [(None, T1), (None, T1)]
    assert follow.handed == []


async def test_a3_a_post_step_that_leaves_nothing_waiting_stops_its_tenant_s_checks(world):
    """A job's post-step ends with nothing waiting in the store: no family-less check follows, however many intervals
    pass, and the clock is idle. (amendment 3, O7; `test_a1_a_job_s_own_post_step_restarts_its_tenant_s_clock` is the
    control, work still waiting)"""
    dsn = world["dsn"]
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn)
    follow = post_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        _no_check_until_a_post_step_ends(dsn)
        worker = learning_worker(world, store, job=ended_child(world, files={END: learning_end("completed")}),
                                 post=_either(follow, check), learning_check_interval=0.3, **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await _until(lambda: ("end", job) in follow.events() and _idle(dsn), "the job's own post-step, then an idle clock")
            await asyncio.sleep(1.5)
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert check.handed == []
    assert _clock(dsn) == {"idle": True, "held": False, "holder": None}


async def test_a3_a_post_step_that_leaves_work_waiting_keeps_its_tenant_s_checks(world, monkeypatch):
    """A job's post-step ends with work the author gate would act on in the store: the tenant is not idle, and a check
    follows within the interval. (amendment 3, O7, Flow 3)"""
    dsn = world["dsn"]
    _work_waits(dsn, monkeypatch)
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn)
    async with job_store(dsn) as store:
        await queued_job(world, store, ticket="J-1")
        _no_check_until_a_post_step_ends(dsn)
        worker = learning_worker(world, store, job=ended_child(world, files={END: learning_end("completed")}),
                                 post=_either(post_child(world), check), learning_check_interval=0.3, **_FAST)
        serving = asyncio.create_task(worker.serve())
        try:
            await _until(lambda: check.handed, "the family-less check")
        finally:
            _stop_serving(serving)
            await asyncio.wait_for(serving, timeout=15)
    assert check.handed[0] == (None, T1)


async def test_a3_the_worker_renews_a_running_check_s_hold_so_no_second_check_starts_beside_it(world):
    """A one-second lease, two learning slots, and a check held open for several leases: the worker renews the hold, so
    the tenant is never claimed again while the check runs, and the check is not fenced. (amendment 3)"""
    dsn = world["dsn"]
    release = world["tmp"] / "release-check"
    check = CheckChild(world["tmp"] / "check", world["runs"], dsn=dsn, wait_for=release)
    async with job_store(dsn, lease=1.0) as store:
        stranded = await queued_job(world, store, ticket="J-0")
        _end_completed(dsn, stranded)
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


# -- the worker: a job the offboarding ended (#1360 O6) -----------------------------------------------------------


@pytest.mark.parametrize("offboarded", [True, False], ids=["offboarded", "control-active"])
async def test_1360_o6_a_running_job_ended_by_the_offboarding_is_followed_by_no_post_step(world, offboarded):
    """No post-step child after the offboard commit; the control tenant stays active and gets one; neither leaves a post-step file in the runs. (#1360 O6)"""
    dsn, release, mark = world["dsn"], world["tmp"] / "release", world["tmp"] / "term-{id}"
    jobs = ended_child(world, files={END: learning_end("completed")}, wait_for=release, term="finish",
                     term_mark=str(mark))
    post = post_child(world)
    async with job_store(dsn) as store:
        job = await queued_job(world, store, ticket="J-1")
        draining = asyncio.create_task(learning_worker(world, store, job=jobs, post=post, **_FAST).drain())
        try:
            await _until(lambda: jobs.seen(job), "the job's child to start")
            execute(dsn, "UPDATE jobs.learning_jobs SET status = 'skipped', reason = 'tenant_offboarded', message = 'tenant offboarded', "
                         "evidence_state = 'none', finished_at = now(), lease_expires_at = NULL WHERE id = %s", (job,))
            if offboarded:
                move_tenant(dsn, T1, state="offboarding")
            await _until(lambda: Path(str(mark).replace("{id}", job)).exists(), "the ended job's child to be ended", timeout=10)
        finally:
            release.touch()
            await asyncio.wait_for(draining, timeout=60)

    assert (job_row(dsn, job)["status"], job_row(dsn, job)["reason"]) == ("skipped", "tenant_offboarded")
    assert [p.name for p in world["runs"].iterdir() if "post-step" in p.name] == [], "a post-step file reached the runs"
    if offboarded:
        assert post.handed == [], "a post-step was started for a tenant being removed"
    else:
        assert [h[0] for h in post.handed] == [job], "control: the same flow launches its post-step"
