"""#1343 piece B over the #1342 worker: leases and their renewal, cost so far, a fenced row ending its child, end writes
that error, take-over, cancel of a running row and the deliberate stop, with the repair and review rounds that followed.
Shared setup: `_worker1342`."""
from __future__ import annotations

import asyncio
import inspect
import logging
import os
import signal
import sys
import time
import uuid
from pathlib import Path

import pytest

from defender.tests.support.jobs._jobs1342 import (
    NOW,
    T1,
    WORKER_LOGGER,
    ScriptedChild,
    StandInContainers,
    an_alert,
    job_end,
    job_store,
    lower_limit,
    plant_sessions,
    plant_spend,
    row,
    session_pointer,
    REFUSED,
    UNSEEN,
)
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.jobs._jobs1342 import (  # noqa: E402
    FaultableStore,
    LaneLanding,
    accounting_written,
    lapse_lease,
    lease_left,
    session_database_held_locked,
)
from defender.tests.support.jobs._worker1342 import (
    CASE,
    CASES,
    SONNET_IN,
    SONNET_OUT,
    _FAST,
    _NobodyPlannedThis,
    _StoreWhoseAlertReadFails,
    _StoreWhoseFinishFails,
    _child,
    _committed,
    _gone,
    _handed_back,
    _kill_whatever_remains,
    _lanes_failing,
    _queued,
    _until,
    _worker,
)
from defender.tests.support.jobs import _worker1342 as _shared

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]
# The shared fixtures, bound in this module so pytest finds them here (an import of `world` would be shadowed by
# every test's parameter of that name).
world = _shared.world
_no_database_address_in_the_workers_environment = _shared._no_database_address_in_the_workers_environment


SONNET = "claude-sonnet-4-6"


_SPEND = [(SONNET, {"input_tokens": 1_000_000})]  # priced SONNET_IN = 3.0 USD


def _spending(world: dict, steps: list[tuple[str, dict]], *, released: bool = False, marks_name: str = "marks",
              seal: bool = True, **kw) -> tuple[ScriptedChild, Path]:
    """A child that holds its session database open and appends one priced response per step, then waits for `marks/go-<n>` (`released`: they exist already); `seal=False`: the child never seals its ledger (a run killed before its seal, r7.3 T2)."""
    marks = world["tmp"] / marks_name
    if released:
        marks.mkdir(exist_ok=True)
        for n in range(len(steps)):
            (marks / f"go-{n}").touch()
    return _child(world, sessions={"case": CASE, "per_run": True, "steps": steps, "marks": str(marks), "seal": seal}, **kw), marks


def _term_mark(world: dict) -> str:
    return str(world["tmp"] / "term-{id}")


def _termed(world: dict, inv: str) -> bool:
    return Path(_term_mark(world).replace("{id}", inv)).exists()


class _StoreOutage:
    """The real store; while `down`, every method outside the stable read/admission/claim/cancel/delete/take-over API raises a connection error (the worker's own writes, whatever they are named). Notes every call."""

    ALLOWED = frozenset({"claim", "get_alert", "get_investigation", "insert_alert", "create_investigation",
                         "cancel_investigation", "delete_investigation", "take_over", "close"})

    def __init__(self, store) -> None:
        self._store, self.down, self.calls, self.refused = store, False, [], []

    def __getattr__(self, name):
        attr = getattr(self._store, name)
        if name.startswith("_") or not callable(attr):
            return attr

        async def call(*args, **kw):
            self.calls.append(name)
            if self.down and name not in self.ALLOWED:
                self.refused.append(name)
                raise ConnectionError("the database is gone")
            return await attr(*args, **kw)
        return call


class _StoreHoldingTheLaunch:
    """The real store, except the first alert read (the launch's first step, before any child exists) waits for `gate`."""

    def __init__(self, store) -> None:
        self._store, self.gate, self.waiting = store, asyncio.Event(), asyncio.Event()
        self._held = False

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def get_alert(self, tenant_id, alert_id):
        if not self._held:
            self._held = True
            self.waiting.set()
            await self.gate.wait()
        return await self._store.get_alert(tenant_id, alert_id)


def _plant_running_lapsed(dsn: str, alert_id: str, *, attempt: int = 1) -> str:
    """A `running` row nobody holds, its lease lapsed a minute ago by the database clock."""
    inv = str(uuid.uuid4())
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                 "started_at, cost_usd, cost_is_lower_limit, lease_expires_at) VALUES (%s, %s, %s, 'planted', %s, 'running', "
                 "%s, %s, 0, false, now() - interval '1 minute')", (inv, T1, alert_id, attempt, NOW, NOW))
    return inv


def _lapsed(dsn: str, inv: str) -> bool:
    left = lease_left(dsn, inv)
    return left is not None and left <= 0


async def _stop_all(*tasks) -> None:
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def test_b_the_ratified_defaults_are_a_thirty_second_lease_renewed_each_second_cost_every_fifteen_and_take_over_every_five():
    """The seams' defaults: lease 30 s, renewal 1 s, cost tick 15 s, take-over 5 s. (B1, B2, B7, r5 item 11)"""
    from defender.jobs import JobStore
    from defender.worker import Worker

    lease = inspect.signature(JobStore.__init__).parameters["lease"].default
    worker = inspect.signature(Worker.__init__).parameters
    assert (lease, worker["renewal_interval"].default, worker["cost_interval"].default,
            worker["takeover_interval"].default) == (30.0, 1.0, 15.0, 5.0)


# --- B1: renewal ----------------------------------------------------------------------------------------

async def test_b1_a_held_row_keeps_a_fresh_lease_while_its_child_runs(world):
    """A 2 s lease, renewed each 0.2 s: 4 s into the run the lease has not lapsed. (B1)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    async with job_store(world["dsn"], lease=2.0) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            await asyncio.sleep(4.0)
            left = lease_left(world["dsn"], inv)
            assert left is not None
            assert left > 0, f"the held row's lease lapsed while its child ran: {left}"
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    assert row(world["dsn"], inv)["stage"] == "completed"


async def test_b1_every_held_row_is_renewed_by_one_store_call_per_tick(world):
    """Three held rows, a 0.2 s tick: over 2 s the worker makes about one store call per tick, not one per row (30). (B1: one statement for all held rows)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    async with job_store(world["dsn"]) as inner:
        store = _StoreOutage(inner)
        ids = [await _queued(inner, ticket=f"T-{n}", key=f"k{n}") for n in range(3)]
        drained = asyncio.create_task(_worker(world, store, child, slots=3, renewal_interval=0.2,
                                              cost_interval=60.0, takeover_interval=60.0).drain())
        try:
            await _until(lambda: len(child.seen_all()) == 3, "three children")
            await asyncio.sleep(0.5)
            before = len(store.calls)
            await asyncio.sleep(2.0)
            made = len(store.calls) - before
            assert all((lease_left(world["dsn"], i) or 0) > 0 for i in ids)
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    assert 5 <= made <= 15, f"{made} store calls in 10 ticks of three held rows"


async def test_b1_a_late_renewal_of_a_row_nobody_took_over_succeeds(world):
    """A held row whose lease lapsed (a stalled renewal) and was not taken over is made fresh again by the next renewal; its child runs on. (B1: conditional on `running`, not on a fresh lease)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            lapse_lease(dsn, inv)
            await _until(lambda: (lease_left(dsn, inv) or -1) > 10, "the late renewal", timeout=3)
            assert row(dsn, inv)["stage"] == "running"
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    assert row(dsn, inv)["stage"] == "completed"


async def test_b1_a_deliberate_stop_keeps_renewing_until_the_rows_last_write_so_nothing_is_taken_over_during_teardown(world):
    """A child that ignores SIGTERM for the whole 3 s grace: a taker polling take-over never gets the row (1 s lease) while the stop runs; afterwards the hand-back, not a lapse, ended it. (B1, B11, r5 item 1)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="ignore")
    dsn = world["dsn"]
    async with job_store(dsn, lease=1.0) as store_a, job_store(dsn, lease=1.0) as store_b:
        inv = await _queued(store_a)
        serving = asyncio.create_task(_worker(world, store_a, child, stop_grace=3.0, **_FAST).serve())

        async def taker() -> None:
            while True:
                await store_b.take_over(held=frozenset())
                await asyncio.sleep(0.1)
        taking = asyncio.create_task(taker())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            began = time.monotonic()
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            while not serving.done() and accounting_written(dsn, inv) is None:  # the mark: the hand-back landed
                assert row(dsn, inv)["stage"] == "running", "the row was taken over while its worker was stopping"
                assert (lease_left(dsn, inv) or 0) > 0, "the stopping worker let the row's lease lapse"
                await asyncio.sleep(0.1)
            await asyncio.wait_for(serving, timeout=10)
            assert time.monotonic() - began >= 2.5, "premise: the stop waited out the child's grace"
            await _until(lambda: row(dsn, inv)["failure_reason"] == "lease_lapsed", "the handed-back row to be taken over")
        finally:
            release.touch()
            await _stop_all(taking, serving)
    assert accounting_written(dsn, inv) is not None, "the row was lost to a lapse, not handed back"
    _kill_whatever_remains(child.seen(inv))


async def test_b_drain_renews_its_rows_takes_nothing_over_and_ends_only_when_they_are_done(world):
    """`drain()` over one running row beside a stranger's lapsed one: the held lease stays fresh, the stranger stays `running`, and drain returns after the child's end. (r5 item 10, B1, B7)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn, lease=1.0) as store:
        inv = await _queued(store)
        stranger = _plant_running_lapsed(dsn, (await an_alert(store, T1, ticket="T-9")).alert_id)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            for _ in range(20):
                assert (lease_left(dsn, inv) or 0) > -0.3, "drain stopped renewing its row"
                await asyncio.sleep(0.1)
            assert row(dsn, stranger)["stage"] == "running", "drain took over a lapsed row"
            assert not drained.done()
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    assert (row(dsn, inv)["stage"], row(dsn, stranger)["stage"]) == ("completed", "running")


# --- B2: cost so far ------------------------------------------------------------------------------------

async def test_b2_b6_cost_so_far_is_copied_while_the_live_child_writes_its_session_database(world):
    """Each response the live child appends shows as cost so far within the cost tick, knowledge stays unset, the child's writes are not blocked; finish sets the final figures. (B2, claim B6, B4)"""
    child, marks = _spending(world, [(SONNET, {"input_tokens": 1_000_000}), (SONNET, {"output_tokens": 1_000_000})],
                             files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            for step, so_far in ((0, SONNET_IN), (1, SONNET_IN + SONNET_OUT)):
                await _until(lambda s=step: (marks / f"wrote-{s}").exists(), f"the child's append {step}")
                await _until(lambda f=so_far: row(dsn, inv)["cost_usd"] == pytest.approx(f), f"cost so far {so_far}",
                             timeout=5.0)
                live = row(dsn, inv)
                assert (live["stage"], live["knowledge"]) == ("running", None), "knowledge was written mid-run"
                (marks / f"go-{step}").touch()
        finally:
            for step in (0, 1):
                (marks / f"go-{step}").touch()
            await asyncio.wait_for(drained, timeout=60)

    assert not list(marks.glob("insert-failed-*")), [f.read_text(encoding="utf-8") for f in marks.glob("insert-failed-*")]
    took = [float((marks / f"wrote-{n}").read_text(encoding="utf-8")) + float((marks / f"ledger-{n}").read_text(encoding="utf-8"))
            for n in (0, 1)]  # the append, then the ledger insert
    assert max(took) < 1.0, f"the worker's reads blocked the child's appends: {took}"
    final = row(dsn, inv)
    assert (final["stage"], final["cost_usd"]) == ("completed", pytest.approx(SONNET_IN + SONNET_OUT))
    assert final["knowledge"] is not None
    assert accounting_written(dsn, inv) is not None, "finish did not mark the final accounting written"


async def test_r7_a_live_cost_so_far_read_beside_an_unseen_row_is_not_marked_and_the_final_read_is(world):
    """A running job whose ledger holds one priced response and one unseen request: the live copy is the sum and reads
    exact, stored and on the record; the final read over the same rows is "at least". (r7 S2 live reads, S2a)"""
    release = world["tmp"] / "release"
    dsn, runs = world["dsn"], world["runs"]
    child = _child(world, files=_committed(), wait_for=release)
    plant_sessions(runs, CASE, [("main", SONNET, {"input_tokens": 1_000_000})])
    async with job_store(dsn) as store:
        inv = await _queued(store)
        plant_spend(runs, CASE, inv, [(SONNET, {"input_tokens": 1_000_000})], sealed=False)
        plant_spend(runs, CASE, inv, [(SONNET, {})], outcome=UNSEEN)
        (runs / f"{inv}.session-pointer.json").write_text(session_pointer(CASE), encoding="utf-8")
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            await _until(lambda: row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN), "the live copy", timeout=5.0)
            for _ in range(5):  # several cost ticks
                await asyncio.sleep(0.3)
                live = await store.get_investigation(T1, inv)
                assert (live.stage, live.cost_usd) == ("running", pytest.approx(SONNET_IN)), "premise: a live row"
                assert (lower_limit(dsn, inv), live.cost_is_lower_limit) == (False, False), "a live read was marked"
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
        final = await store.get_investigation(T1, inv)

    assert (final.stage, final.cost_usd) == ("completed", pytest.approx(SONNET_IN))
    assert (lower_limit(dsn, inv), final.cost_is_lower_limit) == (True, True), "an unseen row left the final cost exact"


_EXTRA_ROWS = {
    "none": (None, False),
    "refused": (dict(outcome=REFUSED, agent_id="gather:l-00c", model="claude-haiku-4-5", usage={}), False),
    "unpriced": (dict(outcome="response", agent_id="gather:l-001", model="claude-opus-9-0", usage={"input_tokens": 1_000_000}), True),
}


@pytest.mark.parametrize("extra", _EXTRA_ROWS)
async def test_r7_the_final_cost_reads_at_least_exactly_when_the_ledger_has_an_unpriced_row(world, extra):
    """A finished job whose ledger holds one priced response beside a refused ($0) row, an unpriced response, or nothing: the
    sum is the priced response in all three, and only the unpriced row marks it. (r7 S2b, S5)"""
    row, marked = _EXTRA_ROWS[extra]
    dsn, runs = world["dsn"], world["runs"]
    child = _child(world, files=_committed())
    plant_sessions(runs, CASE, [("main", SONNET, {"input_tokens": 1_000_000})])
    async with job_store(dsn) as store:
        inv = await _queued(store)
        plant_spend(runs, CASE, inv, [(SONNET, {"input_tokens": 1_000_000})], sealed=row is None)
        if row is not None:
            plant_spend(runs, CASE, inv, [(row["model"], row["usage"])], outcome=row["outcome"], agent_id=row["agent_id"])
        (runs / f"{inv}.session-pointer.json").write_text(session_pointer(CASE), encoding="utf-8")
        await _worker(world, store, child, **_FAST).drain()
        final = await store.get_investigation(T1, inv)

    assert (final.stage, final.cost_usd) == ("completed", pytest.approx(SONNET_IN))
    assert (lower_limit(dsn, inv), final.cost_is_lower_limit) == (marked, marked)


@pytest.mark.parametrize("agent_id", ["gather", "review", "planner"])
async def test_r7_s4_a_ledger_row_of_an_unknown_agent_id_leaves_the_finished_job_s_cost_unknown(world, agent_id):
    """A finished job whose ledger holds a priced MAIN response and one row of an id outside the four kinds: stage completed, cost None (unknown, not the priced sum), mark false. (r7.1 F, S4)"""
    dsn, runs = world["dsn"], world["runs"]
    child = _child(world, files=_committed())
    plant_sessions(runs, CASE, [("main", SONNET, {"input_tokens": 1_000_000})])
    async with job_store(dsn) as store:
        inv = await _queued(store)
        plant_spend(runs, CASE, inv, [(SONNET, {"input_tokens": 1_000_000})], sealed=False)
        plant_spend(runs, CASE, inv, [(SONNET, {"input_tokens": 1_000_000})], agent_id=agent_id)
        (runs / f"{inv}.session-pointer.json").write_text(session_pointer(CASE), encoding="utf-8")
        await _worker(world, store, child, **_FAST).drain()
        final = await store.get_investigation(T1, inv)

    assert (final.stage, final.cost_usd) == ("completed", None)
    assert (lower_limit(dsn, inv), final.cost_is_lower_limit) == (False, False)


@pytest.mark.parametrize("end", ["finish", "cancel", "stop"])
async def test_b2_a_failed_cost_read_keeps_the_last_good_figure_mid_run_and_writes_null_in_the_end_write(world, end):
    """The pointer goes unreadable after one copied figure: the row keeps 3.0 for several ticks while still renewed; the end write (finish, final accounting or hand-back) then carries cost NULL, not 3.0. (B2, R2)"""
    child, marks = _spending(world, _SPEND, files=_committed(), term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            await _until(lambda: row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN), "the first copy", timeout=5)
            (world["runs"] / f"{inv}.session-pointer.json").write_text("not json", encoding="utf-8")
            for _ in range(15):  # about five cost ticks
                await asyncio.sleep(0.1)
                assert row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN), "a failed read replaced the last good figure"
                assert (lease_left(dsn, inv) or 0) > 0
            if end == "cancel":
                await store.cancel_investigation(T1, inv, actor="u-1")
            elif end == "finish":
                (marks / "go-0").touch()
            else:
                assert not serving.done()
                os.kill(os.getpid(), signal.SIGTERM)
            await _until(lambda: accounting_written(dsn, inv) is not None, "the end write", timeout=10)
        finally:
            (marks / "go-0").touch()
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await _stop_all(serving)

    final = row(dsn, inv)
    assert final["cost_usd"] is None, "an unreadable final cost was written as a figure"
    assert final["stage"] == {"finish": "completed", "cancel": "aborted", "stop": "running"}[end]


async def test_b2_a_cost_read_that_hangs_never_delays_the_lease_renewal(world):
    """The session database is locked, so the cost read waits on SQLite for the whole window: a 1 s lease is still fresh at every sample for 3 s; once unlocked the cost (the run's ledger rows, #1377 S1) shows. (B2, r5 item 4)"""
    release = world["tmp"] / "release"
    dsn, runs = world["dsn"], world["runs"]
    child = _child(world, files=_committed(), wait_for=release)
    plant_sessions(runs, CASE, [("main", SONNET, {"input_tokens": 1_000_000})])
    async with job_store(dsn, lease=1.0) as store:
        inv = await _queued(store)
        plant_spend(runs, CASE, inv, [(SONNET, {"input_tokens": 1_000_000})])  # the cost is the run's ledger, not its conversation (S1)
        (runs / f"{inv}.session-pointer.json").write_text(session_pointer(CASE), encoding="utf-8")
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            with session_database_held_locked(runs, CASE):
                await _until(lambda: child.seen(inv), "the child to start")
                for _ in range(30):
                    left = lease_left(dsn, inv)
                    assert left is not None
                    assert left > 0, f"a blocked cost read delayed the renewal: {left}"
                    await asyncio.sleep(0.1)
                assert row(dsn, inv)["cost_usd"] == 0, "premise: the read has not returned"
            await _until(lambda: row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN), "the cost once unlocked", timeout=10)
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)


# --- B3/B4/B9: a fenced row ends its child; one end path -------------------------------------------------

@pytest.mark.parametrize("how", ["cancel", "delete"])
async def test_b9_b3_b4_a_cancelled_or_deleted_running_row_has_its_child_ended_within_a_renewal_and_the_holder_writes_what_is_left(
        world, how):
    """Cancel answers `aborted` at once (a deleted row vanishes); within ~1 s (default renewal) the child gets SIGTERM; after it exits a cancelled row keeps its stage and gains final cost and the mark, a deleted row stays gone. (B9, B3, B4)"""
    child, marks = _spending(world, _SPEND, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, cost_interval=60.0).drain())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            if how == "cancel":
                got = await store.cancel_investigation(T1, inv, actor="u-1")
                assert (got.stage, got.failure_reason) == ("aborted", "cancelled")
            else:
                execute(dsn, "DELETE FROM jobs.investigations WHERE id = %s", (inv,))
            await _until(lambda: _termed(world, inv), "the fenced row's child to get SIGTERM", timeout=3.0)
        finally:
            (marks / "go-0").touch()
            await asyncio.wait_for(drained, timeout=60)

    final = row(dsn, inv)
    if how == "delete":
        assert final is None, "the worker wrote a row that was deleted"
        return
    assert (final["stage"], final["failure_reason"], final["finished_at"]) == ("aborted", "cancelled", NOW)
    assert final["cost_usd"] == pytest.approx(SONNET_IN), "the holder's final cost was not written after the cancel"
    assert lower_limit(dsn, inv) is True  # the child was killed before sealing its ledger (r7.3 T2)
    assert accounting_written(dsn, inv) is not None


@pytest.mark.parametrize("how", ["cancel", "delete", "take_over"])
async def test_b3_a_row_fenced_before_its_child_exists_is_never_launched_and_still_gets_its_final_accounting(world, how):
    """Claimed, then cancelled/deleted/taken over while the launch is held before any child: the child is never started; a surviving row ends with cost 0, no knowledge and the mark, its stage untouched. (B3, B4, r5 item 5)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as inner, job_store(dsn) as taker:
        store = _StoreHoldingTheLaunch(inner)
        inv = await _queued(inner)
        drained = asyncio.create_task(_worker(world, store, child, **_FAST).drain())
        try:
            await asyncio.wait_for(store.waiting.wait(), timeout=10)
            if how == "cancel":
                await inner.cancel_investigation(T1, inv, actor="u-1")
            elif how == "delete":
                execute(dsn, "DELETE FROM jobs.investigations WHERE id = %s", (inv,))
            else:
                async def lapsed() -> bool:
                    lapse_lease(dsn, inv)
                    await taker.take_over(held=frozenset())
                    return row(dsn, inv)["stage"] == "failed"
                for _ in range(100):
                    if await lapsed():
                        break
                    await asyncio.sleep(0.01)
            await asyncio.sleep(1.0)  # five renewal ticks: the fence is seen while the launch is still held
        finally:
            store.gate.set()
            await asyncio.wait_for(drained, timeout=30)

    assert [e for e in child.events() if e[1] == inv] == [], "a fenced row's child was launched"
    final = row(dsn, inv)
    if how == "delete":
        assert final is None
        return
    assert final["stage"] == {"cancel": "aborted", "take_over": "failed"}[how]
    assert (final["cost_usd"], final["knowledge"], lower_limit(dsn, inv)) == (0, None, False)  # nothing launched: exact 0, the holder's own write
    assert accounting_written(dsn, inv) is not None


# --- B5: an end write that errors -----------------------------------------------------------------------

async def test_b5_a_failing_end_write_is_retried_until_it_lands_and_nothing_new_is_claimed_meanwhile(world):
    """The finish fails four times: tried each second until it lands (`completed`); a row queued meanwhile waits until then. (B5, r4 item 3)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        used = _StoreWhoseFinishFails(store, bad, ConnectionError("the database is gone"), fails=4)
        serving = asyncio.create_task(_worker(world, used, child, slots=2, **_FAST).serve())
        try:
            await _until(lambda: used.tries(bad), "the first failed end write")
            later = await _queued(store, ticket="T-2", key="k2")
            await _until(lambda: len(used.tries(bad)) >= 3, "a third try of the end write", timeout=10)
            assert row(dsn, later)["stage"] == "queued", "a row was claimed while an end write was failing"
            await _until(lambda: row(dsn, bad)["stage"] == "completed", "the end write to land", timeout=15)
            await _until(lambda: row(dsn, later)["stage"] == "completed", "the waiting row to run", timeout=15)
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert [t[0] for t in used.tries(bad)] == ["completed"] * 5


async def test_b5_a_final_accounting_write_that_hits_an_outage_is_retried_until_it_lands_and_nothing_is_claimed_meanwhile(world):
    """A cancelled row whose child ends by itself during an outage: its final accounting is refused for a few seconds, claims wait, then it lands with the cost and the stage untouched. (B5, B4)"""
    release = world["tmp"] / "release"
    child, marks = _spending(world, _SPEND, files=_committed(), released=True, wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as inner:
        store = _StoreOutage(inner)
        inv = await _queued(inner)
        serving = asyncio.create_task(_worker(world, store, child, renewal_interval=30.0, cost_interval=60.0,
                                              takeover_interval=30.0).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            store.down = True
            await inner.cancel_investigation(T1, inv, actor="u-1")
            release.touch()  # the child ends by itself while the database is down
            await _until(lambda: store.refused, "the worker's first refused write", timeout=40)
            later = await _queued(inner, ticket="T-2", key="k2")
            await asyncio.sleep(2.5)
            assert len(store.refused) >= 2, "a refused end write was not retried"
            assert row(dsn, later)["stage"] == "queued", "a row was claimed while the worker's writes were failing"
            assert accounting_written(dsn, inv) is None
            store.down = False
            await _until(lambda: accounting_written(dsn, inv) is not None, "the final accounting to land", timeout=10)
            await _until(lambda: row(dsn, later)["stage"] == "completed", "the waiting row to run", timeout=15)
        finally:
            release.touch()
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    final = row(dsn, inv)
    assert (final["stage"], final["failure_reason"], final["cost_usd"]) == ("aborted", "cancelled", pytest.approx(SONNET_IN))


_TWO_STEPS = [(SONNET, {"input_tokens": 1_000_000}), (SONNET, {"output_tokens": 1_000_000})]  # 3.0 USD, then 15.0 more


@pytest.mark.parametrize("schedule", ["renewals fail until the end write has landed", "the end write fails eleven times",
                                      "one cost read fails"])
async def test_b5_b2_a_transient_fault_is_waited_out_and_the_worker_ends_as_it_would_have_with_none(world, schedule):
    """Whatever the fault schedule, once it clears the row ends as the reader decided, no retry exists, a row queued afterwards runs, and a live row's cost moves on. (B5, B2, r5 items 7, 13, 14)"""
    child, marks = _spending(world, _TWO_STEPS, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as inner:
        store = FaultableStore(inner)
        inv = await _queued(inner, ticket="T-1", key="k1")
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's first spend")
            await _until(lambda: row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN), "the first copy", timeout=5)
            pointer = world["runs"] / f"{inv}.session-pointer.json"
            if schedule == "one cost read fails":
                good = pointer.read_text(encoding="utf-8")
                pointer.write_text("not json", encoding="utf-8")
                await asyncio.sleep(1.0)  # three cost ticks: the read fails and the cost stays at the last good figure
                assert row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN)
                pointer.write_text(good, encoding="utf-8")
                (marks / "go-0").touch()  # the live child spends again: the cost moves past its frozen value
                await _until(lambda: row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN + SONNET_OUT),
                             "the cost to move past the frozen figure while the child runs", timeout=5)
                assert row(dsn, inv)["stage"] == "running"
            elif schedule == "the end write fails eleven times":
                store.finish_fails = 11  # more than any bounded retry the design replaced or a cap of 5 or 10 would make
            else:
                store.renew_down = True
                await _until(lambda: store.renews_failed >= 2, "two renewals to fail while the child runs", timeout=10)
            for step in (0, 1):
                (marks / f"go-{step}").touch()
            await _until(lambda: row(dsn, inv)["stage"] == "completed", "the row to end as the reader decided", timeout=45)
            store.renew_down = False  # the faults are over
            assert store.finish_fails == 0
            later_marks = [marks / f"go-{step}" for step in (0, 1)]
            renewed_before = store.renews_ok
            for mark in later_marks:  # the next row waits for us, so a renewal has a row to cover
                mark.unlink()
            later = await _queued(inner, ticket="T-2", key="k2")
            await _until(lambda: child.seen(later), "the row queued after the faults to be claimed", timeout=20)
            await _until(lambda: store.renews_ok > renewed_before, "a renewal to succeed once the fault is over", timeout=10)
            for mark in later_marks:
                mark.touch()
            await _until(lambda: row(dsn, later)["stage"] == "completed", "the row queued after the faults to run", timeout=20)
        finally:
            for step in (0, 1):
                (marks / f"go-{step}").touch()
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)

    final = row(dsn, inv)
    assert (final["stage"], final["disposition"], final["failure_reason"]) == ("completed", "inconclusive", None)
    assert final["cost_usd"] == pytest.approx(SONNET_IN + SONNET_OUT)
    assert accounting_written(dsn, inv) is not None
    assert execute(dsn, "SELECT count(*) FROM jobs.investigations WHERE request_key = 'k1'") == [(1,)], "a retry was made"


# --- B7: take-over ---------------------------------------------------------------------------------------

async def test_b_p3_b6_b3_a_worker_never_takes_over_a_row_it_holds_another_does_and_the_holder_ends_its_child_and_records_its_spend(world):
    """Holder A (0.5 s lease, renewing every 2 s, one slot) never takes its own lapsed row over while it takes over a stranger's; worker B does, A then ends its child and writes its spend to the old row, B's retry starts at 0. (B-P3, B7, B6, B3, B4)"""
    release = world["tmp"] / "release"
    child, marks = _spending(world, _SPEND, files=_committed(), released=True, wait_for=release, seal=False,
                             term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn, lease=0.5) as store_a, job_store(dsn) as store_b:
        held = await _queued(store_a, ticket="T-1", key="k1")
        stranger = _plant_running_lapsed(dsn, (await an_alert(store_a, T1, ticket="T-9")).alert_id)
        a = asyncio.create_task(_worker(world, store_a, child, slots=1, renewal_interval=2.0,
                                        takeover_interval=0.1).serve())
        b = None
        try:
            await _until(lambda: child.seen(held), "A's child")
            await _until(lambda: row(dsn, stranger)["stage"] == "failed", "A to take over the stranger's row", timeout=5)
            seen_lapsed = False
            for _ in range(60):  # 3 s, about 20 of A's take-over passes while its own lease is lapsed
                seen_lapsed |= (lease_left(dsn, held) or 0) < 0
                assert row(dsn, held)["stage"] == "running", "a worker took over a row it holds"
                await asyncio.sleep(0.05)
            assert seen_lapsed, "premise: the held row's lease was never seen lapsed"
            b = asyncio.create_task(_worker(world, store_b, child, slots=1, renewal_interval=1.0,
                                            takeover_interval=0.1).serve())
            await _until(lambda: row(dsn, held)["failure_reason"] == "lease_lapsed", "B to take the row over", timeout=5)
            # read now: A's 0.5 s lease (renewed every 2 s) lets B take over any retry A itself claims later
            attempts = execute(dsn, "SELECT attempt FROM jobs.investigations WHERE request_key = 'k1' ORDER BY attempt")
            await _until(lambda: _termed(world, held), "A to end its child", timeout=5)
            await _until(lambda: accounting_written(dsn, held) is not None, "A's final accounting", timeout=5)
        finally:
            release.touch()
            await _stop_all(*(t for t in (a, b) if t is not None))

    old = row(dsn, held)
    assert old["stage"] == "failed", "the holder's final accounting changed the stage"
    assert old["cost_usd"] == pytest.approx(SONNET_IN), "the cut-off holder's spend was not recorded on its own row"
    assert not (marks / "sealed").exists(), "premise: the child must be killed before it seals its ledger"
    assert lower_limit(dsn, held) is True  # taken over, then a child killed before sealing its ledger (r7.3 T2)
    assert attempts == [(1,), (2,)]


async def test_b7_b5_a_worker_whose_own_end_write_keeps_failing_as_an_outage_takes_nothing_over_and_claims_nothing(world):
    """CONFLICT-UPDATED: one row's end write fails as an outage for good: the same worker leaves a stranger's lapsed row alone (its own calls hit an outage within the last lease, so others' leases may have lapsed in the same outage) and claims nothing. (B7 as amended by #1343's second review; B5: no claims meanwhile)

    The stranger and the queued row appear only once the end write is failing: present from the start, the stranger
    was taken over and its retry claimed and run before the first failure, and the test raced that order."""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        bad = await _queued(store, ticket="T-1", key="k1")
        stranger_alert = (await an_alert(store, T1, ticket="T-9")).alert_id
        used = _StoreWhoseFinishFails(store, bad, ConnectionError("the database is gone"), fails=10**6)
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: len(used.tries(bad)) >= 2, "the end write to be failing")
            stranger = _plant_running_lapsed(dsn, stranger_alert)
            waiting = await _queued(store, ticket="T-2", key="k2")
            tries = len(used.tries(bad))
            await asyncio.sleep(2.5)  # many take-over intervals and claim polls
            assert len(used.tries(bad)) > tries, "premise: the end write stopped being tried"
            assert row(dsn, stranger)["stage"] == "running", "a worker in an outage took a lapsed row over"
            assert row(dsn, stranger)["failure_reason"] is None
            assert row(dsn, waiting)["stage"] == "queued", "a row was claimed while a write was failing"
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert row(dsn, bad)["stage"] == "running", "premise: the end write never landed"


# --- B11: the deliberate stop ----------------------------------------------------------------------------

@pytest.mark.parametrize("term", ["default", "mark"])
async def test_b11_a_deliberate_stop_hands_a_running_row_back_with_its_final_cost_and_its_retry_is_a_new_row(world, term):
    """SIGTERM while a child runs (killed by it, or exiting at once with no records: R1): the row stays `running`, lease lapsed, final cost, marked; never claimed again; a take-over queues attempt 2. (B11, r4 item 2, r5 R1)"""
    child, marks = _spending(world, _SPEND, term=term, term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            (marks / "go-0").touch()
            await _stop_all(serving)

        _handed_back(dsn, inv, cost=SONNET_IN, at_least=True)  # killed run: its ledger never sealed (r7.3 T2)
        assert await store.claim() is None, "a handed-back row was claimed again"
        await store.take_over(held=frozenset())
        retry = await store.claim()
    assert (row(dsn, inv)["stage"], row(dsn, inv)["failure_reason"]) == ("failed", "lease_lapsed")
    assert retry is not None, "the take-over queued no retry"
    assert (retry.record.investigation_id != inv, retry.record.attempt) == (True, 2)


async def test_b11_a_child_that_completes_on_its_own_as_the_stop_signals_it_is_finished_not_handed_back(world):
    """The child writes its committed report as SIGTERM lands and exits 0: the row is `completed` with its cost and knowledge and the mark, and no retry exists. (B11, r5 item 3)"""
    child, marks = _spending(world, _SPEND, files=_committed(), term="finish", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            (marks / "go-0").touch()
            await _stop_all(serving)
        assert await store.claim() is None, "a retry was queued for a finished run"
    final = row(dsn, inv)
    assert (final["stage"], final["cost_usd"]) == ("completed", pytest.approx(SONNET_IN))
    assert final["knowledge"] is not None
    assert accounting_written(dsn, inv) is not None
    assert execute(dsn, "SELECT count(*) FROM jobs.investigations WHERE request_key = 'k1'") == [(1,)]


async def test_b11_a_row_that_became_terminal_before_the_stop_gets_its_final_accounting_not_a_hand_back(world):
    """Cancelled just before SIGTERM (the worker has not seen it): at the stop the row keeps `aborted` and gains its final cost and the mark. (B11, B4, r5 item 2)"""
    child, marks = _spending(world, _SPEND, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, renewal_interval=60.0, cost_interval=60.0,
                                              takeover_interval=60.0).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            await store.cancel_investigation(T1, inv, actor="u-1")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            (marks / "go-0").touch()
            await _stop_all(serving)
    final = row(dsn, inv)
    assert (final["stage"], final["failure_reason"], final["cost_usd"]) == ("aborted", "cancelled", pytest.approx(SONNET_IN))
    assert accounting_written(dsn, inv) is not None


@pytest.mark.parametrize("fails", [1, 10**6])
async def test_b11_a_pending_end_write_gets_one_try_during_the_stop_then_the_stop_gives_up_on_it(world, fails):
    """The child ended by itself and its finish is being retried when SIGTERM lands: the stop tries it once more and returns promptly; it lands if the database is back, else the row stays `running` for its lease to lapse. (B11, B5, r5 item 3)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn, lease=1.0) as store:
        bad = await _queued(store)
        used = _StoreWhoseFinishFails(store, bad, ConnectionError("the database is gone"), fails=fails)
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: used.tries(bad), "the first failed end write")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=10)
        finally:
            await _stop_all(serving)
        tries = len(used.tries(bad))
        assert tries <= 3, f"the stop kept retrying a failing write: {tries} tries"
        if fails == 1:
            assert row(dsn, bad)["stage"] == "completed"
        else:
            assert row(dsn, bad)["stage"] == "running"
            await _until(lambda: _lapsed(dsn, bad), "the abandoned row's lease to lapse", timeout=5)
        assert len(used.tries(bad)) == tries, "the write was tried after the stop returned"


async def test_b11_a_redeploy_mid_run_hands_the_row_back_and_another_worker_runs_attempt_2(world):
    """A stops with its child mid-run; B, started afterwards, takes the row over within seconds and runs attempt 2 to `completed`; attempt 1 is `failed`/`lease_lapsed` with the cost it reached. (B11, B6, B7)"""
    child, marks = _spending(world, _SPEND, files=_committed(), term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store_a, job_store(dsn) as store_b:
        inv = await _queued(store_a)
        a = asyncio.create_task(_worker(world, store_a, child, **_FAST).serve())
        b = None
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            assert not a.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(a, timeout=60)
            (marks / "go-0").touch()
            b = asyncio.create_task(_worker(world, store_b, child, **_FAST).serve())
            await _until(lambda: row(dsn, inv)["failure_reason"] == "lease_lapsed", "B to take the row over", timeout=10)
            await _until(lambda: execute(dsn, "SELECT stage FROM jobs.investigations WHERE request_key = 'k1' "
                                               "AND attempt = 2") == [("completed",)], "attempt 2 to complete", timeout=30)
        finally:
            (marks / "go-0").touch()
            await _stop_all(*(t for t in (a, b) if t is not None))
    old = row(dsn, inv)
    assert (old["stage"], old["failure_reason"], old["cost_usd"]) == ("failed", "lease_lapsed", pytest.approx(SONNET_IN))


# --- repair round: renewal errors, the stop's one try, a real outage, take-over survival, spawn fence --------

class _StoreWhoseEndWritesReachNobody:
    """The real store, except that while `down` its `finish` goes to a second store whose database address is a closed port: the driver's own refusal, not an exception the test builds. Notes each try and what it raised."""

    def __init__(self, store, unreachable) -> None:
        self._store, self._dead, self.down = store, unreachable, False
        self.tries, self.errors = 0, []

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def finish(self, *args, **kw):
        self.tries += 1
        try:
            return await (self._dead if self.down else self._store).finish(*args, **kw)
        except Exception as fault:
            self.errors.append(fault)
            raise


def _closed_port_dsn(dsn: str) -> str:
    import socket
    from urllib.parse import urlsplit

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]  # closed again when the probe is: nothing listens there
    parts = urlsplit(dsn)
    userinfo = parts.netloc.rpartition("@")[0]
    return parts._replace(netloc=f"{userinfo + '@' if userinfo else ''}127.0.0.1:{port}").geturl()


async def test_b5_r5_13_an_end_write_to_a_database_that_does_not_answer_is_retried_until_it_lands(world):
    """The end write reaches a closed port (a real refusal): retried each second, claims blocked, then it lands once the database answers. (B5, r5 item 13)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as inner, job_store(_closed_port_dsn(dsn)) as unreachable:
        used = _StoreWhoseEndWritesReachNobody(inner, unreachable)
        used.down = True
        inv = await _queued(inner, ticket="T-1", key="k1")
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: bool(used.errors), "the first failed end write", timeout=20)
            later = await _queued(inner, ticket="T-2", key="k2")
            await _until(lambda: used.tries >= 3, "the end write to be tried again and again", timeout=20)
            assert used.errors, "premise: the unreachable database raised nothing"
            assert row(dsn, inv)["stage"] == "running"
            assert row(dsn, later)["stage"] == "queued", "a row was claimed while the end write was failing"
            used.down = False
            await _until(lambda: row(dsn, inv)["stage"] == "completed", "the end write to land", timeout=10)
            await _until(lambda: row(dsn, later)["stage"] == "completed", "the waiting row to run", timeout=15)
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


async def test_b5_t2_a_renewal_that_errors_fences_nothing_claims_nothing_and_the_next_tick_recovers(world):
    """The store is down about a second under a running child with a row queued: the child is not ended, the row stays `running` unmarked, the queued row is not claimed; once up the lease is renewed and the queued row runs. (r5 item 14, B5)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as inner:
        store = _StoreOutage(inner)
        inv = await _queued(inner)
        serving = asyncio.create_task(_worker(world, store, child, slots=2, **_FAST).serve())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            store.down = True
            await _until(lambda: store.refused, "a renewal to be refused")
            later = await _queued(inner, ticket="T-2", key="k2")
            await asyncio.sleep(1.0)
            assert len(store.refused) >= 2, "premise: renewals were not failing tick after tick"
            assert not _termed(world, inv), "a renewal that errored ended the child"
            assert row(dsn, inv)["stage"] == "running"
            assert accounting_written(dsn, inv) is None
            assert row(dsn, later)["stage"] == "queued", "a row was claimed while renewals were failing"
            down_left = lease_left(dsn, inv)
            store.down = False
            await _until(lambda: lease_left(dsn, inv) > down_left + 0.5, "the next tick to renew the lease")
            await _until(lambda: child.seen(later), "the queued row to run")
            assert not _termed(world, inv)
            release.touch()
            await _until(lambda: row(dsn, inv)["stage"] == "completed", "the first row to complete", timeout=15)
            await _until(lambda: row(dsn, later)["stage"] == "completed", "the second row to complete", timeout=15)
        finally:
            release.touch()
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


async def test_b11_a_hand_back_that_errors_gets_one_try_and_the_stop_returns_promptly_the_lease_lapsing_on_its_own(world):
    """SIGTERM with the store down and a child running: `serve()` returns promptly, the hand-back is tried once, the row stays `running` unmarked and its lease lapses by itself. (B11, r5 item 3)"""
    release = world["tmp"] / "release"  # never touched: the child is still running when the stop lands
    child = _child(world, files=_committed(), wait_for=release, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn, lease=3.0) as inner:
        store = _StoreOutage(inner)
        inv = await _queued(inner)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: child.seen(inv), "the child to start")
            store.down = True
            await _until(lambda: store.refused, "a renewal to be refused")
            periodic, before = set(store.refused), len(store.refused)
            began = time.monotonic()
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=15)
            assert time.monotonic() - began < 10, "the stop waited on writes that were failing"
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await _stop_all(serving)
        hand_back = [name for name in store.refused[before:] if name not in periodic]
        assert len(hand_back) == 1, f"the hand-back was tried {len(hand_back)} times, not once: {hand_back} (renewals {sorted(periodic)} excluded)"
        assert _termed(world, inv)
        assert row(dsn, inv)["stage"] == "running"
        assert accounting_written(dsn, inv) is None
        await _until(lambda: _lapsed(dsn, inv), "the abandoned row's lease to lapse", timeout=6)


class _StoreWhoseTakeOverFailsOnce:
    def __init__(self, store, fault: Exception) -> None:
        self._store, self._fault, self.raised = store, fault, False

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def take_over(self, **kw):
        if not self.raised:
            self.raised = True
            raise self._fault
        return await self._store.take_over(**kw)


@pytest.mark.parametrize("fault", [ConnectionError("the database is gone"), _NobodyPlannedThis("a bug")], ids=["outage", "bug"])
async def test_b7_the_take_over_task_survives_a_pass_that_raised(world, fault):
    """CONFLICT-UPDATED (#1343 review; an outage now holds take-over back for one lease, so the lease here is short): one take-over pass raises; a row that lapses afterwards is still taken over (`lease_lapsed`) by the same worker. (B7)"""
    dsn = world["dsn"]
    async with job_store(dsn, lease=1.0) as inner:
        used = _StoreWhoseTakeOverFailsOnce(inner, fault)
        alert_id = (await an_alert(inner, T1, ticket="T-9")).alert_id
        serving = asyncio.create_task(_worker(world, used, _child(world, files=_committed()), **_FAST).serve())
        try:
            await _until(lambda: used.raised, "the first take-over pass to raise")
            stranger = _plant_running_lapsed(dsn, alert_id)
            await _until(lambda: row(dsn, stranger)["failure_reason"] == "lease_lapsed",
                         "the later lapsed row to be taken over", timeout=10)
            assert not serving.done(), "a raised take-over pass ended the worker"
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


async def test_b3_a_fence_landing_while_the_spawn_is_prepared_ends_the_child_as_soon_as_it_exists(world):
    """The row is deleted inside `child_argv`, after the worker's last look before the spawn: the child that then exists is ended by the next renewal, not left to run. (B3, r5 item 5)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="mark", term_mark=_term_mark(world))
    pidfile = world["tmp"] / "child.pid"
    dsn = world["dsn"]

    def argv(launch):
        execute(dsn, "DELETE FROM jobs.investigations WHERE id = %s", (launch.investigation_id,))
        return ["sh", "-c", 'echo $$ > "$0"; exec "$@"', str(pidfile), *child(launch)]

    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, argv, **_FAST).serve())
        pid = None
        try:
            # `>` creates the file before `echo` writes it: wait for the pid itself, one short write, not the name.
            await _until(lambda: pidfile.exists() and pidfile.read_text().strip(), "the child to be spawned")
            pid = int(pidfile.read_text())
            await _until(lambda: _gone(pid), "the fenced row's child to be ended", timeout=10)
        finally:
            release.touch()
            if pid is not None and not _gone(pid):
                os.kill(pid, signal.SIGKILL)
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert row(dsn, inv) is None


# --- repair round: what a stop does with a child that failed ------------------------------------------------

_FAILING_RECORD = job_end(setup="crashed", box="not_started", report_committed=False, scrub_verified=False)


_CUT_SHORT_RECORD = job_end(report_committed=False, cut_short="box-lost")


@pytest.mark.parametrize("record", [_FAILING_RECORD, "{not json", _CUT_SHORT_RECORD],
                         ids=["failing-record", "unparseable-record", "box-lost-record"])
async def test_b11_a_child_that_writes_a_failing_ending_as_the_stop_lands_is_handed_back_with_its_cost_not_failed(world, record):
    """The signal makes the child leave a failing or unparseable job-end and exit: the row is handed back (still `running`, lapsed, cost, marked) and its retry is a new row. (B11, r5 R1)"""
    child, marks = _spending(world, _SPEND, files={"{id}.job-end.json": record}, term="finish", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            (marks / "go-0").touch()
            await _stop_all(serving)
        assert _termed(world, inv), "premise: the stop signalled the child"
        _handed_back(dsn, inv, cost=SONNET_IN)
        await store.take_over(held=frozenset())
        retry = await store.claim()
    assert retry is not None, "the handed-back run was not retried"
    assert retry.record.attempt == 2


async def test_b11_a_child_that_failed_on_its_own_before_the_stop_signalled_it_ends_failed_and_is_not_retried(world):
    """The child exits 7 by itself, its end write is pending when SIGTERM lands: the stop's one try lands it `failed`/`no_report` with the mark; no retry exists. (B11, r5 item 3 'otherwise B4')"""
    child = _child(world, files={"{id}.job-end.json": _FAILING_RECORD}, exit=7, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        used = _StoreWhoseFinishFails(store, inv, ConnectionError("the database is gone"), fails=1)
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: used.tries(inv), "the first failed end write")
            assert not serving.done()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=15)
        finally:
            await _stop_all(serving)
        assert not _termed(world, inv), "premise: the child had already exited when the stop came"
        final = row(dsn, inv)
        assert (final["stage"], final["failure_reason"]) == ("failed", "no_report")
        assert accounting_written(dsn, inv) is not None
        await store.take_over(held=frozenset())
        assert await store.claim() is None, "a run that failed by itself was retried"
    assert execute(dsn, "SELECT count(*) FROM jobs.investigations WHERE request_key = 'k1'") == [(1,)]


# --- repair round (attack): a stop or a fence before the child exists; what a stopped child's row ends with; the stop's bound ---

def _cancel_in_sql(dsn: str, inv: str) -> None:
    """What `cancel_investigation` writes, by SQL (a thread cannot await the store)."""
    execute(dsn, "UPDATE jobs.investigations SET stage = 'aborted', failure_reason = 'cancelled', finished_at = now() "
                 "WHERE id = %s AND stage IN ('queued', 'running')", (inv,))


class _Landing:
    """An event (a deliberate stop, or the row's cancel seen by a renewal) that the test lands at a chosen point, from the worker's thread (`thread`) or from inside the spawn (`spawn`)."""

    def __init__(self, event: str, dsn: str, store: FaultableStore, inv: str) -> None:
        self.event, self.dsn, self.store, self.inv = event, dsn, store, inv

    def thread(self) -> None:
        if self.event == "stop":
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.5)  # the idle loop acts on it meanwhile
        else:
            _cancel_in_sql(self.dsn, self.inv)
            assert self.store.omitted_event.wait(10), "premise: the worker never saw the fence"

    async def spawn(self) -> None:
        if self.event == "stop":
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(0.5)
        else:
            _cancel_in_sql(self.dsn, self.inv)
            await _until(self.store.omitted_event.is_set, "the worker to see the fence", timeout=10)


@pytest.mark.parametrize("moment", ["during write_launch", "after write_launch", "inside the spawn"])
@pytest.mark.parametrize("event", ["stop", "fence"])
async def test_b3_b11_a_stop_or_fence_between_the_claim_and_the_childs_existence_hands_back_or_ends_the_row_and_leaves_no_child(
        world, event, moment):
    """A stop lands: the row is handed back (cost 0, no knowledge). A fence lands: final accounting, cost 0, no knowledge. Landed before the spawn: it never happens; else the spawned child is gone within 1 s of the spawn returning. (B3, B11, r4 item 4, r5 item 5)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    spawned: list[int] = []
    real_spawn = asyncio.create_subprocess_exec
    landing: list[_Landing] = []

    async def spawn(*argv, **kw):
        if moment == "inside the spawn":
            await landing[0].spawn()
        proc = await real_spawn(*argv, **kw)
        spawned.append(proc.pid)
        return proc

    lanes = LaneLanding(lambda: landing[0].thread(), "during" if moment == "during write_launch" else "after")
    async with job_store(dsn) as inner:
        store = FaultableStore(inner)
        inv = await _queued(inner)
        landing.append(_Landing(event, dsn, store, inv))
        serving = asyncio.create_task(_worker(world, store, child, open_lane=None if moment == "inside the spawn" else lanes,
                                              spawn=spawn, **_FAST).serve())
        try:
            if event == "stop":
                await asyncio.wait_for(asyncio.shield(serving), timeout=60)
            else:
                await _until(lambda: accounting_written(dsn, inv) is not None, "the fenced row's final accounting", timeout=30)
            if moment == "inside the spawn":
                assert len(spawned) == 1, "premise: the spawn was not reached"
                await _until(lambda: _gone(spawned[0]), "the child that was spawned as the event landed to be gone", timeout=1.0)
            else:
                assert lanes.landed, "premise: the event never landed"
                assert spawned == [], "a child was spawned after the event had landed"
                assert child.seen() is None
        finally:
            release.touch()
            for pid in spawned:
                if not _gone(pid):
                    os.killpg(pid, signal.SIGKILL)
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)

    if event == "stop":
        _handed_back(dsn, inv, cost=0, knowledge=None)
    else:
        final = row(dsn, inv)
        assert (final["stage"], final["failure_reason"], final["cost_usd"], final["knowledge"]) == ("aborted", "cancelled", 0, None)
        assert accounting_written(dsn, inv) is not None


def _stopped_endings() -> dict[str, str]:
    """One case of `CASES` per ending the reader can give (stage, reason, disposition), and an unparseable one whose fault is in reading the report and a failed one that read its knowledge."""
    first: dict[tuple, str] = {}
    for name, plan in CASES.items():
        first.setdefault(tuple(plan["expect"]), name)
    return {name: name for name in [*first.values(), "4-report-not-utf8", "5-tree-not-verified"]}


@pytest.mark.parametrize("case", list(_stopped_endings()))
async def test_b11_a_stopped_childs_row_is_finished_when_the_reader_says_completed_else_handed_back_with_what_the_reader_read(world, case):
    """CONFLICT-UPDATED (#1343 review; was: only completed stands): the run is left alone once, and stopped once: an ending the run's own record decided (completed, unparseable, setup_refused) ends as it did alone, any other is handed back with the cost and knowledge the reader gave alone. (B11, r5 item 3, R1)"""
    plan = CASES[case]
    dsn = world["dsn"]
    alone, alone_marks = _spending(world, _SPEND, released=True, exit=plan["exit"], **plan["spec"])
    async with job_store(dsn) as store:
        control = await _queued(store, ticket="T-1", key="k1")
        await _worker(world, store, alone, **_FAST).drain()
        ended = row(dsn, control)
        assert ended["cost_usd"] == pytest.approx(SONNET_IN), "premise: the run alone read no cost"
        if "{id}.knowledge-source.json" in plan["spec"].get("files", {}):
            assert ended["knowledge"] is not None, "premise: the run alone read no knowledge"
        stopped, marks = _spending(world, _SPEND, marks_name="marks-stopped", term="finish", term_mark=_term_mark(world),
                                   **plan["spec"])
        inv = await _queued(store, ticket="T-2", key="k2")
        serving = asyncio.create_task(_worker(world, store, stopped, **_FAST).serve())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            (marks / "go-0").touch()
            await _stop_all(serving)
    assert _termed(world, inv), "premise: the stop signalled the child"
    if plan["expect"][0] in ("completed", "unparseable") or plan["expect"][1] == "setup_refused":
        got, want = row(dsn, inv), ended
        assert {k: got[k] for k in ("stage", "disposition", "failure_reason", "cost_usd", "knowledge")} == {
            k: want[k] for k in ("stage", "disposition", "failure_reason", "cost_usd", "knowledge")}
        assert lower_limit(dsn, inv) is lower_limit(dsn, control), "the stopped run's mark differs from the run alone"
        assert accounting_written(dsn, inv) is not None
    else:
        _handed_back(dsn, inv, cost=ended["cost_usd"], knowledge=ended["knowledge"], at_least=lower_limit(dsn, control))


async def test_b11_a_stop_is_bounded_by_one_stop_grace_however_many_children_ignore_sigterm(world):
    """Three children ignore SIGTERM: the stop returns in about one stop grace (under two, not three), every child gone, every row handed back. (R3 the stop timeout rests on one grace; B11)"""
    grace = 1.5
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="ignore")
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        invs = [await _queued(store, ticket=f"T-{n}", key=f"k{n}") for n in range(3)]
        serving = asyncio.create_task(_worker(world, store, child, slots=3, stop_grace=grace, **_FAST).serve())
        try:
            await _until(lambda: all(child.seen(i) for i in invs), "all three children")
            began = time.monotonic()
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
            took = time.monotonic() - began
        finally:
            release.touch()
            for i in invs:
                _kill_whatever_remains(child.seen(i))
            await _stop_all(serving)
    assert took < 2 * grace, f"the stop took {took:.1f} s for children each given {grace} s"
    for i in invs:
        assert _gone(child.seen(i)["pid"]), "a stop handed a row back but left its child running"
        _handed_back(dsn, i)


class _SlowSecondHandBack:
    """The real store, except that every hand-back after the first waits `delay` first, so take-over passes run between them."""

    def __init__(self, store, delay: float) -> None:
        self._store, self._delay = store, delay
        self.handed: list[str] = []

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def hand_back(self, tenant_id, investigation_id, **kw):
        if self.handed:
            await asyncio.sleep(self._delay)
        self.handed.append(investigation_id)
        return await self._store.hand_back(tenant_id, investigation_id, **kw)


async def test_b11_a_stopping_worker_takes_none_of_its_own_handed_back_rows_over(world, caplog):
    """A stop hands two rows back with many take-over intervals between the two hand-backs: the stopping worker takes over neither (it stops taking over when its stop begins; other workers' passes retry them), so both stay handed back. (B11, B7)"""
    caplog.set_level(logging.INFO, logger="defender.jobs.audit")
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as inner:
        store = _SlowSecondHandBack(inner, delay=20 * _FAST["takeover_interval"])
        invs = [await _queued(inner, ticket=f"T-{n}", key=f"k{n}") for n in range(2)]
        serving = asyncio.create_task(_worker(world, store, child, slots=2, **_FAST).serve())
        try:
            await _until(lambda: all(child.seen(i) for i in invs), "both children")
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            release.touch()
            for i in invs:
                _kill_whatever_remains(child.seen(i))
            await _stop_all(serving)
    assert sorted(store.handed) == sorted(invs), f"premise: both rows were handed back: {store.handed}"
    taken = [r.getMessage() for r in caplog.records if "investigation.takeover" in r.getMessage()]
    assert not taken, f"the stopping worker took a row over: {taken}"
    for i in invs:
        _handed_back(dsn, i)


# --- #1343 review: a second cancel while stopping, and a renewal that races a row's own end ---------------------

async def test_b11_a_second_cancel_while_the_worker_stops_kills_every_child_at_once_and_leaves_none_behind(world):
    """Cancelled once, the worker stops as a deliberate stop does and waits out the grace for a child that ignores SIGTERM; cancelled again during that wait, it kills the child's group at once and leaves, cancelled, well inside the grace. (#1343 review, r5 item 3)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="ignore")
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        containers = StandInContainers(world["tmp"] / "containers-second-cancel")
        draining = asyncio.create_task(_worker(world, store, child, stop_grace=30, containers=containers, **_FAST).drain())
        try:
            await _until(lambda: child.seen(inv), "the child")
            pid = child.seen(inv)["pid"]
            draining.cancel()
            await asyncio.sleep(0.5)
            assert not draining.done(), "premise: the first cancel waits out the grace"
            assert not _gone(pid), "premise: the child ignored SIGTERM"
            began = time.monotonic()
            draining.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(draining, timeout=10)
            took = time.monotonic() - began
            assert containers.swept, "the worker left before its row's cleanup ran"
            await _until(lambda: _gone(pid), "the child to die after the second cancel", timeout=5)
        finally:
            release.touch()
            _kill_whatever_remains(child.seen(inv))
            await _stop_all(draining)
    assert took < 5, f"the second cancel took {took:.1f} s to leave"


async def test_d_ac_a_cancel_while_the_childs_group_is_waited_for_still_removes_its_box(world):
    """The row's cleanup waits for the child's killed group to be gone, then removes the box: a second cancel landing in that wait still removes the box (the removal runs however the wait ends). (D-ac, #1343 review r5 item 3)"""
    import threading

    from defender.execution import wait_group_gone

    in_wait = threading.Event()

    def slow_wait(pgid: int) -> bool:
        in_wait.set()
        time.sleep(3.0)
        return wait_group_gone(pgid)

    child = _child(world, files=_committed())
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        swept: list[str] = []

        class _Recording(StandInContainers):
            def remove_claimed(self, claim: str) -> None:
                swept.append(claim)
                super().remove_claimed(claim)

        containers = _Recording(world["tmp"] / "containers-cancel-in-wait")
        draining = asyncio.create_task(
            _worker(world, store, child, containers=containers, wait_group=slow_wait, **_FAST).drain())
        try:
            await _until(in_wait.is_set, "the row's cleanup to wait for the child's group")
            draining.cancel()
            await asyncio.sleep(0.2)
            draining.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(draining, timeout=10)
        finally:
            _kill_whatever_remains(child.seen(inv))
            await _stop_all(draining)
    assert swept, "a cancel in the group wait skipped the sweep of the child's boxes"


async def test_b11_a_group_whose_wait_ran_out_is_not_waited_for_again_by_the_rows_cleanup(world):
    """A child ignores SIGTERM and its killed group never empties: the stop waits for it once (the limit, logged), and the row's own cleanup kills it again without a second wait, so a stop stays one grace plus one limit. (R3, B11)"""
    waited: list[int] = []

    def never_gone(pgid: int) -> bool:
        waited.append(pgid)
        return False

    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="ignore")
    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        serving = asyncio.create_task(_worker(world, store, child, stop_grace=0.5, wait_group=never_gone, **_FAST).serve())
        try:
            await _until(lambda: child.seen(inv), "the child")
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            release.touch()
            _kill_whatever_remains(child.seen(inv))
            await _stop_all(serving)
    assert waited == [child.seen(inv)["pid"]], f"the group was waited for {len(waited)} times: {waited}"


class _RenewalRacingAnEnd:
    """The real store, except that the first renewal covering `inv` answers only after that row's finish
    committed, and its answer omits the row: a renewal whose snapshot of the held rows predates the row's own end."""

    def __init__(self, store, inv: str) -> None:
        self._store, self._inv = store, inv
        self._finished = asyncio.Event()
        self.raced = False

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def finish(self, tenant_id, investigation_id, **kw):
        got = await self._store.finish(tenant_id, investigation_id, **kw)
        if investigation_id == self._inv:
            self._finished.set()
        return got

    async def renew(self, held, **kw):
        covered = await self._store.renew(held, **kw)
        if self._inv in held and not self.raced:
            await asyncio.wait_for(self._finished.wait(), timeout=20)
            self.raced = True
            return [i for i in covered if i != self._inv]
        return covered


async def test_b3_a_renewal_that_misses_a_row_which_ended_on_its_own_meanwhile_fences_nothing_and_says_nothing_of_a_cancel(world, caplog):
    """The row's own finish commits while a renewal that snapshotted it is in flight; the renewal's answer omits it. That is the row's own end, not a cancel or take-over: nothing is fenced and no such warning is logged. (#1343 review, B3)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        used = _RenewalRacingAnEnd(store, inv)
        serving = asyncio.create_task(_worker(world, used, child, **_FAST).serve())
        try:
            await _until(lambda: child.seen(inv), "the child")
            await asyncio.sleep(0.5)  # a renewal snapshots the row while its child runs, and waits
            release.touch()
            await _until(lambda: used.raced, "the racing renewal to answer", timeout=30)
            await asyncio.sleep(0.5)  # the answer is acted on
        finally:
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert row(dsn, inv)["stage"] == "completed"
    assert not [r for r in caplog.records if r.name.startswith(WORKER_LOGGER) and inv in r.getMessage()
                and "cancelled, taken over or deleted" in r.getMessage()], "a row that ended on its own was fenced"


# --- #1343 review: a worker's own count of its leases, and faults that decide nothing about the job --------------

class _TakeOverOutage:
    """The real store, except that the first take-over pass raises a connection error, and every pass is timed."""

    def __init__(self, store) -> None:
        self._store = store
        self.passes: list[float] = []

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def take_over(self, **kw):
        self.passes.append(time.monotonic())
        if len(self.passes) == 1:
            raise ConnectionError("the database is gone")
        return await self._store.take_over(**kw)


async def test_b7_a_worker_whose_store_calls_hit_an_outage_takes_nothing_over_for_one_lease(world):
    """Other workers' leases lapsed in the same outage and their renewals have not had their chance: after a take-over pass hits an outage, the next pass waits a full lease, then passes resume. (#1343 review, B7)"""
    lease = 2.0
    async with job_store(world["dsn"], lease=lease) as inner:
        store = _TakeOverOutage(inner)
        serving = asyncio.create_task(_worker(world, store, _child(world), **_FAST).serve())
        try:
            await _until(lambda: len(store.passes) >= 3, "take-over passes to resume", timeout=20)
        finally:
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
    assert store.passes[1] - store.passes[0] >= lease, f"the next pass came {store.passes[1] - store.passes[0]:.2f} s after the outage"
    assert store.passes[2] - store.passes[1] < lease, "passes did not resume at their own cadence"


async def test_b1_t2_a_worker_cut_off_past_the_lease_keeps_its_child_and_the_next_renewal_revives_the_row(world):
    """CONFLICT-UPDATED: renewals fail for longer than the lease: the child is not told to stop and the row is not handed back, so an outage uses no attempt; when the store answers, the late renewal covers the row (nobody took it over) and the run ends as its own. (T2, r5 item 14, B1)"""
    lease = 2.0
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn, lease=lease) as inner:
        store = FaultableStore(inner)
        inv = await _queued(inner)
        serving = asyncio.create_task(_worker(world, store, child, **_FAST).serve())
        try:
            await _until(lambda: child.seen(inv), "the child")
            store.renew_down = True
            await _until(lambda: lease_left(dsn, inv) < -0.5, "the lease to lapse with renewals failing", timeout=15)
            assert not _termed(world, inv), "a lapsed lease stopped the child"
            assert not _gone(child.seen(inv)["pid"]), "a lapsed lease ended the child"
            assert accounting_written(dsn, inv) is None, "the row was handed back"
            store.renew_down = False
            await _until(lambda: lease_left(dsn, inv) > 0, "the late renewal to land")
            release.touch()
            await _until(lambda: row(dsn, inv)["stage"] == "completed", "the run to complete", timeout=15)
            assert not _termed(world, inv), "the child was stopped after the store came back"
        finally:
            release.touch()
            _kill_whatever_remains(child.seen(inv))
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


class _RenewalThatHangs:
    """The real store, except that once `hang` is set a renewal never answers. Counts the calls that hung."""

    def __init__(self, store) -> None:
        self._store = store
        self.hang = False
        self.hung = 0

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def renew(self, held, **kw):
        if self.hang:
            self.hung += 1
            await asyncio.Event().wait()
        return await self._store.renew(held, **kw)


async def test_b1_t2_a_renewal_that_hangs_counts_as_failed_so_claims_wait_and_the_child_keeps_running(world):
    """CONFLICT-UPDATED: one store call that never answers fails at `store_call_limit`, so nothing new is claimed and the next renewal is tried; the child carries on past the lease, and when renewals answer again the queued row runs. (T2, B1, B5)"""
    lease = 2.0
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release, term="mark", term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn, lease=lease) as inner:
        store = _RenewalThatHangs(inner)
        inv = await _queued(inner, ticket="T-1", key="k1")
        serving = asyncio.create_task(_worker(world, store, child, store_call_limit=0.3, **_FAST).serve())
        try:
            await _until(lambda: child.seen(inv), "the child")
            store.hang = True
            await _until(lambda: store.hung >= 2, "a hung renewal to fail and the next to be tried", timeout=10)
            later = await _queued(inner, ticket="T-2", key="k2")
            await _until(lambda: lease_left(dsn, inv) < -0.5, "the lease to lapse with renewals hanging", timeout=15)
            assert not _termed(world, inv), "a lapsed lease stopped the child"
            assert row(dsn, later)["stage"] == "queued", "a row was claimed while renewals were failing"
            store.hang = False
            await _until(lambda: child.seen(later), "the queued row to run once renewals answer", timeout=15)
            assert not _termed(world, inv), "the child was stopped after the store came back"
        finally:
            release.touch()
            _kill_whatever_remains(child.seen(inv))
            store.hang = False
            if not serving.done():
                os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)


async def test_b5_an_outage_reading_the_alert_at_launch_hands_the_row_back_with_nothing_spent(world):
    """A store outage before the child exists is nothing the job did: no terminal ending, no child, cost 0; the row is handed back and retried. (#1343 review, B5, B11)"""
    child = _child(world, files=_committed())
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        alert_id = (await store.get_investigation(T1, inv)).alert_id
        await _worker(world, _StoreWhoseAlertReadFails(store, alert_id, ConnectionError("the database is gone")), child, **_FAST).drain()
    _handed_back(dsn, inv, cost=0, knowledge=None, at_least=False)
    assert child.seen(inv) is None


class _CostReads:
    """Wraps a lane door and counts the lanes' `cost` calls: a run whose premise is "no live figure was read" proves it."""

    def __init__(self, lanes) -> None:
        self._lanes, self.reads = lanes, 0

    def __call__(self, root, tenant):
        outer, lane = self, self._lanes(root, tenant)

        class _Counting:
            def __getattr__(self, name):
                real = getattr(lane, name)
                if name != "cost":
                    return real

                def cost(*a, **k):
                    outer.reads += 1
                    return real(*a, **k)
                return cost

            def __enter__(self):
                return self

            def __exit__(self, *_exc) -> None:
                lane.close()
        return _Counting()


_NO_TICK = {**_FAST, "cost_interval": 60.0}  # the cost tick never fires inside the test: no live figure is ever read


async def test_b11_a_fault_reading_a_stopped_runs_ending_still_hands_the_row_back(world):
    """A stop signalled the child and reading its records then raises something nobody planned for: the stop cut the run short, so the row is handed back (cost unknown: no live figure was read), never failed `worker_error`. (#1343 review, B11; r6 S2/S4)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        lanes = _CostReads(_lanes_failing(inv, "read_job_end", _NobodyPlannedThis("x")))
        serving = asyncio.create_task(_worker(world, store, child, open_lane=lanes, **_NO_TICK).serve())
        try:
            await _until(lambda: child.seen(inv), "the child")
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)
        finally:
            release.touch()
            _kill_whatever_remains(child.seen(inv))
            await _stop_all(serving)
    assert lanes.reads == 0, "premise: no live cost read happened"
    _handed_back(dsn, inv, unknown_cost=True)  # a child ran but no live figure was read: unknown, not "at least 0" (r6 S2/S4)


async def test_s2_an_outage_reading_a_finished_childs_records_hands_the_row_back_with_its_live_copy_marked(world):
    """A child ran and its ending then cannot be read for an outage: the row is handed back with the cost so far it had copied, as a lower limit; the copy may be short. (S2)"""
    release = world["tmp"] / "release"
    child, marks = _spending(world, _SPEND, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        lanes = _lanes_failing(inv, "read_job_end", ConnectionError("the volume is gone"))
        drained = asyncio.create_task(_worker(world, store, child, open_lane=lanes, **_FAST).drain())
        try:
            await _until(lambda: row(dsn, inv)["cost_usd"] == pytest.approx(SONNET_IN), "the live copy", timeout=10)
        finally:
            (marks / "go-0").touch()
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    _handed_back(dsn, inv, cost=SONNET_IN, at_least=True)


async def test_s4_an_outage_reading_a_finished_childs_records_before_any_live_figure_hands_the_row_back_unknown(world):
    """A child ran, spent nothing the worker copied, and its ending cannot be read for an outage: the row is handed back with a NULL cost and no mark. (r6 S2/S4)"""
    release = world["tmp"] / "release"
    child = _child(world, files=_committed(), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        lanes = _CostReads(_lanes_failing(inv, "read_job_end", ConnectionError("the volume is gone")))
        drained = asyncio.create_task(_worker(world, store, child, open_lane=lanes, **_NO_TICK).drain())
        try:
            await _until(lambda: child.seen(inv), "the child")
        finally:
            release.touch()
            await asyncio.wait_for(drained, timeout=60)
    assert lanes.reads == 0, "premise: no live cost read happened"
    _handed_back(dsn, inv, unknown_cost=True)


@pytest.mark.parametrize(("child_ends", "expect"), [("killed", True), ("with its records", False)])
async def test_s2_a_cancelled_running_row_stays_at_least_until_its_holder_writes_its_own_figure(world, child_ends, expect):
    """The cancelled row reads "at least" at once (derived, not stored); the holder's final write then stores its own value: true after a killed child, false after a clean job-end. (S2, B1)"""
    child, marks = _spending(world, _SPEND, files=_committed(), term="mark" if child_ends == "killed" else "finish",
                             term_mark=_term_mark(world))
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, cost_interval=60.0).drain())
        try:
            await _until(lambda: (marks / "wrote-0").exists(), "the child's spend")
            got = await store.cancel_investigation(T1, inv, actor="u-1")
            assert (got.cost_is_lower_limit, lower_limit(dsn, inv)) == (True, False), (
                "cancel must read at least by derivation and store no mark (B1, B2)")
            assert (await store.get_investigation(T1, inv)).cost_is_lower_limit is True
            await _until(lambda: _termed(world, inv), "the child to get SIGTERM", timeout=3.0)
        finally:
            (marks / "go-0").touch()
            await asyncio.wait_for(drained, timeout=60)

    assert (row(dsn, inv)["stage"], row(dsn, inv)["cost_usd"], lower_limit(dsn, inv)) == (
        "aborted", pytest.approx(SONNET_IN), expect)


@pytest.mark.parametrize("sealed", [True, False], ids=["killed after its seal", "killed before its seal"])
async def test_t2_r7_3_a_child_killed_before_its_job_end_reads_exact_after_its_seal_and_at_least_before_it(world, sealed):
    """A running child's ledger holds its response; it is cancelled (SIGTERM, no job-end left) either after the child sealed or while
    it was still working: the holder's final figure is the ledger's sum, exact after the seal ("every request was recorded") and
    "at least" before it. (r7.3 T2)"""
    release = world["tmp"] / "release"
    child, marks = _spending(world, _SPEND, released=sealed, term="mark", term_mark=_term_mark(world), wait_for=release)
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        inv = await _queued(store)
        drained = asyncio.create_task(_worker(world, store, child, cost_interval=60.0).drain())
        try:
            await _until(lambda: (marks / ("sealed" if sealed else "wrote-0")).exists(), "the child's seal" if sealed else "the child's spend")
            assert not list(marks.glob("seal-failed")), (marks / "seal-failed").read_text(encoding="utf-8")
            await store.cancel_investigation(T1, inv, actor="u-1")
            await _until(lambda: _termed(world, inv), "the child to get SIGTERM", timeout=3.0)
        finally:
            (marks / "go-0").touch()
            release.touch()
            await asyncio.wait_for(drained, timeout=60)

    assert (row(dsn, inv)["stage"], row(dsn, inv)["cost_usd"], lower_limit(dsn, inv)) == (
        "aborted", pytest.approx(SONNET_IN), not sealed)
    assert (marks / "sealed").exists() is sealed, "premise: the child sealed exactly when it was meant to"


class _CallFinishingAsItIsCancelled:
    """The real store, except that a renewal or take-over waits until the test releases it, so it can finish in the very tick its service task is cancelled."""

    def __init__(self, store) -> None:
        self._store = store
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    def __getattr__(self, name):
        return getattr(self._store, name)

    async def _held_up(self) -> list:
        self.entered.set()
        await self.release.wait()
        return []

    async def renew(self, held, **kw):
        return await self._held_up()

    async def take_over(self, **kw):
        return await self._held_up()


@pytest.mark.parametrize("service", ["renewal", "take-over"])
async def test_b11_a_service_cancelled_as_its_store_call_finishes_still_ends_so_a_stop_cannot_hang(world, service):
    """The cancel that ends a service lands in the tick its store call finishes: the service ends all the same. A lost cancel would leave its loop running and the worker's stop waiting forever. (#1343 review, B11)"""
    from types import SimpleNamespace

    from defender.worker._held import Held

    async with job_store(world["dsn"]) as inner:
        store = _CallFinishingAsItIsCancelled(inner)
        worker = _worker(world, store, _child(world))
        worker._held["x"] = Held(SimpleNamespace(investigation_id="x"))
        task = asyncio.create_task(worker._renewal_loop() if service == "renewal" else worker._takeover_loop())
        await asyncio.wait_for(store.entered.wait(), timeout=10)
        store.release.set()
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=5)
        leftover = not done
        if leftover:
            task.cancel()
            await asyncio.wait({task}, timeout=5)
    assert not leftover, f"the {service} service survived its cancel"
    assert task.cancelled()


async def test_1170_the_worker_starts_each_investigation_as_its_tenants_host_helper(world):
    """The worker's default child is the per-job host helper, not the job entry: one spawn per claim, naming the
    helper module, the job's kind, the investigation, its tenant and the worker's pid; the row ends as the child's
    end record says. (#1170 H7, Flow: claim)

    The `spawn` door records the command the worker asked for and starts the scripted child in its place."""
    from defender.worker import Launch, run_argv

    child = _child(world, files=_committed())
    real_spawn = asyncio.create_subprocess_exec
    asked: list[list[str]] = []

    async def as_scripted(*argv, **kw):
        asked.append(list(argv))
        inv = argv[argv.index("--job") + 1]
        return await real_spawn(*child(Launch(inv, T1, os.getpid())), **kw)

    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await _worker(world, store, run_argv, spawn=as_scripted).drain()

    assert asked == [[sys.executable, "-m", "defender.job_host", "--kind", "investigation", "--job", inv,
                      "--tenant", T1, "--parent-pid", str(os.getpid())]]
    assert row(world["dsn"], inv)["stage"] == "completed"


async def test_1170_the_worker_starts_a_learning_job_and_its_post_step_as_their_kinds_host_helper(world):
    """The worker's learning and post-step commands start the per-job host helper: `-m defender.job_host --kind learning`
    with the job, tenant, source run and the worker's pid; `--kind post-step` with the job it follows (none when
    family-less), the tenant and the pid. One spawn each; the rows end as the scripted children's records say. (#1170 H7)

    The flag order is a pick (the exact argv); the `spawn` door records it and starts the scripted child instead."""
    from defender.tests.jobs.test_1344_learning_jobs import (
        END,
        investigation_of,
        job_child,
        job_row,
        learning_end,
        learning_worker,
        post_child,
        queued_job,
    )
    from defender.worker import LearningLaunch, PostStepLaunch, job_entry_argv, post_step_argv

    jobs = job_child(world, files={END: learning_end("completed")})
    post = post_child(world)
    real_spawn = asyncio.create_subprocess_exec
    asked: list[list[str]] = []
    pid = os.getpid()

    async def as_scripted(*argv, **kw):
        asked.append(list(argv))
        rest = list(argv[3:])
        flags = dict(zip(rest[::2], rest[1::2], strict=False))
        kind, job = flags["--kind"], flags["--job"]
        launch = (LearningLaunch(job, T1, pid, flags["--source"]) if kind == "learning"
                  else PostStepLaunch(job, T1, pid, (job,)))
        return await real_spawn(*(jobs if kind == "learning" else post)(launch), **kw)

    async with job_store(world["dsn"]) as store:
        job = await queued_job(world, store, ticket="T-1")
        source = investigation_of(world["dsn"], job)
        await learning_worker(world, store, job=job_entry_argv, post=post_step_argv, spawn=as_scripted).drain()

    base = [sys.executable, "-m", "defender.job_host"]
    assert asked == [
        [*base, "--kind", "learning", "--job", job, "--tenant", T1, "--source", source, "--parent-pid", str(pid)],
        [*base, "--kind", "post-step", "--job", job, "--tenant", T1, "--parent-pid", str(pid)]]
    assert job_row(world["dsn"], job)["status"] == "completed"
    assert post_step_argv(PostStepLaunch(None, T1, pid, ())) == [*base, "--kind", "post-step", "--tenant", T1,
                                                                 "--parent-pid", str(pid)]
    assert job_entry_argv(LearningLaunch(job, T1, pid, "src-1")) == [*base, "--kind", "learning", "--job", job, "--tenant", T1,
                                                                       "--source", "src-1", "--parent-pid", str(pid)]


@pytest.mark.parametrize("copied", [True, False], ids=["code-copy", "control-no-copy"])
async def test_1170_the_worker_spawns_the_helper_in_its_code_copy_and_only_there(world, copied):
    """The helper is started with `cwd` set to the worker's code copy (the `child_cwd` it was given), so it imports the copy and the container mounts it; a worker given no copy sets no `cwd` (control). (#1170 A7, G-D3)"""
    from defender.worker import Launch, run_argv

    copy = world["tmp"] / "code-copy"
    copy.mkdir()
    child = _child(world, files=_committed())
    real_spawn = asyncio.create_subprocess_exec
    cwds: list[str] = []

    async def as_scripted(*argv, **kw):
        cwds.append(kw.get("cwd", "<unset>"))
        inv = argv[argv.index("--job") + 1]
        kw.pop("cwd", None)
        return await real_spawn(*child(Launch(inv, T1, os.getpid())), **kw)

    async with job_store(world["dsn"]) as store:
        inv = await _queued(store)
        await _worker(world, store, run_argv, spawn=as_scripted, **({"child_cwd": copy} if copied else {})).drain()

    assert cwds == [str(copy) if copied else "<unset>"]
    assert row(world["dsn"], inv)["stage"] == "completed", "control: the spawned child ran to its end record"


async def test_1170_the_worker_start_sweeps_the_job_containers_a_dead_helper_left_by_their_label(world):
    """At start the worker removes every container carrying the job-container label (their helper, and the claim tokens
    that named them, died with the previous worker); a tenant's box without that label stays. (#1170 A5)"""
    import signal

    from defender import job_host
    from defender.box import CLAIM_LABEL, TENANT_LABEL
    from defender.tests.support.jobs._job_helper import ContainerStandIn, until
    from defender.worker._containers import DockerContainers

    docker = ContainerStandIn()
    docker.live.update({"job-left-over": {job_host.JOB_LABEL: "1", TENANT_LABEL: T1, CLAIM_LABEL: "a" * 32},
                        "tenant-box": {TENANT_LABEL: T1}})
    async with job_store(world["dsn"]) as store:
        worker = _worker(world, store, _child(world), containers=DockerContainers(docker=docker))
        serving = asyncio.create_task(worker.serve())
        try:
            await asyncio.to_thread(until, lambda: "job-left-over" not in docker.live, "the start sweep", 15.0)
        finally:
            assert not serving.done(), "premise: serve() is still running, so the SIGTERM below is its to handle"
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.wait_for(serving, timeout=60)

    assert "tenant-box" in docker.live, "the sweep took a container that is not a job container"
    assert any(c[1] == "rm" and "job-left-over" in c for c in docker.calls)
