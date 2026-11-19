"""#1581 AP1: the alert's stored outcome always equals O1 computed over its investigations, after every committed write.

Entry: `defender.jobs.JobStore` on a per-test migrated database. The copy is read by SQL (`jobs.alerts.outcome`,
`outcome_investigation_id`, `outcome_created_at`) and through `list_alerts`; the oracle is O1 written out in Python over the
investigation rows (`support/jobs/_outcome1581.py`). Every investigation is made through the store (a SQL plant bypasses
the copy). Interleavings are made by raw connections holding a lock until the operation under test is blocked, as #1339's
helpers do, not by sleeps."""
from __future__ import annotations

import asyncio
import datetime as dt
import random
from typing import Any

import pytest

from defender._vocab import DISPOSITION_VALUES
from defender.tests.support.jobs._jobs1342 import NOW, T1, lapse_lease, register_tenant
from defender.tests.support.jobs._outcome1581 import (
    expected_copy,
    expected_latest_status,
    Reader,
    holding,
    investigations_of,
    stored_copy,
)
from defender.tests.support.shared._pglocks1339 import blocked, until, until_blocked
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

HOUR = dt.timedelta(hours=1)
SEEDS = range(8)
STEPS = 70
WINDOW: dict[str, Any] = {"fired_after": None, "fired_before": None, "outcome": None, "after": None, "limit": 50}


@pytest.fixture
def dsn(migrated_database: str) -> str:
    register_tenant(migrated_database, T1)
    return migrated_database


class Clock:
    def __init__(self) -> None:
        self.at = NOW

    def __call__(self) -> dt.datetime:
        return self.at


async def _store(dsn: str, clock: Clock) -> Any:
    from defender.jobs import JobStore

    return JobStore(dsn, clock=clock)


async def _alert(store: Any, ticket: str, at: dt.datetime = NOW) -> str:
    return (await store.insert_alert(T1, vendor="elastic", vendor_ticket_id=ticket, fired_at=at, changed_at=at,
                                     received_at=at, raw=b"{}")).alert_id


async def _running(store: Any, alert_id: str, key: str) -> str:
    """A new investigation of the alert under `key`, claimed: its id."""
    inv, _ = await store.create_investigation(T1, alert_id, key, actor="setup")
    claimed = await store.claim()
    assert claimed is not None
    assert claimed.record.investigation_id == inv.investigation_id, "premise: the one just made"
    return inv.investigation_id


async def _settled(dsn: str, *tasks: asyncio.Task[Any]) -> None:
    """Wait until each task is done or parked on a lock (as many backends wait as tasks are unfinished): the operations stand
    where the test wants them, or have finished, which an implementation with other lock needs may do."""
    async def condition() -> bool:
        return await blocked(dsn) >= sum(not t.done() for t in tasks)
    await until(condition)


def _agrees(dsn: str | Reader, alert_id: str, where: str) -> None:
    rows = investigations_of(dsn, alert_id)
    assert stored_copy(dsn, alert_id) == expected_copy(rows), where


# --- the three columns follow finish and delete, as the design says (AP1) ------------------------------------------------

async def test_ap1_the_three_columns_follow_a_completed_finish_and_a_delete_and_ignore_other_endings(dsn):
    """`finish(completed)` stores disposition, the investigation's id and `created_at`; other endings and older completions
    leave them; a delete of the source falls back to the next newest completed, the last delete clears all three. (AP1)"""
    clock = Clock()
    store = await _store(dsn, clock)
    try:
        alert_id = await _alert(store, "A-1")
        assert stored_copy(dsn, alert_id) == (None, None, None)
        stamps = []
        made = {}
        for key, stage, disposition in (("k1", "completed", "benign"), ("k2", "failed", None), ("k3", "completed", "malicious"),
                                        ("k4", "aborted", None)):
            stamps.append(clock.at)
            made[key] = await _running(store, alert_id, key)
            await store.finish(T1, made[key], stage=stage, disposition=disposition, cost_usd=0.0,
                               failure_reason=None if stage == "completed" else "worker_error")
            clock.at += HOUR
            if key == "k1":
                assert stored_copy(dsn, alert_id) == ("benign", made["k1"], stamps[0])
            if key == "k2":
                assert stored_copy(dsn, alert_id) == ("benign", made["k1"], stamps[0]), "a failed ending is not an outcome"
            if key == "k3":
                assert stored_copy(dsn, alert_id) == ("malicious", made["k3"], stamps[2]), "the newer completed replaces"
            if key == "k4":
                assert stored_copy(dsn, alert_id) == ("malicious", made["k3"], stamps[2]), "an aborted ending is not one"
        await store.delete_investigation(T1, made["k2"], actor="u-1")
        assert stored_copy(dsn, alert_id) == ("malicious", made["k3"], stamps[2]), "deleting a non-source changes nothing"
        await store.delete_investigation(T1, made["k3"], actor="u-1")
        assert stored_copy(dsn, alert_id) == ("benign", made["k1"], stamps[0]), "the source went: the next newest completed"
        await store.delete_investigation(T1, made["k1"], actor="u-1")
        assert stored_copy(dsn, alert_id) == (None, None, None)
    finally:
        await store.close()


# --- generated sequences of store operations (AP1's guard) -----------------------------------------------------------------

class _Hits(dict):
    def hit(self, name: str) -> None:
        self[name] = self.get(name, 0) + 1


async def _step(dsn: str, read: Reader, store: Any, rng: random.Random, clock: Clock, alerts: list[str], keys: list[int], hits: _Hits) -> None:  # noqa: C901, PLR0912 — one arm per store operation
    from defender.jobs import Conflict, NotFound

    rows = read.rows("SELECT id, alert_id, stage, request_key, attempt FROM jobs.investigations")
    running = [r for r in rows if r[2] == "running"]
    live = [r for r in rows if r[2] in {"queued", "running"}]
    ended = [r for r in rows if r[2] not in {"queued", "running"}]
    if rng.random() < 0.35:
        clock.at += HOUR  # the others leave the clock still: equal `created_at`, ordered by id
    op = rng.choices(["create", "claim", "finish", "cancel", "takeover", "delete", "pair"], [5, 4, 6, 1, 1, 3, 2])[0]
    try:
        if op == "create":
            keys[0] += 1
            await store.create_investigation(T1, rng.choice(alerts), f"k{keys[0]}", actor="gen")
        elif op == "claim":
            await store.claim()
        elif op == "finish" and running:
            inv_id, alert_id, _, _, attempt = rng.choice(running)
            stage = rng.choice(["completed"] * 7 + ["unparseable", "failed", "aborted"])
            if stage == "completed" and expected_copy(investigations_of(read, alert_id))[0] is not None:
                hits.hit("completed over a completed")
            if stage == "completed" and attempt > 1:
                hits.hit("a retry completed")
            await store.finish(T1, inv_id, stage=stage, disposition=rng.choice(DISPOSITION_VALUES) if stage == "completed" else None,
                               cost_usd=0.0, failure_reason=None if stage in {"completed", "unparseable"} else "worker_error")
        elif op == "cancel" and live:
            await store.cancel_investigation(T1, rng.choice(live)[0], actor="gen")
        elif op == "takeover" and running:
            lapse_lease(dsn, rng.choice(running)[0])
            if await store.take_over():
                hits.hit("a take-over")
        elif op == "delete" and ended:
            inv_id, alert_id, _, key, _ = rng.choice(ended)
            doomed = {x[0] for x in rows if x[1] == alert_id and x[3] == key}
            kept = [r for r in investigations_of(read, alert_id) if r[1] == "completed" and r[0] not in doomed]
            source = expected_copy(investigations_of(read, alert_id))[1]
            if source in doomed and kept:
                hits.hit("the source deleted, an older completed remains")
            elif source is not None and source not in doomed:
                hits.hit("a non-source deleted")
            await store.delete_investigation(T1, inv_id, actor="gen")
        elif op == "pair" and running:
            inv_id, alert_id, _, key, _ = rng.choice(running)
            others = [r for r in ended if r[1] == alert_id and r[3] != key]
            if others:
                hits.hit("a finish beside a delete")
                results = await asyncio.gather(
                    store.finish(T1, inv_id, stage="completed", disposition=rng.choice(DISPOSITION_VALUES), cost_usd=0.0),
                    store.delete_investigation(T1, rng.choice(others)[0], actor="gen"), return_exceptions=True)
                for result in results:
                    if isinstance(result, BaseException) and not isinstance(result, Conflict | NotFound):
                        raise result  # a deadlock or any other failure is a failure of the invariant
    except (Conflict, NotFound):
        pass  # a refused operation changes nothing: the invariant still has to hold


async def test_ap1_after_any_sequence_of_store_operations_the_stored_outcome_is_o1_of_the_investigations(dsn):
    """Over seeded random sequences of create, claim, finish in every stage, cancel, take-over, delete and finish-beside-delete
    pairs, after every step each alert's three columns and its listed `outcome` and `latest_status` equal O1 computed from its
    investigations, with no deadlock; the sequences reach the cases the guard exists for. (AP1)"""
    hits = _Hits()
    clock = Clock()
    store = await _store(dsn, clock)
    read = Reader(dsn)
    try:
        for seed in SEEDS:
            rng = random.Random(seed)
            keys = [seed * 1000]
            alerts = [await _alert(store, f"G-{seed}-{n}", NOW - n * HOUR) for n in range(3)]
            for step in range(STEPS):
                await _step(dsn, read, store, rng, clock, alerts, keys, hits)
                for alert_id in alerts:
                    _agrees(read, alert_id, f"seed {seed}, step {step}")
            listed = {a.alert_id: a for a in await store.list_alerts(T1, **WINDOW)}
            for alert_id in alerts:
                rows = investigations_of(read, alert_id)
                assert (listed[alert_id].outcome, listed[alert_id].latest_status) == (
                    expected_copy(rows)[0], expected_latest_status(rows)), f"seed {seed}: the list"
    finally:
        read.close()
        await store.close()
    wanted = {"completed over a completed", "a retry completed", "a take-over", "the source deleted, an older completed remains",
              "a non-source deleted", "a finish beside a delete"}
    assert wanted <= set(hits), f"premise: the sequences never reached {sorted(wanted - set(hits))}"


# --- a finish and a delete of one alert, each commit order, on two real transactions (AP1) -------------------------------

async def _alert_with_source_a_and_b_running(store: Any, clock: Clock) -> tuple[str, str, str]:
    """An alert whose completed investigation A (k1, benign) is the stored source and whose rerun B (k2) is running."""
    alert_id = await _alert(store, "R-1")
    a = await _running(store, alert_id, "k1")
    await store.finish(T1, a, stage="completed", disposition="benign", cost_usd=0.0)
    clock.at += HOUR
    return alert_id, a, await _running(store, alert_id, "k2")


async def test_ap1_a_delete_that_commits_first_and_missed_the_finish_leaves_the_finishs_outcome(dsn):
    """The delete of the source A holds the alert lock and commits (its fallback cannot see B's uncommitted completion) before
    B's finish writes its copy: the outcome is B's. (AP1)"""
    clock = Clock()
    store = await _store(dsn, clock)
    try:
        alert_id, a, b = await _alert_with_source_a_and_b_running(store, clock)
        async with holding(dsn, "SELECT id FROM jobs.learning_jobs WHERE investigation_id = %s FOR UPDATE", (a,)):
            delete = asyncio.ensure_future(store.delete_investigation(T1, a, actor="u-1"))  # parks on A's job, alert lock taken
            await until_blocked(dsn, 1)
            finish = asyncio.ensure_future(store.finish(T1, b, stage="completed", disposition="malicious", cost_usd=0.0))
            await _settled(dsn, delete, finish)
        await asyncio.wait_for(asyncio.gather(delete, finish), timeout=15)
        [(created_b,)] = execute(dsn, "SELECT created_at FROM jobs.investigations WHERE id = %s", (b,))
        assert stored_copy(dsn, alert_id) == ("malicious", b, created_b)
        assert [r[0] for r in investigations_of(dsn, alert_id)] == [b], "premise: A is gone"
    finally:
        await store.close()


async def test_ap1_a_finish_that_commits_first_leaves_a_delete_of_the_old_source_changing_nothing(dsn):
    """B's finish is parked after it began, the delete of the old source A starts and waits for the alert, and B's outcome
    stands once both commit. (AP1)"""
    clock = Clock()
    store = await _store(dsn, clock)
    try:
        alert_id, a, b = await _alert_with_source_a_and_b_running(store, clock)
        other = await _alert(store, "R-2")
        await store.finish(T1, await _running(store, other, "k1"), stage="completed", disposition="benign", cost_usd=0.0)  # arms the check clock row
        async with holding(dsn, "SELECT tenant_id FROM jobs.learning_checks WHERE tenant_id = %s FOR UPDATE", (T1,)):
            finish = asyncio.ensure_future(store.finish(T1, b, stage="completed", disposition="malicious", cost_usd=0.0))
            await until_blocked(dsn, 1)  # parked on the check clock, after its other writes
            delete = asyncio.ensure_future(store.delete_investigation(T1, a, actor="u-1"))
            await _settled(dsn, finish, delete)
        await asyncio.wait_for(asyncio.gather(delete, finish), timeout=15)
        [(created_b,)] = execute(dsn, "SELECT created_at FROM jobs.investigations WHERE id = %s", (b,))
        assert stored_copy(dsn, alert_id) == ("malicious", b, created_b)
        assert [r[0] for r in investigations_of(dsn, alert_id)] == [b], "premise: A is gone"
    finally:
        await store.close()


# --- the lock order: finish beside take-over on a lapsed lease (design, "Lock order") ------------------------------------

async def test_ap1_a_finish_is_not_held_up_by_the_foreign_key_lock_take_over_takes_on_the_alert(dsn):
    """With another transaction holding the alert only `FOR KEY SHARE` (what take-over's retry insert takes) a finish
    completes and stores its copy; with it held `FOR UPDATE` the finish waits (control, so the holder is felt). (AP1, lock order)"""
    clock = Clock()
    store = await _store(dsn, clock)
    try:
        shared, exclusive = await _alert(store, "L-1"), await _alert(store, "L-2", NOW - HOUR)
        first, second = await _running(store, shared, "k1"), await _running(store, exclusive, "k1")
        async with holding(dsn, "SELECT id FROM jobs.alerts WHERE id = %s FOR KEY SHARE", (shared,)):
            done = await asyncio.wait_for(store.finish(T1, first, stage="completed", disposition="benign", cost_usd=0.0), timeout=10)
        assert done is not None
        assert stored_copy(dsn, shared)[:2] == ("benign", first)
        async with holding(dsn, "SELECT id FROM jobs.alerts WHERE id = %s FOR UPDATE", (exclusive,)):
            parked = asyncio.ensure_future(store.finish(T1, second, stage="completed", disposition="benign", cost_usd=0.0))
            await until_blocked(dsn, 1)
        assert await asyncio.wait_for(parked, timeout=10) is not None
        assert stored_copy(dsn, exclusive)[:2] == ("benign", second)
    finally:
        await store.close()


@pytest.mark.parametrize("finish_first", [True, False])
async def test_ap1_a_finish_and_a_take_over_of_one_lapsed_row_never_deadlock_and_leave_one_consistent_state(dsn, finish_first):
    """A running row with a lapsed lease is finished `completed` while take-over passes, each starting first in turn with the
    alert held; neither fails, and the state is the finish's (copy set, no retry) or take-over's (failed, one queued retry,
    no outcome). (AP1, lock order)"""
    clock = Clock()
    store = await _store(dsn, clock)
    try:
        alert_id = await _alert(store, "T-1")
        running = await _running(store, alert_id, "k1")
        lapse_lease(dsn, running)
        async with holding(dsn, "SELECT id FROM jobs.alerts WHERE id = %s FOR UPDATE", (alert_id,)):
            start_finish = lambda: asyncio.ensure_future(  # noqa: E731
                store.finish(T1, running, stage="completed", disposition="malicious", cost_usd=0.0))
            start_takeover = lambda: asyncio.ensure_future(store.take_over())  # noqa: E731
            first = (start_finish if finish_first else start_takeover)()
            await _settled(dsn, first)
            second = (start_takeover if finish_first else start_finish)()
            await _settled(dsn, first, second)
        finished, taken = await asyncio.wait_for(asyncio.gather(*((first, second) if finish_first else (second, first))), timeout=15)
        rows = investigations_of(dsn, alert_id)
        _agrees(dsn, alert_id, "the copy after the race")
        if finished is not None:
            assert taken == [], "the finish won: nothing left to take over"
            assert [r[1] for r in rows] == ["completed"], "the finish won: nothing left to take over"
            assert stored_copy(dsn, alert_id)[0] == "malicious"
        else:
            assert taken == [running], "take-over won: a failed row and its retry"
            assert sorted(r[1] for r in rows) == ["failed", "queued"], "take-over won: a failed row and its retry"
            assert stored_copy(dsn, alert_id) == (None, None, None)
    finally:
        await store.close()
