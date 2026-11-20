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
from defender.tests.support.jobs._jobs1342 import NOW, T1, T2, lapse_lease, register_tenant
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
SEEDS = range(4)
STEPS = 50
ALERTS_PER_TENANT = 2


@pytest.fixture
def dsn(migrated_database: str) -> str:
    register_tenant(migrated_database, T1)
    register_tenant(migrated_database, T2)
    return migrated_database


class Clock:
    def __init__(self) -> None:
        self.at = NOW

    def __call__(self) -> dt.datetime:
        return self.at


async def _store(dsn: str, clock: Clock) -> Any:
    from defender.jobs import JobStore

    return JobStore(dsn, clock=clock)


async def _alert(store: Any, ticket: str, at: dt.datetime = NOW, tenant: str = T1) -> str:
    return (await store.insert_alert(tenant, vendor="elastic", vendor_ticket_id=ticket, fired_at=at, changed_at=at,
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


#: How often each state or event the sequences exist to reach must be reached: a premise, so a generator that stops reaching
#: one fails instead of passing over states it no longer builds.
AT_LEAST = 5
_COMPLETED_REMAIN = "the source deleted, two or more completed remain"
_TIED_TOP = "... the two newest remaining tied on created_at, finished_at against id order"
_OTHER_ATTEMPT = "a delete named by an attempt that is not the source, the source another attempt of its request"
_RETRY_NEWEST = "an alert whose newest investigation has a lower attempt than an older one, with another stage"
_FAILED_OVER_OUTCOME = "an alert whose newest investigation is failed, aborted or unparseable over a stored outcome"
_EVENTS = ("completed over a completed", "a retry completed", "a take-over", "a non-source deleted", "a finish beside a delete",
           "a cycle", _COMPLETED_REMAIN, _TIED_TOP, _OTHER_ATTEMPT)
_STATES = (_RETRY_NEWEST, _FAILED_OVER_OUTCOME)


Ending = tuple[str, str | None]  # a stage and, for `completed`, a disposition


async def _finish_one(store: Any, rng: random.Random, tenant: str, inv_id: str, copy_before: Any, attempt: int, hits: _Hits,
                      ending: Ending | None = None) -> Ending:
    """Finish the running investigation in `ending`, one drawn when not given: mostly `completed`, its disposition by turns
    with chance in it, so every tenant certainly holds every outcome in orders that differ from run to run."""
    if ending is None:
        stage = rng.choice(["completed"] * 7 + ["unparseable", "failed", "aborted"])
        turn = DISPOSITION_VALUES[hits.get("finished", 0) % len(DISPOSITION_VALUES)]
        ending = (stage, (rng.choice(DISPOSITION_VALUES) if rng.random() < 0.4 else turn) if stage == "completed" else None)
    stage, disposition = ending
    hits.hit("finished")
    if stage == "completed" and copy_before[0] is not None:
        hits.hit("completed over a completed")
    if stage == "completed" and attempt > 1:
        hits.hit("a retry completed")
    await store.finish(tenant, inv_id, stage=stage, disposition=disposition, cost_usd=0.0,
                       failure_reason=None if stage in {"completed", "unparseable"} else "worker_error")
    return ending


async def _life(dsn: str, store: Any, read: Reader, rng: random.Random, clock: Clock, tenant: str, alert_id: str, keys: list[int],  # noqa: PLR0913 — the generator threads its whole world
                alerts: int, hits: _Hits, check: Any, *, advance: tuple[bool, bool] | None = None, ending: Ending | None = None) -> tuple[str, Ending] | None:
    """One request's whole life on an alert with no live investigation, the clock standing still between its writes unless
    `advance` says to move it before the request and between its claim and its end (by chance, about half the time, when not
    given); a third of the lives lose their worker first and are ended by the retry. The request key and how it ended, or
    `None` when the claim never reached it."""
    before, inside = advance if advance is not None else (rng.random() < 0.3, rng.random() < 0.5)
    if before:
        clock.at += HOUR
    keys[0] += 1
    key = f"k{keys[0]}"
    await store.create_investigation(tenant, alert_id, key, actor="gen")
    await check(only=alert_id)
    claimed = await _claim_for(store, alert_id, alerts, check)
    if claimed is not None and rng.random() < 0.35:
        lapse_lease(dsn, claimed.record.investigation_id)
        hits.hit("a take-over")
        await store.take_over()
        await check(only=alert_id)
        claimed = await _claim_for(store, alert_id, alerts, check)
    if claimed is None:
        return None
    hits.hit("a cycle")
    if inside:
        clock.at += HOUR
    ended = await _finish_one(store, rng, tenant, claimed.record.investigation_id, expected_copy(investigations_of(read, alert_id)),
                              claimed.record.attempt, hits, ending)
    await check(only=alert_id)
    return key, ended


async def _lives(dsn: str, store: Any, read: Reader, rng: random.Random, clock: Clock, tenant: str, alert_id: str,  # noqa: PLR0913 — the generator threads its whole world
                 keys: list[int], alerts: int, hits: _Hits, check: Any, *, trio: bool, endings: list[Ending] | None) -> list[Ending]:
    """A life on the alert, or (`trio`) three completed lives, the first two made at one clock reading and the second ended
    later, the third made later and then deleted: the two left tie on `created_at` and end in the order of their ids half the
    time against it. `endings` fixes how each ends, as an earlier call (the twin alert's) drew them; the endings used."""
    if not trio:
        lived = await _life(dsn, store, read, rng, clock, tenant, alert_id, keys, alerts, hits, check, ending=endings[0] if endings else None)
        return [lived[1]] if lived else []
    used: list[Ending] = []
    key = None
    for n, advance in enumerate(((False, False), (False, True), (True, False))):
        ending = endings[n] if endings and n < len(endings) else ("completed", rng.choice(DISPOSITION_VALUES))
        lived = await _life(dsn, store, read, rng, clock, tenant, alert_id, keys, alerts, hits, check, advance=advance, ending=ending)
        key = lived[0] if lived else None
        used.append(ending)
    if key is not None:
        rows = read.rows("SELECT id, alert_id, stage, request_key, attempt, tenant_id FROM jobs.investigations WHERE alert_id = %s", (alert_id,))
        attempts = [r for r in rows if r[3] == key]
        spare = [r for r in attempts if r[0] != expected_copy(investigations_of(read, alert_id))[1]]  # named by an attempt that is not the source
        await _delete(store, read, rows, rng.choice(spare if spare and rng.random() < 0.7 else attempts), hits)
        await check(only=alert_id)
    return used


async def _delete(store: Any, read: Reader, rows: list[tuple[Any, ...]], named: tuple[Any, ...], hits: _Hits) -> None:
    """Delete the request of the investigation `named` (a row of `id, alert_id, stage, request_key, attempt, tenant_id`),
    noting which of the cases the guard exists for it is."""
    inv_id, alert_id, _, key, _, tenant = named
    doomed = {x[0] for x in rows if x[1] == alert_id and x[3] == key}
    source = expected_copy(investigations_of(read, alert_id))[1]
    kept = [r for r in read.rows("SELECT id, created_at, finished_at FROM jobs.investigations WHERE alert_id = %s AND stage = 'completed'",
                                 (alert_id,)) if r[0] not in doomed]
    if source in doomed and len(kept) >= 2:
        hits.hit(_COMPLETED_REMAIN)
        top = [r for r in kept if r[1] == max(k[1] for k in kept)]
        best = max(top, key=lambda r: r[0])
        if len(top) >= 2 and any(r[2] > best[2] for r in top):
            hits.hit(_TIED_TOP)
    if source in doomed and inv_id != source:
        hits.hit(_OTHER_ATTEMPT)
    elif source is not None and source not in doomed:
        hits.hit("a non-source deleted")
    await store.delete_investigation(tenant, inv_id, actor="gen")


async def _claim_for(store: Any, alert_id: str, tries: int, check: Any) -> Any:
    """Claim until the alert's queued investigation is the one claimed (claim() takes the oldest queued, which may be another
    alert's, and that one runs on): its `Claim`, or `None` when it was not queued."""
    for _ in range(tries + 1):
        claimed = await store.claim()
        await check(only=alert_id)
        if claimed is None or claimed.record.alert_id == alert_id:
            return claimed
    return None


async def _step(dsn: str, read: Reader, store: Any, rng: random.Random, clock: Clock, alerts: list[tuple[str, str]], keys: list[int],  # noqa: C901, PLR0912, PLR0913, PLR0915 — one arm per store operation
                hits: _Hits, check: Any) -> None:
    """One generated operation on one of the tenants' alerts; `check()` is awaited after each store write a cycle makes."""
    from defender.jobs import Conflict, NotFound

    order = {alert_id: n for n, (_, alert_id) in enumerate(alerts)}  # stable keys, so the choice does not depend on row order; claim() still breaks created_at ties by random id, so a seed does not fully replay
    rows = sorted(read.rows("SELECT id, alert_id, stage, request_key, attempt, tenant_id FROM jobs.investigations"),
                  key=lambda r: (order.get(r[1], len(order)), r[3], r[4]))
    running = [r for r in rows if r[2] == "running"]
    live = [r for r in rows if r[2] in {"queued", "running"}]
    ended = [r for r in rows if r[2] not in {"queued", "running"}]
    if rng.random() < 0.2:
        clock.at += HOUR  # the others leave the clock still: equal `created_at`, ordered by id
    op = rng.choices(["create", "claim", "finish", "cancel", "takeover", "delete", "pair", "race", "cycle", "trio"], [2, 2, 4, 1, 3, 3, 2, 3, 5, 4])[0]
    try:
        if op == "create":
            keys[0] += 1
            tenant, alert_id = rng.choice(alerts)
            await store.create_investigation(tenant, alert_id, f"k{keys[0]}", actor="gen")
        elif op == "claim":
            await store.claim()
        elif op == "finish" and running:
            inv_id, alert_id, _, _, attempt, tenant = rng.choice(running)
            await _finish_one(store, rng, tenant, inv_id, expected_copy(investigations_of(read, alert_id)), attempt, hits)
        elif op == "cancel" and live:
            row = rng.choice(live)
            await store.cancel_investigation(row[5], row[0], actor="gen")
        elif op == "takeover" and running:
            lapse_lease(dsn, rng.choice(running)[0])
            if await store.take_over():
                hits.hit("a take-over")
        elif op == "delete" and ended:
            await _delete(store, read, rows, rng.choice(ended), hits)
        elif op in {"pair", "race"}:
            # A finish beside a delete of another request of its alert: of a running one, or of a new request's life.
            others: list[tuple[Any, ...]] = []
            inv_id = None
            if op == "pair" and running:
                inv_id, alert_id, _, key, _, tenant = rng.choice(running)
                others = [r for r in ended if r[1] == alert_id and r[3] != key]
            elif op == "race":
                tenant, alert_id = rng.choice(alerts)
                others = [r for r in ended if r[1] == alert_id]
                if others and not [r for r in live if r[1] == alert_id]:
                    keys[0] += 1
                    await store.create_investigation(tenant, alert_id, f"k{keys[0]}", actor="gen")
                    await check(only=alert_id)
                    claimed = await _claim_for(store, alert_id, len(alerts), check)
                    inv_id = claimed.record.investigation_id if claimed is not None else None
            if others and inv_id is not None:
                hits.hit("a finish beside a delete")
                results = await asyncio.gather(
                    store.finish(tenant, inv_id, stage="completed", disposition=rng.choice(DISPOSITION_VALUES), cost_usd=0.0),
                    store.delete_investigation(tenant, rng.choice(others)[0], actor="gen"), return_exceptions=True)
                for result in results:
                    if isinstance(result, BaseException) and not isinstance(result, Conflict | NotFound):
                        raise result  # a deadlock or any other failure is a failure of the invariant
        elif op in {"cycle", "trio"}:
            # The life, or the three lives, then the same ending(s) for the twin alert of the other tenant (the alerts come in
            # pairs, one per tenant), so both tenants hold the same outcomes at once.
            # The dispositions go round the five by turns (a trio's three lives take three of them), so every outcome is
            # given to both twins again and again whatever the draws; only the stage a cycle ends in, which alert goes
            # first and whether the twin follows are chance.
            first = rng.randrange(len(alerts))
            hits.hit("rounds")
            turn = hits["rounds"] * 3
            dispositions = [DISPOSITION_VALUES[(turn + n) % len(DISPOSITION_VALUES)] for n in range(3)]
            stage = rng.choice(["completed"] * 7 + ["unparseable", "failed", "aborted"])
            endings: list[Ending] | None = (
                [("completed", d) for d in dispositions] if op == "trio" else [(stage, dispositions[0] if stage == "completed" else None)]
            )
            for index in (first, first ^ 1) if rng.random() < 0.8 else (first,):
                tenant, alert_id = alerts[index]
                if not [r for r in live if r[1] == alert_id]:
                    await _lives(dsn, store, read, rng, clock, tenant, alert_id, keys, len(alerts), hits, check,
                                         trio=op == "trio", endings=endings)
    except (Conflict, NotFound):
        pass  # a refused operation changes nothing: the invariant still has to hold


async def test_ap1_after_any_sequence_of_store_operations_each_tenants_listing_is_o1_of_its_investigations_unfiltered_and_under_every_outcome(dsn):  # noqa: C901, PLR0915 — the generator, its oracle and its premises in one case
    """Over seeded random sequences of create, claim, finish in every stage, cancel, take-over, delete, whole-life cycles and
    finish-beside-delete pairs, on the alerts of two tenants, after every store write each alert's three columns equal O1
    computed from its investigations, and each tenant's listing through the API adapter, unfiltered and under each of the six
    `outcome` values, is exactly that tenant's alerts with O1's `outcome` and `latest_status`, in order, with no deadlock. The
    sequences reach, at least five times each, the states the guard exists for. (AP1, O1, O2)"""
    from defender._vocab import NoOutcome
    from defender.api.job_store import JobStorePorts

    hits = _Hits()
    clock = Clock()
    store = await _store(dsn, clock)
    ports = JobStorePorts(store)
    read = Reader(dsn)
    filters: tuple[Any, ...] = (None, NoOutcome(), *DISPOSITION_VALUES)
    states: dict[str, set[tuple[int, str]]] = {name: set() for name in _STATES}
    held: dict[tuple[str, int], int] = {}  # per tenant and filter, the checks at which the listing was not empty
    both: dict[int, int] = {}  # per filter, the checks at which both tenants' listings were not
    # The alerts of every seed so far stay in the database: each tenant's listing is all of them, newest fired first.
    alerts: list[tuple[str, str]] = []
    newest_first: dict[str, list[str]] = {T1: [], T2: []}
    current = [0]  # the seed running

    async def check(where: str = "", only: str | None = None) -> None:  # noqa: C901 — O1 per alert, then each tenant under each filter
        """The stored copy of every alert (of `only`, when given) equals O1; and, unless `only`, every tenant's listing through
        the adapter, unfiltered and under each outcome, equals O1's."""
        if only is not None:
            assert stored_copy(read, only) == expected_copy(investigations_of(read, only)), f"seed {current[0]} {where}: the stored copy"
            return
        by_alert: dict[str, list[tuple[Any, ...]]] = {alert_id: [] for _, alert_id in alerts}
        for row in read.rows("SELECT id, stage, disposition, created_at, alert_id, attempt FROM jobs.investigations"):
            if row[4] in by_alert:
                by_alert[row[4]].append(row)
        stored = {r[0]: tuple(r[1:]) for r in read.rows(
            "SELECT id, outcome, outcome_investigation_id, outcome_created_at FROM jobs.alerts")}
        want: dict[str, tuple[str | None, str | None]] = {}
        for _, alert_id in alerts:
            rows = by_alert[alert_id]
            plain = [r[:4] for r in rows]
            assert stored[alert_id] == expected_copy(plain), f"seed {current[0]} {where}: the stored copy"
            want[alert_id] = (expected_copy(plain)[0], expected_latest_status(plain))
            if rows:
                newest = max(rows, key=lambda r: (r[3], r[0]))
                most_attempts = max(rows, key=lambda r: (r[5], r[3], r[0]))
                if newest[5] < most_attempts[5] and newest[1] != most_attempts[1]:
                    states[_RETRY_NEWEST].add((current[0], alert_id))
                if want[alert_id][0] is not None and newest[1] in {"failed", "aborted", "unparseable"}:
                    states[_FAILED_OVER_OUTCOME].add((current[0], alert_id))
        answers = await asyncio.gather(*(ports.list_alerts(
            tenant, fired_after=None, fired_before=None, outcome=value, after=None, limit=200)
            for tenant in (T1, T2) for value in filters))
        listings = dict(zip(((tenant, n) for tenant in (T1, T2) for n in range(len(filters))), answers, strict=True))
        for tenant in (T1, T2):
            for n, value in enumerate(filters):
                expect = [(a, *want[a]) for a in newest_first[tenant]
                          if value is None or (want[a][0] is None if isinstance(value, NoOutcome) else want[a][0] == value)]
                got = [(x.alert_id, x.outcome, x.latest_status) for x in listings[(tenant, n)]]
                assert got == expect, f"seed {current[0]} {where}: {tenant}'s listing under outcome {value!r}"
                if expect:
                    held[(tenant, n)] = held.get((tenant, n), 0) + 1
        for n in range(len(filters)):
            if listings[(T1, n)] and listings[(T2, n)]:
                both[n] = both.get(n, 0) + 1

    try:
        for seed in SEEDS:
            current[0] = seed
            rng = random.Random(seed)
            keys = [seed * 1000]
            mine = [(tenant, await _alert(store, f"G-{seed}-{n}", NOW - (seed * ALERTS_PER_TENANT + n) * HOUR, tenant))
                    for n in range(ALERTS_PER_TENANT) for tenant in (T1, T2)]
            alerts += mine
            for tenant, alert_id in mine:
                newest_first[tenant].append(alert_id)
            for step in range(STEPS):
                try:
                    await _step(dsn, read, store, rng, clock, mine, keys, hits, check)
                    await check(f"step {step}")
                except BaseException:
                    print(f"AP1 failed at seed {seed}, step {step}")  # noqa: T201 — pytest shows it with the failure
                    for _, alert_id in alerts:
                        print(f"  alert {alert_id}: {investigations_of(read, alert_id)}")  # noqa: T201 — pytest shows it with the failure
                    raise
    finally:
        read.close()
        await store.close()
    short = {name: hits.get(name, 0) for name in _EVENTS if hits.get(name, 0) < AT_LEAST}
    short |= {name: len(found) for name, found in states.items() if len(found) < AT_LEAST}
    short |= {f"{tenant} held outcome {filters[n]!r}": held.get((tenant, n), 0) for tenant in (T1, T2) for n in range(len(filters))
              if held.get((tenant, n), 0) < AT_LEAST}
    short |= {f"both tenants held outcome {filters[n]!r}": both.get(n, 0) for n in range(len(filters)) if both.get(n, 0) < AT_LEAST}
    assert not short, f"premise: the sequences reached these fewer than {AT_LEAST} times: {short}"


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
            start_finish = lambda: asyncio.ensure_future(  # noqa: E731 — a named thunk the race starts later
                store.finish(T1, running, stage="completed", disposition="malicious", cost_usd=0.0))
            start_takeover = lambda: asyncio.ensure_future(store.take_over())  # noqa: E731 — a named thunk the race starts later
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
