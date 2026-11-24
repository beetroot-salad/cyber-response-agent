"""#1083 O10: the API's ports, served by the adapter over the real job store (PostgreSQL-gated); the list cases run over the real store only (#1496: the fake is gone).

FORCED CHOICE FC-10: the adapter is `defender.api.job_store.JobStorePorts(store)`, one object serving the alerts, investigations,
learning jobs, alert-mapping and write ports over a `JobStore` it does not own. FC-12 (r5 Am-6): a write takes `(principal, ...)`
only; a read keeps `tenant_id`."""
from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import typing
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from defender.api.models import InvestigationStatus
from defender.tests.support.jobs._ending1546 import complete_through_the_store
from defender.tests.support.jobs._jobs1342 import ALERT_BYTES, DESCRIPTION, TITLE, JobsAudit, register_tenant
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING

pytestmark = pytest.mark.anyio

A = "5d0e7a10-1083-4c00-8a00-0000000000aa"
B = "5d0e7a10-1083-4c00-8a00-0000000000bb"
U = "5d0e7a10-1083-4c00-8a00-0000000000cc"  # registered with no alert mapping
AT = dt.datetime(2026, 11, 2, 8, tzinfo=dt.UTC)
MINUTE = dt.timedelta(minutes=1)
PERSON = "7a0c0c0c-1083-4000-8000-0000000000a1"
PROGRAM = "7a0c0c0c-1083-4000-8000-00000000c0de"
CREDENTIAL = "7a0c0c0c-1083-4000-8000-0000000c4ed1"
POSTGRES = pytest.mark.postgres


def _principal(tenant: str = A, *, program: bool = False) -> Any:
    from defender.api.ports import Principal

    return Principal(tenant_id=tenant, actor_id=PROGRAM if program else PERSON,
                     credential_id=CREDENTIAL if program else None)


@dataclasses.dataclass
class Clock:
    at: dt.datetime = AT

    def __call__(self) -> dt.datetime:
        return self.at


@pytest.fixture
def dsn(migrated_database: str) -> str:
    register_tenant(migrated_database, A)
    register_tenant(migrated_database, B)
    register_tenant(migrated_database, U, alert_mapping=None)
    return migrated_database


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
async def store(dsn: str, clock: Clock) -> AsyncIterator[Any]:
    from defender.jobs import JobStore

    opened = JobStore(dsn, clock=clock)
    try:
        yield opened
    finally:
        await opened.close()


@pytest.fixture
def adapter(store: Any) -> Any:
    from defender.api.job_store import JobStorePorts  # FC-10

    return JobStorePorts(store)


async def _alert(store: Any, tenant: str, ticket: str, fired: dt.datetime = AT) -> str:
    stored = await store.insert_alert(tenant, vendor="elastic", vendor_ticket_id=ticket, fired_at=fired,
                                      changed_at=fired, received_at=fired, raw=ALERT_BYTES)
    return str(stored.alert_id)


async def _ended(store: Any, adapter: Any, alert_id: str, *, stage: str = "completed", tenant: str = A, key: str = "k1",
                 **figures: Any) -> str:
    """An investigation of `alert_id` taken through the store's own claim and ended in `stage`; its id. #1546 (design Flows
    "Investigation end" 5: "A learning job is queued from an investigation only when its state is `complete`"): a
    `completed` end is the worker's normal end through `decide` and `apply` over its claim's facts and an uploaded bundle
    (`_ending1546.complete_through_the_store`), so its auto learning job is queued as before; any other stage is stated
    (`finish`), which queues none either way."""

    investigation, _ = await adapter.create_investigation(_principal(tenant), alert_id, key)
    claimed = await store.claim()
    assert claimed is not None
    assert claimed.record.investigation_id == investigation.investigation_id
    if stage == "completed":
        assert figures.pop("failure_reason", None) is None, "a completed end has no failure reason"
        assert await complete_through_the_store(store, tenant, str(investigation.investigation_id), **figures)
    else:
        await store.finish(tenant, investigation.investigation_id, stage=stage, **figures)
    return str(investigation.investigation_id)


# --- the list reads: the real store, one set of cases --------------------------------------------------------------------

class RealBackend:
    """Rows through the store's own writes, over the adapter."""

    def __init__(self, store: Any, adapter: Any, clock: Clock) -> None:
        self.store, self.reads, self.clock = store, adapter, clock

    async def alerts(self, tenant: str, times: list[dt.datetime]) -> list[str]:
        return [await _alert(self.store, tenant, f"L-{n}", t) for n, t in enumerate(times)]

    async def investigations(self, tenant: str, times: list[dt.datetime]) -> list[str]:
        ids = []
        for n, t in enumerate(times):
            alert = await _alert(self.store, tenant, f"I-{n}")
            self.clock.at = t
            investigation, _ = await self.reads.create_investigation(_principal(tenant), alert, "k1")
            ids.append(str(investigation.investigation_id))
        self.clock.at = AT
        return ids

    async def learning_jobs(self, tenant: str, times: list[dt.datetime]) -> list[str]:
        """Each job's id read from its table by its own investigation, in creation order: never from the read under test."""
        from sqlalchemy import select, update

        from defender.jobs.models import LearningJobRow

        ids = []
        for n, t in enumerate(times):
            alert = await _alert(self.store, tenant, f"J-{n}")
            self.clock.at = t
            investigation = await _ended(self.store, self.reads, alert, tenant=tenant, disposition="benign", cost_usd=1.0)  # the end queues the auto job, stamped now
            async with self.store._sessions() as session:
                found = (await session.execute(select(LearningJobRow.id).where(LearningJobRow.investigation_id == investigation))).scalars().all()
            assert len(found) == 1, "one auto job per ended investigation"
            # #1546 (code-record owner decision D10): the job's `created_at` is the database's clock, not the store's; the
            # case's time layout (its ties included) is the one the list is judged by, so the job is stamped at `t` here.
            async with self.store._tx() as session:
                await session.execute(update(LearningJobRow).where(LearningJobRow.id == found[0]).values(created_at=t))
            ids.append(str(found[0]))
        self.clock.at = AT
        return ids


@pytest.fixture(params=[pytest.param("real", marks=POSTGRES)])
async def backend(request: pytest.FixtureRequest) -> AsyncIterator[Any]:
    from defender.api.job_store import JobStorePorts
    from defender.jobs import JobStore

    clock = Clock()
    opened = JobStore(request.getfixturevalue("dsn"), clock=clock)  # a sync fixture: no loop is entered
    try:
        yield RealBackend(opened, JobStorePorts(opened), clock)
    finally:
        await opened.close()


#: kind -> (read, position of an item, how to call it for one tenant)
KINDS: dict[str, tuple[Callable[..., Any], Callable[[Any], tuple[dt.datetime, str]], Callable[..., Any], Callable[[Any], str]]] = {
    "alerts": (lambda r, t, **kw: r.list_alerts(t, fired_after=None, fired_before=None, outcome=None, **kw),
               lambda a: (a.fired_at, a.alert_id), lambda b, t, times: b.alerts(t, times), lambda a: str(a.alert_id)),
    "investigations": (lambda r, t, **kw: r.list_investigations(t, alert_id=None, **kw),
                       lambda i: (i.created_at, i.investigation_id), lambda b, t, times: b.investigations(t, times),
                       lambda i: str(i.investigation_id)),
    "learning_jobs": (lambda r, t, **kw: r.list_learning_jobs(t, investigation_id=None, **kw),
                      lambda j: (j.created_at, j.learning_job_id), lambda b, t, times: b.learning_jobs(t, times),
                      lambda j: str(j.learning_job_id)),
}


async def _pages(read: Callable[..., Any], position: Callable[[Any], Any], limit: int) -> list[list[Any]]:
    pages: list[list[Any]] = []
    after = None
    for _ in range(50):
        page = await read(after=after, limit=limit)
        pages.append(page)
        if len(page) < limit:
            return pages
        after = position(page[-1])
    raise AssertionError("a list never ran out")


@pytest.mark.parametrize("kind", sorted(KINDS))
@pytest.mark.parametrize("count", [6, 7])
async def test_o10_every_list_pages_newest_first_breaking_ties_by_id_descending_and_is_short_only_at_the_end(backend, kind, count):
    """Rows tied in pairs, a page size of 3, a total that is and is not a multiple of it: no gap or repeat, every page full but the last. (O10)"""
    read, position, seed, ident = KINDS[kind]
    times = [AT + (n // 2) * MINUTE for n in range(count)]  # pairs tie, and a page boundary falls inside a pair
    ids = await seed(backend, A, times)
    await seed(backend, B, [AT])  # another tenant's row never appears
    expected = [i for _, i in sorted(zip(times, ids, strict=True), reverse=True)]  # uuid order is text order (C9)

    pages = await _pages(lambda **kw: read(backend.reads, A, **kw), position, 3)

    assert [len(p) for p in pages[:-1]] == [3] * (len(pages) - 1), "a short page before the end"
    assert len(pages[-1]) < 3
    assert len(pages) == count // 3 + 1, "a multiple of the page size ends on an empty page, never a missing one"
    assert [ident(i) for p in pages for i in p] == expected


@pytest.mark.parametrize("kind", sorted(KINDS))
async def test_o10_a_list_with_nothing_after_the_last_position_is_empty_and_another_tenants_list_is_its_own(backend, kind):
    """After the oldest row nothing is served; each tenant lists only its rows (control: the owner's non-empty). (O10)"""
    read, position, seed, ident = KINDS[kind]
    mine = await seed(backend, A, [AT, AT + MINUTE])
    theirs = await seed(backend, B, [AT])
    first = await read(backend.reads, A, after=None, limit=10)
    assert [ident(i) for i in first] == [mine[1], mine[0]]
    assert await read(backend.reads, A, after=position(first[-1]), limit=10) == []
    assert [ident(i) for i in await read(backend.reads, B, after=None, limit=10)] == theirs


async def test_o10_the_alert_window_is_closed_below_open_above_and_adjacent_windows_neither_gap_nor_overlap(backend):
    """`fired_after <= fired_at < fired_before`; each bound alone; two adjacent windows together serve every alert once. (O10)"""
    times = [AT + n * MINUTE for n in range(5)]
    ids = dict(zip(times, await backend.alerts(A, times), strict=True))

    async def window(after: dt.datetime | None, before: dt.datetime | None) -> list[str]:
        found = await backend.reads.list_alerts(A, fired_after=after, fired_before=before, outcome=None, after=None, limit=50)
        return [str(a.alert_id) for a in found]

    assert await window(times[1], times[3]) == [ids[times[2]], ids[times[1]]]
    assert await window(times[3], None) == [ids[times[4]], ids[times[3]]]
    assert await window(None, times[1]) == [ids[times[0]]]
    assert await window(times[2], times[2]) == []
    lower, upper = await window(None, times[2]), await window(times[2], None)
    assert sorted(lower + upper) == sorted(ids.values())
    assert set(lower).isdisjoint(upper)


@POSTGRES
async def test_alert_list_o1_o2_the_adapter_lists_each_alerts_outcome_and_latest_status_and_filters_by_the_outcome(store, adapter, clock):
    """Over the real store: wire summaries carry the newest completed investigation's disposition and the newest one's
    status (a queued rerun over a completed one keeps the outcome), `outcome=<code>` and the `NoOutcome` marker narrow the
    list, and no summary carries `raw`. (O1, O2, AP4)"""
    from defender.tests.support.jobs._outcome1581 import no_outcome

    newest, middle, oldest = [await _alert(store, A, f"X-{n}", AT + n * MINUTE) for n in (2, 1, 0)]
    await _ended(store, adapter, newest, disposition="malicious", cost_usd=1.0)
    clock.at += MINUTE
    await _ended(store, adapter, middle, disposition="benign", cost_usd=1.0)
    clock.at += MINUTE
    await adapter.create_investigation(_principal(), middle, "k2")  # queued over a known outcome

    async def listed(outcome: Any = None) -> list[Any]:
        return await adapter.list_alerts(A, fired_after=None, fired_before=None, outcome=outcome, after=None, limit=10)

    everything = await listed()
    assert [(a.alert_id, a.outcome, a.latest_status) for a in everything] == [
        (newest, "malicious", "completed"), (middle, "benign", "queued"), (oldest, None, None)]
    assert all("raw" not in a.model_dump() for a in everything)
    assert [a.alert_id for a in await listed("malicious")] == [newest]
    assert [a.alert_id for a in await listed("benign")] == [middle]
    assert [a.alert_id for a in await listed(no_outcome())] == [oldest]
    assert await listed("unresolved") == []


# --- reads by id, the wire mapping, tenant keying ------------------------------------------------------------------

# --- #1485: the learning work port, real adapter and fake, one set of cases ---------------------------------------
# A sibling of `backend` (so no existing case needs the learning store): its store stamps rows with the database's clock
# (no clock seam), so the real side seeds ties by one transaction (one close) or one `UPDATE`, and every seeder returns the
# positions it made read back from the store; the fake seeds given times and minted ids and returns the same.

class RealLearning:
    """Items held and batches parked through the learning store's own verbs, read through `StoreLearningWork`."""

    def __init__(self, store: Any, adapter: Any, dsn: str) -> None:
        self.store, self.reads, self.dsn = store, adapter, dsn

    async def items(self, tenant: str, groups: list[tuple[str, list[str]]]) -> list[tuple[str, dt.datetime, str]]:
        """Each group `(status, keys)` is one transaction: `held` keys one close (tied), `dead` keys one dead each."""
        from defender.tests.support.api._learning1485 import dead_alone, held_together

        for status, keys in groups:
            if status == "held":
                await held_together(self.store, tenant, [("finding", k) for k in keys])
            else:
                for key in keys:
                    await dead_alone(self.store, tenant, key)
        found = await self.store.work(tenant, statuses=["held", "dead"])
        return [(i.status, i.updated_at, str(i.id)) for i in found]

    async def parked(self, tenant: str, groups: list[tuple[int, int]]) -> list[tuple[dt.datetime, str]]:
        """Each group `(hours, count)`: `count` parked revert batches created at `AT` plus `hours`, tied by one `UPDATE`."""
        from defender.tests.support.api._learning1485 import parked_revert, tie_batches

        for hours, count in groups:
            made = [await parked_revert(self.store, tenant, f"reason {hours}/{n}") for n in range(count)]
            tie_batches(self.dsn, made, AT + dt.timedelta(hours=hours))
        return [(b.created_at, str(b.id)) for b in await self.store.batches(tenant) if b.phase == "needs_person"]


@pytest.fixture(params=[pytest.param("real", marks=POSTGRES)])
async def learning_backend(request: pytest.FixtureRequest) -> AsyncIterator[Any]:
    from defender.api.learning_work import StoreLearningWork
    from defender.learning_store import LearningStore

    dsn_ = request.getfixturevalue("dsn")
    opened = LearningStore(dsn_)
    try:
        yield RealLearning(opened, StoreLearningWork(opened), dsn_)
    finally:
        await opened.close()


#: Two held groups (4 and 3 tied) around one dead item: three instants, seven rows, a page of 3 crossing every boundary.
SET_ASIDE_GROUPS = [("held", ["a", "B", "c", "d"]), ("dead", ["z"]), ("held", ["e", "F", "g"])]


async def test_1485_set_aside_items_page_by_time_then_id_descending_over_ties_and_are_tenant_scoped(learning_backend):
    """Eight items over three instants, two of them ties, paged three at a time by the last item's (time, id): (time, id)
    descending, each once, every page full but the last; another tenant's item never appears. Real adapter (the demo's fake is gone, #1496). (O1)"""
    made = await learning_backend.items(A, SET_ASIDE_GROUPS)
    await learning_backend.items(B, [("held", ["b-only"])])
    assert len(made) == 8
    assert len({at for _, at, _ in made}) == 3, 'premise: three instants'
    expected = [i for _, i in sorted(((at, i) for _, at, i in made), reverse=True)]

    pages = await _pages(lambda **kw: learning_backend.reads.list_set_aside(A, status=None, **kw),
                         lambda i: (i.updated_at, i.item_id), 3)

    assert [len(p) for p in pages] == [3, 3, 2]
    assert [str(i.item_id) for p in pages for i in p] == expected


@pytest.mark.parametrize("status", ["held", "dead"])
async def test_1485_a_set_aside_status_narrows_the_page_and_the_other_status_is_absent(learning_backend, status):
    """`status` lists only that status, in the same order, paged; control: the other status's items exist. (O1)"""
    made = await learning_backend.items(A, SET_ASIDE_GROUPS)
    mine = sorted(((at, i) for s, at, i in made if s == status), reverse=True)
    assert mine
    assert len(mine) < len(made), 'premise: both statuses exist'

    pages = await _pages(lambda **kw: learning_backend.reads.list_set_aside(A, status=status, **kw),
                         lambda i: (i.updated_at, i.item_id), 3)

    assert [str(i.item_id) for p in pages for i in p] == [i for _, i in mine]
    assert {i.status for p in pages for i in p} == {status}


PARKED_GROUPS = [(0, 3), (1, 3), (-1, 1)]


async def test_1485_parked_batches_page_by_creation_then_id_descending_over_ties_and_are_tenant_scoped(learning_backend):
    """Seven parked batches over three creation instants, two of them ties, paged three at a time: (created_at, id)
    descending, each once; another tenant's batch never appears. Real adapter (the demo's fake is gone, #1496). (O2)"""
    made = await learning_backend.parked(A, PARKED_GROUPS)
    await learning_backend.parked(B, [(0, 1)])
    assert len(made) == 7
    assert len({at for at, _ in made}) == 3, 'premise: three instants'

    pages = await _pages(lambda **kw: learning_backend.reads.list_parked_batches(A, **kw),
                         lambda b: (b.created_at, b.batch_id), 3)

    assert [len(p) for p in pages] == [3, 3, 1]
    assert [str(b.batch_id) for p in pages for b in p] == [i for _, i in sorted(made, reverse=True)]


# --- reads by id, the wire mapping, tenant keying ------------------------------------------------------------------

@POSTGRES
async def test_o10_o6_an_alert_reads_as_the_store_holds_it_and_lists_without_its_raw_text(store, adapter):
    """The wire alert carries the store's fields by name and the raw text exactly; the list omits `raw`. (O10, O6)"""
    alert_id = await _alert(store, A, "T-1")
    alert = await adapter.get_alert(A, alert_id)
    [summary] = await adapter.list_alerts(A, fired_after=None, fired_before=None, outcome=None, after=None, limit=5)
    assert (alert.alert_id, alert.vendor, alert.vendor_ticket_id) == (alert_id, "elastic", "T-1")
    assert (alert.title, alert.description) == (TITLE, DESCRIPTION)
    assert alert.fired_at == alert.changed_at == alert.received_at == AT
    assert alert.raw == ALERT_BYTES.decode()
    assert "raw" in alert.model_dump()
    assert (summary.alert_id, summary.title) == (alert_id, TITLE)
    assert "raw" not in summary.model_dump()


@POSTGRES
async def test_o10_another_tenants_ids_read_as_absent_and_its_writes_find_nothing(store, adapter):
    """Tenant B asking for tenant A's alert, investigation and learning job reads `None`; B's writes on them are refused as for an unknown id; A's own reads are the control. (O10)"""
    from defender.api.ports import NotFound, UnknownReference

    alert_id = await _alert(store, A, "T-1")
    investigation_id = await _ended(store, adapter, alert_id, disposition="benign")  # #1581 O10: a completed row has one (conflict, updated)
    [job] = await adapter.list_learning_jobs(A, investigation_id=investigation_id, after=None, limit=5)
    assert (await adapter.get_alert(A, alert_id)).alert_id == alert_id
    assert (await adapter.get_investigation(A, investigation_id)).investigation_id == investigation_id
    assert (await adapter.get_learning_job(A, job.learning_job_id)).learning_job_id == job.learning_job_id

    assert await adapter.get_alert(B, alert_id) is None
    assert await adapter.get_investigation(B, investigation_id) is None
    assert await adapter.get_learning_job(B, job.learning_job_id) is None
    assert await adapter.list_investigations(B, alert_id=alert_id, after=None, limit=5) == []
    assert await adapter.list_learning_jobs(B, investigation_id=investigation_id, after=None, limit=5) == []
    with pytest.raises(UnknownReference):
        await adapter.create_investigation(_principal(B), alert_id, "k9")
    with pytest.raises(UnknownReference):
        await adapter.create_learning_job(_principal(B), investigation_id, "c-9")
    with pytest.raises(NotFound):
        await adapter.cancel_investigation(_principal(B), investigation_id)
    with pytest.raises(NotFound):
        await adapter.delete_investigation(_principal(B), investigation_id)
    assert (await adapter.get_investigation(A, investigation_id)).status == "completed", "B's refused writes changed nothing"


@POSTGRES
async def test_o10_a_write_acts_in_its_principals_tenant(store, adapter):
    """A write names no tenant but the principal's: the row lands under it, and under no other. (Am-6)"""
    alert_id = await _alert(store, B, "T-B")
    investigation, _ = await adapter.create_investigation(_principal(B), alert_id, "k1")
    assert (await store.get_investigation(B, investigation.investigation_id)).tenant_id == B
    assert await store.get_investigation(A, investigation.investigation_id) is None


@POSTGRES
@pytest.mark.parametrize("status", typing.get_args(InvestigationStatus))
async def test_o6_an_investigations_status_is_the_stores_stage_for_every_wire_status(store, adapter, status):
    """Every value of the wire's status is reached through the store and read back as the same word; `artifacts` is empty. (O6)"""
    alert_id = await _alert(store, A, "T-1")
    if status in {"queued", "running"}:
        investigation, _ = await adapter.create_investigation(_principal(), alert_id, "k1")
        investigation_id = str(investigation.investigation_id)
        if status == "running":
            await store.claim()
    else:
        investigation_id = await _ended(store, adapter, alert_id, stage=status, disposition="benign" if status == "completed" else None,
                                        failure_reason=None if status in {"completed", "unparseable"} else "worker_error")  # #1581 O10 (conflict, updated)
    stored = await store.get_investigation(A, investigation_id)
    wire = await adapter.get_investigation(A, investigation_id)
    assert stored.stage == status
    assert wire.status == status
    assert wire.artifacts == []
    assert [i.status for i in await adapter.list_investigations(A, alert_id=None, after=None, limit=5)] == [status]


@POSTGRES
async def test_o6_an_investigation_carries_the_stores_fields_by_name(store, adapter, clock):
    """Every wire field but `status`, `artifacts` and `knowledge` equals the store's field of the same name; a finished row's figures and times are the ones written. (O6)"""
    from defender.api.models import Investigation

    alert_id = await _alert(store, A, "T-1")
    clock.at = AT + MINUTE
    created, _ = await adapter.create_investigation(_principal(), alert_id, "req-1")
    clock.at = AT + 2 * MINUTE
    await store.claim()
    clock.at = AT + 3 * MINUTE
    await store.finish(A, created.investigation_id, stage="completed", disposition="benign", cost_usd=2.5, cost_is_lower_limit=True)
    stored = await store.get_investigation(A, created.investigation_id)
    wire = await adapter.get_investigation(A, created.investigation_id)
    for name in set(Investigation.model_fields) - {"status", "artifacts", "knowledge"}:
        assert getattr(wire, name) == getattr(stored, name), name
    assert (wire.request_key, wire.attempt, wire.disposition, wire.cost_usd, wire.cost_is_lower_limit) == (
        "req-1", 1, "benign", 2.5, True)
    assert (wire.created_at, wire.started_at, wire.finished_at) == (AT + MINUTE, AT + 2 * MINUTE, AT + 3 * MINUTE)
    assert wire.knowledge is None


@POSTGRES
async def test_o6_a_failed_investigation_carries_its_reason_and_message(store, adapter):
    """`failure_reason` and `failure_message` reach the wire as written; control: a completed one has neither. (O6)"""
    failed = await _ended(store, adapter, await _alert(store, A, "T-1"), stage="failed", failure_reason="worker_error",
                          failure_message="the worker stopped", cost_usd=None)
    fine = await _ended(store, adapter, await _alert(store, A, "T-2"), stage="completed", disposition="benign", cost_usd=1.0)
    wire = await adapter.get_investigation(A, failed)
    assert (wire.failure_reason, wire.failure_message, wire.cost_usd) == ("worker_error", "the worker stopped", None)
    control = await adapter.get_investigation(A, fine)
    assert (control.failure_reason, control.failure_message) == (None, None)


# --- writes: replay, one live per alert, cancel, delete ------------------------------------------------------------

@POSTGRES
async def test_o10_replay_answers_the_latest_attempt_before_the_end_after_it_and_a_new_one_after_the_delete(store, adapter):
    """The same key answers the same investigation live, once ended, and a new one only after it was deleted. (O10, §4.1)"""
    alert_id = await _alert(store, A, "T-1")
    who = _principal()
    first, created = await adapter.create_investigation(who, alert_id, "k1")
    assert (created, first.status, first.alert_id) == (True, "queued", alert_id)
    assert (await store.get_investigation(A, first.investigation_id)).stage == "queued", "committed before the call returned"

    live_again, created = await adapter.create_investigation(who, alert_id, "k1")
    assert (live_again.investigation_id, created) == (first.investigation_id, False)

    cancelled = await adapter.cancel_investigation(who, first.investigation_id)
    ended_again, created = await adapter.create_investigation(who, alert_id, "k1")
    assert (ended_again.investigation_id, ended_again.status, created) == (first.investigation_id, "aborted", False)
    assert cancelled.status == "aborted"

    await adapter.delete_investigation(who, first.investigation_id)
    fresh, created = await adapter.create_investigation(who, alert_id, "k1")
    assert created is True
    assert fresh.investigation_id != first.investigation_id
    assert fresh.status == "queued"


@POSTGRES
async def test_o10_one_investigation_is_live_per_alert_whatever_the_request_key(store, adapter):
    """A second key on an alert with a live investigation answers the live one, creating nothing; once it ends, a new key starts a new one; another alert is independent. (O10, §4.1)"""
    who = _principal()
    alert_id = await _alert(store, A, "T-1")
    other = await _alert(store, A, "T-2")
    first, _ = await adapter.create_investigation(who, alert_id, "k1")
    collapsed, created = await adapter.create_investigation(who, alert_id, "k2")
    assert (collapsed.investigation_id, created) == (first.investigation_id, False)
    assert [i.investigation_id for i in await adapter.list_investigations(A, alert_id=alert_id, after=None, limit=9)] == [
        first.investigation_id]
    elsewhere, created = await adapter.create_investigation(who, other, "k2")  # control: the same key, another alert
    assert created is True
    assert elsewhere.investigation_id != first.investigation_id

    await adapter.cancel_investigation(who, first.investigation_id)
    after_end, created = await adapter.create_investigation(who, alert_id, "k2")
    assert created is True
    assert after_end.investigation_id != first.investigation_id
    assert {i.investigation_id for i in await adapter.list_investigations(A, alert_id=alert_id, after=None, limit=9)} == {
        first.investigation_id, after_end.investigation_id}


@POSTGRES
async def test_o10_a_start_without_an_alert_or_a_mapping_is_refused_and_creates_nothing(store, adapter):
    """An unknown alert is `UnknownReference`; a tenant with no alert mapping is a `Conflict` until it saves one. (O10)"""
    from defender.api.ports import Conflict, UnknownReference

    with pytest.raises(UnknownReference):
        await adapter.create_investigation(_principal(), str(uuid.uuid4()), "k1")
    alert_id = await _alert(store, U, "T-1")
    with pytest.raises(Conflict):
        await adapter.create_investigation(_principal(U), alert_id, "k1")
    assert await adapter.list_investigations(U, alert_id=None, after=None, limit=5) == []
    await adapter.put_alert_mapping(_principal(U), _wire_mapping(FIXTURE_ALERT_MAPPING))
    _, created = await adapter.create_investigation(_principal(U), alert_id, "k1")
    assert created is True


@POSTGRES
async def test_o10_a_queued_investigation_cancels_to_aborted_cancelled(store, adapter):
    """Cancelling a queued investigation answers it `aborted`/`cancelled`, finished now; the store holds the same. (O10)"""
    alert_id = await _alert(store, A, "T-1")
    created, _ = await adapter.create_investigation(_principal(), alert_id, "k1")
    answered = await adapter.cancel_investigation(_principal(), created.investigation_id)
    stored = await store.get_investigation(A, created.investigation_id)
    assert (answered.status, answered.failure_reason, answered.finished_at) == ("aborted", "cancelled", AT)
    assert (stored.stage, stored.failure_reason) == ("aborted", "cancelled")


@POSTGRES
async def test_o10_a_running_investigation_cancels_and_its_workers_lease_no_longer_covers_it(store, adapter):
    """Claimed through the store, then cancelled: `aborted`/`cancelled`; the holder's next renewal drops it (control: it covered it before). (O10, #1343)"""
    alert_id = await _alert(store, A, "T-1")
    created, _ = await adapter.create_investigation(_principal(), alert_id, "k1")
    claimed = await store.claim()
    assert claimed is not None
    assert (await adapter.get_investigation(A, created.investigation_id)).status == "running"
    assert await store.renew({created.investigation_id}) == [created.investigation_id], "control: the holder's lease covers it"

    answered = await adapter.cancel_investigation(_principal(), created.investigation_id)

    assert (answered.status, answered.failure_reason) == ("aborted", "cancelled")
    assert (await store.get_investigation(A, created.investigation_id)).stage == "aborted"
    assert await store.renew({created.investigation_id}) == []


@POSTGRES
async def test_o10_cancel_of_an_ended_investigation_is_a_conflict_and_of_an_unknown_one_not_found(store, adapter):
    """Cancel refuses an ended investigation (`Conflict`, nothing changed) and an unknown id (`NotFound`). (O10)"""
    from defender.api.ports import Conflict, NotFound

    done = await _ended(store, adapter, await _alert(store, A, "T-1"), disposition="benign", cost_usd=1.0)
    with pytest.raises(Conflict):
        await adapter.cancel_investigation(_principal(), done)
    assert (await adapter.get_investigation(A, done)).status == "completed"
    with pytest.raises(NotFound):
        await adapter.cancel_investigation(_principal(), str(uuid.uuid4()))


@POSTGRES
async def test_o10_delete_removes_an_ended_investigation_and_its_learning_jobs_and_refuses_a_live_one(store, adapter):
    """A live investigation and one whose learning job runs are a `Conflict` and stay; an ended one is removed with its jobs; an unknown id is `NotFound`. (O10)"""
    from defender.api.ports import Conflict, NotFound

    who = _principal()
    running_job = await _ended(store, adapter, await _alert(store, A, "T-job"), key="k2", disposition="benign", cost_usd=1.0)
    assert await store.claim_learning_job() is not None
    with pytest.raises(Conflict):
        await adapter.delete_investigation(who, running_job)
    assert await adapter.get_investigation(A, running_job) is not None

    done = await _ended(store, adapter, await _alert(store, A, "T-done"), key="k3", disposition="benign", cost_usd=1.0)
    live, _ = await adapter.create_investigation(who, await _alert(store, A, "T-live"), "k1")  # last: a claim takes the oldest queued
    with pytest.raises(Conflict):
        await adapter.delete_investigation(who, live.investigation_id)
    assert await adapter.get_investigation(A, live.investigation_id) is not None
    assert len(await adapter.list_learning_jobs(A, investigation_id=done, after=None, limit=5)) == 1
    await adapter.delete_investigation(who, done)
    assert await adapter.get_investigation(A, done) is None
    assert await adapter.list_learning_jobs(A, investigation_id=done, after=None, limit=5) == []
    with pytest.raises(NotFound):
        await adapter.delete_investigation(who, done)


# --- learning jobs ---------------------------------------------------------------------------------------------------

@POSTGRES
async def test_o10_a_learning_job_starts_replays_by_request_id_and_is_refused_until_the_investigation_completed(store, adapter):
    """An explicit job for a completed investigation is created once per request id; a queued or unknown investigation is refused; the list by investigation holds the auto job and the explicit one. (O10)"""
    from defender.api.ports import Conflict, UnknownReference

    who = _principal()
    queued, _ = await adapter.create_investigation(who, await _alert(store, A, "T-q"), "k1")
    with pytest.raises(Conflict):
        await adapter.create_learning_job(who, queued.investigation_id, "c-1")
    with pytest.raises(UnknownReference):
        await adapter.create_learning_job(who, str(uuid.uuid4()), "c-1")
    assert await adapter.list_learning_jobs(A, investigation_id=queued.investigation_id, after=None, limit=5) == []

    await store.claim()
    # #1546 design Flows 5: only an end whose evidence is `complete` is learned from (the worker's `decide` + `apply`)
    assert await complete_through_the_store(store, A, str(queued.investigation_id), disposition="benign", cost_usd=1.0)
    job, created = await adapter.create_learning_job(who, queued.investigation_id, "c-1")
    again, created_again = await adapter.create_learning_job(who, queued.investigation_id, "c-1")
    other, created_other = await adapter.create_learning_job(who, queued.investigation_id, "c-2")
    assert (created, job.trigger, job.status, job.investigation_id) == (True, "explicit", "queued", queued.investigation_id)
    assert (again.learning_job_id, created_again) == (job.learning_job_id, False)
    assert (created_other, other.learning_job_id != job.learning_job_id) == (True, True)
    listed = await adapter.list_learning_jobs(A, investigation_id=queued.investigation_id, after=None, limit=9)
    assert sorted((j.trigger, str(j.learning_job_id)) for j in listed) == sorted(
        [("auto", next(str(j.learning_job_id) for j in listed if j.trigger == "auto")),
         ("explicit", str(job.learning_job_id)), ("explicit", str(other.learning_job_id))])
    assert (await adapter.get_learning_job(A, job.learning_job_id)).learning_job_id == job.learning_job_id
    assert await adapter.get_learning_job(A, str(uuid.uuid4())) is None


@POSTGRES
async def test_o6_a_learning_job_carries_the_stores_fields_by_name(store, adapter):
    """Every wire field equals the store record's field of the same name. (O6)"""
    from defender.api.models import LearningJob

    from sqlalchemy import update

    from defender.jobs.models import LearningJobRow

    investigation_id = await _ended(store, adapter, await _alert(store, A, "T-1"), disposition="benign", cost_usd=1.0)
    # #1546 (code-record owner decision D10): the auto job's `created_at` is the database's clock, not the store's; it is
    # stamped at `AT` here (as `RealBackend.learning_jobs` does), so the wire's `created_at` is judged against a known value.
    async with store._tx() as session:
        await session.execute(update(LearningJobRow).where(LearningJobRow.investigation_id == investigation_id)
                              .values(created_at=AT))
    [stored] = await store.list_learning_jobs(A, investigation_id=investigation_id, after=None, limit=5)  # FC-13
    wire = await adapter.get_learning_job(A, stored.learning_job_id)
    for name in LearningJob.model_fields:
        assert getattr(wire, name) == getattr(stored, name), name
    assert (wire.trigger, wire.status, wire.created_at) == ("auto", "queued", AT)


# --- the alert mapping ----------------------------------------------------------------------------------------------

def _wire_mapping(paths: Any) -> Any:
    from defender.api.models import AlertMapping

    return AlertMapping(**{k: paths.get(k) for k in AlertMapping.model_fields})


@POSTGRES
async def test_o10_the_alert_mapping_reads_absent_until_saved_then_answers_what_the_store_holds_per_tenant(store, adapter):
    """No mapping reads `None`; the first save is `created`, the second replaces it whole; another tenant's mapping is its own. (O10, Am-8)"""
    who = _principal(U)
    assert await adapter.get_alert_mapping(U) is None
    first = _wire_mapping({"signature": "rule.id", "title": "rule.description"})
    stored, created = await adapter.put_alert_mapping(who, first)
    assert (created, stored) == (True, first)
    assert await adapter.get_alert_mapping(U) == first
    second = _wire_mapping({"title": "a"})
    stored, created = await adapter.put_alert_mapping(who, second)
    assert (created, stored) == (False, second)
    assert await adapter.get_alert_mapping(U) == second, "a replace is whole"
    assert await adapter.get_alert_mapping(A) == _wire_mapping(FIXTURE_ALERT_MAPPING), "control: another tenant's is untouched"


@POSTGRES
async def test_o10_the_alert_mapping_answer_is_what_the_store_returned_not_the_request(store):
    """A store that returns a mapping other than the one sent is answered as the store said, `created` included. (Am-8)"""
    from defender.api.job_store import JobStorePorts
    from defender.tests.support.tenancy._mapping1345 import mapping_value

    class Rewriting:
        """The real store, except its mapping write answers a different stored mapping and `created=False`."""

        def __init__(self, real: Any) -> None:
            self._real = real

        def __getattr__(self, name: str) -> Any:
            return getattr(self._real, name)

        async def put_alert_mapping(self, *args: Any, **kwargs: Any) -> Any:
            await self._real.put_alert_mapping(*args, **kwargs)
            return mapping_value({"title": "stored.title"}), False

    sent = _wire_mapping({"title": "sent.title"})
    answered, created = await JobStorePorts(Rewriting(store)).put_alert_mapping(_principal(U), sent)
    assert created is False
    assert answered == _wire_mapping({"title": "stored.title"})
    assert answered != sent


# --- announcements: once per write, after commit, naming the caller and the credential ------------------------

def _events(audit: JobsAudit, before: int) -> list[Any]:
    return audit.records()[before:]


@POSTGRES
@pytest.mark.parametrize("program", [True, False], ids=["program", "person"])
async def test_o9_each_write_through_the_adapter_is_announced_exactly_once_naming_the_caller_and_credential(store, adapter, caplog, program):
    """Start, cancel, delete, learning-job start and mapping replace each log one event, with the principal's actor and credential and the moved details; replays and refusals log none. (O9, P2)"""
    from defender.api.ports import Conflict

    audit = JobsAudit(caplog)
    who = _principal(program=program)
    credential = CREDENTIAL if program else None
    alert_id = await _alert(store, A, "T-1")
    mark = len(audit.records())

    started, _ = await adapter.create_investigation(who, alert_id, "k1")
    await adapter.create_investigation(who, alert_id, "k1")  # a replay
    start = _events(audit, mark)
    assert [(r.action, r.target, r.detail) for r in start] == [
        ("investigation.start", started.investigation_id, f"alert {alert_id}")]

    mark = len(audit.records())
    await adapter.cancel_investigation(who, started.investigation_id)
    with pytest.raises(Conflict):
        await adapter.cancel_investigation(who, started.investigation_id)  # refused
    cancel = _events(audit, mark)
    assert [(r.action, r.target) for r in cancel] == [("investigation.cancel", started.investigation_id)]

    mark = len(audit.records())
    await adapter.delete_investigation(who, started.investigation_id)
    delete = _events(audit, mark)
    assert [(r.action, r.target) for r in delete] == [("investigation.delete", started.investigation_id)]

    done = await _ended(store, adapter, await _alert(store, A, "T-2"), key="k2", disposition="benign", cost_usd=1.0)
    mark = len(audit.records())
    job, _ = await adapter.create_learning_job(who, done, "c-1")
    await adapter.create_learning_job(who, done, "c-1")  # a replay
    learning = _events(audit, mark)
    assert [(r.action, r.target, r.detail) for r in learning] == [
        ("learning_job.start", job.learning_job_id, f"investigation {done}; trigger=explicit")]

    mark = len(audit.records())
    await adapter.put_alert_mapping(who, _wire_mapping({"title": "a"}))
    mapping = _events(audit, mark)
    assert [(r.action, r.target) for r in mapping] == [("alert_mapping.update", A)]

    for event in (*start, *cancel, *delete, *learning, *mapping):
        assert (event.actor, event.tenant_id) == (who.actor_id, A)
        assert getattr(event, "credential_id", None) == credential


@POSTGRES
async def test_o9_an_event_is_announced_after_its_row_is_visible_to_another_connection(dsn, adapter, store, caplog):
    """When the start event is emitted, another connection already sees the queued row it names. (O9, P2)"""
    from defender.tests.support.jobs._jobs1342 import JOBS_AUDIT_LOGGER, VisibleAtEmit

    alert_id = await _alert(store, A, "T-1")
    seen = VisibleAtEmit(dsn)
    logging.getLogger(JOBS_AUDIT_LOGGER).addHandler(seen)
    try:
        await adapter.create_investigation(_principal(program=True), alert_id, "k1")
    finally:
        logging.getLogger(JOBS_AUDIT_LOGGER).removeHandler(seen)
    assert seen.seen == [("investigation.start", "queued")]



# --- every audited write the port exposes: one event per change, after it is visible, naming the caller -------------

ADMIN = "7a0c0c0c-1083-4000-8000-0000000ad111"  # the administrator who offboards

#: Where another connection reads the change an event names, by the event's action family: (table, column, key).
_VISIBLE_IN = {"investigation": ("jobs.investigations", "stage", "id"),
               "learning_job": ("jobs.learning_jobs", "status", "id"),
               "alert_mapping": ("tenancy.alert_mappings", "title", "tenant_id"),
               # #1471: the host requests, one table for both kinds (stale, updated)
               "readiness": ("jobs.host_requests", "stage", "id"),
               "adoption": ("jobs.host_requests", "stage", "id")}


class _SeenAtEmit(logging.Handler):
    """While `on`, records each job-store audit event with what another connection sees of its target then."""

    def __init__(self, dsn: str) -> None:
        super().__init__(logging.DEBUG)
        self.dsn, self.on, self.seen = dsn, False, []

    def emit(self, record: logging.LogRecord) -> None:
        from defender.tests.support.shared._postgres1339 import execute

        if not self.on:
            return
        table, column, key = _VISIBLE_IN[record.action.split(".")[0]]
        found = execute(self.dsn, f"SELECT {column} FROM {table} WHERE {key} = %s", (record.target,))
        self.seen.append((record.action, str(record.target), record.actor, getattr(record, "credential_id", None),
                          found[0][0] if found else None))


async def _w_create_investigation(dsn: str, store: Any, adapter: Any, act: Any) -> list[tuple[str, str, Any]]:
    alert_id = await _alert(store, A, "W-1")
    started, _ = await act(lambda: adapter.create_investigation(_principal(program=True), alert_id, "k1"))
    return [("investigation.start", str(started.investigation_id), "queued")]


async def _w_cancel_investigation(dsn: str, store: Any, adapter: Any, act: Any) -> list[tuple[str, str, Any]]:
    started, _ = await adapter.create_investigation(_principal(program=True), await _alert(store, A, "W-1"), "k1")
    await act(lambda: adapter.cancel_investigation(_principal(program=True), started.investigation_id))
    return [("investigation.cancel", str(started.investigation_id), "aborted")]


async def _w_delete_investigation(dsn: str, store: Any, adapter: Any, act: Any) -> list[tuple[str, str, Any]]:
    done = await _ended(store, adapter, await _alert(store, A, "W-1"), stage="failed", failure_reason="worker_error")
    await act(lambda: adapter.delete_investigation(_principal(program=True), done))
    return [("investigation.delete", done, None)]


async def _w_create_learning_job(dsn: str, store: Any, adapter: Any, act: Any) -> list[tuple[str, str, Any]]:
    done = await _ended(store, adapter, await _alert(store, A, "W-1"), disposition="benign", cost_usd=1.0)
    job, _ = await act(lambda: adapter.create_learning_job(_principal(program=True), done, "c-1"))
    return [("learning_job.start", str(job.learning_job_id), "queued")]


async def _w_put_alert_mapping(dsn: str, store: Any, adapter: Any, act: Any) -> list[tuple[str, str, Any]]:
    assert FIXTURE_ALERT_MAPPING.get("title") != "vendor.new_title"  # premise: the replace changes what is seen
    await act(lambda: adapter.put_alert_mapping(_principal(program=True), _wire_mapping({"title": "vendor.new_title"})))
    return [("alert_mapping.update", A, "vendor.new_title")]


async def _w_offboard_tenant(dsn: str, store: Any, adapter: Any, act: Any) -> list[tuple[str, str, Any]]:
    from defender.tests.support.shared._postgres1339 import execute

    done = await _ended(store, adapter, await _alert(store, A, "W-1"), disposition="benign", cost_usd=1.0)
    await adapter.create_learning_job(_principal(), done, "c-1")
    queued, _ = await adapter.create_investigation(_principal(), await _alert(store, A, "W-2"), "k2")
    live_jobs = execute(dsn, "SELECT id FROM jobs.learning_jobs WHERE tenant_id = %s AND status = 'queued'", (A,))
    assert len(live_jobs) == 2, "premise: the auto and the explicit learning job are live"
    await act(lambda: adapter.offboard_tenant(A, actor=ADMIN))
    return [("investigation.cancel", str(queued.investigation_id), "aborted"),
            *(("learning_job.finish", str(job), "skipped") for (job,) in live_jobs)]


async def _w_create_readiness(dsn: str, store: Any, adapter: Any, act: Any) -> list[tuple[str, str, Any]]:
    started, created = await act(lambda: adapter.create_readiness(A, actor=PROGRAM, credential_id=CREDENTIAL))
    assert created, "premise: the start inserted the row"
    return [("readiness.start", str(started.readiness_id), "queued")]


async def _w_create_adoption(dsn: str, store: Any, adapter: Any, act: Any) -> list[tuple[str, str, Any]]:
    started, created = await act(lambda: adapter.create_adoption(A, "ticket", actor=PROGRAM, credential_id=CREDENTIAL))
    assert created, "premise: the start inserted the row"
    return [("adoption.start", str(started.adoption_id), "queued")]


WRITE_CASES = {"create_investigation": _w_create_investigation, "cancel_investigation": _w_cancel_investigation,
               "delete_investigation": _w_delete_investigation, "create_learning_job": _w_create_learning_job,
               "put_alert_mapping": _w_put_alert_mapping, "offboard_tenant": _w_offboard_tenant,
               # #1471: the host requests' starts, the audited writes of `HostRequestsRepository` (stale, updated)
               "create_readiness": _w_create_readiness, "create_adoption": _w_create_adoption}


@POSTGRES
@pytest.mark.parametrize("name", sorted(WRITE_CASES))
async def test_o9_each_audited_write_of_the_port_announces_each_change_once_after_another_connection_sees_it(
        dsn, store, adapter, caplog, name):
    """Every audited write the adapter exposes logs one event per change, emitted once another connection sees the
    change, naming the caller's actor and credential (offboarding: the administrator). (O9, P2, #1360 O5)"""
    from defender.api.job_store import JobStorePorts
    from defender.api.ports import (
        AlertMappingRepository, AlertsRepository, HostRequestsRepository, InvestigationsRepository,
        LearningJobsRepository, Offboarding, Writes,
    )
    from defender.jobs.audit import AuditAction
    from defender.tests.support.jobs._jobs1342 import JOBS_AUDIT_LOGGER

    def members(*protocols: type) -> set[str]:
        return {n for p in protocols for n in vars(p) if not n.startswith("_")}

    # #1471 (stale, updated): `HostRequestsRepository` serves both; its starts are the writes, its polls the reads
    host = members(HostRequestsRepository)
    host_writes = {n for n in host if n.startswith("create_")}
    assert {n.split("_", 1)[0] for n in host - host_writes} == {"get"}, f"premise: the rest are reads: {sorted(host)}"
    reads = members(AlertsRepository, InvestigationsRepository, LearningJobsRepository, AlertMappingRepository) | (
        host - host_writes)
    served = {n for n in vars(JobStorePorts) if not n.startswith("_")}
    assert served - reads == members(Writes, Offboarding) | host_writes == set(WRITE_CASES), (
        "census: every write the port serves")
    caplog.set_level(logging.DEBUG, logger=JOBS_AUDIT_LOGGER)
    seen = _SeenAtEmit(dsn)

    async def act(call: Callable[[], Any]) -> Any:
        seen.on = True
        try:
            return await call()
        finally:
            seen.on = False

    logging.getLogger(JOBS_AUDIT_LOGGER).addHandler(seen)
    try:
        expected = await WRITE_CASES[name](dsn, store, adapter, act)
    finally:
        logging.getLogger(JOBS_AUDIT_LOGGER).removeHandler(seen)
    actor, credential = (ADMIN, None) if name == "offboard_tenant" else (PROGRAM, CREDENTIAL)
    assert {action for action, _, _ in expected} <= set(typing.get_args(AuditAction))
    assert sorted(seen.seen) == sorted((action, target, actor, credential, visible) for action, target, visible in expected)
