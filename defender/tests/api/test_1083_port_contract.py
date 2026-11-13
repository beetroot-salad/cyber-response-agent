"""#1083 O10: the API's ports, served by the adapter over the real job store (PostgreSQL-gated); the list cases also run over the fake.

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
from defender.tests.support.jobs._jobs1342 import ALERT_BYTES, DESCRIPTION, TITLE, JobsAudit, register_tenant
from defender.tests.support.shared._fixture_uuid import fixture_uuid
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
    """An investigation of `alert_id` taken through the store's own claim and ended in `stage`; its id."""
    investigation, _ = await adapter.create_investigation(_principal(tenant), alert_id, key)
    claimed = await store.claim()
    assert claimed is not None
    assert claimed.record.investigation_id == investigation.investigation_id
    await store.finish(tenant, investigation.investigation_id, stage=stage, **figures)
    return str(investigation.investigation_id)


# --- the list reads: real store and fake, one set of cases ---------------------------------------------------------

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
        for n, t in enumerate(times):
            alert = await _alert(self.store, tenant, f"J-{n}")
            self.clock.at = t
            await _ended(self.store, self.reads, alert, tenant=tenant, disposition="benign", cost_usd=1.0)  # the end queues the auto job, stamped now
        self.clock.at = AT
        found = await self.reads.list_learning_jobs(tenant, investigation_id=None, after=None, limit=1000)
        return [str(j.learning_job_id) for j in found]


class FakeBackend:
    def __init__(self) -> None:
        from defender.api.fakes import InMemoryStore

        self.reads = InMemoryStore(lambda: AT)
        self._n = 0

    def _id(self, kind: str) -> str:
        self._n += 1
        return fixture_uuid(f"1083:{kind}:{self._n}")

    async def alerts(self, tenant: str, times: list[dt.datetime]) -> list[str]:
        from defender.api.models import Alert

        ids = [self._id("alert") for _ in times]
        for i, t in zip(ids, times, strict=True):
            self.reads.add_alert(tenant, Alert(alert_id=i, vendor="elastic", vendor_ticket_id=f"F-{i}", title="t",
                                               description="d", fired_at=t, changed_at=t, received_at=t, raw="{}"))
        return ids

    async def investigations(self, tenant: str, times: list[dt.datetime]) -> list[str]:
        from defender.api.models import Investigation

        ids = [self._id("investigation") for _ in times]
        for i, t in zip(ids, times, strict=True):
            self.reads.add_investigation(tenant, Investigation(
                investigation_id=i, alert_id=self._id("alert"), status="queued", request_key="k1", attempt=1,
                cost_usd=0.0, cost_is_lower_limit=False, created_at=t))
        return ids

    async def learning_jobs(self, tenant: str, times: list[dt.datetime]) -> list[str]:
        from defender.api.models import LearningJob

        ids = [self._id("job") for _ in times]
        for i, t in zip(ids, times, strict=True):
            self.reads.add_learning_job(tenant, LearningJob(
                learning_job_id=i, investigation_id=self._id("investigation"), alert_id=self._id("alert"),
                status="queued", trigger="explicit", created_at=t))
        return ids


@pytest.fixture(params=[pytest.param("real", marks=POSTGRES), "fake"])
async def backend(request: pytest.FixtureRequest) -> AsyncIterator[Any]:
    if request.param == "fake":
        yield FakeBackend()
        return
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
    "alerts": (lambda r, t, **kw: r.list_alerts(t, fired_after=None, fired_before=None, **kw),
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
        found = await backend.reads.list_alerts(A, fired_after=after, fired_before=before, after=None, limit=50)
        return [str(a.alert_id) for a in found]

    assert await window(times[1], times[3]) == [ids[times[2]], ids[times[1]]]
    assert await window(times[3], None) == [ids[times[4]], ids[times[3]]]
    assert await window(None, times[1]) == [ids[times[0]]]
    assert await window(times[2], times[2]) == []
    lower, upper = await window(None, times[2]), await window(times[2], None)
    assert sorted(lower + upper) == sorted(ids.values())
    assert set(lower).isdisjoint(upper)


# --- reads by id, the wire mapping, tenant keying ------------------------------------------------------------------

@POSTGRES
async def test_o10_o6_an_alert_reads_as_the_store_holds_it_and_lists_without_its_raw_text(store, adapter):
    """The wire alert carries the store's fields by name and the raw text exactly; the list omits `raw`. (O10, O6)"""
    alert_id = await _alert(store, A, "T-1")
    alert = await adapter.get_alert(A, alert_id)
    [summary] = await adapter.list_alerts(A, fired_after=None, fired_before=None, after=None, limit=5)
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
    investigation_id = await _ended(store, adapter, alert_id)
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
        investigation_id = await _ended(store, adapter, alert_id, stage=status,
                                        failure_reason=None if status in {"completed", "unparseable"} else "worker_error")
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
    await store.finish(A, queued.investigation_id, stage="completed", disposition="benign", cost_usd=1.0)
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

    investigation_id = await _ended(store, adapter, await _alert(store, A, "T-1"), disposition="benign", cost_usd=1.0)
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

