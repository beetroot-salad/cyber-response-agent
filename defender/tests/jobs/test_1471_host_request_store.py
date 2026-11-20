"""#1471 slice A, the store: `jobs.host_requests` as the one table of readiness and adoption (R1, A1, B1, B2, R13-5, R13-6
claim order), over a real database. Names are `test-surface.md` §3-§4. Postgres-gated."""
from __future__ import annotations

import datetime as dt

import psycopg
import pytest

from defender.jobs.store import is_refusal
from defender.records.job_facts import OFFBOARD_MESSAGE
from defender.tests.support.jobs._host_requests1471 import (
    host_row,
    host_rows,
    ids_of,
    lapse,
    plant,
)
from defender.tests.support.jobs._jobs1342 import NOW, T1, T2, JobsAudit, job_store, move_tenant, register_tenant
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

SYSTEM = "ticket"


@pytest.fixture
def world(migrated_database: str) -> str:
    register_tenant(migrated_database, T1)
    register_tenant(migrated_database, T2)
    return migrated_database


# --- R1, A1: start and dedupe -------------------------------------------------------------------------------------------

async def test_r1_a_readiness_start_stores_a_queued_row_with_its_requester_and_announces_it_once(world, caplog):
    """A new readiness request is one queued row naming tenant, kind and requester, announced `readiness.start`. (R1)"""
    audit = JobsAudit(caplog)
    async with job_store(world) as store:
        record, created = await store.create_readiness(T1, actor="u-1")
    assert created is True
    row = host_row(world, record.request_id)
    assert (row["tenant_id"], row["kind"], row["stage"], row["requester"], row["system_id"]) == (
        T1, "readiness", "queued", "u-1", None)
    assert row["created_at"] is not None
    assert (row["result"], row["failure_reason"], row["started_at"], row["finished_at"]) == (None, None, None, None)
    assert [(e.action, e.actor, e.tenant_id, e.target) for e in audit.events()] == [
        ("readiness.start", "u-1", T1, record.request_id)]
    assert (record.kind, record.stage, record.tenant_id) == ("readiness", "queued", T1)


async def test_r1_a_second_start_while_one_is_queued_returns_that_one_and_makes_no_row_and_no_event(world, caplog):
    """Two readiness requests while queued give one id, one row, one start event, and the first requester. (R1, N4)"""
    audit = JobsAudit(caplog)
    async with job_store(world) as store:
        first, c1 = await store.create_readiness(T1, actor="u-1")
        again, c2 = await store.create_readiness(T1, actor="u-2")
    assert (c1, c2) == (True, False)
    assert again.request_id == first.request_id
    assert ids_of(world) == [first.request_id]
    assert host_row(world, first.request_id)["requester"] == "u-1"
    assert [e.action for e in audit.events()] == ["readiness.start"]


async def test_r1_a_running_request_does_not_dedupe_and_the_queued_one_then_does(world):
    """While one runs, a start queues a new one; a further start returns that queued one. (R1)"""
    async with job_store(world) as store:
        first, _ = await store.create_readiness(T1, actor="u-1")
        claimed = await store.claim_host_request()
        assert claimed.record.request_id == first.request_id
        second, c2 = await store.create_readiness(T1, actor="u-1")
        third, c3 = await store.create_readiness(T1, actor="u-1")
    assert (c2, c3) == (True, False)
    assert second.request_id not in (first.request_id,)
    assert third.request_id == second.request_id
    assert [(r["id"], r["stage"]) for r in host_rows(world)] == [(first.request_id, "running"),
                                                                 (second.request_id, "queued")]


@pytest.mark.parametrize("ended", ["completed", "failed"])
async def test_r1_a_finished_request_never_dedupes(world, ended):
    """After a request ends, the next start is a new queued row. (R1, B2)"""
    plant(world, T1, "readiness", stage=ended,
          reason=None if ended == "completed" else "worker_error", message=None if ended == "completed" else "x")
    async with job_store(world) as store:
        record, created = await store.create_readiness(T1, actor="u-1")
    assert created is True
    assert len(host_rows(world)) == 2
    assert host_row(world, record.request_id)["stage"] == "queued"


async def test_r1_readiness_dedupes_per_tenant_only(world):
    """Another tenant's queued request is not this tenant's: each gets its own row. (R1)"""
    async with job_store(world) as store:
        one, _ = await store.create_readiness(T1, actor="u-1")
        two, created = await store.create_readiness(T2, actor="u-1")
    assert created is True
    assert one.request_id != two.request_id
    assert sorted(r["tenant_id"] for r in host_rows(world)) == sorted([T1, T2])


async def test_a1_an_adoption_dedupes_on_tenant_and_system_and_records_the_system_in_its_event(world, caplog):
    """Same (tenant, system) while queued is one row; another system, another tenant and readiness are not it. (A1)"""
    audit = JobsAudit(caplog)
    async with job_store(world) as store:
        first, c1 = await store.create_adoption(T1, SYSTEM, actor="u-1")
        again, c2 = await store.create_adoption(T1, SYSTEM, actor="u-2")
        other_system, c3 = await store.create_adoption(T1, "elastic", actor="u-1")
        other_tenant, c4 = await store.create_adoption(T2, SYSTEM, actor="u-1")
        readiness, c5 = await store.create_readiness(T1, actor="u-1")
    assert (c1, c2, c3, c4, c5) == (True, False, True, True, True)
    assert again.request_id == first.request_id
    assert len({first.request_id, other_system.request_id, other_tenant.request_id, readiness.request_id}) == 4
    row = host_row(world, first.request_id)
    assert (row["kind"], row["system_id"], row["requester"]) == ("adoption", SYSTEM, "u-1")
    starts = [(e.action, e.target, e.detail) for e in audit.events() if e.action == "adoption.start"]
    assert (("adoption.start", first.request_id, f"system {SYSTEM}")) in starts
    assert len(starts) == 3


async def test_a1_a_running_adoption_does_not_dedupe(world):
    """A start while the same system's adoption runs queues a new one. (A1)"""
    async with job_store(world) as store:
        first, _ = await store.create_adoption(T1, SYSTEM, actor="u-1")
        await store.claim_host_request()
        second, created = await store.create_adoption(T1, SYSTEM, actor="u-1")
    assert created is True
    assert second.request_id != first.request_id


@pytest.mark.parametrize("state", ["offboarding", "offboarded"])
@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r1_a_start_for_a_tenant_being_removed_is_refused_and_makes_no_row(world, state, kind):
    """A tenant offboarding or offboarded takes no request: a refusal the API answers 409, nothing stored or announced. (R1, A1)"""
    move_tenant(world, T1, state=state)
    async with job_store(world) as store:
        starting = store.create_readiness(T1, actor="u-1") if kind == "readiness" else store.create_adoption(T1, SYSTEM, actor="u-1")
        with pytest.raises(Exception) as refused:  # noqa: PT011 — the store's own refusal type, told by `is_refusal`
            await starting
    assert is_refusal(refused.value) or type(refused.value).__name__ == "Conflict"
    assert host_rows(world) == []


@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_r1_a_start_for_a_creating_tenant_is_accepted_and_queued(world, kind):
    """A `creating` tenant's request is queued like any (surface §9 addendum 1). (R1, A1)"""
    move_tenant(world, T1, state="creating")
    async with job_store(world) as store:
        record, created = await (store.create_readiness(T1, actor="u-1") if kind == "readiness"
                                 else store.create_adoption(T1, SYSTEM, actor="u-1"))
    assert created is True
    assert host_row(world, record.request_id)["stage"] == "queued"


# --- reads --------------------------------------------------------------------------------------------------------------

async def test_r2_a_row_is_read_only_by_its_tenant_and_kind(world):
    """`get_host_request` answers None for another tenant, the other kind and an unknown id. (R2)"""
    async with job_store(world) as store:
        r, _ = await store.create_readiness(T1, actor="u-1")
        a, _ = await store.create_adoption(T1, SYSTEM, actor="u-1")
        assert (await store.get_host_request(T1, r.request_id, kind="readiness")).request_id == r.request_id
        assert (await store.get_host_request(T1, a.request_id, kind="adoption")).request_id == a.request_id
        assert await store.get_host_request(T2, r.request_id, kind="readiness") is None
        assert await store.get_host_request(T1, r.request_id, kind="adoption") is None
        assert await store.get_host_request(T1, a.request_id, kind="readiness") is None
        assert await store.get_host_request(T1, "00000000-0000-4000-8000-000000000000", kind="readiness") is None


# --- the table's own constraints, by real inserts -----------------------------------------------------------------------

async def test_the_database_refuses_a_second_queued_row_for_one_kind_and_key_but_not_a_running_one(world):
    """At most one queued row per (kind, dedupe key): a real second queued insert is a unique violation; a running or
    finished row of the same key, a queued row of another kind or key insert. (§7)"""
    plant(world, T1, "readiness")
    with pytest.raises(psycopg.errors.UniqueViolation):
        plant(world, T1, "readiness")
    plant(world, T1, "readiness", stage="running")
    plant(world, T1, "readiness", stage="completed")
    plant(world, T2, "readiness")
    plant(world, T1, "adoption", system=SYSTEM)
    with pytest.raises(psycopg.errors.UniqueViolation):
        plant(world, T1, "adoption", system=SYSTEM)
    plant(world, T1, "adoption", system="elastic")
    assert len(host_rows(world)) == 6


async def test_the_database_refuses_an_unknown_stage_and_a_running_row_without_a_lease(world):
    """The stage is one of the four; a running row holds a lease. (§7)"""
    with pytest.raises(psycopg.errors.CheckViolation):
        plant(world, T1, "readiness", stage="paused")
    with pytest.raises(psycopg.errors.CheckViolation):
        execute(world, "INSERT INTO jobs.host_requests (id, tenant_id, kind, dedupe_key, requester, created_at, stage) "
                       "VALUES (gen_random_uuid(), %s, 'readiness', 'k', 'u', now(), 'running')", (T1,))


# --- R13-6: one claim, oldest first across kinds ------------------------------------------------------------------------

async def test_r13_6_claim_takes_the_oldest_queued_row_of_any_kind_and_marks_it_running_with_a_lease(world, caplog):
    """Claims go oldest first across both kinds; the claim carries the kind and the tenant's state, sets stage, start and
    lease, and is announced; nothing queued answers None. (R13-6)"""
    audit = JobsAudit(caplog)
    older = plant(world, T1, "adoption", system=SYSTEM, created=NOW - dt.timedelta(minutes=3))
    middle = plant(world, T2, "readiness", created=NOW - dt.timedelta(minutes=2))
    newest = plant(world, T1, "readiness", created=NOW - dt.timedelta(minutes=1))
    async with job_store(world) as store:
        first = await store.claim_host_request()
        assert (first.record.request_id, first.record.kind, first.record.system_id, first.tenant_state) == (
            older, "adoption", SYSTEM, "active")
        assert [(await store.claim_host_request()).record.request_id for _ in range(2)] == [middle, newest]
        assert await store.claim_host_request() is None
    row = host_row(world, older)
    assert row["stage"] == "running"
    assert row["started_at"] is not None
    assert row["lease_expires_at"] is not None
    assert [(e.action, e.target) for e in audit.events() if e.action.endswith(".claim")] == [
        ("adoption.claim", older), ("readiness.claim", middle), ("readiness.claim", newest)]


async def test_r13_6_claiming_a_host_request_never_takes_a_running_row(world):
    """Only queued host-request rows are claimed. (R13-6)"""
    plant(world, T1, "readiness", stage="running")
    async with job_store(world) as store:
        assert await store.claim_host_request() is None


# --- the fenced finish --------------------------------------------------------------------------------------------------

async def test_the_finish_is_fenced_on_running_and_stores_the_result_once(world, caplog):
    """A running row finishes `completed` with its result, announced; a second finish, and a finish of a queued row,
    change nothing and answer None. (B2)"""
    audit = JobsAudit(caplog)
    result = {"outcome": "refused", "step": "tenant", "sentence": "the tenant is not active", "knowledge": None}
    async with job_store(world) as store:
        queued, _ = await store.create_readiness(T2, actor="u-1")
        assert await store.finish_host_request(T2, queued.request_id, stage="completed", result=result) is None
        running, _ = await store.create_readiness(T1, actor="u-1")
        await store.claim_host_request()
        ended = await store.finish_host_request(T1, running.request_id, stage="completed", result=result)
        again = await store.finish_host_request(T1, running.request_id, stage="failed", failure_reason="worker_error",
                                                failure_message="late")
    assert ended.stage == "completed"
    assert again is None
    row = host_row(world, running.request_id)
    assert (row["stage"], row["result"], row["failure_reason"], row["lease_expires_at"]) == ("completed", result, None, None)
    assert row["finished_at"] is not None
    assert host_row(world, queued.request_id)["stage"] == "queued"
    assert [e.action for e in audit.events() if e.action.endswith(".finish")] == ["readiness.finish"]


async def test_a_failed_finish_stores_its_reason_and_words_and_no_result(world):
    """`failed` carries a fixed reason and our words. (R3, P-3)"""
    async with job_store(world) as store:
        rec, _ = await store.create_adoption(T1, SYSTEM, actor="u-1")
        await store.claim_host_request()
        await store.finish_host_request(T1, rec.request_id, stage="failed", failure_reason="repository_busy",
                                        failure_message="a ref lock collided")
    row = host_row(world, rec.request_id)
    assert (row["stage"], row["failure_reason"], row["failure_message"], row["result"]) == (
        "failed", "repository_busy", "a ref lock collided", None)


# --- B1: offboarding ----------------------------------------------------------------------------------------------------

async def test_b1_offboarding_ends_live_rows_of_both_kinds_failed_tenant_offboarded_and_deletes_none(world, caplog):
    """Queued and running rows of both kinds end `failed`/`tenant_offboarded` with the offboard words, lease cleared and
    finish time set, each announced; a finished row and another tenant's are untouched; no row is deleted. (B1)"""
    q_r = plant(world, T1, "readiness")
    r_a = plant(world, T1, "adoption", system=SYSTEM, stage="running")
    done = plant(world, T1, "readiness", stage="completed")
    other = plant(world, T2, "readiness")
    before = {r["id"]: r for r in host_rows(world)}
    audit = JobsAudit(caplog)
    async with job_store(world) as store:
        await store.offboard_tenant(T1, actor="op-1")
    after = {r["id"]: r for r in host_rows(world)}
    assert set(after) == set(before), "a row was deleted or made"
    for rid in (q_r, r_a):
        row = after[rid]
        assert (row["stage"], row["failure_reason"], row["failure_message"], row["lease_expires_at"]) == (
            "failed", "tenant_offboarded", OFFBOARD_MESSAGE, None)
        assert row["finished_at"] is not None
        assert row["result"] is None
    assert after[done] == before[done]
    assert after[other] == before[other]
    ended = {(e.action, e.target, e.detail) for e in audit.events() if e.action.endswith(".finish")}
    assert ended == {("readiness.finish", q_r, "status=failed reason=tenant_offboarded"),
                     ("adoption.finish", r_a, "status=failed reason=tenant_offboarded")}


# --- B2, R13-5: take-over never retries ---------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["readiness", "adoption"])
async def test_b2_a_lapsed_running_row_is_taken_over_failed_worker_lost_with_no_retry(world, kind, caplog):
    """A lapsed host request ends `failed`/`worker_lost`; no queued row is made; the row never goes back to queued; the
    take-over is announced; a row in the held set and one whose lease stands are left alone. (B2, R13-5)"""
    system = SYSTEM if kind == "adoption" else None
    lost = plant(world, T1, kind, system=system, stage="running")
    held = plant(world, T2, kind, system=system, stage="running")
    live = plant(world, T1, kind, system="elastic" if system else None, stage="running")
    for rid in (lost, held):
        lapse(world, rid)
    held_before = host_row(world, held)
    audit = JobsAudit(caplog)
    async with job_store(world) as store:
        taken = await store.take_over(held=frozenset({held}))
        again = await store.take_over(held=frozenset({held}))
    assert taken == [lost]
    assert again == []
    row = host_row(world, lost)
    assert (row["stage"], row["failure_reason"]) == ("failed", "worker_lost")
    assert row["failure_message"]
    assert row["finished_at"] is not None
    assert host_row(world, held) == held_before
    assert host_row(world, live)["stage"] == "running"
    assert [r["stage"] for r in host_rows(world)].count("queued") == 0
    assert [(e.action, e.target, e.detail) for e in audit.events() if e.action.endswith(".takeover")] == [
        (f"{kind}.takeover", lost, "reason=worker_lost")]


async def test_b2_a_worker_lost_row_is_never_claimed_again(world):
    """A taken-over row stays failed: the next claim finds nothing. (B2)"""
    async with job_store(world) as store:
        rec, _ = await store.create_readiness(T1, actor="u-1")
        await store.claim_host_request()
        lapse(world, rec.request_id)
        await store.take_over()
        assert await store.claim_host_request() is None
    assert host_row(world, rec.request_id)["stage"] == "failed"
