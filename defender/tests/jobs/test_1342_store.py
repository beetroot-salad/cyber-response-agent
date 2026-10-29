"""#1342 the job store over PostgreSQL: tables and their rules (O1), the trusted alert insert (O2),
create's replay rules (O3), the claim (O4), cancel (O9), delete (O10) and audit after commit (O13).

Entry: `defender.jobs.JobStore(dsn, clock=)` on a per-test migrated database; rows are read back on a
separate connection. Rows the store has no A-path for (an attempt 2, a terminal stage) are planted by
SQL, as B and the worker would leave them."""
from __future__ import annotations

import asyncio
import uuid

import pytest

from defender.tests.support.jobs._jobs1342 import (
    ALERT_BYTES,
    NOW,
    T1,
    T2,
    JobsAudit,
    VisibleAtEmit,
    an_alert,
    job_store,
    register_tenant,
    row,
)
from defender.tests.support.shared._pglocks1339 import fetch
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


@pytest.fixture
def dsn(migrated_database: str) -> str:
    register_tenant(migrated_database, T1)
    register_tenant(migrated_database, T2)
    return migrated_database


def _plant_investigation(dsn: str, *, tenant: str, alert_id: str, key: str, attempt: int,
                         stage: str) -> str:
    investigation_id = str(uuid.uuid4())
    execute(dsn, "INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, "
                 "stage, created_at, cost_usd) VALUES (%s, %s, %s, %s, %s, %s, %s, 0)",
            (investigation_id, tenant, alert_id, key, attempt, stage, NOW))
    return investigation_id


def _set_stage(dsn: str, investigation_id: str, stage: str) -> None:
    execute(dsn, "UPDATE jobs.investigations SET stage = %s WHERE id = %s", (stage, investigation_id))


# --- O1 ------------------------------------------------------------------------------------------

async def test_o1_the_database_allows_one_live_investigation_per_alert(dsn):
    """A second queued row for one alert is refused by the database; a terminal one is not. (O1)"""
    import psycopg

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
    _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=1, stage="queued")
    _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k0", attempt=1, stage="completed")

    with pytest.raises(psycopg.errors.UniqueViolation):
        _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k2", attempt=1,
                             stage="running")


async def test_o1_an_investigation_cannot_point_at_another_tenants_alert(dsn):
    """The `(tenant, alert)` foreign key refuses a cross-tenant reference. (O1)"""
    import psycopg

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
    _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=1, stage="queued")

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        _plant_investigation(dsn, tenant=T2, alert_id=alert.alert_id, key="k1", attempt=1,
                             stage="queued")


def test_o1_the_store_loads_nothing_the_api_must_not():
    """`defender.jobs` loads without the runtime, so the API can load it. (O1, packages)"""
    from defender.tests.api.test_1080_api_loads import _loaded
    from defender.tests.tooling.layout_contracts._spec1080 import api_forbidden

    loaded = _loaded("defender.jobs")
    assert "defender.jobs" in loaded, "premise: the probe imported the store"
    assert api_forbidden(loaded) == []


# --- O2 ------------------------------------------------------------------------------------------

async def test_o2_an_alert_round_trips_its_exact_bytes(dsn):
    """The stored and the read raw alert are the inserted bytes, byte for byte. (O2)"""
    async with job_store(dsn) as store:
        inserted = await an_alert(store, T1)
        read = await store.get_alert(T1, inserted.alert_id)

    assert read.raw == ALERT_BYTES
    [(stored,)] = execute(dsn, "SELECT raw FROM jobs.alerts WHERE id = %s", (inserted.alert_id,))
    assert bytes(stored) == ALERT_BYTES
    assert (read.title, read.description) == (inserted.title, inserted.description)


async def test_o2_bytes_admit_refuses_store_nothing(dsn):
    """`admit()`'s refusal reaches the caller and leaves the table empty. (O2)"""
    from defender.records.formats import AlertRefused

    async with job_store(dsn) as store:
        with pytest.raises(AlertRefused):
            await an_alert(store, T1, raw=b"[1, 2]")
        assert execute(dsn, "SELECT count(*) FROM jobs.alerts") == [(0,)]
        await an_alert(store, T1)  # positive control on the same path
    assert execute(dsn, "SELECT count(*) FROM jobs.alerts") == [(1,)]


# --- O3 ------------------------------------------------------------------------------------------

async def test_o3_a_first_request_queues_attempt_one(dsn):
    """A new request key inserts attempt 1, `queued`, `created=True`. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert created is True
    assert (inv.request_key, inv.attempt, inv.stage, inv.alert_id) == ("k1", 1, "queued", alert.alert_id)
    assert row(dsn, inv.investigation_id)["stage"] == "queued"


async def test_o3_a_replayed_request_returns_its_latest_attempt(dsn):
    """A replay answers the highest attempt under its key, `created=False`. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        first, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        _set_stage(dsn, first.investigation_id, "failed")
        retry = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=2,
                                     stage="queued")

        again, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert created is False
    assert (again.investigation_id, again.attempt) == (retry, 2)


async def test_o3_a_new_request_on_a_live_alert_gets_the_live_one_and_its_key_is_not_kept(dsn):
    """Collapsed onto the live investigation; after that one ends, the same key starts a new one. (O3)"""
    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        live, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

        collapsed, created = await store.create_investigation(T1, alert.alert_id, "k2", actor="u-2")
        assert (collapsed.investigation_id, collapsed.request_key, created) == (
            live.investigation_id, "k1", False)

        _set_stage(dsn, live.investigation_id, "completed")
        fresh, created = await store.create_investigation(T1, alert.alert_id, "k2", actor="u-2")

    assert created is True
    assert fresh.investigation_id != live.investigation_id
    assert (fresh.request_key, fresh.attempt) == ("k2", 1)


async def test_o3_an_alert_this_tenant_lacks_is_an_unknown_reference(dsn):
    """Another tenant's alert id is `UnknownReference`, and nothing is inserted. (O3)"""
    from defender.jobs import UnknownReference

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        with pytest.raises(UnknownReference):
            await store.create_investigation(T2, alert.alert_id, "k1", actor="u-1")
    assert execute(dsn, "SELECT count(*) FROM jobs.investigations") == [(0,)]


# --- O4 ------------------------------------------------------------------------------------------

async def test_o4_two_claims_race_one_queued_row_and_exactly_one_wins(dsn):
    """Two stores (two pools) claim at once: one gets the row, `running` with `started_at`. (O4)"""
    async with job_store(dsn) as setup:
        alert = await an_alert(setup, T1)
        inv, _ = await setup.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    async with job_store(dsn) as a, job_store(dsn) as b:
        got = await asyncio.gather(a.claim(), b.claim())

    winners = [g for g in got if g is not None]
    assert [w.investigation_id for w in winners] == [inv.investigation_id]
    stored = row(dsn, inv.investigation_id)
    assert (stored["stage"], stored["started_at"]) == ("running", NOW)


async def test_o4_a_row_locked_elsewhere_is_skipped_not_waited_for(dsn):
    """`SKIP LOCKED`: while another transaction holds the only queued row, claim returns nothing at once. (O4)"""
    import psycopg

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            await conn.execute("SELECT id FROM jobs.investigations WHERE id = %s FOR UPDATE",
                               (inv.investigation_id,))
            assert await asyncio.wait_for(store.claim(), timeout=5) is None
            await conn.commit()
        claimed = await store.claim()
    assert claimed is not None
    assert claimed.investigation_id == inv.investigation_id


# --- O9 ------------------------------------------------------------------------------------------

async def test_o9_cancel_aborts_queued_and_refuses_running_and_ended(dsn):
    """queued → `aborted`/`cancelled`; running → "not yet"; terminal → "already ended". (O9)"""
    from defender.jobs import Conflict

    async with job_store(dsn) as store:
        a1 = await an_alert(store, T1, ticket="T-1")
        a2 = await an_alert(store, T1, ticket="T-2")
        queued, _ = await store.create_investigation(T1, a1.alert_id, "k1", actor="u-1")
        running, _ = await store.create_investigation(T1, a2.alert_id, "k2", actor="u-1")
        _set_stage(dsn, running.investigation_id, "running")

        cancelled = await store.cancel_investigation(T1, queued.investigation_id, actor="u-1")
        with pytest.raises(Conflict, match="cannot cancel a running investigation yet"):
            await store.cancel_investigation(T1, running.investigation_id, actor="u-1")
        with pytest.raises(Conflict, match="already ended"):
            await store.cancel_investigation(T1, queued.investigation_id, actor="u-1")

    assert (cancelled.stage, cancelled.failure_reason) == ("aborted", "cancelled")
    assert row(dsn, queued.investigation_id)["stage"] == "aborted"
    assert row(dsn, running.investigation_id)["stage"] == "running"


# --- O10 -----------------------------------------------------------------------------------------

async def test_o10_delete_removes_every_attempt_and_a_replay_starts_afresh(dsn):
    """Refused while any attempt is live; then every attempt goes, and the key mints a new attempt 1. (O10)"""
    from defender.jobs import Conflict, NotFound

    async with job_store(dsn) as store:
        alert = await an_alert(store, T1)
        first, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
        _set_stage(dsn, first.investigation_id, "failed")
        retry = _plant_investigation(dsn, tenant=T1, alert_id=alert.alert_id, key="k1", attempt=2,
                                     stage="queued")

        with pytest.raises(Conflict):
            await store.delete_investigation(T1, first.investigation_id, actor="u-1")
        assert row(dsn, first.investigation_id) is not None

        _set_stage(dsn, retry, "failed")
        await store.delete_investigation(T1, first.investigation_id, actor="u-1")
        assert execute(dsn, "SELECT count(*) FROM jobs.investigations WHERE request_key = 'k1'") == [(0,)]

        with pytest.raises(NotFound):
            await store.delete_investigation(T1, first.investigation_id, actor="u-1")
        again, created = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")

    assert created is True
    assert again.investigation_id not in {first.investigation_id, retry}
    assert again.attempt == 1


# --- O13 -----------------------------------------------------------------------------------------

async def test_o13_create_cancel_delete_are_audited_after_commit_with_the_caller(dsn, caplog):
    """Each event names the calling actor and is emitted once the row change is visible elsewhere. (O13)"""
    import logging

    audit = JobsAudit(caplog)
    seen = VisibleAtEmit(dsn)
    logging.getLogger("defender.jobs.audit").addHandler(seen)
    try:
        async with job_store(dsn) as store:
            alert = await an_alert(store, T1)
            inv, _ = await store.create_investigation(T1, alert.alert_id, "k1", actor="u-1")
            await store.cancel_investigation(T1, inv.investigation_id, actor="u-2")
            await store.delete_investigation(T1, inv.investigation_id, actor="u-3")
    finally:
        logging.getLogger("defender.jobs.audit").removeHandler(seen)

    assert [(e.action, e.actor, e.tenant_id, e.target) for e in audit.events()] == [
        ("investigation.start", "u-1", T1, inv.investigation_id),
        ("investigation.cancel", "u-2", T1, inv.investigation_id),
        ("investigation.delete", "u-3", T1, inv.investigation_id),
    ]
    assert seen.seen == [("investigation.start", "queued"), ("investigation.cancel", "aborted"),
                         ("investigation.delete", None)]


async def test_o13_a_refused_create_emits_nothing(dsn, caplog):
    """No commit, no event: an unknown alert leaves the audit log empty. (O13)"""
    from defender.jobs import UnknownReference

    audit = JobsAudit(caplog)
    async with job_store(dsn) as store:
        with pytest.raises(UnknownReference):
            await store.create_investigation(T1, str(uuid.uuid4()), "k1", actor="u-1")
    assert audit.events() == []
    assert await fetch(dsn, "SELECT count(*) FROM jobs.investigations") == [(0,)]
