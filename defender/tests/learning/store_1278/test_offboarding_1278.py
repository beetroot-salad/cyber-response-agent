"""#1278 O6 and Offboarding: a tenant off active gets no new learning work, its working batches are told to stop and
are ended when their lease lapses, and its rows are purged at the end; another tenant's are never touched.

The store verbs on a real PostgreSQL. The last cases run the lifecycle's offboarding (`LifecycleWorld`) with the
learning store found at `DEFENDER_DATABASE_DSN` (interface request: the host actor's `teardown` step does the
cancel, the wait within `teardown_wait` and the purge).
"""
from __future__ import annotations

import contextlib
import threading
import time

import pytest

from defender.tests.support.jobs._jobs1342 import move_tenant, register_tenant
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE, DSN_ENV, LEAD_LANE, ONE, changes_of, finding, lapse_lease, learning_store, oid, store_mod, world_finding)
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1278-off-blue")
GREEN = fixture_uuid("tenant:1278-off-green")


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


async def _items(store, tenant):
    return {(i.kind, i.key): i for i in await store.work(tenant)}


def _pitfall(pid: str) -> dict:
    return {"schema_version": 1, "pitfall_id": pid, "source_run": "r", "system": "elastic", "query_id": "elastic.esql",
            "goal": "g", "executed_query": "x", "stderr_digest": f"exit=1; {pid}", "error_class": "agent-fixable"}


# --- a tenant off active takes on nothing new -----------------------------------------------------------------------


@pytest.mark.parametrize("state", ["offboarding", "offboarded"])
async def test_o6_a_tenant_off_active_takes_no_new_batch_and_no_published_findings(dsn, state):
    """Off active: the claim and the revert claim insert no batch, a findings publish inserts no row, and the tenant's
    waiting items stay as they were; an active tenant beside it still works. (O6, Offboarding, D11a)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        await store.publish_findings(GREEN, "run-1", [finding("g1")], kind="finding")
        move_tenant(dsn, BLUE, state=state)

        with pytest.raises(S.TenantInactive):
            await store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ONE)
        with pytest.raises(S.TenantInactive):
            await store.claim_revert(BLUE, owner="cli")
        with pytest.raises(S.TenantInactive):
            await store.publish_findings(BLUE, "run-2", [finding("f2")], kind="finding")
        with pytest.raises(S.TenantInactive):
            await store.publish_findings(BLUE, "run-2", [world_finding("q2")], kind="questioner_finding")

        assert await store.batches(BLUE) == []
        assert sorted(await _items(store, BLUE)) == [("finding", "f1")], "a refused publish inserted a row"
        assert (await _items(store, BLUE))[("finding", "f1")].status == "waiting"
        assert await store.claim(GREEN, AUTHOR_LANE, owner="host-a", thresholds=ONE) is not None


# --- cancel -----------------------------------------------------------------------------------------------------------


async def test_o6_cancel_is_set_on_the_tenants_working_batches_and_no_other(dsn):
    """`request_cancel` marks the tenant's working batch; its author batch already in review and another tenant's
    working batch are left alone; the working holder's next renewal is a stop. (Offboarding, O3)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        reviewed = await store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ONE)
        await store.in_review(reviewed, 7, {})
        await store.add_pitfall(BLUE, _pitfall("p1"))
        working = await store.claim(BLUE, LEAD_LANE, owner="host-a", thresholds=ONE)
        await store.publish_findings(GREEN, "run-1", [finding("g1")], kind="finding")
        other = await store.claim(GREEN, AUTHOR_LANE, owner="host-b", thresholds=ONE)

        await store.request_cancel(BLUE)

        flags = {b.id: b.cancel_requested for t in (BLUE, GREEN) for b in await store.batches(t)}
        assert flags == {reviewed.batch_id: False, working.batch_id: True, other.batch_id: False}
        with pytest.raises(S.Stop):
            await store.renew(working)
        await store.renew(other)  # control: another tenant's holder goes on


async def test_o6_a_holder_told_to_stop_that_stops_cleanly_costs_its_items_nothing(dsn):
    """The holder that sees the cancel as a stop and abandons cleanly leaves its items waiting with no attempt counted,
    and the batch ended. (Offboarding, D8)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        claim = await store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ONE)
        await store.request_cancel(BLUE)
        with pytest.raises(S.Stop):
            await store.renew(claim)

        await store.abandon_clean(claim)

        [batch] = await store.batches(BLUE)
        item = (await _items(store, BLUE))[("finding", "f1")]
        assert (batch.phase, batch.outcome) == ("ended", "abandoned")
        assert (item.status, item.attempts) == ("waiting", 0)


async def test_o6_a_batch_whose_lease_lapsed_is_ended_by_the_offboarding_itself(dsn):
    """A holder that never answers the cancel is ended by recovery once its lease lapses: the batch ended, nothing left in
    the batch. (Offboarding, D8 invariant)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")], kind="finding")
        claim = await store.claim(BLUE, AUTHOR_LANE, owner="lost-host", thresholds=ONE)
        await store.request_cancel(BLUE)
        lapse_lease(dsn, claim.batch_id)

        await store.abandon(BLUE, claim.batch_id, by="recovery")

        [batch] = await store.batches(BLUE)
        assert batch.phase == "ended"
        assert all(i.status != "in_batch" for i in (await store.work(BLUE)))


# --- purge ------------------------------------------------------------------------------------------------------------


def _learning_rows_of(dsn: str, tenant: str) -> dict[str, int]:
    """Row counts of `tenant` in every `learning` table that carries a tenant id column: a census, so a table the
    purge forgets is found whatever its name."""
    tables = execute(dsn, "SELECT table_name FROM information_schema.columns WHERE table_schema = 'learning' "
                          "AND column_name = 'tenant_id'")
    counts = {name: execute(dsn, f"SELECT count(*) FROM learning.{name} WHERE tenant_id = %s", (tenant,))[0][0]
              for (name,) in tables}
    assert counts, "premise: the learning schema has tables that carry a tenant id"
    return counts


async def _populate(store, tenant: str, tag: str) -> object:
    """Items in every kind and state the tick leaves, batches working, in review and ended, and a commit record row."""
    await store.publish_findings(tenant, f"run-{tag}", [finding(f"{tag}-f1"), finding(f"{tag}-f2")], kind="finding")
    await store.publish_findings(tenant, f"run-{tag}", [world_finding(f"{tag}-q1")], kind="questioner_finding")
    await store.add_pitfall(tenant, _pitfall(f"{tag}-p1"))
    await store.enqueue_request(tenant, f"run-{tag}", f"case-{tag}", {"case": tag})
    authored = await store.claim(tenant, AUTHOR_LANE, owner="host-a", thresholds=ONE)
    await store.record_commit(authored, oid(1), oid(2), oid(3), changes_of(f"agent/lessons/{tag}.md"))
    await store.in_review(authored, 7, {})
    await store.publish_findings(tenant, f"run-{tag}", [finding(f"{tag}-f9")], kind="finding")
    working = await store.claim(tenant, LEAD_LANE, owner="host-a", thresholds=ONE)
    return working


async def test_o6_purge_removes_every_row_of_the_tenant_and_none_of_another(dsn):
    """After the offboarding's purge no learning table holds the tenant's rows; another tenant's rows are as they were;
    a holder of a purged batch is refused. (O6, Offboarding)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        gone = await _populate(store, BLUE, "b")
        await _populate(store, GREEN, "g")
        before = _learning_rows_of(dsn, GREEN)
        assert sum(_learning_rows_of(dsn, BLUE).values()) > 0
        green_view = ([(i.kind, i.key, i.status) for i in await store.work(GREEN)],
                      [(b.lane, b.phase) for b in await store.batches(GREEN)])

        await store.purge(BLUE)

        assert sum(_learning_rows_of(dsn, BLUE).values()) == 0, _learning_rows_of(dsn, BLUE)
        assert await store.work(BLUE) == []
        assert await store.batches(BLUE) == []
        assert await store.commit_record(BLUE) == []
        assert _learning_rows_of(dsn, GREEN) == before
        assert ([(i.kind, i.key, i.status) for i in await store.work(GREEN)],
                [(b.lane, b.phase) for b in await store.batches(GREEN)]) == green_view
        with pytest.raises(S.LeaseLost):
            await store.renew(gone)


# --- the lifecycle's offboarding drives all of it -------------------------------------------------------------------------


@pytest.fixture
def lifecycle(tmp_path, data_root, dsn, monkeypatch):
    """The lifecycle world (in-memory tenant twin) with the learning store of `dsn` found as the host actor finds it."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld

    world = LifecycleWorld(tmp_path, data_root)
    monkeypatch.setenv(DSN_ENV, dsn)
    yield world
    world.close()


def _offboard(world, dsn: str, tenant: str) -> None:
    """Ask for the offboarding and drive both actors to its end. The tenant's Postgres record moves off active, as the one
    record of production would at the request."""
    from defender.tests.tenancy.lifecycle_1214._job_cases import sample

    asked = world.ops.post(f"/admin/tenants/{tenant}/offboard")
    assert asked.status_code == 202, asked.text
    move_tenant(dsn, tenant, state="offboarding")
    sample(world, tenant)
    assert world.record(tenant).state == "offboarded"


def _seed_working(dsn: str, tenant: str):
    async def go():
        async with learning_store(dsn) as store:
            await store.publish_findings(tenant, "run-1", [finding("f1")], kind="finding")
            claim = await store.claim(tenant, AUTHOR_LANE, owner="host-a", thresholds=ONE)
            await store.record_commit(claim, oid(1), oid(2), oid(3), changes_of("agent/lessons/x.md"))
            return claim
    import anyio
    return anyio.run(go)


def test_offboarding_a_lapsed_batch_is_ended_and_the_tenants_rows_are_purged(lifecycle, dsn):
    """A batch whose holder is gone is ended by the offboarding itself and every row of the tenant is purged; the other
    tenant's work is untouched. (O6, Offboarding)"""
    world = lifecycle
    tenant = world.active_tenant()
    register_tenant(dsn, tenant)
    claim = _seed_working(dsn, tenant)
    lapse_lease(dsn, claim.batch_id)
    _seed_working(dsn, GREEN)  # GREEN is registered by the `dsn` fixture
    green_before = _learning_rows_of(dsn, GREEN)

    _offboard(world, dsn, tenant)

    assert sum(_learning_rows_of(dsn, tenant).values()) == 0
    assert _learning_rows_of(dsn, GREEN) == green_before


def test_offboarding_a_live_holder_is_told_to_stop_and_the_purge_waits_for_its_clean_stop(lifecycle, dsn):
    """A holder renewing its lease sees the cancel as a stop and abandons; only then are the rows purged, within the
    teardown wait. (O6, Offboarding, #1368)"""
    world = lifecycle
    tenant = world.active_tenant()
    register_tenant(dsn, tenant)
    claim = _seed_working(dsn, tenant)
    stopped = threading.Event()
    ended: list[str] = []

    def holder() -> None:
        import anyio

        async def run() -> None:
            S = store_mod()
            async with learning_store(dsn) as store:
                while not stopped.is_set():
                    try:
                        await store.renew(claim)
                    except S.LeaseLost:
                        return
                    except S.Stop:
                        await store.abandon_clean(claim)
                        ended.append("clean")
                        return
                    await anyio.sleep(0.05)
        anyio.run(run)

    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        _offboard(world, dsn, tenant)
        assert time.monotonic() - started < 30
    finally:
        stopped.set()
        thread.join(timeout=10)

    assert ended == ["clean"], "the holder never saw the cancel before its rows went"
    assert sum(_learning_rows_of(dsn, tenant).values()) == 0


def test_offboarding_a_live_holder_that_ignores_the_stop_past_the_time_limit_fails_the_step_and_nothing_is_purged(lifecycle, dsn, tmp_path, data_root):
    """A holder that keeps renewing through the cancel outlasts #1368's `teardown_wait`: the step fails and is retried, the rows
    stay; once the holder is gone and its lease lapsed, the retry ends the batch and purges. (G-T2, O6, #1368)"""
    from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config

    world = lifecycle
    world.host_actor = world.new_host(world.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=1.0))
    tenant = world.active_tenant()
    register_tenant(dsn, tenant)
    claim = _seed_working(dsn, tenant)
    stopped = threading.Event()

    def stubborn() -> None:
        import anyio

        async def run() -> None:
            S = store_mod()
            async with learning_store(dsn) as store:
                while not stopped.is_set():
                    try:
                        await store.renew(claim)
                    except S.Stop:
                        pass  # told to stop, carries on regardless
                    except S.LeaseLost:
                        return
                    await anyio.sleep(0.05)
        anyio.run(run)

    thread = threading.Thread(target=stubborn, daemon=True)
    thread.start()
    try:
        asked = world.ops.post(f"/admin/tenants/{tenant}/offboard")
        assert asked.status_code == 202, asked.text
        move_tenant(dsn, tenant, state="offboarding")
        with contextlib.suppress(Exception):  # a failing step is retried: the drive may give up or raise, the state tells
            world.drive(limit=8)
        assert world.record(tenant).state != "offboarded", "the offboarding finished under a live lease"
        assert sum(_learning_rows_of(dsn, tenant).values()) > 0, "rows purged under a live lease"
    finally:
        stopped.set()
        thread.join(timeout=10)

    lapse_lease(dsn, claim.batch_id)
    world.drive()
    assert world.record(tenant).state == "offboarded"
    assert sum(_learning_rows_of(dsn, tenant).values()) == 0
