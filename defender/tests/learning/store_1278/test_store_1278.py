"""#1278 sketch: the learning store's own promises, driven through its verbs on a real PostgreSQL.

Findings dedup for good (O14 path), the claim that inserts a batch and marks its items in one call
(P2'), one working batch per lane (O3), a lapsed or stale holder changing nothing (O3, P6), the
active-tenant condition and cancel (O6 offboarding), and the per-tenant view (O2).
"""
from __future__ import annotations

import pytest

from defender.tests.support.jobs._jobs1342 import move_tenant, register_tenant
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    finding,
    lapse_lease,
    learning_store,
    store_mod,
)

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

BLUE = fixture_uuid("tenant:1278-blue")
GREEN = fixture_uuid("tenant:1278-green")


@pytest.fixture
def dsn(migrated_database):
    register_tenant(migrated_database, BLUE)
    register_tenant(migrated_database, GREEN)
    return migrated_database


async def _work(store, tenant):
    return {item.key: item for item in await store.work(tenant)}


async def test_flow1_a_finding_id_is_unique_for_good_past_its_claim_O14(dsn):
    """A republished finding id adds nothing, whether waiting or already claimed; a new id is queued. (O14, r8 work_items)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")])
        await store.publish_findings(BLUE, "run-1", [finding("f1")])
        assert [(i.key, i.status) for i in await store.work(BLUE)] == [("f1", "waiting")]

        claim = await store.claim(BLUE, AUTHOR_LANE, owner="host-a")
        await store.publish_findings(BLUE, "run-1", [finding("f1"), finding("f2")])

        items = await _work(store, BLUE)
        assert sorted(items) == ["f1", "f2"], items
        assert (items["f1"].status, items["f1"].batch_id) == ("in_batch", claim.batch_id)
        assert items["f2"].status == "waiting", "control: a new id is still queued"


async def test_p2_a_claim_inserts_its_batch_working_and_marks_its_items_in_it(dsn):
    """The claim alone leaves a working author batch holding the lane's waiting items. (P2', O3)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1"), finding("f2")])
        claim = await store.claim(BLUE, AUTHOR_LANE, owner="host-a")

        assert sorted(claim.items) == ["f1", "f2"]
        [batch] = await store.batches(BLUE)
        assert (batch.id, batch.lane, batch.kind, batch.phase) == (claim.batch_id, AUTHOR_LANE, "author", "working")
        assert {k: (i.status, i.batch_id) for k, i in (await _work(store, BLUE)).items()} == {
            "f1": ("in_batch", claim.batch_id), "f2": ("in_batch", claim.batch_id)}


async def test_o3_a_second_claim_on_a_lane_with_a_working_batch_is_refused(dsn):
    """One working batch per lane: the second claim is refused and inserts nothing; after release the lane claims again. (O3, H4)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")])
        first = await store.claim(BLUE, AUTHOR_LANE, owner="host-a")
        await store.publish_findings(BLUE, "run-2", [finding("f2")])

        with pytest.raises(store_mod().LaneBusy):
            await store.claim(BLUE, AUTHOR_LANE, owner="host-b")
        assert [b.id for b in await store.batches(BLUE)] == [first.batch_id]
        assert (await _work(store, BLUE))["f2"].status == "waiting"

        await store.release(first)
        second = await store.claim(BLUE, AUTHOR_LANE, owner="host-b")
        assert second.batch_id != first.batch_id
        assert sorted(second.items) == ["f1", "f2"], "control: a released lane claims again, its items returned"


async def test_p6_a_holder_past_its_lease_neither_renews_nor_changes_items(dsn):
    """After the lease lapses, renewal and the holder's release are refused and nothing moves; a takeover's token rules. (O3, P6)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")])
        claim = await store.claim(BLUE, AUTHOR_LANE, owner="host-a")
        await store.renew(claim)  # control: a live lease renews

        lapse_lease(dsn, claim.batch_id)
        with pytest.raises(S.Stop):
            await store.renew(claim)
        with pytest.raises(S.LeaseLost):
            await store.release(claim)
        [batch] = await store.batches(BLUE)
        assert batch.phase == "working"
        assert (await _work(store, BLUE))["f1"].batch_id == claim.batch_id

        taken = await store.take_over(BLUE, claim.batch_id, owner="host-b")
        assert taken.token != claim.token
        with pytest.raises(S.LeaseLost):
            await store.release(claim)
        await store.release(taken)
        assert (await _work(store, BLUE))["f1"].status == "waiting", "control: the live token's release returns the item"


async def test_o6_a_tenant_off_active_gets_no_batch_and_its_working_batch_is_told_to_stop(dsn):
    """Off active, the claim inserts nothing; cancel on a working batch makes its renewal a stop. (O6, Offboarding)"""
    S = store_mod()
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")])
        await store.publish_findings(GREEN, "run-2", [finding("g1")])
        working = await store.claim(GREEN, AUTHOR_LANE, owner="host-a")  # control: an active tenant claims

        move_tenant(dsn, BLUE, state="offboarding")
        with pytest.raises(S.TenantInactive):
            await store.claim(BLUE, AUTHOR_LANE, owner="host-a")
        assert await store.batches(BLUE) == []
        assert (await _work(store, BLUE))["f1"].status == "waiting"

        await store.request_cancel(GREEN)
        [batch] = await store.batches(GREEN)
        assert batch.cancel_requested is True
        with pytest.raises(S.Stop):
            await store.renew(working)


async def test_o2_the_view_names_each_items_status_batch_and_pr_per_tenant(dsn):
    """Per tenant: each item's status, batch and PR; another tenant's items never show. (O2, O6)"""
    async with learning_store(dsn) as store:
        await store.publish_findings(BLUE, "run-1", [finding("f1")])
        await store.publish_findings(GREEN, "run-2", [finding("g1")])
        claim = await store.claim(BLUE, AUTHOR_LANE, owner="host-a")
        await store.in_review(claim, pr_number=7)

        blue = await store.work(BLUE)
        assert [(i.kind, i.key, i.status, i.batch_id, i.pr_number) for i in blue] == [
            ("finding", "f1", "in_batch", claim.batch_id, 7)]
        assert [(i.key, i.status, i.batch_id, i.pr_number) for i in await store.work(GREEN)] == [
            ("g1", "waiting", None, None)]
