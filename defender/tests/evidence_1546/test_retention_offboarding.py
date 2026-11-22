"""#1546 sketch (r6), flows "Retention sweep", "Offboarding pass" and "Retention rollout" (A-O5, A-O7, PR7).

Seams (missing):
- the lifecycle makes `evidence-<T>` (aes256-gcm96) and the tenant's evidence AppRole at prepare, beside the sign
  AppRole, and destroys both at offboarding beside the signing key; read off the twin's `FakeOpenBao`.
- `lifecycle.sweep_evidence(jobs=JobStore, blob=BlobStore)`: one pass of the retention sweep (database clock).
- `lifecycle.offboard_evidence(jobs=JobStore, blob=BlobStore, tenant_id=)`: the host step between `teardown` and
  `finish` (`lifecycle/_host.py:279-347`). FORCED CHOICE: the lifecycle host holds no blob store or jobs store today;
  how the step is handed them (the host's settings? a store key "with delete" for the lifecycle service).
"""
from __future__ import annotations

import uuid

import pytest

from defender.tests.evidence_1546._support import (
    RawS3,
    accepted,
    blob_store,
    claim_row,
    evidence_state,
    facts,
    insert_claim,
    object_key,
    stage_fact,
    stage_upload,
    uploads,
)
from defender.tests.support.jobs._jobs1342 import T1, T2, an_alert, job_store, register_tenant
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio]


# --- offboarding: the key and the AppRole ------------------------------------------------------------------------------

@pytest.fixture
def lifecycle_world(tmp_path, data_root, monkeypatch):
    from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld, learning_database

    with learning_database(monkeypatch):
        w = LifecycleWorld(tmp_path, data_root)
        yield w
        w.close()


def test_tenant_creation_makes_the_evidence_key_and_approle_and_offboarding_destroys_both(lifecycle_world):
    """Created: `evidence-<T>` is an aes256-gcm96 transit key, and one evidence AppRole of the tenant exists. Offboarded:
    neither is left. (A-O5; "a read after offboarding is refused" at the key layer)
    FORCED CHOICES: the AppRole's name (`evidence-<T>-<salt>` on the sign AppRole's pattern?), what a rotation does to
    it, and the backfill step for existing tenants (r6: "a lifecycle step backfills existing tenants": a pending
    action, or a step run on every resume?)."""
    from defender.tests.support.api._mount1161 import API

    world = lifecycle_world
    tenant = world.active_tenant()
    bao = world.openbao
    key = bao.transit_keys.get(f"evidence-{tenant}")
    assert key is not None, sorted(bao.transit_keys)
    assert key["type"] == "aes256-gcm96"
    roles = [name for name in bao.approles if name.startswith("evidence-") and tenant in name]
    assert len(roles) == 1, sorted(bao.approles)

    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.record(tenant).state == "offboarded"
    assert f"evidence-{tenant}" not in bao.transit_keys
    assert not [name for name in bao.approles if tenant in name and name.startswith("evidence-")]


# --- rows planted as the end transaction leaves them -------------------------------------------------------------------

async def _with_evidence(store, dsn: str, raw: RawS3, tenant: str, ticket: str, *, days_ago: int) -> tuple[str, str, str]:
    """A completed investigation of `tenant` whose bundle was accepted `days_ago` days ago (database clock), its object in
    the bucket; (owner, claim, key)."""
    alert = await an_alert(store, tenant, ticket=ticket)
    inv, _ = await store.create_investigation(tenant, alert.alert_id, f"k-{ticket}", actor="u-1")
    owner_id, claim = inv.investigation_id, uuid.uuid4().hex
    insert_claim(dsn, token=claim, tenant=tenant, kind="investigation", ref=owner_id)
    execute(dsn, "UPDATE jobs.investigations SET stage = 'completed', disposition = 'benign', finished_at = now(), "
                 "evidence_state = 'complete', scrub = 'clean', claim_token = %s WHERE id = %s", (claim, owner_id))
    key = object_key(tenant, "investigation", owner_id, claim, "bundle")
    raw.put(key, b"bundle")
    stage_upload(dsn, claim, "bundle", b"bundle")
    execute(dsn, "UPDATE jobs.uploads SET created_at = now() - make_interval(days => %s), "
                 "accepted_at = now() - make_interval(days => %s) WHERE token = %s", (days_ago, days_ago, claim))
    return owner_id, claim, key


def _retention(dsn: str, tenant: str, days: int) -> None:
    execute(dsn, "INSERT INTO tenancy.evidence_retention (tenant_id, investigation_days, learning_days) "
                 "VALUES (%s, %s, %s)", (tenant, days, days))


@pytest.mark.postgres
async def test_the_sweep_expires_past_each_tenants_setting_except_a_queued_learning_jobs_source(migrated_database):
    """T1 keeps evidence 30 days, T2 90; T3 has no retention row (release 1). Each has runs accepted 40 days ago.
    Swept: T1's run is `expired`, its object and upload rows gone; T1's run a queued learning job names keeps it
    (`complete`); T2's and T3's runs keep theirs. An unaccepted upload of a claim no longer live, 2 hours old, is gone;
    one of a live claim (its row running under an unexpired lease), as old, stays (PR7, 1-hour grace). (A-O7)
    FORCED CHOICE: whether `expired` replaces `lost` and `partial` too, or only `complete` (r6: "expires accepted
    objects"; a `lost` run has accepted objects)."""
    from defender import lifecycle  # SEAM (missing): lifecycle.sweep_evidence

    sweep = lifecycle.sweep_evidence
    dsn = migrated_database
    t3 = str(uuid.uuid4())
    for tenant in (T1, T2, t3):
        register_tenant(dsn, tenant)
    _retention(dsn, T1, 30)
    _retention(dsn, T2, 90)
    raw = RawS3()
    async with job_store(dsn) as store:
        old, old_claim, old_key = await _with_evidence(store, dsn, raw, T1, "T-old", days_ago=40)
        source, source_claim, source_key = await _with_evidence(store, dsn, raw, T1, "T-source", days_ago=40)
        other, _, other_key = await _with_evidence(store, dsn, raw, T2, "T-other", days_ago=40)
        unset, _, unset_key = await _with_evidence(store, dsn, raw, t3, "T-unset", days_ago=40)
        execute(dsn, "INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, "
                     "trigger, status, created_at, sibling_cost_usd, publish_state) SELECT %s, tenant_id, alert_id, id, "
                     "'k-learn', 1, 'auto', 'queued', now(), 0, 'none' FROM jobs.investigations WHERE id = %s",
                (str(uuid.uuid4()), source))
        dead_owner = await _queued_running(store, dsn, T1, "T-dead", live=False)
        live_owner = await _queued_running(store, dsn, T1, "T-live", live=True)
        stray = {}
        for name, owner_id in (("dead", dead_owner), ("live", live_owner)):
            [(token,)] = execute(dsn, "SELECT claim_token FROM jobs.investigations WHERE id = %s", (owner_id,))
            stray[name] = (token, object_key(T1, "investigation", owner_id, token, "bundle"))
            raw.put(stray[name][1], b"never promoted")
            stage_upload(dsn, token, "bundle", b"never promoted")
            execute(dsn, "UPDATE jobs.uploads SET created_at = now() - interval '2 hours' WHERE token = %s", (token,))
        await sweep(jobs=store, blob=blob_store())

    assert evidence_state(dsn, "investigations", old) == "expired"
    assert raw.get(old_key) == 404
    assert uploads(dsn, old_claim) == {}
    assert evidence_state(dsn, "investigations", source) == "complete"
    assert raw.get(source_key) != 404 and accepted(dsn, source_claim) == ["bundle"]
    for owner_id, key in ((other, other_key), (unset, unset_key)):
        assert evidence_state(dsn, "investigations", owner_id) == "complete"
        assert raw.get(key) != 404
    assert raw.get(stray["dead"][1]) == 404 and uploads(dsn, stray["dead"][0]) == {}
    assert raw.get(stray["live"][1]) != 404 and list(uploads(dsn, stray["live"][0])) == ["bundle"]


async def _queued_running(store, dsn: str, tenant: str, ticket: str, *, live: bool) -> str:
    """A running investigation under a claim of its own, its lease unexpired (`live`) or lapsed."""
    alert = await an_alert(store, tenant, ticket=ticket)
    inv, _ = await store.create_investigation(tenant, alert.alert_id, f"k-{ticket}", actor="u-1")
    token = uuid.uuid4().hex
    insert_claim(dsn, token=token, tenant=tenant, kind="investigation", ref=inv.investigation_id)
    execute(dsn, "UPDATE jobs.investigations SET stage = 'running', started_at = now(), claim_token = %s, "
                 "lease_expires_at = now() + %s * interval '1 hour' WHERE id = %s",
            (token, 1 if live else -1, inv.investigation_id))
    return inv.investigation_id


@pytest.mark.postgres
async def test_the_offboarding_pass_deletes_the_tenants_objects_facts_and_uploads_and_keeps_its_claims(
        migrated_database):
    """T1 is offboarding; it and T2 each have a run with an accepted bundle and staged facts. The pass deletes every
    object under `t/<T1>/` and T1's staged facts and uploads; T1's claims stay with their launch facts nulled; T2 is
    untouched. A second pass (the step repeats on every pass) after a late object lands under `t/<T1>/` deletes it.
    (A-O5, "Offboarding pass")"""
    from defender import lifecycle  # SEAM (missing): lifecycle.offboard_evidence

    step = lifecycle.offboard_evidence
    dsn = migrated_database
    for tenant in (T1, T2):
        register_tenant(dsn, tenant)
    raw = RawS3()
    async with job_store(dsn) as store:
        _, mine, my_key = await _with_evidence(store, dsn, raw, T1, "T-mine", days_ago=1)
        _, theirs, their_key = await _with_evidence(store, dsn, raw, T2, "T-theirs", days_ago=1)
        for token in (mine, theirs):
            stage_fact(dsn, token, "started", {"container": "started"})
        execute(dsn, "UPDATE jobs.claims SET launch = '{\"alert_id\": \"a\"}'::jsonb")
        execute(dsn, "UPDATE tenancy.tenants SET state = 'offboarding' WHERE id = %s", (T1,))
        await step(jobs=store, blob=blob_store(), tenant_id=T1)
        late = f"t/{T1}/investigation/late/{uuid.uuid4().hex}/bundle"
        raw.put(late, b"late")
        await step(jobs=store, blob=blob_store(), tenant_id=T1)

    assert raw.keys(f"t/{T1}/") == []
    assert (uploads(dsn, mine), facts(dsn, mine)) == ({}, {})
    assert claim_row(dsn, mine) is not None and claim_row(dsn, mine)["launch"] is None
    assert raw.get(their_key) == b"bundle"
    assert list(uploads(dsn, theirs)) == ["bundle"] and "started" in facts(dsn, theirs)
    assert raw.get(my_key) == 404


@pytest.mark.postgres
@pytest.mark.parametrize(("days", "ok"), [(29, False), (30, True), (730, True), (731, False)])
async def test_the_retention_setting_is_checked_30_to_730_days_per_kind(migrated_database, days, ok):
    """Both values NOT NULL and checked 30–730 days; no default. (A-O7)"""
    dsn = migrated_database
    register_tenant(dsn, T1)
    if ok:
        _retention(dsn, T1, days)
        return
    with pytest.raises(Exception, match="check"):
        _retention(dsn, T1, days)


def test_both_readiness_warning_lists_declare_the_two_rollout_warnings():
    """Release 1: two readiness warnings produced host-side (missing retention; missing evidence AppRole), declared in
    both warning-kind lists (`records/job_lane.py:395-396`, `api/models.py:132-136`).
    FORCED CHOICE: their kind words (`retention_unset`, `evidence_login_missing` here) and whether the readiness
    helper (host-side, which produces no warning today: §B item 7) merges them into the container's record or the
    worker adds them at finish."""
    from typing import get_args

    from defender.api import models
    from defender.records import job_lane

    new = {"retention_unset", "evidence_login_missing"}
    assert new <= set(job_lane.READINESS_WARNING_KINDS)
    assert new <= set(get_args(models.WarningKind))
