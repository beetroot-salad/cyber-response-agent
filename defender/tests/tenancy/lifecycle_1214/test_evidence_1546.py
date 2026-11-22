# ruff: noqa: F811, PLR0913, PT018
"""#1546 A-O5: the tenant's evidence key and AppRole (made with the tenant, backfilled, destroyed at offboarding) and the
offboarding pass over the real store (Garage) and the jobs database, through the lifecycle's own actors and fakes.

Pinned (missing): the host step `evidence` between `teardown` and `finish`; `HostActor(blob=<defender.evidence.BlobStore>)`
(the store the step reaches; the jobs database is `DEFENDER_DATABASE_DSN`, as the learning purge's); transit key
`evidence-<T>` (aes256-gcm96) and one AppRole whose name starts `evidence-` and holds `<T>`. FakeOpenBao only records (no policy)."""
from __future__ import annotations

import uuid

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.api._mount1161 import API  # noqa: E402
from defender.tests.support.evidence._evidence1546 import garage  # noqa: E402,F401 — fixture
from defender.tests.support.evidence._retention1546 import (  # noqa: E402
    blob_store,
    claim_launch,
    facts,
    gone,
    make_owner,
    present,
    stage_fact,
    uploads,
)
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402


def _key(tenant: str) -> str:
    return f"evidence-{tenant}"


def _roles(bao, tenant: str) -> list[str]:
    return sorted(n for n in bao.approles if n.startswith("evidence-") and tenant in n)


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


# --- the key and AppRole: made with the tenant, backfilled, destroyed ----------------------------------------------

def test_a_created_tenant_has_its_evidence_key_and_one_approle_with_a_secret_it_can_log_in_with(world):
    """Once the tenant is active, `evidence-<T>` is an aes256-gcm96 transit key and one evidence AppRole of the tenant holds a
    secret id that logs in; the other tenant has its own pair and the signing key is still ed25519. (A-O5)"""
    tenant, other = world.active_tenant(), world.active_tenant()
    bao = world.openbao
    assert bao.transit_keys[_key(tenant)]["type"] == "aes256-gcm96"
    assert bao.transit_keys[f"request-token-{tenant}"]["type"] == "ed25519", "control: the signing key is as before"
    [role] = _roles(bao, tenant)
    assert _roles(bao, other) and _roles(bao, other) != [role] and _key(other) in bao.transit_keys
    secrets = list(bao.approles[role].values())
    assert secrets, "no secret id was issued for the evidence AppRole"
    login = world.call(bao.client(None).post, "/v1/auth/approle/login",
                       json={"role_id": f"role-id-{role}", "secret_id": secrets[0]})
    assert login.status_code == 200, login.text


def test_a_tenant_made_before_the_key_existed_gets_key_and_approle_from_a_lifecycle_step(world):
    """An active tenant with no evidence key or AppRole (made by an earlier release) has both after fresh actors have run
    their passes, and a tenant that has them is sent no second key create (backfill; A-O5).
    FORCED CHOICE: the trigger (the design says "a lifecycle step backfills existing tenants")."""
    tenant, other = world.active_tenant(), world.active_tenant()
    bao = world.openbao
    bao.transit_keys.pop(_key(tenant))
    for role in _roles(bao, tenant):
        bao.approles.pop(role)
        bao.approle_policies.pop(role, None)
    mark = len(bao.calls)
    world.service_actor = world.new_service(world.tenants, identity=world.service)
    world.host_actor = world.new_host(world.tenants)
    world.drive()
    assert bao.transit_keys[_key(tenant)]["type"] == "aes256-gcm96" and len(_roles(bao, tenant)) == 1
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    touched_other = [c for c in bao.calls[mark:] if _key(other) in c.path or any(r in c.path for r in _roles(bao, other))]
    assert [c for c in touched_other if c.method in ("POST", "PUT", "DELETE")] == [], "the tenant that had them was written to"


def test_offboarding_destroys_the_evidence_key_and_approle_and_only_that_tenants(world):
    """After offboarding, the tenant's `evidence-<T>` key (made deletable, then deleted once) and its evidence AppRole are
    gone; the other tenant's pair stays. (A-O5, "a read after offboarding is refused" at the key layer)"""
    tenant, other = world.active_tenant(), world.active_tenant()
    bao = world.openbao
    assert _key(tenant) in bao.transit_keys and _roles(bao, tenant), "premise"
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.record(tenant).state == "offboarded" and world.record(tenant).failure is None
    assert _key(tenant) not in bao.transit_keys and _roles(bao, tenant) == []
    path = f"/v1/transit/keys/{_key(tenant)}"
    calls = [(c.method, c.path, c.body) for c in bao.calls if c.path.startswith(path)]
    config = next(i for i, (m, p, b) in enumerate(calls) if p.endswith("/config") and m in ("POST", "PUT") and b["deletion_allowed"] is True)
    deletes = [i for i, (m, p, _b) in enumerate(calls) if m == "DELETE" and p == path]
    assert len(deletes) == 1 and config < deletes[0]
    assert _key(other) in bao.transit_keys and _roles(bao, other), "control: the other tenant's pair stays"


def test_offboarding_a_tenant_whose_evidence_key_and_approle_are_already_gone_finishes_sending_no_delete(world):
    """With the key and AppRole already absent, offboarding finishes and sends no delete for either. (A-O5, idempotent)"""
    tenant = world.active_tenant()
    bao = world.openbao
    roles = _roles(bao, tenant)
    bao.transit_keys.pop(_key(tenant))
    for role in roles:
        bao.approles.pop(role)
    mark = len(bao.calls)
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.record(tenant).state == "offboarded" and world.record(tenant).failure is None
    sent = [(c.method, c.path) for c in bao.calls[mark:] if c.method == "DELETE" and (
        _key(tenant) in c.path or any(r in c.path for r in roles))]
    assert sent == []


# --- the offboarding pass over the real store ------------------------------------------------------------------------

@pytest.fixture
def evidence_world(tmp_path, data_root, monkeypatch, garage):
    """A world whose host actors reach the real Garage, over a database that also holds the jobs rows."""
    w = LifecycleWorld(tmp_path, data_root, blob=blob_store(garage))
    if w.dsn is None:
        w.close()
        pytest.skip("needs the test database")
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", w.dsn)  # the host's jobs database is the world's
    yield w
    w.close()


@pytest.mark.garage
@pytest.mark.postgres
def test_the_offboarding_pass_deletes_the_tenants_objects_facts_and_uploads_keeps_its_claims_and_touches_no_other(
        evidence_world, garage):
    """T has accepted evidence and staged facts, another tenant too. Offboarded, nothing is left under `t/<T>/` in the store
    and no staged fact or upload of T remains; T's claims stay with launch facts nulled; the other tenant's objects, facts
    and uploads are as they were. (A-O5)"""
    world, dsn = evidence_world, evidence_world.dsn
    tenant, other = world.active_tenant(), world.active_tenant()
    mine = make_owner(dsn, garage, tenant, "mine", accepted_days_ago=1)
    theirs = make_owner(dsn, garage, other, "theirs", accepted_days_ago=1)
    for made in (mine, theirs):
        stage_fact(dsn, made["claim"], "started", {"container": "started"})
    from defender.tests.support.shared._postgres1339 import execute

    execute(dsn, "UPDATE jobs.claims SET launch = '{\"alert_id\": \"a\"}'::jsonb")
    assert present(garage, mine["key"]), "premise"
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.record(tenant).state == "offboarded", world.item(tenant)
    assert garage.list(f"t/{tenant}/") == []
    assert (uploads(dsn, mine["claim"]), facts(dsn, mine["claim"])) == ({}, {})
    assert claim_launch(dsn, mine["claim"]) == (True, None)
    assert present(garage, theirs["key"]) and list(uploads(dsn, theirs["claim"])) == ["bundle"]
    assert "started" in facts(dsn, theirs["claim"]) and claim_launch(dsn, theirs["claim"])[1] is not None


@pytest.mark.garage
@pytest.mark.postgres
def test_an_object_and_rows_that_arrive_after_offboarding_are_removed_by_the_next_pass(evidence_world, garage):
    """Once the tenant is `offboarded`, a late object under `t/<T>/` and a late staged fact and upload row of one of its
    claims are gone after one more host pass (the step repeats while offboarding or offboarded). (A-O5)"""
    world, dsn = evidence_world, evidence_world.dsn
    tenant = world.active_tenant()
    mine = make_owner(dsn, garage, tenant, "mine", accepted_days_ago=1)
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.record(tenant).state == "offboarded" and garage.list(f"t/{tenant}/") == []
    late = f"t/{tenant}/investigation/late/{uuid.uuid4().hex}/bundle"
    garage.put(late, b"late")
    stage_fact(dsn, mine["claim"], "started", {"container": "started"})
    from defender.tests.support.evidence._retention1546 import stage_upload

    stage_upload(dsn, mine["claim"], "page/runtime.html")
    world.host_pass()
    assert gone(garage, late) and garage.list(f"t/{tenant}/") == []
    assert (uploads(dsn, mine["claim"]), facts(dsn, mine["claim"])) == ({}, {})


@pytest.mark.garage
@pytest.mark.postgres
def test_an_offboarding_whose_store_cannot_be_reached_does_not_finish_and_resumes_when_it_can(
        tmp_path, data_root, monkeypatch, garage):
    """With the store's address refusing connections the tenant stays `offboarding` at the evidence step with a failure
    recorded and nothing deleted; given the working store, a resume finishes and the objects are gone. (A-O5)"""
    from defender.evidence import BlobStore  # noqa: F401 — the pinned class; missing until built

    dead = blob_store(garage).__class__(endpoint="http://127.0.0.1:9", bucket=garage.bucket, access_key=garage.access_key,
                                        secret_key=garage.secret_key, region=garage.region)
    world = LifecycleWorld(tmp_path, data_root, blob=dead)
    try:
        if world.dsn is None:
            pytest.skip("needs the test database")
        monkeypatch.setenv("DEFENDER_DATABASE_DSN", world.dsn)
        tenant = world.active_tenant()
        mine = make_owner(world.dsn, garage, tenant, "mine", accepted_days_ago=1)
        assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
        world.drive()
        item = world.item(tenant)
        assert (item["state"], item["step"]) == ("offboarding", "evidence") and item["failure"], item
        assert present(garage, mine["key"]), "an unreachable store deleted nothing"
        world.host_actor = world.new_host(world.tenants, blob=blob_store(garage))
        assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 202
        world.drive()
        assert world.record(tenant).state == "offboarded" and gone(garage, mine["key"])
    finally:
        world.close()
