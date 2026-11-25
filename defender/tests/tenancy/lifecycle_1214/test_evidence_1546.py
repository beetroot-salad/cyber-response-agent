# ruff: noqa: F811, PLR0913, PT018
"""#1546 A-O5 (r9): the tenant's evidence key `evidence-<T>` (per tenant, made once, kept across rotations like the signing
key, destroyed at offboarding) and each generation's evidence login (an AppRole beside the sign chain, made by the management
service, its secret unwrapped by the host at install and proven by a datakey/decrypt probe); the offboarding pass over the real
store (Garage) and the jobs database, through the lifecycle's own actors and fakes. There is no backfill: no tenant survives
the upgrade (D16, B).

Pinned (missing): the host step `evidence` between `teardown` and `finish`; `HostActor(blob=<defender.evidence.BlobStore>)`;
transit key `evidence-<T>` (aes256-gcm96); on `Generation`, mirroring `sign_*`: `evidence_approle` (name starts `evidence-`),
`evidence_entity`, `evidence_role_id`, `evidence_wrapped_secret`, `evidence_secret_accessor`, `evidence_secret_file`;
`LifecycleConfig.evidence_policy` (the fake's `EVIDENCE_POLICY`, datakey/decrypt on the login's own tenant's key); the store
settings `DEFENDER_EVIDENCE_{ENDPOINT,BUCKET,ACCESS_KEY,SECRET_KEY}` (required, `LifecycleConfig.from_env` refuses naming a
missing one). FakeOpenBao enforces the policy by the entity's tenant on datakey/decrypt, as it does for sign."""
from __future__ import annotations

import os
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
from defender.tests.support.tenancy._active1214 import CREATE_RETENTION  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402


def _key(tenant: str) -> str:
    return f"evidence-{tenant}"


def _roles(bao, tenant: str) -> list[str]:
    """The evidence AppRoles of the tenant's generations (names start `evidence-`, hold the tenant)."""
    return sorted(n for n in bao.approles if n.startswith("evidence-") and tenant in n)


def _login(world, role_id: str, secret: str) -> str:
    done = world.call(world.openbao.client(None).post, "/v1/auth/approle/login", json={"role_id": role_id, "secret_id": secret})
    assert done.status_code == 200, done.text
    return done.json()["auth"]["client_token"]


def _transit(world, token: str, op: str, key: str) -> int:
    path = f"/v1/transit/datakey/plaintext/{key}" if op == "datakey" else f"/v1/transit/sign/{key}"
    body = {} if op == "datakey" else {"input": "cHJvYmU="}
    return world.call(world.openbao.client(None).post, path, json=body, headers={"X-Vault-Token": token}).status_code


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


# --- the key (per tenant) and the login (per generation) ------------------------------------------------------------

def test_a_created_tenant_has_its_evidence_key_and_a_generation_login_on_its_own_policy(world):
    """Once the tenant is active, `evidence-<T>` is an aes256-gcm96 transit key (the signing key still ed25519), and the live
    generation has an evidence AppRole on the evidence policy beside the delivery and sign ones, an entity carrying the
    tenant and an alias named by its role id; the other tenant has its own. (A-O5, r9)"""
    tenant, other = world.active_tenant(), world.active_tenant()
    bao = world.openbao
    assert bao.transit_keys[_key(tenant)]["type"] == "aes256-gcm96"
    assert bao.transit_keys[f"request-token-{tenant}"]["type"] == "ed25519", "control: the signing key is as before"
    gen, theirs = world.live(tenant), world.live(other)
    assert gen.evidence_approle.startswith("evidence-") and gen.evidence_approle in _roles(bao, tenant)
    assert bao.approle_policies[gen.evidence_approle] == [bao.evidence_policy]
    assert bao.approle_policies[gen.sign_approle] != bao.approle_policies[gen.evidence_approle]
    assert bao.entities[gen.evidence_entity]["metadata"]["tenant_id"] == tenant
    assert gen.evidence_role_id not in (gen.role_id, gen.sign_role_id)
    assert {a["name"]: a["canonical_id"] for a in bao.aliases}[gen.evidence_role_id] == bao.entities[gen.evidence_entity]["id"]
    assert theirs.evidence_approle != gen.evidence_approle and _key(other) in bao.transit_keys


def test_the_evidence_secret_is_wrapped_unwrapped_at_install_written_and_proved_by_a_datakey_and_decrypt(world):
    """A secret id is wrapped for the evidence AppRole and unwrapped by the host at install, which writes its file beside the
    others, records the accessor, clears the wrapping token, and proves the login with one datakey and one decrypt of the
    tenant's key (not at prepare). (A-O5, r9)"""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    bao = world.openbao
    wrapped_for = {c.path.split("/")[5] for c in bao.calls if c.path.endswith("/secret-id") and "x-vault-wrap-ttl" in c.headers}
    assert gen.evidence_approle in wrapped_for
    assert gen.evidence_secret_file.parent == gen.sign_secret_file.parent == world.config.secrets_dir / tenant
    assert gen.evidence_secret_file != gen.sign_secret_file
    assert gen.evidence_secret_file.read_text(encoding="utf-8") == bao.approles[gen.evidence_approle][gen.evidence_secret_accessor] + "\n"
    assert gen.evidence_wrapped_secret is None
    assert bao.datakeys == [(_key(tenant), gen.evidence_approle)] and bao.decrypts == [(_key(tenant), gen.evidence_approle)]


def test_each_login_may_use_only_its_own_key_and_only_for_its_own_purpose(world):
    """The evidence login takes a datakey on its own tenant's key (200, control), not on another tenant's, and cannot sign;
    the sign login cannot take a datakey. (A-O5, r9)"""
    tenant, other = world.active_tenant(), world.active_tenant()
    gen = world.live(tenant)
    bao = world.openbao
    evidence = _login(world, gen.evidence_role_id, next(iter(bao.approles[gen.evidence_approle].values())))
    sign = _login(world, gen.sign_role_id, next(iter(bao.approles[gen.sign_approle].values())))
    assert _transit(world, evidence, "datakey", _key(tenant)) == 200
    assert _transit(world, evidence, "datakey", _key(other)) == 403
    assert _transit(world, evidence, "sign", f"request-token-{tenant}") == 403
    assert _transit(world, sign, "datakey", _key(tenant)) == 403


def test_the_key_is_the_tenants_and_survives_rotations_while_each_generation_proves_its_own_login(world):
    """Two rotations leave the one key `evidence-<T>` (created once, never deleted), and every generation's install proved a
    datakey with its own evidence login. (A-O5, A25, r9)"""
    tenant = world.active_tenant()
    for _ in range(2):
        assert world.ops.post(f"{API}/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
        world.drive()
        assert world.item(tenant)["state"] == "active"
    bao = world.openbao
    path = f"/v1/transit/keys/{_key(tenant)}"
    assert bao.made("DELETE", path) == [] and len([c for c in bao.calls if c.method in ("POST", "PUT") and c.path == path]) == 1
    gens = world.generations(tenant)
    assert len(gens) == 3 and len({g.evidence_approle for g in gens}) == 3
    assert {role for key, role in bao.datakeys if key == _key(tenant)} == {g.evidence_approle for g in gens}


def test_an_evidence_proof_that_fails_fails_install_and_restarts_at_wrap_with_no_file_left(world):
    """The tenant's `evidence-<T>` is gone when install proves the login: install fails, restarts at `wrap`, leaves no secret
    file; with the key back, resume finishes and the proof is made. (A-O5, r9)"""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    lost = world.openbao.transit_keys.pop(_key(tenant))
    world.drive()
    item = world.item(tenant)
    assert (item["step"], item["step_actor"]) == ("wrap", "service") and "install" in item["failure"], item
    assert not [p for p in world.config.secrets_dir.rglob("*") if p.is_file()], "a failed install left a secret file"
    assert world.openbao.datakeys == []
    world.openbao.transit_keys[_key(tenant)] = lost
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert [role for _key_, role in world.openbao.datakeys] == [world.live(tenant).evidence_approle]


def test_offboarding_destroys_the_evidence_key_and_logins_and_only_that_tenants(world):
    """After offboarding, the tenant's `evidence-<T>` key (made deletable, then deleted once) and its evidence AppRoles are
    gone; the other tenant's key and login stay. (A-O5, "a read after offboarding is refused" at the key layer)"""
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
    assert _key(other) in bao.transit_keys and _roles(bao, other), "control: the other tenant's key and login stay"


def test_offboarding_a_tenant_whose_evidence_key_and_logins_are_already_gone_finishes_sending_no_delete(world):
    """With the key and AppRoles already absent, offboarding finishes and sends no delete for either. (A-O5, idempotent)"""
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


# --- no store configured: fail closed ------------------------------------------------------------------------------------

STORE_ENV = ("ENDPOINT", "BUCKET", "ACCESS_KEY", "SECRET_KEY")


@pytest.mark.parametrize("missing", [None, *STORE_ENV])
def test_a_lifecycle_with_no_evidence_store_configured_is_refused_at_its_settings(tmp_path, data_root, monkeypatch, missing):
    """The lifecycle's settings with the evidence store's four variables set are built (control); with any one unset,
    `from_env` refuses naming it, so the service never runs an offboarding that would skip the store. (A-O5, fail closed)"""
    from defender.lifecycle import ConfigRefused
    from defender.lifecycle import config as settings
    from defender.tests.support.evidence._facts1546 import EVIDENCE_ENV_PREFIX
    from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config, people_settings

    expected = lifecycle_config(tmp_path, data_root)
    for name, value in (("forge-token", expected.forge_admin_token), ("bao-login", expected.openbao_login)):
        (tmp_path / name).write_text(value + "\n", encoding="utf-8")
    for name in [k for k in os.environ if k.startswith(("DEFENDER_LIFECYCLE_", "DEFENDER_EVIDENCE_"))]:
        monkeypatch.delenv(name)
    for name, value in ((settings.FORGE_URL_ENV, expected.forge_url), (settings.FORGE_TOKEN_FILE_ENV, str(tmp_path / "forge-token")),
                        (settings.OPENBAO_LOGIN_FILE_ENV, str(tmp_path / "bao-login")),
                        (settings.INTEGRATION_ENV, expected.integration_command),
                        (settings.SECRETS_DIR_ENV, str(expected.secrets_dir)), (settings.DATA_ROOT_ENV, str(data_root)),
                        *people_settings(settings)):  # #1592: the people worker's required settings
        monkeypatch.setenv(name, value)
    for name in STORE_ENV:
        if name != missing:
            monkeypatch.setenv(f"{EVIDENCE_ENV_PREFIX}{name}", "x")
    if missing is None:
        assert settings.LifecycleConfig.from_env(template_dir=expected.template_dir)
        return
    with pytest.raises(ConfigRefused, match=f"{EVIDENCE_ENV_PREFIX}{missing}"):
        settings.LifecycleConfig.from_env(template_dir=expected.template_dir)


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


@pytest.mark.garage
@pytest.mark.postgres
def test_offboarding_keeps_the_tenants_retention_row_and_its_investigations_foreign_key_holds(evidence_world, garage):
    """After offboarding, the tenant's retention row is still there with its created values (the investigations that name it
    would refuse its delete), and the other tenant's is untouched. (A-O7, D16)"""
    from defender.tests.support.shared._postgres1339 import execute

    world, dsn = evidence_world, evidence_world.dsn
    tenant, other = world.active_tenant(), world.active_tenant()
    make_owner(dsn, garage, tenant, "mine", accepted_days_ago=1)
    sql = "SELECT investigation_days, learning_days FROM tenancy.evidence_retention WHERE tenant_id = %s"
    want = [(CREATE_RETENTION["investigation_days"], CREATE_RETENTION["learning_days"])]
    assert execute(dsn, sql, (tenant,)) == want, "premise: the create request wrote the row"
    assert world.ops.post(f"{API}/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.record(tenant).state == "offboarded" and world.record(tenant).failure is None, world.item(tenant)
    assert execute(dsn, sql, (tenant,)) == want and execute(dsn, sql, (other,)) == want
