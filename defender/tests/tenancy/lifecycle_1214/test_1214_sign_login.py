# ruff: noqa: PT018
"""#1214 r8: each generation's sign-only login (A24' lifecycle mechanics) and each tenant's signing key (A25), through the
create, rotate and offboard jobs in memory over the fakes. What the signer and the proxy do with them is not here."""
from __future__ import annotations

import contextlib
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214._fakes import SIGN_POLICY, TOKEN_POLICY  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import openbao_failing  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld, lifecycle_config  # noqa: E402

PROBE = "cHJvYmU="


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _key(tenant: str) -> str:
    return f"request-token-{tenant}"


def _key_path(tenant: str) -> str:
    return f"/v1/transit/keys/{_key(tenant)}"


def _writes_to(world, path: str) -> list:
    return [c for c in world.openbao.calls if c.method in ("POST", "PUT") and c.path == path]


def _login(world, role_id: str, secret: str) -> str:
    """The client token of a login with the pair (asserted accepted)."""
    done = world.call(world.openbao.client(None).post, "/v1/auth/approle/login", json={"role_id": role_id, "secret_id": secret})
    assert done.status_code == 200, done.text
    return done.json()["auth"]["client_token"]


def _sign(world, token: str, tenant: str) -> int:
    return world.call(world.openbao.client(token).post, f"/v1/transit/sign/{_key(tenant)}", json={"input": PROBE}).status_code


def _mint(world, token: str, role: str) -> int:
    return world.call(world.openbao.client(token).get, f"/v1/identity/oidc/token/{role}").status_code


def _pair(world, gen) -> tuple[str, str]:
    """(delivery client token, sign client token) of a live generation, from the secrets the fake holds."""
    bao = world.openbao
    return (_login(world, gen.role_id, bao.approles[gen.approle][gen.secret_accessor]),
            _login(world, gen.sign_role_id, bao.approles[gen.sign_approle][gen.sign_secret_accessor]))


# --- names (P1) and the provider -------------------------------------------------------------------------

def test_the_sign_names_are_recorded_before_anything_is_made(world):
    """The first OpenBao call of the create fails: the generation already records the sign AppRole and entity names by
    the design's rule, and OpenBao holds nothing (A24' names, P1)."""
    flaky = openbao_failing(world, lambda _r: True)
    tenant = world.create()
    world.drive()
    assert flaky.hit, "control: the injected failure happened"
    [gen] = world.generations(tenant)
    assert (gen.sign_approle, gen.sign_entity) == (f"sign-{tenant}-{gen.salt}", f"tenant-{tenant}-{gen.salt}-sign")
    assert (gen.approle, gen.entity) == (f"delivery-{tenant}-{gen.salt}", f"tenant-{tenant}-{gen.salt}")
    bao = world.openbao
    assert (bao.approles, bao.entities, bao.aliases, bao.transit_keys) == ({}, {}, [], {})


def test_the_provider_makes_the_sign_approle_entity_alias_and_key_each_on_its_own_policy(world):
    """A sign AppRole on the sign policy beside the delivery one on its own, a sign entity carrying the tenant, one alias per
    entity named by its role id, and the tenant's ed25519 key (A24', A25)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    bao = world.openbao
    assert bao.approle_policies[gen.approle] == [TOKEN_POLICY], "the delivery AppRole's policy gained a rule"
    assert bao.approle_policies[gen.sign_approle] == [SIGN_POLICY]
    assert bao.entities[gen.sign_entity]["metadata"]["tenant_id"] == tenant
    assert gen.sign_role_id and gen.sign_role_id != gen.role_id
    by_name = {a["name"]: a["canonical_id"] for a in bao.aliases}
    assert by_name == {gen.role_id: bao.entities[gen.entity]["id"], gen.sign_role_id: bao.entities[gen.sign_entity]["id"]}
    assert bao.transit_keys[_key(tenant)]["type"] == "ed25519"


def test_the_delivery_login_cannot_sign_and_the_sign_login_cannot_mint_a_token(world):
    """The two logins differ in what they may ask: delivery mints its OIDC token (200, control) and cannot sign; sign signs
    its own tenant's key (200, control) and cannot mint, nor sign another tenant's key (A24')."""
    tenant, other = world.active_tenant(), world.active_tenant()
    gen = world.live(tenant)
    delivery, sign = _pair(world, gen)
    assert _mint(world, delivery, gen.oidc_role) == 200 and _sign(world, sign, tenant) == 200
    assert _sign(world, delivery, tenant) == 403
    assert _mint(world, sign, gen.oidc_role) == 403
    assert _sign(world, sign, other) == 403


def test_the_sign_policy_is_the_configured_name(tmp_path, data_root):
    """`LifecycleConfig.sign_policy` names the policy of the sign AppRole; the delivery AppRole keeps `token_policy`
    (A24', r8.4)."""
    w = LifecycleWorld(tmp_path, data_root)
    try:
        config = lifecycle_config(tmp_path, data_root, sign_policy="custom-sign")
        w.openbao.sign_policy = "custom-sign"
        w.config = config
        w.service_actor = w.new_service(w.tenants, identity=w.service, config=config)
        w.host_actor = w.new_host(w.tenants, config=config)
        gen = w.live(w.active_tenant())
        assert w.openbao.approle_policies[gen.sign_approle] == ["custom-sign"]
        assert w.openbao.approle_policies[gen.approle] == [TOKEN_POLICY]
    finally:
        w.close()


class _DropsTheProviderCommit:
    """A hold whose first commit recording a role id is lost before it lands, as when the lock connection fails mid-step."""

    def __init__(self, held: Any, dropped: list[int]) -> None:
        self._held, self._dropped = held, dropped

    def __getattr__(self, name: str) -> Any:
        return getattr(self._held, name)

    async def commit(self, **kwargs: Any) -> Any:
        updates = (kwargs.get("update_generations") or {}).values()
        if not self._dropped and any("role_id" in fields or "sign_role_id" in fields for fields in updates):
            self._dropped.append(1)
            raise ConnectionError("the lock connection dropped before the commit")
        return await self._held.commit(**kwargs)


def test_a_provider_that_died_before_committing_is_run_again_reusing_its_entities_and_aliases(world):
    """The provider made both chains, then its commit was lost: the re-run finds the entity and alias of each recorded name
    and reuses them (OpenBao refuses a second alias), so the job finishes with one alias per entity (r8.4, P-c)."""
    real, dropped = world.tenants.lock, []

    @contextlib.asynccontextmanager
    async def lock(tenant_id: str) -> Any:
        async with real(tenant_id) as held:
            yield None if held is None else _DropsTheProviderCommit(held, dropped)
    world.tenants.lock = lock
    tenant = world.create()
    world.drive()
    world.tenants.lock = real
    item = world.item(tenant)
    assert dropped and (item["step"], item["step_actor"]) == ("provider", "service") and item["failure"], item
    assert world.openbao.aliases and world.openbao.approles, "control: the provider had made things before its commit was lost"
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active", world.item(tenant)
    gen = world.live(tenant)
    bao = world.openbao
    assert {a["name"] for a in bao.aliases} == {gen.role_id, gen.sign_role_id} and len(bao.aliases) == 2
    assert (set(bao.approles), set(bao.entities)) == ({gen.approle, gen.sign_approle}, {gen.entity, gen.sign_entity})


# --- wrap, install, sweep ----------------------------------------------------------------------------------

def test_wrap_and_install_handle_both_secrets_and_prove_the_sign_pair_by_signing(world):
    """A secret id is wrapped for each AppRole and unwrapped by install, which writes both files, records both accessors,
    clears both wrapping tokens and signs one probe as the tenant's sign login (A24' wrap/install)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    bao = world.openbao
    wrapped_for = {c.path.split("/")[5] for c in bao.calls if c.path.endswith("/secret-id") and "x-vault-wrap-ttl" in c.headers}
    assert wrapped_for == {gen.approle, gen.sign_approle}
    assert len(bao.made("POST", "/v1/sys/wrapping/unwrap")) == 2
    assert gen.host_secret_file != gen.sign_secret_file and gen.host_secret_file.parent == gen.sign_secret_file.parent
    assert world.config.secrets_dir / tenant == gen.sign_secret_file.parent
    assert gen.sign_secret_file.read_text(encoding="utf-8") == bao.approles[gen.sign_approle][gen.sign_secret_accessor] + "\n"
    assert gen.host_secret_file.read_text(encoding="utf-8") == bao.approles[gen.approle][gen.secret_accessor] + "\n"
    assert gen.sign_secret_accessor and gen.sign_secret_accessor != gen.secret_accessor
    assert (gen.wrapped_secret, gen.sign_wrapped_secret) == (None, None)
    assert [(key, role) for key, role, _input in bao.signs] == [(_key(tenant), gen.sign_approle)]


def test_a_sign_proof_that_fails_fails_install_and_restarts_at_wrap_with_no_file_left(world):
    """The tenant's key is gone when install signs: install fails, restarts at `wrap`, leaves no secret file; with the key
    back, resume finishes and the proof is made (A24' install, A25)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    lost = world.openbao.transit_keys.pop(_key(tenant))
    world.drive()
    item = world.item(tenant)
    assert (item["step"], item["step_actor"]) == ("wrap", "service") and "install" in item["failure"], item
    assert not [p for p in world.config.secrets_dir.rglob("*") if p.is_file()], "a failed install left a secret file"
    assert world.openbao.signs == []
    world.openbao.transit_keys[_key(tenant)] = lost
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert [role for _key_, role, _input in world.openbao.signs] == [world.live(tenant).sign_approle]


# --- rotation (A25 key kept and ensured, A24' retire) ------------------------------------------------------

def test_the_key_is_the_tenants_and_survives_rotations_while_each_generation_proves_its_own_sign_login(world):
    """Two rotations leave the one key `request-token-<tenant>` (created once, never deleted, none per generation), and
    every generation's install signed with it as its own sign login (A25, r8.4)."""
    tenant, other = world.active_tenant(), world.active_tenant()
    for _ in range(2):
        assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
        world.drive()
        assert world.item(tenant)["state"] == "active"
    bao = world.openbao
    assert set(bao.transit_keys) == {_key(tenant), _key(other)}
    assert bao.made("DELETE", _key_path(tenant)) == [] and len(_writes_to(world, _key_path(tenant))) == 1
    gens = world.generations(tenant)
    assert len(gens) == 3 and {g.status for g in gens} == {"destroyed", "live"}
    assert {role for key, role, _i in bao.signs if key == _key(tenant)} == {g.sign_approle for g in gens}


def test_a_rotation_makes_the_key_of_a_tenant_that_has_none(world):
    """A tenant created before the key existed gets it from its next rotation, whose install proof needs it (A25 ensure, upgrade)."""
    tenant = world.active_tenant()
    world.openbao.transit_keys.pop(_key(tenant))
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active" and world.item(tenant)["failure"] is None
    assert world.openbao.transit_keys[_key(tenant)]["type"] == "ed25519"
    assert len(_writes_to(world, _key_path(tenant))) == 2


# --- offboarding (A25 destroy) -----------------------------------------------------------------------------

def test_offboarding_makes_the_key_deletable_then_deletes_it(world):
    """The key is read, made deletable (`/config`) and only then deleted, once; the tenant's other keys stay (A25 destroy, r8.1)."""
    tenant, other = world.active_tenant(), world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert set(world.openbao.transit_keys) == {_key(other)}
    calls = [(c.method, c.path, c.body) for c in world.openbao.calls if c.path.startswith(_key_path(tenant))]
    config = next(i for i, (m, p, b) in enumerate(calls) if p.endswith("/config") and m in ("POST", "PUT") and b["deletion_allowed"] is True)
    delete = [i for i, (m, p, _b) in enumerate(calls) if m == "DELETE" and p == _key_path(tenant)]
    assert len(delete) == 1 and config < delete[0]


def test_a_key_that_is_already_gone_is_done_without_a_delete(world):
    """An absent key is already done: offboarding sends no delete for it and finishes (A25, RC-4)."""
    tenant = world.active_tenant()
    world.openbao.transit_keys.pop(_key(tenant))
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.record(tenant).state == "offboarded" and world.record(tenant).failure is None
    assert world.openbao.made("DELETE", _key_path(tenant)) == []


def test_the_final_sweep_of_offboarding_destroys_a_key_a_late_effect_left(world):
    """A key that reappears after `offboard` (a timed-out call's late effect) is destroyed by `finish` (A25, r8.4)."""
    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive(stop=lambda: world.item(tenant)["step"] == "finish")
    assert _key(tenant) not in world.openbao.transit_keys, "control: offboard destroyed the key"
    world.openbao.transit_keys[_key(tenant)] = {"type": "ed25519", "deletion_allowed": False}
    world.drive()
    assert world.record(tenant).state == "offboarded"
    assert world.openbao.transit_keys == {}
