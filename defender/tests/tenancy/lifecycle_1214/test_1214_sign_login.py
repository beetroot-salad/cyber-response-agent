# ruff: noqa: PT018
"""#1214 r8: each generation's sign-only login (A24' lifecycle mechanics) and each tenant's signing key (A25), through the
create, rotate and offboard jobs in memory over the fakes. What the signer and the proxy do with them is not here."""
from __future__ import annotations

import contextlib
from typing import Any

import httpx

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214._fakes import ORG, SIGN_POLICY, TOKEN_POLICY  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import as_bot, jwts, openbao_failing  # noqa: E402
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


@pytest.mark.parametrize("kind", ["create", "rotate"])
def test_the_names_step_alone_records_the_sign_names_on_the_pending_generation(world, kind):
    """Right after `names` (no later step run) the pending generation carries the sign AppRole and entity names by the
    design's rule, in create and in rotate (A24' names, P1: recorded with the others, not later by `provider`)."""
    if kind == "create":
        tenant = world.create()
    else:
        tenant = world.active_tenant()
        assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202

    async def names_only() -> None:
        async with world.tenants.lock(tenant) as held:
            assert held is not None
            await world.service_actor.steps()["names"](held)
    world.call(names_only)
    pending = _only_pending(world, tenant)
    assert (pending.sign_approle, pending.sign_entity) == (f"sign-{tenant}-{pending.salt}", f"tenant-{tenant}-{pending.salt}-sign")
    assert (pending.approle, pending.entity) == (f"delivery-{tenant}-{pending.salt}", f"tenant-{tenant}-{pending.salt}")
    assert world.item(tenant)["step"] == "provider"


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
    """A hold whose first commit recording `field` is lost before it lands, as when the lock connection fails mid-step."""

    def __init__(self, held: Any, dropped: list[int], field: str) -> None:
        self._held, self._dropped, self._field = held, dropped, field

    def __getattr__(self, name: str) -> Any:
        return getattr(self._held, name)

    async def commit(self, **kwargs: Any) -> Any:
        updates = (kwargs.get("update_generations") or {}).values()
        if not self._dropped and any(self._field in fields for fields in updates):
            self._dropped.append(1)
            raise ConnectionError("the lock connection dropped before the commit")
        return await self._held.commit(**kwargs)


@pytest.mark.parametrize(("field", "chain"), [("role_id", "delivery"), ("sign_role_id", "sign")])
def test_a_provider_that_died_before_committing_is_run_again_reusing_its_entities_and_aliases(world, field, chain):
    """The commit recording `field` is lost after the {chain} chain was made: the re-run reuses that chain's entity and
    alias (OpenBao refuses a second alias) and ends with one alias per entity (r8.4, P-c)."""
    real, dropped = world.tenants.lock, []

    @contextlib.asynccontextmanager
    async def lock(tenant_id: str) -> Any:
        async with real(tenant_id) as held:
            yield None if held is None else _DropsTheProviderCommit(held, dropped, field)
    world.tenants.lock = lock
    tenant = world.create()
    world.drive()
    world.tenants.lock = real
    item = world.item(tenant)
    assert dropped and (item["step"], item["step_actor"]) == ("provider", "service") and item["failure"], item
    [pending] = world.generations(tenant)
    bao = world.openbao
    entity = pending.entity if chain == "delivery" else pending.sign_entity
    assert entity in bao.entities and bao.entities[entity]["id"] in {a["canonical_id"] for a in bao.aliases}, \
        f"control: the {chain} chain's alias existed before its commit was lost"
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active", world.item(tenant)
    gen = world.live(tenant)
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


@pytest.mark.parametrize("answer", [{"data": {"key_version": 1}}, {"data": {"signature": ""}}], ids=["no signature", "empty signature"])
def test_a_sign_that_answers_200_without_a_signature_is_not_a_proof(world, answer):
    """Install's sign answers 200 carrying no signature: install fails and restarts at `wrap` with no secret file; with
    a forge of real signatures again (control), resume finishes (A24' install, r8.4)."""
    def unsigned(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/v1/transit/sign/"):
            return httpx.Response(200, json=answer)
        return world.openbao.handle(request)
    real_host = world.host_actor
    world.host_actor = world.new_host(world.tenants, openbao_login=httpx.AsyncClient(
        transport=httpx.MockTransport(unsigned), base_url=str(world.openbao.client(None).base_url)))
    tenant = world.create()
    world.drive()
    item = world.item(tenant)
    assert (item["step"], item["step_actor"]) == ("wrap", "service") and "install" in (item["failure"] or ""), item
    assert not [p for p in world.config.secrets_dir.rglob("*") if p.is_file()], "a failed install left a secret file"
    world.host_actor = real_host  # control: the same job with a sign that returns a signature
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"


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


# --- upgrade: generations recorded before the sign login existed (r8.2 upgrade, r8.4) -----------------------

SIGN_FIELDS = ("sign_approle", "sign_entity", "sign_role_id", "sign_secret_file", "sign_wrapped_secret", "sign_secret_accessor")


def _row(world, tenant: str, status: str) -> Any:
    [row] = [r for (owner, _s), r in world.tenants._generations.items() if owner == tenant and r.status == status]  # noqa: SLF001
    return row


def _as_recorded_before_r8(world, tenant: str):
    """Make the tenant's live generation the shape an older deployment recorded: no sign names, and no sign AppRole,
    entity, alias, secret file or signing key anywhere (the in-memory twin's rows). Returns the generation as it was."""
    gen = world.live(tenant)
    bao = world.openbao
    bao.approles.pop(gen.sign_approle)
    bao.approle_policies.pop(gen.sign_approle, None)
    bao.aliases[:] = [a for a in bao.aliases if a["name"] != gen.sign_role_id]
    bao.entities.pop(gen.sign_entity)
    bao.transit_keys.pop(_key(tenant))
    gen.sign_secret_file.unlink()
    row = _row(world, tenant, "live")
    for name in SIGN_FIELDS:
        setattr(row, name, None)
    assert world.live(tenant).sign_approle is None, "control: the record reads as an older one"
    return gen


def test_a_rotation_gives_a_tenant_recorded_before_r8_its_sign_login_key_and_rule_and_retires_the_old_generation(world):
    """Rotating a tenant whose live generation has no sign names (and a pre-r8 rule) retires it without any request naming
    a missing record, and the new generation holds the sign login, the key and the merge whitelist (r8.3 heals all three)."""
    tenant = world.active_tenant()
    old = _as_recorded_before_r8(world, tenant)
    full = f"{ORG}/{tenant}"
    world.forge.put_rule(full, rule_name="main", branch_name="main", enable_push=True, enable_push_whitelist=False,
                         enable_merge_whitelist=False)
    mark = len(world.openbao.calls)
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["pending_action"], item["failure"]) == ("active", None, None), item
    new, bao = world.live(tenant), world.openbao
    assert new.salt != old.salt and {g.status for g in world.generations(tenant)} == {"destroyed", "live"}
    assert all(getattr(new, name) for name in SIGN_FIELDS if name != "sign_wrapped_secret")
    assert bao.approle_policies[new.sign_approle] == [SIGN_POLICY] and bao.transit_keys[_key(tenant)]["type"] == "ed25519"
    assert new.sign_secret_file.is_file() and not old.host_secret_file.exists()
    rule = world.forge.rule(full)
    assert (rule["enable_push"], rule["enable_merge_whitelist"], rule["merge_whitelist_teams"]) == (False, True, ["Owners"])
    assert [c.path for c in bao.calls[mark:] if "None" in c.path] == []


def test_offboarding_a_tenant_recorded_before_r8_sends_nothing_for_a_missing_sign_record(world):
    """Offboarding a tenant whose live generation has no sign names finishes, leaves nothing behind and sends no request
    naming a missing record (`None`) (r8.2 upgrade, A24')."""
    tenant, other = world.active_tenant(), world.active_tenant()
    _as_recorded_before_r8(world, tenant)
    mark = len(world.openbao.calls)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    record = world.record(tenant)
    assert (record.state, record.failure) == ("offboarded", None)
    assert {g.status for g in world.generations(tenant)} == {"destroyed"}
    assert [c.path for c in world.openbao.calls[mark:] if "None" in c.path] == []
    assert world.openbao.made("DELETE", f"/v1/auth/approle/role/{world.live(other).approle}") == [], "control: the other tenant is untouched"
    assert world.live(other).sign_approle in world.openbao.approles and _key(other) in world.openbao.transit_keys


def _seed_pending_before_r8(world, kind: str, past: tuple[str, ...] = ()) -> tuple[str, Any]:
    """A `kind` job (create or rotate) with a pending generation as an older deployment recorded it: the real `names` step
    and then the `past` steps run alone (no failure injected), then, past `template` or in a rotation, `main`'s rule as
    `main`'s `template` made it (merge whitelist off, no Owners team; pre-r8 rotation had no `protect`), then the sign names removed from the row and the sign
    chain (AppRole, entity, alias, key) from the twin, as the older code never made them. The job's next step is the one
    after the last of `past` (`provider` when none). Returns the tenant and the pending generation as seeded."""
    if kind == "create":
        tenant = world.create()
    else:
        tenant = world.active_tenant()
        assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202

    async def run(steps: tuple[str, ...]) -> None:
        async with world.tenants.lock(tenant) as held:
            assert held is not None
            for step in steps:
                await world.service_actor.steps()[step](held)
    world.call(run, ("names", *past))
    if kind == "rotate" or "template" in past:  # r8.6 A23: main's pre-r8 rule, which a pre-r8 job past `template` left
        world.forge.put_rule(f"{ORG}/{tenant}", rule_name="main", branch_name="main", enable_push=False,
                             enable_push_whitelist=False, enable_merge_whitelist=False, enable_force_push=False)
    pending = _row(world, tenant, "pending")
    bao = world.openbao
    if pending.sign_approle is not None:
        bao.approles.pop(pending.sign_approle, None)
        bao.approle_policies.pop(pending.sign_approle, None)
        bao.entities.pop(pending.sign_entity, None)
    bao.aliases[:] = [a for a in bao.aliases if a["name"] != pending.sign_role_id or pending.sign_role_id is None]
    bao.transit_keys.pop(_key(tenant), None)
    for name in SIGN_FIELDS:
        setattr(pending, name, None)
    item = world.item(tenant)
    assert (item["step"], item["step_actor"], item["failure"]) == (_NEXT_AFTER[kind][past[-1] if past else "names"], "service", None), item
    return tenant, _only_pending(world, tenant)


#: The step a job is parked at after the named step ran (the lifecycle's step lists).
_NEXT_AFTER = {"create": {"names": "provider", "provider": "repo", "repo": "bot", "bot": "integration", "integration": "template",
                          "template": "wrap"},
               "rotate": {"names": "provider", "provider": "bot", "bot": "protect", "protect": "integration", "integration": "wrap"}}


def _only_pending(world, tenant: str) -> Any:
    [pending] = [g for g in world.generations(tenant) if g.status == "pending"]
    return pending


class _LogsCommits:
    """A hold that logs, for each commit recording sign names, how many OpenBao requests had been made by then."""

    def __init__(self, held: Any, world: Any, log: list[tuple[int, dict[str, Any]]]) -> None:
        self._held, self._world, self._log = held, world, log

    def __getattr__(self, name: str) -> Any:
        return getattr(self._held, name)

    async def commit(self, **kwargs: Any) -> Any:
        for fields in (kwargs.get("update_generations") or {}).values():
            if any(name in fields for name in ("sign_approle", "sign_entity")):
                self._log.append((len(self._world.openbao.calls), dict(fields)))
        return await self._held.commit(**kwargs)


@pytest.mark.parametrize(("kind", "past"), [
    ("create", ()), ("create", ("provider", "repo")), ("create", ("provider", "repo", "bot", "integration", "template")),
    ("rotate", ()), ("rotate", ("provider", "bot", "protect")), ("rotate", ("provider", "bot", "protect", "integration"))])
def test_a_pending_generation_recorded_before_r8_completes_with_its_sign_login(world, kind, past):
    """A create or rotate job parked at any step from `provider` through `wrap` (rotations at `provider`, `integration` and
    `wrap`; the rule main's pre-r8 `template` made) over a pending generation with no sign names records them before any
    request makes the sign AppRole or entity, then completes with a working sign login, a rule holding the invariant, a bot
    that cannot merge and no failure (r8.5 A24', P1: an in-flight job finishes normally; r8.6 A23: the rule is healed before install)."""
    tenant, seeded = _seed_pending_before_r8(world, kind, past)
    assert (seeded.sign_approle, seeded.sign_entity, seeded.sign_role_id) == (None, None, None), "control: seeded without sign names"
    bao = world.openbao
    sign_approle, sign_entity = f"sign-{tenant}-{seeded.salt}", f"tenant-{tenant}-{seeded.salt}-sign"
    assert sign_approle not in bao.approles and sign_entity not in bao.entities, "control: no sign chain of this generation exists yet"
    mark, log, real = len(bao.calls), [], world.tenants.lock

    @contextlib.asynccontextmanager
    async def lock(tenant_id: str) -> Any:
        async with real(tenant_id) as held:
            yield None if held is None else _LogsCommits(held, world, log)
    world.tenants.lock = lock
    world.drive()
    world.tenants.lock = real

    assert log, "the provider recorded the sign names"
    recorded_after, fields = log[0]  # the first such commit; a later one may repeat the names (r8.5 allows it)
    assert (fields["sign_approle"], fields["sign_entity"]) == (sign_approle, sign_entity)
    made = [i for i, c in enumerate(bao.calls) if i >= mark and c.method in ("POST", "PUT")
            and c.path in (f"/v1/auth/approle/role/{sign_approle}", f"/v1/identity/entity/name/{sign_entity}")]
    assert made, "control: the provider made the sign AppRole and entity"
    assert recorded_after <= min(made) and recorded_after >= mark, "a sign AppRole or entity was requested before its names were recorded"

    item = world.item(tenant)
    assert (item["state"], item["pending_action"], item["failure"]) == ("active", None, None), item
    assert world.record(tenant).failure is None
    gen = world.live(tenant)
    assert gen.salt == seeded.salt and (gen.sign_approle, gen.sign_entity) == (sign_approle, sign_entity)
    assert all(getattr(gen, name) for name in SIGN_FIELDS if name != "sign_wrapped_secret")
    assert bao.approle_policies[gen.sign_approle] == [SIGN_POLICY] and sign_entity in bao.entities
    assert gen.sign_role_id in {a["name"] for a in bao.aliases}
    assert bao.transit_keys[_key(tenant)]["type"] == "ed25519"
    assert gen.sign_secret_file.read_text(encoding="utf-8") == bao.approles[gen.sign_approle][gen.sign_secret_accessor] + "\n"
    _delivery, sign = _pair(world, gen)
    assert _sign(world, sign, tenant) == 200
    rule = world.forge.rule(f"{ORG}/{tenant}")
    assert (rule["enable_push"], rule["enable_merge_whitelist"]) == (False, True), "the pre-r8 rule was healed before install"
    assert "Owners" in rule["merge_whitelist_teams"] and not rule["merge_whitelist_usernames"]
    view = as_bot(world, jwts(world, gen)[-1], f"repos/{ORG}/{tenant}/branches/main").json()
    assert (view["user_can_push"], view["user_can_merge"]) == (False, False)


@pytest.mark.parametrize("parked", ["install", "sweep"])
@pytest.mark.parametrize("kind", ["create", "rotate"])
def test_a_job_that_wrapped_or_installed_before_r8_goes_back_to_wrap_and_completes(world, kind, parked):
    """A create or rotate job whose `wrap` (parked at `install`) or host install (parked at `sweep`) ran before the sign
    login existed goes back to `wrap` and completes with a working sign login, one secret id per AppRole and no failure
    (r8.5: an in-flight job finishes normally)."""
    if kind == "create":
        tenant = world.create()
    else:
        tenant = world.active_tenant()
        assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive(stop=lambda: world.item(tenant)["step"] == parked)
    seeded, row, bao = _only_pending(world, tenant), _row(world, tenant, "pending"), world.openbao
    bao.approles.pop(seeded.sign_approle)
    bao.approle_policies.pop(seeded.sign_approle, None)
    bao.aliases[:] = [a for a in bao.aliases if a["name"] != seeded.sign_role_id]
    bao.entities.pop(seeded.sign_entity)
    if kind == "create":
        bao.transit_keys.pop(_key(tenant))
    if parked == "sweep":
        seeded.sign_secret_file.unlink()
    for name in SIGN_FIELDS:
        setattr(row, name, None)
    item, pending = world.item(tenant), _only_pending(world, tenant)
    assert (item["step"], item["failure"]) == (parked, None)
    assert (pending.wrapped_secret, pending.secret_accessor) == (seeded.wrapped_secret, seeded.secret_accessor), \
        "control: only the delivery secret was wrapped (and, at sweep, installed)"
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["pending_action"], item["failure"]) == ("active", None, None), item
    gen = world.live(tenant)
    assert gen.salt == seeded.salt and all(getattr(gen, name) for name in SIGN_FIELDS if name != "sign_wrapped_secret")
    assert list(bao.approles[gen.approle]) == [gen.secret_accessor], "the delivery secret id installed first was swept"
    assert list(bao.approles[gen.sign_approle]) == [gen.sign_secret_accessor]
    _delivery, sign = _pair(world, gen)
    assert _sign(world, sign, tenant) == 200
