# ruff: noqa: PT018
"""#1214 on real services (`live`): O8 two-tenant isolation, O9 lab adoption, and the OpenBao behaviours the in-memory
fakes can only assume (an old token's read of a deleted OIDC role is refused; the templated policy resolves per entity;
wrapped secret-id creation and accessor listing work under the management policy). Owner: the #1214 implementer, run
by hand on the dev stack after the revision is applied and Forgejo is 17.

Skips are for absent infrastructure only, each with the variable that is missing. Inputs (test-only environment):

    DEFENDER_LIVE_FORGE_URL             Forgejo 17, e.g. http://forgejo:3000
    DEFENDER_LIVE_FORGE_ADMIN_TOKEN     its administrator access token
    DEFENDER_LIVE_INTEGRATION_CONTAINER the Forgejo container `docker exec` runs `forgejo admin ...` in
    DEFENDER_LIVE_OPENBAO_URL           OpenBao, e.g. https://openbao:8200
    DEFENDER_LIVE_OPENBAO_ROOT_TOKEN    to set up the OpenBao-only cases (policies, keys, entities)
    DEFENDER_LIVE_OPENBAO_MANAGEMENT_TOKEN  a token holding the management policy the service logs in with
    DEFENDER_LIVE_OPENBAO_CA            the dev CA file (optional)
    DEFENDER_LIVE_LAB_TENANT, DEFENDER_LIVE_LAB_ISSUER_DIR, DEFENDER_LIVE_DATA_ROOT   the lab (O9 only)

    PYTHONPATH="$PWD" flock /tmp/defender-pytest.lock defender/.venv/bin/python -m pytest \\
        -m live defender/tests/tenancy/lifecycle_1214/test_1214_live.py

GAP-Rc-8: the real git runner of the lifecycle (the sealed-transport callable) is imported as `defender.lifecycle.git_runner`;
the name is the implementer's to give (fix `_stack`).
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import os
import subprocess
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.live

NOW = _dt.datetime(2026, 10, 29, 9, 0, tzinfo=_dt.UTC)


def _need(*names: str) -> dict[str, str]:
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        pytest.skip(f"set {', '.join(missing)} (Forgejo 17 and OpenBao in dev)")
    return {n: os.environ[n] for n in names}


@dataclass
class Live:
    forge_url: str
    forge_token: str
    container: str
    bao_url: str
    ca: str | bool


def _live() -> Live:
    env = _need("DEFENDER_LIVE_FORGE_URL", "DEFENDER_LIVE_FORGE_ADMIN_TOKEN", "DEFENDER_LIVE_INTEGRATION_CONTAINER",
                "DEFENDER_LIVE_OPENBAO_URL")
    return Live(env["DEFENDER_LIVE_FORGE_URL"], env["DEFENDER_LIVE_FORGE_ADMIN_TOKEN"],
                env["DEFENDER_LIVE_INTEGRATION_CONTAINER"], env["DEFENDER_LIVE_OPENBAO_URL"],
                os.environ.get("DEFENDER_LIVE_OPENBAO_CA") or True)


def _forgejo_major(live: Live) -> int:
    version = httpx.get(f"{live.forge_url}/api/v1/version", timeout=30).json()["version"]
    return int(version.split(".")[0])


def _integration_runner(container: str) -> Any:
    def run(arguments: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["docker", "exec", container, "forgejo", "admin", "user",  # noqa: S603, S607
                               "create-authorized-integration", *map(str, arguments)],
                              capture_output=True, text=True, timeout=120, check=False)
    return run


class _NoMembers:
    """Identity as the live cases need it: nobody is a member, so ending memberships is nothing."""

    async def end_tenant(self, _tenant: str, *, now: Any) -> None:
        return None


@dataclass
class Stack:
    service: Any
    host: Any
    tenants: Any
    live: Live
    openbao: Any
    config: Any

    async def drive(self, limit: int = 80) -> None:
        for _ in range(limit):
            if not (await self.service.work() + await self.host.work()):
                return
        raise AssertionError("the job did not settle")


def _stack(tmp_path: Path, live: Live, data_root: Path) -> Stack:
    """The real actors over the real services and an in-memory tenant repository (the PostgreSQL repository is covered
    by the contract suite)."""
    from defender.lifecycle import HostActor, ManagementService, git_runner  # noqa: PLC0415 — GAP-Rc-8
    from defender.tenancy import InMemoryTenantRepository, template_dir
    from defender.tests.tenancy.lifecycle_1214._support import REPO_ROOT, lifecycle_config

    env = _need("DEFENDER_LIVE_OPENBAO_MANAGEMENT_TOKEN")
    config = lifecycle_config(
        tmp_path, data_root, issuer_url=f"{live.bao_url}/v1/identity/oidc", forge_url=live.forge_url,
        forge_admin_token=live.forge_token, openbao_url=live.bao_url,
        openbao_login=env["DEFENDER_LIVE_OPENBAO_MANAGEMENT_TOKEN"], integration_command=live.container,
        template_dir=template_dir(REPO_ROOT))
    tenants: Any = InMemoryTenantRepository()
    forge_admin = httpx.AsyncClient(base_url=live.forge_url, headers={"Authorization": f"token {live.forge_token}"})
    bao_admin = httpx.AsyncClient(base_url=live.bao_url, verify=live.ca,
                                  headers={"X-Vault-Token": env["DEFENDER_LIVE_OPENBAO_MANAGEMENT_TOKEN"]})
    service = ManagementService(tenants, identity=_NoMembers(), forge=forge_admin, openbao=bao_admin,
                                integration=_integration_runner(live.container), git=git_runner, config=config,
                                clock=lambda: NOW)
    publish = lambda tenant, **_k: "fresh live-1214"  # noqa: E731 — the publish child is not under test here
    host = HostActor(tenants, forge=httpx.AsyncClient(base_url=live.forge_url),
                     openbao_login=httpx.AsyncClient(base_url=live.bao_url, verify=live.ca), git=git_runner,
                     publish=publish, config=config, clock=lambda: NOW)
    return Stack(service, host, tenants, live, bao_admin, config)


async def _create(stack: Stack) -> str:
    return (await stack.tenants.request_create(now=NOW)).id


async def _credential_token(stack: Stack, tenant: str) -> str:
    """A JWT minted exactly as the host does it: the recorded AppRole pair, the entity's OIDC role."""
    gen = next(g for g in await stack.tenants.generations(tenant) if g.status == "live")
    secret = Path(gen.host_secret_file).read_text(encoding="utf-8").strip()
    async with httpx.AsyncClient(base_url=stack.live.bao_url, verify=stack.live.ca) as bao:
        logged = await bao.post("/v1/auth/approle/login", json={"role_id": gen.role_id, "secret_id": secret})
        logged.raise_for_status()
        minted = await bao.get(f"/v1/identity/oidc/token/{gen.oidc_role}",
                               headers={"X-Vault-Token": logged.json()["auth"]["client_token"]})
        minted.raise_for_status()
        return minted.json()["data"]["token"]


def test_two_tenants_on_real_services_cannot_reach_each_other(tmp_path):
    """O8 on real Forgejo and OpenBao: A's JWT reads A's repo (200, control) and gets 404 on B's; B's integration refuses A's
    claim; both are offboarded afterwards (O8, O1, F-6)."""
    live = _live()
    if _forgejo_major(live) < 17:
        pytest.skip("needs Forgejo 17 (authorized integrations)")
    stack = _stack(tmp_path, live, tmp_path / "data")

    async def scenario() -> None:
        a, b = await _create(stack), await _create(stack)
        try:
            await stack.drive()
            for tenant in (a, b):
                assert (await stack.tenants.tenant(tenant)).state == "active"
            jwt = await _credential_token(stack, a)
            headers = {"Authorization": f"Bearer {jwt}"}
            async with httpx.AsyncClient(base_url=live.forge_url) as forge:
                assert (await forge.get(f"/api/v1/repos/tenants/{a}", headers=headers)).status_code == 200
                assert (await forge.get(f"/api/v1/repos/tenants/{b}", headers=headers)).status_code == 404
                crossed = await _credential_token(stack, b)  # B's own JWT on A's repo, the other direction
                assert (await forge.get(f"/api/v1/repos/tenants/{a}",
                                        headers={"Authorization": f"Bearer {crossed}"})).status_code == 404
        finally:
            for tenant in (a, b):
                with contextlib.suppress(Exception):
                    await stack.tenants.request_offboard(tenant, now=NOW)
            with contextlib.suppress(Exception):
                await stack.drive()
    asyncio.run(scenario())


def test_the_lab_is_adopted_and_its_old_facts_are_destroyed(tmp_path):
    """O9 on the lab: backfilled-style row -> `adopt` -> the actors -> `active` on the existing repo with only its new bot
    collaborating; `tenant.json`, the issuer directory and the old AppRole, role and entity are gone (O9, Flow 5)."""
    live = _live()
    env = _need("DEFENDER_LIVE_LAB_TENANT", "DEFENDER_LIVE_LAB_ISSUER_DIR", "DEFENDER_LIVE_DATA_ROOT")
    if _forgejo_major(live) < 17:
        pytest.skip("needs Forgejo 17 (authorized integrations)")
    lab, data_root, issuer_dir = env["DEFENDER_LIVE_LAB_TENANT"], Path(env["DEFENDER_LIVE_DATA_ROOT"]), Path(env["DEFENDER_LIVE_LAB_ISSUER_DIR"])
    stack = _stack(tmp_path, live, data_root)

    async def scenario() -> None:
        from defender.lifecycle import adopt

        await stack.tenants.add_tenant(
            lab, created_at=NOW, state="creating", pending_action="create", step="adopt", step_actor="service",
            failure="registered before #1214: adopt it", repo="tenants/playground",
            origin=f"{live.forge_url}/tenants/playground.git")
        await adopt(lab, tenants=stack.tenants, openbao=stack.openbao, config=stack.config,
                    clock=lambda: NOW, issuer_dir=issuer_dir)
        await stack.drive()
        assert (await stack.tenants.tenant(lab)).state == "active"
        await adopt(lab, tenants=stack.tenants, openbao=stack.openbao, config=stack.config,
                    clock=lambda: NOW, issuer_dir=issuer_dir)
        [live_gen] = [g for g in await stack.tenants.generations(lab) if g.status == "live"]
        headers = {"Authorization": f"token {live.forge_token}"}
        async with httpx.AsyncClient(base_url=live.forge_url, headers=headers) as forge:
            collaborators = {c["login"] for c in (await forge.get("/api/v1/repos/tenants/playground/collaborators")).json()}
        assert collaborators == {live_gen.bot_login}
        assert not (data_root / lab / "tenant.json").exists() and not (issuer_dir / "client" / lab).exists()
        async with httpx.AsyncClient(base_url=live.bao_url, verify=live.ca,
                                     headers={"X-Vault-Token": stack.config.openbao_login}) as bao:
            assert (await bao.get(f"/v1/auth/approle/role/delivery-{lab}")).status_code == 404
            assert (await bao.get(f"/v1/identity/oidc/role/tenant-{lab}")).status_code == 404
    asyncio.run(scenario())


# --- OpenBao alone (no production code) ------------------------------------------------------------

class Bao:
    """A thin OpenBao client; `cleanup` collects deletions run at the end."""

    def __init__(self, live: Live, token: str) -> None:
        self.http = httpx.Client(base_url=live.bao_url, verify=live.ca, headers={"X-Vault-Token": token}, timeout=30)
        self.cleanup: list[str] = []

    def write(self, path: str, body: dict | None = None, *, headers: dict | None = None) -> httpx.Response:
        return self.http.post(f"/v1/{path}", json=body or {}, headers=headers)

    def read(self, path: str) -> httpx.Response:
        return self.http.get(f"/v1/{path}")

    def undo(self) -> None:
        for path in reversed(self.cleanup):
            with contextlib.suppress(Exception):
                self.http.delete(f"/v1/{path}")


@pytest.fixture
def root() -> Iterator[Bao]:
    live = _live()
    token = _need("DEFENDER_LIVE_OPENBAO_ROOT_TOKEN")["DEFENDER_LIVE_OPENBAO_ROOT_TOKEN"]
    bao = Bao(live, token)
    yield bao
    bao.undo()


def _entity(bao: Bao, live_policy: str, name: str, key: str) -> dict[str, str]:
    """An OIDC role, an AppRole on the templated policy, and an entity (metadata `oidc_role`) aliased by the role id."""
    role, approle = f"live1214-role-{name}", f"live1214-approle-{name}"
    assert bao.write(f"identity/oidc/role/{role}", {"key": key, "ttl": "600s", "client_id": f"live-{name}"}).status_code in (200, 204)
    bao.cleanup.append(f"identity/oidc/role/{role}")
    assert bao.write(f"auth/approle/role/{approle}", {"token_policies": [live_policy]}).status_code in (200, 204)
    bao.cleanup.append(f"auth/approle/role/{approle}")
    role_id = bao.read(f"auth/approle/role/{approle}/role-id").json()["data"]["role_id"]
    entity = bao.write(f"identity/entity/name/live1214-{name}", {"metadata": {"oidc_role": role}}).json()["data"]["id"]
    bao.cleanup.append(f"identity/entity/name/live1214-{name}")
    accessor = bao.read("sys/auth").json()["data"]["approle/"]["accessor"]
    assert bao.write("identity/entity-alias", {"name": role_id, "canonical_id": entity, "mount_accessor": accessor}).status_code in (200, 204)
    secret = bao.write(f"auth/approle/role/{approle}/secret-id").json()["data"]["secret_id"]
    return {"role": role, "role_id": role_id, "secret_id": secret, "approle": approle}


def _setup_policy(bao: Bao, name: str) -> tuple[str, str]:
    policy, key = f"live1214-policy-{name}", f"live1214-key-{name}"
    rule = 'path "identity/oidc/token/{{identity.entity.metadata.oidc_role}}" { capabilities = ["read"] }'
    assert bao.http.put(f"/v1/sys/policies/acl/{policy}", json={"policy": rule}).status_code in (200, 204)
    bao.cleanup.append(f"sys/policies/acl/{policy}")
    assert bao.write(f"identity/oidc/key/{key}", {"algorithm": "RS256", "allowed_client_ids": "*"}).status_code in (200, 204)
    bao.cleanup.append(f"identity/oidc/key/{key}")
    return policy, key


def _login(live: Live, who: dict[str, str]) -> httpx.Client:
    with httpx.Client(base_url=live.bao_url, verify=live.ca, timeout=30) as anon:
        logged = anon.post("/v1/auth/approle/login", json={"role_id": who["role_id"], "secret_id": who["secret_id"]})
    assert logged.status_code == 200, logged.text
    return httpx.Client(base_url=live.bao_url, verify=live.ca, timeout=30,
                        headers={"X-Vault-Token": logged.json()["auth"]["client_token"]})


def test_the_templated_policy_resolves_per_entity(root):
    """One templated policy: each entity's AppRole token reads its own OIDC role's token (200, control) and is refused the
    other entity's (OpenBao, F-6)."""
    suffix = uuid.uuid4().hex[:8]
    policy, key = _setup_policy(root, suffix)
    one, two = _entity(root, policy, f"{suffix}-a", key), _entity(root, policy, f"{suffix}-b", key)
    live = _live()
    with _login(live, one) as a, _login(live, two) as b:
        assert a.get(f"/v1/identity/oidc/token/{one['role']}").status_code == 200
        assert b.get(f"/v1/identity/oidc/token/{two['role']}").status_code == 200
        assert a.get(f"/v1/identity/oidc/token/{two['role']}").status_code == 403
        assert b.get(f"/v1/identity/oidc/token/{one['role']}").status_code == 403


def test_an_old_token_cannot_read_a_deleted_oidc_role(root):
    """A token issued before the role was deleted reads it (200, control) and is refused afterwards (OpenBao, Flow 3)."""
    suffix = uuid.uuid4().hex[:8]
    policy, key = _setup_policy(root, suffix)
    who = _entity(root, policy, suffix, key)
    with _login(_live(), who) as client:
        assert client.get(f"/v1/identity/oidc/token/{who['role']}").status_code == 200
        assert root.http.delete(f"/v1/identity/oidc/role/{who['role']}").status_code == 204
        refused = client.get(f"/v1/identity/oidc/token/{who['role']}")
        assert refused.status_code in (400, 403, 404), refused.text


def test_wrapped_secret_ids_and_accessor_listing_work_under_the_management_policy(root):
    """With the management token: a wrapped secret id is made (a wrapping token, no secret in the answer), the AppRole's
    accessors are listed, and one is destroyed (OpenBao, DC-12, P1)."""
    live = _live()
    token = _need("DEFENDER_LIVE_OPENBAO_MANAGEMENT_TOKEN")["DEFENDER_LIVE_OPENBAO_MANAGEMENT_TOKEN"]
    managed = Bao(live, token)
    approle = f"live1214-wrap-{uuid.uuid4().hex[:8]}"
    try:
        assert managed.write(f"auth/approle/role/{approle}", {"secret_id_ttl": "10m"}).status_code in (200, 204)
        managed.cleanup.append(f"auth/approle/role/{approle}")
        wrapped = managed.write(f"auth/approle/role/{approle}/secret-id", headers={"X-Vault-Wrap-TTL": "600"})
        assert wrapped.status_code == 200 and wrapped.json()["wrap_info"]["token"], wrapped.text
        assert "secret_id" not in (wrapped.json().get("data") or {})
        listed = managed.http.request("LIST", f"/v1/auth/approle/role/{approle}/secret-id")
        assert listed.status_code == 200, listed.text
        [accessor] = listed.json()["data"]["keys"]
        destroyed = managed.write(f"auth/approle/role/{approle}/secret-id-accessor/destroy", {"secret_id_accessor": accessor})
        assert destroyed.status_code in (200, 204)
        assert managed.http.request("LIST", f"/v1/auth/approle/role/{approle}/secret-id").status_code == 404
    finally:
        managed.undo()
