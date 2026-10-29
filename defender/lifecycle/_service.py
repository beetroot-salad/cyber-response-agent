"""The management service (#1214 P5, Flows 1-3): the service's steps of create, rotate, offboard
and the repo deletion. It alone holds the forge admin token, the integration command and the
OpenBao management login; it reaches the execution host only through the tenant's row.

Every name a step creates outside PostgreSQL is committed first, at `names` (P1); every destroy
checks first and counts "already gone" as done (RC-4)."""
from __future__ import annotations

import asyncio
import datetime as _dt
import json
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

from defender import _io
from defender.identity import audit
from defender.lifecycle._bot import Minted, approle_login, mint
from defender.lifecycle._job import SERVICE, Actor, Step, StepFailed, answered, field_of, next_step, only
from defender.lifecycle.config import LifecycleConfig
from defender.tenancy import ALL, ForgeWiring, Generation, HeldTenant, TenantId, TenantRepository, tenant_id_file_text

#: The forge organisation every tenant's repository is made in.
ORG = "tenants"
#: How long the archived repo is kept after offboarding (Q5).
REPO_WINDOW = _dt.timedelta(days=30)
#: The OIDC role's claim template: the minting entity's tenant (G10, F-6).
CLAIMS = '{"tenant_id": {{identity.entity.metadata.tenant_id}}}'
#: How long a JWT of a tenant lives, and a wrapped secret waits for the host.
TOKEN_TTL = "10m"
WRAP_TTL = "600"
MAIN_WAIT_TRIES = 40
MAIN_WAIT_SECONDS = 0.25
_COLLABORATOR_PAGE = 50

Git = Callable[..., subprocess.CompletedProcess[str]]
Integration = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class ManagementService(Actor):
    """The service's half of every tenant's job. `forge` and `openbao` are HTTP clients carrying the
    admin token and the management login; `integration` runs the fixed integration command with
    the recorded arguments; `git` is the sealed-transport git runner (`git_runner`); `identity`
    ends the tenant's memberships (`end_tenant`)."""

    actor = SERVICE

    def __init__(self, tenants: TenantRepository, *, identity: Any, forge: httpx.AsyncClient,  # noqa: PLR0913 — the pinned constructor
                 openbao: httpx.AsyncClient, integration: Integration, git: Git, config: LifecycleConfig,
                 clock: Callable[[], _dt.datetime]) -> None:
        super().__init__(tenants, clock=clock, secrets=(config.forge_admin_token, config.openbao_login))
        self._identity, self._forge, self._bao = identity, forge, openbao
        self._run_integration, self._git, self._config = integration, git, config

    def steps(self) -> Mapping[str, Step]:
        return {"names": self._names, "provider": self._provider, "repo": self._repo, "bot": self._bot,
                "integration": self._integration, "template": self._template, "wrap": self._wrap,
                "sweep": self._sweep, "activate": self._activate, "retire": self._retire,
                "offboard": self._offboard, "finish": self._finish, "delete_repo": self._delete_repo}

    async def _commit_next(self, held: HeldTenant, **records: Any) -> None:
        step, actor = next_step(held)
        await held.commit(step=step, actor=actor, **records)

    # --- create and rotate ------------------------------------------------------------------------

    async def _names(self, held: HeldTenant) -> None:
        """P1: the new generation's names and the integration's arguments, and (unless the tenant has
        them, as the lab does) the repo and its origin, before anything is made."""
        tenant = held.tenant_id
        wiring = await held.forge_wiring()
        if wiring is None:
            repo = f"{ORG}/{tenant}"
            wiring = ForgeWiring(tenant_id=tenant, repo=repo, origin=f"{self._config.forge_url.rstrip('/')}/{repo}.git")
        salt = secrets.token_hex(4)
        bot = f"bot-{tenant[:8]}-{salt}"
        generation = Generation(
            tenant_id=tenant, salt=salt, status="pending", bot_login=bot,
            oidc_role=f"tenant-{tenant}-{salt}", approle=f"delivery-{tenant}-{salt}", entity=f"tenant-{tenant}-{salt}",
            integration_args=["--username", bot, "--name", f"defender-{salt}", "--issuer", self._config.issuer_url,
                              "--claim-eq", f"tenant_id={tenant}", "--scope", "write:repository",
                              "--repo", wiring.repo])
        repo_url = held.record.repo_url or f"{self._config.forge_url.rstrip('/')}/{wiring.repo}"
        await self._commit_next(held, add_generation=generation, wiring=wiring, repo_url=repo_url)

    async def _building(self, held: HeldTenant) -> Generation:
        return only(await held.generations(), "pending")

    async def _wiring(self, held: HeldTenant) -> ForgeWiring:
        wiring = await held.forge_wiring()
        if wiring is None:
            raise StepFailed("the tenant has no forge wiring")
        return wiring

    async def _provider(self, held: HeldTenant) -> None:
        """The OIDC role, the AppRole on the templated policy, the entity naming its role and tenant,
        and the entity's alias by the AppRole's role id (Flow 1.3), before the integration."""
        gen = await self._building(held)
        await self._write_role(gen, client_id=None)
        answered(await self._bao.post(f"/v1/auth/approle/role/{gen.approle}", json={
            "token_policies": [self._config.token_policy], "token_ttl": TOKEN_TTL, "token_max_ttl": TOKEN_TTL,
            "secret_id_ttl": 0, "secret_id_num_uses": 0}))
        role_id = str(field_of(answered(await self._bao.get(f"/v1/auth/approle/role/{gen.approle}/role-id")),
                               "data", "role_id"))
        made = answered(await self._bao.post(f"/v1/identity/entity/name/{gen.entity}", json={
            "metadata": {"oidc_role": gen.oidc_role, "tenant_id": held.tenant_id}}))
        entity_id = (made.json().get("data") or {}).get("id") if made.content else None
        if not entity_id:
            entity_id = field_of(answered(await self._bao.get(f"/v1/identity/entity/name/{gen.entity}")), "data", "id")
        mounts = field_of(answered(await self._bao.get("/v1/sys/auth")), "data")
        accessor = (mounts.get("approle/") or {}).get("accessor") if isinstance(mounts, dict) else None
        if not accessor:
            raise StepFailed("OpenBao has no approle/ auth mount")
        answered(await self._bao.post("/v1/identity/entity-alias", json={
            "name": role_id, "canonical_id": entity_id, "mount_accessor": accessor}))
        await self._commit_next(held, update_generations={gen.salt: {"role_id": role_id}})

    async def _write_role(self, gen: Generation, *, client_id: str | None) -> None:
        """The generation's OIDC role; its claim comes from the minting entity's metadata, and its
        client id (once the integration exists) is the integration's audience."""
        body: dict[str, Any] = {"key": self._config.oidc_key, "ttl": TOKEN_TTL, "template": CLAIMS}
        if client_id is not None:
            body["client_id"] = client_id
        answered(await self._bao.post(f"/v1/identity/oidc/role/{gen.oidc_role}", json=body))

    async def _repo(self, held: HeldTenant) -> None:
        """The tenant's private repository, made empty if absent (Flow 1.4)."""
        wiring = await self._wiring(held)
        found = answered(await self._forge.get(f"/api/v1/repos/{wiring.repo}"), 404)
        if found.status_code == 404:
            org, name = wiring.repo.split("/", 1)
            answered(await self._forge.post(f"/api/v1/orgs/{org}/repos", json={
                "name": name, "private": True, "auto_init": False, "default_branch": "main"}))
        elif found.json().get("private") is not True:
            raise StepFailed(f"the repository {wiring.repo} exists and is not private")
        await self._commit_next(held)

    async def _bot(self, held: HeldTenant) -> None:
        """The new bot, able to sign in through its integration (G23, G15: a random password nobody
        keeps, not login-prohibited), the repo's write collaborator; every other collaborator but the
        live bot (rotation keeps it until `retire`) is removed (Flow 1.5)."""
        gens = await held.generations()
        gen = only(gens, "pending")
        wiring = await self._wiring(held)
        if answered(await self._forge.get(f"/api/v1/users/{gen.bot_login}"), 404).status_code == 404:
            answered(await self._forge.post("/api/v1/admin/users", json={
                "username": gen.bot_login, "email": f"{gen.bot_login}@bots.invalid", "visibility": "private",
                "password": self.secret(secrets.token_urlsafe(32)), "must_change_password": False}))
        answered(await self._forge.put(f"/api/v1/repos/{wiring.repo}/collaborators/{gen.bot_login}",
                                       json={"permission": "write"}))
        keep = {gen.bot_login, *(g.bot_login for g in gens if g.status == "live")}
        for login_name in await self._collaborators(wiring.repo):
            if login_name not in keep:
                answered(await self._forge.delete(f"/api/v1/repos/{wiring.repo}/collaborators/{login_name}"), 404)
        await self._commit_next(held)

    async def _collaborators(self, repo: str) -> list[str]:
        found: list[str] = []
        page = 1
        while True:
            listed = answered(await self._forge.get(f"/api/v1/repos/{repo}/collaborators",
                                                    params={"page": page, "limit": _COLLABORATOR_PAGE})).json()
            if not isinstance(listed, list):
                raise StepFailed(f"the collaborators of {repo} are not a list")
            found += [str(c.get("login")) for c in listed if isinstance(c, dict)]
            if len(listed) < _COLLABORATOR_PAGE:
                return found
            page += 1

    async def _integration(self, held: HeldTenant) -> None:
        """The fixed command with the recorded arguments (Flow 1.6), then the OIDC role's client id
        set to its audience (RC-6), then the audience recorded. A repeat after a crash adds a second,
        identical integration to the bot, which dies with it."""
        gen = await self._building(held)
        done = await asyncio.to_thread(self._run_integration, list(gen.integration_args or ()))
        if done.returncode != 0:
            raise StepFailed(f"the integration command failed (exit {done.returncode}): {(done.stderr + done.stdout).strip()}")
        try:
            audience = json.loads(done.stdout).get("audience")
        except (ValueError, AttributeError):
            audience = None
        if not isinstance(audience, str) or not audience:
            raise StepFailed("the integration command printed no audience")
        await self._write_role(gen, client_id=audience)
        await self._commit_next(held, update_generations={gen.salt: {"audience": audience}})

    async def _template(self, held: HeldTenant) -> None:
        """An empty repo gets the template and `agent/.tenant-id`, pushed as the bot (DC-10); then
        `main` is protected and the protection read back (Flow 1.7)."""
        gen = await self._building(held)
        wiring = await self._wiring(held)
        repo = answered(await self._forge.get(f"/api/v1/repos/{wiring.repo}"))
        if repo.json().get("empty") is True:
            credential = Minted(held.tenant_id, await self._bot_jwt(gen))
            await asyncio.to_thread(self._push_template, held.tenant_id, wiring.origin, credential)
        await self._await_main(wiring.repo)
        rule = f"/api/v1/repos/{wiring.repo}/branch_protections/main"
        if answered(await self._forge.get(rule), 404).status_code == 404:
            answered(await self._forge.post(f"/api/v1/repos/{wiring.repo}/branch_protections", json={
                "rule_name": "main", "branch_name": "main", "enable_push": False, "enable_push_whitelist": False,
                "enable_merge_whitelist": False, "enable_force_push": False}))
        back = answered(await self._forge.get(rule)).json()
        if not isinstance(back, dict) or "main" not in (back.get("rule_name"), back.get("branch_name")):
            raise StepFailed(f"the protection of main on {wiring.repo} does not read back")
        await self._commit_next(held)

    async def _await_main(self, repo: str) -> None:
        """The forge accepts a push before it registers the branch (it does that after the push returns),
        so `main` is waited for, bounded, before anything reads or protects it."""
        for _ in range(MAIN_WAIT_TRIES):
            if answered(await self._forge.get(f"/api/v1/repos/{repo}")).json().get("empty") is not True:
                return
            await asyncio.sleep(MAIN_WAIT_SECONDS)
        raise StepFailed(f"{repo} is still empty after the template push")

    async def _bot_jwt(self, gen: Generation) -> str:
        """The bot's JWT, through a short-lived secret id of the recorded AppRole (swept at `sweep`, P1)."""
        made = answered(await self._bao.post(f"/v1/auth/approle/role/{gen.approle}/secret-id"))
        secret = self.secret(str(field_of(made, "data", "secret_id")))
        token = self.secret(await approle_login(self._bao, str(gen.role_id), secret))
        return self.secret(await mint(self._bao, gen.oidc_role, token))

    def _push_template(self, tenant: str, origin: str, credential: Minted) -> None:
        with tempfile.TemporaryDirectory(prefix="defender-template-") as scratch:
            work = Path(scratch) / "repo"
            shutil.copytree(self._config.template_dir, work, symlinks=True)
            _io.guarded_mkdir(work / "agent", base=work)
            _io.write_guarded(work / "agent" / ".tenant-id", tenant_id_file_text(TenantId(tenant)))
            author = ["-c", "user.name=defender", "-c", "user.email=defender@bots.invalid"]
            for args in (["init", "-q", "-b", "main"], ["add", "-A", "-f"],
                         [*author, "commit", "-q", "-m", "tenant template"]):
                self._git_ok(args, cwd=work)
            self._git_ok(["push", "-q", origin, "HEAD:refs/heads/main"], cwd=work, origin=origin,
                         identity=credential)

    def _git_ok(self, args: list[str], **kw: Any) -> None:
        done = self._git(args, **kw)
        if done.returncode != 0:
            verb = next(a for i, a in enumerate(args) if not a.startswith("-") and (i == 0 or args[i - 1] != "-c"))
            raise StepFailed(f"git {verb} failed: {(done.stderr + done.stdout).strip()}")

    async def _wrap(self, held: HeldTenant) -> None:
        """A fresh single-use wrapped secret id for the host (Flow 1.7, DC-12)."""
        gen = await self._building(held)
        made = answered(await self._bao.post(f"/v1/auth/approle/role/{gen.approle}/secret-id",
                                             headers={"X-Vault-Wrap-TTL": WRAP_TTL}))
        wrapped = self.secret(str(field_of(made, "wrap_info", "token")))
        await self._commit_next(held, update_generations={gen.salt: {"wrapped_secret": wrapped}})

    async def _sweep(self, held: HeldTenant) -> None:
        """Every secret id of the AppRole but the one the host installed is destroyed (P1, RC-9); the
        new generation goes live, the one before it `retiring` (DC-5)."""
        gen = await self._building(held)
        if not gen.secret_accessor:
            raise StepFailed("the host recorded no installed secret")
        await self._sweep_secret_ids(gen.approle, keep=gen.secret_accessor)
        await self._commit_next(held, go_live=gen.salt)

    async def _sweep_secret_ids(self, approle: str, *, keep: str) -> None:
        listed = answered(await self._bao.get(f"/v1/auth/approle/role/{approle}/secret-id", params={"list": "true"}), 404)
        keys = field_of(listed, "data", "keys") if listed.status_code != 404 else []
        for accessor in keys:
            if accessor != keep:
                answered(await self._bao.post(f"/v1/auth/approle/role/{approle}/secret-id-accessor/destroy",
                                              json={"secret_id_accessor": accessor}), 404)

    async def _activate(self, held: HeldTenant) -> None:
        """The tenant is `active`, nothing pending (Flow 1.10, RC-9)."""
        await held.commit(step=None, actor=None, state="active", pending_action=None)

    async def _retire(self, held: HeldTenant) -> None:
        """Rotation's end on the forge and OpenBao: the old chain destroyed, its bot (and with it its
        integrations, so its JWTs) first (FR-8)."""
        old = [g for g in await held.generations() if g.status == "retiring"]
        for gen in old:
            await self._destroy(gen)
        await self._commit_next(held, destroy=[g.salt for g in old])

    async def _destroy(self, gen: Generation) -> None:
        """A generation's chain, each part checked first (RC-4): the bot with `purge` (its
        integrations go with it, G8), the OIDC role, the AppRole and its secret ids, the entity."""
        if answered(await self._forge.get(f"/api/v1/users/{gen.bot_login}"), 404).status_code != 404:
            answered(await self._forge.delete(f"/api/v1/admin/users/{gen.bot_login}", params={"purge": "true"}), 404)
        for path in (f"identity/oidc/role/{gen.oidc_role}", f"auth/approle/role/{gen.approle}",
                     f"identity/entity/name/{gen.entity}"):
            answered(await self._bao.delete(f"/v1/{path}"), 404)

    # --- offboard -------------------------------------------------------------------------------

    async def _offboard(self, held: HeldTenant) -> None:
        """Memberships end and invitations are revoked, every generation is destroyed, the repo is
        archived (Flow 2.2)."""
        await self._identity.end_tenant(held.tenant_id, now=self._clock())
        for gen in await held.generations():
            if gen.status != "destroyed":
                await self._destroy(gen)
        wiring = await held.forge_wiring()
        if wiring is not None:
            answered(await self._forge.patch(f"/api/v1/repos/{wiring.repo}", json={"archived": True}), 404)
        await self._commit_next(held, destroy=ALL)

    async def _finish(self, held: HeldTenant) -> None:
        """The by-name sweep once more (late effects of a timed-out call), then `offboarded` with the
        repo deletion pending once the window ends; the publish status goes (Flow 2.4)."""
        for gen in await held.generations():
            await self._destroy(gen)
        now = self._clock()
        await held.commit(step="delete_repo", actor=SERVICE, state="offboarded", pending_action="delete_repo",
                          offboarded_at=now, repo_delete_after=now + REPO_WINDOW, drop_publish_status=True)

    async def _delete_repo(self, held: HeldTenant) -> None:
        """Due once `repo_delete_after` passed (the listing waits for it): the by-name sweep again
        (RC-8), the repo deleted, `repo_url` and the wiring cleared; audited after the commit."""
        for gen in await held.generations():
            await self._destroy(gen)
        wiring = await held.forge_wiring()
        if wiring is not None and answered(await self._forge.get(f"/api/v1/repos/{wiring.repo}"), 404).status_code != 404:
            answered(await self._forge.delete(f"/api/v1/repos/{wiring.repo}"), 404)
        await held.commit(step=None, actor=None, pending_action=None, repo_url=None, drop_wiring=True)
        audit.emit("tenant.repo.delete", actor=audit.SYSTEM, tenant_id=held.tenant_id, target=held.tenant_id)
