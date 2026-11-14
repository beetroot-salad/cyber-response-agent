"""The management service (#1214 P5, Flows 1-3): the service's steps of create, rotate, offboard
and the repo deletion. It alone holds the forge admin token, the integration command and the
OpenBao management login; it reaches the execution host only through the tenant's row.

Every name a step creates outside PostgreSQL is committed first, at `names` (P1); every destroy
checks first and counts "already gone" as done (RC-4)."""
from __future__ import annotations

import asyncio
import datetime as _dt
import json
import logging
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx

from defender import _git, _io
from defender.configuration.issuer import TRANSIT_MOUNT
from defender.credential_proxy import transit_key_for
from defender.identity import audit
from defender.lifecycle._bot import Minted, log_in, mint
from defender.lifecycle._eligibility import eligible_to_merge, listed_logins
from defender.lifecycle._job import SERVICE, Actor, Step, StepFailed, answered, field_of, next_step, only
from defender.lifecycle.config import LifecycleConfig
from defender.tenancy import ALL, ForgeWiring, Generation, HeldTenant, TenantId, TenantRepository, tenant_id_file_text

#: The forge organisation every tenant's repository is made in.
ORG = "tenants"
#: The team of the repository's owning organisation that alone may merge `main` (#1163 A23).
OWNERS = "Owners"
#: How long the archived repo is kept after offboarding (Q5).
REPO_WINDOW = _dt.timedelta(days=30)
#: The OIDC role's claim template: the minting entity's tenant (G10, F-6).
CLAIMS = '{"tenant_id": {{identity.entity.metadata.tenant_id}}}'
#: How long a JWT of a tenant lives, and a wrapped secret waits for the host.
TOKEN_TTL = "10m"
WRAP_TTL = "600"
#: The integration's grant: the repository, and issues, labels and comments (#1414 D13). One value, the way the forge takes it.
INTEGRATION_SCOPES = "write:repository,write:issue"
#: How old a tenant's merge-eligibility record may be before a pass reads it again: a third of the feedback tick's
#: default 60 s staleness bound, so a record never goes stale between passes, and the forge is not read every pass.
ELIGIBILITY_REFRESH = _dt.timedelta(seconds=20)
MAIN_WAIT_TRIES = 40
MAIN_WAIT_SECONDS = 0.25

_logger = logging.getLogger(__name__)

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
                "protect": self._protect, "integration": self._integration, "template": self._template, "wrap": self._wrap,
                "sweep": self._sweep, "activate": self._activate, "retire": self._retire,
                "offboard": self._offboard, "finish": self._finish, "delete_repo": self._delete_repo}

    async def work(self) -> int:
        """The job's steps (`Actor.work`), then the merge eligibility of every active tenant whose record is older than
        `ELIGIBILITY_REFRESH` read afresh (#1414 D13), whether or not a step ran. The count is the steps run."""
        ran = await super().work()
        await self._record_eligibility()
        return ran

    async def _record_eligibility(self) -> None:
        """For each active tenant: `main`'s merge whitelist (users and team members) less every generation's bot,
        recorded with the time read. A read that fails, for any reason, is logged and leaves the tenant's earlier record
        as it was; the other tenants are still read."""
        try:
            tenants = [t for t in await self._tenants.tenants() if t.state == "active"]
        except Exception:  # noqa: BLE001 — a failed listing never fails the pass: the next one retries
            _logger.exception("merge eligibility: the tenants could not be listed")
            return
        for tenant in tenants:
            try:
                await self._record_eligibility_of(tenant.id)
            except Exception as failed:  # noqa: BLE001 — one tenant's failed read keeps its record and never stops the others
                _logger.warning("tenant %s: merge eligibility not read, the earlier record stays: %s", tenant.id, failed)

    async def _record_eligibility_of(self, tenant: TenantId) -> None:
        recorded = await self._tenants.merge_eligibility(tenant)
        if recorded is not None and _dt.timedelta(0) <= self._clock() - recorded.read_at < ELIGIBILITY_REFRESH:
            return
        wiring = await self._tenants.forge_wiring(tenant)
        if wiring is None:
            raise StepFailed("the tenant has no forge wiring")
        bots = {g.bot_login for g in await self._tenants.generations(tenant)}
        logins = await eligible_to_merge(self._forge, wiring.repo, bots=bots)
        await self._tenants.record_merge_eligibility(tenant, logins=logins, read_at=self._clock())

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
        sign = _sign_names(tenant, salt)
        generation = Generation(
            tenant_id=tenant, salt=salt, status="pending", bot_login=bot,
            oidc_role=f"tenant-{tenant}-{salt}", approle=f"delivery-{tenant}-{salt}", entity=f"tenant-{tenant}-{salt}",
            sign_approle=sign["sign_approle"], sign_entity=sign["sign_entity"],
            integration_args=["--username", bot, "--name", f"defender-{salt}", "--issuer", self._config.issuer_url,
                              "--claim-eq", f"tenant_id={tenant}", "--scope", INTEGRATION_SCOPES,
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
        and the entity's alias by the AppRole's role id (Flow 1.3), before the integration; then the
        sign-only chain the same way on the sign policy, its entity carrying the tenant (A24'), and the
        tenant's signing key, made if absent (A25). A re-run after a crash reuses what exists.

        A pending generation recorded before the sign login existed gets its sign names recorded
        first, before anything is made (r8.5, P1)."""
        gen = await self._with_sign_names(held, await self._building(held))
        await self._write_role(gen, client_id=None)
        accessor = await self._approle_accessor()
        role_id = await self._approle(gen.approle, self._config.token_policy)
        await self._entity(gen.entity, {"oidc_role": gen.oidc_role, "tenant_id": held.tenant_id}, role_id, accessor)
        sign_role_id = await self._sign_chain(held, gen, accessor)
        await self._commit_next(held, update_generations={gen.salt: {"role_id": role_id, "sign_role_id": sign_role_id}})

    async def _with_sign_names(self, held: HeldTenant, gen: Generation) -> Generation:
        """`gen`, its sign names recorded first if it was recorded before the sign login existed
        (r8.5, P1): committed before anything is made."""
        if gen.sign_approle is not None and gen.sign_entity is not None:
            return gen
        await held.commit(step=held.record.step, actor=SERVICE,
                          update_generations={gen.salt: _sign_names(held.tenant_id, gen.salt)})
        return await self._building(held)

    async def _sign_chain(self, held: HeldTenant, gen: Generation, accessor: str) -> str:
        """The sign-only AppRole on the sign policy, its own entity carrying the tenant, and the
        tenant's signing key (A24', A25); the sign role id. Reuses what exists."""
        sign_role_id = await self._approle(str(gen.sign_approle), self._config.sign_policy)
        await self._entity(str(gen.sign_entity), {"tenant_id": held.tenant_id}, sign_role_id, accessor)
        await self._ensure_key(held.tenant_id)
        return sign_role_id

    async def _approle_accessor(self) -> str:
        mounts = field_of(answered(await self._bao.get("/v1/sys/auth")), "data")
        accessor = (mounts.get("approle/") or {}).get("accessor") if isinstance(mounts, dict) else None
        if not accessor:
            raise StepFailed("OpenBao has no approle/ auth mount")
        return str(accessor)

    async def _approle(self, name: str, policy: str) -> str:
        """The AppRole `name` on the one templated `policy` (written again if it exists); its role id."""
        answered(await self._bao.post(f"/v1/auth/approle/role/{name}", json={
            "token_policies": [policy], "token_ttl": TOKEN_TTL, "token_max_ttl": TOKEN_TTL,
            "secret_id_ttl": 0, "secret_id_num_uses": 0}))
        return str(field_of(answered(await self._bao.get(f"/v1/auth/approle/role/{name}/role-id")), "data", "role_id"))

    async def _entity(self, name: str, metadata: Mapping[str, str], role_id: str, accessor: str) -> None:
        """The entity `name` with `metadata`, aliased on the AppRole mount by `role_id`. An entity that
        exists is updated, and its alias on the mount kept: OpenBao allows one alias per entity and mount."""
        answered(await self._bao.post(f"/v1/identity/entity/name/{name}", json={"metadata": dict(metadata)}))
        entity = field_of(answered(await self._bao.get(f"/v1/identity/entity/name/{name}")), "data")
        entity_id = entity.get("id") if isinstance(entity, dict) else None
        if not entity_id:
            raise StepFailed(f"OpenBao answered no id for the entity {name}")
        aliases = [a for a in entity.get("aliases") or [] if isinstance(a, dict) and a.get("mount_accessor") == accessor]
        if any(a.get("name") == role_id for a in aliases):
            return
        if aliases:
            raise StepFailed(f"the entity {name} is aliased on the AppRole mount by another role id")
        answered(await self._bao.post("/v1/identity/entity-alias", json={
            "name": role_id, "canonical_id": entity_id, "mount_accessor": accessor}))

    async def _ensure_key(self, tenant: str) -> None:
        """The tenant's request-token signing key, made (ed25519) only when absent: one key per tenant,
        kept across rotations (A25)."""
        path = f"/v1/{TRANSIT_MOUNT}/keys/{transit_key_for(tenant)}"
        if answered(await self._bao.get(path), 404).status_code == 404:
            answered(await self._bao.post(path, json={"type": "ed25519"}))

    async def _destroy_key(self, tenant: str) -> None:
        """The tenant's signing key, at offboarding only: read (absent is done), made deletable, deleted
        (A25, RC-4)."""
        path = f"/v1/{TRANSIT_MOUNT}/keys/{transit_key_for(tenant)}"
        if answered(await self._bao.get(path), 404).status_code == 404:
            return
        answered(await self._bao.post(f"{path}/config", json={"deletion_allowed": True}))
        answered(await self._bao.delete(path), 404)

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
        return await listed_logins(self._forge, f"/api/v1/repos/{repo}/collaborators", f"the collaborators of {repo}")

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
        `main` is protected and the protection read back (Flow 1.7, A23: after the push, which a rule
        made before it would refuse)."""
        gen = await self._building(held)
        wiring = await self._wiring(held)
        repo = answered(await self._forge.get(f"/api/v1/repos/{wiring.repo}"))
        if repo.json().get("empty") is True:
            credential = Minted(held.tenant_id, await self._bot_jwt(gen))
            await asyncio.to_thread(self._push_template, held.tenant_id, wiring.origin, credential)
        await self._await_main(wiring.repo)
        await self._protect_main(held, wiring)
        await self._commit_next(held)

    async def _protect(self, held: HeldTenant) -> None:
        """Rotation's `main` rule (A23, r8.3): the invariant `template` sets at creation, enforced and
        read back again after `bot`, so a rotation heals a tenant made before it."""
        await self._protect_main(held, await self._wiring(held))
        await self._commit_next(held)

    async def _protect_main(self, held: HeldTenant, wiring: ForgeWiring) -> None:
        """`main`'s rule holds the invariant, as stored (A23, r8.2): push disabled, the merge whitelist
        enabled with the owning organisation's `Owners` team on it, and no bot login of any of the
        tenant's generations; other users and teams on it are kept. An absent rule is made, one that
        breaks the invariant is changed with both whitelists sent whole (the forge keeps a list a
        change omits). The rule is then read back as stored: the forge drops a user without access to
        the repository and every team of a user-owned one, so only the stored rule shows the invariant."""
        bots = {g.bot_login for g in await held.generations()}
        rules = f"/api/v1/repos/{wiring.repo}/branch_protections"
        found = answered(await self._forge.get(f"{rules}/main"), 404)
        if found.status_code == 404:
            answered(await self._forge.post(rules, json={
                "rule_name": "main", "branch_name": "main", "enable_push": False, "enable_push_whitelist": False,
                "enable_force_push": False, "enable_merge_whitelist": True, "merge_whitelist_usernames": [],
                "merge_whitelist_teams": [OWNERS]}))
        else:
            rule = _rule(found, wiring.repo)
            if _breaks_invariant(rule, bots) is not None:
                users = [u for u in _names_in(rule, "merge_whitelist_usernames") if u not in bots]
                teams = _names_in(rule, "merge_whitelist_teams")
                answered(await self._forge.patch(f"{rules}/main", json={
                    "enable_push": False, "enable_merge_whitelist": True, "merge_whitelist_usernames": users,
                    "merge_whitelist_teams": teams if OWNERS in teams else [*teams, OWNERS]}))
        broken = _breaks_invariant(_rule(answered(await self._forge.get(f"{rules}/main")), wiring.repo), bots)
        if broken is not None:
            raise StepFailed(f"the protection of main on {wiring.repo} reads back with {broken}")

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
        token = self.secret(await log_in(self._bao, str(gen.role_id), secret))
        return self.secret(await mint(self._bao, gen.oidc_role, token))

    def _push_template(self, tenant: str, origin: str, credential: Minted) -> None:
        with tempfile.TemporaryDirectory(prefix="defender-template-") as scratch:
            work = Path(scratch) / "repo"
            shutil.copytree(self._config.template_dir, work, symlinks=True)
            _io.guarded_mkdir(work / "agent", base=work)
            _io.write_guarded(work / "agent" / ".tenant-id", tenant_id_file_text(TenantId(tenant)))
            for args in (["init", "-q", "-b", "main"], ["add", "-A", "-f"], ["commit", "-q", "-m", "tenant template"]):
                self._git_ok(args, cwd=work, env=_git.PRODUCT_IDENTITY)
            self._git_ok(["push", "-q", origin, "HEAD:refs/heads/main"], cwd=work, origin=origin,
                         identity=credential)

    def _git_ok(self, args: list[str], **kw: Any) -> None:
        done = self._git(args, **kw)
        if done.returncode != 0:
            verb = next(a for i, a in enumerate(args) if not a.startswith("-") and (i == 0 or args[i - 1] != "-c"))
            raise StepFailed(f"git {verb} failed: {(done.stderr + done.stdout).strip()}")

    async def _wrap(self, held: HeldTenant) -> None:
        """A fresh single-use wrapped secret id for the host of each AppRole, delivery and sign (Flow
        1.7, DC-12, A24'). First `main`'s rule is enforced again (r8.6): install, the host's step, checks
        it as the bot but cannot change it, and a job in flight across the upgrade, or a rule changed by
        hand, reaches it here, as does every install that failed and restarts at `wrap`."""
        await self._protect_main(held, await self._wiring(held))
        gen = await self._building(held)
        if gen.sign_role_id is None:
            # A generation recorded before the sign login existed whose job was already past
            # `provider` at the upgrade: its sign chain is made here, as `provider` would have
            # (r8.5: an in-flight job finishes normally).
            gen = await self._with_sign_names(held, gen)
            sign_role_id = await self._sign_chain(held, gen, await self._approle_accessor())
            await held.commit(step=held.record.step, actor=SERVICE,
                              update_generations={gen.salt: {"sign_role_id": sign_role_id}})
            gen = await self._building(held)
        wrapped = [self.secret(str(field_of(answered(await self._bao.post(
            f"/v1/auth/approle/role/{approle}/secret-id", headers={"X-Vault-Wrap-TTL": WRAP_TTL})), "wrap_info", "token")))
            for approle in (gen.approle, gen.sign_approle)]
        await self._commit_next(held, update_generations={
            gen.salt: {"wrapped_secret": wrapped[0], "sign_wrapped_secret": wrapped[1]}})

    async def _sweep(self, held: HeldTenant) -> None:
        """Every secret id of both AppRoles but the ones the host installed is destroyed (P1, RC-9,
        A24'); the new generation goes live, the one before it `retiring` (DC-5)."""
        gen = await self._building(held)
        if not gen.secret_accessor:
            raise StepFailed("the host recorded no installed secret")
        if not gen.sign_approle or not gen.sign_secret_accessor:
            # Installed before the sign login existed (a job in flight across the upgrade, r8.5): back
            # to `wrap`, which makes the sign chain and wraps both secrets for a fresh install.
            await held.commit(step="wrap", actor=SERVICE)
            return
        await self._sweep_secret_ids(gen.approle, keep=gen.secret_accessor)
        await self._sweep_secret_ids(gen.sign_approle, keep=gen.sign_secret_accessor)
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
        """Rotation's end on the forge and OpenBao: the old chains revoked, then their bots deleted
        (FR-8, #1433)."""
        old = [g for g in await held.generations() if g.status == "retiring"]
        await self._destroy(old, repo=await self._repo_of(held))
        await self._commit_next(held, destroy=[g.salt for g in old])

    async def _repo_of(self, held: HeldTenant) -> str | None:
        wiring = await held.forge_wiring()
        return None if wiring is None else wiring.repo

    async def _destroy(self, gens: list[Generation], *, repo: str | None) -> None:
        """`_revoke` then `_delete_bots`, for a step with nothing else to revoke."""
        await self._delete_bots(await self._revoke(gens, repo=repo))

    async def _revoke(self, gens: list[Generation], *, repo: str | None) -> list[str]:
        """Everything of `gens` that grants access, each part checked first (RC-4): each existing bot
        removed from the tenant repo, then the OIDC role, the AppRole and its secret ids, the entity
        (its alias with it), and the sign AppRole and its entity likewise when the generation records
        them (one recorded before the sign login has none, A24'). The bots that still exist, for
        `_delete_bots`. Revoking comes before any account delete because the forge can refuse that
        delete (#1433): a refusal must find nothing left that grants access."""
        bots: list[str] = []
        for gen in gens:
            if answered(await self._forge.get(f"/api/v1/users/{gen.bot_login}"), 404).status_code != 404:
                bots.append(gen.bot_login)
                if repo is not None:
                    answered(await self._forge.delete(f"/api/v1/repos/{repo}/collaborators/{gen.bot_login}"), 404)
            paths = [f"identity/oidc/role/{gen.oidc_role}", f"auth/approle/role/{gen.approle}",
                     f"identity/entity/name/{gen.entity}"]
            if gen.sign_approle is not None:
                paths.append(f"auth/approle/role/{gen.sign_approle}")
            if gen.sign_entity is not None:
                paths.append(f"identity/entity/name/{gen.sign_entity}")
            for path in paths:
                answered(await self._bao.delete(f"/v1/{path}"), 404)
        return bots

    async def _delete_bots(self, bots: list[str]) -> None:
        """Each bot account deleted WITHOUT purge (its integrations go with it, G8), the step's last
        act (#1433): purge erases the PRs, reviews and comments it wrote. A delete the forge refuses
        (the bot owns a repository, a fork of the tenant repo included, or belongs to an
        organisation) fails the step with the forge's reason; the bot is revoked by then."""
        for bot in bots:
            answered(await self._forge.delete(f"/api/v1/admin/users/{bot}"), 404)

    # --- offboard -------------------------------------------------------------------------------

    async def _offboard(self, held: HeldTenant) -> None:
        """Memberships end and invitations are revoked, every generation is revoked and the tenant's
        signing key destroyed, the repo is archived, and only then are the bots deleted (Flow 2.2, A25,
        #1433)."""
        await self._identity.end_tenant(held.tenant_id, now=self._clock())
        repo = await self._repo_of(held)
        bots = await self._revoke([g for g in await held.generations() if g.status != "destroyed"], repo=repo)
        await self._destroy_key(held.tenant_id)
        if repo is not None:
            answered(await self._forge.patch(f"/api/v1/repos/{repo}", json={"archived": True}), 404)
        await self._delete_bots(bots)
        await self._commit_next(held, destroy=ALL)

    async def _finish(self, held: HeldTenant) -> None:
        """The by-name sweep once more (late effects of a timed-out call), the signing key included,
        then `offboarded` with the repo deletion pending once the window ends; the publish status goes
        (Flow 2.4, A25), and the tenant's system and case records, every version, with its imported
        mark (#1366 O10), in the same fenced commit."""
        bots = await self._revoke(await held.generations(), repo=await self._repo_of(held))
        await self._destroy_key(held.tenant_id)
        await self._delete_bots(bots)
        now = self._clock()
        await held.commit(step="delete_repo", actor=SERVICE, state="offboarded", pending_action="delete_repo",
                          offboarded_at=now, repo_delete_after=now + REPO_WINDOW, drop_publish_status=True,
                          drop_records=True)

    async def _delete_repo(self, held: HeldTenant) -> None:
        """Due once `repo_delete_after` passed (the listing waits for it): the by-name sweep again
        (RC-8), the repo deleted, `repo_url` and the wiring cleared; audited after the commit."""
        repo = await self._repo_of(held)
        await self._destroy(await held.generations(), repo=repo)
        if repo is not None and answered(await self._forge.get(f"/api/v1/repos/{repo}"), 404).status_code != 404:
            answered(await self._forge.delete(f"/api/v1/repos/{repo}"), 404)
        await held.commit(step=None, actor=None, pending_action=None, repo_url=None, drop_wiring=True)
        audit.emit("tenant.repo.delete", actor=audit.SYSTEM, tenant_id=held.tenant_id, target=held.tenant_id)


def _sign_names(tenant: str, salt: str) -> dict[str, str]:
    """The names of a generation's sign-only AppRole and its own entity (A24'; OpenBao allows one
    alias per entity and auth mount, so the sign login cannot share the delivery entity)."""
    return {"sign_approle": f"sign-{tenant}-{salt}", "sign_entity": f"tenant-{tenant}-{salt}-sign"}


def _rule(response: httpx.Response, repo: str) -> dict[str, Any]:
    rule = response.json()
    if not isinstance(rule, dict) or "main" not in (rule.get("rule_name"), rule.get("branch_name")):
        raise StepFailed(f"the protection of main on {repo} does not read back")
    return rule


def _names_in(rule: Mapping[str, Any], key: str) -> list[str]:
    listed = rule.get(key)
    return [str(n) for n in listed] if isinstance(listed, list) else []


def _breaks_invariant(rule: Mapping[str, Any], bots: set[str]) -> str | None:
    """What of A23's invariant `rule` breaks (for the failure text), or None when it holds."""
    if rule.get("enable_push") is not False:
        return f"enable_push={rule.get('enable_push')!r}"
    if rule.get("enable_merge_whitelist") is not True:
        return f"enable_merge_whitelist={rule.get('enable_merge_whitelist')!r}"
    if OWNERS not in _names_in(rule, "merge_whitelist_teams"):
        return f"merge_whitelist_teams={_names_in(rule, 'merge_whitelist_teams')!r}, without {OWNERS}"
    if on := sorted(bots & set(_names_in(rule, "merge_whitelist_usernames"))):
        return f"the bot logins {on} on the merge whitelist"
    return None
