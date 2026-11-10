"""The execution-host actor (#1214 Q1, Flows 1-3): the host's steps (install, prepare,
remove_old_file, teardown). It holds no management login and no forge admin token (DC-12, F-1):
it unwraps the single-use secret the service wrapped for it, logs in with the AppRole pair and acts
as the tenant's bot. Blocking work (git, files, signals, the publish child, waiting for the host
lock) runs in a worker thread; the tenant's lock and its writes stay on the actor's own loop (RC-5).

Secret files (DC-2): `<secrets dir>/<T>/<accessor>`, mode 0600, the AppRole secret id and a newline,
and beside it the sign-only AppRole's as `sign-<accessor>` (A24'); the generation records both
paths. Host lock (RC-5): install and remove_old_file hold it shared, prepare and teardown exclusive."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as _dt
import logging
import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx

from defender import _io
from defender.configuration import publish_root
from defender.configuration.issuer import TRANSIT_MOUNT
from defender.credential_proxy import transit_key_for
from defender.lifecycle._bot import Minted, log_in, mint
from defender.lifecycle._job import (
    HOST,
    SERVICE,
    Actor,
    Step,
    StepFailed,
    answered,
    field_of,
    next_step,
    only,
)
from defender.lifecycle._teardown import Containers, stop_containers, take_exclusive
from defender.lifecycle.config import LifecycleConfig
from defender.tenancy import FenceMissed, Generation, HeldTenant, TenantRepository, host_lock

_logger = logging.getLogger(__name__)

#: Where an install that failed restarts: its wrapped secret may be spent (DC-4).
_REWRAP = ("wrap", SERVICE)
_KNOWLEDGE, _LEARNING = "knowledge", "learning"
#: The sign secret file's name is its accessor after this prefix, beside the delivery file.
_SIGN_FILE = "sign-"
#: What install signs to prove the sign pair (A24', r8.4): a fixed payload, never a request token.
_PROBE = base64.b64encode(b"defender install sign proof").decode("ascii")

Git = Callable[..., subprocess.CompletedProcess[str]]
Publish = Callable[..., str]


class HostActor(Actor):
    """The host's half of every tenant's job. `forge` is an HTTP client for the forge carrying NO
    credential (each call presents the bot's JWT); `openbao_login` reaches only unwrap, AppRole
    login, token reads and install's one sign as the tenant's sign login; `git` is the sealed-transport git runner; `publish` launches the first
    publish (`launch_publish`'s shape) and answers its report line; `containers` removes a tenant's
    box containers (default: docker by label)."""

    actor = HOST

    def __init__(self, tenants: TenantRepository, *, forge: httpx.AsyncClient,  # noqa: PLR0913 — the pinned constructor
                 openbao_login: httpx.AsyncClient, git: Git, publish: Publish, config: LifecycleConfig,
                 clock: Callable[[], _dt.datetime], containers: Containers = stop_containers) -> None:
        super().__init__(tenants, clock=clock)
        self._forge, self._bao, self._git, self._publish = forge, openbao_login, git, publish
        self._config, self._containers = config, containers
        self._root: Path = config.data_root

    def steps(self) -> Mapping[str, Step]:
        return {"install": self._install, "prepare": self._prepare, "remove_old_file": self._remove_old_file,
                "teardown": self._teardown}

    def _tenant_secrets(self, tenant: str) -> Path:
        return self._config.secrets_dir / tenant

    @contextlib.asynccontextmanager
    async def _host_lock(self, tenant: str, *, exclusive: bool) -> Any:
        fd = await asyncio.to_thread(host_lock.acquire, self._root, tenant, exclusive=exclusive,
                                     timeout=self._config.teardown_wait)
        if fd is None:
            raise StepFailed(f"the tenant's host lock was not free ({'exclusive' if exclusive else 'shared'}) "
                             f"within {self._config.teardown_wait:g}s")
        try:
            yield
        finally:
            host_lock.release_lock(fd)

    async def _bot_jwt(self, gen: Generation, secret_id: str) -> str:
        token = self.secret(await log_in(self._bao, str(gen.role_id), secret_id))
        return self.secret(await mint(self._bao, gen.oidc_role, token))

    # --- install ----------------------------------------------------------------------------------

    async def _install(self, held: HeldTenant) -> None:
        """Unwrap both secrets (delivery and sign) and write both files before any check; act as the
        bot: it reads the repo and `main` refuses its pushes and merges (`GET branches/main`:
        protected, user can neither push nor merge; DC-11, G22, A23); prove the sign pair by signing
        (A24'); then record both accessors and files (Flow 1.8). Any failure removes the files written
        and restarts at `wrap`, which wraps both again (DC-4)."""
        try:
            async with self._host_lock(held.tenant_id, exclusive=False):
                await self._install_under_lock(held)
        except FenceMissed:
            raise
        except StepFailed as failed:
            raise StepFailed(str(failed), restart=_REWRAP) from failed
        except Exception as failed:  # noqa: BLE001 — re-raised with install's restart point
            raise StepFailed(f"{type(failed).__name__}: {failed}", restart=_REWRAP) from failed

    async def _install_under_lock(self, held: HeldTenant) -> None:
        gen = only(await held.generations(), "pending")
        wiring = await held.forge_wiring()
        if wiring is not None and gen.wrapped_secret and not gen.sign_wrapped_secret:
            # Wrapped before the sign login existed (a job in flight across the upgrade, r8.5): back
            # to `wrap`, which makes the sign chain and wraps both, with no failure to resume.
            await held.commit(step="wrap", actor=SERVICE)
            return
        if wiring is None or not gen.wrapped_secret or not gen.sign_wrapped_secret:
            raise StepFailed("there is no wrapped secret or forge wiring to install")
        secret_id, accessor = await self._unwrap(gen.wrapped_secret, "delivery")
        sign_secret_id, sign_accessor = await self._unwrap(gen.sign_wrapped_secret, "sign")
        paths: list[Path] = []
        try:
            paths.append(await asyncio.to_thread(self._write_secret, held.tenant_id, accessor, secret_id))
            paths.append(await asyncio.to_thread(self._write_secret, held.tenant_id, sign_accessor, sign_secret_id,
                                                 prefix=_SIGN_FILE))
            jwt = await self._bot_jwt(gen, secret_id)
            bearer = {"Authorization": f"Bearer {jwt}"}
            answered(await self._forge.get(f"/api/v1/repos/{wiring.repo}", headers=bearer))
            branch = answered(await self._forge.get(f"/api/v1/repos/{wiring.repo}/branches/main", headers=bearer)).json()
            if not (isinstance(branch, dict) and branch.get("protected") is True and branch.get("user_can_push") is False
                    and branch.get("user_can_merge") is False):
                seen = branch if isinstance(branch, dict) else {}
                raise StepFailed(f"the bot could push to or merge main of {wiring.repo} (protected={seen.get('protected')!r}, "
                                 f"user_can_push={seen.get('user_can_push')!r}, user_can_merge={seen.get('user_can_merge')!r})")
            await self._prove_sign(held.tenant_id, gen, sign_secret_id)
            step, actor = next_step(held)
            await held.commit(step=step, actor=actor, update_generations={gen.salt: {
                "wrapped_secret": None, "secret_accessor": accessor, "host_secret_file": paths[0],
                "sign_wrapped_secret": None, "sign_secret_accessor": sign_accessor, "sign_secret_file": paths[1]}})
        except FenceMissed:  # the commit may have landed with its answer lost: the files stay (a stray one is
            raise            # dropped by prepare and remove_old_file, and teardown removes the secrets directory)
        except BaseException:
            for path in paths:
                path.unlink(missing_ok=True)
            raise

    async def _unwrap(self, wrapped: str, which: str) -> tuple[str, str]:
        """The secret id and its accessor that `wrapped` wraps (spent by this call)."""
        unwrapped = await self._bao.post("/v1/sys/wrapping/unwrap", headers={"X-Vault-Token": self.secret(wrapped)})
        if unwrapped.status_code != 200:
            raise StepFailed(f"the wrapped {which} secret could not be unwrapped (HTTP {unwrapped.status_code}): it was "
                             "spent or has expired")
        secret_id = self.secret(str(field_of(unwrapped, "data", "secret_id")))
        return secret_id, str(field_of(unwrapped, "data", "secret_id_accessor"))

    async def _prove_sign(self, tenant: str, gen: Generation, sign_secret_id: str) -> None:
        """The installed sign pair works (A24', r8.4): logged in as the generation's sign login, one fixed
        probe is signed with the tenant's key, and the answer carries a signature."""
        token = self.secret(await log_in(self._bao, str(gen.sign_role_id), sign_secret_id))
        signed = answered(await self._bao.post(f"/v1/{TRANSIT_MOUNT}/sign/{transit_key_for(tenant)}",
                                               json={"input": _PROBE}, headers={"X-Vault-Token": token}))
        signature = field_of(signed, "data", "signature")
        if not isinstance(signature, str) or not signature:
            raise StepFailed("the sign proof answered no signature")

    def _write_secret(self, tenant: str, accessor: str, secret_id: str, *, prefix: str = "") -> Path:
        if not accessor or "/" in accessor or accessor.startswith("."):
            raise StepFailed("OpenBao answered an unusable secret accessor")
        folder = self._tenant_secrets(tenant)
        _io.guarded_mkdir(folder, base=self._config.secrets_dir)
        os.chmod(folder, 0o700)
        path = folder / f"{prefix}{accessor}"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(secret_id + "\n")
        return path

    def _drop_unrecorded_secrets(self, tenant: str, gens: list[Generation]) -> None:
        """RC-8: every file of the tenant's secrets directory no generation still records goes."""
        keep = {Path(f) for g in gens if g.status != "destroyed"
                for f in (g.host_secret_file, g.sign_secret_file) if f}
        folder = self._tenant_secrets(tenant)
        with contextlib.suppress(FileNotFoundError):
            for entry in folder.iterdir():
                if entry not in keep:
                    entry.unlink()

    # --- prepare --------------------------------------------------------------------------------

    async def _prepare(self, held: HeldTenant) -> None:
        """The host folder: `<data root>/<T>/` with the tenant's clone (an existing clone of the
        recorded repo is kept, any other refuses) and an empty real `learning/`; then the first
        publish, which must answer `fresh <commit>` (Flow 1.9, RC-7, GAP-Re-4)."""
        gens = await held.generations()
        gen = only(gens, "live")
        wiring = await held.forge_wiring()
        if wiring is None or gen.host_secret_file is None:
            raise StepFailed("there is no forge wiring or installed secret to prepare with")
        tenant = held.tenant_id
        async with self._host_lock(tenant, exclusive=True):
            await asyncio.to_thread(self._drop_unrecorded_secrets, tenant, gens)
            clone = await asyncio.to_thread(self._existing_clone, tenant, wiring.origin)
            if clone is None:
                secret_id = self.secret(await asyncio.to_thread(_read_secret, Path(gen.host_secret_file)))
                credential = Minted(tenant, await self._bot_jwt(gen, secret_id))
                await asyncio.to_thread(self._clone, tenant, wiring.origin, credential)
            await asyncio.to_thread(self._learning, tenant)
            line = (await asyncio.to_thread(self._publish, tenant, data_root=self._root)).strip()
            head, _sep, commit = line.partition(" ")
            if head != "fresh" or not commit or " " in commit:
                raise StepFailed(f"the first publish answered {line!r}, not 'fresh <commit>'")
            step, actor = next_step(held)
            await held.commit(step=step, actor=actor)

    def _folder(self, tenant: str) -> Path:
        folder = self._root / tenant
        if folder.is_symlink():
            raise StepFailed(f"{folder} is a link; the tenant's folder must be a real directory")
        return folder

    def _existing_clone(self, tenant: str, origin: str) -> Path | None:
        """The tenant's clone if one is there (`<T>/knowledge`, where every entry point accepts it),
        after checking its origin is the recorded one; None when there is none to keep."""
        clone = self._folder(tenant) / _KNOWLEDGE
        if clone.is_symlink():
            raise StepFailed(f"{clone} is a link; the tenant's clone must be a real directory")
        if not (clone / ".git").exists() or (clone / ".git").is_symlink():
            return None
        found = self._git_out(["remote", "get-url", "origin"], clone)
        if found != origin and found != self._git_out(["ls-remote", "--get-url", origin], clone):
            raise StepFailed(f"{clone} is a clone of {found}, not of the recorded {origin}")
        return clone

    def _git_out(self, args: list[str], clone: Path) -> str:
        """What a local git call in `clone` prints (`ls-remote --get-url` names a URL as git resolves
        it, without a network call)."""
        done = self._git(["-C", str(clone), *args], cwd=clone)
        if done.returncode != 0:
            raise StepFailed(f"git {args[0]} in {clone} failed: {done.stderr.strip()}")
        return done.stdout.strip()

    def _clone(self, tenant: str, origin: str, credential: Minted) -> None:
        folder = self._folder(tenant)
        _io.guarded_mkdir(folder, base=self._root)
        target = folder / _KNOWLEDGE
        if target.exists() or target.is_symlink():
            raise StepFailed(f"{target} is there but is not a clone; remove it to prepare the tenant")
        done = self._git(["clone", "-q", origin, str(target)], cwd=folder, origin=origin, identity=credential)
        if done.returncode != 0:
            raise StepFailed(f"git clone failed: {done.stderr.strip()}")

    def _learning(self, tenant: str) -> None:
        learning = self._folder(tenant) / _LEARNING
        if learning.is_symlink():
            raise StepFailed(f"{learning} is a link; the learning root must be a real directory")
        _io.guarded_mkdir(learning, base=self._root)

    # --- rotate's end, offboard -------------------------------------------------------------------

    async def _remove_old_file(self, held: HeldTenant) -> None:
        """The destroyed generations' secret files go; the live one's stays (Flow 3, DC-2, RC-4)."""
        gens = await held.generations()
        async with self._host_lock(held.tenant_id, exclusive=False):
            await asyncio.to_thread(self._drop_unrecorded_secrets, held.tenant_id, gens)
        await held.commit(step=None, actor=None, pending_action=None)

    async def _teardown(self, held: HeldTenant) -> None:
        """Under the exclusive host lock, once what works for the tenant is stopped: the tenant's
        folder, its secrets directory and its dev output are removed; anything already gone is done
        (Flow 2.3, RC-4)."""
        tenant = held.tenant_id
        await self._offboard_learning(tenant)
        fd = await asyncio.to_thread(take_exclusive, self._root, tenant,
                                     wait=self._config.teardown_wait, containers=self._containers)
        try:
            await asyncio.to_thread(self._remove_tenant_files, tenant)
            step, actor = next_step(held)
            await held.commit(step=step, actor=actor)
        finally:
            host_lock.release_lock(fd)

    async def _offboard_learning(self, tenant: str) -> None:
        """The tenant's learning rows (#1278 O6): holders told to stop, lapsed batches ended, rows purged. A live holder
        past the wait fails the step, which is retried. No database address: nothing of learning is stored here."""
        dsn = os.environ.get("DEFENDER_DATABASE_DSN")
        if not dsn:
            return
        from defender.learning.store import LaneBusy, LearningStore

        store = LearningStore(dsn)
        try:
            await store.offboard(tenant, wait=self._config.teardown_wait)
        except LaneBusy as busy:
            # Not a failure: a failure waits for an operator's resume. The pass ends here and the next one asks again.
            raise FenceMissed(f"the tenant's learning batch is still held: {busy}") from None
        finally:
            await store.close()

    def _remove_tenant_files(self, tenant: str) -> None:
        targets = [self._root / tenant, self._tenant_secrets(tenant)]
        root = publish_root.publish_root()
        if isinstance(root, Path):
            targets.append(root / tenant)
        for target in targets:
            _remove_tree(target)


def _remove_tree(target: Path) -> None:
    """Remove `target` without following it: a link is unlinked, a directory removed whole."""
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.is_dir():
        shutil.rmtree(target)


def _read_secret(path: Path) -> str:
    value = _io.read_text_utf8(path).strip()
    if not value:
        raise StepFailed(f"the secret file {path} is empty")
    return value

