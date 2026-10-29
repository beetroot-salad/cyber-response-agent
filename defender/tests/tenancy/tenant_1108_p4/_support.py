"""Shared machinery for #1108 P4: the fixture tenant as a real tenant repo, published for real
through P3's delivery path.

Built on P3's `tenant_1108_delivery/` helpers, imported, never copied: a real clone, a bare remote
served over smart HTTP (`GitHTTP`, Bearer-authenticated as Forgejo is), the forge API fake
(`ForgeHTTP`), the issuer fake (`VaultHTTP`) and P3's `place_tenant`. Nothing here implements P4
policy: it plants trees, lands commits on the fake origin as a human merge would, and calls P3's
real `TenantDelivery.open(...).publish()`; every judgement is the code under test's.

The pytest fixture `p4_tenant` (conftest.py) is a `PublishedTenant` under the test's own data root.
"""
from __future__ import annotations

import contextlib
import shutil
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared.contracts._data_root_1078 import D9_TENANT_ID
from defender.tests.support.tenancy import _tenants1106 as tenants
from defender.tests.tenancy.tenant_1108_delivery._identity import AUDIENCE as ISSUER_AUDIENCE
from defender.tests.tenancy.tenant_1108_delivery._identity import VaultHTTP
from defender.tests.tenancy.tenant_1108_delivery._identity import token as issuer_token
from defender.tests.tenancy.tenant_1108_delivery._support import (
    BARE_NO_UPKEEP,
    DEFENDER,
    ForgeHTTP,
    GitHTTP,
    Trickle,
    agent_blobs,
    files_under,
    git,
    index_entry,
    push_to_remote,
    target,
)

#: The committed fixture tenant (`knowledge/tenant-fixture/`). It carries no `agent/.tenant-id`:
#: the same tree is placed under several ids, so the id is written at placement.
FIXTURE = tenants.FIXTURE
FIXTURE_AGENT = tenants.FIXTURE_AGENT
FIXTURE_SETTINGS = tenants.FIXTURE_SETTINGS

#: The fixture tenant's id: the one every replay that names no tenant runs as (D9).
FIXTURE_TENANT_ID = D9_TENANT_ID
#: A second tenant under the same data root, for isolation cases.
OTHER_TENANT_ID = fixture_uuid("tenant:p4-other")

#: The one lesson only the second tenant holds by default (repo-relative path, bytes), so an
#: isolation case has a tenant-specific file to look for (and to find missing) out of the box.
OTHER_LESSON = (
    "agent/lessons/other-tenant-only.md",
    b"---\nname: other-tenant-only\ndescription: Only the second fixture tenant holds this "
    b"lesson.\ncreated_at: 2026-10-04T00:00:00Z\n---\n\nSecond-tenant fixture content.\n",
)

#: What `files` maps: a repo-relative path (`agent/...`, `settings/...`) to its new content;
#: `None` deletes the file. A `str` is written as UTF-8.
Files = Mapping[str, bytes | str | None]


def _write_files(checkout: Path, files: Files | None) -> None:
    for rel, content in (files or {}).items():
        path = Path(checkout) / rel
        if content is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)


@dataclass(frozen=True, eq=False)
class PublishedTenant:
    """An accepted tenant whose clone is a real git repo holding the fixture (plus any `files`),
    with a live loopback origin, a forge fake and an issuer fake, published once for real.

    Fault seams are P3's fakes: `server` (`GitHTTP`: `.refuse`, `.on_service` returning a
    `Trickle`), `forge` (`ForgeHTTP`: `.fault`, `.protection`), `vault` (`VaultHTTP`: `.status`,
    `.body`, `.calls`). `identity` is the first publish's; it caches its token under a clock that
    never moves, so `open_delivery` builds a fresh `vault.identity()` per call: set an issuer
    fault on `vault` before the next `open_delivery`/`publish`. `p3` is P3's
    `(tenant, bare remote, None)` repo tuple, so P3's helpers (`push_to_remote`, ...) apply."""

    tenant: Any
    data_root: Path
    clone: Path
    remote: Path
    origin: str
    forge: ForgeHTTP
    vault: VaultHTTP
    identity: Any
    server: GitHTTP
    scratch: Path
    export: Any
    p3: tuple = field(repr=False)

    @property
    def tenant_id(self) -> str:
        return str(self.tenant.id)

    @property
    def directory(self) -> Any:
        """A `TenantDirectory` (#1214) over `repository`: this tenant active, wired to `repo=tenants/<id>` and
        `origin=self.origin`, plus what `bind_forge(t, ...)` / `unbind_forge(t)` recorded: what a call site passes
        as `directory=`. One per tenant (reset by bind/unbind). `issuer_role`, `audience` and `issuer_config` are not
        directory facts: the credential provider derives them from generations."""
        cached = self.__dict__.get("_dir")
        if cached is None:
            from defender.tenancy import TenantDirectory

            cached = TenantDirectory(lambda: self.repository)
            object.__setattr__(self, "_dir", cached)
        return cached

    @property
    def repository(self) -> Any:
        """The in-memory tenant repository behind `directory` (cached): a test reads back what a process recorded
        on it (`await t.repository.publish_status(T)`, GAP-Rc-2)."""
        cached = self.__dict__.get("_repo")
        if cached is None:
            cached = self.repository_with()
            object.__setattr__(self, "_repo", cached)
        return cached

    def repository_with(self, *, origin: str | None = None, repo: str | None = None, **keywords: Any) -> Any:
        """A fresh repository like `repository` with another `origin`/`repo`, or `state=`/`wiring=False` for the
        refusal sides, or `generations=[fields]` to seed the live generation a minting call site needs:
        `fields = _active1214.provision_generation(openbao, T, secrets_dir)` builds its OpenBao chain and host
        secret file (GAP-Ma-1, see `_active1214`). Keywords win over what `bind_forge` recorded."""
        from defender.tests.support.tenancy._active1214 import active_repository

        bound: dict[str, Any] = dict(self.__dict__.get("_bound") or {})
        if origin is not None:
            bound["origin"] = origin
        bound.setdefault("origin", self.origin)
        return active_repository(self.data_root, self.tenant_id, repo=repo, **{**bound, **keywords})

    def directory_with(self, **keywords: Any) -> Any:
        """A fresh `TenantDirectory` over `repository_with(**keywords)`."""
        from defender.tenancy import TenantDirectory

        twin = self.repository_with(**keywords)
        return TenantDirectory(lambda: twin)

    @property
    def commit(self) -> str:
        """The commit the first publish exported (the clone's seeded fixture commit)."""
        return self.export.commit

    def open_delivery(self, **options: Any) -> Any:
        """P3's real `TenantDelivery.open` for this tenant over the forge fake's client, a fresh
        `vault.identity()` (so a fault set on `vault` is seen) and the clone's origin; any of them
        overridable by keyword."""
        options.setdefault("defender_dir", DEFENDER)
        options.setdefault("client", self.forge.client)
        if "identity" not in options:
            options["identity"] = self.vault.identity()
        options.setdefault("origin", self.origin)
        return target().TenantDelivery.open(self.tenant, **options)

    def publish(self, **options: Any) -> Any:
        """Publish again for real (`open_delivery(**options).publish()`); returns the export."""
        return self.open_delivery(**options).publish()

    def merge(self, files: Files, message: str = "human merge") -> str:
        """A human-merged PR: one commit on the fake origin's `main` writing `files` (`None`
        deletes); the clone and exports are untouched until something publishes. Returns the new
        `main` commit. For raw tree entries (a link, a gitlink) use P3's
        `push_to_remote(self.p3, self.scratch, edit, stage=False)` with `index_entry`."""
        return push_to_remote(self.p3, self.scratch, lambda w: _write_files(w, files), message)

    def origin_main(self) -> str:
        """The fake origin's `main` tip, read from the bare remote."""
        return git(self.remote, "rev-parse", "refs/heads/main")


def place_fixture(root: Path, tenant_id: str = FIXTURE_TENANT_ID, *,
                  files: Files | None = None, agent: Path | None = None) -> Path:
    """Place `tenant_id` under `root` as an operator does (P3's `place_tenant`) with the fixture's
    `settings/` and `agent/` (or the `agent=` directory's tree), then `files` written over them.
    Returns the knowledge folder; publishes nothing."""
    root = Path(root)
    knowledge = tenants.place_tenant(root, tenant_id)
    marker = (knowledge / "agent" / ".tenant-id").read_bytes()
    for half, source in (("settings", FIXTURE / "settings"),
                         ("agent", Path(agent) if agent is not None else FIXTURE / "agent")):
        shutil.rmtree(knowledge / half)
        shutil.copytree(source, knowledge / half, symlinks=True)
    (knowledge / "agent" / ".tenant-id").write_bytes(marker)
    _write_files(knowledge, files)
    return knowledge


@contextlib.contextmanager
def publish_placed(scratch: Path, *, root: Path, tenant_id: str,
                   repo_name: str | None = None) -> Iterator[PublishedTenant]:
    """Publish for real a tenant already placed under `root`, with whatever its folder holds now.

    The folder becomes (or stays) a git repo on `main` with everything committed; the commit goes
    to the bare remote `<scratch>/tenants/<repo_name>.git` (default name: the tenant id), served
    as `origin` for the context, and P3's real publish exports it and points `current` at it.
    Calling it again (same `scratch`) publishes new content as a fast-forward. P3's
    `DeliveryRefused` and acceptance's `TenantRefused` propagate: a caller planting a broken
    tenant decides what a failed publish means."""
    root, scratch = Path(root), Path(scratch)
    name = repo_name if repo_name is not None else tenant_id
    tenant = tenants.accept(root, tenant_id)
    clone = Path(location_path(tenant.knowledge))
    if not (clone / ".git").exists():
        git(clone, "init", "-b", "main")
        git(clone, "config", "user.name", "P4 fixture")
        git(clone, "config", "user.email", "p4@test.invalid")
    git(clone, "add", "-A")
    if git(clone, "status", "--porcelain"):
        git(clone, "commit", "-m", "tenant content")
    head = git(clone, "rev-parse", "HEAD")
    remote = scratch / "tenants" / f"{name}.git"
    if remote.exists():
        git(clone, "push", "-q", remote, "main:main")
    else:
        remote.parent.mkdir(parents=True, exist_ok=True)
        git(scratch, "clone", "--bare", *BARE_NO_UPKEEP, clone, remote)
    server = GitHTTP(scratch, token=issuer_token(tenant_id))
    try:
        origin = f"{server.url}/tenants/{name}.git"
        if git(clone, "remote"):
            git(clone, "remote", "set-url", "origin", origin)
        else:
            git(clone, "remote", "add", "origin", origin)
        git(clone, "fetch", remote, "+refs/heads/*:refs/remotes/origin/*")
        forge = ForgeHTTP(remote=remote, origin=origin)
        vault = VaultHTTP(tenant_id)
        identity = vault.identity()
        export = target().TenantDelivery.open(
            tenant, defender_dir=DEFENDER, client=forge.client, identity=identity,
            origin=origin).publish()
        assert export.commit == head, (export.commit, head)
        yield PublishedTenant(
            tenant=tenant, data_root=root, clone=clone, remote=remote, origin=origin,
            forge=forge, vault=vault, identity=identity, server=server, scratch=scratch,
            export=export, p3=(tenant, remote, None))
    finally:
        server.close()


def publish_once(scratch: Path, *, root: Path, tenant_id: str) -> PublishedTenant:
    """`publish_placed` for a caller that needs only the export: the origin server is closed on
    return, so `publish()` needs another `publish_placed`/`publish_once`."""
    with publish_placed(scratch, root=root, tenant_id=tenant_id) as done:
        return done


@contextlib.contextmanager
def published_tenant(scratch: Path, *, root: Path, tenant_id: str = FIXTURE_TENANT_ID,
                     files: Files | None = None, agent: Path | None = None,
                     repo_name: str = "fixture") -> Iterator[PublishedTenant]:
    """`place_fixture` then `publish_placed`: the clone holds one commit on `main`, exported and
    named by `current`. Keep `scratch` (served remotes, merge checkouts) apart from `root`; `root`
    must not already hold `tenant_id` (don't combine with `d9_tenant` or `fixture_tenant()` on
    one id).

    The yielded `PublishedTenant` has `.directory` (#1214); no row is written (O6)."""
    place_fixture(root, tenant_id, files=files, agent=agent)
    with publish_placed(scratch, root=root, tenant_id=tenant_id, repo_name=repo_name) as done:
        yield done


@contextlib.contextmanager
def second_tenant(first: PublishedTenant, *,
                  files: Files | None = None) -> Iterator[PublishedTenant]:
    """Another tenant under `first`'s data root, from the same fixture content plus
    `OTHER_LESSON` (unless `files` is given), with its own remote, origin server, forge fake and
    issuer fake, published for real."""
    if files is None:
        files = dict([OTHER_LESSON])
    with published_tenant(first.scratch, root=first.data_root, tenant_id=OTHER_TENANT_ID,
                          files=files, repo_name="other") as other:
        yield other


def current_commit(tenant: Any) -> str | None:
    """What `<T>/exports/current` holds, read as a plain file (trailing newline dropped), or
    `None` when it is absent. An independent observation: never `current_export`."""
    pointer = Path(location_path(tenant.tenant_root)) / "exports" / "current"
    if not pointer.is_file():
        return None
    return pointer.read_text(encoding="utf-8").removesuffix("\n")


def export_dir(tenant: Any, commit: str) -> Path:
    """`<T>/exports/<commit>/`, spelled from the tenant's own folder."""
    return Path(location_path(tenant.tenant_root)) / "exports" / commit


def bind_forge(t: PublishedTenant, *, origin: str | None = None,
               generations: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Record the tenant's forge wiring and a live generation on `t`, so `t.directory` (what a call site passes as
    `directory=`) holds the tenant active with `origin` (default `t.origin`) and `generations` (default: one live
    generation from `_active1214.generation_fields`, no OpenBao behind it: a call site that mints for real passes
    `[provision_generation(...)]`). Returns what it recorded.

    #1214 O6: nothing is written to the tenant folder; `issuer_role`/`issuer_config`/`audience` are not facts of the
    wiring: the provider derives them from the live generation and its host secret file."""
    from defender.tests.support.tenancy._active1214 import generation_fields

    if generations is None:
        generations = [generation_fields(t.tenant_id, default_secrets_dir(t))]
    bound = {"origin": t.origin if origin is None else origin, "generations": list(generations)}
    object.__setattr__(t, "_bound", bound)
    object.__setattr__(t, "_dir", None)
    object.__setattr__(t, "_repo", None)
    return bound


def default_secrets_dir(t: PublishedTenant) -> Path:
    """Where `bind_forge`'s default generation names its host secret file."""
    return Path(t.data_root).absolute().parent / "operator" / "secrets"


def unbind_forge(t: PublishedTenant) -> None:
    """Remove what `bind_forge` recorded and the forge wiring: `t.directory` knows the tenant active with no wiring."""
    object.__setattr__(t, "_bound", {"wiring": False})
    object.__setattr__(t, "_dir", None)
    object.__setattr__(t, "_repo", None)


def fixture_agent_files() -> dict[str, bytes]:
    """The committed fixture's `agent/` files by POSIX relative path, with their bytes."""
    return files_under(FIXTURE_AGENT)


def committed_blobs(clone: Path, rev: str, pathspec: str) -> dict[str, bytes]:
    """Every regular-file blob under `pathspec` at `rev`, by repo-relative path: git's own read
    of the commit, which no worktree entry can redirect."""
    from defender import _git

    listing = _git.git_bytes(["--literal-pathspecs", "ls-tree", "-r", "-z", "--full-name", rev,
                              "--", pathspec], cwd=clone)
    return {path: _git.git_bytes(["cat-file", "blob", oid], cwd=clone)  # lint-oracle: ok — live tests read the lab repo's committed tree as data; no production reader is the oracle
            for mode, kind, oid, path in _git.tree_records(listing)
            if kind == "blob" and mode in ("100644", "100755")}


__all__ = [
    "committed_blobs",
    "default_secrets_dir",
    "DEFENDER",
    "FIXTURE",
    "FIXTURE_AGENT",
    "FIXTURE_SETTINGS",
    "FIXTURE_TENANT_ID",
    "ISSUER_AUDIENCE",
    "OTHER_LESSON",
    "OTHER_TENANT_ID",
    "ForgeHTTP",
    "PublishedTenant",
    "Trickle",
    "agent_blobs",
    "bind_forge",
    "current_commit",
    "export_dir",
    "files_under",
    "fixture_agent_files",
    "place_fixture",
    "publish_once",
    "publish_placed",
    "git",
    "index_entry",
    "published_tenant",
    "push_to_remote",
    "second_tenant",
    "unbind_forge",
]
