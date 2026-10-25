"""Shared machinery for #1108 P4's contract (slice S0): the fixture tenant as a real tenant repo,
published for real through P3's delivery path (O11: "fixtures obtain exports through one helper
that git-inits the fixture tenant and publishes for real").

Built on P3's machinery (`tenant_1108_delivery/`), imported, never copied: a real clone, a bare
remote served over smart HTTP (`GitHTTP`, Bearer-authenticated as Forgejo is), the forge's HTTP
API fake (`ForgeHTTP`), the issuer fake (`VaultHTTP`, whose `identity()` is P3's real
`ForgejoIdentity` over it), and P3's operator-style tenant placement (`place_tenant`). Nothing
here implements P4 policy: it plants trees, lands commits on the fake origin as a human merge
would, and calls P3's real `TenantDelivery.open(...).publish()`. Every judgement (fresh or stale,
what a run copies, what a publish child reports) is the code under test's.

Interface (other slices code against this; ask the orchestrator for changes):

    FIXTURE, FIXTURE_AGENT, FIXTURE_SETTINGS     # knowledge/tenant-fixture/{,agent,settings}
    FIXTURE_TENANT_ID, OTHER_TENANT_ID, OTHER_LESSON
    published_tenant(scratch, *, root, tenant_id=FIXTURE_TENANT_ID, files=None, agent=None,
                     repo_name="fixture") -> ContextManager[PublishedTenant]
    place_fixture(root, tenant_id=FIXTURE_TENANT_ID, *, files=None, agent=None) -> Path
    publish_placed(scratch, *, root, tenant_id, repo_name=None) -> ContextManager[PublishedTenant]
                                                  # an ALREADY-placed tenant, current content; re-callable
    publish_once(scratch, *, root, tenant_id, repo_name=None) -> PublishedTenant  # server closed after
    second_tenant(first, *, tenant_id=OTHER_TENANT_ID, files=None, repo_name="other")
                     -> ContextManager[PublishedTenant]
    PublishedTenant: .tenant .tenant_id .data_root .clone .remote .origin .forge .vault
                     .identity .server .scratch .export .commit .p3
                     .open_delivery(**options) -> TenantDelivery
                     .publish(**options) -> TenantExport
                     .merge(files, message="human merge") -> str (new origin main)
                     .origin_main() -> str
    current_commit(tenant) -> str | None          # raw `<T>/exports/current`, no parsing policy
    export_dir(tenant, commit) -> Path            # `<T>/exports/<commit>/`
    bind_forge(t, *, origin=None, audience=ISSUER_AUDIENCE, issuer_role=None,
               issuer_config=None) -> dict
                                                  # writes row `forge: {origin, audience, issuer_role}`
    unbind_forge(t) -> None                       # removes the row's `forge` field
    fixture_agent_files() -> dict[str, bytes]     # the committed fixture's agent/ files
    pytest fixture `p4_tenant` (conftest.py): a PublishedTenant under the test's own data root
"""
from __future__ import annotations

import contextlib
import json
import shutil
from collections.abc import Iterator, Mapping
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

#: The committed fixture tenant (`knowledge/tenant-fixture/`): settings + minimal made-up agent
#: content (decision 4). It carries no `agent/.tenant-id`: the same tree is set up under several
#: ids (`_data_root_1078.set_up_tenant`, `fixture_tenant(tenant_id)`), so the id is written when
#: a tenant is placed, never committed in the fixture.
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
    """An accepted tenant whose clone is a real git repo holding the committed fixture tenant
    (plus any `files`), with a live loopback origin, a forge fake and an issuer fake, published
    once for real: `<T>/exports/<commit>/` exists and `<T>/exports/current` names it.

    Fault seams, all P3's fakes: `server` (the origin's `GitHTTP`: `.refuse`, `.on_service`
    returning a `Trickle`), `forge` (`ForgeHTTP`: `.fault`, `.protection`), `vault` (the
    issuer's `VaultHTTP`: `.status`, `.body`, `.calls`). `identity` is the FIRST publish's
    `ForgejoIdentity`; it caches its token and the fake clock never moves, so it would never ask
    the issuer again: `open_delivery` therefore builds a fresh `vault.identity()` per call, and an
    issuer fault is set on `vault` before the next `open_delivery`/`publish`.

    `p3` is P3's `(tenant, bare remote, None)` repo tuple (no legacy credential file is written),
    so P3's own helpers (`push_to_remote`, `merge_on_remote`, `delivery`, ...) apply."""

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
    def commit(self) -> str:
        """The commit the first publish exported (the clone's seeded fixture commit)."""
        return self.export.commit

    def open_delivery(self, **options: Any) -> Any:
        """P3's real `TenantDelivery.open` for this tenant: this checkout's `defender/`, the forge
        fake's client, a fresh identity over the issuer fake (`vault.identity()`, so a fault set
        on `vault` is seen) and the clone's configured origin; any of them overridable by keyword
        (e.g. `client=` another forge's, `network_timeout=`)."""
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
        """A merged PR: one commit on the fake origin's `main` writing `files` (repo-relative;
        `None` deletes), landed from a fresh checkout as a human merge would. The clone and the
        exports are untouched until something publishes. Returns the new `main` commit.

        For raw tree entries (a link, a gitlink) use P3's
        `push_to_remote(self.p3, self.scratch, edit, stage=False)` with `index_entry`."""
        return push_to_remote(self.p3, self.scratch, lambda w: _write_files(w, files), message)

    def origin_main(self) -> str:
        """The fake origin's `main` tip, read from the bare remote."""
        return git(self.remote, "rev-parse", "refs/heads/main")


def place_fixture(root: Path, tenant_id: str = FIXTURE_TENANT_ID, *,
                  files: Files | None = None, agent: Path | None = None) -> Path:
    """Set up `tenant_id` under the data root `root` the way an operator does (P3's
    `place_tenant`: the knowledge folder, `agent/.tenant-id` naming it, the row), with the
    committed fixture's `settings/` and `agent/` (or, with `agent=`, that directory's tree as
    `agent/`, e.g. a golden replay's own agent content), then `files` written over them
    (repo-relative; `None` deletes). Returns the knowledge folder. Publishes nothing."""
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
    """Publish for real a tenant ALREADY placed under `root` (its knowledge folder, its
    `agent/.tenant-id` and its row exist; e.g. `place_fixture`, `_tenants1106.place_tenant`, or a
    suite's own planter), with whatever content the folder holds now.

    The knowledge folder becomes (or stays) a git repo on `main`; everything in it is committed
    (nothing when it is unchanged since the last call). The commit goes to the bare remote
    `<scratch>/tenants/<repo_name>.git` (default name: the tenant id), served by P3's `GitHTTP`
    as `origin` for the length of the context, and P3's real `TenantDelivery.open(...).publish()`
    exports it and points `current` at it. Calling it again for the same tenant (same `scratch`)
    publishes the folder's new content as a fast-forward on the same remote.

    P3's publish refusals propagate (`DeliveryRefused`: a link or special entry, a missing or
    foreign `agent/.tenant-id`), as does acceptance's (`TenantRefused`): a caller that plants a
    deliberately broken tenant decides what a failed publish means for its scenario."""
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


def publish_once(scratch: Path, *, root: Path, tenant_id: str,
                 repo_name: str | None = None) -> PublishedTenant:
    """`publish_placed` for a caller that needs only the export: publishes and closes the
    origin server again. The returned value's `export`, `commit`, `tenant` and `merge` stay
    usable; `server` is closed, so `publish()` needs another `publish_placed`/`publish_once`."""
    with publish_placed(scratch, root=root, tenant_id=tenant_id, repo_name=repo_name) as done:
        return done


@contextlib.contextmanager
def published_tenant(scratch: Path, *, root: Path, tenant_id: str = FIXTURE_TENANT_ID,
                     files: Files | None = None, agent: Path | None = None,
                     repo_name: str = "fixture") -> Iterator[PublishedTenant]:
    """The fixture tenant set up under the data root `root` (`place_fixture`) and published for
    real (`publish_placed`): the clone holds one commit on `main`, exported, `current` naming it.

    `scratch` holds the served remotes and merge checkouts; keep it apart from `root`. `root`
    must not already hold `tenant_id` (do not combine with the `d9_tenant` fixture or
    `fixture_tenant()` on one id). The server lives until the context exits."""
    place_fixture(root, tenant_id, files=files, agent=agent)
    with publish_placed(scratch, root=root, tenant_id=tenant_id, repo_name=repo_name) as done:
        yield done


@contextlib.contextmanager
def second_tenant(first: PublishedTenant, *, tenant_id: str = OTHER_TENANT_ID,
                  files: Files | None = None,
                  repo_name: str = "other") -> Iterator[PublishedTenant]:
    """Another tenant under `first`'s data root, from the same fixture content plus
    `OTHER_LESSON` (unless `files` is given), with its own remote, origin server, forge fake and
    issuer fake, published for real."""
    if files is None:
        files = dict([OTHER_LESSON])
    with published_tenant(first.scratch, root=first.data_root, tenant_id=tenant_id,
                          files=files, repo_name=repo_name) as other:
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


def _row_path(t: PublishedTenant) -> Path:
    return Path(location_path(t.tenant.row_path))


def bind_forge(t: PublishedTenant, *, origin: str | None = None,
               audience: str = ISSUER_AUDIENCE, issuer_role: str | None = None,
               issuer_config: Path | None = None) -> dict:
    """Write the forge binding r3's data model gives the tenant row (`<T>/tenant.json` gains
    `forge: {origin, audience, issuer_role, issuer_config}`; operator config, not secret) and
    return it. Defaults agree with the fakes: `t.origin`, the issuer fake's audience, the role
    `VaultHTTP.identity()` uses (`tenant-<id>`), and an issuer client config path beside the
    data root (`<data root>/../operator/issuer.json`; a test that logs in for real writes its
    config there or passes its own). Other row fields are kept. `published_tenant` never binds:
    P3's publish does not read the binding."""
    if issuer_config is None:
        issuer_config = default_issuer_config(t)
    binding = {"origin": t.origin if origin is None else origin, "audience": audience,
               "issuer_role": f"tenant-{t.tenant_id}" if issuer_role is None else issuer_role,
               "issuer_config": str(Path(issuer_config).absolute())}
    path = _row_path(t)
    row = json.loads(path.read_text(encoding="utf-8"))
    row["forge"] = binding
    path.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return binding


def default_issuer_config(t: PublishedTenant) -> Path:
    """Where `bind_forge`'s binding names the tenant's issuer client config by default."""
    return Path(t.data_root).absolute().parent / "operator" / "issuer.json"


def unbind_forge(t: PublishedTenant) -> None:
    """Remove the tenant row's `forge` field (absent stays absent); other fields are kept."""
    path = _row_path(t)
    row = json.loads(path.read_text(encoding="utf-8"))
    row.pop("forge", None)
    path.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def fixture_agent_files() -> dict[str, bytes]:
    """The committed fixture's `agent/` files by POSIX relative path, with their bytes."""
    return files_under(FIXTURE_AGENT)


def committed_blobs(clone: Path, rev: str, pathspec: str) -> dict[str, bytes]:
    """Every regular-file blob under `pathspec` at `rev` in `clone`, by repo-relative path, with
    its stored bytes: git's own read of the commit (`ls-tree -r`, then `cat-file blob` each),
    which no worktree entry can redirect."""
    from defender import _git

    listing = _git.git_bytes(["--literal-pathspecs", "ls-tree", "-r", "-z", "--full-name", rev,
                              "--", pathspec], cwd=clone)
    return {path: _git.git_bytes(["cat-file", "blob", oid], cwd=clone)  # lint-oracle: ok — live tests read the lab repo's committed tree as data; no production reader is the oracle
            for mode, kind, oid, path in _git.tree_records(listing)
            if kind == "blob" and mode in ("100644", "100755")}


__all__ = [
    "committed_blobs",
    "default_issuer_config",
    "DEFENDER",
    "FIXTURE",
    "FIXTURE_AGENT",
    "FIXTURE_SETTINGS",
    "FIXTURE_TENANT_ID",
    "ISSUER_AUDIENCE",
    "OTHER_LESSON",
    "OTHER_TENANT_ID",
    "ForgeHTTP",
    "GitHTTP",
    "PublishedTenant",
    "Trickle",
    "VaultHTTP",
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
    "target",
    "unbind_forge",
]
