"""Shared machinery for #1108 P4: the fixture tenant as a real tenant repository on a fake Forgejo.

Built on P3's `tenant_1108_delivery/` helpers, imported, never copied: a bare remote served over smart HTTP (`GitHTTP`,
Bearer-authenticated as Forgejo is), the forge API fake (`ForgeHTTP`), the issuer fake (`VaultHTTP`) and P3's
`place_tenant`. Nothing here implements P4 policy: it plants trees, seeds and lands commits on the fake origin by git
plumbing as a human merge would (#1618 r5: knowledge lives only in Forgejo; there is no publish, clone, `exports/` or
`current` on the host), and every judgement is the code under test's. Expected values are read from the bare remote.

The pytest fixture `p4_tenant` (conftest.py) is a `PublishedTenant` under the test's own data root.
"""
from __future__ import annotations

import contextlib
import shutil
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
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

#: The committed fixture tenant (`defender/tests/fixtures/tenant-fixture/`). It carries no `agent/.tenant-id`:
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
    """An accepted tenant whose Forgejo repository (the bare `remote`, served at `origin`) holds the fixture (plus any
    `files`) on `main`, with a forge fake and an issuer fake. `clone` is the test's own seed checkout, outside the data
    root (`seed_checkout`): a human's copy, never read by the code under test. `export.commit` (= `commit`) is the seed.

    Fault seams are P3's fakes: `server` (`GitHTTP`: `.refuse`, `.on_service` returning a
    `Trickle`), `forge` (`ForgeHTTP`: `.fault`, `.protection`), `vault` (`VaultHTTP`: `.status`,
    `.body`, `.calls`). `identity` is the first publish's; it caches its token under a clock that
    never moves, so `open_delivery` builds a fresh `vault.identity()` per call: set an issuer
    fault on `vault` before the next `open_delivery`. `p3` is P3's
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
    #: What the running case carries on its tenant (a mutable holder in a frozen record), e.g. `_drain_support.CARRIED`.
    carried: dict = field(default_factory=dict, repr=False)

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

            twin = self.repository  # built here, outside any loop: the directory opens it inside its own
            cached = TenantDirectory(lambda: twin)
            object.__setattr__(self, "_dir", cached)
        return cached

    def admitted(self) -> Any:
        """The tenant's host acceptance over `directory` (r10.1 C3: checked at the call, released by `with`): the value
        the connect command's verbs (`update`, `propose`) take (C1: a tenant is the scope's value)."""
        from defender.systems.run_tenant import host_tenant
        from defender.tests.support.shared._locations_1210 import fixture_data_root

        return host_tenant(fixture_data_root(self.data_root), self.tenant_id, directory=self.directory)

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
        merged = {**bound, **keywords}
        if "records" not in merged:
            # #1366 R8 DERIVED read `<T>/knowledge/settings`, which #1618 removes: derive from the seed checkout's instead.
            from defender.tests.support.tenancy._systems1366 import derive

            merged["records"] = derive(Path(self.clone) / "settings")
        if merged.get("wiring", True) and "generations" not in merged:
            # The fixture tenant's elastic is proxied (#1391 P1/D12): run start needs a live generation with a
            # sign login. A test whose premise is "none" passes `generations=()`.
            from defender.tests.support.tenancy._proxied1391 import sign_generation

            merged["generations"] = [sign_generation(self.tenant_id)]
        return active_repository(self.data_root, self.tenant_id, repo=repo, **merged)

    def directory_with(self, **keywords: Any) -> Any:
        """A fresh `TenantDirectory` over `repository_with(**keywords)`."""
        from defender.tenancy import TenantDirectory

        twin = self.repository_with(**keywords)
        return TenantDirectory(lambda: twin)

    @property
    def commit(self) -> str:
        """The seed commit: `main` on the remote when the tenant was seeded."""
        return self.export.commit

    def open_delivery(self, **options: Any) -> Any:
        """P3's real `TenantDelivery.open` for this tenant over the forge fake's client, a fresh
        `vault.identity()` (so a fault set on `vault` is seen) and the origin; any of them
        overridable by keyword. It owns a private repository (#1618): use it as a context manager."""
        options.setdefault("defender_dir", DEFENDER)
        options.setdefault("client", self.forge.client)
        if "identity" not in options:
            options["identity"] = self.vault.identity()
        options.setdefault("origin", self.origin)
        return target().TenantDelivery.open(self.tenant, **options)

    def publish(self, **_options: Any) -> Any:
        """#1618 r5 has no publish (readers fetch `main` themselves): what an existing case's "publish again" step stood for
        is now only the remote's `main`, answered as `.commit` (read from the bare remote, no code under test runs)."""
        return SimpleNamespace(commit=self.origin_main())

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


def seed_checkout(scratch: Path, name: str) -> Path:
    """The test's own working checkout of the tenant's repository (a human's copy, outside the data root): where
    `publish_placed` commits what was placed, `<scratch>/seeds/<name>`."""
    return Path(scratch) / "seeds" / name


def _take_placed(placed: Path, work: Path) -> None:
    """Move what was placed at `<T>/knowledge` into the seed checkout `work` (its `agent/` and `settings/` replace the
    checkout's), and leave `<T>` with no `knowledge/` (#1618 K8, design "Upgrade")."""
    if not work.exists():
        work.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(placed), str(work))
        return
    for entry in list(work.iterdir()):
        if entry.name != ".git":
            shutil.rmtree(entry) if entry.is_dir() and not entry.is_symlink() else entry.unlink()
    for entry in list(placed.iterdir()):
        if entry.name != ".git":
            shutil.move(str(entry), str(work / entry.name))
    shutil.rmtree(placed)


@contextlib.contextmanager
def publish_placed(scratch: Path, *, root: Path, tenant_id: str,
                   repo_name: str | None = None) -> Iterator[PublishedTenant]:
    """Seed the tenant's Forgejo repository with what is placed under `root` now, by git plumbing alone (#1618: r5 has no
    publish, clone, `exports/` or `current`; knowledge lives only in Forgejo).

    What `place_fixture`/`place_tenant` planted at `<T>/knowledge` is moved into the seed checkout
    (`seed_checkout(scratch, name)`, outside the data root), committed on `main` and pushed to the bare remote
    `<scratch>/tenants/<repo_name>.git` (default name: the tenant id), served as `origin` for the context. `<T>` is left
    with no `knowledge/`, `exports/` or `knowledge.lock` (the design's upgrade step done). Calling it again (same
    `scratch`) after placing new content pushes it as a fast-forward. Acceptance's `TenantRefused` propagates. Nothing
    of the code under test runs here: every expected value is the remote's (`t.commit`, `t.origin_main()`)."""
    root, scratch = Path(root), Path(scratch)
    name = repo_name if repo_name is not None else tenant_id
    tenant = tenants.accept(root, tenant_id)
    tenant_folder = Path(location_path(tenant.tenant_root))
    placed = tenant_folder / "knowledge"
    work = seed_checkout(scratch, name)
    if placed.is_dir():
        _take_placed(placed, work)
    for leftover in ("exports",):
        shutil.rmtree(tenant_folder / leftover, ignore_errors=True)
    (tenant_folder / "knowledge.lock").unlink(missing_ok=True)
    assert work.is_dir(), f"nothing placed for {tenant_id} and no seed checkout at {work}"
    if not (work / ".git").exists():
        git(work, "init", "-b", "main")
        git(work, "config", "user.name", "P4 fixture")
        git(work, "config", "user.email", "p4@test.invalid")
    git(work, "add", "-A")
    if git(work, "status", "--porcelain"):
        git(work, "commit", "-m", "tenant content")
    head = git(work, "rev-parse", "HEAD")
    remote = scratch / "tenants" / f"{name}.git"
    if remote.exists():
        git(work, "push", "-q", remote, "main:main")
    else:
        remote.parent.mkdir(parents=True, exist_ok=True)
        git(scratch, "clone", "--bare", *BARE_NO_UPKEEP, work, remote)
    assert git(remote, "rev-parse", "refs/heads/main") == head, "premise: the remote's main is the seed"
    server = GitHTTP(scratch, token=issuer_token(tenant_id))
    try:
        origin = f"{server.url}/tenants/{name}.git"
        if git(work, "remote"):
            git(work, "remote", "set-url", "origin", origin)
        else:
            git(work, "remote", "add", "origin", origin)
        git(work, "fetch", remote, "+refs/heads/*:refs/remotes/origin/*")
        forge = ForgeHTTP(remote=remote, origin=origin)
        vault = VaultHTTP(tenant_id)
        identity = vault.identity()
        yield PublishedTenant(
            tenant=tenant, data_root=root, clone=work, remote=remote, origin=origin,
            forge=forge, vault=vault, identity=identity, server=server, scratch=scratch,
            export=SimpleNamespace(commit=head), p3=(tenant, remote, None))
    finally:
        server.close()


def publish_once(scratch: Path, *, root: Path, tenant_id: str) -> PublishedTenant:
    """`publish_placed` for a caller that needs only the seeded remote: the origin server is closed on return."""
    with publish_placed(scratch, root=root, tenant_id=tenant_id) as done:
        return done


@contextlib.contextmanager
def published_tenant(scratch: Path, *, root: Path, tenant_id: str = FIXTURE_TENANT_ID,
                     files: Files | None = None, agent: Path | None = None,
                     repo_name: str = "fixture") -> Iterator[PublishedTenant]:
    """`place_fixture` then `publish_placed`: the remote holds one commit on `main` (the seed). Keep `scratch` (served remotes, merge checkouts) apart from `root`; `root`
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
    from defender.tests.support.tenancy._proxied1391 import with_sign_login

    if generations is None:  # with a sign login: the fixture tenant's elastic is proxied (#1391 P1/D12)
        generations = [with_sign_login(t.tenant_id, generation_fields(t.tenant_id, default_secrets_dir(t)))]
    bound = {"origin": t.origin if origin is None else origin, "generations": list(generations)}
    object.__setattr__(t, "_bound", bound)
    object.__setattr__(t, "_dir", None)
    object.__setattr__(t, "_repo", None)
    return bound


@dataclass
class Minting:
    """A live generation provisioned through a fake OpenBao, and the real `forge_credential` over it: handing
    `credential` to a drain or publish child as `identity=` puts the host secret really inside that process
    (the provider reads the file on every mint). `secrets` are the values a leak scan must not find."""

    fields: dict[str, Any]
    bao: Any
    credential: Any
    secret: str

    @property
    def secrets(self) -> tuple[str, str]:
        return (self.secret, self.fields["role_id"])

    def logins(self) -> list[dict[str, Any]]:
        return [c.body for c in self.bao.calls if c.path == "/v1/auth/approle/login"]

    def assert_logged_in_with_the_file(self) -> None:
        """Premise: the fake's recorded login carried the file's secret id and the generation's role id."""
        assert {"role_id": self.fields["role_id"], "secret_id": self.secret} in self.logins(), (
            "the host secret never entered the process: no login carried the file's secret")


def minting(t: PublishedTenant, tmp_path: Path, *, purpose: str = "drain") -> Minting:
    """Provision a live generation for `t` over a `FakeOpenBao` (host secret file written), record it with
    `bind_forge`, and build the real credential provider over that fake (tokens given a JWT's shape)."""
    import base64
    import json
    import time
    from types import SimpleNamespace

    import httpx

    from defender.learning.author.version_control import forge_credential
    from defender.tests.support.tenancy._active1214 import provision_generation
    from defender.tests.tenancy.lifecycle_1214._fakes import FakeOpenBao

    bao = FakeOpenBao()
    management = httpx.Client(transport=httpx.MockTransport(bao.handle), base_url="https://openbao.test",
                              headers={"X-Vault-Token": bao.management_token})
    fields = provision_generation(management, t.tenant_id, tmp_path / "secrets")
    secret = Path(fields["host_secret_file"]).read_text(encoding="utf-8").strip()
    from defender.tests.support.tenancy._proxied1391 import with_sign_login

    # With a sign login: the fixture tenant's elastic is proxied (#1391 P1/D12), so a run of it signs request tokens.
    bind_forge(t, generations=[with_sign_login(t.tenant_id, fields)])

    def part(doc: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(doc).encode()).decode().rstrip("=")

    now = int(time.time())
    claims = {"iss": "https://openbao.test/v1/identity/oidc", "tenant_id": t.tenant_id, "aud": fields["audience"],
              "iat": now, "exp": now + 600}
    jwt = f"{part({'alg': 'none'})}.{part(claims)}.sig"
    t.server.token = jwt  # the fake origin accepts the one token this provider mints

    def signed(request: httpx.Request) -> httpx.Response:
        # The fake mints opaque strings; the credential decodes claims, so give the token a JWT's shape.
        answer = bao.handle(request)
        if request.method != "GET" or "/identity/oidc/token/" not in request.url.path or answer.status_code != 200:
            return answer
        return httpx.Response(200, json={"data": {"token": jwt}})

    config = SimpleNamespace(issuer_url="https://openbao.test/v1/identity/oidc", openbao_url="https://openbao.test",
                             ca_cert=None)
    credential = forge_credential(t.tenant_id, purpose, directory=t.directory, config=config,
                                  transport=httpx.MockTransport(signed))
    return Minting(fields=fields, bao=bao, credential=credential, secret=secret)


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
