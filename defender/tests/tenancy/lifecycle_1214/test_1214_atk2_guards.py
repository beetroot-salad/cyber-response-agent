# ruff: noqa: PT018
"""#1214 attack-2 holes (input boundaries and guards): entry-point placement order, secret modes, hostile accessors, the
production adapters (`_process`), `LifecycleConfig` refusals and the teardown/retire link guards."""
from __future__ import annotations

import asyncio
import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.records._tenant_id import TenantRefused  # noqa: E402
from defender.tests.support.shared._locations_1210 import fixture_data_root  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._atk2_fakes import GitStub, host_answering_accessor  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import REPO_ROOT, LifecycleWorld, lifecycle_config  # noqa: E402
from defender.tests.tenancy.lifecycle_1214.test_1214_host_entry import TENANT, _connect, _drain_start, _run_start  # noqa: E402
from defender.tests.tenancy.tenant_1108_p4.test_r6_issuer import tls_issuer  # noqa: E402,F401 — fixture

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
JWT = "eyJ.atk2-sentinel-jwt-8c1f.sig"


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def _files_below(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")) if root.is_dir() else []


# --- FR3-13: placement is judged before the host lock is taken --------------------------------------

@pytest.fixture
def inside_the_checkout():
    """A data root path under this checkout's `defender/` tree (removed afterwards, whatever a failing run left)."""
    root = REPO_ROOT / "defender" / f"atk2-placement-{uuid.uuid4().hex[:12]}"
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize("existing", [False, True], ids=["absent root", "existing root"])
def test_hold_tenant_refuses_a_data_root_inside_the_checkout_before_it_creates_anything(inside_the_checkout, existing):
    """The placement refusal comes before the host lock: the root is neither created nor given a `.host-locks` (FR3-13)."""
    from defender.tenancy._admission import hold_tenant

    if existing:
        inside_the_checkout.mkdir()
        (inside_the_checkout / "keep.txt").write_text("mine", encoding="utf-8")
    before = _files_below(inside_the_checkout)
    with pytest.raises(TenantRefused):
        hold_tenant(fixture_data_root(inside_the_checkout), TENANT)
    assert _files_below(inside_the_checkout) == before and inside_the_checkout.exists() == existing


@pytest.mark.parametrize("entry", ["run start", "drain start", "connect command"])
def test_each_host_entry_point_refuses_a_data_root_inside_the_checkout_and_creates_nothing(entry, inside_the_checkout, tmp_path,
                                                                                         monkeypatch):
    """Run start, drain start and the connect command refuse a data root under `defender/` and leave it uncreated (FR3-13)."""
    monkeypatch.setenv(DATA_ROOT_ENV, str(inside_the_checkout))
    text = {"run start": lambda: _run_start(TENANT, tmp_path), "drain start": lambda: _drain_start(TENANT),
            "connect command": lambda: _connect(["check", TENANT])}[entry]()
    assert text.strip() and "Traceback" not in text, "control: the entry point refused in words"
    assert not inside_the_checkout.exists(), f"{entry} created {inside_the_checkout}: {_files_below(inside_the_checkout)}"


# --- DC-2: the secret file and its folder grant nothing to group or other ---------------------------

def test_an_installed_secret_file_is_mode_0600_in_a_folder_that_grants_nothing_to_others(world):
    """The host secret file is `0600` and its per-tenant folder gives group and other nothing (DC-2, round-2 pin)."""
    tenant = world.active_tenant()
    path = world.live(tenant).host_secret_file
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) & 0o077 == 0


# --- DC-2: an accessor OpenBao answers is a file name, never a path ---------------------------------

@pytest.mark.parametrize("accessor", ["../../escaped", "nested/accessor", ".hidden"])
def test_a_hostile_secret_accessor_fails_install_names_it_and_writes_no_file(world, tmp_path, accessor):
    """An accessor that is not a plain file name fails install (restart at `wrap`, failure names the accessor); nothing is
    written outside `<secrets>/<T>` and no secret file is recorded (DC-2, RC-4)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    host_answering_accessor(world, accessor)
    world.drive()
    item = world.item(tenant)
    assert item["state"] == "creating" and "accessor" in item["failure"].lower(), item
    assert (item["step"], item["step_actor"]) == ("wrap", "service"), item
    assert not (tmp_path / "escaped").exists()
    secrets = world.config.secrets_dir
    assert [p for p in secrets.rglob("*") if p.is_file()] == [], "a secret file was written for a hostile accessor"
    assert all(g.host_secret_file is None for g in world.generations(tenant))


# --- DC-10: the JWT reaches a real git process only through the sealed descriptor -------------------

def test_the_real_git_runner_never_puts_the_jwt_in_argv_environment_or_a_file(tmp_path, monkeypatch):
    """`git_runner` with an identity: a git stub sees the JWT only in the sealed include file (control), not in its argv,
    its environment or any file under its home (DC-10)."""
    from defender.lifecycle import git_runner

    stub = GitStub(tmp_path / "stub")
    monkeypatch.setenv("PATH", stub.path())
    identity = SimpleNamespace(token=lambda min_validity=0.0: JWT)
    repo = tmp_path / "repo"
    repo.mkdir()
    done = git_runner(["ls-remote", "https://forge.test/tenants/t.git"], cwd=repo, origin="https://forge.test",
                      identity=identity)
    assert done.returncode == 0, done.stderr
    assert "ARGV:" in stub.recorded(), "control: the stub was the git that ran"
    assert JWT in stub.sealed_text(), "control: the token went through the sealed descriptor"
    assert JWT not in stub.recorded()


# --- F-6: the integration command is fixed -----------------------------------------------------------

def test_the_integration_runner_runs_only_the_fixed_command_as_the_git_user(monkeypatch):
    """`integration_runner(c)(args)` execs `forgejo admin user create-authorized-integration <args>` as `git` in container
    `c`, and nothing else (F-6, design Assets 'one fixed command')."""
    from defender.lifecycle import integration_runner

    seen: list[list[str]] = []

    def run(argv: Any, **_kw: Any) -> subprocess.CompletedProcess[str]:
        seen.append([str(a) for a in argv])
        return subprocess.CompletedProcess(argv, 0, "{}", "")

    monkeypatch.setattr(subprocess, "run", run)
    args = ["--username", "bot-x", "--scope", "write:repository", "--repo", f"{ORG}/t"]
    integration_runner("forge-c")(args)
    assert seen == [["docker", "exec", "-u", "git", "forge-c", "forgejo", "admin", "user",
                     "create-authorized-integration", *args]]


# --- DC-12 / F-1: the clients a process builds carry exactly the credential their actor may hold ----

def _closed(client: Any) -> dict[str, str]:
    seen = {k.lower(): v for k, v in client.headers.items()}
    seen["repr"] = repr(client) + repr(client.auth)
    asyncio.run(client.aclose())
    return seen


def test_the_host_clients_carry_no_credential_and_the_service_clients_carry_theirs(tmp_path, data_root):
    """`openbao_login` has no token and `forge_anonymous` no authorization, neither holding the management login or the
    forge admin token; the service's two clients carry theirs (control) (DC-12, F-1)."""
    from defender.lifecycle import _process

    config = lifecycle_config(tmp_path, data_root)
    host_bao, host_forge = _closed(_process.openbao_login(config)), _closed(_process.forge_anonymous(config))
    assert "x-vault-token" not in host_bao and "authorization" not in host_forge
    for seen in (host_bao, host_forge):
        assert config.openbao_login not in str(seen) and config.forge_admin_token not in str(seen)
    assert _closed(_process.openbao_management(config))["x-vault-token"] == config.openbao_login
    assert _closed(_process.forge_admin(config))["authorization"] == f"token {config.forge_admin_token}"


# --- DC-13: OpenBao is reached over TLS verified against the configured CA --------------------------

def test_the_openbao_clients_refuse_a_server_the_configured_ca_did_not_sign(tls_issuer, data_root):  # noqa: F811
    """`openbao_login` and `openbao_management` fail the handshake with a server another CA signed, and send it nothing; a
    server the named CA signed is reached (control) (DC-13)."""
    import httpx

    from defender.lifecycle import _process

    port, got, folder = tls_issuer
    url = f"https://localhost:{port}"

    async def post(client: Any) -> None:
        async with client:
            await client.post("/v1/auth/approle/login", json={"role_id": "r", "secret_id": "s"})

    trusting = lifecycle_config(folder, data_root, openbao_url=url, openbao_ca=folder / "server.pem")
    asyncio.run(post(_process.openbao_login(trusting)))
    assert got, "control: a server the configured CA signed was reached"
    got.clear()
    distrusting = lifecycle_config(folder, data_root, openbao_url=url, openbao_ca=folder / "trusted.pem")
    for factory in (_process.openbao_login, _process.openbao_management):
        with pytest.raises(httpx.ConnectError):
            asyncio.run(post(factory(distrusting)))
    assert got == [], f"a body reached a server the configured CA did not sign: {got}"


# --- DC-13 / DC-2: what a LifecycleConfig refuses ----------------------------------------------------

def _refused(tmp_path: Path, data_root: Path, **overrides: Any) -> None:
    from defender.lifecycle import ConfigRefused

    with pytest.raises(ConfigRefused):
        lifecycle_config(tmp_path, data_root, **overrides)


def test_a_secrets_directory_in_or_at_the_data_root_is_refused_and_one_beside_it_is_not(tmp_path, data_root):
    """`secrets_dir` equal to the data root or below it is refused; a sibling whose name starts with the root's is fine (DC-2)."""
    _refused(tmp_path, data_root, secrets_dir=data_root)
    _refused(tmp_path, data_root, secrets_dir=data_root / "secrets")
    _refused(tmp_path, data_root, secrets_dir=data_root / "a" / "b" / "secrets")
    assert lifecycle_config(tmp_path, data_root, secrets_dir=data_root.parent / f"{data_root.name}-secrets")


def test_a_secrets_directory_that_resolves_into_the_data_root_is_refused(tmp_path, data_root):
    """Containment is judged on resolved paths: a `..` detour or a link into the data root does not escape it (D4, DC-2)."""
    detour = tmp_path / "other" / ".." / data_root.name
    _refused(tmp_path, data_root, secrets_dir=data_root.parent / "other" / ".." / data_root.name / "secrets")
    _refused(tmp_path, data_root, secrets_dir=detour)
    alias = tmp_path / "alias"
    alias.symlink_to(data_root)
    _refused(tmp_path, data_root, secrets_dir=alias)
    _refused(tmp_path, data_root, secrets_dir=alias / "secrets")
    real = tmp_path / "real-root"
    real.mkdir()
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real)
    _refused(tmp_path, linked_root, secrets_dir=real / "secrets")


@pytest.mark.parametrize("name", ["issuer_url", "openbao_url"])
def test_a_cleartext_issuer_or_openbao_address_is_refused(tmp_path, data_root, name):
    """The issuer URL and the OpenBao address are https, each refused on its own (DC-13, r9 pin; D3)."""
    _refused(tmp_path, data_root, **{name: "http://openbao.test:8200" + ("/v1/identity/oidc" if name == "issuer_url" else "")})


# --- O4 / GAP-Re-3 / O6: link guards at teardown and retirement -------------------------------------

def test_teardown_unlinks_a_link_at_the_tenant_folder_or_secrets_folder_and_leaves_its_target(world, tmp_path):
    """A link standing where `<data root>/<T>` and `<secrets>/<T>` are is removed as a link; the directories it points to
    keep their contents (O4: teardown removes the tenant's, nothing else's)."""
    tenant = world.active_tenant()
    folder, secrets = world.data_root / tenant, world.live(tenant).host_secret_file.parent
    witnesses = {}
    for name, link in (("folder", folder), ("secrets", secrets)):
        witnesses[name] = tmp_path / f"witness-{name}"
        witnesses[name].mkdir()
        (witnesses[name] / "keep.txt").write_text("mine", encoding="utf-8")
        shutil.rmtree(link)
        link.symlink_to(witnesses[name])
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    for name, link in (("folder", folder), ("secrets", secrets)):
        assert (witnesses[name] / "keep.txt").read_text(encoding="utf-8") == "mine", f"the {name} link was followed"
        assert not link.is_symlink() and not link.exists()


def _make(kind: str, path: Path, tmp_path: Path) -> None:
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "socket":
        os.mknod(path, stat.S_IFSOCK | 0o600)
    elif kind == "directory":
        path.mkdir()
        (path / "inside.txt").write_text("kept", encoding="utf-8")
    else:
        target = tmp_path / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        path.symlink_to(target)


@pytest.mark.parametrize("kind", ["fifo", "socket", "directory", "link"])
def test_retire_row_refuses_anything_but_a_regular_file_and_leaves_it_where_it_was(tmp_path, kind):
    """A FIFO, a socket, a directory or a link at `<T>/tenant.json` is refused and still there afterwards (GAP-Re-3, O6)."""
    from defender.tenancy import retire_row

    folder = tmp_path / "data" / TENANT
    folder.mkdir(parents=True)
    row = folder / "tenant.json"
    _make(kind, row, tmp_path)
    before = os.lstat(row).st_mode
    with pytest.raises(Exception):  # noqa: B017, PT011 — a refusal; its type is not pinned
        retire_row(tmp_path / "data", TENANT)
    assert os.lstat(row).st_mode == before, "the entry was removed or replaced"
    if kind == "link":
        assert (tmp_path / "elsewhere.json").read_text(encoding="utf-8") == "{}"
    if kind == "directory":
        assert (row / "inside.txt").read_text(encoding="utf-8") == "kept"


def test_retire_row_refuses_a_linked_tenant_folder_and_leaves_the_other_folders_row(tmp_path):
    """`<data root>/<T>` linked to another directory is refused; the row inside that directory survives (GAP-Re-3, GAP-Re-4)."""
    from defender.tenancy import retire_row

    other = tmp_path / "other"
    other.mkdir()
    (other / "tenant.json").write_text("{}", encoding="utf-8")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / TENANT).symlink_to(other)
    with pytest.raises(Exception):  # noqa: B017, PT011 — a refusal; its type is not pinned
        retire_row(tmp_path / "data", TENANT)
    assert (other / "tenant.json").read_text(encoding="utf-8") == "{}"
    assert (tmp_path / "data" / TENANT).is_symlink()


# --- F-6: exactly the repository write scope ----------------------------------------------------------

def test_each_integration_is_created_with_exactly_the_write_repository_scope(world):
    """The recorded `--scope` is `write:repository` and nothing else, so no organization or admin scope rides along (F-6, O8)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    [made] = [c for c in world.integration.created if c["user"] == gen.bot_login]
    assert made["scopes"] == ["write:repository"]
