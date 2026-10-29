"""#1214 test-machinery smoke: the subprocess launcher, each `.directory` helper and the generation seeder work for a
migrated call site (FR-7). Code-stage check: these must be green before the stale-test census migrates call sites.

Expected red before implementation: the missing `InMemoryTenantRepository` / `directory=` keyword / `tenancy.generations`.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from defender.tests.support.shared.contracts import _data_root_1078 as d9
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.support.tenancy import _launcher1214 as launcher
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture

TENANT = "5c1e8f30-72ab-4d96-b1f4-0a9d3e6c7b82"
STATES = ("not active", "offboarding", "creating", "offboarded", "no database")
OPENBAO = "https://openbao.test"


def _placed(data_root: Path, tenant: str = TENANT) -> None:
    """`tenant`'s host folder, complete (knowledge plus an empty real `learning/`)."""
    from defender.tests.support.tenancy._tenants1106 import place_tenant

    place_tenant(data_root, tenant)
    (data_root / tenant / "learning").mkdir(exist_ok=True)


def _launch(data_root: Path, *seed: str, env: dict[str, str] | None = None) -> str:
    """A drain start through the launcher; its exit status and text."""
    argv = ["loop.py", "--author-drain", "--tenant", TENANT]
    done = subprocess.run(launcher.command("drain", argv, seed=seed, data_root=data_root),  # noqa: S603
                          env=launcher.environment({"DEFENDER_DATA_ROOT": str(data_root), **(env or {})}),
                          capture_output=True, text=True, timeout=120, check=False)
    return f"{done.returncode}\n{done.stdout}{done.stderr}"


def test_launcher_with_no_directory_refuses_naming_the_tenant(data_root):
    """Fail-closed side: an empty launcher directory knows no tenant, so the entry refuses (Flow 4, DC-9)."""
    _placed(data_root)
    text = _launch(data_root)
    assert not text.startswith("0\n"), text
    assert TENANT in text, text
    assert "Traceback" not in text, f"a crash, not a refusal: {text}"  # base: TypeError on `directory=`


def test_launcher_seeded_active_is_admitted_and_seeded_offboarding_is_refused_naming_the_state(data_root):
    """Seeded side: `--seed T` is admitted (no state refusal), `--seed T:offboarding` is refused naming `offboarding`."""
    _placed(data_root)
    admitted = _launch(data_root, TENANT)
    assert "unexpected keyword" not in admitted, admitted  # base: the entry has no `directory=` yet
    assert not any(word in admitted for word in STATES), f"control: an active tenant passes the check: {admitted}"
    refused = _launch(data_root, f"{TENANT}:offboarding")
    assert "offboarding" in refused, refused
    assert TENANT in refused, refused


def test_launcher_environment_gives_the_child_the_database_address_only_when_asked(monkeypatch):
    """`environment()` strips `DEFENDER_DATABASE_DSN`; `environment(database_env(dsn))` is how a publish child gets it."""
    from defender.tests.support.tenancy._active1214 import database_env

    monkeypatch.setenv("DEFENDER_DATABASE_DSN", "postgresql://inherited/x")
    assert "DEFENDER_DATABASE_DSN" not in launcher.environment()
    assert launcher.environment(database_env("postgresql://t/y"))["DEFENDER_DATABASE_DSN"] == "postgresql://t/y"


# --- one test per `.directory` helper kind ---------------------------------------------------------------

def _reports_active(directory: Any, tenant: str, origin_ends: str | None = None) -> None:
    assert directory.state(tenant) == "active"
    wiring = directory.forge_wiring(tenant)
    assert wiring.repo == f"tenants/{tenant}"
    assert wiring.origin.endswith(origin_ends or f"/tenants/{tenant}.git"), wiring
    assert directory.state("not-this-tenant") is None  # control: it reports only its own tenant


def test_d9_tenant_directory_reports_it_active_with_wiring(data_root):
    """`ensure_d9_tenant(...).directory` holds that tenant active with its forge wiring."""
    tenant = d9.ensure_d9_tenant()
    _reports_active(tenant.directory, str(tenant))


def test_knowledge_folder_directory_reports_its_tenant_active_with_wiring(data_root):
    """`place_tenant(...).directory` holds the folder's tenant active with its forge wiring."""
    from defender.tests.support.tenancy._tenants1106 import place_tenant

    folder = place_tenant(data_root, TENANT)
    _reports_active(folder.directory, TENANT)


def test_published_tenant_directory_reports_it_active_with_its_clone_origin(p4_tenant):  # noqa: F811
    """`PublishedTenant.directory` is active, wired to the tenant's own origin; `directory_with(state=...)` refuses it."""
    t = p4_tenant
    directory = t.directory
    assert directory.state(t.tenant_id) == "active"
    assert directory.forge_wiring(t.tenant_id).origin == t.origin
    assert t.directory_with(state="offboarding").state(t.tenant_id) == "offboarding"  # control: the refusal side
    assert t.directory_with(wiring=False).forge_wiring(t.tenant_id) is None


def test_accepted_tenant_lazy_directory_reports_it_active_with_wiring(data_root):
    """The accepted `Tenant` from `set_up_tenant` carries a `LazyDirectory` for itself."""
    accepted = d9.set_up_tenant(data_root, TENANT)
    _reports_active(accepted.directory, TENANT)


# --- the generation seeder ---------------------------------------------------------------------------

def _bao(openbao: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(openbao.handle), base_url=OPENBAO,
                        headers={"X-Vault-Token": openbao.management_token})


def test_the_provisioned_generation_mints_through_the_host_secret_file(tmp_path):
    """The seeder's chain works as `forge_credential` uses it: log in with `role_id` and the file's secret, mint for
    the generation's role, and the token carries the tenant and audience (P4). Needs no production code."""
    from defender.tests.support.tenancy._active1214 import provision_generation
    from defender.tests.tenancy.lifecycle_1214._fakes import FakeOpenBao

    bao = FakeOpenBao()
    fields = provision_generation(_bao(bao), TENANT, tmp_path / "secrets")
    secret = fields["host_secret_file"].read_text(encoding="utf-8").strip()
    host = httpx.Client(transport=httpx.MockTransport(bao.handle), base_url=OPENBAO)
    login = host.post("/v1/auth/approle/login", json={"role_id": fields["role_id"], "secret_id": secret})
    assert login.status_code == 200
    minted = host.get(f"/v1/identity/oidc/token/{fields['oidc_role']}",
                      headers={"X-Vault-Token": login.json()["auth"]["client_token"]})
    assert minted.status_code == 200
    claims = bao.claims(minted.json()["data"]["token"])
    assert (claims["tenant_id"], claims["aud"]) == (TENANT, fields["audience"])
    bad = host.post("/v1/auth/approle/login", json={"role_id": fields["role_id"], "secret_id": "wrong"})
    assert bad.status_code == 400  # control: the file's secret is what authenticates


def test_a_seeded_in_memory_generation_is_read_back_through_the_repository(tmp_path, data_root):
    """`active_repository(..., generations=[fields])` stores the generation with r9's field names (needs `add_generation`, GAP-Ma-1)."""
    import asyncio

    from defender.tests.support.tenancy._active1214 import active_repository, generation_fields

    fields = generation_fields(TENANT, tmp_path / "secrets")
    repo = active_repository(data_root, TENANT, generations=[fields])
    [got] = asyncio.run(repo.generations(TENANT))
    assert {k: getattr(got, k) for k in fields} == fields
    assert got.status == "live"


@pytest.mark.postgres
def test_a_seeded_sql_generation_is_read_back_through_the_repository(tmp_path, data_root, migrated_database):  # noqa: F811
    """`insert_active_tenant(..., generations=[fields])` inserts a `tenancy.generations` row the repository reads."""
    import asyncio

    from defender.tenancy.postgres import PostgresTenantRepository
    from defender.tests.support.tenancy._active1214 import generation_fields, insert_active_tenant

    fields = generation_fields(TENANT, tmp_path / "secrets")
    insert_active_tenant(migrated_database, TENANT, data_root=data_root, generations=[fields])
    [got] = asyncio.run(PostgresTenantRepository(migrated_database).generations(TENANT))
    assert got.bot_login == fields["bot_login"]
    assert got.status == "live"
    assert Path(got.host_secret_file) == fields["host_secret_file"]

