"""#1214 (r9, Flow 4): an ACTIVE tenant in the repository, for host code that now fails closed.

Host entry points (`run.main`, `learning.core.cli.main`, the connect command, drains) work for a tenant only
while `TenantDirectory.state(T) == "active"`, with the origin from `forge_wiring(T)`; with no directory and no
`DEFENDER_DATABASE_DSN` they refuse. This module is the one replacement for the `tenant.json` writers (it does
NOT migrate the existing fixtures). No test functions.

Interface:
- `active_directory(data_root, tenant, *, state="active", repo=None, origin=None) -> TenantDirectory`
  a directory over a fresh in-memory tenant repository holding `tenant` in `state` with forge wiring.
  Hand it to the host entry point as `directory=` (`run.main(argv, directory=d)`,
  `learning.core.cli.main(argv, directory=d)`). `origin` defaults to the folder's own `git remote get-url
  origin` when `<data_root>/<tenant>` is a clone, else `http://forge.test/tenants/<tenant>.git`; `repo` defaults to
  `tenants/<tenant>`. Pass `state="offboarding"` etc. for the refusal side; `repo=None, origin=None` is NOT
  "no wiring" -- use `wiring=False` for a row without forge wiring.
- fixture `active_tenant_directory`: a factory `make(tenant, **same_keywords) -> TenantDirectory` bound to the
  test's `data_root`; import it into a test module or conftest to use it.
- PostgreSQL form, for subprocess/host tests that need `DEFENDER_DATABASE_DSN`:
  `insert_active_tenant(dsn, tenant, *, state="active", repo=None, origin=None, wiring=True)` inserts the rows
  by SQL into a `migrated_database` (test support, not a port method); `database_env(dsn) -> dict` is the
  environment to give the subprocess; `postgres_directory(dsn) -> TenantDirectory` reads the same rows.
  GAP-0-4: the `tenancy.forge_wiring` column names (`tenant_id, repo, origin`) are not pinned; they are spelled only here.

Credential call sites (a host-side caller that mints: the p4 drain-credential cases, `bind_forge`'s issuer half, the
publish child) need a live GENERATION and the host secret file it points at, as well as the tenant:
- `provision_generation(openbao, tenant, secrets_dir, *, salt="g1", status="live", audience=None) -> dict`
  builds the chain in OpenBao over its HTTP API (`openbao`: a sync `httpx.Client` carrying the management token; for
  the fake, `httpx.Client(transport=httpx.MockTransport(world.openbao.handle), base_url=OPENBAO_URL,
  headers={"X-Vault-Token": world.openbao.management_token})`; for a live OpenBao the same, over its address): OIDC
  role (`client_id` = audience, the `tenant_id` template), AppRole, entity with metadata `oidc_role` and `tenant_id`,
  an entity-alias named by the AppRole's `role_id`, one secret id. It writes the host secret file
  (`<secrets_dir>/<tenant>-<salt>`, the secret id and a newline: GAP-Ma-2, the file's format is the implementer's
  to confirm) and returns the generation fields (`salt, status, bot_login, oidc_role, approle, role_id, entity,
  audience, host_secret_file, secret_accessor`, r9's pinned names). A live OpenBao also needs the templated policy
  and the mounts the deployment sets up; this creates only the per-tenant chain. The bot is not created in Forgejo.
- hand the fields to the tenant: `active_directory(..., generations=[fields])` (in memory) or
  `insert_active_tenant(..., generations=[fields])` (PostgreSQL rows by SQL into `tenancy.generations`).
  `PublishedTenant.directory_with(generations=[fields])` forwards. `generation_status`-only rows (no OpenBao chain)
  need no provisioning: pass `generation_fields(tenant, secrets_dir)`.
- In memory this calls `InMemoryTenantRepository.add_generation(tenant, **fields)` (async like `add_tenant`):
  a NEW production name, listed in the slice report (GAP-Ma-1); r9 pins no way to seed a generation without the
  service. Where the implementer prefers another spelling, only `_seed_generation` here changes.
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import inspect
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from defender.tenancy import TenantDirectory

CREATED = _dt.datetime(2026, 10, 26, 9, 0, tzinfo=_dt.UTC)
#: The `defender.tenancy` env var the host reads the database address from (DC-9).
DSN_ENV = "DEFENDER_DATABASE_DSN"
FORGE_ORIGIN = "http://forge.test"


def _origin_of(data_root: Path, tenant: str, origin: str | None) -> str:
    if origin is not None:
        return origin
    folder = Path(data_root) / tenant
    if (folder / ".git").exists():
        got = subprocess.run(["git", "-C", str(folder), "remote", "get-url", "origin"],  # noqa: S603, S607
                             capture_output=True, text=True, check=False)
        if got.returncode == 0 and got.stdout.strip():
            return got.stdout.strip()
    return f"{FORGE_ORIGIN}/tenants/{tenant}.git"


def active_directory(data_root: Path, tenant: str, **keywords: Any) -> TenantDirectory:
    """See the module doc; `keywords` are `active_repository`'s."""
    from defender.tenancy import TenantDirectory

    twin = active_repository(data_root, tenant, **keywords)
    return TenantDirectory(lambda: twin)


def active_repository(data_root: Path, tenant: str, *, state: str = "active", repo: str | None = None,
                      origin: str | None = None, wiring: bool = True,
                      generations: Sequence[Mapping[str, Any]] = ()) -> Any:
    """The in-memory tenant repository behind `active_directory` (for a test that reads it back directly)."""
    from defender.tenancy import InMemoryTenantRepository

    twin: Any = InMemoryTenantRepository()
    extra: dict[str, Any] = {}
    if wiring:
        extra = {"repo": repo or f"tenants/{tenant}", "origin": _origin_of(data_root, tenant, origin)}
    added = twin.add_tenant(str(tenant), created_at=CREATED, state=state, **extra)
    if inspect.isawaitable(added):  # GAP-0-1: the seeder's sync/async shape is not pinned
        asyncio.run(_await(added))
    for fields in generations:
        _seed_generation(twin, str(tenant), fields)
    return twin


def _seed_generation(twin: Any, tenant: str, fields: Mapping[str, Any]) -> None:
    added = twin.add_generation(tenant, **fields)  # GAP-Ma-1: not pinned by r9
    if inspect.isawaitable(added):
        asyncio.run(_await(added))


async def _await(awaitable: Any) -> None:
    await awaitable


@pytest.fixture
def active_tenant_directory(data_root: Path) -> Callable[..., TenantDirectory]:
    def make(tenant: str, **keywords: Any) -> TenantDirectory:
        return active_directory(data_root, tenant, **keywords)

    return make


# --- PostgreSQL form ------------------------------------------------------------------------------

#: (pending_action, step, step_actor) a row in each state may carry (the data model's CHECK).
_JOB = {"creating": ("create", "names", "service"), "offboarding": ("offboard", "offboard", "service")}


def insert_active_tenant(dsn: str, tenant: str, *, state: str = "active", repo: str | None = None,
                         origin: str | None = None, wiring: bool = True,
                         data_root: Path | None = None, generations: Sequence[Mapping[str, Any]] = ()) -> None:
    from defender.tests.support.shared._postgres1339 import execute

    action, step, actor = _JOB.get(state, (None, None, None))
    execute(dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                    VALUES (%s, %s, %s, %s, %s, %s)""", (tenant, CREATED, state, action, step, actor))
    if wiring:
        execute(dsn, "INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES (%s, %s, %s)",
                (tenant, repo or f"tenants/{tenant}", _origin_of(data_root or Path("/nonexistent"), tenant, origin)))
    for fields in generations:
        insert_generation(dsn, tenant, fields)


def insert_generation(dsn: str, tenant: str, fields: Mapping[str, Any]) -> None:
    """One `tenancy.generations` row by SQL: `fields` (r9's pinned Generation field names, paths as `str`) plus a
    plausible value for every other NOT NULL column without a default (the rest of the table is not pinned)."""
    import uuid

    from defender.tests.support.shared._postgres1339 import execute

    values: dict[str, Any] = {k: str(v) if isinstance(v, Path) else v for k, v in fields.items()}
    values["tenant_id"] = tenant
    needed = execute(dsn, """SELECT column_name, data_type FROM information_schema.columns
                             WHERE table_schema = 'tenancy' AND table_name = 'generations' AND is_nullable = 'NO'
                               AND column_default IS NULL""")
    for name, kind in needed:
        if name not in values:
            values[name] = (CREATED if kind.startswith("timestamp") else False if kind == "boolean" else
                            0 if kind in ("integer", "bigint", "smallint") else "{}" if kind in ("json", "jsonb")
                            else f"{name}-{uuid.uuid4()}")
    names = ", ".join(f'"{n}"' for n in values)
    execute(dsn, f'INSERT INTO tenancy."generations" ({names}) VALUES ({", ".join(["%s"] * len(values))})',  # noqa: S608
            tuple(values.values()))


def database_env(dsn: str) -> dict[str, str]:
    return {DSN_ENV: dsn}


def postgres_directory(dsn: str) -> TenantDirectory:
    from defender.tenancy import TenantDirectory
    from defender.tenancy.postgres import PostgresTenantRepository

    return TenantDirectory(lambda: PostgresTenantRepository(dsn))


# --- generations: the credential chain a minting call site needs --------------------------------------

def generation_fields(tenant: str, secrets_dir: Path, *, salt: str = "g1", status: str = "live",
                      audience: str | None = None) -> dict[str, Any]:
    """The generation's fields with deterministic names and no OpenBao behind them (rows whose chain a test
    does not exercise). `role_id`/`secret_accessor` are placeholders."""
    approle = f"approle-{tenant}-{salt}"
    return {"salt": salt, "status": status, "bot_login": f"bot-{tenant}-{salt}", "oidc_role": f"oidc-{tenant}-{salt}",
            "approle": approle, "role_id": f"role-id-{approle}", "entity": f"entity-{tenant}-{salt}",
            "audience": audience or f"audience-{tenant}-{salt}",
            "host_secret_file": Path(secrets_dir) / f"{tenant}-{salt}", "secret_accessor": f"accessor-{tenant}-{salt}"}


def provision_generation(openbao: Any, tenant: str, secrets_dir: Path, *, salt: str = "g1", status: str = "live",
                         audience: str | None = None) -> dict[str, Any]:
    """Build the generation's OpenBao chain through `openbao` (a sync management-token `httpx.Client`), write the host
    secret file, and return the fields (see the module doc). Raises on any non-2xx answer."""
    fields = generation_fields(tenant, secrets_dir, salt=salt, status=status, audience=audience)

    def call(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        done = openbao.request(method, f"/v1/{path}", json=body)
        done.raise_for_status()
        return done.json().get("data") or {} if done.content else {}

    call("POST", f"identity/oidc/role/{fields['oidc_role']}", {
        "key": "default", "client_id": fields["audience"], "ttl": "10m",
        "template": '{"tenant_id": {{identity.entity.metadata.tenant_id}}}'})
    call("POST", f"auth/approle/role/{fields['approle']}", {"secret_id_num_uses": 0})
    fields["role_id"] = call("GET", f"auth/approle/role/{fields['approle']}/role-id")["role_id"]
    entity = call("POST", f"identity/entity/name/{fields['entity']}", {
        "name": fields["entity"], "metadata": {"oidc_role": fields["oidc_role"], "tenant_id": tenant}})
    mount = next(v["accessor"] for k, v in call("GET", "sys/auth").items() if k.startswith("approle"))
    call("POST", "identity/entity-alias", {"name": fields["role_id"], "canonical_id": entity["id"],
                                           "mount_accessor": mount})
    secret = call("POST", f"auth/approle/role/{fields['approle']}/secret-id")
    fields["secret_accessor"] = secret["secret_id_accessor"]
    path = Path(fields["host_secret_file"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secret["secret_id"] + "\n", encoding="utf-8")
    path.chmod(0o600)
    return fields
