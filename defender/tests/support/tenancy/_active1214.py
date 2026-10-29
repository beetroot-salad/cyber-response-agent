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
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import inspect
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.tenancy import InMemoryTenantRepository, TenantDirectory

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


def active_directory(data_root: Path, tenant: str, *, state: str = "active", repo: str | None = None,
                     origin: str | None = None, wiring: bool = True) -> TenantDirectory:
    twin: Any = InMemoryTenantRepository()
    extra: dict[str, Any] = {}
    if wiring:
        extra = {"repo": repo or f"tenants/{tenant}", "origin": _origin_of(data_root, tenant, origin)}
    added = twin.add_tenant(str(tenant), created_at=CREATED, state=state, **extra)
    if inspect.isawaitable(added):  # GAP-0-1: the seeder's sync/async shape is not pinned
        asyncio.run(_await(added))
    return TenantDirectory(lambda: twin)


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
                         data_root: Path | None = None) -> None:
    from defender.tests.support.shared._postgres1339 import execute

    action, step, actor = _JOB.get(state, (None, None, None))
    execute(dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                    VALUES (%s, %s, %s, %s, %s, %s)""", (tenant, CREATED, state, action, step, actor))
    if wiring:
        execute(dsn, "INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES (%s, %s, %s)",
                (tenant, repo or f"tenants/{tenant}", _origin_of(data_root or Path("/nonexistent"), tenant, origin)))


def database_env(dsn: str) -> dict[str, str]:
    return {DSN_ENV: dsn}


def postgres_directory(dsn: str) -> TenantDirectory:
    from defender.tenancy.postgres import PostgresTenantRepository

    return TenantDirectory(lambda: PostgresTenantRepository(dsn))
