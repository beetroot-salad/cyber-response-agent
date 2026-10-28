"""#1214 P6 on PostgreSQL: one worker per tenant through the tenant lock; a crash mid-step continues
from the recorded names (O3). Each worker is its own thread, event loop and repository (connection)."""
from __future__ import annotations

import asyncio
import datetime as _dt
import threading
from typing import Any

import pytest

pytest.importorskip("httpx")

from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: E402,F401 — fixture
from defender.tests.tenancy.lifecycle_1214._fakes import (  # noqa: E402
    FakeForge,
    FakeIntegrationCommand,
    FakeOpenBao,
    RoutedGit,
)

pytestmark = pytest.mark.postgres

NOW = _dt.datetime(2026, 10, 28, 12, 0, tzinfo=_dt.UTC)
USERS = "/api/v1/admin/users"
WAIT = 10.0


class _NoIdentity:
    """Create never calls the identity service; any call is recorded so the case can see it."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        self.calls.append(name)
        raise AssertionError(f"create called identity.{name}")


class Fakes:
    def __init__(self, tmp_path) -> None:
        self.forge = FakeForge(tmp_path / "forge")
        self.integration = FakeIntegrationCommand(self.forge)
        self.openbao = FakeOpenBao()
        self.git = RoutedGit(self.forge)


def _service_work(dsn: str, fakes: Fakes) -> int:
    """One worker: its own loop, repository and connection; one `work()` pass."""
    from defender.lifecycle import ManagementService
    from defender.tenancy.postgres import PostgresTenantRepository

    async def run() -> int:
        repo = PostgresTenantRepository(dsn)
        try:
            service = ManagementService(
                repo, identity=_NoIdentity(), forge=fakes.forge.client(), openbao=fakes.openbao.client(),
                integration=fakes.integration, git=fakes.git, clock=lambda: NOW)
            return await service.work()
        finally:
            await repo.close()
    return asyncio.run(run())


def _request_create(dsn: str) -> str:
    from defender.tenancy.postgres import PostgresTenantRepository

    async def run() -> str:
        repo = PostgresTenantRepository(dsn)
        try:
            return (await repo.request_create(now=NOW)).id
        finally:
            await repo.close()
    return asyncio.run(run())


def _row(dsn: str, tenant: str) -> tuple[Any, ...]:
    [row] = execute(dsn, "SELECT state, pending_action, step, step_actor, failure FROM tenancy.tenants WHERE id = %s",
                    (tenant,))
    return row


def _advisory_holders(dsn: str) -> list[int]:
    return [pid for (pid,) in execute(dsn, """SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted
        AND database = (SELECT oid FROM pg_database WHERE datname = current_database())""")]


def _in_thread(fn, *args) -> tuple[threading.Thread, dict[str, Any]]:
    out: dict[str, Any] = {}

    def target() -> None:
        try:
            out["result"] = fn(*args)
        except BaseException as e:  # noqa: BLE001 — kept for the case to inspect
            out["error"] = e
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, out


def test_a_second_worker_skips_a_locked_tenant_and_takes_another(migrated_database, tmp_path):
    """While worker A holds T's lock mid-step, worker B makes no call for T but works U (O3, P6)."""
    dsn = migrated_database
    fakes = Fakes(tmp_path)
    t = _request_create(dsn)
    inside, release = threading.Event(), threading.Event()

    def block() -> None:
        inside.set()
        assert release.wait(WAIT)
    fakes.forge.during[("POST", USERS)] = block  # A stops inside T's bot creation
    a, a_out = _in_thread(_service_work, dsn, fakes)
    try:
        assert inside.wait(WAIT), f"worker A never reached the bot step: {a_out}"
        u = _request_create(dsn)
        f0, o0 = len(fakes.forge.calls), len(fakes.openbao.calls)
        b_ran = _service_work(dsn, fakes)
        b_calls = [*fakes.forge.calls[f0:], *fakes.openbao.calls[o0:]]
        assert b_ran >= 1
        assert not [c for c in b_calls if t in c.path or t in str(c.body)], "B worked on the locked tenant"
        assert [c for c in b_calls if u in c.path or u in str(c.body)], "control: B worked on the other tenant"
    finally:
        release.set()
        a.join(WAIT)


def test_a_crash_mid_step_releases_the_lock_and_the_next_worker_continues_from_recorded_names(
        migrated_database, tmp_path):
    """A's connection dies inside the bot step; B takes T up, finds the bot A created under the
    recorded name, makes no second one, and finishes the service's steps (O3, P1, P6)."""
    dsn = migrated_database
    fakes = Fakes(tmp_path)
    t = _request_create(dsn)
    inside, release = threading.Event(), threading.Event()

    def block() -> None:
        inside.set()
        assert release.wait(WAIT)
    fakes.forge.during[("POST", USERS)] = block
    a, a_out = _in_thread(_service_work, dsn, fakes)
    assert inside.wait(WAIT), f"worker A never reached the bot step: {a_out}"
    [holder] = _advisory_holders(dsn)
    execute(dsn, "SELECT pg_terminate_backend(%s)", (holder,))
    release.set()  # A's bot creation completes at the forge; A can no longer record anything
    a.join(WAIT)
    assert not a.is_alive()
    assert _advisory_holders(dsn) == []
    assert _row(dsn, t)[2:4] == ("bot", "service"), "A recorded progress after losing its lock"

    _service_work(dsn, fakes)
    assert len(fakes.forge.made("POST", USERS)) == 1, "a second bot was created"
    [bot] = fakes.forge.users
    [args] = fakes.integration.calls
    assert args[args.index("--username") + 1] == bot
    state, pending, step, actor, failure = _row(dsn, t)
    assert (state, pending, step, actor, failure) == ("creating", "create", "install", "host", None)
