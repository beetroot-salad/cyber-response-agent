# ruff: noqa: F811, PT018
"""#1214 attack-1 on PostgreSQL: a failure text the database cannot store (H-0), a spent hold frees the lock for another
copy (H-2), the fence needs the lock still held (H-3), the keepalive bound is the configured one (H-4) (DC-1, DC-14, RC-1, RC-2)."""
from __future__ import annotations

import asyncio
import datetime as _dt
import json
import socket
from typing import Any

import httpx
import pytest

pytest.importorskip("httpx")

from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: E402,F401 — fixture
from defender.tests.tenancy.lifecycle_1214._fakes import ADMIN_TOKEN, FORGE_URL, Fakes  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config  # noqa: E402
from defender.tests.tenancy.lifecycle_1214.test_1214_worker_lock import WAIT, _Identity, _StartupProxy  # noqa: E402

pytestmark = pytest.mark.postgres

NOW = _dt.datetime(2026, 10, 28, 12, 0, tzinfo=_dt.UTC)
REPOS = "/api/v1/orgs/tenants/repos"
ROW = "SELECT state, pending_action, step, step_actor, failure FROM tenancy.tenants WHERE id = %s"


class _NulStderr:
    """The fixed integration command, failing with a NUL in its stderr."""

    calls: list[Any] = []

    def __call__(self, arguments: Any) -> Any:
        import subprocess

        return subprocess.CompletedProcess(list(arguments), 1, "", "bad\x00thing")


# --- H-0: a failure text PostgreSQL cannot store ------------------------------------------------------

@pytest.mark.parametrize("hostile", ["a\x00b", "a\ud800b", "integration-stderr-nul"], ids=["nul", "lone-surrogate", "command-nul"])
def test_a_failure_text_the_database_cannot_store_is_still_recorded_and_the_pass_goes_on(
        migrated_database, tmp_path, hostile):
    """An external answer with a NUL or a lone surrogate (or a command's NUL) becomes a recorded failure without it; the
    pass returns, the step is not retried by itself, and the pass serves the other tenant (DC-14, P6)."""
    from defender.lifecycle import ManagementService
    from defender.tenancy.postgres import PostgresTenantRepository

    fakes, config = Fakes(tmp_path), lifecycle_config(tmp_path, tmp_path / "data")
    integration = fakes.integration
    asked: list[int] = []

    def handle(request: httpx.Request) -> httpx.Response:
        if hostile != "integration-stderr-nul" and request.method == "POST" and request.url.path == REPOS and not asked:
            asked.append(1)
            return httpx.Response(500, content=json.dumps({"message": hostile}).encode())
        return fakes.forge.handle(request)
    if hostile == "integration-stderr-nul":
        integration = _NulStderr()
    forge = httpx.AsyncClient(transport=httpx.MockTransport(handle), base_url=FORGE_URL,
                              headers={"Authorization": f"token {ADMIN_TOKEN}"})

    async def go() -> tuple[list[int], list[tuple[Any, ...]]]:
        repo = PostgresTenantRepository(migrated_database)
        try:
            tenants = [(await repo.request_create(now=NOW)).id for _ in range(2)]
            service = ManagementService(repo, identity=_Identity(), forge=forge, openbao=fakes.openbao.client(),
                                        integration=integration, git=fakes.git, config=config, clock=lambda: NOW)
            ran = [await service.work(), await service.work()]
            return ran, [execute(migrated_database, ROW, (t,))[0] for t in tenants]
        finally:
            await repo.close()
    ran, rows = asyncio.run(go())
    failed = [r for r in rows if r[4] is not None]
    assert len(failed) >= 1, f"no failure was recorded: {rows}"
    for row in failed:
        assert "\x00" not in row[4] and row[3] == "service"
    assert ran[1] == 0 or hostile == "integration-stderr-nul", f"the failed step was retried by itself: {ran}"
    if hostile != "integration-stderr-nul":
        [bad] = failed
        assert "repo" in bad[4]
        [good] = [r for r in rows if r[4] is None]
        assert good[3] == "host", f"the pass did not serve the other tenant: {rows}"


# --- H-2: a spent hold frees the lock ----------------------------------------------------------------

def test_after_a_fence_miss_another_copy_can_take_the_tenants_lock_while_the_first_process_lives(migrated_database):
    """A's hold is spent by a fence miss; A's repository stays open, yet B can take T's lock: the lock connection was
    closed, not returned to a pool with the lock still on it (DC-1, RC-1)."""
    from defender.tenancy import FenceMissed
    from defender.tenancy.postgres import PostgresTenantRepository

    async def go() -> tuple[bool, bool]:
        a, b = PostgresTenantRepository(migrated_database), PostgresTenantRepository(migrated_database)
        try:
            t = (await a.request_create(now=NOW)).id
            async with a.lock(t) as held:
                await b.request_offboard(t, now=NOW)  # the job moves under the worker
                with pytest.raises(FenceMissed):
                    await held.commit(step="provider", actor="service")
            async with b.lock(t) as other:
                taken_by_b = other is not None
            async with a.lock(t) as again:  # and the first process itself can take it up again
                return taken_by_b, again is not None
        finally:
            await a.close()
            await b.close()
    assert asyncio.run(go()) == (True, True)


# --- H-3: the fence needs the lock still held --------------------------------------------------------

@pytest.mark.parametrize("write", ["commit", "fail"])
def test_a_write_from_a_session_that_no_longer_holds_the_lock_changes_nothing(migrated_database, write):
    """T's lock is released on the hold's own live connection (not the connection killed): the fenced write misses and
    the row is as it was (RC-1)."""
    from sqlalchemy import text

    from defender.tenancy import FenceMissed
    from defender.tenancy.postgres import PostgresTenantRepository

    async def go() -> tuple[str, list[tuple[Any, ...]], list[tuple[Any, ...]]]:
        repo = PostgresTenantRepository(migrated_database)
        try:
            t = (await repo.request_create(now=NOW)).id
            before = execute(migrated_database, ROW, (t,))
            outcome = "landed"
            async with repo.lock(t) as held:
                assert held is not None
                conn = held._conn  # the hold's own session: the case needs one that is alive and has lost the lock
                await conn.execute(text("SELECT pg_advisory_unlock_all()"))
                await conn.commit()
                try:
                    if write == "commit":
                        await held.commit(step="provider", actor="service")
                    else:
                        await held.fail("lost the lock", step="names", actor="service")
                except FenceMissed:
                    outcome = "missed"
            return outcome, before, execute(migrated_database, ROW, (t,))
        finally:
            await repo.close()
    outcome, before, after = asyncio.run(go())
    assert (outcome, after) == ("missed", before)


# --- H-4: the keepalive bound is the configured one --------------------------------------------------

@pytest.mark.parametrize("keepalive", [12, 30, 60])
def test_the_lock_connections_keepalive_options_stay_within_the_configured_bound(migrated_database, keepalive):
    """For each `lock_keepalive`, idle + interval * count and the user timeout end a dead worker's lock within that many
    seconds (RC-2, DC-1)."""
    import re

    from sqlalchemy.engine import make_url

    from defender.tenancy.postgres import PostgresTenantRepository

    url = make_url(migrated_database)
    try:
        socket.create_connection((url.host, url.port or 5432), timeout=3).close()
    except OSError as e:
        pytest.skip(f"cannot reach the database to proxy it: {e}")
    proxy = _StartupProxy(url.host, url.port or 5432)
    dsn = url.set(host="127.0.0.1", port=proxy.port, query={"sslmode": "disable"}).render_as_string(hide_password=False)

    async def go() -> None:
        repo = PostgresTenantRepository(dsn, lock_keepalive=keepalive)
        try:
            t = (await repo.request_create(now=NOW)).id
            async with repo.lock(t) as held:
                assert held is not None
        finally:
            await repo.close()
    try:
        asyncio.run(asyncio.wait_for(go(), WAIT))
        [options] = [o for o in proxy.options.values() if "tcp_keepalives_idle" in o]
    finally:
        proxy.stop()
    value = {n: int(re.search(rf"{n}\s*=\s*(\d+)", options).group(1))  # type: ignore[union-attr]
             for n in ("tcp_keepalives_idle", "tcp_keepalives_interval", "tcp_keepalives_count", "tcp_user_timeout")}
    assert all(v > 0 for v in value.values()), value
    dies_within = value["tcp_keepalives_idle"] + value["tcp_keepalives_interval"] * value["tcp_keepalives_count"]
    assert dies_within <= keepalive, f"a silent connection lives {dies_within}s > {keepalive}s: {options!r}"
    assert value["tcp_user_timeout"] <= keepalive * 1000, options
