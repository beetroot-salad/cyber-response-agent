# ruff: noqa: F811, PT018
"""#1214 P6 on PostgreSQL: one worker per tenant through the tenant lock; every write fenced; a worker that
lost its lock writes nothing; a crash mid-step continues from the recorded names (O3, P1, P6, DC-1, RC-1, RC-2).
Each worker is its own thread, event loop and repository (connection); the API side is `request_*` on its own."""
from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import re
import socket
import threading
from typing import Any

import pytest

pytest.importorskip("httpx")

from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: E402,F401 — fixture
from defender.tests.tenancy.lifecycle_1214._fakes import Fakes  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config  # noqa: E402

pytestmark = pytest.mark.postgres

NOW = _dt.datetime(2026, 10, 28, 12, 0, tzinfo=_dt.UTC)
USERS = "/api/v1/admin/users"
REPOS = "/api/v1/orgs/tenants/repos"
WAIT = 10.0
#: Everything of `tenancy` a worker could write for one tenant, as rows (before == after means nothing was written).
TENANT_ROW = "SELECT state, pending_action, step, step_actor, failure FROM tenancy.tenants WHERE id = %s"


class _Identity:
    """Records `end_tenant`; any other identity call fails the case (create never calls identity)."""

    def __init__(self) -> None:
        self.ended: list[str] = []

    async def end_tenant(self, tenant: str, *, now: Any) -> None:
        self.ended.append(tenant)

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the job called identity.{name}")


class _BlockingIntegration:
    """The fixed command, held open: the worker is inside the call until `release` is set."""

    def __init__(self, inner: Any, inside: threading.Event, release: threading.Event) -> None:
        self.inner, self.inside, self.release = inner, inside, release

    def __call__(self, arguments: Any) -> Any:
        self.inside.set()
        assert self.release.wait(WAIT)
        return self.inner(arguments)


class _BlockingPublish:
    """The first publish, held open."""

    def __init__(self, inner: Any, inside: threading.Event, release: threading.Event) -> None:
        self.inner, self.inside, self.release = inner, inside, release

    def __call__(self, tenant_id: str, **kw: Any) -> str:
        self.inside.set()
        assert self.release.wait(WAIT)
        return self.inner(tenant_id, **kw)


def _config(tmp_path):
    return lifecycle_config(tmp_path, tmp_path / "data")


def _pass(dsn: str, kind: str, fakes: Fakes, config: Any, *, identity: Any = None, integration: Any = None,
          publish: Any = None) -> int:
    """One `work()` pass of one actor on its own loop, repository and connection."""
    from defender.lifecycle import HostActor, ManagementService
    from defender.tenancy.postgres import PostgresTenantRepository

    async def run() -> int:
        repo = PostgresTenantRepository(dsn)
        try:
            if kind == "service":
                actor: Any = ManagementService(
                    repo, identity=identity or _Identity(), forge=fakes.forge.client(),
                    openbao=fakes.openbao.client(), integration=integration or fakes.integration,
                    git=fakes.git, config=config, clock=lambda: NOW)
            else:
                actor = HostActor(repo, openbao_login=fakes.openbao.client(None), git=fakes.git,
                                  publish=publish or fakes.publish, config=config, clock=lambda: NOW)
            return await actor.work()
        finally:
            await repo.close()
    return asyncio.run(run())


def _api(dsn: str, request: str, *args: Any, **kwargs: Any) -> Any:
    """One API request on its own ordinary connection (`request_create(now=)`, `request_offboard(t, now=)` ...)."""
    from defender.tenancy.postgres import PostgresTenantRepository

    async def run() -> Any:
        repo = PostgresTenantRepository(dsn)
        try:
            return await getattr(repo, request)(*args, **kwargs)
        finally:
            await repo.close()
    return asyncio.run(run())


def _request_create(dsn: str) -> str:
    return _api(dsn, "request_create", now=NOW).id


def _row(dsn: str, tenant: str) -> tuple[Any, ...]:
    [row] = execute(dsn, TENANT_ROW, (tenant,))
    return row


def _snapshot(dsn: str, tenant: str) -> tuple[Any, ...]:
    """Every row of the job's three tables for `tenant`, in full."""
    return (execute(dsn, "SELECT * FROM tenancy.tenants WHERE id = %s", (tenant,)),
            execute(dsn, "SELECT * FROM tenancy.generations WHERE tenant_id = %s ORDER BY salt", (tenant,)),
            execute(dsn, "SELECT * FROM tenancy.forge_wiring WHERE tenant_id = %s", (tenant,)))


def _generations(dsn: str, tenant: str) -> list[tuple[Any, ...]]:
    return execute(dsn, "SELECT status, bot_login, oidc_role, approle, entity, audience FROM tenancy.generations "
                        "WHERE tenant_id = %s ORDER BY salt", (tenant,))


def _advisory_holders(dsn: str) -> list[int]:
    return [pid for (pid,) in execute(dsn, """SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted
        AND database = (SELECT oid FROM pg_database WHERE datname = current_database())""")]


def _in_thread(fn, *args, **kwargs) -> tuple[threading.Thread, dict[str, Any]]:
    out: dict[str, Any] = {}

    def target() -> None:
        try:
            out["result"] = fn(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001 — kept for the case to inspect
            out["error"] = e
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, out


def _hold_forge(fakes: Fakes, method: str, path: str) -> tuple[threading.Event, threading.Event]:
    """The next forge call `method path` stops mid-call (the worker is inside it) until `release`."""
    inside, release = threading.Event(), threading.Event()

    def block() -> None:
        inside.set()
        assert release.wait(WAIT)
    fakes.forge.during[(method, path)] = block
    return inside, release


def _settle(dsn: str, tenant: str, fakes: Fakes, config: Any, until, *, rounds: int = 40, **kw: Any) -> None:
    """Alternate service and host passes until `until(row)`; fails if it does not get there."""
    for _ in range(rounds):
        if until(_row(dsn, tenant)):
            return
        ran = sum(_pass(dsn, kind, fakes, config, **kw) for kind in ("service", "host"))
        assert ran or until(_row(dsn, tenant)), f"nothing ran and the job is at {_row(dsn, tenant)}"
    raise AssertionError(f"the job did not get there: {_row(dsn, tenant)}")


# --- one worker per tenant ----------------------------------------------------------------------------

def test_a_second_worker_skips_a_locked_tenant_and_takes_another(migrated_database, tmp_path):
    """While worker A holds T's lock mid-step, B makes no call for T but works U; once A is done B works T (O3, P6)."""
    dsn, fakes, config = migrated_database, Fakes(tmp_path), _config(tmp_path)
    t = _request_create(dsn)
    inside, release = _hold_forge(fakes, "POST", USERS)  # A stops inside T's bot creation
    a, a_out = _in_thread(_pass, dsn, "service", fakes, config)
    try:
        assert inside.wait(WAIT), f"worker A never reached the bot step: {a_out}"
        u = _request_create(dsn)
        f0, o0 = len(fakes.forge.calls), len(fakes.openbao.calls)
        b_ran = _pass(dsn, "service", fakes, config)
        b_calls = [*fakes.forge.calls[f0:], *fakes.openbao.calls[o0:]]
        assert b_ran >= 1
        assert not [c for c in b_calls if t in c.path or t in str(c.body)], "B worked on the locked tenant"
        assert [c for c in b_calls if u in c.path or u in str(c.body)], "control: B worked on the other tenant"
    finally:
        release.set()
        a.join(WAIT)
    assert not a.is_alive() and _advisory_holders(dsn) == []
    before = _row(dsn, t)
    assert _pass(dsn, "service", fakes, config) >= 1, "control: with A done, T is takeable"
    assert _row(dsn, t) != before


def test_the_lock_is_the_two_key_advisory_lock_on_the_tenant_held_on_the_workers_own_connection(
        migrated_database, tmp_path):
    """T's lock is `pg_try_advisory_lock(ns, hashtext(T))` (two-key form), held for the step only (P6, DC-1)."""
    dsn, fakes, config = migrated_database, Fakes(tmp_path), _config(tmp_path)
    t, u = _request_create(dsn), _request_create(dsn)
    inside, release = _hold_forge(fakes, "POST", USERS)
    a, a_out = _in_thread(_pass, dsn, "service", fakes, config)
    try:
        assert inside.wait(WAIT), f"worker A never reached the bot step: {a_out}"
        mine = "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND objsubid = 2 " \
               "AND objid = (hashtext(%s)::bigint & 4294967295)::oid"
        assert execute(dsn, mine, (t,)) == [(1,)] or execute(dsn, mine, (u,)) == [(1,)], \
            "the held lock is not keyed by (namespace, hashtext(tenant id))"
        assert len(_advisory_holders(dsn)) == 1
    finally:
        release.set()
        a.join(WAIT)
    assert _advisory_holders(dsn) == [], "the lock outlived the step"


def test_requests_are_not_blocked_by_a_running_step_and_take_no_lock(migrated_database, tmp_path):
    """With a step held open on T, create/offboard requests return at once and hold no advisory lock (P6, DC-1)."""
    dsn, fakes, config = migrated_database, Fakes(tmp_path), _config(tmp_path)
    t = _request_create(dsn)
    inside, release = _hold_forge(fakes, "POST", USERS)
    a, a_out = _in_thread(_pass, dsn, "service", fakes, config)
    try:
        assert inside.wait(WAIT), f"worker A never reached the bot step: {a_out}"
        [holder] = _advisory_holders(dsn)
        made, made_out = _in_thread(_request_create, dsn)
        asked, asked_out = _in_thread(_api, dsn, "request_offboard", t, now=NOW)
        made.join(WAIT)
        asked.join(WAIT)
        assert not made.is_alive() and not asked.is_alive(), "a request waited for the running step"
        assert "error" not in made_out and "error" not in asked_out, (made_out, asked_out)
        assert _advisory_holders(dsn) == [holder], "a request took an advisory lock"
        assert _row(dsn, t)[:2] == ("offboarding", "offboard")
    finally:
        release.set()
        a.join(WAIT)


# --- RC-2: the lock connection's server-side keepalives -----------------------------------------------

class _StartupProxy:
    """A TCP pass-through to the server that records, per connection, the `options` of the startup packet
    and the local port it connects from (what `pg_stat_activity.client_port` shows the server)."""

    def __init__(self, host: str, port: int) -> None:
        self.upstream = (host, port)
        self.options: dict[int, str] = {}
        ready = threading.Event()
        self.loop = asyncio.new_event_loop()
        self.port = 0

        async def boot() -> None:
            server = await asyncio.start_server(self._client, "127.0.0.1", 0)
            self.port = server.sockets[0].getsockname()[1]
            ready.set()
            async with server:
                await server.serve_forever()
        threading.Thread(target=lambda: self.loop.run_until_complete(boot()), daemon=True).start()
        assert ready.wait(WAIT)

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        up_reader, up_writer = await asyncio.open_connection(*self.upstream)
        local = up_writer.get_extra_info("sockname")[1]
        try:
            while True:  # SSLRequest / GSSENCRequest are declined, then the startup packet
                head = await reader.readexactly(8)
                length, code = int.from_bytes(head[:4], "big"), int.from_bytes(head[4:], "big")
                body = await reader.readexactly(length - 8)
                if code in (80877103, 80877104):
                    writer.write(b"N")
                    await writer.drain()
                    continue
                pairs = body.split(b"\0")
                params = dict(zip(pairs[0::2], pairs[1::2], strict=False))
                self.options[local] = params.get(b"options", b"").decode()
                up_writer.write(head + body)
                break
            await up_writer.drain()

            async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
                with contextlib.suppress(Exception):
                    while data := await src.read(65536):
                        dst.write(data)
                        await dst.drain()
                    dst.close()
            await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            for w in (writer, up_writer):
                with contextlib.suppress(Exception):
                    w.close()

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)


def test_the_lock_connection_sets_server_side_keepalives_and_a_user_timeout(migrated_database, tmp_path):
    """The connection holding T's lock was opened with tcp_keepalives_idle/interval/count and tcp_user_timeout
    as positive startup options, so the database drops the lock of a dead or cut-off worker in bounded time (RC-2)."""
    from sqlalchemy.engine import make_url

    url = make_url(migrated_database)
    try:
        socket.create_connection((url.host, url.port or 5432), timeout=3).close()
    except OSError as e:  # the database must be reachable from the test to sit a proxy in front of it
        pytest.skip(f"cannot reach the database to proxy it: {e}")
    proxy = _StartupProxy(url.host, url.port or 5432)
    dsn = url.set(host="127.0.0.1", port=proxy.port, query={"sslmode": "disable"}).render_as_string(hide_password=False)
    fakes, config = Fakes(tmp_path), _config(tmp_path)
    t = _request_create(migrated_database)
    inside, release = _hold_forge(fakes, "POST", USERS)
    a, a_out = _in_thread(_pass, dsn, "service", fakes, config)
    try:
        assert inside.wait(WAIT), f"worker A never reached the bot step: {a_out}"
        [holder] = _advisory_holders(migrated_database)
        [(port,)] = execute(migrated_database, "SELECT client_port FROM pg_stat_activity WHERE pid = %s", (holder,))
        assert port in proxy.options, f"the lock holder did not come through the proxy: {sorted(proxy.options)}"
        options = proxy.options[port]
        for name in ("tcp_keepalives_idle", "tcp_keepalives_interval", "tcp_keepalives_count", "tcp_user_timeout"):
            found = re.search(rf"{name}\s*=\s*(\d+)", options)
            assert found and int(found.group(1)) > 0, f"{name} is not set on the lock connection: {options!r}"
    finally:
        release.set()
        a.join(WAIT)
        proxy.stop()
    assert t


# --- a worker that lost its lock writes nothing (RC-1) --------------------------------------------------

def _hold_and_kill(dsn: str, fakes: Fakes, config: Any, site: str, *, outcome: str = "completes"):
    """Worker A is inside the external call of `site`; its lock connection is then terminated and A is released.
    Returns (tenant, snapshot taken while A held the lock) once A has finished."""
    t = _request_create(dsn)
    inside, release = threading.Event(), threading.Event()
    integration = None
    if site == "integration":
        integration = _BlockingIntegration(fakes.integration, inside, release)
    else:
        path = {"bot": USERS, "repo": REPOS}[site]
        inside, release = _hold_forge(fakes, "POST", path)
        if outcome == "errors":
            fakes.forge.fail_next[("POST", path)] = 500
    a, a_out = _in_thread(_pass, dsn, "service", fakes, config, integration=integration)
    assert inside.wait(WAIT), f"worker A never reached the {site} step: {a_out}"
    [holder] = _advisory_holders(dsn)
    held = _snapshot(dsn, t)
    execute(dsn, "SELECT pg_terminate_backend(%s)", (holder,))
    release.set()  # A's call completes (or errors) at the other side; A can no longer record anything
    a.join(WAIT)
    assert not a.is_alive()
    assert _advisory_holders(dsn) == []
    return t, held


@pytest.mark.parametrize("site", ["repo", "bot", "integration"])
def test_a_worker_whose_lock_connection_is_terminated_writes_nothing_and_the_next_continues_from_recorded_names(
        migrated_database, tmp_path, site):
    """A's backend is terminated inside an external call that then completes: A records no step and no failure
    though the library could reconnect; B finds the created thing under its recorded name, makes no second
    one, reaches the host step, and offboarding destroys everything that exists (O3, P1, P6, RC-1)."""
    dsn, fakes, config = migrated_database, Fakes(tmp_path), _config(tmp_path)
    identity = _Identity()
    t, held = _hold_and_kill(dsn, fakes, config, site)
    assert _snapshot(dsn, t) == held, "A wrote after losing its lock"
    assert _row(dsn, t)[4] is None

    _settle(dsn, t, fakes, config, lambda row: row[3] == "host", rounds=6)  # the service's steps finish
    assert _row(dsn, t) == ("creating", "create", "install", "host", None)
    [gen] = _generations(dsn, t)
    status, bot, role, approle, entity, audience = gen
    assert (status, set(fakes.forge.users), set(fakes.openbao.oidc_roles), set(fakes.openbao.approles),
            set(fakes.openbao.entities)) == ("pending", {bot}, {role}, {approle}, {entity}), "unknown or duplicate things"
    assert list(fakes.forge.repos) == [f"tenants/{t}"] and len(fakes.forge.made("POST", REPOS)) == 1
    assert len(fakes.forge.made("POST", USERS)) == 1
    args = fakes.integration.calls
    assert all(a == args[0] for a in args) and args[0][args[0].index("--username") + 1] == bot
    if site == "integration":
        assert len(args) == 2, "B did not redo the interrupted integration"
        assert fakes.forge.integrations[bot][-1] == audience, "the recorded audience is not the committed integration's"
        assert fakes.openbao.oidc_roles[role]["client_id"] == audience

    _api(dsn, "request_offboard", t, now=NOW)
    _pass(dsn, "service", fakes, config, identity=identity)
    assert (fakes.forge.users, fakes.forge.integrations) == (set(), {}), "a duplicate integration outlived its bot"
    assert not (fakes.openbao.oidc_roles or fakes.openbao.approles or fakes.openbao.entities)
    assert identity.ended == [t]


@pytest.mark.parametrize("site", ["bot", "repo"])
def test_a_worker_that_lost_its_lock_and_then_errors_records_no_failure(migrated_database, tmp_path, site):
    """A's backend is terminated and A's call then fails: no failure is written (RC-1); B retries the step
    and the job goes on (O3, P6)."""
    dsn, fakes, config = migrated_database, Fakes(tmp_path), _config(tmp_path)
    t, held = _hold_and_kill(dsn, fakes, config, site, outcome="errors")
    assert _snapshot(dsn, t) == held
    assert _row(dsn, t)[4] is None
    _settle(dsn, t, fakes, config, lambda row: row[3] == "host", rounds=6)
    assert _row(dsn, t) == ("creating", "create", "install", "host", None)


# --- every write is fenced (RC-1) ---------------------------------------------------------------------

FENCES = {
    "step": "UPDATE tenancy.tenants SET step = 'repo' WHERE id = %s",
    "step_actor": "UPDATE tenancy.tenants SET step_actor = 'host' WHERE id = %s",
    "failure": "UPDATE tenancy.tenants SET failure = 'put there by the case' WHERE id = %s",
}


@pytest.mark.parametrize("changed", [*FENCES, "nothing"])
def test_a_step_commit_lands_only_if_step_actor_and_failure_are_as_read(migrated_database, tmp_path, changed):
    """The row changes under A (only one column at a time): A's commit misses and the row is as the change
    left it; with nothing changed the same commit lands (RC-1, DC-1, P6)."""
    dsn, fakes, config = migrated_database, Fakes(tmp_path), _config(tmp_path)
    t = _request_create(dsn)
    inside, release = _hold_forge(fakes, "POST", USERS)
    a, a_out = _in_thread(_pass, dsn, "service", fakes, config)
    try:
        assert inside.wait(WAIT), f"worker A never reached the bot step: {a_out}"
        if changed != "nothing":
            execute(dsn, FENCES[changed], (t,))
        held = _snapshot(dsn, t)
    finally:
        release.set()
        a.join(WAIT)
    assert not a.is_alive()
    if changed == "nothing":
        assert _snapshot(dsn, t) != held and _row(dsn, t)[2] != "bot", "control: an unchanged row takes the commit"
    else:
        assert _snapshot(dsn, t) == held, f"A's write ignored a changed {changed}"


def test_a_failure_is_fenced_too_and_an_offboard_mid_step_makes_the_commit_miss_and_the_worker_stop(
        migrated_database, tmp_path):
    """Offboard commits while A is inside a call that then fails: A records no failure and runs no later step;
    B (after A releases) offboards, destroying what A created under its recorded names (O3, O4, P1, P6)."""
    dsn, fakes, config = migrated_database, Fakes(tmp_path), _config(tmp_path)
    identity = _Identity()
    t = _request_create(dsn)
    inside, release = _hold_forge(fakes, "POST", USERS)
    fakes.forge.fail_next[("POST", USERS)] = 500
    a, a_out = _in_thread(_pass, dsn, "service", fakes, config)
    try:
        assert inside.wait(WAIT), f"worker A never reached the bot step: {a_out}"
        _api(dsn, "request_offboard", t, now=NOW)
        f0 = len(fakes.forge.calls)
        assert _pass(dsn, "service", fakes, config, identity=identity) == 0, "B took up a locked tenant"
        assert len(fakes.forge.calls) == f0
    finally:
        release.set()
        a.join(WAIT)
    assert not a.is_alive()
    assert _row(dsn, t) == ("offboarding", "offboard", "offboard", "service", None), "A wrote after the offboard"
    assert fakes.integration.calls == [], "A went on to a later step"

    _pass(dsn, "service", fakes, config, identity=identity)
    assert identity.ended == [t]
    assert _row(dsn, t)[2:5] == ("teardown", "host", None)


def test_an_offboard_mid_step_leaves_a_created_bot_to_be_destroyed_by_its_recorded_name(migrated_database, tmp_path):
    """A's bot creation completes after the offboard committed; its commit misses; offboarding still removes
    that bot and anything else A made, and the integration with it (O4, P1)."""
    dsn, fakes, config = migrated_database, Fakes(tmp_path), _config(tmp_path)
    identity = _Identity()
    t = _request_create(dsn)
    inside, release = _hold_forge(fakes, "POST", USERS)
    a, a_out = _in_thread(_pass, dsn, "service", fakes, config)
    try:
        assert inside.wait(WAIT), f"worker A never reached the bot step: {a_out}"
        _api(dsn, "request_offboard", t, now=NOW)
    finally:
        release.set()
        a.join(WAIT)
    assert len(fakes.forge.users) == 1, "control: A did create the bot"
    _pass(dsn, "service", fakes, config, identity=identity)
    assert (fakes.forge.users, fakes.forge.integrations) == (set(), {})
    assert not (fakes.openbao.oidc_roles or fakes.openbao.approles or fakes.openbao.entities)
    assert set(fakes.forge.repos) <= {f"tenants/{t}"} and all(r["archived"] for r in fakes.forge.repos.values())


def test_the_host_actor_holds_the_same_lock_and_an_offboard_mid_prepare_makes_its_commit_miss(
        migrated_database, tmp_path):
    """The host actor inside prepare holds T's lock (the service skips T); an offboard commits; prepare's commit
    misses and records nothing; teardown then removes what prepare made (O4, P6, Flow 2)."""
    dsn, fakes, config = migrated_database, Fakes(tmp_path), _config(tmp_path)
    identity = _Identity()
    t = _request_create(dsn)
    _settle(dsn, t, fakes, config, lambda row: row[2] == "prepare", identity=identity)
    inside, release = threading.Event(), threading.Event()
    blocking = _BlockingPublish(fakes.publish, inside, release)
    host, host_out = _in_thread(_pass, dsn, "host", fakes, config, publish=blocking)
    try:
        assert inside.wait(WAIT), f"the host never reached the first publish: {host_out}"
        assert len(_advisory_holders(dsn)) == 1, "the host actor holds no lock for its step"
        _api(dsn, "request_offboard", t, now=NOW)
        assert _pass(dsn, "service", fakes, config, identity=identity) == 0
    finally:
        release.set()
        host.join(WAIT)
    assert not host.is_alive()
    assert _row(dsn, t) == ("offboarding", "offboard", "offboard", "service", None), "prepare wrote after the offboard"
    assert (config.data_root / t).is_dir(), "control: prepare did make the folder"
    _settle(dsn, t, fakes, config, lambda row: row[0] == "offboarded", identity=identity)
    assert not (config.data_root / t).exists(), "teardown left what prepare made"
    assert not [p for p in config.secrets_dir.rglob("*") if p.is_file()], "teardown left a secret file"
