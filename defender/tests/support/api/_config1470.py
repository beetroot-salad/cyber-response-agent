"""#1470: the real server composed for the config routes (systems, adapters, case record, credentials) — NO test functions.

`served_config` composes the app as `defender.api_server.serving` does, over a migrated database with tenants A and B
registered with no records (O8) and the identity seeded (`seed_identity`). The API's secret store is either a
`ScriptedOpenBao` handed to `serving(openbao_transport=...)` (the real `OpenBaoSecrets` over a scripted HTTP transport) or
a real OpenBao test server holding the writer policy. Fixtures: `configured` (both, so the stand-in is held to the real
server's answers) and `scripted` (the stand-in alone, for faults a real server cannot be made to give).

`Configured` is the caller's view: Ann (admin of A), Bob (admin of B), the seeded program's key, and one method per route."""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import json
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest
from defender.tests.support.api._openbao1470 import (
    KV_MOUNT,
    WRITER_TOKEN,
    ScriptedOpenBao,
)
from defender.tests.support.api._server1083 import (
    ORIGIN,
    A,
    B,
    FakeKeycloak,
    Seeded,
    environment,
    person,
    program,
    seed_identity,
)
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._openbao1163 import (  # noqa: F401 — the fixture
    Bao,
    openbao,
)
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.support.tenancy import _systems1366 as R

TICKET, ELASTIC = "ticket", "elastic"
TICKET_SETTINGS = dict(R.FIXTURE_FOLDERS[TICKET][0])
TICKET_ACCESS = R.FIXTURE_FOLDERS[TICKET][1]
ELASTIC_SETTINGS = dict(R.FIXTURE_FOLDERS[ELASTIC][0])
ELASTIC_ACCESS = R.FIXTURE_FOLDERS[ELASTIC][1]
TICKET_NAME = "Ticket store (lab)"  # ticket_adapter.DISPLAY_NAME
TOKEN = "a-ticket-token-of-sixteen-or-more"
PASSWORD = "a-password-of-sixteen-or-more"
BODY = "{disposition} — {cause}\n\n{narrative}"
BASE_MOVED = ("http://soc-playground:8004", "http://soc-elsewhere:8004")

#: The routes this piece makes real or keeps refusing, as the app serves them (the tenant segment erased).
CONFIG_ROUTES = frozenset({
    ("GET", "/tenants/{}/adapters"),
    ("GET", "/tenants/{}/systems"), ("GET", "/tenants/{}/systems/{}"),
    ("PUT", "/tenants/{}/systems/{}"), ("DELETE", "/tenants/{}/systems/{}"),
    ("PUT", "/tenants/{}/systems/{}/credentials"), ("POST", "/tenants/{}/systems/{}/check"),
    ("GET", "/tenants/{}/case-record"), ("PUT", "/tenants/{}/case-record"), ("DELETE", "/tenants/{}/case-record"),
})
#: The permission each declares (config.read for reads, config.write for the rest, the check included).
CONFIG_PERMISSION = {route: "config.read" if route[0] == "GET" else "config.write" for route in CONFIG_ROUTES}
#: A body in the new shape for each route that takes one (valid shape; its content need not be accepted).
CONFIG_BODIES: dict[tuple[str, str], dict[str, Any]] = {
    ("PUT", "/tenants/{}/systems/{}"): {"replaces": 0, "enabled": True, "settings": TICKET_SETTINGS,
                                        "access": TICKET_ACCESS},
    ("PUT", "/tenants/{}/systems/{}/credentials"): {"for_version": 1, "credentials": {"api_key": TOKEN}},
    ("PUT", "/tenants/{}/case-record"): {"replaces": 0, "system_id": TICKET, "comment_body": BODY},
}


def config_route(route: tuple[str, str]) -> bool:
    from defender.tests.support.api._routes1307a import normal

    return (route[0], normal(route[1])) in CONFIG_ROUTES


class Configured:
    def __init__(self, client: httpx.AsyncClient, dsn: str, seeded: Seeded, keycloak: FakeKeycloak, app: Any, *,
                 scripted: ScriptedOpenBao | None, real: Bao | None) -> None:
        self.client, self.dsn, self.seeded, self.keycloak, self.app = client, dsn, seeded, keycloak, app
        self.scripted, self.real = scripted, real

    # --- callers ----------------------------------------------------------------------------------

    def ann(self, *, write: bool = True) -> dict[str, str]:
        return person(self.seeded.ann_session, write=write)

    def bob(self, *, write: bool = True) -> dict[str, str]:
        return person(self.seeded.bob_session, write=write)

    def program(self) -> dict[str, str]:
        return program(self.seeded.program_key)

    def user_id(self, email: str) -> str:
        [(found,)] = execute(self.dsn, "SELECT id FROM identity.users WHERE email = %s", (email,))
        return str(found)

    # --- routes (as Ann, admin of A, unless said) -------------------------------------------------

    async def put_system(self, system: str, replaces: int, *, settings: Mapping[str, str] | None = None,
                         access: str | None = None, enabled: bool = True, tenant: str = A) -> httpx.Response:
        body = {"replaces": replaces, "enabled": enabled,
                "settings": TICKET_SETTINGS if settings is None else dict(settings),
                "access": TICKET_ACCESS if access is None else access}
        return await self.put_raw(f"/tenants/{tenant}/systems/{system}", body)

    async def put_raw(self, path: str, body: Any, **kw: Any) -> httpx.Response:
        return await self.client.put(path, headers=kw.pop("headers", None) or self.ann(), json=body, **kw)

    async def get(self, path: str, *, tenant: str = A) -> httpx.Response:
        return await self.client.get(f"/tenants/{tenant}{path}", headers=self.ann(write=False))

    async def get_system(self, system: str) -> httpx.Response:
        return await self.get(f"/systems/{system}")

    async def list_systems(self) -> httpx.Response:
        return await self.get("/systems")

    async def delete_system(self, system: str, replaces: int, *, tenant: str = A) -> httpx.Response:
        return await self.client.delete(f"/tenants/{tenant}/systems/{system}", params={"replaces": replaces},
                                        headers=self.ann())

    async def put_case(self, replaces: int, system_id: str = TICKET, comment_body: str = BODY) -> httpx.Response:
        return await self.put_raw(f"/tenants/{A}/case-record",
                                  {"replaces": replaces, "system_id": system_id, "comment_body": comment_body})

    async def delete_case(self, replaces: int) -> httpx.Response:
        return await self.client.delete(f"/tenants/{A}/case-record", params={"replaces": replaces}, headers=self.ann())

    async def put_credentials(self, system: str, for_version: int, credentials: Mapping[str, str], *,
                              tenant: str = A) -> httpx.Response:
        return await self.put_raw(f"/tenants/{tenant}/systems/{system}/credentials",
                                  {"for_version": for_version, "credentials": dict(credentials)})

    # --- observing what was stored ----------------------------------------------------------------

    def versions(self, system: str, tenant: str = A) -> list[Any]:
        return R.system_versions(self.dsn, tenant, system)

    def stored_set(self, system: str, generation: int, tenant: str = A) -> Any:
        """The set at `<tenant>/<system>/g<N>`, as stored (the real server's is read as root: the API cannot)."""
        path = f"{tenant}/{system}/g{generation}"
        if self.scripted is not None:
            return self.scripted.stored(path)
        assert self.real is not None
        got = self.real.call("GET", f"{self.real.kv_mount}/data/{path}")
        return got.json()["data"]["data"] if got.status_code == 200 else None

    def stored_generations(self, system: str, tenant: str = A) -> list[int]:
        return [g for g in range(1, 7) if self.stored_set(system, g, tenant) is not None]

    def plant_version(  # noqa: PLR0913 — a version row's columns
            self, system: str, version: int, *, adapter: str | None = None, settings: Mapping[str, str] | None = None,
                      access: str | None = None, generation: int = 1, enabled: bool = True, deleted: bool = False,
                      tenant: str = A) -> None:
        """A version row as an earlier release or the catalog's removal of an adapter left it (data the judgement would
        refuse today): written by SQL, since no route writes it."""
        execute(self.dsn, """INSERT INTO tenancy.system_versions (tenant_id, system_id, version, adapter_id, enabled,
                             settings, access, credential_generation, deleted, author, written_at)
                             VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)""",
                (tenant, system, version, adapter or system, enabled,
                 json.dumps(dict(TICKET_SETTINGS if settings is None else settings)),
                 TICKET_ACCESS if access is None else access, generation, deleted, "planted",
                 dt.datetime.now(dt.UTC)))


@contextlib.asynccontextmanager
async def served_config(dsn: str, tmp_path: Path, *, scripted: ScriptedOpenBao | None = None, real: Bao | None = None,
                        register: bool = True, keep_calls: bool = False) -> AsyncIterator[Configured]:
    """The real server over `dsn`. `scripted` or `real` is the API's secret store; a `real` one is given the writer
    policy on its own KV mount. The scripted store's calls are cleared once the program has started (`keep_calls` keeps
    the start's own). Tenants A and B are registered with no records unless `register` is False."""
    from defender.api_server import Settings, serving
    from defender.credential_proxy._openbao import store_policies

    if register:
        register_tenant(dsn, A, records=None)
        register_tenant(dsn, B, records=None)
    seeded = await seed_identity(dsn)
    if real is not None:
        writer = real.token_for(real.apply_policy("api-writer", store_policies(kv_mount=real.kv_mount)["writer"]))
        environ = environment(tmp_path, dsn=dsn, openbao=real.addr, kv_mount=real.kv_mount, token=writer)
    else:
        environ = environment(tmp_path, dsn=dsn, kv_mount=KV_MOUNT, token=WRITER_TOKEN)
    keycloak = FakeKeycloak()
    async with serving(Settings.from_environ(environ), transport=keycloak,
                       openbao_transport=scripted if real is None else None) as running, \
            httpx.AsyncClient(transport=httpx.ASGITransport(app=running.app), base_url=ORIGIN) as client:
        if scripted is not None and not keep_calls:
            scripted.calls.clear()
        yield Configured(client, dsn, seeded, keycloak, running.app, scripted=scripted, real=real)
    assert keycloak.unmodelled == []


@pytest.fixture
async def scripted(migrated_database: str, tmp_path: Path) -> AsyncIterator[Configured]:
    async with served_config(migrated_database, tmp_path, scripted=ScriptedOpenBao()) as configured:
        yield configured


@pytest.fixture(params=["scripted", pytest.param("real", marks=pytest.mark.openbao)])
async def configured(request: pytest.FixtureRequest, migrated_database: str, tmp_path: Path) -> AsyncIterator[Configured]:
    """Over the scripted stand-in and over a real OpenBao server: a case that holds on both."""
    if request.param == "scripted":
        async with served_config(migrated_database, tmp_path, scripted=ScriptedOpenBao()) as configured:
            yield configured
    else:
        async with served_config(migrated_database, tmp_path, real=request.getfixturevalue("openbao")) as configured:
            yield configured


def edited_cursor(cursor: str, **changes: Any) -> str:
    """`cursor` with fields of its JSON changed, re-encoded as the API encodes one (an edited cursor is the caller's)."""
    body = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    return base64.urlsafe_b64encode(json.dumps({**body, **changes}).encode()).decode().rstrip("=")


def problem_text(problem: httpx.Response) -> str:
    """Everything a refusal body says in words: its detail and each listed fault or error."""
    body = problem.json()
    return " ".join([str(body.get("detail") or ""), *(str(f) for f in body.get("faults") or []),
                     *(str(e) for e in body.get("errors") or [])])


def audit_events(caplog: pytest.LogCaptureFixture, *actions: str) -> list[Any]:
    return [r for r in caplog.records if getattr(r, "action", None) in actions]


def told(record: Any) -> str:
    """An audit event's words: its message and its detail."""
    return f"{record.getMessage()} {getattr(record, 'detail', None) or ''}"



def served_config_routes(app: Any) -> set[tuple[str, str]]:
    """(METHOD, template with its parameters erased) of every config route the app serves, from the app's own table."""
    from defender.tests.support.api._routes1307a import _served, normal

    found = {(method, normal(route.path)) for route in _served(app.routes) for method in route.methods
             if method not in {"HEAD", "OPTIONS"}}
    return {r for r in found if r in CONFIG_ROUTES or any(w in r[1] for w in ("/systems", "/adapters", "/case-record"))}


async def config_call(served: Configured, route: tuple[str, str], headers: Mapping[str, str], *, tenant: str = A,
                       **kw: Any) -> httpx.Response:
    """`route` (a CONFIG_ROUTES row) at `tenant`, system `ticket`, with its new-shape body unless `kw` gives content."""
    path = route[1].replace("{}", tenant, 1).replace("{}", TICKET, 1)
    if route in CONFIG_BODIES and not kw:
        kw = {"json": CONFIG_BODIES[route]}
    if route[0] == "DELETE":
        kw.setdefault("params", {"replaces": 1})
    return await served.client.request(route[0], path, headers=headers, **kw)
