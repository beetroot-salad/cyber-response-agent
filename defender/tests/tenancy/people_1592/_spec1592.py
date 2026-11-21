"""#1592 shared machinery (r15), NO test functions: the people requests read at two boundaries, a baseline helper, the
Forgejo admin fake with per-call failure injection, the Forgejo sessions database, a settable clock, and the worker's
seams. The interface is listed in `.contract-first/1592-contract-map.md`, "Machinery".

Production names the design gives are imported lazily here and nowhere else in this package, so a module collects and
each case fails on the missing symbol (expected red). Names the design leaves open are forced choices, each marked FC
and listed as a gap in the map:
- r15.1: the sessions port is `defender.lifecycle.PostgresForgeSessions(dsn, *, statement_timeout)`; its twin `defender.lifecycle.InMemoryForgeSessions()`
  with `insert(key, data, *, signed_in_at)` and `keys()` for seeding and reading.
- FC-W: `PeopleWorker` takes `identity`, `forge`, `sessions`, `config`, `clock` by keyword (the `ManagementService`
  convention); `forge` is an `httpx.AsyncClient`, `clock` a `Callable[[], datetime]`.
- FC-L: `people_lock()` is async and answers a bool; `PEOPLE_LOCK_NAMESPACE` lives beside `LOCK_NAMESPACE` in
  `defender.tenancy.repository`.
"""
from __future__ import annotations

import asyncio
import collections
import contextlib
import datetime as _dt
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any, NamedTuple

import httpx

from defender.tests.tenancy.lifecycle_1214._fakes import ADMIN_TOKEN, FORGE_URL, FakeForge
from defender.tests.tenancy.people_1592._gob1592 import ANONYMOUS_P31, signed_in_data  # noqa: F401 — re-exported

KEYCLOAK_SOURCE_ID = 7
#: The team every tenant's people are in.
MEMBERS = "members"
#: The sketch's name for P31's anonymous (OAuth-start) row.
ANONYMOUS_DATA = ANONYMOUS_P31


def login_of(user_id: Any) -> str:
    return f"p-{user_id}"


def org_of(tenant_id: Any) -> str:
    return f"t-{tenant_id}"


def repo_of(tenant_id: Any) -> str:
    return f"t-{tenant_id}/knowledge"


# --- people requests -------------------------------------------------------------------------------

class Req(NamedTuple):
    """One open people request, as text: `user` and `tenant` are canonical ids or None."""

    id: str
    user: str | None
    tenant: str | None
    requested_at: _dt.datetime


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def requests_sql(dsn: str) -> list[Req]:
    """The open requests by SQL on the design's table: the independent boundary for the trigger tests."""
    from defender.tests.support.shared._postgres1339 import execute

    rows = execute(dsn, "SELECT id::text, user_id::text, tenant_id::text, requested_at FROM tenancy.forge_people_requests")
    return [Req(i, u, t, at) for i, u, t, at in rows]


async def requests_port(tenants: Any) -> list[Req]:
    """The open requests through the tenancy port's `open_people_requests()` (either twin)."""
    rows = await tenants.open_people_requests()
    return [Req(str(r.id), _text(r.user_id), _text(r.tenant_id), r.requested_at) for r in rows]


def pairs(rows: list[Req]) -> collections.Counter[tuple[str | None, str | None]]:
    """`(user, tenant)` as a multiset: requests in one transaction share `now()`, so no order is asserted."""
    return collections.Counter((r.user, r.tenant) for r in rows)


class RequestLog:
    """Requests recorded after a baseline, by id (seeding records on both backends, so a case marks the end of its
    setup). `read` is `lambda: requests_port(tenants)` or an async wrapper of `requests_sql(dsn)`."""

    def __init__(self, read: Callable[[], Awaitable[list[Req]]]) -> None:
        self._read = read
        self._seen: set[str] = set()

    async def mark(self) -> None:
        self._seen = {r.id for r in await self._read()}

    async def new(self) -> list[Req]:
        return [r for r in await self._read() if r.id not in self._seen]

    async def since(self) -> collections.Counter[tuple[str | None, str | None]]:
        return pairs(await self.new())


def sql_reader(dsn: str) -> Callable[[], Awaitable[list[Req]]]:
    async def read() -> list[Req]:
        return requests_sql(dsn)

    return read


# --- Forgejo ---------------------------------------------------------------------------------------

class Fault(NamedTuple):
    status: int | None
    error: type[httpx.TransportError] | None
    times: int | None


class PeopleForge(FakeForge):
    """#1214's Forgejo fake plus what the request worker and `resync-people` call (P20, P33, P35):
    - person accounts: `POST /admin/users` records the body and gives an `id`; 422 if the login is held;
      `GET /users/{login}` answers `id`, `login`, `login_name`, `source_id`, `prohibit_login`, or 404;
      `PATCH /admin/users/{login}` takes `prohibit_login` (#1214's arm), every body recorded in `calls`;
      `GET /admin/users?source_id=N`: the accounts on that source, paged with `X-Total-Count` (P33);
    - `GET /orgs/{org}/teams/search` 404s for a missing organisation, and matches substrings (#1214's arm, P35);
    - team membership: `PUT`/`DELETE /teams/{id}/members/{login}` (204; DELETE of a non-member 404, PUT of an unknown
      login 404); `GET /teams/{id}/members` as #1214's fake;
    - faults: `fail("METHOD /api/v1/...", status=500 | error=httpx.ConnectError, times=None)` answers (or raises) for
      every matching call until `times` run out (None: always); `clear_faults()`;
    - `gate(method, path)`: an asyncio event the next such call waits on before answering (a run in flight);
    - `arrived`: every call as `METHOD path`, on arrival, before any gate or fault.
    It decides no lifecycle policy."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.accounts: dict[str, dict[str, Any]] = {}
        self.gates: dict[tuple[str, str], asyncio.Event] = {}
        self.faults: dict[str, Fault] = {}
        self.arrived: list[str] = []
        self._next_uid = 2

    # seeders ------------------------------------------------------------------------------------
    def add_account(self, login: str, *, login_name: str = "", prohibit_login: bool = False,
                    source_id: int | None = KEYCLOAK_SOURCE_ID, uid: int | None = None) -> int:
        """A person account as the lifecycle (or an administrator) left it; its Forgejo id."""
        number = self._next_uid if uid is None else uid
        self._next_uid = max(self._next_uid, number) + 1
        self.users.add(login)
        self.must_change_password[login] = False
        self.accounts[login] = {"id": number, "login": login, "login_name": login_name, "source_id": source_id,
                                "restricted": True}
        if prohibit_login:
            self.prohibit_login.add(login)
        return number

    def add_team(self, tenant_id: str, *members: str, name: str = MEMBERS) -> None:
        """Organisation `t-<T>` with team `name` holding `members`."""
        self.orgs.setdefault(org_of(tenant_id), set()).add(name)
        self.team_members[(org_of(tenant_id), name)] = set(members)

    def members(self, tenant_id: str) -> set[str]:
        return set(self.team_members.get((org_of(tenant_id), MEMBERS), set()))

    def uid(self, login: str) -> int:
        return int(self.accounts[login]["id"])

    def gate(self, method: str, path: str) -> asyncio.Event:
        event = asyncio.Event()
        self.gates[(method, path)] = event
        return event

    def fail(self, signature: str, *, status: int | None = 500, error: type[httpx.TransportError] | None = None,
             times: int | None = None) -> None:
        self.faults[signature] = Fault(None if error else status, error, times)

    def clear_faults(self) -> None:
        self.faults.clear()

    def writes(self) -> list[str]:
        """Every non-GET call answered, as `METHOD path`, in order."""
        return [f"{c.method} {c.path}" for c in self.calls if c.method != "GET"]

    def signatures(self) -> list[str]:
        """The distinct calls that arrived, in first-arrival order (a clean run's census for fault injection)."""
        return list(dict.fromkeys(self.arrived))

    # transport ----------------------------------------------------------------------------------
    def client(self, token: str | None = ADMIN_TOKEN) -> httpx.AsyncClient:
        headers = {} if token is None else {"Authorization": f"token {token}"}
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle_async), base_url=FORGE_URL, headers=headers)

    async def handle_async(self, request: httpx.Request) -> httpx.Response:
        signature = f"{request.method} {request.url.path}"
        self.arrived.append(signature)
        gate = self.gates.pop((request.method, request.url.path), None)  # one-shot
        if gate is not None:
            await gate.wait()
        fault = self.faults.get(signature)
        if fault is not None:
            if fault.times is not None:
                self.faults[signature] = fault._replace(times=fault.times - 1)
                if fault.times <= 1:
                    del self.faults[signature]
            self._record(request)
            if fault.error is not None:
                raise fault.error(f"injected {fault.error.__name__}", request=request)
            return httpx.Response(fault.status or 500, json={"message": f"injected {fault.status}"})
        return self.handle(request)

    def _account(self, login: str) -> dict[str, Any]:
        return dict(self.accounts[login], prohibit_login=login in self.prohibit_login)

    def handle(self, request: httpx.Request) -> httpx.Response:  # noqa: C901, PLR0911 — one arm per endpoint
        parts = request.url.path.removeprefix("/api/v1/").split("/")
        method = request.method
        match (method, parts):
            case ("GET", ["users", login]):
                _call, injected = self._record(request)
                if injected is not None:
                    return injected
                return httpx.Response(200, json=self._account(login)) if login in self.accounts \
                    else httpx.Response(404, json={"message": "user does not exist"})
            case ("GET", ["admin", "users"]):
                call, injected = self._record(request)
                if injected is not None:
                    return injected
                source = call.query.get("source_id", [None])[0]
                listed = [self._account(login) for login in sorted(self.accounts)
                          if source is None or str(self.accounts[login]["source_id"]) == source]
                return self._paged(call, listed)
            case ("POST", ["admin", "users"]):
                call, injected = self._record(request)
                if injected is not None:
                    return injected
                body = call.body or {}
                login = body["username"]
                if login in self.users:
                    return httpx.Response(422, json={"message": "user already exists"})
                self.add_account(login, login_name=str(body.get("login_name", "")), source_id=body.get("source_id"))
                self.accounts[login].update(restricted=bool(body.get("restricted")), email=body.get("email"),
                                            full_name=body.get("full_name"))
                return httpx.Response(201, json=self._account(login))
            case ("GET", ["orgs", org]):
                self._record(request)
                return httpx.Response(200, json={"username": org}) if org in self.orgs \
                    else httpx.Response(404, json={"message": "organization does not exist"})
            case ("GET", ["orgs", org, "teams", "search"]) if org not in self.orgs:
                self._record(request)
                return httpx.Response(404, json={"message": "organization does not exist"})
            case ("PUT" | "DELETE", ["teams", team_id, "members", login]):
                _call, injected = self._record(request)
                if injected is not None:
                    return injected
                named = next((k for k, v in self._team_ids.items() if str(v) == team_id), None)
                if named is None:
                    return httpx.Response(404, json={"message": "team does not exist"})
                members = self.team_members.setdefault(named, set())
                if method == "PUT":
                    if login not in self.users:
                        return httpx.Response(404, json={"message": "user does not exist"})
                    members.add(login)
                    return httpx.Response(204)
                if login not in members:
                    return httpx.Response(404, json={"message": "not a member"})
                members.discard(login)
                return httpx.Response(204)
        return super().handle(request)


# --- the Forgejo sessions database -----------------------------------------------------------------

#: The design's setup script, minus roles and grants (the test login is the server's superuser): Forgejo's table with
#: `signed_in_at`, the re-key trigger that alone stamps it, and its index. The shipped script's path is not given
#: (gap); S2's script row asserts the shipped script makes this same table and trigger.
SESSIONS_SCHEMA = """
CREATE TABLE session (key CHAR(16) PRIMARY KEY, data BYTEA, expiry INTEGER NOT NULL, signed_in_at timestamptz NULL);
CREATE FUNCTION stamp_sign_in() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.signed_in_at := now(); RETURN NEW; END $$;
CREATE TRIGGER stamp_sign_in BEFORE UPDATE OF key ON session FOR EACH ROW EXECUTE FUNCTION stamp_sign_in();
CREATE INDEX session_signed_in_at ON session (signed_in_at);
"""


def session_key(name: str) -> str:
    """A 16-character session key (Forgejo's cookie value) from a short name."""
    return name.ljust(16, "0")[:16]


class Sessions:
    """The sessions database of one case, planted and read by SQL as the test server's superuser."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    def plant(self, key: str, data: bytes, *, signed_in_at: _dt.datetime | None) -> None:
        from defender.tests.support.shared._postgres1339 import execute

        execute(self.dsn, "INSERT INTO session (key, data, expiry, signed_in_at) VALUES (%s, %s, %s, %s)",
                (session_key(key), data, 2_000_000_000, signed_in_at))

    def rekey(self, old: str, new: str) -> None:
        """A sign-in's re-key, as Forgejo does it (P31): the trigger stamps `signed_in_at`."""
        from defender.tests.support.shared._postgres1339 import execute

        execute(self.dsn, "UPDATE session SET key = %s WHERE key = %s", (session_key(new), session_key(old)))

    def keys(self) -> set[str]:
        from defender.tests.support.shared._postgres1339 import execute

        return {k.strip() for (k,) in execute(self.dsn, "SELECT key FROM session")}

    def clear(self) -> None:
        from defender.tests.support.shared._postgres1339 import execute

        execute(self.dsn, "DELETE FROM session")


@contextlib.contextmanager
def sessions_database() -> Iterator[Sessions]:
    from defender.tests.support.shared._postgres1339 import database, execute

    with database(migrated=False) as dsn:
        execute(dsn, SESSIONS_SCHEMA)
        yield Sessions(dsn)


#: A DSN nothing listens on: a real connection-refused fault for the sessions port (cache: closed local port).
UNREACHABLE_DSN = "postgresql://nobody:nothing@127.0.0.1:9/forgejo_sessions"


def sessions_port(dsn: str, *, statement_timeout: float = 5.0) -> Any:
    """The product's sessions port over `dsn` (r15.1)."""
    from defender.lifecycle import PostgresForgeSessions

    return PostgresForgeSessions(dsn, statement_timeout=statement_timeout)


def sessions_twin() -> Any:
    """The sessions port's memory twin (FC-S)."""
    from defender.lifecycle import InMemoryForgeSessions

    return InMemoryForgeSessions()


# --- the clock, the config and the worker ----------------------------------------------------------

class Clock:
    """A settable clock for the worker (`clock=`): `advance` moves it; it never moves by itself."""

    def __init__(self, now: _dt.datetime | None = None) -> None:
        self.now = now or _dt.datetime.now(_dt.UTC)

    def __call__(self) -> _dt.datetime:
        return self.now

    def advance(self, by: _dt.timedelta) -> None:
        self.now += by


def people_config(tmp_path: Path, data_root: Path, *, sessions_dsn: str, **overrides: Any) -> Any:
    """`LifecycleConfig` with the design's Settings: the two required fields, and a short poll."""
    from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config

    fields = {"keycloak_source_id": KEYCLOAK_SOURCE_ID, "forge_sessions_dsn": sessions_dsn, "people_poll": 0.01,
              "people_concurrency": 4}
    return lifecycle_config(tmp_path, data_root, **{**fields, **overrides})


def people_worker(tenants: Any, *, identity: Any, forge: PeopleForge, sessions: Any, config: Any,
                  clock: Callable[[], _dt.datetime]) -> Any:
    """`PeopleWorker(tenants, identity, forge, sessions, config, clock)` (FC-W)."""
    from defender.lifecycle import PeopleWorker

    return PeopleWorker(tenants, identity=identity, forge=forge.client(), sessions=sessions, config=config, clock=clock)


# --- the worker's lock on PostgreSQL ---------------------------------------------------------------

def people_lock_namespace() -> int:
    from defender.tenancy.repository import PEOPLE_LOCK_NAMESPACE  # FC-L

    return int(PEOPLE_LOCK_NAMESPACE)


def people_lock_holders(dsn: str) -> list[int]:
    """The backend pids holding `(PEOPLE_LOCK_NAMESPACE, 0)`, as `pg_locks` shows a two-key advisory lock."""
    from defender.tests.support.shared._postgres1339 import execute

    rows = execute(dsn, """SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted
                           AND classid = %s AND objid = 0 AND objsubid = 2""", (people_lock_namespace(),))
    return [pid for (pid,) in rows]


def end_backend(dsn: str, pid: int) -> None:
    """A crashed holder: its connection ends, and the server frees its lock."""
    from defender.tests.support.shared._postgres1339 import execute

    execute(dsn, "SELECT pg_terminate_backend(%s)", (pid,))


@contextlib.contextmanager
def people_lock_held_elsewhere(dsn: str) -> Iterator[None]:
    """Another process holds the worker's lock for the block (a plain session-level advisory lock)."""
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        assert conn.execute("SELECT pg_try_advisory_lock(%s, 0)", (people_lock_namespace(),)).fetchone() == (True,)
        yield
