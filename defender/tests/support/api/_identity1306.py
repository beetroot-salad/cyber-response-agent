"""#1306 test world: the API over an in-memory identity repository, a fake sign-in port, a fake
mail port and one injected clock — NO test functions. The fakes record calls and inject answers
(failures, a hook that runs inside a send); they never implement policy.

#1339 (D11): the service, the repository and the two ports are async. `World` keeps the sync
`TestClient` for requests and runs every service/repository call on ONE event loop, the loop its
clients' requests run on: `world.call(async_fn, *args)` is the bridge. Hooks are coroutines
awaited on that loop; a hook that needs HTTP runs the sync client through `asyncio.to_thread`, never on the loop.

#1214 r9 (DC-6, DC-7): the world is built the Q3 way. ONE `InMemoryTenantRepository` (`world.tenants`) is
shared with `InMemoryIdentityRepository(tenants=...)` and handed to `ApiDeps(tenants=...)`; every tenant
named in `World(tenants={T: [emails]})` is seeded `active` through the twin's `add_tenant` seeder (never a
`register_tenant`, which no port has). `Bootstrap(administrators=...)` only.
First members (the `[emails]`) are seeded, NOT invited through an administrator: when the world is built,
and on `restart(tenants=...)` for a tenant that never had a membership, each email gets its user, an
invitation `invited_by=None` and the same set-password / notification request the old bootstrap made,
all through the raw identity repository's existing seeders (so `failing_writes` never touches seeding).
So every old observable (sends, first sign-in accepting the invitation, audit lines) is unchanged; the
administrator invite path is `World.member(admin_browser, tenant, email)` (a world with an administrator
that wants the r9 route uses it). Seeding is idempotent. #1454 (P-L): an invitation is only ever written into an `active` tenant, so a case that
needs an open invitation in a tenant that is not active seeds it while the tenant is active and then calls
`world.move_tenant(T, state)`.

Interface: `World(administrators=, tenants=, start=, failing_sends=, send_interval=, send_deadline=,
failing_writes=, tenant_repo=None, alert_mapping=PLANTED_ALERT_MAPPING, database=False)`; `world.tenants` (the twin), `world.repo` (identity repository,
failure-wrapped if `failing_writes`), `world.raw_repo` (never wrapped); `world.register(T, *, state="active")`;
`world.seed_first_members(T, emails)`; `world.restart(administrators=, tenants=)`.

#1496: the store ports are composed by the real server's own wiring (`api_server.api_deps`), never by a second
implementation. `database=True` puts the whole world on a fresh migrated test database (skipped without
`DEFENDER_TEST_POSTGRES_DSN`): people in `PostgresIdentityRepository`, tenants in `PostgresTenantRepository`, and the
alerts, investigations, learning jobs, alert mapping, writes and offboarding in one `JobStorePorts` over a `JobStore`;
`world.add_alert(T)` stores an alert through the store and answers its id. Without a database, and for the families
the real server leaves unbacked (the check, artifact links, the audit-only port, lessons) in either world, every store
port is `Refusing`: a route reaching one answers 501 after sign-in and membership passed. The tenant's records and
credentials (systems, the case record, credentials) refuse too in either world (`NO_RECORDS`): the real server backs
them with its record store and OpenBao, which the config tests reach through `serving` (#1470)."""
from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as _dt
import hashlib
import itertools
import inspect
import logging
import threading
import time
import weakref
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any
from urllib.parse import parse_qs, urlsplit

import anyio
import anyio.from_thread
from fastapi.testclient import TestClient

from defender.api.app import create_app
from defender.api.refusing import Refusing
from defender.api.models import Alert, AlertSummary
from defender.api.ports import ApiDeps

# Production names #1306 must supply. Kept in this one block so a missing package is one ImportError.
from defender.identity import (  # noqa: F401  (re-exported for the cases)
    Bootstrap,
    BootstrapRefused,
    IdentityService,
    InMemoryIdentityRepository,
    SignInRefused,
    SignInUnavailable,
    VerifiedSignIn,
)
from defender.tenancy import InMemoryTenantRepository
from defender.tests.support.tenancy._mapping1345 import PLANTED_ALERT_MAPPING, add_to_twin, mapping_value
from defender.tests.support.shared import _worlds
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy._active1214 import offboard_on_database
from defender.tests.support.tenancy._twin1496 import offboard_twin
from defender.tests.support.tenancy._twin1496 import seed_tenant

T0 = _dt.datetime(2026, 10, 26, 9, 0, tzinfo=_dt.UTC)
HOUR = _dt.timedelta(hours=1)
DAY = _dt.timedelta(days=1)
SEVEN_DAYS = _dt.timedelta(days=7)
SECOND = _dt.timedelta(seconds=1)
#: The configured frontend origin (O6): state-changing requests must carry it.
FRONTEND_ORIGIN = "https://app.defender.test"
#: DC-6. Both are HttpOnly, Secure, SameSite=Lax, Path=/, no Domain.
SESSION_COOKIE = "__Host-defender_session"
#: Secure cookies only round-trip over https; TestClient defaults to http.
BASE_URL = "https://testserver"
SIGNIN_URL = "https://signin.test/realms/defender/auth"
#: `sign_in_response(state=NO_STATE)` sends a callback without a `state` parameter.
NO_STATE = "<no state parameter>"
AUDIT_LOGGER = "defender.identity.audit"

T1 = fixture_uuid("tenant:1306-t1")
T2 = fixture_uuid("tenant:1306-t2")
LAB = fixture_uuid("tenant:1306-lab")
EMPTY = fixture_uuid("tenant:1306-empty")
UNKNOWN = fixture_uuid("tenant:1306-never-registered")
NO_SUCH_ID = "00000000-0000-4000-8000-000000000000"
ANN, BOB, NEW, NINA = "ann@a.example", "bob@b.example", "new@n.example", "nina@n.example"
OPS, ME = "ops@x.example", "me@x.example"

ALERT = Alert(
    alert_id="a1000000-0000-4000-8000-000000000001", vendor="tickets", vendor_ticket_id="T-1", title="t", description="d",
    fired_at=T0, changed_at=T0, received_at=T0, raw='{"id": "a1000000-0000-4000-8000-000000000001"}',
)
SUMMARY = AlertSummary.model_validate(ALERT.model_dump(exclude={"raw"}))


class Clock:
    """The one clock the data store, the identity service and every test read."""

    def __init__(self, now: _dt.datetime = T0) -> None:
        self.now = now

    def __call__(self) -> _dt.datetime:
        return self.now

    def advance(self, by: _dt.timedelta) -> None:
        self.now += by


class InjectedFailure(Exception):
    """What the mail fake raises when a test scripted a failure (any exception fails one send)."""


class FailingRepository:
    """The in-memory identity repository with scripted write failures: every method named in
    `failing` raises `InjectedFailure` instead of running; everything else is delegated.
    `after` maps a method name to a hook (a coroutine function, no arguments) awaited once right
    after that method returns, and `before` the same right before the method runs (interleaving points: the
    hook is the test's own action, e.g. a sign-in or `World.move_tenant`; it decides nothing, and the method
    then runs against what the hook did). #1454: a tenant that is not active is made so for real
    (`World.move_tenant`), never scripted here: the tenant's state is the rule and the repository reads it.
    Every delegated method is a coroutine function and the inner
    method is awaited strictly: a repository whose method is not async fails loudly."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.failing: set[str] = set()
        #: method name -> how many calls were refused (the sender may be the caller).
        self.refusals: dict[str, int] = {}
        self.after: dict[str, Callable[[], Awaitable[None]]] = {}
        self.before: dict[str, Callable[[], Awaitable[None]]] = {}

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        attribute = getattr(self._inner, name)
        if not callable(attribute):
            return attribute

        async def call(*args: Any, **kwargs: Any) -> Any:
            # Decided at CALL time, so a caller that kept the bound method still sees later changes.
            if name in self.failing:
                self.refusals[name] = self.refusals.get(name, 0) + 1
                raise InjectedFailure(f"{name} failed")
            first = self.before.pop(name, None)
            if first is not None:
                await first()
            result = await attribute(*args, **kwargs)
            hook = self.after.pop(name, None)
            if hook is not None:
                await hook()
            return result

        return call


@dataclasses.dataclass(frozen=True)
class Account:
    username: str
    email: str
    required_actions: frozenset[str]
    account_id: str


@dataclasses.dataclass(frozen=True)
class SignInStart:
    state: str
    nonce: str
    code_challenge: str


@dataclasses.dataclass(frozen=True)
class SignInFinish:
    code: str
    code_verifier: str
    nonce: str


class FakeSignIn:
    """The sign-in port (Keycloak) as a recorder. `create_account` finds by username, as the port
    promises. Token verification (signature, issuer, audience, nonce) is the real adapter's job."""

    def __init__(self) -> None:
        self._ids = itertools.count(1)
        self.accounts: dict[str, Account] = {}
        self.create_calls: list[str] = []
        self.set_password_sent: list[tuple[str, _dt.timedelta]] = []
        self.otp_required: list[str] = []
        self.started: list[SignInStart] = []
        self.finished: list[SignInFinish] = []
        #: account id -> answer to `has_otp`.
        self.has_otp_answers: dict[str, bool] = {}
        #: code -> what the callback's token verification returns.
        self.answers: dict[str, VerifiedSignIn] = {}
        #: The next N token verifications fail (`finish_signin` records the call, then raises `SignInRefused`).
        self.refuse_signins = 0
        #: The next N `finish_signin` calls record the call, then raise `SignInUnavailable`.
        self.unavailable_signins = 0
        #: The next N `begin_signin` calls record the call, then raise `SignInUnavailable` (the provider is unreachable).
        self.unavailable_begins = 0
        #: When set, every `has_otp` call records the call, then raises this exception.
        self.raise_on_has_otp: Exception | None = None
        #: The name of every port method called, in order (all of them, round trips included).
        self.every_call: list[str] = []
        #: The account id of every set-password send attempted, failed ones included.
        self.send_attempts: list[str] = []
        #: Scripted failures, all `SignInUnavailable`: the next N set-password sends raise; every
        #: send to an email in `fail_sends_to` raises until the test removes it; the next N
        #: creations record the account and then raise (a crash before the caller recorded the id).
        self.fail_sends = 0
        self.fail_sends_to: set[str] = set()
        self.crash_after_create = 0
        #: Runs once inside the next set-password send, after it is recorded.
        self.during_send: Callable[[], Awaitable[None]] | None = None
        #: email -> the exception (any type) every send to that account raises until removed.
        self.raise_on_send_to: dict[str, Exception] = {}
        #: email -> the exception (any type) every `create_account` for that email raises until removed.
        self.raise_on_create_to: dict[str, Exception] = {}
        #: How many times `close` ran (kept out of `every_call`, which records port round trips).
        self.closes = 0
        #: Methods run on the app's loop, the test's views on its thread; views read snapshots taken
        #: under this lock. A thread lock is bound to no loop, and nothing is awaited while held.
        self._lock = threading.RLock()

    # --- the port ---------------------------------------------------------------------
    async def close(self) -> None:
        with self._lock:
            self.closes += 1

    async def create_account(self, username: str, email: str, required_actions: frozenset[str]) -> str:
        with self._lock:
            self.every_call.append("create_account")
            self.create_calls.append(username)
            if email in self.raise_on_create_to:
                raise self.raise_on_create_to[email]
            if username not in self.accounts:
                self.accounts[username] = Account(
                    username, email, frozenset(required_actions), f"kc-{next(self._ids):04d}")
                if self.crash_after_create:
                    self.crash_after_create -= 1
                    raise SignInUnavailable("crash after the account was created")
            return self.accounts[username].account_id

    async def send_set_password_email(self, account_id: str, lifespan: _dt.timedelta) -> None:
        with self._lock:
            self.every_call.append("send_set_password_email")
            self.send_attempts.append(account_id)
            if self.fail_sends:
                self.fail_sends -= 1
                raise SignInUnavailable("the set-password send failed")
            for a in list(self.accounts.values()):
                if a.account_id == account_id and a.email in self.raise_on_send_to:
                    raise self.raise_on_send_to[a.email]
                if a.account_id == account_id and a.email in self.fail_sends_to:
                    raise SignInUnavailable("the set-password send to this account failed")
            self.set_password_sent.append((account_id, lifespan))
            hook, self.during_send = self.during_send, None
        if hook:
            await hook()

    async def has_otp(self, account_id: str) -> bool:
        with self._lock:
            self.every_call.append("has_otp")
        if self.raise_on_has_otp is not None:
            raise self.raise_on_has_otp
        return self.has_otp_answers.get(account_id, False)

    async def require_otp_setup(self, account_id: str) -> None:
        with self._lock:
            self.every_call.append("require_otp_setup")
        self.otp_required.append(account_id)

    async def begin_signin(self, state: str, nonce: str, code_challenge: str) -> str:
        with self._lock:
            self.every_call.append("begin_signin")
        if self.unavailable_begins:
            self.unavailable_begins -= 1
            raise SignInUnavailable("the sign-in provider is unavailable")
        self.started.append(SignInStart(state, nonce, code_challenge))
        return f"{SIGNIN_URL}?state={state}"

    async def finish_signin(self, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn:
        with self._lock:
            self.every_call.append("finish_signin")
        self.finished.append(SignInFinish(code, code_verifier, nonce))
        if self.refuse_signins:
            self.refuse_signins -= 1
            raise SignInRefused("the ID token failed verification")
        if self.unavailable_signins:
            self.unavailable_signins -= 1
            raise SignInUnavailable("the sign-in provider is unavailable")
        return self.answers[code]

    # --- test-side views --------------------------------------------------------------
    def calls(self) -> int:
        """Every account-side call so far (sign-in round trips excluded)."""
        with self._lock:
            return len(self.create_calls) + len(self.set_password_sent) + len(self.otp_required)

    def account_for(self, email: str) -> str:
        """The one Keycloak account for `email` (a retried create finds it, never adds one)."""
        return self.account_of(email).account_id

    def account_of(self, email: str) -> Account:
        [account] = [a for a in list(self.accounts.values()) if a.email == email]
        return account

    def sends_to(self, email: str) -> int:
        with self._lock:
            ids = {a.account_id for a in list(self.accounts.values()) if a.email == email}
            return sum(1 for a, _ in list(self.set_password_sent) if a in ids)

    def attempts_to(self, email: str) -> int:
        """Set-password sends attempted to `email`'s account, failed ones included."""
        with self._lock:
            ids = {a.account_id for a in list(self.accounts.values()) if a.email == email}
            return sum(1 for a in list(self.send_attempts) if a in ids)


@dataclasses.dataclass(frozen=True)
class Notice:
    to: str
    tenant_id: str
    invitation_id: str


class FakeMail:
    """Our own mail port as a recorder."""

    def __init__(self) -> None:
        self.sent: list[Notice] = []
        #: The recipient of every notification attempted, failed ones included.
        self.attempts: list[str] = []
        self._lock = threading.RLock()
        self.fail_notices = 0
        #: Every notification to a recipient in this set raises until the test removes it.
        self.fail_notices_to: set[str] = set()
        #: Runs once inside the next notification, after it is recorded.
        self.during_notice: Callable[[], Awaitable[None]] | None = None

    async def notify_invitation(self, to: str, tenant_id: str, invitation_id: str) -> None:
        with self._lock:
            self.attempts.append(to)
            if self.fail_notices:
                self.fail_notices -= 1
                raise InjectedFailure("the notification failed")
            if to in list(self.fail_notices_to):
                raise InjectedFailure("the notification to this recipient failed")
            self.sent.append(Notice(to, str(tenant_id), str(invitation_id)))
            hook, self.during_notice = self.during_notice, None
        if hook:
            await hook()


def pkce_challenge(verifier: str) -> str:
    """RFC 7636 S256."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --- response helpers ----------------------------------------------------------------------

def me(browser: Any) -> dict[str, Any]:
    response = browser.get("/api/me")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def tenants_of(browser: Any) -> set[str]:
    return {t["tenant_id"] for t in me(browser)["tenants"]}


def user_id(browser: Any) -> str:
    return str(me(browser)["user"]["id"])


def items(response: Any) -> list[dict[str, Any]]:
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["next_cursor"] is None
    rows: list[dict[str, Any]] = body["items"]
    return rows


def problem_type(response: Any) -> str:
    return str(response.json()["type"])


def invitation_rows(browser: Any, tenant: str) -> list[dict[str, Any]]:
    return items(browser.get(f"/api/tenants/{tenant}/invitations"))


def invitation_id(browser: Any, tenant: str, email: str) -> str:
    [row] = [r for r in invitation_rows(browser, tenant) if r["email"] == email]
    return str(row["id"])


def masked(response: Any, *ids: str) -> str:
    text: str = response.text
    for i in ids:
        text = text.replace(i, "{id}")
    return text


def same_invite_answer(a: Any, b: Any) -> None:
    """Two invitations answered alike (P-E): same status and body but for the typed email and the row id."""
    assert a.status_code == b.status_code == 202
    assert set(a.json()) == set(b.json())
    keep = lambda r: {k: v for k, v in r.json().items() if k not in {"id", "email"}}  # noqa: E731
    assert keep(a) == keep(b)


def set_cookie(response: Any, name: str) -> str | None:
    found = [c for c in response.headers.get_list("set-cookie") if c.startswith(f"{name}=")]
    assert len(found) <= 1
    return found[0] if found else None


def cookie_attributes(header: str) -> dict[str, str]:
    """`{"httponly": "", "max-age": "600", ...}` of a Set-Cookie header, lower-cased names."""
    parts = [p.strip() for p in header.split(";")[1:]]
    return {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else "") for p in parts}


def is_cleared(header: str) -> bool:
    """A clearing Set-Cookie a browser obeys for a `__Host-` name: expired now, and with the same
    Secure, Path=/, HttpOnly and SameSite=Lax the cookie was set with (DC-6)."""
    attrs = cookie_attributes(header)
    expired = attrs.get("max-age") == "0" or "1970" in attrs.get("expires", "")
    return (expired and {"secure", "httponly"} <= set(attrs) and attrs.get("path") == "/"
            and attrs.get("samesite", "").lower() == "lax" and "domain" not in attrs)


def _children(obj: Any) -> list[Any]:
    if isinstance(obj, Mapping):
        return [*obj.keys(), *obj.values()]
    if isinstance(obj, list | tuple | set | frozenset):
        return list(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return [getattr(obj, f.name, None) for f in dataclasses.fields(obj)]
    if type(obj).__module__.startswith("defender."):
        slots = [getattr(obj, s, None) for k in type(obj).__mro__ for s in getattr(k, "__slots__", ())]
        return [*getattr(obj, "__dict__", {}).values(), *slots]
    return []


def repo_holds(repo: object, needle: str) -> bool:
    """Does `needle` occur anywhere in what the repository holds (strings, bytes, nested)?
    Implementation-agnostic: walks containers, dataclasses and the repository's own objects."""
    seen: set[int] = set()
    todo: list[Any] = [repo]
    while todo:
        obj = todo.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        if isinstance(obj, str) and needle in obj:
            return True
        if isinstance(obj, bytes | bytearray) and needle.encode() in bytes(obj):
            return True
        todo.extend(_children(obj))
    return False


# --- audit (K11) -----------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Event:
    action: str
    actor: str
    tenant_id: str | None
    target: str | None


class AuditLog:
    """The structured events on logger `defender.identity.audit`, read from each record's extras
    `action`, `actor`, `tenant_id`, `target`. Construct it before the world it watches."""

    def __init__(self, caplog: Any) -> None:
        caplog.set_level(logging.DEBUG, logger=AUDIT_LOGGER)
        self._caplog = caplog

    def events(self) -> list[Event]:
        out = []
        for r in self._caplog.records:
            if r.name == AUDIT_LOGGER:
                tenant = r.tenant_id
                out.append(Event(r.action, r.actor, None if tenant is None else str(tenant),
                                 None if r.target is None else str(r.target)))
        return out

    def mark(self) -> int:
        return len(self.events())

    def since(self, mark: int) -> list[Event]:
        return self.events()[mark:]

    def actions(self, mark: int = 0) -> list[str]:
        return [e.action for e in self.since(mark)]


# --- the world -----------------------------------------------------------------------------------

class _AppLoop:
    """One event loop on a daemon thread, with a blocking portal into it. Daemon, so a world nobody
    closed cannot hold the interpreter at exit."""

    def __init__(self) -> None:
        ready = threading.Event()
        box: list[anyio.from_thread.BlockingPortal] = []

        async def main() -> None:
            async with anyio.from_thread.BlockingPortal() as portal:
                box.append(portal)
                ready.set()
                await portal.sleep_until_stopped()

        self.thread = threading.Thread(target=anyio.run, args=(main,), daemon=True, name="world-loop")
        self.thread.start()
        assert ready.wait(10), "the world's event loop did not start"
        self.portal = box[0]

    def stop(self) -> None:
        with contextlib.suppress(Exception):  # already stopped, or the interpreter is exiting
            self.portal.call(self.portal.stop)


class _WorldClient(TestClient):
    """A `TestClient` whose requests run on the world's loop (no loop per request). Never entered
    as a context manager, so no lifespan, unless it is a `lifespan_client`."""

    def __init__(self, loop: _AppLoop, app: Any, **kwargs: Any) -> None:
        super().__init__(app, **kwargs)
        self.portal = loop.portal


class _LifespanClient(_WorldClient):
    """Entered as a context manager it runs the app's lifespan ON THE WORLD'S LOOP (the stock
    client would start a second loop of its own)."""

    def __enter__(self) -> _LifespanClient:
        import math

        from starlette.testclient import StapledObjectStream

        portal = self.portal
        assert portal is not None
        with contextlib.ExitStack() as stack:
            send: Any = anyio.create_memory_object_stream(math.inf)
            receive: Any = anyio.create_memory_object_stream(math.inf)
            for channel in (*send, *receive):
                stack.callback(channel.close)
            self.stream_send = StapledObjectStream(*send)
            self.stream_receive = StapledObjectStream(*receive)
            self.task = portal.start_task_soon(self.lifespan)
            portal.call(self.wait_startup)
            stack.callback(lambda: portal.call(self.wait_shutdown))
            self.exit_stack = stack.pop_all()
        return self


class OffboardingSpy:
    """#1360 D6: the world's store ports (the real `JobStorePorts`, or `Refusing`) as handed to the server's own wiring
    (`api_server.api_deps`), with the offboard recorded: each call as `(tenant, actor)` in `calls`; with `failing` set it
    raises before delegating. Every other port method is the wrapped object's. It holds NO policy: the tenant
    transition and the ending of jobs are the store's."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.calls: list[tuple[str, str]] = []
        self.failing = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def offboard_tenant(self, tenant_id: str, *, actor: Any) -> Any:
        self.calls.append((str(tenant_id), str(actor)))
        if self.failing:
            raise InjectedFailure("offboard_tenant failed")
        return await self._inner.offboard_tenant(tenant_id, actor=actor)


@dataclasses.dataclass(frozen=True)
class Announced:
    """One audit event the job store announced (its `defender.jobs.audit` log line), by the fields the cases read."""

    action: str
    tenant_id: str
    user_id: str
    target: str
    detail: str | None
    credential_id: str | None


class AuditRecorder:
    """One world's audit events: every event its job store announced, oldest first, in `events` (#1496)."""

    def __init__(self) -> None:
        self.events: list[Announced] = []
        #: While set, announcements are seeding's (the world saving a tenant's mapping), not a case's: not recorded.
        self.paused = False

    def record(self, record: logging.LogRecord) -> None:
        if not self.paused:
            self.events.append(Announced(*(None if (v := getattr(record, f, None)) is None else str(v) for f in (
                "action", "tenant_id", "actor", "target", "detail", "credential_id"))))


class _AuditTap(logging.Handler):
    """The one listener on the job store's audit log (`defender.jobs.audit`) for every world alive in the process. The
    store announces on the loop thread of the world it serves, so each event goes to the recorder of the world whose
    loop emitted it: worlds alive together never see each other's. The tap owns the logger's level while any world is
    attached (raised to INFO when the first attaches, restored when the last detaches), so no world's close can stop
    another's capture."""

    LOGGER = "defender.jobs.audit"

    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self._by_thread: dict[int, AuditRecorder] = {}
        self._level: int | None = None
        self._guard = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        recorder = self._by_thread.get(record.thread or 0)
        if recorder is not None:
            recorder.record(record)

    def attach(self, thread: int, recorder: AuditRecorder) -> None:
        with self._guard:
            logger = logging.getLogger(self.LOGGER)
            if not self._by_thread:
                self._level = logger.level
                logger.addHandler(self)
                if not logger.isEnabledFor(logging.INFO):
                    logger.setLevel(logging.INFO)
            self._by_thread[thread] = recorder

    def detach(self, thread: int) -> None:
        with self._guard:
            if self._by_thread.pop(thread, None) is not None and not self._by_thread:
                logger = logging.getLogger(self.LOGGER)
                logger.removeHandler(self)
                logger.setLevel(self._level if self._level is not None else logging.NOTSET)


_TAP = _AuditTap()


#: What a world with no database refuses its store ports with.
NO_STORE = "no store in this test world (#1496)"
#: What every world refuses the tenant's records and credentials with: the config routes are served over the real
#: server's `serving`, on its record store and secret store (`tests/support/api/_config1470.py`; #1470).
NO_RECORDS = "no record store or secret store in this test world (#1470)"


class World:
    """App + identity service over an in-memory repository (or the test database, `database=True`), one clock and a
    bootstrap file.
    `restart` builds a fresh service and app over the same repository and fakes; browsers follow it.

    Rule for the cases: no browser is reused after more than 12 hours idle or 7 days since its
    sign-in (O6). After a clock jump, `sign_in` again (it always opens a new browser)."""

    def __init__(self, *, administrators: Sequence[str] = (),  # noqa: PLR0913
                 tenants: Mapping[str, Sequence[str]] | None = None, start: bool = True,
                 failing_sends: int = 0, send_interval: _dt.timedelta | None = None,
                 send_deadline: _dt.timedelta | None = None, failing_writes: bool = False,
                 tenant_repo: Any = None,
                 alert_mapping: Mapping[str, str | None] | None = PLANTED_ALERT_MAPPING,
                 database: bool = False) -> None:
        #: #1345: the mapping each seeded tenant holds in the twin (`None`: none), see `_mapping1345`.
        self.alert_mapping = alert_mapping
        self.clock = Clock()
        #: #1496: the test database's DSN, or None for a world without one; opened before the loop starts, so a
        #: database `pytest.skip`s leaves no thread behind.
        self.dsn: str | None = None
        self.jobs: Any = None
        self._learning_store: Any = None
        self.audit: AuditRecorder | None = None
        self._resources = contextlib.ExitStack()
        if database:
            self._open_database()
        self._loop = _AppLoop()
        if self.audit is not None:  # the store announces on this loop's thread: its events are this world's
            ident = self._loop.thread.ident
            assert ident is not None
            _TAP.attach(ident, self.audit)
            self._resources.callback(_TAP.detach, ident)
        #: Stops the loop, then drops the database: run once, by `close()` or when the world is collected unclosed.
        self._finalizer = weakref.finalize(self, _release, self._loop, self._resources)
        _worlds.opened(self)
        if database:
            self.tenants: Any = tenant_repo if tenant_repo is not None else self._pg_tenants
            self.raw_repo: Any = self._pg_people
        else:
            #: The one tenant twin, shared with the identity repository and the API (r9 DC-7).
            self.tenants = tenant_repo if tenant_repo is not None else InMemoryTenantRepository()
            self.raw_repo = InMemoryIdentityRepository(tenants=self.tenants)
        self.repo: Any = FailingRepository(self.raw_repo) if failing_writes else self.raw_repo
        #: The backed families' ports, composed as the real server composes them (#1496).
        self.store: Any = self._backed_ports()
        #: #1360 D6: the one port the admin offboard route reaches the tenant transition and the jobs through: the real
        #: store's on the test database, refusing without one.
        self.offboarding = OffboardingSpy(self.store)
        self.signin = FakeSignIn()
        self.signin.fail_sends = failing_sends
        self.mail = FakeMail()
        self._codes = itertools.count(1)
        self.app: Any = None
        self.service: Any = None
        self.send_interval = send_interval
        self.send_deadline = send_deadline
        self.build(administrators=administrators, tenants=tenants or {})
        self._seed(tenants or {})
        if start:
            self.call(self.service.start)
            self.send_pending()

    def _open_database(self) -> None:
        """A migrated database of this world's own, with the real repositories and job store over it; dropped when the
        world closes, after its pools and loop."""
        from defender.identity.postgres import PostgresIdentityRepository
        from defender.jobs.store import JobStore
        from defender.tenancy.postgres import PostgresTenantRepository
        from defender.tests.support.shared._postgres1339 import database

        self.dsn = self._resources.enter_context(database(migrated=True))
        self.audit = AuditRecorder()
        self._pg_tenants = PostgresTenantRepository(self.dsn)
        self._pg_people = PostgresIdentityRepository(self.dsn)
        self.jobs = JobStore(self.dsn, clock=self.clock)

    def _backed_ports(self) -> Any:
        if self.jobs is None:
            return Refusing(NO_STORE)
        from defender.api.job_store import JobStorePorts

        return JobStorePorts(self.jobs)

    @property
    def audit_events(self) -> list[Announced]:
        """Every audit event the job store announced since the world was built (database worlds only)."""
        if self.audit is None:
            raise TypeError("audit_events needs a world on the test database (database=True)")
        return self.audit.events

    def add_alert(self, tenant: str, alert: Alert = ALERT) -> str:
        """Plant `alert` for `tenant` as a row of the test database, under its own id, title and
        description (test support, as `tests/jobs/test_store.py` plants rows); its id. The store serves it from there."""
        if self.dsn is None:
            raise TypeError("add_alert needs a world on the test database (database=True)")
        from defender.tests.support.shared._postgres1339 import execute

        execute(self.dsn, "INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, "
                          "received_at, title, description, raw) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (alert.alert_id, tenant, alert.vendor, alert.vendor_ticket_id, alert.fired_at, alert.changed_at,
                 alert.received_at, alert.title, alert.description, alert.raw.encode()))
        return str(alert.alert_id)

    def _sql(self, statement: str, params: tuple[Any, ...]) -> None:
        if self.dsn is None:
            raise TypeError("planting rows needs a world on the test database (database=True)")
        from defender.tests.support.shared._postgres1339 import execute

        execute(self.dsn, statement, params)

    def plant_investigation(self, tenant: str, investigation: Any) -> Any:
        """Plant `investigation` (the wire model) as its row, its status as the row's stage, with a bare alert of its
        `alert_id` when the tenant has none (test support, as `tests/jobs/test_store.py` plants rows); returns it."""
        inv = investigation
        self._sql("INSERT INTO jobs.alerts (id, tenant_id, vendor, vendor_ticket_id, fired_at, changed_at, received_at, "
                  "raw) VALUES (%s, %s, 'tickets', %s, %s, %s, %s, '{}') ON CONFLICT DO NOTHING",
                  (inv.alert_id, tenant, f"T-{inv.alert_id}", inv.created_at, inv.created_at, inv.created_at))
        lease = inv.created_at + DAY if inv.status == "running" else None
        self._sql("INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, "
                  "started_at, finished_at, disposition, cost_usd, cost_is_lower_limit, failure_reason, "
                  "lease_expires_at, update_ticket) "
                  "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                  (inv.investigation_id, tenant, inv.alert_id, inv.request_key, inv.attempt, inv.status, inv.created_at,
                   inv.started_at, inv.finished_at, inv.disposition, inv.cost_usd, inv.cost_is_lower_limit,
                   inv.failure_reason, lease, inv.update_ticket))  # C-3: every INSERT writes the flag
        return inv

    def plant_learning_job(self, tenant: str, job: Any) -> Any:
        """Plant `job` (the wire model) as its row; its investigation must be planted. Returns it."""
        lease = job.created_at + DAY if job.status == "running" else None
        self._sql("INSERT INTO jobs.learning_jobs (id, tenant_id, alert_id, investigation_id, request_key, attempt, "
                  "trigger, status, created_at, finished_at, reason, lease_expires_at, sibling_cost_usd, "
                  "publish_state) VALUES (%s, %s, %s, %s, %s, 1, %s, %s, %s, %s, %s, %s, 0, 'none')",
                  (job.learning_job_id, tenant, job.alert_id, job.investigation_id, f"k-{job.learning_job_id}",
                   job.trigger, job.status, job.created_at, job.finished_at, job.reason, lease))
        return job

    def call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Run `fn(*args, **kwargs)` on the app's loop and return what it awaited:
        `world.call(world.repo.user, uid)`, `world.call(world.service.send_pending)`. The call is
        made on the loop thread, so a coroutine function sees the same loop as the app. `fn` must
        return an awaitable: a method that is still synchronous (or a coroutine object passed
        instead of the function) is refused with TypeError, never run silently."""
        async def run() -> Any:
            result = fn(*args, **kwargs)
            if not inspect.isawaitable(result):
                raise TypeError(f"world.call: {fn!r} returned {type(result).__name__}, not an awaitable")
            return await result
        return self._loop.portal.call(run)

    def close(self) -> None:
        """Close the service (repository and sign-in port), the job store and the tenant repository on the loop, then
        stop the loop and drop the database. Idempotent; `tests/conftest.py` closes every world a test left open."""
        if not self._finalizer.alive:
            return
        try:
            async def pools() -> None:
                try:
                    service = getattr(self, "service", None)  # None when the world failed while being built
                    if service is not None:
                        await service.close()  # the identity repository's pool with it
                finally:
                    for opened in (getattr(self, "jobs", None), getattr(self, "_pg_tenants", None),
                                   getattr(self, "_learning_store", None)):
                        if opened is not None:
                            await opened.close()
            self._loop.portal.call(pools)
        finally:
            self._finalizer()

    def build(self, *, administrators: Sequence[str], tenants: Mapping[str, Sequence[str]]) -> None:
        """A fresh service and app over the same repositories. `tenants` is not read here (the bootstrap
        file has no tenants, Q3); `_seed` applies it."""
        extra: dict[str, Any] = {} if self.send_interval is None else {"send_interval": self.send_interval}
        if self.send_deadline is not None:
            extra["send_deadline"] = self.send_deadline
        # #1307 D7: the programs port is required; people-only worlds hold the quiet no-programs realm.
        from defender.tests.support.api._programs1307 import NoProgramsRealm
        self.service = IdentityService(
            self.repo, signin=self.signin, mail=self.mail, clock=self.clock,
            bootstrap=Bootstrap(administrators=tuple(administrators)),
            programs=NoProgramsRealm(),
            **extra,
        )
        self.app = create_app(self.deps())

    def deps(self) -> ApiDeps:
        """The app's ports for the current service, composed by the server's own wiring (#1496): the store's ports (with
        the offboard recorded) back what the server backs, the rest refuse as the server's do."""
        from defender.api.learning_work import StoreLearningWork
        from defender.api_server import api_deps
        from defender.learning_store import LearningStore

        no_records = Refusing(NO_RECORDS)
        learning = None
        if self.dsn is not None:  # #1485: the learning reads are the real adapter's over the world's database
            if self._learning_store is None:
                self._learning_store = LearningStore(self.dsn)
            learning = StoreLearningWork(self._learning_store)
        return api_deps(identity=self.service, tenants=self.tenants, ports=self.offboarding,
                        frontend_origin=FRONTEND_ORIGIN, systems=no_records, secrets=no_records, learning_work=learning)

    def restart(self, *, administrators: Sequence[str] = (),
                tenants: Mapping[str, Sequence[str]] | None = None) -> None:
        """A process start: bootstrap (may raise `BootstrapRefused`), then the sender's first pass."""
        self.build(administrators=administrators, tenants=tenants or {})
        self._seed(tenants or {})
        self.call(self.service.start)
        self.send_pending()

    def _seed(self, tenants: Mapping[str, Sequence[str]]) -> None:
        for tenant, emails in tenants.items():
            self._add_tenant(str(tenant), "active")
            self.call(self._seed_first_members, str(tenant), tuple(emails))

    def _add_tenant(self, tenant: str, state: str) -> None:
        """Seed one tenant (and its mapping), from the calling thread: the database's rows by blocking SQL here, never on
        the world's loop (a sender sharing the loop would stall), the async writes through `call`."""
        if tenant in {r.id for r in self.call(self.tenants.tenants)}:
            return
        if self.dsn is not None and not isinstance(self.tenants, InMemoryTenantRepository):
            from defender.tests.support.tenancy._active1214 import insert_active_tenant

            insert_active_tenant(self.dsn, tenant, state=state, wiring=False)
            if self.alert_mapping is not None:
                self.call(self._save_mapping, tenant)
            return
        self.call(seed_tenant, self.tenants, tenant, created_at=self.clock(), state=state)
        if self.alert_mapping is not None:  # design-implied twin seeder (r5), see `_mapping1345.seed_twin`
            self.call(add_to_twin, self.tenants, tenant, mapping_value(self.alert_mapping))

    async def _save_mapping(self, tenant: str) -> None:
        """The seeded tenant's mapping, through the store, its announcement not a case's (paused)."""
        assert self.audit is not None
        assert self.alert_mapping is not None
        self.audit.paused = True
        try:
            await self.jobs.put_alert_mapping(tenant, mapping_value(self.alert_mapping), actor="u-1")
        finally:
            self.audit.paused = False

    async def _seed_first_members(self, tenant: str, emails: Sequence[str]) -> None:
        repo, now = self.raw_repo, self.clock()
        if await repo.memberships_of_tenant(tenant):  # any row, whatever its status: seed once
            return
        for email in dict.fromkeys(emails):
            user = await repo.ensure_user(email, now=now)
            row = await repo.ensure_invitation(user.id, tenant, invited_by=None, now=now)
            if row is None:
                continue
            if user.status == "invited":
                await repo.request_set_password(user.id, now=now)
            else:
                await repo.request_notification(row.id, now=now)

    def seed_first_members(self, tenant: str, emails: Sequence[str]) -> None:
        """Seed `emails` as first members of an existing tenant (see the module docstring)."""
        self.call(self._seed_first_members, str(tenant), tuple(emails))

    def send_pending(self) -> None:
        """One run of the sender. It must not raise: a port failure only leaves that send pending."""
        self.call(self.service.send_pending)

    def register(self, tenant: str, *, state: str = "active") -> None:
        """Seed `tenant` through the tenant twin's seeder (r9 DC-6: no port method registers a tenant)."""
        self._add_tenant(str(tenant), state)

    async def amove_tenant(self, tenant: str, state: str) -> None:
        """`move_tenant` for a hook already running on the world's loop (a hook must not block on `call`)."""
        if self.dsn is not None:
            await offboard_on_database(self.dsn, tenant)
        else:
            await offboard_twin(self.tenants, tenant)
        if state == "offboarded":  # the worker's last step, through the twin's own hold
            async with self.tenants.lock(tenant) as held:
                assert held is not None, "the tenant is held by nobody else"
                await held.commit(step=None, actor=None, state="offboarded", pending_action=None, offboarded_at=self.clock())

    def move_tenant(self, tenant: str, state: str) -> None:
        """#1454: move an existing `active` tenant to `offboarding` (the request) or `offboarded` (the request, then the
        worker's commit), through the twin's own operations. Seed a tenant's invitations or programs while it is `active`,
        then call this: nothing is created in a tenant that is not (P-L)."""
        assert state in ("offboarding", "offboarded"), state
        self.call(self.amove_tenant, str(tenant), state)

    async def _asgi(self, scope: Any, receive: Any, send: Any) -> None:
        await self.app(scope, receive, send)

    def client(self, *, origin: str | None = FRONTEND_ORIGIN, raise_errors: bool = True) -> TestClient:
        """A browser: its own cookie jar and, unless `origin` is None, the Origin header on every
        request. Never entered as a context manager, so no lifespan (no background sender)."""
        headers = {} if origin is None else {"Origin": origin}
        return _WorldClient(self._loop, self._asgi, base_url=BASE_URL, follow_redirects=False,
                            headers=headers, raise_server_exceptions=raise_errors)

    def client_with_cookie(self, value: str, *, name: str = SESSION_COOKIE,
                           origin: str | None = FRONTEND_ORIGIN, raise_errors: bool = True) -> TestClient:
        """A browser that already holds a cookie (a replayed or invented session value)."""
        browser = self.client(origin=origin, raise_errors=raise_errors)
        browser.cookies.set(name, value)
        return browser

    def lifespan_client(self) -> TestClient:
        """A browser over the app itself: used as a context manager it runs the app's lifespan (the
        start-up and the periodic sender). Send every request of a lifespan test through it."""
        return _LifespanClient(self._loop, self.app, base_url=BASE_URL, follow_redirects=False,
                               headers={"Origin": FRONTEND_ORIGIN})

    def begin_signin(self, browser: TestClient, return_path: str | None = None) -> str:
        """GET /api/auth/login (with `return` when given); the state the person is sent to Keycloak with."""
        login = browser.get("/api/auth/login", params={} if return_path is None else {"return": return_path})
        assert login.status_code == 302, login.text
        return parse_qs(urlsplit(login.headers["location"]).query)["state"][0]

    def _callback_params(self, email: str, sent_state: str, *, amr: Sequence[str], name: str | None,
                         account_id: str | None, state: str | None,
                         extra: Mapping[str, str] | None) -> dict[str, str]:
        code = f"code-{next(self._codes)}"
        self.signin.answers[code] = VerifiedSignIn(
            account_id=account_id or self.signin.account_for(email),
            name=name or email.split("@")[0].title(), amr=tuple(amr))
        params = {"code": code, "state": sent_state if state is None else state, **(extra or {})}
        if state == NO_STATE:
            del params["state"]
        return params

    def sign_in_response(  # noqa: PLR0913 — one keyword per thing a case varies
            self, browser: TestClient, email: str, *, amr: Sequence[str] = ("pwd",),
                         name: str | None = None, account_id: str | None = None,
                         state: str | None = None, begin: bool = True,
                         extra: Mapping[str, str] | None = None, return_path: str | None = None) -> Any:
        """login -> (the person at Keycloak) -> callback; the callback's response. `state`
        overrides the state the callback carries (`""` sends it empty, `NO_STATE` leaves it
        out); `begin=False` skips the login step; `extra` adds query parameters to the callback; `return_path` is the
        sign-in start's `return` parameter (#1161 P2)."""
        sent_state = self.begin_signin(browser, return_path) if begin else (state or "no-login")
        params = self._callback_params(email, sent_state, amr=amr, name=name, account_id=account_id,
                                       state=state, extra=extra)
        return browser.get("/api/auth/callback", params=params)

    def sign_in(self, email: str, *, amr: Sequence[str] = ("pwd",), name: str | None = None,
                browser: TestClient | None = None) -> TestClient:
        """A new browser (or the given one) signed in as `email` (needs an account: the sender has run)."""
        browser = browser or self.client()
        response = self.sign_in_response(browser, email, amr=amr, name=name)
        assert response.status_code == 303, response.text
        assert browser.cookies.get(SESSION_COOKIE), "session cookie did not round-trip"
        return browser

    def sign_in_admin(self, email: str = OPS) -> TestClient:
        """The administrator's real sign-in: the account has a code and the token says so."""
        self.signin.has_otp_answers[self.signin.account_for(email)] = True
        return self.sign_in(email, amr=("pwd", "otp"))

    def invite(self, browser: TestClient, tenant: str, email: str) -> Any:
        return browser.post(f"/api/tenants/{tenant}/invitations", json={"email": email})

    def member(self, inviter: TestClient, tenant: str, email: str) -> TestClient:
        """Invite `email` (new to the platform) into `tenant`, send, and sign them in."""
        assert self.invite(inviter, tenant, email).status_code == 202
        self.send_pending()
        return self.sign_in(email)


def _release(loop: Any, resources: contextlib.ExitStack) -> None:
    """Stop the world's loop, then drop its database, if it has one (FORCE: a pool left open is cut)."""
    loop.stop()
    resources.close()


def wait_until(condition: Callable[[], bool], *, seconds: float = 5.0) -> bool:
    """Poll `condition` in real time for at most `seconds` (the lifespan's sender runs on the app's loop thread)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


def two_tenants() -> tuple[World, TestClient, TestClient]:
    """T1 with member ann (and one alert, `ALERT`), T2 with member bob, both signed in at T0; on the
    test database (#1496)."""
    world = World(tenants={T1: [ANN], T2: [BOB]}, database=True)
    world.add_alert(T1)
    return world, world.sign_in(ANN), world.sign_in(BOB)


def lab(*, database: bool = False) -> World:
    """The lab scenario: `ops` listed as administrator, `me` as the lab's first member; `database=True` puts it on the test
    database (a case that offboards, #1496)."""
    return World(administrators=[OPS], tenants={LAB: [ME]}, database=database)
