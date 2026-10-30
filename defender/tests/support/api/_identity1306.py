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
invitation `invited_by="system"` and the same set-password / notification request the old bootstrap made,
all through the raw identity repository's existing seeders (so `failing_writes` never touches seeding).
So every old observable (sends, first sign-in accepting the invitation, audit lines) is unchanged; the
administrator invite path is `World.member(admin_browser, tenant, email)` (a world with an administrator
that wants the r9 route uses it). Seeding is idempotent.

Interface: `World(administrators=, tenants=, start=, failing_sends=, send_interval=, send_deadline=,
failing_writes=, tenant_repo=None)`; `world.tenants` (the twin), `world.repo` (identity repository,
failure-wrapped if `failing_writes`), `world.raw_repo` (never wrapped); `world.register(T, *, state="active")`;
`world.seed_first_members(T, emails)`; `world.restart(administrators=, tenants=)`."""
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
from defender.api.fakes import InMemorySecrets, InMemoryStore, StubArtifactLinks, StubSystemChecker
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
from defender.identity.audit import SYSTEM as _SYSTEM
from defender.tenancy import InMemoryTenantRepository
from defender.tests.support.shared._fixture_uuid import fixture_uuid

T0 = _dt.datetime(2026, 10, 26, 9, 0, tzinfo=_dt.UTC)
HOUR = _dt.timedelta(hours=1)
DAY = _dt.timedelta(days=1)
SEVEN_DAYS = _dt.timedelta(days=7)
SECOND = _dt.timedelta(seconds=1)
#: The configured frontend origin (O6): state-changing requests must carry it.
FRONTEND_ORIGIN = "https://app.defender.test"
#: DC-6. Both are HttpOnly, Secure, SameSite=Lax, Path=/, no Domain.
SESSION_COOKIE = "__Host-defender_session"
PRELOGIN_COOKIE = "__Host-defender_prelogin"
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
    alert_id="al-1", vendor="tickets", vendor_ticket_id="T-1", title="t", severity="high",
    rule="r", fired_at=T0, changed_at=T0, received_at=T0, raw={"id": "al-1"},
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
    `missing_tenants` scripts the answer of `tenant_exists` (False) and `active_tenants` (left out)
    for a tenant whose row is gone or no longer active (#1214's lifecycle); nothing else about the
    tenant changes.
    `after` maps a method name to a hook (a coroutine function, no arguments) awaited once right
    after that method returns (an interleaving point: the hook is the test's own action, e.g. a
    sign-in; it decides nothing). Every delegated method is a coroutine function and the inner
    method is awaited strictly: a repository whose method is not async fails loudly."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.failing: set[str] = set()
        self.missing_tenants: set[str] = set()
        #: method name -> how many calls were refused (the sender may be the caller).
        self.refusals: dict[str, int] = {}
        self.after: dict[str, Callable[[], Awaitable[None]]] = {}

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
            if name == "tenant_exists" and args and str(args[0]) in self.missing_tenants:
                return False
            result = await attribute(*args, **kwargs)
            if name == "active_tenants":
                result = result - self.missing_tenants
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
    response = browser.get("/me")
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
    return items(browser.get(f"/tenants/{tenant}/invitations"))


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

        threading.Thread(target=anyio.run, args=(main,), daemon=True, name="world-loop").start()
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


class World:
    """App + identity service over an in-memory repository, fakes, one clock and a bootstrap file.
    `restart` builds a fresh service and app over the same repository and fakes; browsers follow it.

    Rule for the cases: no browser is reused after more than 12 hours idle or 7 days since its
    sign-in (O6). After a clock jump, `sign_in` again (it always opens a new browser)."""

    def __init__(self, *, administrators: Sequence[str] = (),
                 tenants: Mapping[str, Sequence[str]] | None = None, start: bool = True,
                 failing_sends: int = 0, send_interval: _dt.timedelta | None = None,
                 send_deadline: _dt.timedelta | None = None, failing_writes: bool = False,
                 tenant_repo: Any = None) -> None:
        self.clock = Clock()
        self.store = InMemoryStore(self.clock)
        #: The one tenant twin, shared with the identity repository and the API (r9 DC-7).
        self.tenants: Any = tenant_repo if tenant_repo is not None else InMemoryTenantRepository()
        self.raw_repo: Any = InMemoryIdentityRepository(tenants=self.tenants)
        self.repo: Any = FailingRepository(self.raw_repo) if failing_writes else self.raw_repo
        self._loop = _AppLoop()
        weakref.finalize(self, self._loop.stop)
        self.signin = FakeSignIn()
        self.signin.fail_sends = failing_sends
        self.mail = FakeMail()
        self._codes = itertools.count(1)
        self.app: Any = None
        self.service: Any = None
        self.send_interval = send_interval
        self.send_deadline = send_deadline
        self.build(administrators=administrators, tenants=tenants or {})
        self.call(self._seed, tenants or {})
        if start:
            self.call(self.service.start)
            self.send_pending()

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
        """Close the service (repository and sign-in port) on the loop, then stop the loop."""
        self.call(self.service.close)
        self._loop.stop()

    def build(self, *, administrators: Sequence[str], tenants: Mapping[str, Sequence[str]]) -> None:
        """A fresh service and app over the same repositories. `tenants` is not read here (the bootstrap
        file has no tenants, Q3); `_seed` applies it."""
        extra: dict[str, Any] = {} if self.send_interval is None else {"send_interval": self.send_interval}
        if self.send_deadline is not None:
            extra["send_deadline"] = self.send_deadline
        self.service = IdentityService(
            self.repo, signin=self.signin, mail=self.mail, clock=self.clock,
            bootstrap=Bootstrap(administrators=tuple(administrators)),
            **extra,
        )
        self.app = create_app(ApiDeps(
            alerts=self.store, investigations=self.store, learning_jobs=self.store,
            lessons=self.store, systems=self.store, writes=self.store,
            secrets=InMemorySecrets(), checker=StubSystemChecker(),
            artifact_links=StubArtifactLinks(),
            identity=self.service, frontend_origin=FRONTEND_ORIGIN, tenants=self.tenants,
        ))

    def restart(self, *, administrators: Sequence[str] = (),
                tenants: Mapping[str, Sequence[str]] | None = None) -> None:
        """A process start: bootstrap (may raise `BootstrapRefused`), then the sender's first pass."""
        self.build(administrators=administrators, tenants=tenants or {})
        self.call(self._seed, tenants or {})
        self.call(self.service.start)
        self.send_pending()

    async def _seed(self, tenants: Mapping[str, Sequence[str]]) -> None:
        for tenant, emails in tenants.items():
            await self._add_tenant(str(tenant), "active")
            await self._seed_first_members(str(tenant), tuple(emails))

    async def _add_tenant(self, tenant: str, state: str) -> None:
        if tenant in {r.id for r in await self.tenants.tenants()}:
            return
        added = self.tenants.add_tenant(tenant, created_at=self.clock(), state=state)
        if inspect.isawaitable(added):  # GAP-0-1: the seeder's sync/async shape is not pinned
            await added

    async def _seed_first_members(self, tenant: str, emails: Sequence[str]) -> None:
        repo, now = self.raw_repo, self.clock()
        if await repo.tenant_has_ever_had_membership(tenant):
            return
        for email in dict.fromkeys(emails):
            user = await repo.ensure_user(email, now=now)
            row = await repo.ensure_invitation(user.id, tenant, invited_by=_SYSTEM, now=now)
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
        self.call(self._add_tenant, str(tenant), state)

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

    def begin_signin(self, browser: TestClient) -> str:
        """GET /auth/login; the state the person is sent to Keycloak with."""
        login = browser.get("/auth/login")
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

    def sign_in_response(self, browser: TestClient, email: str, *, amr: Sequence[str] = ("pwd",),
                         name: str | None = None, account_id: str | None = None,
                         state: str | None = None, begin: bool = True,
                         extra: Mapping[str, str] | None = None) -> Any:
        """login -> (the person at Keycloak) -> callback; the callback's response. `state`
        overrides the state the callback carries (`""` sends it empty, `NO_STATE` leaves it
        out); `begin=False` skips the login step; `extra` adds query parameters to the callback."""
        sent_state = self.begin_signin(browser) if begin else (state or "no-login")
        params = self._callback_params(email, sent_state, amr=amr, name=name, account_id=account_id,
                                       state=state, extra=extra)
        return browser.get("/auth/callback", params=params)

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
        return browser.post(f"/tenants/{tenant}/invitations", json={"email": email})

    def member(self, inviter: TestClient, tenant: str, email: str) -> TestClient:
        """Invite `email` (new to the platform) into `tenant`, send, and sign them in."""
        assert self.invite(inviter, tenant, email).status_code == 202
        self.send_pending()
        return self.sign_in(email)


def wait_until(condition: Callable[[], bool], *, seconds: float = 5.0) -> bool:
    """Poll `condition` in real time for at most `seconds` (the lifespan's sender runs on the app's loop thread)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


def two_tenants() -> tuple[World, TestClient, TestClient]:
    """T1 with member ann (and one alert), T2 with member bob, both signed in at T0."""
    world = World(tenants={T1: [ANN], T2: [BOB]})
    world.store.add_alert(T1, ALERT)
    return world, world.sign_in(ANN), world.sign_in(BOB)


def lab() -> World:
    """The lab scenario: `ops` listed as administrator, `me` as the lab's first member."""
    return World(administrators=[OPS], tenants={LAB: [ME]})
