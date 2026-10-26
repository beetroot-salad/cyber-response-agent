"""#1306 test world: the API over an in-memory identity repository, a fake sign-in port, a fake
mail port and one injected clock — NO test functions. The fakes record calls and inject answers
(failures, a hook that runs inside a send); they never implement policy."""
from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import hashlib
import itertools
import logging
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.parse import parse_qs, urlsplit

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
    SignInUnavailable,
    VerifiedSignIn,
    register_tenant,
)
from defender.tenancy._tenant import TenantId
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
    `failing` raises `InjectedFailure` instead of running; everything else is delegated."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.failing: set[str] = set()
        #: method name -> how many calls were refused (the sender thread may be the caller).
        self.refusals: dict[str, int] = {}

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._inner, name)
        if name not in self.failing:
            return attribute

        def refuse(*args: Any, **kwargs: Any) -> Any:
            self.refusals[name] = self.refusals.get(name, 0) + 1
            raise InjectedFailure(f"{name} failed")

        return refuse


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
        #: Scripted failures, all `SignInUnavailable`: the next N set-password sends raise; every
        #: send to an email in `fail_sends_to` raises until the test removes it; the next N
        #: creations record the account and then raise (a crash before the caller recorded the id).
        self.fail_sends = 0
        self.fail_sends_to: set[str] = set()
        self.crash_after_create = 0
        #: Runs once inside the next set-password send, after it is recorded.
        self.during_send: Callable[[], None] | None = None
        #: email -> the exception (any type) every send to that account raises until removed.
        self.raise_on_send_to: dict[str, Exception] = {}
        #: The lifespan's sender runs on its own thread; views read snapshots taken under this lock.
        self._lock = threading.RLock()

    # --- the port ---------------------------------------------------------------------
    def create_account(self, username: str, email: str, required_actions: frozenset[str]) -> str:
        with self._lock:
            self.create_calls.append(username)
            if username not in self.accounts:
                self.accounts[username] = Account(
                    username, email, frozenset(required_actions), f"kc-{next(self._ids):04d}")
                if self.crash_after_create:
                    self.crash_after_create -= 1
                    raise SignInUnavailable("crash after the account was created")
            return self.accounts[username].account_id

    def send_set_password_email(self, account_id: str, lifespan: _dt.timedelta) -> None:
        with self._lock:
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
            hook()

    def has_otp(self, account_id: str) -> bool:
        return self.has_otp_answers.get(account_id, False)

    def require_otp_setup(self, account_id: str) -> None:
        self.otp_required.append(account_id)

    def begin_signin(self, state: str, nonce: str, code_challenge: str) -> str:
        self.started.append(SignInStart(state, nonce, code_challenge))
        return f"{SIGNIN_URL}?state={state}"

    def finish_signin(self, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn:
        self.finished.append(SignInFinish(code, code_verifier, nonce))
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


@dataclasses.dataclass(frozen=True)
class Notice:
    to: str
    tenant_id: str
    invitation_id: str


class FakeMail:
    """Our own mail port as a recorder."""

    def __init__(self) -> None:
        self.sent: list[Notice] = []
        self._lock = threading.RLock()
        self.fail_notices = 0
        #: Every notification to a recipient in this set raises until the test removes it.
        self.fail_notices_to: set[str] = set()
        #: Runs once inside the next notification, after it is recorded.
        self.during_notice: Callable[[], None] | None = None

    def notify_invitation(self, to: str, tenant_id: str, invitation_id: str) -> None:
        with self._lock:
            if self.fail_notices:
                self.fail_notices -= 1
                raise InjectedFailure("the notification failed")
            if to in list(self.fail_notices_to):
                raise InjectedFailure("the notification to this recipient failed")
            self.sent.append(Notice(to, str(tenant_id), str(invitation_id)))
            hook, self.during_notice = self.during_notice, None
        if hook:
            hook()


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
    attrs = cookie_attributes(header)
    return attrs.get("max-age") == "0" or "1970" in attrs.get("expires", "")


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

class World:
    """App + identity service over an in-memory repository, fakes, one clock and a bootstrap file.
    `restart` builds a fresh service and app over the same repository and fakes; browsers follow it.

    Rule for the cases: no browser is reused after more than 12 hours idle or 7 days since its
    sign-in (O6). After a clock jump, `sign_in` again (it always opens a new browser)."""

    def __init__(self, *, administrators: Sequence[str] = (),
                 tenants: Mapping[str, Sequence[str]] | None = None, start: bool = True,
                 failing_sends: int = 0, send_interval: _dt.timedelta | None = None,
                 failing_writes: bool = False) -> None:
        self.clock = Clock()
        self.store = InMemoryStore(self.clock)
        self.repo: Any = InMemoryIdentityRepository()
        if failing_writes:
            self.repo = FailingRepository(self.repo)
        self.signin = FakeSignIn()
        self.signin.fail_sends = failing_sends
        self.mail = FakeMail()
        self._codes = itertools.count(1)
        self.app: Any = None
        self.service: Any = None
        self.send_interval = send_interval
        self.build(administrators=administrators, tenants=tenants or {})
        if start:
            self.service.start()
            self.send_pending()

    def build(self, *, administrators: Sequence[str], tenants: Mapping[str, Sequence[str]]) -> None:
        extra = {} if self.send_interval is None else {"send_interval": self.send_interval}
        self.service = IdentityService(
            self.repo, signin=self.signin, mail=self.mail, clock=self.clock,
            bootstrap=Bootstrap(administrators=tuple(administrators),
                                tenants={t: tuple(e) for t, e in tenants.items()}),
            **extra,
        )
        self.app = create_app(ApiDeps(
            alerts=self.store, investigations=self.store, learning_jobs=self.store,
            lessons=self.store, systems=self.store, writes=self.store,
            secrets=InMemorySecrets(), checker=StubSystemChecker(),
            artifact_links=StubArtifactLinks(),
            identity=self.service, frontend_origin=FRONTEND_ORIGIN,
        ))

    def restart(self, *, administrators: Sequence[str] = (),
                tenants: Mapping[str, Sequence[str]] | None = None) -> None:
        """A process start: bootstrap (may raise `BootstrapRefused`), then the sender's first pass."""
        self.build(administrators=administrators, tenants=tenants or {})
        self.service.start()
        self.send_pending()

    def send_pending(self) -> None:
        """One run of the sender. It must not raise: a port failure only leaves that send pending."""
        self.service.send_pending()

    def register(self, tenant: str) -> None:
        register_tenant(self.repo, TenantId(tenant))

    async def _asgi(self, scope: Any, receive: Any, send: Any) -> None:
        await self.app(scope, receive, send)

    def client(self, *, origin: str | None = FRONTEND_ORIGIN, raise_errors: bool = True) -> TestClient:
        """A browser: its own cookie jar and, unless `origin` is None, the Origin header on every
        request. Never entered as a context manager, so no lifespan (no background sender)."""
        headers = {} if origin is None else {"Origin": origin}
        return TestClient(self._asgi, base_url=BASE_URL, follow_redirects=False, headers=headers,
                          raise_server_exceptions=raise_errors)

    def client_with_cookie(self, value: str, *, name: str = SESSION_COOKIE,
                           origin: str | None = FRONTEND_ORIGIN, raise_errors: bool = True) -> TestClient:
        """A browser that already holds a cookie (a replayed or invented session value)."""
        browser = self.client(origin=origin, raise_errors=raise_errors)
        browser.cookies.set(name, value)
        return browser

    def lifespan_client(self) -> TestClient:
        """A browser over the app itself: used as a context manager it runs the app's lifespan (the
        start-up and the periodic sender). Send every request of a lifespan test through it."""
        return TestClient(self.app, base_url=BASE_URL, follow_redirects=False,
                          headers={"Origin": FRONTEND_ORIGIN})

    def begin_signin(self, browser: TestClient) -> str:
        """GET /auth/login; the state the person is sent to Keycloak with."""
        login = browser.get("/auth/login")
        assert login.status_code == 302, login.text
        return parse_qs(urlsplit(login.headers["location"]).query)["state"][0]

    def sign_in_response(self, browser: TestClient, email: str, *, amr: Sequence[str] = ("pwd",),
                         name: str | None = None, account_id: str | None = None,
                         state: str | None = None, begin: bool = True) -> Any:
        """login -> (the person at Keycloak) -> callback; the callback's response. `state`
        overrides the state the callback carries; `begin=False` skips the login step."""
        sent_state = self.begin_signin(browser) if begin else (state or "no-login")
        code = f"code-{next(self._codes)}"
        self.signin.answers[code] = VerifiedSignIn(
            account_id=account_id or self.signin.account_for(email),
            name=name or email.split("@")[0].title(), amr=tuple(amr))
        return browser.get("/auth/callback", params={"code": code, "state": state or sent_state})

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
    """Poll `condition` in real time for at most `seconds` (the lifespan's sender runs on its own thread)."""
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
