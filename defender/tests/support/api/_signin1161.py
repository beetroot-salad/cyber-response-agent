"""#1161 piece 1, test-only: the identity provider's front channel (design B8), and helpers for the sign-in cookies.

The front channel is modelled on Keycloak 26.4.0 as observed (`keycloak-observed-q34.md`, Q4a/Q4b): the success
redirect carries `state`, `session_state`, `iss`, `code` (in that order); the error redirect `error`, optional
`error_description`, `state`, `iss`. Its back channel is `FakeKeycloak`'s code grant in `_server1083`; the two share
no state. The code is minted here from the authorize request's challenge, nonce and `redirect_uri` and the test's
choices for that attempt (`authorization_code()`), and the exchange verifies it from the code itself.

- `authorize(url, account_id, ...)` / `authorize_error(url, error, ...)`: the pure answers (a redirect target), for
  in-process tests that need no HTTP. `answer(url, choice)` picks the right one.
- `Choice`: what one attempt signs in as (account, `amr`, name, credential types), a per-code `fault`
  (`invalid_grant` or `unavailable`), or an `error` redirect instead of a code.
- `FrontChannel`: a loopback HTTP server in the test process. It models no policy under test; the three provider
  behaviours it does model are observed ones (an unsupported `response_type`, and a missing or other PKCE method,
  answer the observed error redirects).

It does nothing for: the redirect URI's registration (Keycloak answers an HTML page, no redirect; not modelled), a
code's 60 s lifespan, `prompt=none`, or a cancel link (the form has none)."""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import html
import http.server
import threading
import time
import urllib.parse
from collections.abc import Iterable
from http.cookies import SimpleCookie
from typing import Any

import httpx

from defender.tests.support.api._server1083 import CODE_FAULTS, SIGNIN_REALM, authorization_code

AUTH_PATH = f"/realms/{SIGNIN_REALM}/protocol/openid-connect/auth"
#: Where a held-and-never-released request gives up (the test is broken, not slow): recorded as an error.
HOLD_LIMIT = 60.0


@dataclasses.dataclass(frozen=True)
class Choice:
    """What one authorize request is answered with. `account` signs in as that account id (the `sub`); `error`
    answers C42's error redirect instead (with `error_description` when given); `fault` makes the code's exchange
    fail (`invalid_grant` "Code not valid", or a refused connection for `unavailable`)."""
    account: str | None = None
    amr: tuple[str, ...] = ("pwd",)
    name: str = ""
    credentials: tuple[str, ...] = ("password",)
    fault: str | None = None
    error: str | None = None
    error_description: str | None = None

    def __post_init__(self) -> None:
        assert (self.account is None) != (self.error is None), "a choice is an account or an error, not both/neither"
        assert self.fault is None or self.fault in CODE_FAULTS, self.fault


def _query(url: str) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))


def _issuer(url: str) -> str:
    split = urllib.parse.urlsplit(url)
    return f"{split.scheme}://{split.netloc}{split.path.split('/protocol/')[0]}"


def _redirect(query: dict[str, str], params: list[tuple[str, str]]) -> str:
    return f"{query['redirect_uri']}?{urllib.parse.urlencode(params)}"


def authorize_error(url: str, error: str, description: str | None = None) -> str:
    """The error redirect for the authorize `url` (Q4b): `error`, `error_description` if any, `state`, `iss`."""
    query = _query(url)
    params = [("error", error)] + ([("error_description", description)] if description else [])
    params += [("state", query["state"])] if "state" in query else []
    return _redirect(query, [*params, ("iss", _issuer(url))])


def authorize(url: str, account_id: str, *, amr: Iterable[str] = ("pwd",), name: str = "",
              credentials: Iterable[str] = ("password",), fault: str | None = None,
              session_state: str | None = None) -> str:
    """Where the browser goes after the password prompt for the authorize `url` the API built: its `redirect_uri`
    with `state`, `session_state`, `iss` and a code for `account_id` (Q4a). A request the provider refuses (observed:
    PKCE method missing or other than S256, an unsupported `response_type`) is answered with its error redirect."""
    query = _query(url)
    if query.get("response_type") != "code":
        return authorize_error(url, "unsupported_response_type")  # observed: no description
    if "code_challenge_method" not in query:
        return authorize_error(url, "invalid_request", "Missing parameter: code_challenge_method")
    if query["code_challenge_method"] != "S256" or "code_challenge" not in query:
        return authorize_error(url, "invalid_request", "Invalid parameter: code challenge method is not matching "
                                                       "the configured one")
    code = authorization_code(sub=account_id, nonce=query.get("nonce", ""), challenge=query["code_challenge"],
                              redirect_uri=query["redirect_uri"], amr=amr, name=name, credentials=credentials,
                              fault=fault, session_state=session_state)
    session = code.split(".")[1]
    params = ([("state", query["state"])] if "state" in query else []) + [
        ("session_state", session), ("iss", _issuer(url)), ("code", code)]
    return _redirect(query, params)


def answer(url: str, choice: Choice) -> str:
    """The redirect target for the authorize `url` under `choice`."""
    if choice.error is not None:
        return authorize_error(url, choice.error, choice.error_description)
    assert choice.account is not None
    return authorize(url, choice.account, amr=choice.amr, name=choice.name, credentials=choice.credentials,
                     fault=choice.fault)


@dataclasses.dataclass
class Authorize:
    """One authorize request the front channel received: `index` is its arrival order."""
    index: int
    url: str
    query: dict[str, str]
    released: threading.Event = dataclasses.field(default_factory=threading.Event)
    choice: Choice | None = None  # the release's own choice, when it gave one


class FrontChannel:
    """The provider's front channel on loopback (`origin`, `http://127.0.0.1:<port>`: a different site from the
    frontend's `localhost`, as the real provider's host is).

    By default each authorize request is answered at once with a 302 to `answer()` for the next queued `Choice`
    (`queue()`), else the default (`sign_in_as()`).

    - `hold = True`: each request is parked unanswered, the navigation staying pending, until `release(index)` (in
      any order; `release_all()`). `wait_held(n)` blocks until n are parked.
    - `form = True`: the answer is the provider's form, a committed 200 document (the page `go_back()` leaves);
      its button continues to the redirect, which the test clicks (`FORM_BUTTON`), or `complete(index)` for the same
      without a browser. Combined with `hold`, the form is served on release.

    `seen` keeps every authorize request. A fault in the handler (a missing default choice, a request held past
    `HOLD_LIMIT`) is kept in `errors` and answered 500, and `close()` raises it: a browser would only hang."""

    FORM_BUTTON = "button[type=submit]"

    def __init__(self) -> None:
        self.default: Choice | None = None
        self.queued: list[Choice] = []
        self.hold = False
        self.form = False
        self.seen: list[Authorize] = []
        self.errors: list[str] = []
        self._lock = threading.Condition()
        self._parked = 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a: Any) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 — http.server's dispatch name
                try:
                    outer._serve(self)
                except Exception as error:  # noqa: BLE001 — recorded, raised at close
                    outer.errors.append(f"{type(error).__name__}: {error}")
                    self._send(500, b"front channel fault")

            def _send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
                self.send_response(status)
                for key, value in {"Content-Length": str(len(body)), **(headers or {})}.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    # --- what the test says ------------------------------------------------------------------------

    def sign_in_as(self, account: str, **choice: Any) -> None:
        """Every attempt not otherwise chosen signs in as `account` (`Choice`'s other fields as keywords)."""
        self.default = Choice(account=account, **choice)

    def queue(self, *choices: Choice) -> None:
        """The next authorize requests, in arrival order, are answered with these (then the default)."""
        self.queued.extend(choices)

    def release(self, index: int, choice: Choice | None = None) -> None:
        """Answer the parked request `index`, with `choice` when given (else the queue or the default)."""
        request = self.seen[index]
        request.choice = choice
        request.released.set()

    def release_all(self) -> None:
        for request in list(self.seen):
            request.released.set()

    def wait_held(self, count: int, *, page: Any = None, timeout: float = 30.0) -> None:
        """Until `count` requests are parked. With a Playwright `page`, waits through it (its events keep flowing)."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if self._parked >= count:
                    return
            assert time.monotonic() < deadline, f"{self._parked} of {count} authorize requests reached the provider"
            if page is not None:
                page.wait_for_timeout(50)
            else:
                time.sleep(0.05)

    def complete(self, index: int) -> str:
        """Where the form's button sends the browser for request `index` (a redirect target), for tests with no browser."""
        return answer(self.seen[index].url, self._choice(self.seen[index]))

    def reset(self, default: str | None = None) -> None:
        """Back to a fresh channel for the next test of a module that shares one: nothing parked, queued, seen or
        faulted. A fault the previous test caused is raised here, as `close()` would have; `default` is the account every
        attempt signs in as unless a test says otherwise."""
        self.release_all()
        with self._lock:
            errors, self.errors = self.errors, []
            self.queued.clear()
            self.seen.clear()
            self._parked = 0
            self.hold = False
            self.form = False
            self.default = Choice(account=default) if default is not None else None
        assert not errors, f"the front channel faulted: {errors}"

    def close(self) -> None:
        self.release_all()
        self._server.shutdown()
        self._server.server_close()
        assert not self.errors, f"the front channel faulted: {self.errors}"

    # --- the server --------------------------------------------------------------------------------

    def _choice(self, request: Authorize) -> Choice:
        with self._lock:
            chosen = request.choice or (self.queued.pop(0) if self.queued else self.default)
        assert chosen is not None, "no Choice: call sign_in_as() or queue()"
        return chosen

    def _serve(self, handler: Any) -> None:
        split = urllib.parse.urlsplit(handler.path)
        if split.path == "/continue":
            index = int(dict(urllib.parse.parse_qsl(split.query))["i"])
            target = answer(self.seen[index].url, self._choice(self.seen[index]))
            return handler._send(302, headers={"Location": target})
        if split.path != AUTH_PATH:
            return handler._send(404)
        url = f"{self.origin}{handler.path}"
        with self._lock:
            request = Authorize(len(self.seen), url, _query(url))
            self.seen.append(request)
            parked = self.hold
            if parked:
                self._parked += 1
        if parked and not request.released.wait(HOLD_LIMIT):
            raise TimeoutError(f"authorize request {request.index} held past {HOLD_LIMIT} s and never released")
        if self.form:
            page = (f"<!doctype html><title>Sign in to your account</title><form method=get action=/continue>"
                    f"<input type=hidden name=i value={request.index}>"
                    f"<p>{html.escape(request.query.get('state', ''))}</p><button type=submit>Sign In</button></form>")
            return handler._send(200, page.encode(), {"Content-Type": "text/html; charset=utf-8"})
        handler._send(302, headers={"Location": answer(url, self._choice(request))})


# --- accounts and cookies -------------------------------------------------------------------------

async def link_account(dsn: str, email: str) -> str:
    """Record a sign-in account for the user `email` (the seed makes users without one); returns its id.
    Idempotent: the id derives from the email, so a second call finds the one already recorded."""
    from defender.identity.postgres import PostgresIdentityRepository

    account_id = f"kc-{hashlib.sha256(email.encode()).hexdigest()[:16]}"
    repo = PostgresIdentityRepository(dsn)
    try:
        user = await repo.user_by_email(email)
        assert user is not None, email
        if user.signin_account_id is not None:
            assert user.signin_account_id == account_id, (email, user.signin_account_id)
            return account_id
        assert await repo.record_signin_account(user.id, account_id)
        return account_id
    finally:
        await repo.close()


def set_cookies(response: httpx.Response) -> dict[str, Any]:
    """Each `Set-Cookie` of `response` as a morsel, by name (a later one of a name wins)."""
    found: dict[str, Any] = {}
    for header in response.headers.get_list("set-cookie"):
        jar: SimpleCookie = SimpleCookie()
        jar.load(header)
        found.update(jar)
    return found


def deleted(morsel: Any) -> bool:
    """Whether a `Set-Cookie` removes its cookie (a zero max-age or an expiry in the past)."""
    if morsel["max-age"] not in ("", None):
        return int(morsel["max-age"]) <= 0
    if morsel["expires"]:
        from email.utils import parsedate_to_datetime

        return parsedate_to_datetime(morsel["expires"]) <= dt.datetime.now(dt.UTC)
    return False
