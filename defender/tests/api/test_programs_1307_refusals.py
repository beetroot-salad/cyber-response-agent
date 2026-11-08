"""#1307 contract repair (code-stage attack batch): what a refused credential may and may not leave behind, and what
counts as "an Authorization header is present" (O1, O9, D2, P-F, A4, A7). Each test's input is the whole class the
attackers sampled: every way a bearer can be refused, every header-legal `Authorization` value against every cookie
state, every authenticating write route against every invalid credential."""
from __future__ import annotations

import itertools
from typing import Any

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

import datetime as _dt  # noqa: E402

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ALERT,
    FRONTEND_ORIGIN,
    SESSION_COOKIE,
    T1,
    user_id,
)
from defender.tests.support.api._programs1307 import (  # noqa: E402
    MIN_LIFETIME,
    Soar,
    create_program,
    issue_key,
    issue_oauth,
    revoke,
    soar,
)
from defender.tests.support.api._routes1307a import (  # noqa: E402
    authenticating_routes,
    concrete,
    route_id,
)

KINDS = ("key", "oauth_client")
ROUTES = authenticating_routes()


# --- A refused credential leaves no trace (Keys: "hash lookup -> usable -> program active -> last_used written") -------------

def _all_rows(s: Soar, *programs: str) -> dict[str, list[Any]]:
    """Every credential row of the given programs, as stored: dataclass equality covers every field, `last_used_at` included."""
    return {program: s.world.credentials(program) for program in programs}


def _present(s: Soar, kind: str, reason: str, programs: tuple[str, str]) -> str:
    """Arrange `reason` for a credential of `kind` that was used once (so it has a `last_used_at` the purge could advance) and
    return the bearer value to present. Each reason breaks exactly one thing and leaves the rest of the credential sound."""
    expires = s.world.clock() + MIN_LIFETIME
    if kind == "key":
        credential, secret = issue_key(s.ann, T1, programs[0], name="subject", expires_at=expires)
        value = secret
    else:
        credential = issue_oauth(s.ann, T1, programs[0], expires_at=expires)
        subject = s.world.realm.clients[credential].service_account_id
        value = s.world.realm.forge(credential, subject)
    if reason != "unused":
        assert s.world.bearer(value).get(f"/tenants/{T1}/alerts").status_code == 200  # control: it works, and is recorded
    s.world.clock.advance(_dt.timedelta(minutes=10))  # long enough that a use would be written again (every 5 minutes)
    if reason == "revoked":
        assert revoke(s.ann, T1, programs[0], credential).status_code == 204
    elif reason == "program-inactive":
        membership = s.world.call(s.world.raw_repo.active_membership, programs[0], T1)
        assert s.world.call(s.world.raw_repo.end_membership, membership.id, ended_by=user_id(s.ann),
                            now=s.world.clock()) is True  # the credential row stays live
    elif reason == "expired":
        s.world.clock.advance(MIN_LIFETIME)
    elif reason == "wrong-sub":
        value = s.world.realm.forge(credential, "00000000-5a00-4000-8000-999999999999")
    elif reason == "wrong-kind":  # a credential of the other kind named where this kind is expected
        if kind == "key":
            oauth = issue_oauth(s.ann, T1, programs[1])
            value = f"dfk_{oauth}_" + "x" * 43
        else:
            value = s.world.realm.forge(s.key_id, s.world.realm.clients[credential].service_account_id)
    elif reason == "unknown":
        value = f"dfk_{'0' * 8}-0000-4000-8000-{'0' * 12}_" + "x" * 43 if kind == "key" else s.world.realm.forge(
            "00000000-0000-4000-8000-00000000dead", "00000000-5a00-4000-8000-999999999999")
    elif reason == "altered":
        value = value[:-1] + ("A" if value[-1] != "A" else "B")
    else:
        assert reason in ("unused", "usable"), reason
    return value


REASONS = {
    "key": ["revoked", "expired", "program-inactive", "wrong-kind", "altered", "unknown"],
    "oauth_client": ["revoked", "expired", "program-inactive", "wrong-sub", "wrong-kind", "unknown"],
}
CASES = [(kind, reason) for kind in KINDS for reason in REASONS[kind]]


@pytest.mark.parametrize(("kind", "reason"), [*CASES, *((kind, "usable") for kind in KINDS)],
                         ids=lambda v: v if isinstance(v, str) else None)
def test_a_refused_bearer_is_401_and_changes_no_credential_row(kind: str, reason: str) -> None:
    """Every way a bearer can be refused (revoked, expired, program inactive, wrong `sub`, wrong kind, altered, unknown),
    for both credential kinds: 401 and every credential row of every program exactly as before, `last_used_at` included
    (use is recorded only once the credential is usable and its program active). `usable` is the control: the same
    arrangement without a fault is served and DOES advance `last_used_at`, so an unchanged row means something."""
    s = soar()
    other = str(create_program(s.ann, T1, "Other")["id"])
    issue_key(s.ann, T1, other, name="bystander")
    programs = (s.program_id, other)
    value = _present(s, kind, reason, programs)
    before = _all_rows(s, *programs)
    response = s.world.bearer(value).get(f"/tenants/{T1}/alerts")
    after = _all_rows(s, *programs)
    if reason == "usable":
        assert response.status_code == 200, response.text
        assert after != before
        [moved] = [(b, a) for p in programs for b, a in zip(before[p], after[p], strict=True) if b != a]
        assert moved[1].last_used_at == s.world.clock()
        return
    assert response.status_code == 401, response.text
    assert after == before


# --- "Authorization present" is one test (O1, O9, D2, A4) ------------------------------------------------------------

#: Header-legal values of `Authorization`: an optional scheme, an optional separator and an optional credential, in every
#: combination, plus the values that are only whitespace. `valid` ones carry the program's key once, as `Bearer`.
_SCHEMES = ("", "Bearer", "bearer", "BEARER", "Basic", "Token", "dfk_x")
_SEPARATORS = ("", " ", "  ", "\t")
_CREDENTIALS = ("", " ", "garbage", "KEY")
_WHITESPACE_ONLY = (" ", "  ", "\t", " \t ")


def _classify(scheme: str, separator: str, credential: str) -> str:
    if credential == "KEY" and scheme.lower() == "bearer":
        return "valid" if separator == " " else "ambiguous"  # extra whitespace: a server may or may not normalise it
    return "invalid"


def _authorization_values(key: str) -> list[tuple[str, str]]:
    """(value, class) for the whole generated space; class is `valid`, `invalid` or `ambiguous`."""
    out = {("", "invalid")}  # present but empty (A4)
    out |= {(w, "invalid") for w in _WHITESPACE_ONLY}
    for scheme, separator, credential in itertools.product(_SCHEMES, _SEPARATORS, _CREDENTIALS):
        out.add((f"{scheme}{separator}{credential.replace('KEY', key)}", _classify(scheme, separator, credential)))
    out.add((key, "invalid"))  # a bare key has no scheme
    return sorted(out)


def _cookie_states(s: Soar) -> list[tuple[str | None, str]]:
    """(Cookie header value, what it is): none at all, present but empty, a cookie that is not a session, a real session."""
    return [(None, "absent"), ("", "empty"), ("analytics=1", "junk"), (f"{SESSION_COOKIE}={s.ann.cookies.get(SESSION_COOKIE)}", "session")]


def _send(s: Soar, method: str, path: str, authorization: str | None, cookie: str | None, origin: str | None, **kw: Any) -> int:
    headers = {k: v for k, v in (("Authorization", authorization), ("Cookie", cookie)) if v is not None}
    return int(s.world.client(origin=origin).request(method, path, headers=headers, **kw).status_code)


def test_authorization_present_means_the_bearer_path_in_both_layers_whatever_its_value() -> None:
    """Over every header-legal `Authorization` value (absent, empty, whitespace, any scheme, any credential) and every
    cookie state: with a `Cookie` header the request is never authenticated by bearer or by cookie (401; a write with no
    frontend Origin is the origin layer's 403, which comes first), and without one a header, whatever its value, is the
    bearer path alone: a write with no Origin passes the origin layer and authentication decides (401 or served); with no
    header the cookie decides (O1, O9, D2, A4)."""
    s = soar()
    read, write = f"/tenants/{T1}/alerts", f"/tenants/{T1}/investigations"
    count = itertools.count()

    def post(authorization: str | None, cookie: str | None, origin: str | None) -> int:
        return _send(s, "POST", write, authorization, cookie, origin,
                     json={"alert_id": ALERT.alert_id, "client_request_id": f"r{next(count)}"})

    served = {200, 201}
    failures: list[str] = []

    def expect(what: str, got: int, want: set[int]) -> None:
        if got not in want:
            failures.append(f"{what}: {got}, wanted {sorted(want)}")

    values: list[tuple[str | None, str]] = [(None, "absent"), *_authorization_values(s.key)]
    for (cookie, cookie_kind), (authorization, kind) in itertools.product(_cookie_states(s), values):
        what = f"Authorization={authorization!r} Cookie={cookie_kind}"
        if kind == "ambiguous":
            continue
        if cookie is not None:  # a Cookie header at all: the origin rule applies, and nothing is authenticated twice
            expect(f"{what} write without Origin", post(authorization, cookie, None), {403})
            if authorization is not None:
                expect(f"{what} read", _send(s, "GET", read, authorization, cookie, None), {401})
                expect(f"{what} write with Origin", post(authorization, cookie, FRONTEND_ORIGIN), {401})
            elif cookie_kind == "session":
                expect(f"{what} read", _send(s, "GET", read, None, cookie, None), served)
                expect(f"{what} write with Origin", post(None, cookie, FRONTEND_ORIGIN), served)
            else:  # no header and no session: refused
                expect(f"{what} read", _send(s, "GET", read, None, cookie, None), {401})
                expect(f"{what} write with Origin", post(None, cookie, FRONTEND_ORIGIN), {401})
        elif authorization is None:  # nothing at all: the origin layer refuses a write without Origin; reads and writes with one are 401
            expect(f"{what} write without Origin", post(None, None, None), {403})
            expect(f"{what} read", _send(s, "GET", read, None, None, None), {401})
            expect(f"{what} write with Origin", post(None, None, FRONTEND_ORIGIN), {401})
        else:  # a header and no Cookie header: bearer path alone; the origin layer lets it pass whatever the value
            want = served if kind == "valid" else {401}
            expect(f"{what} read", _send(s, "GET", read, authorization, None, None), want)
            expect(f"{what} write without Origin", post(authorization, None, None), want)
            expect(f"{what} write with a foreign Origin", post(authorization, None, "https://evil.example"), want)
    assert failures == []
    assert next(count) > 500  # control: the generated space was walked, not a handful of values


@pytest.mark.parametrize("route", ROUTES, ids=route_id)
def test_an_authorization_header_of_any_kind_with_a_cookie_is_401_on_every_authenticating_route(route: tuple[str, str]) -> None:
    """The route census against the values the contract's own sample missed: an empty or whitespace `Authorization` beside a
    real session cookie is still a request that carries both, so 401 on every route that authenticates (O1, P-F, D2, A4)."""
    s = soar()
    cookie = f"{SESSION_COOKIE}={s.ann.cookies.get(SESSION_COOKIE)}"
    for value in ("", " ", "\t", "Bearer", "Bearer ", f"Bearer {s.key}"):
        got = s.world.client(origin=FRONTEND_ORIGIN).request(
            route[0], concrete(route[1]), headers={"Authorization": value, "Cookie": cookie}).status_code
        assert got == 401, (value, got)
    assert s.world.client(origin=FRONTEND_ORIGIN).request(
        route[0], concrete(route[1]), headers={"Cookie": cookie}).status_code != 401  # control: the cookie alone


# --- authentication comes before the body (O1, A7) ---------------------------------------------------------------------

_MALFORMED = b"{not json"
_JSON = {"content-type": "application/json"}
WRITES = [r for r in ROUTES if r[0] in ("POST", "PUT", "PATCH")]


@pytest.mark.parametrize("route", WRITES, ids=route_id)
def test_an_invalid_or_missing_credential_is_401_whatever_the_body_holds(route: tuple[str, str]) -> None:
    """On every authenticating route that takes a body, a malformed JSON body does not turn a refused credential into a 422:
    the credential is checked first (O1: "no credential, an invalid one ... -> 401, on every route that authenticates", A7).
    A pre-authentication parse would be reachable by anyone, since a bearer-only write skips the origin layer (O9)."""
    s = soar()
    path = concrete(route[1])
    refused = [
        s.world.client(origin=None).request(
            route[0], path, headers={"Authorization": value, **_JSON}, content=_MALFORMED)
        for value in ("Bearer garbage", f"Bearer {s.key[:-1]}x", "Bearer eyJ.not-issued.sig", f"Basic {s.key}", "Bearer ", "")
    ]
    refused.append(s.world.client(origin=FRONTEND_ORIGIN).request(route[0], path, headers=_JSON, content=_MALFORMED))  # nothing at all
    stale = s.world.client(origin=FRONTEND_ORIGIN)
    stale.cookies.set(SESSION_COOKIE, "not-a-session")
    refused.append(stale.request(route[0], path, headers=_JSON, content=_MALFORMED))  # a cookie that names no session
    assert [r.status_code for r in refused] == [401] * len(refused), [(r.status_code, r.text) for r in refused]
    # control: past authentication the same body is the body's problem, so the sweep can tell the two apart
    past = s.world.bearer(s.key).request(route[0], path, headers=_JSON, content=_MALFORMED)
    assert past.status_code != 401


def test_a_valid_credential_with_a_malformed_body_is_a_422() -> None:
    """Control for the body sweep: authentication first does not mean the body is never read (O1)."""
    s = soar()
    response = s.program().post(f"/tenants/{T1}/investigations", headers=_JSON, content=_MALFORMED)
    assert response.status_code == 422, response.text
