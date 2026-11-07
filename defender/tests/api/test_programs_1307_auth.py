"""#1307: how a program signs in and where it may act (O1, O2 outside tenants, O9, D2, D9, P-F, P-I)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

import datetime as _dt  # noqa: E402
from typing import Any  # noqa: E402

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ALERT,
    ANN,
    FRONTEND_ORIGIN,
    LAB,
    ME,
    NEW,
    OPS,
    SESSION_COOKIE,
    T1,
    T2,
    user_id,
)
from defender.tests.support.api._programs1307 import (  # noqa: E402
    DAY,
    EXPIRY_HEADER,
    ProgramsWorld,
    Soar,
    create_program,
    issue_key,
    issue_oauth,
    parse_time,
    soar,
)
from defender.tests.support.api._routes1307a import (  # noqa: E402
    PUBLIC,
    app_routes,
    authenticating_routes,
    concrete,
    route_id,
)

ROUTES = authenticating_routes()
EVIL = "https://evil.example"


def _send(client: Any, route: tuple[str, str], **headers: str) -> Any:
    return client.request(route[0], concrete(route[1]), headers=headers)


def _cookie(s: Soar) -> str:
    return f"{SESSION_COOKIE}={s.ann.cookies.get(SESSION_COOKIE)}"


def _expiry(s: Soar, credential_id: str, program_id: str | None = None) -> _dt.datetime:
    """The expiry our listing shows for a credential (the oracle for the header and `/me`)."""
    rows = s.ann.get(f"/tenants/{T1}/programs/{program_id or s.program_id}/credentials").json()["items"]
    [row] = [r for r in rows if r["id"] == credential_id]
    return parse_time(row["expires_at"])


def _flip(value: str, index: int) -> str:
    return value[:index] + ("A" if value[index] != "A" else "B") + value[index + 1:]


# --- O1: three ways in, one caller ------------------------------------------------------------

def test_a_live_key_of_an_active_program_reaches_its_tenant() -> None:
    """`Authorization: Bearer dfk_…` naming a live key -> the program, in its tenant (O1)."""
    s = soar()
    assert s.key.startswith(f"dfk_{s.key_id}_")
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 200


def test_a_key_altered_at_any_part_is_refused() -> None:
    """Prefix, credential id, separator or secret altered -> 401; the unaltered key is the control (O1)."""
    s = soar()
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 200
    secret_start = len(f"dfk_{s.key_id}_")
    positions = [0, 3, 4, 4 + len(s.key_id) // 2, 4 + len(s.key_id) - 1, secret_start - 1,
                 secret_start, (secret_start + len(s.key)) // 2, len(s.key) - 1]
    for index in positions:
        altered = _flip(s.key, index)
        assert s.world.bearer(altered).get(f"/tenants/{T1}/alerts").status_code == 401, index
    assert s.world.bearer(s.key + "x").get(f"/tenants/{T1}/alerts").status_code == 401
    assert s.world.bearer(s.key[:-1]).get(f"/tenants/{T1}/alerts").status_code == 401


def test_another_programs_key_acts_as_that_program_in_its_own_tenant_only() -> None:
    """A key names one program and one tenant: T2's program is a 404 in T1, a 200 in T2 (O1, O2)."""
    s = soar()
    theirs = str(create_program(s.bob, T2, "B's SOAR")["id"])
    _, their_key = issue_key(s.bob, T2, theirs)
    other = s.world.bearer(their_key)
    assert other.get(f"/tenants/{T2}/alerts").status_code == 200
    assert other.get(f"/tenants/{T1}/alerts").status_code == 404


def test_a_programs_realm_token_naming_a_live_oauth_credential_reaches_its_tenant() -> None:
    """A verified JWT whose client id and `sub` name a live OAuth credential -> the program (O1)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    assert credential in s.world.realm.clients
    token = s.world.realm.issue(credential)
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 200
    assert s.world.bearer("eyJ.not-issued.sig").get(f"/tenants/{T1}/alerts").status_code == 401


def test_a_token_whose_sub_is_not_the_recorded_service_account_is_refused() -> None:
    """Client id alone is a name: a token for a recreated client (other `sub`) -> 401 (O1, P-B)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    recorded = s.world.realm.clients[credential].service_account_id
    assert s.world.bearer(s.world.realm.forge(credential, recorded)).get(f"/tenants/{T1}/alerts").status_code == 200
    other = "00000000-5a00-4000-8000-999999999999"
    assert s.world.bearer(s.world.realm.forge(credential, other)).get(f"/tenants/{T1}/alerts").status_code == 401


def test_a_verified_token_must_name_an_oauth_credential_of_a_program() -> None:
    """A realm-signed token naming a key's id, a person's id or nothing we hold -> 401 (O1, P-F, kind pinned)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    sub = s.world.realm.clients[credential].service_account_id
    assert s.world.bearer(s.world.realm.forge(credential, sub)).get(f"/tenants/{T1}/alerts").status_code == 200
    for named in (s.key_id, user_id(s.ann), "00000000-0000-4000-8000-00000000dead"):
        token = s.world.realm.forge(named, sub)
        assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 401, named


def test_a_program_that_was_removed_is_no_caller_by_key_or_by_token() -> None:
    """Only an active program authenticates: removal -> 401 for its key and its tokens (O1)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 200
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 200
    assert s.ann.delete(f"/tenants/{T1}/programs/{s.program_id}").status_code == 204
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 401
    assert s.world.bearer(token).get(f"/tenants/{T1}/alerts").status_code == 401


def test_a_person_user_id_is_not_a_bearer_identity() -> None:
    """Cookies identify only people, bearer tokens only programs: a person's session value as a bearer -> 401 (P-F)."""
    s = soar()
    session = s.ann.cookies.get(SESSION_COOKIE)
    assert s.ann.get("/me").status_code == 200
    assert s.world.bearer(session).get("/me").status_code == 401
    assert s.world.client_with_cookie(s.key).get("/me").status_code == 401  # and a key as a cookie


@pytest.mark.parametrize("route", ROUTES, ids=route_id)
def test_a_cookie_and_an_authorization_header_together_are_refused_on_every_authenticating_route(
        route: tuple[str, str]) -> None:
    """Cookie + any `Authorization` -> 401 by no precedence; each alone does not (O1, P-F, D2)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    cookie = _cookie(s)
    for value in (f"Bearer {s.key}", f"Bearer {token}", "Bearer garbage", f"Basic {s.key}"):
        both = s.world.client(origin=FRONTEND_ORIGIN)
        assert _send(both, route, Cookie=cookie, Authorization=value).status_code == 401, value
    assert _send(s.world.bearer(s.key), route).status_code != 401  # control: the key alone
    assert _send(s.world.bearer(token), route).status_code != 401  # control: the token alone
    assert _send(s.world.client(), route, Cookie=cookie).status_code != 401  # control: the cookie alone


@pytest.mark.parametrize("route", ROUTES, ids=route_id)
def test_no_valid_credential_is_401_on_every_authenticating_route(route: tuple[str, str]) -> None:
    """No credential, an unknown key or token, a non-Bearer scheme, a bare key, Bearer with no value -> 401 (O1)."""
    s = soar()
    unauthenticated = [
        s.world.client(origin=FRONTEND_ORIGIN).request(route[0], concrete(route[1])),
        *(_send(s.world.client(origin=None), route, Authorization=value)
          for value in (f"Bearer {s.key[:-1]}x", "Bearer eyJ.not-issued.sig", f"Basic {s.key}", f"Token {s.key}",
                        s.key, "Bearer", "Bearer ")),
    ]
    assert [r.status_code for r in unauthenticated] == [401] * len(unauthenticated)
    assert _send(s.world.bearer(s.key), route).status_code != 401  # control
    assert _send(s.ann, route).status_code != 401  # control (last: it may sign the person out)


@pytest.mark.parametrize("route", sorted(PUBLIC))
def test_the_sign_in_routes_never_authenticate(route: tuple[str, str]) -> None:
    """A garbage `Authorization`, with or without a cookie, changes nothing on the public routes (O1, O2)."""
    s = soar()
    bare = _send(s.world.client(), route)
    if route[1] == "/auth/login":
        assert bare.status_code == 302, bare.text  # control: the route answers without a credential
    with_header = _send(s.world.client(), route, Authorization="Bearer garbage")
    with_both = _send(s.world.client(), route, Authorization="Bearer garbage", Cookie=_cookie(s))
    assert with_header.status_code == with_both.status_code == bare.status_code
    assert _send(s.world.client(), ("GET", "/me"), Authorization="Bearer garbage", Cookie=_cookie(s)).status_code == 401


# --- O9, D2: the frontend-origin rule is for cookie requests, and it runs first -------------------

def _origin_case(s: Soar, authorization: str | None, cookie: str | None, origin: str | None) -> Any:
    headers = {k: v for k, v in (("Authorization", authorization), ("Cookie", cookie)) if v is not None}
    return s.world.client(origin=origin).post(
        f"/tenants/{T1}/investigations", headers=headers,
        json={"alert_id": ALERT.alert_id, "client_request_id": "r1"})


@pytest.mark.parametrize(("authorization", "cookie", "origin", "expected", "started"), [
    pytest.param("key", None, None, 201, 1, id="bearer-no-origin"),
    pytest.param("key", None, EVIL, 201, 1, id="bearer-foreign-origin"),
    pytest.param("key", None, FRONTEND_ORIGIN, 201, 1, id="bearer-frontend-origin"),
    pytest.param(None, "session", FRONTEND_ORIGIN, 201, 1, id="cookie-frontend-origin"),
    pytest.param(None, "session", None, 403, 0, id="cookie-no-origin"),
    pytest.param(None, "session", EVIL, 403, 0, id="cookie-foreign-origin"),
    pytest.param(None, None, None, 403, 0, id="nothing-no-origin"),
    pytest.param("key", "session", None, 403, 0, id="both-no-origin-origin-layer-first"),
    pytest.param("garbage", "session", None, 403, 0, id="garbage-and-cookie-no-origin"),
    pytest.param("key", "other", None, 403, 0, id="bearer-and-any-cookie-no-origin"),
    pytest.param("key", "session", FRONTEND_ORIGIN, 401, 0, id="both-frontend-origin-401"),
    pytest.param("key", "other", FRONTEND_ORIGIN, 401, 0, id="bearer-and-any-cookie-frontend-origin-401"),
    pytest.param("basic", None, None, 401, 0, id="non-bearer-scheme-passes-origin-then-401"),
    pytest.param("empty", None, None, 401, 0, id="empty-authorization-passes-origin-then-401"),
])
def test_the_origin_rule_applies_to_cookie_requests_and_runs_before_authentication(
        authorization: str | None, cookie: str | None, origin: str | None, expected: int, started: int) -> None:
    """Writes: Authorization with no Cookie header at all is exempt (O9); a Cookie header keeps the rule (D2)."""
    s = soar()
    auth_value = {None: None, "key": f"Bearer {s.key}", "garbage": "Bearer garbage", "basic": f"Basic {s.key}",
                  "empty": ""}[authorization]
    cookie_value = {None: None, "session": _cookie(s), "other": "analytics=1"}[cookie]
    response = _origin_case(s, auth_value, cookie_value, origin)
    assert response.status_code == expected, response.text
    assert len(s.ann.get(f"/tenants/{T1}/investigations").json()["items"]) == started


# --- D9: the credential's expiry on every response after it verifies -------------------------------

@pytest.mark.parametrize("route", ROUTES, ids=route_id)
def test_every_response_to_a_program_carries_the_credentials_expiry(route: tuple[str, str]) -> None:
    """Whatever the status, a verified program's response has the header; a person's has none (D9)."""
    s = soar()
    expires = _expiry(s, s.key_id)
    response = _send(s.program(), route)
    assert parse_time(response.headers[EXPIRY_HEADER]) == expires, response.status_code
    assert EXPIRY_HEADER not in _send(s.ann, route).headers


def test_the_expiry_header_is_on_successes_and_on_403_404_and_422_alike() -> None:
    """Statuses 200, 403, 404 and 422 all carry it, for a key and for an OAuth credential (D9)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    token = s.world.realm.issue(credential)
    for client, expires in ((s.program(), _expiry(s, s.key_id)), (s.world.bearer(token), _expiry(s, credential))):
        seen = {
            200: client.get(f"/tenants/{T1}/alerts"),
            403: client.get(f"/tenants/{T1}/members"),
            404: client.get(f"/tenants/{T2}/alerts"),
            422: client.post(f"/tenants/{T1}/investigations", json={}),
        }
        for status, response in seen.items():
            assert response.status_code == status, (status, response.text)
            assert parse_time(response.headers[EXPIRY_HEADER]) == expires, status


def test_the_expiry_header_is_absent_when_no_credential_verified() -> None:
    """401 for a bad key, a bad token, a cookie beside a key, an expired key, a removed program: no header (D9)."""
    s = soar()
    short = s.world.clock() + 7 * DAY
    _, soon = issue_key(s.ann, T1, s.program_id, name="soon", expires_at=short)
    gone = str(create_program(s.ann, T1, "gone")["id"])
    _, gone_key = issue_key(s.ann, T1, gone)
    assert EXPIRY_HEADER in s.world.bearer(soon).get("/me").headers  # control
    assert s.ann.delete(f"/tenants/{T1}/programs/{gone}").status_code == 204
    refused = [
        s.world.bearer(s.key[:-1] + "x").get("/me"),
        s.world.bearer("eyJ.not-issued.sig").get("/me"),
        s.world.client(origin=FRONTEND_ORIGIN).get("/me", headers={"Cookie": _cookie(s), "Authorization": f"Bearer {s.key}"}),
        s.world.bearer(gone_key).get("/me"),
    ]
    s.world.clock.advance(7 * DAY)
    refused.append(s.world.bearer(soon).get("/me"))  # `expires_at > now` is false at the expiry itself
    assert [r.status_code for r in refused] == [401] * 5
    assert [EXPIRY_HEADER in r.headers for r in refused] == [False] * 5


# --- /me for both kinds (O2, D10) -------------------------------------------------------------------

def test_a_person_sees_todays_view_and_its_kind() -> None:
    """A person's `/me` keeps its user, tenants, administrator flag and invitations, plus `kind` (O2, D10)."""
    s = soar()
    body = s.ann.get("/me").json()
    assert body["kind"] == "person"
    assert body["user"]["email"] == ANN
    assert [t["tenant_id"] for t in body["tenants"]] == [T1]
    assert body["administrator"] is False
    assert body["invitations"] == []


def test_a_program_sees_itself_its_tenant_and_the_credential_it_used_at_me() -> None:
    """`/me` by key: kind program, itself, its tenant, the used credential's id and expiry; no secret (O2, D10)."""
    s = soar()
    _, other_key = issue_key(s.ann, T1, s.program_id, name="second", expires_at=s.world.clock() + 30 * DAY)
    response = s.program().get("/me")
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["kind"], body["program"]["id"], body["tenant"]["tenant_id"]) == ("program", s.program_id, T1)
    assert body["credential"]["id"] == s.key_id
    assert parse_time(body["credential"]["expires_at"]) == _expiry(s, s.key_id)
    assert s.key not in response.text
    second = s.world.bearer(other_key).get("/me").json()
    assert second["credential"]["id"] != s.key_id
    assert parse_time(second["credential"]["expires_at"]) == s.world.clock() + 30 * DAY


def test_a_program_signed_in_by_token_sees_the_oauth_credential_at_me() -> None:
    """`/me` by token names the OAuth credential, not the token's own expiry (O2, D9)."""
    s = soar()
    credential = issue_oauth(s.ann, T1, s.program_id)
    response = s.world.bearer(s.world.realm.issue(credential)).get("/me")
    body = response.json()
    assert (body["kind"], body["credential"]["id"]) == ("program", credential)
    assert parse_time(body["credential"]["expires_at"]) == _expiry(s, credential)
    assert parse_time(response.headers[EXPIRY_HEADER]) == _expiry(s, credential)


# --- O2 outside /tenants/ ---------------------------------------------------------------------------

def test_person_only_routes_refuse_a_program_and_serve_a_person() -> None:
    """Sign-out and accepting an invitation: a program is 403, a person is not (O2)."""
    s = soar()
    accept = "/invitations/00000000-0000-4000-8000-000000000000/accept"
    program = s.program()
    assert program.post("/auth/logout").status_code == 403
    assert program.post(accept).status_code == 403
    assert s.ann.post(accept).status_code == 404  # a person reaches the lookup
    assert program.get("/me").status_code == 200  # the program was not signed out
    assert s.ann.post("/auth/logout").status_code == 204


def test_platform_routes_refuse_a_program_and_a_person_without_the_flag() -> None:
    """Every `/admin` route: program 403 (even for its own tenant), non-administrator 403, administrator not (O2)."""
    world = ProgramsWorld(administrators=[OPS], tenants={LAB: [ME]})
    me = world.sign_in(ME)
    key = issue_key(me, LAB, str(create_program(me, LAB)["id"]))[1]
    ops = world.sign_in_admin()
    admin_routes = [r for r in app_routes() if r[1].startswith("/admin")]
    assert len(admin_routes) == 7
    for route in admin_routes:
        path = concrete(route[1].replace("{tenant_id}", LAB))
        assert world.bearer(key).request(route[0], path).status_code == 403, route
        assert me.request(route[0], path).status_code == 403, route
    assert world.bearer(key).get("/admin/tenants").status_code == 403
    assert ops.get("/admin/tenants").status_code == 200


# --- P-I: "member" means a person -------------------------------------------------------------------

def test_platform_rescue_still_works_when_only_a_program_remains() -> None:
    """The last person leaves; a program is no member in the people sense, so the rescue invitation goes (P-I)."""
    world = ProgramsWorld(administrators=[OPS], tenants={LAB: [ME]})
    me = world.sign_in(ME)
    program_id = str(create_program(me, LAB)["id"])
    _, key = issue_key(me, LAB, program_id)
    ops = world.sign_in_admin()
    assert ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": NEW}).status_code == 409
    assert me.delete(f"/tenants/{LAB}/members/{user_id(me)}").status_code == 204
    assert world.bearer(key).get(f"/tenants/{LAB}/alerts").status_code == 200
    assert ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": NEW}).status_code == 202


def test_a_program_is_not_listed_or_removable_as_a_member() -> None:
    """Members listing and member removal are about people; a program id there -> absent / 404 (P-I)."""
    s = soar()
    other = s.world.member(s.ann, T1, "carl@a.example")
    listed = s.ann.get(f"/tenants/{T1}/members").json()["items"]
    assert sorted(m["email"] for m in listed) == [ANN, "carl@a.example"]
    assert s.ann.delete(f"/tenants/{T1}/members/{s.program_id}").status_code == 404
    assert s.program().get(f"/tenants/{T1}/alerts").status_code == 200
    assert s.ann.delete(f"/tenants/{T1}/members/{user_id(other)}").status_code == 204  # control: a person goes
