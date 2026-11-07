"""#1306: signing in — login, callback, the pre-login cookie, first sign-in (flow 2, O6, DC-6).

#1306: the browser session — limits, storage, Origin, no Bearer (O6, DC-6).

#1306: who a request is and which tenant it may act in (O1, P-D, O7).
"""
from __future__ import annotations

import re
import datetime as _dt
from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip('fastapi')

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
    FRONTEND_ORIGIN,
    ME,
    NEW,
    NO_STATE,
    OPS,
    PRELOGIN_COOKIE,
    SESSION_COOKIE,
    SIGNIN_URL,
    T1,
    T2,
    cookie_attributes,
    invitation_id,
    is_cleared,
    lab,
    me,
    pkce_challenge,
    problem_type,
    set_cookie,
    tenants_of,
    two_tenants,
    user_id,
    SignInUnavailable,
    World,
)
from defender.tests.support.api._identity1306 import OPS as OPS_EMAIL  # noqa: E402
from defender.tests.support.api._identity1306 import (  # noqa: E402
    EMPTY,
    HOUR,
    NINA,
    SECOND,
    SEVEN_DAYS,
    T0,
    invitation_rows,
    items,
    repo_holds,
)
from defender.api.models import AlertSummary  # noqa: E402
from defender.tests.support.api._identity1306 import (  # noqa: E402
    ALERT,
    NO_SUCH_ID,
    SUMMARY,
    UNKNOWN,
    masked,
)


# A forgotten `world.call` leaves a never-awaited coroutine; pytest reports its RuntimeWarning as an unraisable exception, so both are errors.
pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]


#: RFC 7636 §4.1: a PKCE code verifier is 43 to 128 unreserved characters.
PKCE_VERIFIER = re.compile(r"[A-Za-z0-9\-._~]{43,128}")


def test_login_redirects_to_the_port_and_sets_a_host_prelogin_cookie() -> None:
    """GET /auth/login: 302 to the port's URL, with an HttpOnly Secure Lax Path=/ 10-minute cookie (flow 2, DC-6)."""
    world = World(tenants={T1: [ANN]})
    login = world.client().get("/auth/login")
    assert login.status_code == 302
    assert login.headers["location"] == f"{SIGNIN_URL}?state={world.signin.started[-1].state}"
    attrs = cookie_attributes(set_cookie(login, PRELOGIN_COOKIE) or "")
    assert {"httponly", "secure"} <= set(attrs)
    assert (attrs["samesite"].lower(), attrs["path"], attrs["max-age"]) == ("lax", "/", "600")
    assert "domain" not in attrs


def test_r7_2_the_sign_in_callback_accepts_the_identity_providers_own_extra_parameters() -> None:
    """`GET /auth/callback` with `session_state` and `iss` signs in (303, a session cookie): the one route exempt from the unknown-query refusal. (R7-2, D-ai)"""
    world = World(tenants={T1: [ANN]})
    browser = world.client()
    callback = world.sign_in_response(browser, ANN, extra={"session_state": "kc-session", "iss": "https://idp.example/realms/x"})
    assert callback.status_code == 303, callback.text
    assert set_cookie(callback, SESSION_COOKIE)


def test_sign_in_ends_in_a_host_session_cookie_and_me_names_the_user() -> None:
    """login -> callback -> 303 to exactly the frontend (whatever the query asks), HttpOnly Secure Lax cookie, /me (flow 2, O6, DC-6)."""
    world = World(tenants={T1: [ANN]})
    browser = world.client()
    callback = world.sign_in_response(browser, ANN, name="Ann Example", extra={
        "next": "https://evil.example/", "return_to": "https://evil.example/", "redirect": "https://evil.example/"})
    started, finished = world.signin.started[-1], world.signin.finished[-1]
    assert finished.nonce == started.nonce
    assert pkce_challenge(finished.code_verifier) == started.code_challenge
    assert callback.status_code == 303
    assert callback.headers["location"] in (FRONTEND_ORIGIN, FRONTEND_ORIGIN + "/")  # no open redirect
    attrs = cookie_attributes(set_cookie(callback, SESSION_COOKIE) or "")
    assert {"httponly", "secure"} <= set(attrs)
    assert (attrs["samesite"].lower(), attrs["path"]) == ("lax", "/")
    assert "domain" not in attrs
    body = me(browser)
    assert set(body) == {"user", "tenants", "administrator", "invitations"}
    assert body["user"] == {"id": world.signin.account_of(ANN).username,  # P-C: username = user id
                            "email": ANN, "display_name": "Ann Example"}
    assert body["tenants"] == [{"tenant_id": T1}]
    assert (body["administrator"], body["invitations"]) == (False, [])


def test_the_display_name_follows_the_name_in_the_token_at_each_sign_in() -> None:
    """display_name is taken from `name` at every sign-in, and every session reads the user afresh (flow 2, P-A)."""
    world = World(tenants={T1: [ANN]})
    laptop = world.sign_in(ANN, name="Ann One")
    assert me(laptop)["user"]["display_name"] == "Ann One"
    assert me(world.sign_in(ANN, name="Ann Two"))["user"]["display_name"] == "Ann Two"
    assert me(laptop)["user"]["display_name"] == "Ann Two"  # the older session, already used, too


def test_each_login_starts_with_its_own_pkce_verifier_state_and_nonce() -> None:
    """The pre-login values are per sign-in: two logins never share a verifier, and the verifier is not the state or nonce (flow 2, DC-8 PKCE S256)."""
    world = World(tenants={T1: [ANN]})
    world.sign_in(ANN)
    world.sign_in(ANN)
    (s1, s2), (f1, f2) = world.signin.started[-2:], world.signin.finished[-2:]
    assert f1.code_verifier != f2.code_verifier
    assert s1.state != s2.state
    assert s1.nonce != s2.nonce
    for started, finished in ((s1, f1), (s2, f2)):
        assert finished.code_verifier not in (started.state, started.nonce)


def test_first_sign_in_accepts_every_open_invitation_at_once() -> None:
    """One set-password send per person; first sign-in accepts all open invitations (flow 1/2)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, NEW)
    world.invite(bob, T2, NEW)
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1
    n = world.sign_in(NEW)
    assert tenants_of(n) == {T1, T2}
    assert n.get(f"/tenants/{T2}/alerts").status_code == 200
    assert {m["email"] for m in n.get(f"/tenants/{T2}/members").json()["items"]} == {BOB, NEW}


def test_after_first_sign_in_a_new_invitation_is_a_notification_to_accept_while_signed_in() -> None:
    """invited -> active: later invitations go by our own email and wait for accept (O2, flow 3)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, NEW)
    world.send_pending()
    n = world.sign_in(NEW)
    row = world.invite(bob, T2, NEW).json()["id"]
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1
    assert [x.invitation_id for x in world.mail.sent] == [row]
    assert tenants_of(n) == {T1}
    assert me(n)["invitations"] == [{"id": row, "tenant_id": T2}]


def test_the_four_callback_refusals_are_403_problems_of_distinct_types_and_open_no_session() -> None:
    """Unknown account, state mismatch, no pre-login cookie, administrator without a code (flow 2, O5)."""
    world = lab()
    world.signin.has_otp_answers[world.signin.account_for(OPS)] = True
    unknown = world.client()
    r_unknown = world.sign_in_response(unknown, ME, account_id="kc-not-ours")
    mismatch = world.client()
    r_mismatch = world.sign_in_response(mismatch, ME, state="not-the-state")
    no_cookie = world.client()
    r_no_cookie = world.sign_in_response(no_cookie, ME, begin=False)
    no_code = world.client()
    r_no_code = world.sign_in_response(no_code, OPS, amr=("pwd",))
    refusals = [r_unknown, r_mismatch, r_no_cookie, r_no_code]
    assert [r.status_code for r in refusals] == [403] * 4
    assert len({problem_type(r) for r in refusals}) == 4
    for browser in (unknown, mismatch, no_cookie, no_code):
        assert SESSION_COOKIE not in browser.cookies
    for response in (r_unknown, r_mismatch, r_no_code):  # the cookie existed: cleared whatever the outcome
        assert is_cleared(set_cookie(response, PRELOGIN_COOKIE) or "")
    ok = world.client()
    r_ok = world.sign_in_response(ok, ME)  # positive control
    assert r_ok.status_code == 303
    assert ok.cookies.get(SESSION_COOKIE)
    assert is_cleared(set_cookie(r_ok, PRELOGIN_COOKIE) or "")


@pytest.mark.parametrize("state", ["not-the-state", "", None], ids=["other", "empty", "missing"])
def test_a_state_mismatch_does_not_exchange_the_code(state: str | None) -> None:
    """The state must match before the code is exchanged; an empty or missing state matches nothing (flow 2)."""
    world = World(tenants={T1: [ANN]})
    before = len(world.signin.finished)
    browser = world.client()
    refused = world.sign_in_response(browser, ANN, state=NO_STATE if state is None else state)
    assert refused.status_code == 403
    assert len(world.signin.finished) == before
    assert SESSION_COOKIE not in browser.cookies
    assert world.sign_in_response(world.client(), ANN).status_code == 303  # control


def test_a_token_that_fails_verification_is_a_403_that_opens_no_session_and_clears_the_prelogin_cookie() -> None:
    """A SignInRefused from the port is a refusal, not a crash: 403 problem, no session, pre-login cleared (flow 2, DC-6)."""
    world = World(tenants={T1: [ANN]})
    browser = world.client(raise_errors=False)
    world.signin.refuse_signins = 1
    refused = world.sign_in_response(browser, ANN)
    assert refused.status_code == 403
    assert refused.headers["content-type"] == "application/problem+json"
    assert set_cookie(refused, SESSION_COOKIE) is None
    assert SESSION_COOKIE not in browser.cookies
    assert is_cleared(set_cookie(refused, PRELOGIN_COOKIE) or "")
    assert world.sign_in_response(world.client(), ANN).status_code == 303  # control


def test_the_pkce_verifier_is_a_verifier_rfc_7636_accepts() -> None:
    """PKCE S256 per RFC 7636: the verifier is 43 to 128 unreserved characters, and its challenge is the S256 of it (DC-8)."""
    world = World(tenants={T1: [ANN]})
    world.sign_in(ANN)
    started, finished = world.signin.started[-1], world.signin.finished[-1]
    assert PKCE_VERIFIER.fullmatch(finished.code_verifier), len(finished.code_verifier)
    assert started.code_challenge == pkce_challenge(finished.code_verifier)  # control


@pytest.mark.parametrize("where", ["finish_signin", "has_otp"])
def test_a_callback_the_provider_cannot_serve_opens_no_session_and_still_clears_the_prelogin_cookie(where: str) -> None:
    """Whatever the outcome, the callback clears the pre-login cookie (DC-6); an unavailable provider opens no session."""
    world = lab()
    browser = world.client(raise_errors=False)
    if where == "finish_signin":
        world.signin.unavailable_signins = 1
        failed = world.sign_in_response(browser, ME)
    else:
        world.signin.raise_on_has_otp = SignInUnavailable("keycloak is down")
        failed = world.sign_in_response(browser, OPS, amr=("pwd",))
    assert world.signin.every_call[-1] == where  # control: the failure was the one scripted
    assert failed.status_code >= 400
    assert set_cookie(failed, SESSION_COOKIE) is None
    assert SESSION_COOKIE not in browser.cookies
    assert is_cleared(set_cookie(failed, PRELOGIN_COOKIE) or ""), failed.headers.get_list("set-cookie")


def test_the_prelogin_cookie_is_gone_after_the_callback_and_a_second_callback_is_refused() -> None:
    """The pre-login state works once (DC-6)."""
    world = World(tenants={T1: [ANN]})
    browser = world.client()
    state = world.begin_signin(browser)
    assert browser.cookies.get(PRELOGIN_COOKIE)
    first = world.sign_in_response(browser, ANN, begin=False, state=state)
    assert first.status_code == 303
    assert PRELOGIN_COOKIE not in browser.cookies
    again = world.sign_in_response(browser, ANN, begin=False, state=state)
    never_started = world.sign_in_response(world.client(), ANN, begin=False)
    assert again.status_code == never_started.status_code == 403
    assert problem_type(again) == problem_type(never_started)


def test_an_active_user_with_no_tenants_signs_in_and_sees_none() -> None:
    """Zero tenants is valid: /me shows none and tenant routes are 404 (flow 2, O3)."""
    world, _, bob = two_tenants()
    assert bob.delete(f"/tenants/{T2}/members/{user_id(bob)}").status_code == 204
    afresh = world.sign_in(BOB)
    body = me(afresh)
    assert (body["tenants"], body["invitations"]) == ([], [])
    assert afresh.get(f"/tenants/{T2}/alerts").status_code == 404


def test_a_revoked_invitation_is_not_joined_at_first_sign_in() -> None:
    """Revoke first, then the sign-in: the revocation wins (flow 6, DC-8)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, NEW)
    world.invite(bob, T2, NEW)
    world.send_pending()
    assert bob.delete(f"/tenants/{T2}/invitations/{invitation_id(bob, T2, NEW)}").status_code == 204
    n = world.sign_in(NEW)
    assert tenants_of(n) == {T1}
    assert n.get(f"/tenants/{T2}/alerts").status_code == 404


MINUTE = _dt.timedelta(minutes=1)


def test_idle_expiry_is_twelve_hours_from_a_last_seen_written_only_when_over_five_minutes_old() -> None:
    """Idle when `now - last_seen > 12h`; a request moves last-seen only if it is over 5 minutes old (O6)."""
    world = World(tenants={T1: [ANN]})
    a, b, c, d, e = (world.sign_in(ANN) for _ in range(5))
    world.clock.now = T0 + 5 * MINUTE
    assert c.get("/me").status_code == 200  # exactly 5 minutes: not written
    world.clock.now = T0 + 5 * MINUTE + SECOND
    assert d.get("/me").status_code == 200  # over 5 minutes: written
    world.clock.now = T0 + 6 * MINUTE
    assert b.get("/me").status_code == 200  # written
    world.clock.now = T0 + 12 * HOUR
    assert e.get("/me").status_code == 200  # exactly 12 hours idle is not over the limit
    world.clock.now = T0 + 12 * HOUR + SECOND
    assert [x.get("/me").status_code for x in (a, c, b, d, e)] == [401, 401, 200, 200, 200]


@pytest.mark.parametrize("limit", ["idle", "absolute"])
def test_an_expired_session_stays_expired_however_often_it_is_sent(limit: str) -> None:
    """A refused request does not revive the session it refused (O6: 12 hours idle, 7 days at most)."""
    world = World(tenants={T1: [ANN]})
    ann = world.sign_in(ANN)
    if limit == "idle":
        world.clock.now = T0 + 12 * HOUR + SECOND
    else:
        for _ in range(28):
            world.clock.advance(6 * HOUR)
            ann.get("/me")
        world.clock.now = T0 + SEVEN_DAYS + SECOND
    assert ann.get("/me").status_code == 401
    world.clock.advance(MINUTE)
    assert ann.get("/me").status_code == 401
    assert ann.get(f"/tenants/{T1}/alerts").status_code == 401


def test_a_session_ends_seven_days_after_sign_in_however_busy() -> None:
    """Absolute 7-day limit (O6)."""
    world = World(tenants={T1: [ANN]})
    ann = world.sign_in(ANN)
    for _ in range(27):
        world.clock.advance(6 * HOUR)
        assert ann.get("/me").status_code == 200
    world.clock.now = T0 + SEVEN_DAYS - SECOND
    assert ann.get("/me").status_code == 200
    world.clock.now = T0 + SEVEN_DAYS + SECOND
    assert ann.get("/me").status_code == 401


def test_the_session_value_is_random_and_only_a_hash_of_it_is_stored() -> None:
    """Random values; neither the repository nor the service keeps a cookie value (O6, DC-8)."""
    world = World(tenants={T1: [ANN, BOB]})
    browsers = [world.sign_in(ANN), world.sign_in(ANN), world.sign_in(BOB), world.sign_in(BOB)]
    values = [b.cookies[SESSION_COOKIE] for b in browsers]
    assert len(set(values)) == len(values)
    assert all(len(v) >= 32 for v in values)
    people = {ANN: user_id(browsers[0]), BOB: user_id(browsers[2])}
    for value in values:  # nothing about the person is in the value, and no two share a stem
        for email, uid in people.items():
            assert uid not in value
            assert email not in value
    assert len({v[:8] for v in values}) == len(values)
    for i, v in enumerate(values):  # random: two values agree in few positions, not a shared clock or host part
        for w in values[i + 1:]:
            same = sum(1 for x, y in zip(v, w, strict=False) if x == y)
            assert same < min(len(v), len(w)) // 2, (v, w)
    assert repo_holds(world.repo, ANN)  # control: the walk reaches what the repository holds
    assert repo_holds(world.service, ANN)  # control: and what the service holds
    assert not any(repo_holds(world.repo, v) or repo_holds(world.service, v) for v in values)
    assert all(b.get("/me").status_code == 200 for b in browsers)


def test_a_bearer_header_is_not_a_session_and_a_401_offers_no_bearer_challenge() -> None:
    """The value works only as the cookie; the refusal does not invite Bearer (O6)."""
    world = World(tenants={T1: [ANN]})
    value = world.sign_in(ANN).cookies[SESSION_COOKIE]
    bearer = world.client()
    refused = bearer.get("/me", headers={"Authorization": f"Bearer {value}"})
    assert refused.status_code == 401
    assert "bearer" not in refused.headers.get("www-authenticate", "").lower()
    for name in ("defender_session", "__Secure-defender_session", "session"):  # DC-6: only the __Host- name
        assert world.client_with_cookie(value, name=name).get("/me").status_code == 401, name
    assert world.client_with_cookie(value).get("/me").status_code == 200


def test_a_session_of_a_user_who_is_not_active_is_not_a_caller() -> None:
    """Each request reads the user: a session row of an `invited` user is 401 (flow 4, P-A)."""
    world = World(tenants={T1: [ANN]})
    world.invite(world.sign_in(ANN), T1, NEW)
    invited = world.call(world.repo.user_by_email, NEW)
    assert invited.status == "invited"
    world.call(world.repo.add_session, "seeded-session-of-an-invited-user-0123", invited.id, now=T0, expires_at=T0 + SEVEN_DAYS)
    assert world.client_with_cookie("seeded-session-of-an-invited-user-0123").get("/me").status_code == 401
    ann = world.call(world.repo.user_by_email, ANN)  # control: the same seeding for an active user is a caller
    world.call(world.repo.add_session, "seeded-session-of-an-active-user-01234", ann.id, now=T0, expires_at=T0 + SEVEN_DAYS)
    assert world.client_with_cookie("seeded-session-of-an-active-user-01234").get("/me").status_code == 200


class _Scene:
    def __init__(self) -> None:
        self.world = World(administrators=[OPS_EMAIL], tenants={T1: [ANN], T2: [BOB]})
        self.world.register(EMPTY)
        self.ann, self.bob = self.world.sign_in(ANN), self.world.sign_in(BOB)
        self.ops = self.world.sign_in_admin(OPS_EMAIL)
        self.nina = self.world.member(self.ann, T1, NINA)
        self.world.invite(self.ann, T1, NEW)
        self.world.invite(self.ann, T1, BOB)
        self.world.send_pending()
        self.revoke_id = invitation_id(self.ann, T1, NEW)
        self.accept_id = me(self.bob)["invitations"][0]["id"]
        self.nina_id = user_id(self.nina)


Op = tuple[str, Callable[[Any, _Scene], Any], int, Callable[[_Scene], bool]]


REQUEST_OPS: dict[str, Op] = {
    "invite": ("ann", lambda c, s: c.post(f"/tenants/{T1}/invitations", json={"email": "zed@z.example"}), 202,
               lambda s: "zed@z.example" not in {r["email"] for r in invitation_rows(s.ann, T1)}),
    "revoke": ("ann", lambda c, s: c.delete(f"/tenants/{T1}/invitations/{s.revoke_id}"), 204,
               lambda s: any(r["id"] == s.revoke_id for r in invitation_rows(s.ann, T1))),
    "remove": ("ann", lambda c, s: c.delete(f"/tenants/{T1}/members/{s.nina_id}"), 204,
               lambda s: NINA in {m["email"] for m in items(s.ann.get(f"/tenants/{T1}/members"))}),
    "accept": ("bob", lambda c, s: c.post(f"/invitations/{s.accept_id}/accept"), 200,
               lambda s: tenants_of(s.bob) == {T2}),
    "logout": ("ann", lambda c, s: c.post("/auth/logout"), 204,
               lambda s: s.ann.get("/me").status_code == 200),
    "admin-invite": ("ops", lambda c, s: c.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": "zed@z.example"}),
                     202, lambda s: not s.world.call(s.world.repo.memberships_of_tenant, EMPTY)),
}


FORGED_ORIGINS = [
    "https://evil.example", FRONTEND_ORIGIN + ".evil.example", "null", None,
    FRONTEND_ORIGIN.replace("https://", "http://"),  # a scheme downgrade is another origin
    "https://evil.example/" + FRONTEND_ORIGIN,  # ends with the configured origin
    FRONTEND_ORIGIN + ":8443",  # another port is another origin
]


@pytest.mark.parametrize("name", sorted(REQUEST_OPS))
@pytest.mark.parametrize("origin", FORGED_ORIGINS)
def test_a_state_changing_request_without_the_frontend_origin_is_refused_and_changes_nothing(
        name: str, origin: str | None) -> None:
    """Missing or foreign Origin -> 403, nothing changes; the right Origin works (O6, incl. logout, accept and the platform route)."""
    scene = _Scene()
    who, request, success, untouched = REQUEST_OPS[name]
    actor = {"ann": scene.ann, "bob": scene.bob, "ops": scene.ops}[who]
    cookie = actor.cookies[SESSION_COOKIE]
    refused = request(scene.world.client_with_cookie(cookie, origin=origin), scene)
    assert refused.status_code == 403
    assert untouched(scene)
    allowed = request(scene.world.client_with_cookie(cookie, origin=FRONTEND_ORIGIN), scene)
    assert allowed.status_code == success


def test_a_forged_request_is_refused_before_its_body_is_read() -> None:
    """O6: a body that would not parse still gets the 403, not a 422 that says how it was read."""
    world, ann_session, _ = two_tenants()
    path = f"/tenants/{T1}/invitations"
    forged = world.client_with_cookie(ann_session.cookies[SESSION_COOKIE], origin="https://evil.example")
    for body in ("{", '{"email": 7}'):
        assert forged.post(path, content=body, headers={"content-type": "application/json"}).status_code == 403
    allowed = world.client_with_cookie(ann_session.cookies[SESSION_COOKIE])
    assert allowed.post(path, content="{", headers={"content-type": "application/json"}).status_code == 422  # control


def test_the_origin_is_checked_before_the_session_and_only_for_state_changing_methods() -> None:
    """Check order Origin, session, tenant; GET needs no Origin (O6)."""
    world, _, _ = two_tenants()
    path = f"/tenants/{T1}/invitations"
    assert world.client(origin=None).post(path, json={"email": NEW}).status_code == 403
    assert world.client().post(path, json={"email": NEW}).status_code == 401
    assert world.client(origin=None).get("/me").status_code == 401
    ann = world.sign_in(ANN)
    no_origin = world.client_with_cookie(ann.cookies[SESSION_COOKIE], origin=None)
    assert no_origin.get("/me").status_code == 200
    assert no_origin.post(f"/tenants/{T2}/invitations", json={"email": NEW}).status_code == 403  # not 404


BAD_TENANT = "not-a-tenant-id"


def test_a_request_without_a_valid_session_cookie_is_401_with_no_bearer_challenge() -> None:
    """No credential, or an unknown cookie value -> 401 without a Bearer challenge (O1, O6)."""
    world, ann, _ = two_tenants()
    assert ann.get("/me").status_code == 200
    for browser in (world.client(), world.client_with_cookie("no-such-session")):
        # Check order: the session before the tenant, so an unknown or malformed tenant is 401 too.
        for path in (f"/tenants/{T1}/alerts", f"/tenants/{UNKNOWN}/alerts", f"/tenants/{BAD_TENANT}/alerts",
                     f"/tenants/{BAD_TENANT}/members", "/me", "/admin/tenants"):
            response = browser.get(path)
            assert response.status_code == 401, path
            assert "bearer" not in response.headers.get("www-authenticate", "").lower()


@pytest.mark.parametrize("other", [T2, UNKNOWN])
def test_a_non_member_and_an_unknown_tenant_get_the_same_404(other: str) -> None:
    """A member reaches their tenant; every other tenant answers alike (O1/P-D). A malformed id is a 422 (#1382)."""
    world, ann, _ = two_tenants()
    assert ann.get(f"/tenants/{T1}/alerts").status_code == 200
    reference = ann.get(f"/tenants/{UNKNOWN}/alerts")
    probed = ann.get(f"/tenants/{other}/alerts")
    assert probed.status_code == reference.status_code == 404
    assert probed.headers["content-type"] == reference.headers["content-type"]
    assert masked(probed, other) == masked(reference, UNKNOWN)


@pytest.mark.parametrize(("method", "path", "body"), [
    ("GET", "members", None),
    ("GET", "invitations", None),
    ("POST", "invitations", {"email": NEW}),
])
def test_every_tenant_route_gives_a_non_member_the_same_404_as_an_unknown_tenant(
        method: str, path: str, body: object) -> None:
    """P-D holds on the people routes as well as the data routes (O1/P-D)."""
    _, ann, _ = two_tenants()
    asked = ann.request(method, f"/tenants/{T2}/{path}", json=body)
    unknown = ann.request(method, f"/tenants/{UNKNOWN}/{path}", json=body)
    assert asked.status_code == unknown.status_code == 404
    assert masked(asked, T2) == masked(unknown, UNKNOWN)
    assert items(ann.get(f"/tenants/{T1}/invitations")) == []  # nothing was written into T1


def test_another_tenants_invitation_or_member_id_is_the_same_404_as_a_missing_one() -> None:
    """An id of another tenant's invitation or member is indistinguishable from none (P-D)."""
    world, ann, bob = two_tenants()
    world.invite(bob, T2, NEW)
    foreign_invitation = invitation_id(bob, T2, NEW)
    bob_id = user_id(bob)
    revoke_foreign = ann.delete(f"/tenants/{T1}/invitations/{foreign_invitation}")
    revoke_missing = ann.delete(f"/tenants/{T1}/invitations/{NO_SUCH_ID}")
    remove_foreign = ann.delete(f"/tenants/{T1}/members/{bob_id}")
    remove_missing = ann.delete(f"/tenants/{T1}/members/{NO_SUCH_ID}")
    assert revoke_foreign.status_code == revoke_missing.status_code == 404
    assert remove_foreign.status_code == remove_missing.status_code == 404
    assert masked(revoke_foreign, foreign_invitation) == masked(revoke_missing, NO_SUCH_ID)
    assert masked(remove_foreign, bob_id) == masked(remove_missing, NO_SUCH_ID)
    # positive control: nothing of T2 was touched, and the owner can still act on both
    assert tenants_of(bob) == {T2}
    assert bob.delete(f"/tenants/{T2}/invitations/{foreign_invitation}").status_code == 204


def test_an_invitation_id_of_someone_else_or_nobody_is_the_same_404_at_accept() -> None:
    """Accepting another person's invitation id looks like accepting none (flow 3, P-D)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, BOB)
    world.send_pending()
    mine = me(bob)["invitations"][0]["id"]
    elsewhere = world.sign_in(ANN)  # ann is not the invitee
    refused = elsewhere.post(f"/invitations/{mine}/accept")
    missing = elsewhere.post(f"/invitations/{NO_SUCH_ID}/accept")
    assert refused.status_code == missing.status_code == 404
    assert masked(refused, mine) == masked(missing, NO_SUCH_ID)
    assert problem_type(refused) == problem_type(missing)
    assert bob.post(f"/invitations/{mine}/accept").status_code == 200


def test_a_member_of_two_tenants_reads_and_writes_only_in_the_paths_tenant() -> None:
    """The path's tenant, not one of the caller's others, is the tenant every data route acts in (P-D, O7)."""
    world, ann, bob = two_tenants()
    other = ALERT.model_copy(update={"alert_id": "a1000000-0000-4000-8000-000000000002", "title": "T2's own"})
    world.store.add_alert(T2, other)
    world.invite(bob, T2, ANN)
    world.send_pending()
    [invitation] = me(ann)["invitations"]
    assert ann.post(f"/invitations/{invitation['id']}/accept").status_code == 200
    assert tenants_of(ann) == {T1, T2}
    for tenant, own, foreign in ((T1, ALERT, other), (T2, other, ALERT)):
        summary = AlertSummary.model_validate(own.model_dump(exclude={"raw"})).model_dump(mode="json")
        assert items(ann.get(f"/tenants/{tenant}/alerts")) == [summary], tenant
        assert ann.get(f"/tenants/{tenant}/alerts/{own.alert_id}").json() == own.model_dump(mode="json")
        assert ann.get(f"/tenants/{tenant}/alerts/{foreign.alert_id}").status_code == 404, tenant
    created = ann.post(f"/tenants/{T2}/investigations", json={"alert_id": "a1000000-0000-4000-8000-000000000002", "client_request_id": "r1"})
    assert created.status_code == 201, created.text
    [event] = world.store.audit_events
    assert (event.tenant_id, event.user_id) == (T2, user_id(ann))
    assert items(ann.get(f"/tenants/{T1}/investigations")) == []
    assert [i["investigation_id"] for i in items(bob.get(f"/tenants/{T2}/investigations"))] == [
        created.json()["investigation_id"]]


def test_the_alerts_routes_answer_unchanged_under_the_tenant_prefix() -> None:
    """Existing routes move under /tenants/{T}/ with unchanged behaviour (O7)."""
    _, ann, _ = two_tenants()
    assert items(ann.get(f"/tenants/{T1}/alerts")) == [SUMMARY.model_dump(mode="json")]
    assert ann.get(f"/tenants/{T1}/alerts/a1000000-0000-4000-8000-000000000001").json() == ALERT.model_dump(mode="json")
    assert ann.get("/alerts").status_code == 404
