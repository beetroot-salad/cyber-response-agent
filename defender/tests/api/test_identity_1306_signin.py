"""#1306: signing in — login, callback, the pre-login cookie, first sign-in (flow 2, O6, DC-6)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

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
    World,
)


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
