"""#1161 piece 1: the sign-in routes in process (P2, B2, B4, S1, D6) and the identity service's pre-login record.

The app is the real one over the identity world's fake sign-in port; the real server and Keycloak's front channel are
in `test_1083_real_server.py`. The sign-in-failed screen is a frontend address (S2): these tests read its 303s."""
from __future__ import annotations

import json
import logging
import urllib.parse
from importlib import resources
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.identity import Refused, SignedIn, attempt_cookie  # noqa: E402
from defender.records._run_id import _UUID_TEXT  # noqa: E402
from defender.tests.support.api._flow1161 import REASONS, cookies_set, failed, location  # noqa: E402
from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
    ME,
    OPS,
    SESSION_COOKIE,
    SIGNIN_URL,
    T1,
    FakeSignIn,
    SignInUnavailable,
    VerifiedSignIn,
    World,
    cookie_attributes,
    is_cleared,
    lab,
    me,
    set_cookie,
)
from defender.tests.support.frontend._shapes1161 import (  # noqa: E402
    RETURNABLE,
    SHAPES,
    UUID,
    classify,
    generated_set,
    members,
)
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402

pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]

INV = fixture_uuid("investigation:1161-a")
INV_B = fixture_uuid("investigation:1161-b")
RET = f"/t/{T1}/investigations/{INV}"
RET_B = f"/t/{T1}/investigations/{INV_B}"
BAD_REQUEST = "/sign-in-failed?reason=bad-request"
LOGIN, CALLBACK = "/api/auth/login", "/api/auth/callback"


def _state(url: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["state"][0]


def _arrive(world: World, browser: Any, state: str | None, *, code: str | None = "c-1", who: str = ME,
            amr: tuple[str, ...] = ("pwd",), account_id: str | None = None,
            extra: tuple[tuple[str, str], ...] = ()) -> Any:
    """The browser at the callback with the provider's answer: `code` (None: none) for `who`, `state` (None: none)."""
    params: list[tuple[str, str]] = [] if state is None else [("state", state)]
    if code is not None:
        world.signin.answers[code] = VerifiedSignIn(account_id=account_id or world.signin.account_for(who),
                                                    name="Pat", amr=amr)
        params.append(("code", code))
    return browser.get(CALLBACK, params=[*params, *extra])


def _errors(caplog: Any) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.ERROR]


# --- P2 / B2: one membership rule over the shapes -----------------------------------------------------------

#: Every member of every returnable shape, a few per shape.
RETURNABLE_MEMBERS = [m for s in SHAPES if s.name in RETURNABLE for m in members(s, 1161, 3)]


@pytest.mark.parametrize("path", RETURNABLE_MEMBERS)
def test_a_returnable_member_is_accepted_and_sign_in_lands_on_it_byte_for_byte(path: str) -> None:
    """A member of a returnable shape signs in and the callback's `Location` is that path exactly. (P2, B4)"""
    world = World(tenants={T1: [ANN]})
    landed = world.sign_in_response(world.client(), ANN, return_path=path)
    assert location(landed) == path
    assert set_cookie(landed, SESSION_COOKIE)


def test_an_absent_return_gives_the_root() -> None:
    """No `return` parameter: sign-in lands on `/`. (P2, B2)"""
    world = World(tenants={T1: [ANN]})
    assert location(world.sign_in_response(world.client(), ANN)) == "/"


@pytest.mark.parametrize("query", [
    [("return", "")],
    [("return", RET), ("return", RET)],
    [("return", "/"), ("return", RET)],
    [("return", RET), ("x", "1")],
    [("x", "1")],
    [("Return", RET)],
    [("return", "/sign-in-failed")],
], ids=["empty", "repeated-same", "repeated-different", "undeclared-beside-return", "undeclared-alone",
        "name-case", "failed-screen-shape"])
def test_a_refused_or_malformed_start_is_a_303_bad_request_with_no_return(query: list[tuple[str, str]]) -> None:
    """Sign-in start reads only `return`, once, and a present `return` must be a returnable member: else 303 `bad-request`. (B2, B4)"""
    world = World(tenants={T1: [ANN]})
    refused = world.client().get(LOGIN, params=query)
    assert failed(refused) == ("bad-request", {})
    assert refused.headers["location"] == BAD_REQUEST
    assert world.client().get(LOGIN, params={"return": RET}).status_code == 302  # control: the judged one starts


def test_a_return_is_decoded_once() -> None:
    """`%2F` is `/` once; `%252F` is the text `%2F`, a non-member. (P2)"""
    world = World(tenants={T1: [ANN]})
    once = world.client().get(f"{LOGIN}?return=%2F")
    twice = world.client().get(f"{LOGIN}?return=%252F")
    assert once.status_code == 302
    assert failed(twice) == ("bad-request", {})


#: B3's generated set: members of every shape and every near miss of them (the in-process half of its three checks).
GENERATED = generated_set(1161, per_shape=1)
CHUNKS = [GENERATED[i:i + 4000] for i in range(0, len(GENERATED), 4000)]


def test_the_generated_set_reaches_every_class_it_claims_to() -> None:
    """Premise of the checks below: the set holds members of each shape, the failed screen's and non-members. (B3)"""
    shapes = {c.shape for c in GENERATED}
    assert {s.name for s in SHAPES} <= shapes
    assert None in shapes
    assert sum(c.returnable for c in GENERATED) > 3
    assert len(GENERATED) > 10_000


@pytest.mark.parametrize("chunk", range(len(CHUNKS)))
def test_login_accepts_exactly_the_members_of_a_returnable_shape(chunk: int) -> None:
    """For every value of the generated set, `/api/auth/login` starts sign-in iff it is a returnable member; else the 303 `bad-request`, never a 500. (P2, B2, B3)"""
    world = World(tenants={T1: [ANN]})
    browser = world.client(raise_errors=False)
    wrong: list[tuple[str, int, str]] = []
    for case in CHUNKS[chunk]:
        answer = browser.get(LOGIN, params={"return": case.value})
        browser.cookies.clear()
        expected = (302, None) if case.returnable else (303, BAD_REQUEST)
        got = (answer.status_code, answer.headers.get("location") if answer.status_code == 303 else None)
        if got != expected:
            wrong.append((case.value, answer.status_code, answer.headers.get("location", "")))
    assert wrong[:10] == []


def test_the_address_reader_agrees_with_the_shape_text_on_the_generated_set() -> None:
    """`defender.api.addresses.match` names the shape the test's classifier names, or none; `RETURNABLE` is the flagged ones. (S2, P2)"""
    from defender.api import addresses

    assert set(addresses.RETURNABLE) == set(RETURNABLE)
    wrong = [c.value for c in GENERATED if addresses.match(c.value) != c.shape]
    assert wrong[:10] == []


def test_the_shape_files_uuid_grammar_is_the_records_one() -> None:
    """The uuid placeholder's grammar is `_run_id._UUID_TEXT.pattern`, in the test's shape text and in the repo's address file. (S2, R14)"""
    assert _UUID_TEXT.pattern == UUID
    text = resources.files("defender.api").joinpath("addresses.json").read_text(encoding="utf-8")
    assert json.loads(text)["placeholders"]["uuid"] == _UUID_TEXT.pattern
    assert classify(f"/t/{INV}/investigations/{INV}") == "investigation"  # control: the pattern is what the classifier uses


# --- B4: the callback ---------------------------------------------------------------------------------------

def _outcome_world() -> World:
    world = lab()
    world.signin.has_otp_answers[world.signin.account_for(OPS)] = True
    return world


def _arrival_cases() -> list[Any]:
    def set_attr(name: str, value: Any) -> Any:
        return lambda w: setattr(w.signin, name, value)

    return [
        pytest.param({}, None, id="success"),
        pytest.param({"account_id": "kc-not-ours"}, "unknown-account", id="unknown-account"),
        pytest.param({"who": OPS, "amr": ("pwd",)}, "otp-required", id="otp-required"),
        pytest.param({"setup": set_attr("refuse_signins", 1)}, "login-attempt-invalid", id="token-refused"),
        pytest.param({"code": None}, "login-attempt-invalid", id="no-code"),
        pytest.param({"code": None, "extra": (("error", "access_denied"),)}, "login-attempt-invalid", id="provider-error"),
        pytest.param({"setup": set_attr("unavailable_signins", 1)}, "unavailable", id="provider-unreachable"),
        pytest.param({"setup": set_attr("raise_on_has_otp", SignInUnavailable("down")), "who": OPS},
                     "unavailable", id="otp-check-unreachable"),
    ]


@pytest.mark.parametrize(("arrival", "reason"), _arrival_cases())
def test_every_callback_outcome_is_a_303_and_a_refusal_carries_its_reason_and_the_attempts_return(
        arrival: dict[str, Any], reason: str | None) -> None:
    """Success goes to the judged path byte for byte; each refusal to `/sign-in-failed` with its reason and the `return` its own cookie supplied; no session on a refusal. (B4, S1)"""
    world = _outcome_world()
    arrival = dict(arrival)
    setup = arrival.pop("setup", None)
    browser = world.client()
    state = world.begin_signin(browser, RET)
    if setup:
        setup(world)
    answer = _arrive(world, browser, state, **arrival)
    if reason is None:
        assert location(answer) == RET
        assert browser.cookies.get(SESSION_COOKIE)
    else:
        assert failed(answer) == (reason, {"return": RET})
        assert SESSION_COOKIE not in browser.cookies
        assert set_cookie(answer, SESSION_COOKIE) is None
    assert is_cleared(set_cookie(answer, attempt_cookie(state) or "") or "")


@pytest.mark.parametrize("state", [None, "", "not-the-state", "x" * 5000, "a b", "é"], ids=[
    "missing", "empty", "unknown", "overlong", "space", "non-ascii"])
def test_a_callback_with_no_usable_state_is_prelogin_missing_with_no_return_and_keeps_the_other_cookies(
        state: str | None) -> None:
    """A state that names none of the browser's attempts: `prelogin-missing`, no `return`, only its own cookie name cleared; the open attempt then completes. (B4, D6)"""
    world = lab()
    browser = world.client()
    real = world.begin_signin(browser, RET)
    answer = _arrive(world, browser, state)
    assert failed(answer) == ("prelogin-missing", {})
    own = None if state is None else attempt_cookie(state)  # the callback clears its own, on every answer (data model)
    assert [n for n in cookies_set(answer) if n != SESSION_COOKIE] == ([] if own is None else [own]), cookies_set(answer)
    if own is not None:
        assert is_cleared(set_cookie(answer, own) or ""), set_cookie(answer, own)
    assert browser.cookies.get(attempt_cookie(real))
    assert location(_arrive(world, browser, real)) == RET  # control: it was kept and still works


def test_another_attempts_cookie_never_supplies_a_return() -> None:
    """The browser holds attempt A's cookie; the callback is attempt B's: `prelogin-missing` with no `return`, A untouched. (B4, D6)"""
    world = lab()
    a, b = world.client(), world.client()
    state_a, state_b = world.begin_signin(a, RET), world.begin_signin(b, RET_B)
    answer = _arrive(world, a, state_b)
    assert failed(answer) == ("prelogin-missing", {})
    assert a.cookies.get(attempt_cookie(state_a))
    assert location(_arrive(world, b, state_b)) == RET_B  # control: B's own browser completes it


def test_the_callback_ignores_unknown_parameters_and_takes_the_last_of_a_repeated_one() -> None:
    """`session_state`, `iss` and others are ignored; a repeated `code` or `state` gives its last value, which must still name the attempt. (B4)"""
    world = World(tenants={T1: [ANN, BOB]})
    for name, value in (("session_state", "s"), ("iss", "https://idp.example"), ("whatever", "1")):
        browser = world.client()
        state = world.begin_signin(browser, RET)
        assert location(_arrive(world, browser, state, who=ANN, extra=((name, value),))) == RET, name
    browser = world.client()
    state = world.begin_signin(browser, RET)
    world.signin.answers["c-ann"] = VerifiedSignIn(account_id=world.signin.account_for(ANN), name="A", amr=("pwd",))
    world.signin.answers["c-bob"] = VerifiedSignIn(account_id=world.signin.account_for(BOB), name="B", amr=("pwd",))
    done = browser.get(CALLBACK, params=[("state", "junk"), ("state", state), ("code", "c-ann"), ("code", "c-bob")])
    assert location(done) == RET
    assert me(browser)["user"]["email"] == BOB  # the last `code`
    other = world.client()
    state2 = world.begin_signin(other, RET)
    refused = other.get(CALLBACK, params=[("state", state2), ("state", "junk"), ("code", "c-ann")])
    assert failed(refused) == ("prelogin-missing", {})  # the last `state` names no attempt


# --- S1 binds GET -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("origin", [True, False], ids=["frontend-origin", "no-origin"])
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD"])
@pytest.mark.parametrize("path", [LOGIN, CALLBACK])
def test_the_sign_in_routes_answer_code_to_any_method_but_get(path: str, method: str, origin: bool) -> None:
    """Another method is the origin check's 403 or a 405, never a redirect and never a cookie. (B4, S1)"""
    world = World(tenants={T1: [ANN]})
    browser = world.client(origin=world.client().headers.get("Origin") if origin else None)
    refused = browser.request(method, path, params={"return": RET} if path == LOGIN else {"state": "s", "code": "c"})
    assert refused.status_code in (403, 405), refused.status_code
    assert not refused.headers.get_list("set-cookie")
    assert world.client().get(LOGIN).status_code == 302  # control: GET starts


# --- internal faults --------------------------------------------------------------------------------------

class _Raising(FakeSignIn):
    """A sign-in port that fails as a bug would, not as the provider refuses (a test-only injection)."""

    def __init__(self, *, begin: bool = False, finish: bool = False) -> None:
        super().__init__()
        self.begin, self.finish = begin, finish

    async def begin_signin(self, state: str, nonce: str, code_challenge: str) -> str:
        if self.begin:
            raise RuntimeError("internal fault in sign-in start")
        return await super().begin_signin(state, nonce, code_challenge)

    async def finish_signin(self, code: str, code_verifier: str, nonce: str) -> VerifiedSignIn:
        if self.finish:
            raise RuntimeError("internal fault in the callback")
        return await super().finish_signin(code, code_verifier, nonce)


def test_an_internal_fault_on_sign_in_start_is_logged_as_an_error_and_answers_error(caplog: Any) -> None:
    """A fault is `reason=error`, not a `bad-request`, and is logged at error level. (B4, S1, principle 2)"""
    world = World(tenants={T1: [ANN]})
    caplog.set_level(logging.INFO)
    assert world.client().get(LOGIN, params={"return": RET}).status_code == 302
    assert _errors(caplog) == []  # control: the healthy start logs no error
    world.signin = _Raising(begin=True)
    world.build(administrators=(), tenants={})
    answer = world.client(raise_errors=False).get(LOGIN, params={"return": RET})
    assert failed(answer) == ("error", {})
    assert not answer.headers.get_list("set-cookie")
    assert _errors(caplog)


def test_a_sign_in_start_the_provider_cannot_serve_is_a_303_unavailable_without_a_cookie() -> None:
    """The provider unreachable when sign-in starts: 303 to the failed screen with `reason=unavailable`, no cookie set; the
    next start, once it is back, is the 302. (S1, B4)"""
    world = World(tenants={T1: [ANN]})
    world.signin.unavailable_begins = 1
    answer = world.client(raise_errors=False).get(LOGIN, params={"return": RET})
    assert failed(answer)[0] == "unavailable"
    assert not answer.headers.get_list("set-cookie")
    assert world.signin.every_call[-1] == "begin_signin" and not world.signin.started  # control: the scripted failure was reached
    again = world.client().get(LOGIN, params={"return": RET})
    assert again.status_code == 302, again.text  # control: the same request starts when the provider is back


def test_an_internal_fault_on_the_callback_is_logged_answers_error_without_return_and_clears_its_cookie(caplog: Any) -> None:
    """A fault after the attempt's cookie was read: `reason=error`, no `return`, the attempt's cookie cleared, an error logged. (B4, S1, D6)"""
    world = World(tenants={T1: [ANN]})
    caplog.set_level(logging.INFO)
    done = world.client()
    assert location(world.sign_in_response(done, ANN, return_path=RET)) == RET
    assert _errors(caplog) == []  # control
    world.signin = _Raising(finish=True)
    world.build(administrators=(), tenants={})
    browser = world.client(raise_errors=False)
    state = world.begin_signin(browser, RET)
    answer = _arrive(world, browser, state, who=ANN, account_id="acct")
    assert failed(answer) == ("error", {})
    assert is_cleared(set_cookie(answer, attempt_cookie(state) or "") or "")
    assert SESSION_COOKIE not in browser.cookies
    assert _errors(caplog)


# --- D6: one `__Host-` cookie per attempt -----------------------------------------------------------------

def test_attempt_cookie_is_pure_and_the_one_source_of_the_name() -> None:
    """The same state names the same cookie, distinct states distinct ones, `__Host-` prefixed; the name login sets is that. (D6, data model)"""
    world = World(tenants={T1: [ANN]})
    states = []
    for _ in range(4):
        login = world.client().get(LOGIN)
        states.append(_state(login.headers["location"]))
        assert list(cookies_set(login)) == [attempt_cookie(states[-1])]
    names = [attempt_cookie(s) for s in states]
    assert all(n is not None and n.startswith("__Host-") for n in names)
    assert len(set(names)) == 4
    assert names == [attempt_cookie(s) for s in states]


@pytest.mark.parametrize("state", ["", " ", "a b", "a;b", "a=b", "a,b", "a\nb", "a\x00b", "é", "../x", "x" * 5000])
def test_a_state_of_any_other_shape_names_no_cookie(state: str) -> None:
    """`attempt_cookie` answers None for a state that cannot be one of ours (empty, spaces, cookie syntax, controls, non-ASCII, huge). (data model)"""
    assert attempt_cookie(state) is None
    world = World(tenants={T1: [ANN]})
    assert attempt_cookie(_state(world.client().get(LOGIN).headers["location"])) is not None  # control


def test_the_prelogin_cookie_has_every_d6_attribute_and_every_clear_repeats_them() -> None:
    """HttpOnly, Secure, SameSite=Lax, Path=/, no Domain, Max-Age 600, `__Host-`; the clearing header keeps the same. (D6)"""
    world = World(tenants={T1: [ANN]})
    browser = world.client()
    state = world.begin_signin(browser, RET)
    name = attempt_cookie(state) or ""
    login = world.client().get(LOGIN, params={"return": RET})
    fresh = attempt_cookie(_state(login.headers["location"])) or ""
    attrs = cookie_attributes(set_cookie(login, fresh) or "")
    assert fresh.startswith("__Host-")
    assert {"httponly", "secure"} <= set(attrs)
    assert (attrs["samesite"].lower(), attrs["path"], attrs["max-age"]) == ("lax", "/", "600")
    assert "domain" not in attrs
    cleared = _arrive(world, browser, state, who=ANN)
    assert is_cleared(set_cookie(cleared, name) or "")


@pytest.mark.parametrize(("arrival", "reason"), [
    pytest.param({}, None, id="success"),
    pytest.param({"account_id": "kc-not-ours"}, "unknown-account", id="unknown-account"),
    pytest.param({"code": None}, "login-attempt-invalid", id="no-code"),
])
def test_the_callback_clears_only_its_own_cookie_and_the_other_attempts_survive(
        arrival: dict[str, Any], reason: str | None) -> None:
    """Two attempts in one browser: the answer clears the callback's own cookie only; the other is neither set nor cleared. (D6)"""
    world = lab()
    browser = world.client()
    mine, other = world.begin_signin(browser, RET), world.begin_signin(browser, RET_B)
    answer = _arrive(world, browser, mine, **arrival)
    headers = cookies_set(answer)
    assert is_cleared(headers[attempt_cookie(mine) or ""])
    assert attempt_cookie(other) not in headers
    assert browser.cookies.get(attempt_cookie(other))
    assert (reason is None) == (SESSION_COOKIE in browser.cookies)


def test_a_fault_still_clears_only_the_callbacks_own_cookie() -> None:
    """`error` clears the attempt's own cookie and leaves the others. (D6, B4)"""
    world = World(tenants={T1: [ANN]})
    world.signin = _Raising(finish=True)
    world.build(administrators=(), tenants={})
    browser = world.client(raise_errors=False)
    mine, other = world.begin_signin(browser, RET), world.begin_signin(browser, RET_B)
    answer = _arrive(world, browser, mine, who=ANN, account_id="acct")
    assert failed(answer)[0] == "error"
    assert set(cookies_set(answer)) == {attempt_cookie(mine)}
    assert browser.cookies.get(attempt_cookie(other))


def test_an_unprefixed_cookie_of_the_same_name_is_ignored() -> None:
    """Only the `__Host-` name is read: the callback with the unprefixed twin is `prelogin-missing`, with the real one it lands. (D6)"""
    world = lab()
    a, planted = world.client(), world.client()
    state = world.begin_signin(a, RET)
    name = attempt_cookie(state) or ""
    value = a.cookies[name]
    planted.cookies.set(name.removeprefix("__Host-"), value)
    assert failed(_arrive(world, planted, state)) == ("prelogin-missing", {})
    assert location(_arrive(world, a, state)) == RET


@pytest.mark.parametrize("order", [(0, 1), (1, 0)], ids=["first-first", "second-first"])
def test_two_attempts_in_flight_complete_independently_in_either_order(order: tuple[int, int]) -> None:
    """Each tab's callback lands on its own return path whichever completes first. (D6, B1)"""
    world = lab()
    browser = world.client()
    attempts = [(world.begin_signin(browser, p), p) for p in (RET, RET_B)]
    assert attempt_cookie(attempts[0][0]) != attempt_cookie(attempts[1][0])
    for i in order:
        state, path = attempts[i]
        assert location(_arrive(world, browser, state, code=f"c-{i}")) == path
    assert not [n for n in browser.cookies if n.startswith("__Host-") and n != SESSION_COOKIE]


# --- the identity service's pre-login record -------------------------------------------------------------

#: A return path the service must carry without inspecting it, whatever characters (it is not the API's job to judge).
CARRIED = ["/", RET, "/a.b.c", "/x;y,z=w", "/50%25", "/é", "/t/a b", "/" + "q" * 900, "/.", "//", ""]


@pytest.mark.parametrize("path", CARRIED)
def test_the_service_carries_a_return_path_through_the_cookie_unchanged(path: str) -> None:
    """`begin_signin(path)` then `complete_signin` of the same attempt: `SignedIn` with that path, whatever its characters. (data model)"""
    world = lab()
    start = world.call(world.service.begin_signin, path)
    state = _state(start.url)
    assert (start.cookie_name, start.url) == (attempt_cookie(state), f"{SIGNIN_URL}?state={state}")
    assert start.cookie_value
    world.signin.answers["c"] = VerifiedSignIn(account_id=world.signin.account_for(ME), name="Me", amr=("pwd",))
    done = world.call(world.service.complete_signin, state, "c", start.cookie_value)
    assert isinstance(done, SignedIn), done
    assert done.return_path == path
    assert done.session
    assert world.call(world.service.authenticate, done.session)  # the session is real


def _refusal(world: World, state: str, code: str, cookie: str | None) -> Refused:
    result = world.call(world.service.complete_signin, state, code, cookie)
    assert isinstance(result, Refused), result
    assert result.reason in REASONS
    return result


def test_the_service_refuses_as_a_value_with_the_reason_and_the_return_only_this_attempts_cookie_gave() -> None:
    """`complete_signin` returns `Refused(reason, return_path)`: missing, junk or another attempt's cookie is `prelogin-missing` with none. (data model, B4)"""
    world = _outcome_world()
    start = world.call(world.service.begin_signin, RET)
    other = world.call(world.service.begin_signin, RET_B)
    state = _state(start.url)
    world.signin.answers["c"] = VerifiedSignIn(account_id=world.signin.account_for(ME), name="Me", amr=("pwd",))
    for cookie in (None, "", "junk", "a.b.c", other.cookie_value):  # missing, expired and another attempt's read alike
        got = _refusal(world, state, "c", cookie)
        assert (got.reason, got.return_path) == ("prelogin-missing", None), cookie
    for junk_state in ("", "not-the-state", _state(other.url)):
        got = _refusal(world, junk_state, "c", start.cookie_value)
        assert (got.reason, got.return_path) == ("prelogin-missing", None), junk_state
    assert not world.signin.finished, "nothing was exchanged for a callback with no cookie of its attempt"
    assert isinstance(world.call(world.service.complete_signin, state, "c", start.cookie_value), SignedIn)  # control


@pytest.mark.parametrize(("setup", "who", "code", "reason"), [
    ("account", ME, "c", "unknown-account"),
    ("otp", OPS, "c", "otp-required"),
    ("refused", ME, "c", "login-attempt-invalid"),
    ("unreachable", ME, "c", "unavailable"),
    (None, ME, "", "login-attempt-invalid"),
])
def test_the_service_refusals_after_the_cookie_keep_the_return_including_unavailable(
        setup: str | None, who: str, code: str, reason: str) -> None:
    """Every refusal the attempt's own cookie reached carries its return path, so a retry lands where the person was going. (data model)"""
    world = _outcome_world()
    start = world.call(world.service.begin_signin, RET)
    account = "kc-not-ours" if setup == "account" else world.signin.account_for(who)
    world.signin.answers["c"] = VerifiedSignIn(account_id=account, name="Me", amr=("pwd",))
    world.signin.refuse_signins = int(setup == "refused")
    world.signin.unavailable_signins = int(setup == "unreachable")
    got = _refusal(world, _state(start.url), code, start.cookie_value)
    assert (got.reason, got.return_path) == (reason, RET)
