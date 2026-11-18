# ruff: noqa: PT018 — each compound assert states one fact about one page
"""#1161 B1/B8: the app shell's signed-out rule, in the pinned Chromium through the repo's ingress, with the real API
child and the fake provider. Observed through screen markers and `location.pathname`, compared exactly."""
from __future__ import annotations

import urllib.parse
from typing import Any

import pytest

from defender.tests.frontend._flow1161 import (
    until,
    EMAIL,
    ERROR,
    FAILED,
    HOME,
    NO_STORAGE,
    RETRY,
    ROOT,
    SIGN_IN,
    SIGN_OUT,
    WAIT_MS,
    api_calls,
    auth_calls,
    await_aborted,
    logins,
    navigations_to,
    reason,
    screen,
    settle,
    shown,
    sign_in,
    signed_in,
    where,
)
from defender.tests.support.api._server1083 import ANN, SESSION_COOKIE
from defender.tests.support.frontend._browser1161 import abort_login_navigation, path_is, restore_from_cache

KINDS = pytest.mark.parametrize("kind", ["home", "investigation"])



def _target(world: Any, kind: str) -> str:
    return "/home" if kind == "home" else world.screen()


def _read_path(world: Any) -> str:
    return f"/api{world.screen().replace('/t/', '/tenants/', 1)}"


@KINDS
def test_1161_b1_a_signed_out_link_signs_in_once_and_lands_on_it(world, context, requests, kind):
    """No record: sign in with `return` = the target, land on its exact pathname; the record is consumed. (B1, B8)"""
    target = _target(world, kind)
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    screen(page, kind)
    assert where(page) == (target, {})
    assert logins(requests, world.origin) == [target]
    assert signed_in(context)
    assert page.evaluate("sessionStorage.length") == 0
    assert api_calls(requests, world.origin)[0] == ("GET", "/api/me")
    sent = [r for r in requests if path_is(r.url, "/api") and r.url.startswith(world.origin)]
    assert sent, "positive control: the page made API requests"
    assert [r.url for r in sent if "authorization" in r.headers] == [], "no token in the page (B5): the cookie alone"


@KINDS
def test_1161_b1_a_signed_in_load_asks_me_before_the_screens_own_calls(world, context, requests, kind):
    """`/api/me` precedes any other API call of a load; no sign-in starts. (B1.2)"""
    target = _target(world, kind)
    sign_in(world, context)
    mark = len(requests)
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    screen(page, kind)
    settle(page)
    calls = api_calls(requests[mark:], world.origin)
    assert calls[0] == ("GET", "/api/me")
    assert logins(requests[mark:], world.origin) == []
    if kind == "investigation":
        assert ("GET", _read_path(world)) in calls, "positive control: the screen made its own read after /api/me"


@pytest.mark.parametrize("first", [0, 1], ids=["first-tab-first", "second-tab-first"])
def test_1161_b8_two_tabs_signing_in_together_each_land_on_their_own_address(world, context, requests, first):
    """Two authorize requests held, released in either order: each tab lands on its own address. (B8, D6)"""
    one_target, two_target = world.screen(), "/home"
    world.front.hold = True
    one = context.new_page()
    one.goto(f"{world.origin}{one_target}", wait_until="commit")
    world.front.wait_held(1, page=one)
    two = context.new_page()
    two.goto(f"{world.origin}{two_target}", wait_until="commit")
    world.front.wait_held(2, page=two)
    tabs = {0: (one, "investigation", one_target), 1: (two, "home", two_target)}
    for index in (first, 1 - first):
        world.front.release(index)
        page, kind, target = tabs[index]
        screen(page, kind)
        assert where(page) == (target, {})
    assert sorted(x or "" for x in logins(requests, world.origin)) == sorted([one_target, two_target])
    assert shown(one) == "investigation" and shown(two) == "home"


@KINDS
def test_1161_b1_a_return_that_comes_back_without_a_session_is_session_lost_and_retries_once(
        world, context, requests, cookieless_once, kind):
    """The returning load's `/api/me` reaches the API cookie-less: `session-lost` with `return`, no second automatic
    sign-in; the retry lands on the target. (B1.3, B8)"""
    target = _target(world, kind)
    lost = cookieless_once(lambda u: path_is(u, "/api/me"), skip=1)
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    screen(page, FAILED)
    assert lost.done
    assert reason(page) == "session-lost"
    assert where(page) == ("/sign-in-failed", {"reason": "session-lost", "return": target})
    settle(page)
    assert logins(requests, world.origin) == [target]
    page.locator(RETRY).click()
    screen(page, kind)
    assert where(page) == (target, {})
    assert logins(requests, world.origin) == [target, target]


def test_1161_b1_a_later_401_records_a_fresh_attempt_and_redirects(world, context, requests, cookieless_once):
    """The screen's own read answers 401 after `/api/me` succeeded: a second sign-in, not `session-lost`. (B1.3)"""
    target = world.screen()
    lost = cookieless_once(lambda u: urllib.parse.urlsplit(u).path == _read_path(world))
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    page.locator('[data-field="status"]').wait_for()
    assert lost.done
    assert logins(requests, world.origin) == [target, target]
    assert where(page) == (target, {})
    assert navigations_to(requests, world.origin, "/sign-in-failed") == []


def test_1161_b1_a_screen_read_that_always_401s_after_me_succeeds_stops_at_session_lost(world, context, requests):
    """`/api/me` accepts the session but the screen's own read always answers 401: one more sign-in, then
    `session-refused` with `return` (cookies work: `/api/me` took the session), never a third automatic one. (B1.3,
    amended: the loop is bounded for screen reads too)"""
    target = world.screen()
    read = _read_path(world)
    context.route(lambda u: urllib.parse.urlsplit(u).path == read, lambda route: route.fulfill(status=401, body="{}"))
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    screen(page, FAILED)
    settle(page, 1500)
    assert reason(page) == "session-refused"
    assert where(page) == ("/sign-in-failed", {"reason": "session-refused", "return": target})
    assert logins(requests, world.origin) == [target, target]


@pytest.mark.parametrize("failure", ["500", "403", "404", "429", "204", "network"])
def test_1161_b1_a_me_that_is_not_200_or_401_shows_the_error_state_and_the_screen_makes_no_call(
        world, context, requests, failure):
    """Any other answer or a network failure: `data-screen=error`, no screen call, no sign-in. (B1.2, B8)"""
    sign_in(world, context)
    mark = len(requests)

    def handle(route: Any) -> None:
        if failure == "network":
            route.abort()
        else:
            route.fulfill(status=int(failure), body=None if failure == "204" else "x")

    context.route(lambda u: path_is(u, "/api/me"), handle)
    page = context.new_page()
    page.goto(f"{world.origin}{world.screen()}")
    screen(page, ERROR)
    settle(page)
    assert api_calls(requests[mark:], world.origin) == [("GET", "/api/me")]
    assert logins(requests[mark:], world.origin) == []
    assert page.locator('[data-screen="investigation"]').count() == 0


def test_1161_b1_a_screen_that_fails_while_drawing_shows_the_shells_error_state(world, context, requests):
    """Signed in, the screen's read answers, then drawing it throws (a DOM call made to fail): the shell's
    `data-screen=error`, not a page left on `loading`; no sign-in. (B1.4, the shell owns the error state)"""
    sign_in(world, context)
    mark = len(requests)
    context.add_init_script("""
        const set = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function (name, value) {
            if (name === "data-state" && value === "ready") throw new Error("drawing failed");
            return set.call(this, name, value);
        };
    """)
    page = context.new_page()
    page.goto(f"{world.origin}{world.screen()}")
    screen(page, "error")
    assert page.locator('[data-screen="investigation"]').count() == 0
    assert logins(requests[mark:], world.origin) == []


def test_1161_b1_storage_unavailable_shows_the_reason_with_return_and_its_retry_lands_on_the_target(
        world, context, requests):
    """sessionStorage throws: no sign-in starts, `storage-unavailable` with `return`; the retry lands. (B1.3, B8)"""
    target = world.screen()
    context.add_init_script(NO_STORAGE)
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    screen(page, FAILED)
    assert reason(page) == "storage-unavailable"
    assert where(page) == ("/sign-in-failed", {"reason": "storage-unavailable", "return": target})
    settle(page)
    assert logins(requests, world.origin) == []
    page.locator(RETRY).click()
    screen(page, "investigation")
    assert where(page) == (target, {})
    assert logins(requests, world.origin) == [target]


def _prelogin_missing(world: Any, context: Any, requests: list[Any], target: str) -> Any:
    """Clear the attempt's cookie while the provider holds its authorize request, then let it through."""
    world.front.hold = True
    page = context.new_page()
    page.goto(f"{world.origin}{target}", wait_until="commit")
    world.front.wait_held(1, page=page)
    attempt = [c["name"] for c in context.cookies() if c["name"] != SESSION_COOKIE]
    assert attempt, "positive control: the attempt's cookie is set while the provider holds the request"
    for name in attempt:
        context.clear_cookies(name=name)
    world.front.release(0)
    world.front.hold = False
    screen(page, FAILED)
    return page


@KINDS
def test_1161_b1_prelogin_missing_settles_the_tabs_target_into_its_address_and_the_retry_lands_on_it(
        world, context, requests, kind):
    """The callback sends no `return`; the failed screen writes the record's target into its address; retry lands. (B1, B8)"""
    target = _target(world, kind)
    page = _prelogin_missing(world, context, requests, target)
    assert reason(page) == "prelogin-missing"
    assert navigations_to(requests, world.origin, "/sign-in-failed") == [{"reason": "prelogin-missing"}]
    until(page, "location.search.includes('return=')")
    assert where(page) == ("/sign-in-failed", {"reason": "prelogin-missing", "return": target})
    page.locator(RETRY).click()
    screen(page, kind)
    assert where(page) == (target, {})
    assert logins(requests, world.origin) == [target, target]


def test_1161_b1_a_reload_of_the_settled_failed_screen_keeps_its_target_and_the_retry_lands(world, context, requests):
    """After the settle, reloading the failed screen and retrying still lands on the target. (B1, B8)"""
    target = world.screen()
    page = _prelogin_missing(world, context, requests, target)
    until(page, "location.search.includes('return=')")
    page.reload()
    screen(page, FAILED)
    assert reason(page) == "prelogin-missing"
    assert where(page) == ("/sign-in-failed", {"reason": "prelogin-missing", "return": target})
    page.locator(RETRY).click()
    screen(page, "investigation")
    assert where(page) == (target, {})


@KINDS
def test_1161_b8_back_from_the_providers_form_is_sign_in_left_with_return(world, context, requests, kind):
    """`go_back()` from the provider's form is a fresh load of the target reached by history: `sign-in-left` with
    `return`, not `session-lost`. (B8, C44; reason amended)"""
    target = _target(world, kind)
    world.front.form = True
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    page.wait_for_url(lambda url: url.startswith(world.front.origin))
    page.locator(world.front.FORM_BUTTON).wait_for()
    page.go_back()
    screen(page, FAILED)
    assert reason(page) == "sign-in-left"
    assert where(page) == ("/sign-in-failed", {"reason": "sign-in-left", "return": target})
    assert logins(requests, world.origin) == [target]


@KINDS
def test_1161_b8_a_simulated_cache_restore_signed_out_is_sign_in_left_with_return(world, context, requests, kind):
    """The document stays on the target with its record; a `persisted` pageshow shows `sign-in-left`; a non-persisted
    one does nothing. (B1, B8, C44; reason amended)"""
    target = _target(world, kind)
    aborted = abort_login_navigation(context)
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    await_aborted(page, aborted)
    assert where(page)[0] == target
    assert page.evaluate("sessionStorage.length") > 0, "positive control: the shell wrote its attempt record"
    before = len(api_calls(requests, world.origin))
    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: false}))")
    page.wait_for_timeout(700)
    assert len(api_calls(requests, world.origin)) == before and shown(page) != FAILED
    restore_from_cache(page)
    screen(page, FAILED)
    assert reason(page) == "sign-in-left"
    assert where(page) == ("/sign-in-failed", {"reason": "sign-in-left", "return": target})
    assert aborted and len(aborted) == 1


def test_1161_b1_the_failed_screen_consumes_the_record_and_keeps_an_address_that_already_has_a_return(
        world, context, requests):
    """A record for target X and the same tab opened at `/sign-in-failed?...&return=Y`: the record is gone, the address keeps Y. (B1.1, B1)"""
    x, y = world.screen(), "/home"
    aborted = abort_login_navigation(context)
    page = context.new_page()
    page.goto(f"{world.origin}{x}")
    await_aborted(page, aborted)
    assert page.evaluate("sessionStorage.length") > 0, "positive control: the shell wrote its attempt record for X"
    page.goto(f"{world.origin}/sign-in-failed?reason=unavailable&return={urllib.parse.quote(y, safe='')}")
    screen(page, FAILED)
    settle(page)
    assert page.evaluate("sessionStorage.length") == 0, "the failed screen deletes the record on every load"
    assert where(page) == ("/sign-in-failed", {"reason": "unavailable", "return": y}), "settled only when no `return`"


@pytest.mark.parametrize("given", ["prelogin-missing", "login-attempt-invalid", "unknown-account", "otp-required", "unavailable",
                                   "error", "session-lost", "sign-in-left", "session-refused", "storage-unavailable", "no-such-reason", None, "bad-request"])
def test_1161_b1_the_failed_screen_settles_the_records_target_for_every_reason_but_bad_request(
        world, context, requests, given):
    """A record for X and the screen opened at `/sign-in-failed` with any reason (unknown or none: `error`) and no
    `return`: the address gets `return=X` and the record is gone; for `bad-request` it gets none. (B1)"""
    x = world.screen()
    aborted = abort_login_navigation(context)
    page = context.new_page()
    page.goto(f"{world.origin}{x}")
    await_aborted(page, aborted)
    assert page.evaluate("sessionStorage.length") > 0, "positive control: the shell wrote its attempt record for X"
    page.goto(f"{world.origin}/sign-in-failed" + ("" if given is None else f"?reason={given}"))
    screen(page, FAILED)
    settle(page)
    assert page.evaluate("sessionStorage.length") == 0
    query = {} if given is None else {"reason": given}
    assert where(page) == ("/sign-in-failed", query if given == "bad-request" else {**query, "return": x})


def test_1161_b1_a_session_that_never_arrives_stays_session_lost_after_a_retry_and_no_sign_in_loops(
        world, context, requests):
    """`/api/me` always 401: sign in, `session-lost`; the retry records its own attempt, so it lands on `session-lost`
    again after exactly one more sign-in, not on a third automatic one. (B1.3, B1)"""
    target = world.screen()
    context.route(lambda u: path_is(u, "/api/me"), lambda route: route.fulfill(status=401, body="{}"))
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    screen(page, FAILED)
    assert reason(page) == "session-lost"
    settle(page)
    assert logins(requests, world.origin) == [target]
    page.locator(RETRY).click()
    for _ in range(WAIT_MS // 100):  # until the retry's round trip has come back to the failed screen
        if len(navigations_to(requests, world.origin, "/sign-in-failed")) == 2:
            break
        page.wait_for_timeout(100)
    screen(page, FAILED)
    settle(page, 1500)
    assert reason(page) == "session-lost"
    assert where(page) == ("/sign-in-failed", {"reason": "session-lost", "return": target})
    assert logins(requests, world.origin) == [target, target]


def test_1161_b1_a_restore_from_the_cache_counts_as_a_load_when_signed_in(world, context, requests):
    """Each `persisted` pageshow, the second and third too, is a load of its own: `/api/me` and the investigation read
    are each sent once, by that load. (B1, Am-5 §1: the restored load draws with an empty cache)"""
    sign_in(world, context)
    page = context.new_page()
    page.goto(f"{world.origin}{world.screen()}")
    screen(page, "investigation")
    settle(page)
    for _ in range(3):  # every persisted pageshow is a load, not only the first
        mark = len(requests)
        restore_from_cache(page)
        settle(page, 1000)
        assert api_calls(requests[mark:], world.origin) == [("GET", "/api/me"), ("GET", _read_path(world))]


@pytest.mark.parametrize("path", ["/no/such/screen", "/t/x/investigations/y", "/sign-in-failedx"])
def test_1161_b1_a_signed_out_load_outside_the_list_signs_in_without_return_and_lands_on_the_home(
        world, context, requests, path):
    """No target: sign-in with no `return`; the landing is `/home`. (B1.3, B8; F4's one fallback constant)"""
    page = context.new_page()
    page.goto(f"{world.origin}{path}")
    screen(page, HOME)
    assert where(page) == ("/home", {})
    assert logins(requests, world.origin) == [None]


@pytest.mark.parametrize(("kind", "query"), [("investigation", "?from=ticket&x=a.b"), ("home", "?x=1"),
                                         ("investigation", "?a=1#frag")])
def test_1161_b8_a_returnable_address_with_a_query_lands_on_its_pathname_with_no_query(
        world, context, requests, kind, query):
    """The query and fragment are never part of the target. (B1.3, S3)"""
    target = _target(world, kind)
    page = context.new_page()
    page.goto(f"{world.origin}{target}{query}")
    screen(page, kind)
    assert where(page) == (target, {})
    assert page.evaluate("location.hash") == ""
    assert logins(requests, world.origin) == [target]


def _app_requests(requests: list[Any], origin: str) -> list[str]:
    """Every request to the API (sign-in and sign-out routes included) as `METHOD path`."""
    return [f"{r.method} {urllib.parse.urlsplit(r.url).path}" for r in requests
            if r.url.startswith(origin) and path_is(r.url, "/api")]


@pytest.mark.parametrize("phase", ["signed-out", "signed-in"])
def test_1540_f4_the_landing_page_shows_the_same_signed_out_or_in_and_makes_no_api_call(
        world, context, requests, phase):
    """`/` shows `root`: the product name and a plain link `Sign in` (`<a href="/home" data-action="sign-in">`), no API
    request at all, no sign-in, `location` stays `/`. (F4)"""
    if phase == "signed-in":
        sign_in(world, context)
    mark = len(requests)
    page = context.new_page()
    page.goto(f"{world.origin}/")
    screen(page, ROOT)
    settle(page, 1000)
    assert _app_requests(requests[mark:], world.origin) == []
    assert logins(requests[mark:], world.origin) == []
    assert where(page) == ("/", {})
    assert page.locator(SIGN_IN).count() == 1
    link = page.locator(SIGN_IN)
    assert link.evaluate("e => e.tagName") == "A"
    assert link.get_attribute("href") == "/home"
    assert (link.text_content() or "").strip() == "Sign in"
    assert "Sluice" in (page.locator(f'[data-screen="{ROOT}"]').first.text_content() or ""), "the product name"
    assert signed_in(context) == (phase == "signed-in")
    assert [r.url for r in requests[mark:] if not r.url.startswith(world.origin)] == [], "no third-party origin (F1)"


def test_1540_f4_the_landing_page_still_consumes_the_attempt_record_and_asks_nothing(world, context, requests):
    """A record planted by an aborted sign-in start is deleted by the load of `/`; no API call. (F4, B1.1)"""
    aborted = abort_login_navigation(context)
    page = context.new_page()
    page.goto(f"{world.origin}/home")
    await_aborted(page, aborted)
    assert page.evaluate("sessionStorage.length") > 0, "positive control: the shell wrote its attempt record"
    mark = len(requests)
    page.goto(f"{world.origin}/")
    screen(page, ROOT)
    settle(page)
    assert page.evaluate("sessionStorage.length") == 0
    assert _app_requests(requests[mark:], world.origin) == []
    assert len(aborted) == 1


@pytest.mark.parametrize("phase", ["signed-out", "signed-in"])
def test_1540_f4_the_landing_link_goes_home_through_one_sign_in_or_none_and_the_home_names_the_person(
        world, context, requests, phase):
    """Click `Sign in` at `/`: signed out, one sign-in with `return=/home`; signed in, none. Lands on `/home`, whose
    email field holds the account's and whose first API call is `/api/me`. (F4)"""
    if phase == "signed-in":
        sign_in(world, context)
    mark = len(requests)
    page = context.new_page()
    page.goto(f"{world.origin}/")
    screen(page, ROOT)
    page.locator(SIGN_IN).click()
    screen(page, HOME)
    page.locator(EMAIL).wait_for()
    settle(page)
    assert where(page) == ("/home", {})
    assert logins(requests[mark:], world.origin) == (["/home"] if phase == "signed-out" else [])
    assert signed_in(context)
    assert ANN in page.locator(EMAIL).inner_text()
    assert api_calls(requests[mark:], world.origin)[0] == ("GET", "/api/me")
    assert page.evaluate("sessionStorage.length") == 0


def _signed_in_home(world: Any, context: Any, requests: list[Any]) -> Any:
    """Sign in, then reach `/home` by the landing link (so Back has the landing page behind it)."""
    sign_in(world, context)
    page = context.new_page()
    page.goto(f"{world.origin}/")
    screen(page, ROOT)
    page.locator(SIGN_IN).click()
    screen(page, HOME)
    page.locator(EMAIL).wait_for()
    return page


def test_1540_pr2_signing_out_ends_the_session_and_leaves_by_replace(world, context, requests):
    """One `POST /api/auth/logout`, the session cookie gone, then a document load of `/` (the landing page); the history
    is replaced, so Back does not return to the home. (PR2 signOut)"""
    page = _signed_in_home(world, context, requests)
    length = page.evaluate("history.length")
    mark = len(requests)
    page.locator(SIGN_OUT).click()
    screen(page, ROOT)
    settle(page)
    after = requests[mark:]
    assert auth_calls(after, world.origin, "/api/auth/logout") == [("POST", "/api/auth/logout")]
    assert navigations_to(after, world.origin, "/") == [{}], "leaving is a document navigation to `/`, not a render in place"
    post = next(i for i, r in enumerate(after) if r.method == "POST" and path_is(r.url, "/api/auth/logout"))
    leave = next(i for i, r in enumerate(after) if r.is_navigation_request() and urllib.parse.urlsplit(r.url).path == "/")
    assert post < leave, "the navigation to `/` follows the POST"
    assert not signed_in(context)
    assert where(page) == ("/", {})
    assert page.evaluate("history.length") == length, "replace, not a new history entry"
    page.go_back()
    settle(page)
    assert where(page)[0] != "/home" and shown(page) != HOME
    assert logins(after, world.origin) == [], "the landing page started no sign-in"


def test_1540_pr2_signing_out_when_already_signed_out_still_leaves_for_the_landing_page(world, context, requests):
    """The logout answers 401 (the session cookie is gone): the same exit, to `/` showing `root`. (PR2 signOut)"""
    page = _signed_in_home(world, context, requests)
    context.clear_cookies(name=SESSION_COOKIE)
    assert not signed_in(context), "positive control: the session cookie is gone before the click"
    seen: list[int] = []
    page.on("response", lambda r: seen.append(r.status) if path_is(r.url, "/api/auth/logout") else None)
    page.locator(SIGN_OUT).click()
    screen(page, ROOT)
    assert seen == [401], "the route answers 401 to a caller without a session"
    assert where(page) == ("/", {})
    assert auth_calls(requests, world.origin, "/api/auth/logout") == [("POST", "/api/auth/logout")]


@pytest.mark.parametrize("failure", ["500", "403", "404", "429", "network"])
def test_1540_pr2_a_failed_sign_out_shows_the_error_state_and_does_not_leave(world, context, requests, failure):
    """Any answer but 2xx or 401 (a 4xx as much as a 5xx), or a network failure, is the shell's error state; no
    navigation to `/`. (PR2 signOut)"""
    page = _signed_in_home(world, context, requests)
    mark = len(requests)

    def handle(route: Any) -> None:
        if failure == "network":
            route.abort()
        else:
            route.fulfill(status=int(failure), body="x")

    context.route(lambda u: path_is(u, "/api/auth/logout"), handle)
    page.locator(SIGN_OUT).click()
    screen(page, ERROR)
    settle(page)
    assert where(page)[0] != "/"
    assert page.locator(f'[data-screen="{ROOT}"]').count() == 0
    assert [r for r in requests[mark:] if r.is_navigation_request()] == [], "no navigation followed the failure"


@pytest.mark.parametrize("kind", ["home", "investigation"])
def test_1540_f3_a_me_that_is_not_the_person_shape_is_the_error_state_and_starts_no_sign_in(world, context, requests, kind):
    """`/api/me` answers 200 with a program's view: the shell's error state, no sign-in, not the screen, no screen read;
    also on a screen that never reads the person (the investigation), so the narrowing is the shell's. (F3)"""
    from defender.api.models import ProgramMe

    uid = "6f1c1e3c-55a4-4a4e-9a51-00000000000%d"
    program = ProgramMe.model_validate({
        "program": {"id": uid % 1, "display_name": "soar"}, "tenant": {"tenant_id": uid % 2},
        "credential": {"id": uid % 3, "expires_at": "2026-12-01T00:00:00Z"}}).model_dump(mode="json")
    sign_in(world, context)
    mark = len(requests)
    context.route(lambda u: path_is(u, "/api/me"), lambda route: route.fulfill(status=200, json=program))
    page = context.new_page()
    page.goto(f"{world.origin}{_target(world, kind)}")
    screen(page, ERROR)
    settle(page)
    assert logins(requests[mark:], world.origin) == []
    assert page.locator(f'[data-screen="{kind}"]').count() == 0
    assert api_calls(requests[mark:], world.origin) == [("GET", "/api/me")], "no screen read follows a refused `/api/me`"


# --- #1540 Am-5: one owner per load, one 401 policy, one error state ----------------------------------------------------

def _login_return(url: str) -> str | None:
    """The `return` of a navigation to `/api/auth/login` (None when absent)."""
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query)).get("return")


def test_1540_am5_a_restore_after_a_later_401_left_the_document_is_a_load_that_may_sign_in_again(world, context, requests):
    """The read's 401 starts sign-in (aborted: the document stays with its record); a `persisted` pageshow is a new
    load that asks `/api/me` and the read again, and that read's 401 starts one more sign-in. (Am-5 §1, B1.3)"""
    target = world.screen()
    read = _read_path(world)
    sign_in(world, context)
    context.route(lambda u: urllib.parse.urlsplit(u).path == read, lambda route: route.fulfill(status=401, body="{}"))
    aborted = abort_login_navigation(context)
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    await_aborted(page, aborted)
    settle(page)
    assert len(aborted) == 1, "positive control: the later 401 started one sign-in"
    assert page.evaluate("sessionStorage.length") > 0, "positive control: it wrote its attempt record"
    mark = len(requests)
    restore_from_cache(page)
    settle(page, 1500)
    assert api_calls(requests[mark:], world.origin) == [("GET", "/api/me"), ("GET", read)]
    assert len(aborted) == 2, aborted
    assert _login_return(aborted[1]) == target


#: How the tab's storage fails: the accessor throws (neither read nor write works), only `setItem` throws (the attempt
#: record cannot be written), only `getItem` throws (it cannot be read, writes work).
WRITE_FAILS = "Storage.prototype.setItem = function () { throw new DOMException('full', 'QuotaExceededError'); };"
READ_FAILS = "Storage.prototype.getItem = function () { throw new DOMException('denied', 'SecurityError'); };"
STORAGE_FAILURES = {"neither": NO_STORAGE, "write-fails": WRITE_FAILS}


def test_1540_am5_a_signed_out_load_whose_attempt_record_cannot_be_written_shows_storage_unavailable_and_starts_no_sign_in(
        world, context, requests):
    """Only the write fails (the record can be read): the sign-in is not started, `storage-unavailable` with `return`.
    Neither-works is `test_1161_b1_storage_unavailable_...`. (B1.3)"""
    target = world.screen()
    context.add_init_script(WRITE_FAILS)
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    screen(page, FAILED)
    assert reason(page) == "storage-unavailable"
    assert where(page) == ("/sign-in-failed", {"reason": "storage-unavailable", "return": target})
    settle(page)
    assert logins(requests, world.origin) == []


@pytest.mark.parametrize("failure", ["neither", "write-fails", "read-fails"])
def test_1540_am5_a_later_401_on_a_signed_in_screen_whose_storage_fails_shows_storage_unavailable_and_starts_no_sign_in(
        world, context, requests, failure):
    """Signed in, the screen's read answers 401 in a load whose storage fails (neither works; the write fails; the
    record cannot be read though writes work): `storage-unavailable` with `return`, no login. (B1.3, Am-5 §6(b))"""
    target = world.screen()
    read = _read_path(world)
    sign_in(world, context)
    context.add_init_script({**STORAGE_FAILURES, "read-fails": READ_FAILS}[failure])
    context.route(lambda u: urllib.parse.urlsplit(u).path == read, lambda route: route.fulfill(status=401, body="{}"))
    mark = len(requests)
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    screen(page, FAILED)
    assert reason(page) == "storage-unavailable"
    assert where(page) == ("/sign-in-failed", {"reason": "storage-unavailable", "return": target})
    settle(page)
    assert ("GET", read) in api_calls(requests[mark:], world.origin), "positive control: the read was asked and answered 401"
    assert logins(requests[mark:], world.origin) == []


# --- #1540 Am-5 §6(a): every uncaught error or unhandled rejection in the document is the error state ---------------------

#: Records, from before the app's first script, which of the two page-wide events reached the page: a positive control that
#: the injected failure arrived where the shell's listeners are, so a missing error state is the shell's.
_SEEN_EVENTS = """
    window.__seenEvents = [];
    window.addEventListener('error', () => window.__seenEvents.push('error'));
    window.addEventListener('unhandledrejection', () => window.__seenEvents.push('unhandledrejection'));
"""
_STRAYS = {
    "timer-throw": "setTimeout(() => { throw new Error('stray timer'); }, 0)",
    "stray-rejection": "void Promise.reject(new Error('stray rejection'))",
}


@pytest.mark.parametrize("stray", sorted(_STRAYS))
def test_1540_am5_a_stray_error_or_rejection_on_a_signed_in_home_shows_the_error_state_and_starts_no_sign_in(
        world, context, requests, stray):
    """A timer's throw, or an unhandled rejection, in a loaded signed-in `/home`: `data-screen=error`, no login. (Am-5 §6(a))"""
    sign_in(world, context)
    context.add_init_script(_SEEN_EVENTS)
    mark = len(requests)
    page = context.new_page()
    page.goto(f"{world.origin}/home")
    page.locator(EMAIL).wait_for()
    page.evaluate(_STRAYS[stray])
    until(page, f"window.__seenEvents.includes('{'error' if stray == 'timer-throw' else 'unhandledrejection'}')")
    screen(page, ERROR)
    settle(page)
    assert logins(requests[mark:], world.origin) == []


def test_1540_am5_a_stray_error_while_the_document_is_leaving_for_sign_in_shows_no_error_state(world, context, requests):
    """Signed out `/home`, the sign-in navigation aborted so the load is leaving and the document stays: a timer's throw
    shows no `data-screen=error`. (Am-5 §6(a): except while the load is leaving)"""
    aborted = abort_login_navigation(context)
    context.add_init_script(_SEEN_EVENTS)
    page = context.new_page()
    page.goto(f"{world.origin}/home")
    await_aborted(page, aborted)
    page.evaluate(_STRAYS["timer-throw"])
    until(page, "window.__seenEvents.includes('error')")
    settle(page, 1000)
    assert page.locator(f'[data-screen="{ERROR}"]').count() == 0
    assert len(aborted) == 1


#: A stray whose value is not an `Error`: a thrown string, a rejection with a plain object.
_NON_ERROR_STRAYS = {
    "thrown-string": ("setTimeout(() => { throw 'stray string'; }, 0)", "error"),
    "rejected-plain-object": ("void Promise.reject({ stray: 'plain object' })", "unhandledrejection"),
}


@pytest.mark.parametrize("when", ["first-load", "after-a-restore"])
@pytest.mark.parametrize("stray", sorted(_NON_ERROR_STRAYS))
def test_1540_am5_a_stray_that_is_not_an_error_shows_the_error_state_on_the_first_load_and_after_a_restore(
        world, context, requests, stray, when):
    """A timer's throw of a string, or a rejection with a plain object, in a loaded signed-in `/home`, on the document's
    first load or on the load a restore from the cache made: `data-screen=error`, no login. (Am-5 §6(a): every
    uncaught error or unhandled rejection, whatever its value, on every load)"""
    sign_in(world, context)
    context.add_init_script(_SEEN_EVENTS)
    mark = len(requests)
    page = context.new_page()
    page.goto(f"{world.origin}/home")
    page.locator(EMAIL).wait_for()
    if when == "after-a-restore":
        restore_from_cache(page)
        settle(page, 1000)
        page.locator(EMAIL).wait_for()
        assert api_calls(requests[mark:], world.origin).count(("GET", "/api/me")) == 2, "positive control: a restored load"
    script, event = _NON_ERROR_STRAYS[stray]
    page.evaluate(script)
    until(page, f"window.__seenEvents.includes('{event}')")
    settle(page)
    assert page.locator(f'[data-screen="{ERROR}"]').count() == 1, f"{stray} on the {when} did not show the error state"
    assert logins(requests[mark:], world.origin) == []


def test_1540_am5_a_load_leaving_after_its_screen_reads_401_shows_nothing_whatever_strays_after(world, context, requests):
    """Signed in, the investigation read answers 401 and the shell's sign-in navigation is aborted, so the load is
    leaving and the document stays: a timer's throw and an unhandled rejection after it show neither the shell's error
    state nor the screen's. (Am-5 §6(a), point 4: a leaving load shows nothing)"""
    read = _read_path(world)
    sign_in(world, context)
    context.add_init_script(_SEEN_EVENTS)
    context.route(lambda u: urllib.parse.urlsplit(u).path == read, lambda route: route.fulfill(status=401, body="{}"))
    aborted = abort_login_navigation(context)
    page = context.new_page()
    page.goto(f"{world.origin}{world.screen()}")
    await_aborted(page, aborted)
    for script in _STRAYS.values():
        page.evaluate(script)
    until(page, "window.__seenEvents.includes('error') && window.__seenEvents.includes('unhandledrejection')")
    settle(page, 1000)
    assert page.locator(f'[data-screen="{ERROR}"]').count() == 0, "the shell's error state showed while leaving"
    assert page.locator('[data-state="error"]').count() == 0, "the screen drew its error state while leaving"
    assert len(aborted) == 1


def _abort_navigations_to(context: Any, path: str) -> list[str]:
    """Abort (`ERR_ABORTED`, the document stays) every document navigation to exactly `path`; the URLs, in order."""
    aborted: list[str] = []

    def handle(route: Any) -> None:
        if not route.request.is_navigation_request():
            return route.fallback()
        aborted.append(route.request.url)
        return route.abort("aborted")

    context.route(lambda u: urllib.parse.urlsplit(u).path == path, handle)
    return aborted


#: What an exit leaves behind: the page, the navigations it aborted, and the control that triggers it again (if any).
_Exited = tuple[Any, list[str], str | None]


def _exit_signs_in(world: Any, context: Any, requests: list[Any], cookieless_once: Any) -> _Exited:
    """Signed out `/home`: `/api/me` answers 401 and the shell leaves for sign-in (aborted)."""
    aborted = abort_login_navigation(context)
    page = context.new_page()
    page.goto(f"{world.origin}/home")
    await_aborted(page, aborted)
    return page, aborted, None


def _exit_to_the_failed_screen(world: Any, context: Any, requests: list[Any], cookieless_once: Any) -> _Exited:
    """Back from sign-in with the attempt record found, `/api/me` answers 401: the shell leaves for the failed screen
    (aborted)."""
    aborted = _abort_navigations_to(context, "/sign-in-failed")
    lost = cookieless_once(lambda u: path_is(u, "/api/me"), skip=1)
    page = context.new_page()
    page.goto(f"{world.origin}/home")
    await_aborted(page, aborted)
    assert lost.done, "positive control: the returning load's `/api/me` went cookie-less"
    return page, aborted, None


def _exit_by_retry(world: Any, context: Any, requests: list[Any], cookieless_once: Any) -> _Exited:
    """On the failed screen (session-lost), the retry leaves for sign-in (aborted)."""
    cookieless_once(lambda u: path_is(u, "/api/me"), skip=1)
    page = context.new_page()
    page.goto(f"{world.origin}/home")
    screen(page, FAILED)
    settle(page)
    aborted = abort_login_navigation(context)
    page.locator(RETRY).click()
    await_aborted(page, aborted)
    return page, aborted, RETRY


def _exit_by_sign_out(world: Any, context: Any, requests: list[Any], cookieless_once: Any) -> _Exited:
    """On the signed-in home, sign-out's logout answers and the shell leaves for `/` (aborted)."""
    page = _signed_in_home(world, context, requests)
    aborted = _abort_navigations_to(context, "/")
    page.locator(SIGN_OUT).click()
    await_aborted(page, aborted)
    return page, aborted, SIGN_OUT


_EXITS = {"401-to-sign-in": _exit_signs_in, "401-to-the-failed-screen": _exit_to_the_failed_screen,
          "retry": _exit_by_retry, "sign-out": _exit_by_sign_out}


@pytest.mark.parametrize("exit_", sorted(_EXITS))
def test_1540_am5_every_exit_leaves_once_and_the_leaving_load_shows_nothing_after_it(
        world, context, requests, cookieless_once, exit_):
    """Each way the shell leaves the document (a 401 to sign-in, a 401 to the failed screen, retry, a signed-out
    sign-out), its navigation aborted so the document stays: the trigger pressed again, a stray throw and a stray
    rejection show no error state, and the load navigated exactly once. (Am-5 points 1, 6(a): `leave` is the one exit)"""
    context.add_init_script(_SEEN_EVENTS)
    mark = len(requests)
    page, aborted, trigger = _EXITS[exit_](world, context, requests, cookieless_once)
    if trigger is not None:
        page.locator(trigger).click()
        settle(page)
    for script in _STRAYS.values():
        page.evaluate(script)
    until(page, "window.__seenEvents.includes('error') && window.__seenEvents.includes('unhandledrejection')")
    settle(page, 1000)
    assert page.locator(f'[data-screen="{ERROR}"]').count() == 0, f"{exit_}: the error state showed while leaving"
    assert len(aborted) == 1, f"{exit_}: the load navigated {len(aborted)} times: {aborted}"
    if exit_ == "sign-out":
        assert auth_calls(requests[mark:], world.origin, "/api/auth/logout") == [("POST", "/api/auth/logout")]
