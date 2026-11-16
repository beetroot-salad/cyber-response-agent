# ruff: noqa: PT018 — each compound assert states one fact about one page
"""#1161 B1/B8: the app shell's signed-out rule, in the pinned Chromium through the repo's ingress, with the real API
child and the fake provider. Observed through screen markers and `location.pathname`, compared exactly."""
from __future__ import annotations

import urllib.parse
from typing import Any

import pytest

from defender.tests.frontend._flow1161 import (
    FAILED,
    NO_STORAGE,
    RETRY,
    WAIT_MS,
    api_calls,
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
from defender.tests.support.api._server1083 import SESSION_COOKIE
from defender.tests.support.frontend._browser1161 import abort_login_navigation, path_is, restore_from_cache

KINDS = pytest.mark.parametrize("kind", ["root", "investigation"])


def _target(world: Any, kind: str) -> str:
    return "/" if kind == "root" else world.screen()


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
    one_target, two_target = world.screen(), "/"
    world.front.hold = True
    one = context.new_page()
    one.goto(f"{world.origin}{one_target}", wait_until="commit")
    world.front.wait_held(1, page=one)
    two = context.new_page()
    two.goto(f"{world.origin}{two_target}", wait_until="commit")
    world.front.wait_held(2, page=two)
    tabs = {0: (one, "investigation", one_target), 1: (two, "root", two_target)}
    for index in (first, 1 - first):
        world.front.release(index)
        page, kind, target = tabs[index]
        screen(page, kind)
        assert where(page) == (target, {})
    assert sorted(x or "" for x in logins(requests, world.origin)) == sorted([one_target, two_target])
    assert shown(one) == "investigation" and shown(two) == "root"


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
    screen(page, "error")
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
    page.wait_for_function("location.search.includes('return=')")
    assert where(page) == ("/sign-in-failed", {"reason": "prelogin-missing", "return": target})
    page.locator(RETRY).click()
    screen(page, kind)
    assert where(page) == (target, {})
    assert logins(requests, world.origin) == [target, target]


def test_1161_b1_a_reload_of_the_settled_failed_screen_keeps_its_target_and_the_retry_lands(world, context, requests):
    """After the settle, reloading the failed screen and retrying still lands on the target. (B1, B8)"""
    target = world.screen()
    page = _prelogin_missing(world, context, requests, target)
    page.wait_for_function("location.search.includes('return=')")
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
    x, y = world.screen(), "/"
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
    """Each `persisted` pageshow, the second and third too, asks `/api/me` again. (B1)"""
    sign_in(world, context)
    page = context.new_page()
    page.goto(f"{world.origin}{world.screen()}")
    screen(page, "investigation")
    settle(page)
    before = [c for c in api_calls(requests, world.origin) if c == ("GET", "/api/me")]
    for restores in (1, 2, 3):  # every persisted pageshow is a load, not only the first
        restore_from_cache(page)
        page.wait_for_timeout(1000)
        after = [c for c in api_calls(requests, world.origin) if c == ("GET", "/api/me")]
        assert len(after) == len(before) + restores


@pytest.mark.parametrize("path", ["/no/such/screen", "/t/x/investigations/y", "/sign-in-failedx"])
def test_1161_b1_a_signed_out_load_outside_the_list_signs_in_without_return_and_lands_on_the_root(
        world, context, requests, path):
    """No target: sign-in with no `return`; the landing is the root. (B1.3, B8)"""
    page = context.new_page()
    page.goto(f"{world.origin}{path}")
    screen(page, "root")
    assert where(page) == ("/", {})
    assert logins(requests, world.origin) == [None]


@pytest.mark.parametrize(("kind", "query"), [("investigation", "?from=ticket&x=a.b"), ("root", "?x=1"),
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
