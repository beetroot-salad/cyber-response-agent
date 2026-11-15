# ruff: noqa: PT018 — each compound assert states one fact about one page
"""#1161 B4/B8: the sign-in-failed screen, reached by every callback reason the browser can reach, by `bad-request`
and by address. Real API child, ingress and frontend; the provider is the fake front channel."""
from __future__ import annotations

from typing import Any

import pytest

from defender.tests.frontend._flow1161 import (
    FAILED,
    RETRY,
    api_calls,
    logins,
    navigations_to,
    reason,
    screen,
    settle,
    signed_in,
    where,
)
from defender.tests.support.api._server1083 import OPS
from defender.tests.support.api._signin1161 import Choice, link_account
from defender.tests.support.frontend._browser1161 import run_async

VOCABULARY = ["prelogin-missing", "login-attempt-invalid", "unknown-account", "otp-required", "unavailable",
              "bad-request", "error", "session-lost", "storage-unavailable"]


@pytest.mark.parametrize("code", VOCABULARY)
def test_1161_b8_the_failed_screen_opened_by_address_shows_each_reason_and_a_retry(world, context, requests, code):
    """`data-reason` is the code, the retry control is present, and the screen makes no API call at load. (B8, B1)"""
    page = context.new_page()
    page.goto(f"{world.origin}/sign-in-failed?reason={code}")
    screen(page, FAILED)
    assert reason(page) == code
    assert page.locator(RETRY).count() == 1
    settle(page)
    assert api_calls(requests, world.origin) == []
    assert where(page) == ("/sign-in-failed", {"reason": code})


@pytest.mark.parametrize("query", ["?reason=no-such-reason", "?reason=ERROR", "?reason=", "", "?return=%2F",
                                   "?reason=%3Cb%3Ex%3C%2Fb%3E"],
                         ids=["unknown", "wrong-case", "empty", "missing", "no-reason-param", "markup"])
def test_1161_b8_an_unknown_or_missing_reason_renders_as_error(world, context, requests, query):
    """Anything outside the vocabulary shows `error`; the retry is still there. (B8)"""
    page = context.new_page()
    page.goto(f"{world.origin}/sign-in-failed{query}")
    screen(page, FAILED)
    assert reason(page) == "error"
    assert page.locator(RETRY).count() == 1
    assert api_calls(requests, world.origin) == []


@pytest.mark.parametrize(("ret", "expect"), [("", None), ("&return=%2F", "/"), ("&return=%2Fnowhere", "/nowhere"),
                                              ("&return=%2F%3Fx%3D1", "/?x=1")],
                         ids=["none", "root", "non-member", "with-query"])
def test_1161_b4_the_retry_passes_its_addresss_return_on_unchanged_for_the_api_to_judge(
        world, context, requests, ret, expect):
    """The failed screen keeps no copy of the rule: what it was given goes to `/api/auth/login`. (B1, P2)"""
    page = context.new_page()
    page.goto(f"{world.origin}/sign-in-failed?reason=unavailable{ret}")
    screen(page, FAILED)
    page.locator(RETRY).click()
    if expect in (None, "/"):
        screen(page, "root")
        assert where(page) == ("/", {})
    else:
        page.wait_for_function("location.pathname === '/sign-in-failed' && location.search.includes('bad-request')")
        assert where(page) == ("/sign-in-failed", {"reason": "bad-request"})
    assert logins(requests, world.origin) == [expect]


CALLBACK_REASONS = [
    ("error-redirect", Choice(error="invalid_request", error_description="Missing parameter: code_challenge_method"),
     "login-attempt-invalid"),
    ("invalid-grant", Choice(account="ANN", fault="invalid_grant"), "login-attempt-invalid"),
    ("unknown-account", Choice(account="kc-no-such-account"), "unknown-account"),
    ("unavailable", Choice(account="ANN", fault="unavailable"), "unavailable"),
]


@pytest.mark.parametrize(("choice", "code"), [(c, r) for _, c, r in CALLBACK_REASONS],
                         ids=[i for i, _, _ in CALLBACK_REASONS])
def test_1161_b8_each_callback_refusal_shows_its_reason_with_the_attempts_return_and_the_retry_lands(
        world, context, requests, choice, code):
    """The callback's 303 carries `reason` and `return`; no session is set; the retry (default account) lands. (B4, B8)"""
    if choice.account == "ANN":
        choice = Choice(account=world.accounts["ann@a.example"], fault=choice.fault)
    target = world.screen()
    world.front.queue(choice)
    page = context.new_page()
    page.goto(f"{world.origin}{target}")
    screen(page, FAILED)
    assert reason(page) == code
    assert navigations_to(requests, world.origin, "/sign-in-failed") == [{"reason": code, "return": target}]
    assert not signed_in(context)
    page.locator(RETRY).click()
    screen(page, "investigation")
    assert where(page) == (target, {})
    assert signed_in(context)


def test_1161_b8_an_administrator_without_a_second_factor_is_otp_required_and_with_one_signs_in(
        world, context, requests):
    """`amr` lacking a second factor: `otp-required` with `return`; the same account with `otp` signs in. (B4, B8)"""
    ops = run_async(link_account, world.dsn, OPS)
    world.front.queue(Choice(account=ops, amr=("pwd",)))
    page = context.new_page()
    page.goto(f"{world.origin}/")
    screen(page, FAILED)
    assert reason(page) == "otp-required"
    assert navigations_to(requests, world.origin, "/sign-in-failed") == [{"reason": "otp-required", "return": "/"}]
    assert not signed_in(context)
    world.front.queue(Choice(account=ops, amr=("pwd", "otp")))
    page.locator(RETRY).click()
    screen(page, "root")
    assert signed_in(context)


@pytest.mark.parametrize("url", ["/api/auth/login?x=1", "/api/auth/login?return=%2Fnowhere", "/api/auth/login?return=",
                                 "/api/auth/login?return=%2F&return=%2F"],
                         ids=["undeclared", "refused-return", "empty-return", "repeated-return"])
def test_1161_b2_bad_request_shows_its_reason_with_no_return_and_the_retry_lands_on_the_root(
        world, context, requests, url):
    """A malformed sign-in start: `bad-request`, no `return`; its retry lands on the root. (B2, B4, B8)"""
    page = context.new_page()
    page.goto(f"{world.origin}{url}")
    screen(page, FAILED)
    assert reason(page) == "bad-request"
    assert where(page) == ("/sign-in-failed", {"reason": "bad-request"})
    page.locator(RETRY).click()
    screen(page, "root")
    assert where(page) == ("/", {})
    assert logins(requests, world.origin)[-1] is None
    assert signed_in(context)


def test_1161_b4_a_sign_in_start_with_a_judged_return_goes_to_the_provider_not_the_failed_screen(
        world, context, requests: Any):
    """Positive control for `bad-request`: `return=/` is judged fine and signs in. (B2)"""
    page = context.new_page()
    page.goto(f"{world.origin}/api/auth/login?return=%2F")
    screen(page, "root")
    assert navigations_to(requests, world.origin, "/sign-in-failed") == []
