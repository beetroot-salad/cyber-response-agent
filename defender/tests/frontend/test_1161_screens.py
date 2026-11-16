# ruff: noqa: PT018 — each compound assert states one fact about one page
"""#1161 B7, B1.4, B3 (Chromium half): the investigation screen, the not-found screen, and every returnable shape
reaching the app at its own address through the repo's ingress."""
from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from defender.tests.frontend._flow1161 import api_calls, logins, screen, settle, shown, sign_in, where
from defender.tests.support.api._server1083 import A, BOB
from defender.tests.support.frontend import _shapes1161 as S
from defender.tests.support.frontend._browser1161 import path_is, run_async
from defender.tests.support.jobs._jobs1342 import ALERT_BYTES, job_store

_NOW = dt.datetime(2026, 11, 1, 12, tzinfo=dt.UTC)
UNKNOWN = "0b6f1c1e-3c55-4a4e-9a51-000000000000"


async def _second(dsn: str) -> str:
    """A second completed investigation of A, disposition `false-positive`."""
    async with job_store(dsn) as store:
        alert = await store.insert_alert(A, vendor="elastic", vendor_ticket_id="T-1161-b", fired_at=_NOW,
                                         changed_at=_NOW, received_at=_NOW, raw=ALERT_BYTES)
        inv, _ = await store.create_investigation(A, str(alert.alert_id), "seed-b", actor="seed")
        await store.claim()
        await store.finish(A, inv.investigation_id, stage="completed", disposition="false-positive", cost_usd=0.0)
    return str(inv.investigation_id)


def _open(world: Any, context: Any, address: str) -> Any:
    page = context.new_page()
    page.goto(f"{world.origin}{address}")
    return page


def test_1161_b7_the_investigation_screen_shows_status_and_outcome_from_the_read(world, context):
    """Two investigations of different outcomes show their own status and outcome. (B7)"""
    other = run_async(_second, world.dsn)
    sign_in(world, context)
    first = _open(world, context, world.screen())
    screen(first, "investigation")
    first.locator('[data-field="status"]').wait_for()
    assert "completed" in first.locator('[data-field="status"]').inner_text()
    assert "malicious" in first.locator('[data-field="outcome"]').inner_text()
    second = _open(world, context, world.screen(other))
    screen(second, "investigation")
    second.locator('[data-field="outcome"]').wait_for()
    assert "false-positive" in second.locator('[data-field="outcome"]').inner_text()
    assert "malicious" not in second.locator("body").inner_text()


@pytest.mark.parametrize("who", ["other-tenant-member", "unknown-id"])
def test_1161_b7_a_404_from_the_read_shows_not_available_and_does_not_lead_to_sign_in(world, context, requests, who):
    """Bob reading A's investigation, or Ann an id that does not exist: `data-state=not-available`, one sign-in. (B7, B1.4)"""
    if who == "other-tenant-member":
        world.front.sign_in_as(world.accounts[BOB])
        address = world.screen()
    else:
        address = world.screen(UNKNOWN)
    page = _open(world, context, address)
    screen(page, "investigation")
    page.locator('[data-screen="investigation"][data-state="not-available"]').wait_for()
    settle(page)
    assert logins(requests, world.origin) == [address]
    assert where(page) == (address, {})


@pytest.mark.parametrize("failure", ["500", "network"])
def test_1161_b1_a_5xx_or_network_failure_of_the_screens_read_is_an_error_not_sign_in_or_not_available(
        world, context, requests, failure):
    """Both show `data-state=error`, not `not-available`; neither leads to sign-in. (B1.4)"""
    sign_in(world, context)
    mark = len(requests)

    def handle(route: Any) -> None:
        route.abort() if failure == "network" else route.fulfill(status=500, body="x")

    context.route(lambda u: path_is(u, f"/api/tenants/{A}/investigations/{world.investigation}"), handle)
    page = _open(world, context, world.screen())
    screen(page, "investigation")
    page.locator('[data-screen="investigation"][data-state="error"]').wait_for()
    settle(page)
    assert logins(requests[mark:], world.origin) == []
    assert shown(page) != "sign-in-failed"


@pytest.mark.parametrize("address", ["/no/such/screen", "/t/x/investigations/y", "/sign-in-failedx", "//"])
def test_1161_b9_an_address_outside_the_list_shows_the_not_found_screen_after_me(world, context, requests, address):
    """Signed in: `not-found` at the same pathname, reached through `/api/me` like any screen. (S2, B1.2)"""
    sign_in(world, context)
    mark = len(requests)
    page = _open(world, context, address)
    screen(page, "not-found")
    assert where(page)[0] == address
    assert ("GET", "/api/me") in api_calls(requests[mark:], world.origin)
    assert logins(requests[mark:], world.origin) == []


def _members() -> list[tuple[str, str]]:
    return [(shape.name, m) for shape in S.SHAPES if shape.returnable for m in S.members(shape, 1161, 3)]


@pytest.mark.parametrize("shape", sorted(S.RETURNABLE))
def test_1161_b3_every_returnable_member_reaches_the_app_at_its_own_pathname_signed_out_and_in(
        world, context, browser, shape):
    """Through the ingress in the pinned Chromium: signed out the sign-in carries it and lands on it; signed in its
    own screen shows at that pathname. (B3)"""
    values = [m for name, m in _members() if name == shape]
    for value in values:
        with_context = browser.new_context()
        with_context.set_default_timeout(30_000)
        seen: list[Any] = []
        with_context.on("request", lambda r, seen=seen: seen.append(r))
        try:
            page = with_context.new_page()
            page.goto(f"{world.origin}{value}")
            screen(page, shape)
            assert where(page) == (value, {}), value
            assert logins(seen, world.origin) == [value], value
        finally:
            with_context.close()
    sign_in(world, context)
    for value in values:
        page = _open(world, context, value)
        screen(page, shape)
        assert where(page) == (value, {}), value


@pytest.mark.parametrize("phase", ["signed-out", "signed-in"])
@pytest.mark.parametrize("shape", sorted(s.name for s in S.SHAPES if not s.returnable))
def test_1540_f4_a_member_of_a_non_returnable_shape_shows_its_screen_with_no_api_call_or_sign_in(
        world, context, requests, shape, phase):
    """Signed out or in, a member of a shape the shape list marks non-returnable shows its own screen, makes no API
    call and starts no sign-in. (F4's rule, B1.2, B3)"""
    if phase == "signed-in":
        sign_in(world, context)
    for value in [m for s in S.SHAPES if s.name == shape for m in S.members(s, 1540, 2)]:
        mark = len(requests)
        page = _open(world, context, value)
        screen(page, shape)
        settle(page)
        assert where(page) == (value, {}), value
        assert [r.url for r in requests[mark:] if path_is(r.url, "/api") and r.url.startswith(world.origin)] == [], value
        assert logins(requests[mark:], world.origin) == [], value
        page.close()
