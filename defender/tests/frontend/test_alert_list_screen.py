# ruff: noqa: PT018 — each compound assert states one fact about one page
"""Alert list design: the alerts screen (O5, O6, O7), its address (O4), Home's links and no-tenant text (O8) and the
product's name (O9), in the pinned Chromium through the repo's ingress over the real API.

The browser's zone is Europe/Paris (UTC+1 in November) and its clock is fixed at `BROWSER_NOW` (16:00 there), so
"Today"/"Yesterday" and local times are stated, not computed. `world` already holds one alert of A, `T-1161`, fired
`_NOW` (12:00Z), whose one investigation completed `malicious`.

Markers: `data-screen="alerts"` is the shape's name (the convention every screen follows, B3). The rest are this
sketch's FORCED CHOICES (the design names none): `data-state` (`ready`, `empty`, `no-match`, `invalid`), each row
`[data-row="alert"]` with `[data-field=fired-time|fired-day|ticket|vendor|title|status]`, `[data-action="load-more"]`,
`[data-action="clear-filters"]` (the X and the empty state's clear link), `[data-action="apply"]`, and the form's fields
by their query names (`outcome`, `fired_after`, `fired_before`)."""
from __future__ import annotations

import datetime as dt
import urllib.parse
from typing import Any

from defender.tests.frontend._flow1161 import api_calls, logins, screen, settle, sign_in, where
from defender.tests.frontend.conftest import WAIT_MS, requests_of
from defender.tests.support.api._server1083 import A, B, BOB
from defender.tests.support.api._signin1161 import link_account
from defender.tests.support.frontend._browser1161 import path_is, run_async
from defender.tests.support.jobs._jobs1342 import ALERT_BYTES, PADDED_ALERT_BYTES, TITLE

ZONE = "Europe/Paris"
BROWSER_NOW = "2026-11-01T15:00:00Z"
ALERTS = f"/t/{A}/alerts"
READ = f"/api/tenants/{A}/alerts"
NO_TITLE = "No title — the alert mapping had no title entry when this alert arrived"
#: FORCED CHOICE: the screen's page size. The design gives none ("Per page: up to 201 alerts" in Performance reads as
#: `limit=200`; the API's default is 50). These cases assume the screen sends no `limit`, so a page is the API's 50.
PAGE = 50


def _at(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


async def _seed(dsn: str, tenant: str, alerts: list[tuple[str, str, bytes, list[str]]]) -> dict[str, str]:
    """Each `(ticket, fired_at, raw, investigations)` stored for `tenant`; `investigations` are, oldest first, each
    investigation's end: `completed:<disposition>`, `failed`, `running` or `queued` (the last two only last). The store's
    clock moves a minute per write, so "newest" is by `created_at` (ids are random); it starts after the world's seed."""
    from defender.jobs import JobStore

    at = [_at("2026-11-01T13:00:00Z")]

    def clock() -> dt.datetime:
        at[0] += dt.timedelta(minutes=1)
        return at[0]

    store = JobStore(dsn, clock=clock)
    ids: dict[str, str] = {}
    try:
        for ticket, fired, raw, ends in alerts:
            if ticket == "T-1161":  # the world's own alert: only add investigations to it
                [found] = [a for a in await store.list_alerts(tenant, fired_after=None, fired_before=None, after=None, limit=200)
                           if a.vendor_ticket_id == ticket]
                alert_id = str(found.alert_id)
            else:
                alert_id = str((await store.insert_alert(tenant, vendor="elastic", vendor_ticket_id=ticket, fired_at=_at(fired),
                                                         changed_at=_at(fired), received_at=_at(fired), raw=raw)).alert_id)
            ids[ticket] = alert_id
            for n, end in enumerate(ends):
                inv, _ = await store.create_investigation(tenant, alert_id, f"seed-{n}", actor="seed")
                if end == "queued":
                    continue
                claimed = await store.claim()
                assert claimed is not None and claimed.record.investigation_id == inv.investigation_id, "premise"
                if end == "running":
                    continue
                stage, _, disposition = end.partition(":")
                await store.finish(tenant, inv.investigation_id, stage=stage, disposition=disposition or None, cost_usd=0.0,
                                   failure_reason="no_report" if stage == "failed" else None)
    finally:
        await store.close()
    return ids


def _context(browser: Any, world: Any, account: str | None = None) -> Any:
    """A guarded context in `ZONE`, signed in (as Ann unless `account` is given)."""
    ctx = browser.new_context(timezone_id=ZONE)
    ctx.set_default_timeout(WAIT_MS)
    if account is not None:
        world.front.sign_in_as(account)
    sign_in(world, ctx)
    return ctx


def _open(world: Any, ctx: Any, address: str) -> Any:
    page = ctx.new_page()
    page.clock.set_fixed_time(BROWSER_NOW)
    page.goto(f"{world.origin}{address}")
    screen(page, "alerts")
    return page


def _state(page: Any, state: str) -> None:
    page.locator(f'[data-screen="alerts"][data-state="{state}"]').wait_for()


def _rows(page: Any) -> list[tuple[str, ...]]:
    fields = ("fired-time", "fired-day", "ticket", "vendor", "title", "status")
    return [tuple(row.locator(f'[data-field="{f}"]').inner_text().strip() for f in fields)
            for row in page.locator('[data-row="alert"]').all()]


def _reads(requests: Any, origin: str, path: str) -> list[dict[str, str]]:
    """The query of each GET of `path` the pages sent, in order."""
    return [dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r.url).query, keep_blank_values=True))
            for r in requests if r.method == "GET" and r.url.startswith(origin) and path_is(r.url, path)
            and urllib.parse.urlsplit(r.url).path == path]


# --- O5, O9: the rows ------------------------------------------------------------------------------------------------

def test_alert_list_o5_o9_rows_show_local_fired_time_ticket_title_and_one_status_newest_first(world, browser):
    """Newest first: the local time over Today/Yesterday/the date, the ticket over its vendor, the title or the no-title
    text, and the outcome when one is known (a queued rerun does not hide it), else the newest investigation's state in
    the screen's words. One read; no Load more, no X; the page says Sluice, never Defender. (O5, O9)"""
    run_async(_seed, world.dsn, A, [
        ("T-run", "2026-11-01T11:00:00Z", ALERT_BYTES, ["running"]),
        ("T-none", "2026-10-31T22:30:00Z", PADDED_ALERT_BYTES, []),  # 23:30 in Paris, the day before; no `rule.description`
        ("T-old", "2026-10-30T08:05:00Z", ALERT_BYTES, ["failed"]),
        ("T-1161", "", b"", ["queued"]),  # last: a rerun queued over the completed `malicious` (a claim would take it)
    ])
    ctx = _context(browser, world)
    mark = len(requests_of(ctx))
    page = _open(world, ctx, ALERTS)
    _state(page, "ready")
    assert _rows(page) == [
        ("13:00", "Today", "T-1161", "elastic", TITLE, "malicious"),
        ("12:00", "Today", "T-run", "elastic", TITLE, "investigating"),
        ("23:30", "Yesterday", "T-none", "elastic", NO_TITLE, "not investigated"),
        # FORCED CHOICE: the date line before yesterday (the design says "the date"); ISO is one candidate.
        ("09:05", "2026-10-30", "T-old", "elastic", TITLE, "failed"),
    ]
    settle(page)
    assert [c for c in api_calls(requests_of(ctx)[mark:], world.origin) if c[1] == READ] == [("GET", READ)]
    assert page.locator('[data-action="load-more"]').count() == 0
    assert page.locator('[data-action="clear-filters"]').count() == 0
    assert page.title() == "Sluice"
    assert "Defender" not in page.locator("body").inner_text()


# --- O5, O7: filtering is a full load with the filters in the address ------------------------------------------------

def test_alert_list_o5_o7_apply_submits_the_filters_as_a_full_load_and_the_x_links_to_the_bare_path(world, browser):
    """Choosing an outcome and Apply loads the same path with every field in the query (empty ones too); the read
    carries the outcome; only matching rows show; the form shows the chosen value; the X links to the bare path. (O5, O7)"""
    run_async(_seed, world.dsn, A, [("T-none", "2026-11-01T11:00:00Z", ALERT_BYTES, [])])
    ctx = _context(browser, world)
    page = _open(world, ctx, ALERTS)
    _state(page, "ready")
    mark = len(requests_of(ctx))
    page.locator('select[name="outcome"]').select_option("malicious")
    with page.expect_navigation():
        page.locator('[data-action="apply"]').click()
    screen(page, "alerts")
    _state(page, "ready")
    assert where(page) == (ALERTS, {"outcome": "malicious", "fired_after": "", "fired_before": ""})
    assert [r[2] for r in _rows(page)] == ["T-1161"]
    # FORCED CHOICE: which parameters the read carries beyond `outcome` (empty filters omitted? a `limit`?).
    assert [q.get("outcome") for q in _reads(requests_of(ctx)[mark:], world.origin, READ)] == ["malicious"]
    # FORCED CHOICE: the design does not say the form is filled from the address after the load (the mock shows it).
    assert page.locator('select[name="outcome"]').input_value() == "malicious"
    assert page.locator('[data-action="clear-filters"]').get_attribute("href") == ALERTS


# --- O5: Load more ---------------------------------------------------------------------------------------------------

def _fifty_more(world: Any) -> None:
    run_async(_seed, world.dsn, A, [(f"T-more-{n:02d}", f"2026-10-01T{n // 6:02d}:{(n % 6) * 10:02d}:00Z", ALERT_BYTES, [])
                                    for n in range(PAGE)])


def test_alert_list_o5_load_more_reads_the_next_page_with_its_cursor_and_appends_the_rows(world, browser):
    """With one alert more than a page: a page of rows and Load more; a click sends one read with the cursor and appends
    the last row; Load more is gone once `next_cursor` is null. (O5)"""
    _fifty_more(world)
    ctx = _context(browser, world)
    mark = len(requests_of(ctx))
    page = _open(world, ctx, ALERTS)
    _state(page, "ready")
    assert page.locator('[data-row="alert"]').count() == PAGE
    page.locator('[data-action="load-more"]').click()
    page.locator('[data-row="alert"]').nth(PAGE).wait_for()
    settle(page)
    assert page.locator('[data-row="alert"]').count() == PAGE + 1
    assert _rows(page)[-1][2] == "T-more-00", "the oldest alert, appended last"
    assert page.locator('[data-action="load-more"]').count() == 0
    reads = _reads(requests_of(ctx)[mark:], world.origin, READ)
    assert len(reads) == 2 and "cursor" not in reads[0] and reads[1].get("cursor")


def test_alert_list_o5_a_failed_later_page_keeps_the_rows_and_says_to_reload(world, browser):
    """A 500 to the Load more read: the rows shown stay and the screen says to reload; no read is repeated. (Flows)"""
    _fifty_more(world)
    ctx = _context(browser, world)
    ctx.route(lambda u: path_is(u, READ) and "cursor=" in u, lambda route: route.fulfill(status=500, body="x"))
    page = _open(world, ctx, ALERTS)
    _state(page, "ready")
    page.locator('[data-action="load-more"]').click()
    page.get_by_text("Couldn't load more alerts. Reload the page to try again.").wait_for()
    assert page.locator('[data-row="alert"]').count() == PAGE


# --- O6: empty states ------------------------------------------------------------------------------------------------

def test_alert_list_o6_a_tenant_with_no_alerts_shows_no_alerts_yet(world, browser):
    """Bob's tenant B holds no alert: "No alerts yet", no rows. (O6, board 2)
    FORCED CHOICE: whether the filter bar shows here (board 2 has none; the design names only the text)."""
    ctx = _context(browser, world, account=world.accounts[BOB])
    page = _open(world, ctx, f"/t/{B}/alerts")
    _state(page, "empty")
    assert page.get_by_text("No alerts yet").count() == 1
    assert page.locator('[data-row="alert"]').count() == 0


def test_alert_list_o6_filters_matching_nothing_keep_the_bar_and_header_and_offer_a_clear_link(world, browser):
    """`outcome=benign` matches nothing in A: the filter bar and the table header stay, with one "No alerts match these
    filters" row and a link to the bare path. (O6, board 3)"""
    ctx = _context(browser, world)
    page = _open(world, ctx, f"{ALERTS}?outcome=benign&fired_after=&fired_before=")
    _state(page, "no-match")
    assert page.get_by_text("No alerts match these filters").count() == 1
    assert page.locator('select[name="outcome"]').count() == 1
    assert page.locator("thead th").count() == 4
    assert ALERTS in [link.get_attribute("href") for link in page.locator('[data-action="clear-filters"]').all()]


# --- O7: an address the screen cannot read ---------------------------------------------------------------------------

def test_alert_list_o7_an_invalid_filter_address_sends_no_read_and_is_not_rewritten(world, browser):
    """`outcome=evil`: "These filters aren't valid" with the clear link; no alerts read; the address stays. (O7)"""
    ctx = _context(browser, world)
    mark = len(requests_of(ctx))
    page = _open(world, ctx, f"{ALERTS}?outcome=evil")
    _state(page, "invalid")
    assert page.get_by_text("These filters aren't valid").count() == 1
    assert page.locator('[data-action="clear-filters"]').first.get_attribute("href") == ALERTS
    settle(page)
    assert [c for c in api_calls(requests_of(ctx)[mark:], world.origin) if c[1] == READ] == []
    assert where(page) == (ALERTS, {"outcome": "evil"})


# --- O4: the address through sign-in ---------------------------------------------------------------------------------

def test_alert_list_o4_signed_out_the_alerts_address_returns_to_its_path_without_the_query(world, context, requests):
    """Signed out, a filtered alerts address goes through sign-in and comes back to the path; the query is dropped (C6,
    D-Q's recommended v1). (O4)"""
    page = context.new_page()
    page.goto(f"{world.origin}{ALERTS}?outcome=malicious")
    screen(page, "alerts")
    assert logins(requests, world.origin) == [ALERTS]
    assert where(page) == (ALERTS, {})


# --- O8: Home --------------------------------------------------------------------------------------------------------

def test_alert_list_o8_home_links_each_of_the_persons_tenants_to_its_alerts(world, context):
    """Ann (tenant A only): one link to A's alerts address, which opens the alerts screen. No invite-only text. (O8)
    FORCED CHOICE (D-T, open): the link's label; only its target is asserted."""
    sign_in(world, context)
    page = context.new_page()
    page.goto(f"{world.origin}/home")
    screen(page, "home")
    links = page.locator(f'a[href="{ALERTS}"]')
    assert links.count() == 1
    assert "invite-only" not in page.locator("body").inner_text()
    links.click()
    screen(page, "alerts")


async def _tenantless(dsn: str, email: str) -> str:
    """An active person with no membership and no invitation; returns their sign-in account."""
    from defender.identity.postgres import PostgresIdentityRepository
    from defender.tests.support.identity._seed1496 import seed_user

    repo = PostgresIdentityRepository(dsn)
    try:
        await seed_user(repo, email, created_at=dt.datetime.now(dt.UTC), status="active", display_name=email)
    finally:
        await repo.close()
    return await link_account(dsn, email)


def test_alert_list_o8_o9_home_with_no_tenant_says_sluice_is_invite_only(world, context):
    """A person with no tenant and no invitation: the invite-only text naming their email, and no alerts link. (O8, O9)
    FORCED CHOICES: the design's text has a straight apostrophe and stops at the email; the mock's has a typographic
    one and adds "Once they do, the invitation appears here."; this case asserts the design's sentences only."""
    email = "carol@c.example"
    world.front.sign_in_as(run_async(_tenantless, world.dsn, email))
    sign_in(world, context)
    page = context.new_page()
    page.goto(f"{world.origin}/home")
    screen(page, "home")
    text = " ".join(page.locator("body").inner_text().split())
    assert ("You haven't been added to a team yet. Sluice is invite-only. "
            f"Ask your administrator to invite {email}.") in text
    assert page.locator('a[href^="/t/"]').count() == 0
    assert "Defender" not in text
