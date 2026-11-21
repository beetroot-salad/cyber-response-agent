# ruff: noqa: PT018 — each compound assert states one fact about one page
"""Alert list design (#1581) in the pinned Chromium through the repo's ingress over the real API: the alerts screen
(O5, O6, O7, O12), its address (O4), Home (O8, O11) and the product's name (O9).

The browser's zone is Europe/Paris unless a test says otherwise (UTC+1 on 1 November) and its clock is fixed at
`BROWSER_NOW` (16:00 there), so "Today"/"Yesterday" and local times are stated, not computed. `world` already holds
one alert of A, `T-1161`, fired 12:00Z, whose one investigation completed `malicious`.

Markers: `data-screen="alerts"` is the shape's name (the convention every screen follows). The rest are FORCED CHOICES
(the design names none): `data-state` (O12's seven values), each row `[data-row="alert"]` with
`[data-field=fired-time|fired-day|ticket|vendor|title|status]`, `[data-action="load-more"]`,
`[data-action="clear-filters"]` (the X and the empty state's clear link), `[data-action="apply"]`, the form's fields by
their query names (`outcome` a <select>, `fired_after` and `fired_before` <input type="datetime-local">, and the hidden
`tz`), the table's four header columns (`thead th`), the status cell's `data-tone`, and Home's buttons by their role and
name. Nothing in this file has run: Chromium and Caddy are not installed where it was written."""
from __future__ import annotations

import datetime as dt
import itertools
import urllib.parse
import zoneinfo
from typing import Any

import pytest

from defender.tests.frontend._flow1161 import (
    RECONNECT,
    VISIBLE,
    api_calls,
    await_aborted,
    logins,
    navigations_to,
    screen,
    settle,
    shown,
    sign_in,
    where,
)
from defender.tests.frontend.conftest import WAIT_MS, requests_of
from defender.tests.support.api._server1083 import A, ANN, B, BOB
from defender.tests.support.api._signin1161 import link_account
from defender.tests.support.frontend._browser1161 import abort_login_navigation, path_is, run_async
from defender.tests.support.jobs._jobs1342 import ALERT_BYTES, PADDED_ALERT_BYTES, TITLE

ZONE = "Europe/Paris"
NEW_YORK = "America/New_York"
BROWSER_NOW = "2026-11-01T15:00:00Z"
ALERTS = f"/t/{A}/alerts"
ALERTS_OF_B = f"/t/{B}/alerts"
READ = f"/api/tenants/{A}/alerts"
UNKNOWN_TENANT = "0b6f1c1e-3c55-4a4e-9a51-000000000000"
NO_TITLE = "No title — the alert mapping had no title entry when this alert arrived"
CODES = {"benign", "false-positive", "inconclusive", "malicious", "unresolved"}
PAGE = 50


def _at(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def _plain(text: str) -> str:
    """Whitespace collapsed and typographic apostrophes straightened: the design writes `'`, the mock `’`."""
    return " ".join(text.replace("’", "'").split())


async def _seed(dsn: str, tenant: str, alerts: list[tuple[str, str, bytes, list[str]]],
                world_investigation: str | None = None) -> None:
    """Each `(ticket, fired_at, raw, ends)` stored for `tenant` through the store's own API; `ends` are, oldest first,
    each investigation's end: `completed:<disposition>`, `failed`, `unparseable`, `aborted`, `running` or `queued` (the
    last two only last). `T-1161` is the world's own alert (found through its investigation): only investigations are
    added to it. The store's clock moves a minute per write, so "newest" is by `created_at`."""
    from defender.jobs import JobStore

    at = [_at("2026-11-01T13:00:00Z")]

    def clock() -> dt.datetime:
        at[0] += dt.timedelta(minutes=1)
        return at[0]

    store = JobStore(dsn, clock=clock)
    queued: list[tuple[str, str]] = []  # created last: a claim takes the oldest queued row of any alert
    try:
        for ticket, fired, raw, ends in alerts:
            if ticket == "T-1161":
                assert world_investigation is not None, "premise: the world's investigation names its alert"
                known = await store.get_investigation(tenant, world_investigation)
                assert known is not None
                alert_id = str(known.alert_id)
            else:
                alert_id = str((await store.insert_alert(
                    tenant, vendor="elastic", vendor_ticket_id=ticket, fired_at=_at(fired), changed_at=_at(fired),
                    received_at=_at(fired), raw=raw)).alert_id)
            for n, end in enumerate(ends):
                if end == "queued":
                    queued.append((alert_id, f"seed-{n}"))
                    continue
                inv, _ = await store.create_investigation(tenant, alert_id, f"seed-{n}", actor="seed")
                if end == "aborted":
                    await store.cancel_investigation(tenant, inv.investigation_id, actor="seed")
                    continue
                claimed = await store.claim()
                assert claimed is not None and claimed.record.investigation_id == inv.investigation_id, "premise"
                if end == "running":
                    continue
                stage, _, disposition = end.partition(":")
                await store.finish(tenant, inv.investigation_id, stage=stage, disposition=disposition or None,
                                   cost_usd=0.0, failure_reason="no_report" if stage == "failed" else None)
        for alert_id, key in queued:
            await store.create_investigation(tenant, alert_id, key, actor="seed")
    finally:
        await store.close()


def _more(world: Any, count: int, *, prefix: str = "T-more") -> None:
    """`count` alerts with no investigation, fired a minute apart from 1 October (oldest is `<prefix>-000`)."""
    base = _at("2026-10-01T00:00:00Z")
    run_async(_seed, world.dsn, A, [
        (f"{prefix}-{n:03d}", (base + dt.timedelta(minutes=n)).isoformat(), ALERT_BYTES, []) for n in range(count)])


async def _person(dsn: str, email: str, member_of: tuple[str, ...] = (),
                  invited_to: tuple[str, ...] = ()) -> dict[str, str]:
    """An active person (made when new) with a membership in each of `member_of` and an open invitation to each of
    `invited_to`, through the identity repository's own operations; the invitations' ids by tenant. An active person's
    sign-in accepts nothing, so an invitation stays open until it is accepted here."""
    from defender.identity.postgres import PostgresIdentityRepository
    from defender.tests.support.identity._seed1496 import seed_user

    repo = PostgresIdentityRepository(dsn)
    now = dt.datetime.now(dt.UTC)
    try:
        user = await repo.user_by_email(email) or await seed_user(
            repo, email, created_at=now, status="active", display_name=email)
        for tenant in member_of:
            row = await repo.ensure_invitation(user.id, tenant, invited_by=None, now=now)
            assert row is not None and await repo.accept_invitation(row.id, now=now), "premise: a member"
        ids: dict[str, str] = {}
        for tenant in invited_to:
            row = await repo.ensure_invitation(user.id, tenant, invited_by=None, now=now)
            assert row is not None, "premise: an open invitation"
            ids[tenant] = str(row.id)
    finally:
        await repo.close()
    return ids


async def _revoke(dsn: str, invitation_id: str) -> None:
    from defender.identity.postgres import PostgresIdentityRepository

    repo = PostgresIdentityRepository(dsn)
    try:
        assert await repo.revoke_invitation(invitation_id), "premise: the invitation was open"
    finally:
        await repo.close()


def _signed_in(browser: Any, world: Any, *, account: str | None = None, zone: str = ZONE,
               locale: str | None = None) -> Any:
    """A guarded context in `zone` (and in `locale` when given), signed in as Ann unless `account` is given."""
    ctx = browser.new_context(timezone_id=zone, **({} if locale is None else {"locale": locale}))
    ctx.set_default_timeout(WAIT_MS)
    if account is not None:
        world.front.sign_in_as(account)
    sign_in(world, ctx)
    return ctx


def _carol(world: Any, browser: Any, member_of: tuple[str, ...] = (),
           invited_to: tuple[str, ...] = ()) -> tuple[Any, dict[str, str]]:
    """A signed-in context of `carol@c.example` (no tenant unless `member_of`) and her open invitations' ids."""
    email = "carol@c.example"
    ids = run_async(_person, world.dsn, email, member_of, invited_to)
    return _signed_in(browser, world, account=run_async(link_account, world.dsn, email)), ids


def _open(world: Any, ctx: Any, address: str, *, state: str | None = "ready") -> Any:
    page = ctx.new_page()
    page.clock.set_fixed_time(BROWSER_NOW)
    page.goto(f"{world.origin}{address}")
    screen(page, "alerts")
    if state is not None:
        _state(page, state)
    return page


def _state(page: Any, state: str) -> None:
    page.locator(f'[data-screen="alerts"][data-state="{state}"]').wait_for()


def _home(world: Any, ctx: Any) -> Any:
    page = ctx.new_page()
    page.goto(f"{world.origin}/home")
    screen(page, "home")
    return page


def _rows(page: Any) -> list[tuple[str, ...]]:
    fields = ("fired-time", "fired-day", "ticket", "vendor", "title", "status")
    return [tuple(row.locator(f'[data-field="{f}"]').inner_text().strip() for f in fields)
            for row in page.locator('[data-row="alert"]').all()]


def _tickets(page: Any) -> list[str]:
    return [row[2] for row in _rows(page)]


def _reads(requests: Any, origin: str, path: str = READ) -> list[dict[str, str]]:
    """The query of each GET of exactly `path` the pages sent, in order."""
    return [dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r.url).query, keep_blank_values=True))
            for r in requests if r.method == "GET" and r.url.startswith(origin)
            and urllib.parse.urlsplit(r.url).path == path]


def _instant(text: str | None) -> dt.datetime | None:
    return None if text is None else _at(text)


def _holding(ctx: Any, matches: Any) -> list[Any]:
    """Route every request `matches` selects into the returned list instead of the network, held until the test
    `continue_()`s it."""
    held: list[Any] = []
    ctx.route(matches, lambda route: held.append(route))
    return held


def _until_held(page: Any, held: list[Any], count: int = 1) -> None:
    for _ in range(WAIT_MS // 50):
        if len(held) >= count:
            return
        page.wait_for_timeout(50)
    raise AssertionError(f"{len(held)} of {count} requests were ever held")


def _until_true(page: Any, check: Any, what: str) -> None:
    for _ in range(WAIT_MS // 50):
        if check():
            return
        page.wait_for_timeout(50)
    raise AssertionError(f"never true: {what}")


def _no_defender(page: Any) -> None:
    """O9: nothing a person reads says Defender: the visible text, in any letter case, and the tab's title."""
    shown_text = f"{page.locator('body').inner_text()}\n{page.title()}"
    assert "defender" not in shown_text.lower()


# --- O5, O9, AP4: the rows -------------------------------------------------------------------------------------------

def test_alert_list_o5_o9_rows_show_local_fired_time_ticket_title_and_one_status_newest_first(world, browser):
    """Newest first: zone time over Today/Yesterday/the date, ticket over vendor, title or the no-title text, and one
    status: the outcome when known (a queued rerun does not hide it), else the newest investigation's state in the
    screen's words. One read, no Load more, no X; Sluice never Defender. (O5, O9)"""
    run_async(_seed, world.dsn, A, [
        ("T-queued", "2026-11-01T14:00:00Z", ALERT_BYTES, ["queued"]),
        ("T-run", "2026-11-01T11:00:00Z", ALERT_BYTES, ["running"]),
        ("T-none", "2026-10-31T22:30:00Z", PADDED_ALERT_BYTES, []),  # 23:30 in Paris the day before; no title
        ("T-old", "2026-10-30T08:05:00Z", ALERT_BYTES, ["failed"]),
        ("T-1161", "", b"", ["queued"]),  # a rerun queued over the completed `malicious`
    ], world.investigation)
    ctx = _signed_in(browser, world)
    mark = len(requests_of(ctx))
    page = _open(world, ctx, ALERTS)
    assert _rows(page) == [
        ("15:00", "Today", "T-queued", "elastic", TITLE, "queued"),
        ("13:00", "Today", "T-1161", "elastic", TITLE, "malicious"),
        ("12:00", "Today", "T-run", "elastic", TITLE, "investigating"),
        ("23:30", "Yesterday", "T-none", "elastic", NO_TITLE, "not investigated"),
        ("09:05", "30 Oct", "T-old", "elastic", TITLE, "failed"),
    ]
    settle(page)
    assert len(_reads(requests_of(ctx)[mark:], world.origin)) == 1
    assert page.locator('[data-action="load-more"]').count() == 0
    assert page.locator('[data-action="clear-filters"]').count() == 0
    assert page.locator("thead th").count() == 4
    assert page.title() == "Sluice"
    _no_defender(page)


def test_alert_list_o5_ap4_the_status_column_names_each_outcome_and_each_state(world, browser):
    """Each of the five outcome codes shows as itself; with no outcome, `latest_status` shows null as "not
    investigated", queued as "queued", running as "investigating", aborted as "cancelled", failed and unparseable
    as "failed"; an earlier outcome stays under a newer aborted rerun. (O5, AP4)"""
    ends = {"T-benign": ["completed:benign"], "T-fp": ["completed:false-positive"],
            "T-inc": ["completed:inconclusive"], "T-mal": ["completed:malicious"], "T-unres": ["completed:unresolved"],
            "T-null": [], "T-queued": ["queued"], "T-running": ["running"], "T-aborted": ["aborted"],
            "T-failed": ["failed"], "T-unparse": ["unparseable"],
            "T-rerun": ["completed:benign", "aborted"], "T-rerun-failed": ["completed:inconclusive", "failed"]}
    base = _at("2026-10-31T00:00:00Z")
    run_async(_seed, world.dsn, A, [
        (ticket, (base + dt.timedelta(minutes=n)).isoformat(), ALERT_BYTES, e) for n, (ticket, e) in enumerate(ends.items())])
    page = _open(world, _signed_in(browser, world), ALERTS)
    status = {row[2]: row[5] for row in _rows(page)}
    tone = {row.locator('[data-field="ticket"]').inner_text().split("\n")[0].strip():
            row.locator('[data-field="status"]').get_attribute("data-tone")
            for row in page.locator('[data-row="alert"]').all()}
    assert status == {
        "T-benign": "benign", "T-fp": "false-positive", "T-inc": "inconclusive", "T-mal": "malicious",
        "T-unres": "unresolved", "T-null": "not investigated", "T-queued": "queued", "T-running": "investigating",
        "T-aborted": "cancelled", "T-failed": "failed", "T-unparse": "failed", "T-rerun": "benign",
        "T-rerun-failed": "inconclusive", "T-1161": "malicious"}
    assert {s for s in status.values() if s in CODES} == CODES, "positive control: every code was seeded and shown"
    quiet, outlined, solid = {"benign", "false-positive"}, {"inconclusive", "unresolved"}, {"malicious"}
    assert tone == {ticket: "solid" if word in solid else "outlined" if word in outlined else "quiet" if word in quiet
                    else "muted" for ticket, word in status.items()}, "data-tone on each status cell (every state word muted)"
    assert {*tone.values()} == {"solid", "outlined", "quiet", "muted"}, "positive control: each tone was seen"


def test_alert_list_o5_dates_are_unpadded_with_fixed_english_months_and_the_year_only_when_not_this_one(world, browser):
    """Day unpadded, month a fixed three-letter English name ("Sep", never "Sept"), the year after it with no comma
    when it is not the current one. (O5)"""
    run_async(_seed, world.dsn, A, [("T-2025", "2025-12-20T12:00:00Z", ALERT_BYTES, []),
                                    ("T-2026", "2026-10-20T12:00:00Z", ALERT_BYTES, []),
                                    ("T-sep-5", "2026-09-05T12:00:00Z", ALERT_BYTES, []),
                                    ("T-sep-25", "2026-09-25T12:00:00Z", ALERT_BYTES, []),
                                    ("T-sep-5-2025", "2025-09-05T12:00:00Z", ALERT_BYTES, [])])
    page = _open(world, _signed_in(browser, world), ALERTS)
    days = {row[2]: row[1] for row in _rows(page)}
    assert days["T-2026"] == "20 Oct"
    assert days["T-2025"] == "20 Dec 2025"
    assert days["T-sep-5"] == "5 Sep" and days["T-sep-25"] == "25 Sep"
    assert days["T-sep-5-2025"] == "5 Sep 2025"


THAI = "th-TH-u-nu-thai"


def test_alert_list_o5_o7_a_browser_whose_default_locale_has_another_calendar_digits_and_month_names_changes_nothing(
        world, browser):
    """A context whose default locale is Thai (Buddhist calendar, Thai digits, Thai month names, asserted from the page's own
    `resolvedOptions()`): rows show English months and Latin digits, the year the Gregorian one, and a link's times read
    and refill as in any browser. (O5, O7)"""
    run_async(_seed, world.dsn, A, [("T-2025", "2025-12-20T12:00:00Z", ALERT_BYTES, []),
                                    ("T-sep-5", "2026-09-05T12:00:00Z", ALERT_BYTES, []),
                                    ("T-in", "2026-11-11T23:30:00Z", ALERT_BYTES, []),
                                    ("T-out", "2026-11-11T22:30:00Z", ALERT_BYTES, [])])
    ctx = _signed_in(browser, world, locale=THAI)
    page = _open(world, ctx, ALERTS)
    calendar, digits, month, year = page.evaluate(
        "() => [new Intl.DateTimeFormat().resolvedOptions().calendar, new Intl.DateTimeFormat().resolvedOptions().numberingSystem,"
        " new Date(0).toLocaleString(undefined, {month: 'short', timeZone: 'UTC'}),"
        " new Date(0).toLocaleString(undefined, {year: 'numeric', timeZone: 'UTC'})]")
    assert calendar != "gregory" and digits != "latn" and month != "Jan" and year != "1970", "premise: a default locale unlike en-US"
    days = {row[2]: row[:2] for row in _rows(page)}
    assert days["T-sep-5"] == ("14:00", "5 Sep") and days["T-2025"] == ("13:00", "20 Dec 2025")
    assert days["T-in"] == ("00:30", "12 Nov")
    linked = _open(world, ctx, f"{ALERTS}?fired_after=2026-11-11T18:00&tz={NEW_YORK}")
    assert _tickets(linked) == ["T-in"]  # 18:00 in New York is 23:00Z
    assert linked.locator('input[name="fired_after"]').input_value() == "2026-11-12T00:00"  # Paris, Latin digits
    assert linked.locator('input[name="tz"]').input_value() == ZONE


# --- O5, O7, AP4: filtering is a full load with the filters in the address --------------------------------------------

def test_alert_list_o5_o7_the_outcome_menu_offers_all_the_five_codes_and_no_outcome_yet(world, browser):
    """The Outcome menu: All (empty value), the five codes by their own names, and "No outcome yet" (value `none`). (O5, AP4)"""
    page = _open(world, _signed_in(browser, world), ALERTS)
    options = page.locator('select[name="outcome"] option')
    values = [o.get_attribute("value") for o in options.all()]
    labels = [o.inner_text().strip() for o in options.all()]
    assert values[0] == "" and labels[0] == "All"
    assert values[-1] == "none" and labels[-1] == "No outcome yet"
    assert sorted(values[1:-1]) == sorted(CODES) and labels[1:-1] == values[1:-1]
    for name in ("fired_after", "fired_before"):
        assert page.locator(f'input[name="{name}"]').get_attribute("type") == "datetime-local", name
    assert page.locator("thead th").count() == 4


def test_alert_list_o5_o7_apply_is_a_full_load_that_sends_every_field_and_the_viewers_zone(world, browser):
    """Choosing an outcome and times and Apply loads the same path with every field in the query, `tz` the viewer's
    zone; the read carries the instants; only matching rows show; the form shows the values; the X links to the bare
    path. (O5, O7)"""
    run_async(_seed, world.dsn, A, [("T-a", "2026-11-01T11:30:00Z", ALERT_BYTES, []),
                                    ("T-b", "2026-11-01T12:45:00Z", ALERT_BYTES, []),
                                    ("T-c", "2026-11-01T13:30:00Z", ALERT_BYTES, [])])
    ctx = _signed_in(browser, world)
    page = _open(world, ctx, ALERTS)
    assert page.locator('[data-action="clear-filters"]').count() == 0
    assert page.locator('input[name="tz"]').input_value() == ZONE
    mark = len(requests_of(ctx))
    page.locator('input[name="fired_after"]').fill("2026-11-01T13:30")  # 12:30Z
    page.locator('input[name="fired_before"]').fill("2026-11-01T14:15")  # 13:15Z
    with page.expect_navigation():
        page.locator('[data-action="apply"]').click()
    screen(page, "alerts")
    _state(page, "ready")
    want = {"outcome": "", "fired_after": "2026-11-01T13:30", "fired_before": "2026-11-01T14:15", "tz": ZONE}
    assert where(page) == (ALERTS, want)
    assert navigations_to(requests_of(ctx)[mark:], world.origin, ALERTS)[-1] == want, "a document load, not history"
    assert _tickets(page) == ["T-b"]
    [read] = _reads(requests_of(ctx)[mark:], world.origin)
    assert read.get("outcome") in (None, "")
    assert _instant(read.get("fired_after")) == _at("2026-11-01T12:30:00Z")
    assert _instant(read.get("fired_before")) == _at("2026-11-01T13:15:00Z")
    assert page.locator('input[name="fired_after"]').input_value() == "2026-11-01T13:30"
    assert page.locator('input[name="fired_before"]').input_value() == "2026-11-01T14:15"
    assert page.locator('[data-action="clear-filters"]').get_attribute("href") == ALERTS


@pytest.mark.parametrize(("choice", "kept"), [("malicious", ["T-1161"]), ("none", ["T-run", "T-none"]),
                                              ("benign", [])])
def test_alert_list_o5_o7_the_outcome_menu_filters_the_rows_the_read_returns(world, browser, choice, kept):
    """An outcome chosen and applied is in the address and the read, and the rows are those the API sends for it: a
    code matches its alerts, "No outcome yet" those with no completed investigation. (O5, O7, O2)"""
    run_async(_seed, world.dsn, A, [("T-run", "2026-11-01T11:00:00Z", ALERT_BYTES, ["running"]),
                                    ("T-none", "2026-10-31T11:00:00Z", ALERT_BYTES, [])])
    ctx = _signed_in(browser, world)
    page = _open(world, ctx, ALERTS)
    mark = len(requests_of(ctx))
    page.locator('select[name="outcome"]').select_option(choice)
    with page.expect_navigation():
        page.locator('[data-action="apply"]').click()
    screen(page, "alerts")
    _state(page, "ready" if kept else "no-match")
    assert where(page)[1]["outcome"] == choice
    assert _tickets(page) == kept
    assert [q.get("outcome") for q in _reads(requests_of(ctx)[mark:], world.origin)] == [choice]
    assert page.locator('select[name="outcome"]').input_value() == choice


def test_alert_list_o7_a_link_written_in_another_zone_keeps_its_instants_and_refills_in_the_viewers(world, browser):
    """A Paris link opened in New York selects the same instants, shows them in New York's wall time with `tz` New
    York, and Apply keeps the instants. (O7)"""
    run_async(_seed, world.dsn, A, [("T-in", "2026-11-11T23:30:00Z", ALERT_BYTES, []),
                                    ("T-out", "2026-11-11T22:30:00Z", ALERT_BYTES, [])])
    ctx = _signed_in(browser, world, zone=NEW_YORK)
    mark = len(requests_of(ctx))
    page = _open(world, ctx, f"{ALERTS}?outcome=&fired_after=2026-11-12T00:00&fired_before=&tz={ZONE}")
    assert _tickets(page) == ["T-in"]  # 00:00 in Paris is 23:00Z: T-in (23:30Z) is in, T-out (22:30Z) is not
    paris_midnight = _at("2026-11-11T23:00:00Z")
    assert [_instant(q.get("fired_after")) for q in _reads(requests_of(ctx)[mark:], world.origin)] == [paris_midnight]
    assert page.locator('input[name="fired_after"]').input_value() == "2026-11-11T18:00"  # 18:00 in New York
    assert page.locator('input[name="fired_before"]').input_value() == ""
    assert page.locator('input[name="tz"]').input_value() == NEW_YORK
    mark = len(requests_of(ctx))
    with page.expect_navigation():
        page.locator('[data-action="apply"]').click()
    screen(page, "alerts")
    _state(page, "ready")
    assert where(page) == (ALERTS, {"outcome": "", "fired_after": "2026-11-11T18:00", "fired_before": "",
                                    "tz": NEW_YORK})
    assert _tickets(page) == ["T-in"]
    assert [_instant(q.get("fired_after")) for q in _reads(requests_of(ctx)[mark:], world.origin)] == [paris_midnight]


def test_alert_list_o7_a_link_without_tz_reads_its_times_in_the_viewers_zone(world, browser):
    """With no `tz`, the same wall time is a different instant in each viewer's zone. (O7)"""
    run_async(_seed, world.dsn, A, [("T-1", "2026-11-11T23:30:00Z", ALERT_BYTES, [])])
    address = f"{ALERTS}?fired_after=2026-11-12T00:00"
    in_paris = _open(world, _signed_in(browser, world), address)
    in_new_york = _open(world, _signed_in(browser, world, zone=NEW_YORK), address, state="no-match")
    assert _tickets(in_paris) == ["T-1"]  # 23:00Z
    assert _tickets(in_new_york) == []  # 05:00Z the next day: after the alert


# --- O5, O12: Load more ----------------------------------------------------------------------------------------------

def test_alert_list_o5_load_more_chains_each_page_by_the_cursor_the_last_one_gave(world, browser):
    """101 alerts: 50 rows and Load more; each click is one read with a new cursor and appends 50, then 1; Load more
    goes when `next_cursor` is null; no row twice, newest first throughout; no later stimulus repeats a read. (O5, usePagedRead)"""
    _more(world, PAGE * 2)
    ctx = _signed_in(browser, world)
    mark = len(requests_of(ctx))
    page = _open(world, ctx, ALERTS)
    assert page.locator('[data-row="alert"]').count() == PAGE
    page.locator('[data-action="load-more"]').click()
    page.locator('[data-row="alert"]').nth(PAGE * 2 - 1).wait_for()
    assert page.locator('[data-row="alert"]').count() == PAGE * 2
    mark = len(requests_of(ctx))  # a reload is a new load: page 1 alone, one read without a cursor (AP3)
    page.reload()
    _state(page, "ready")
    settle(page)
    assert page.locator('[data-row="alert"]').count() == PAGE
    assert [q.get("cursor") for q in _reads(requests_of(ctx)[mark:], world.origin)] == [None]
    for expected in (PAGE * 2, PAGE * 2 + 1):
        page.locator('[data-action="load-more"]').click()
        page.locator('[data-row="alert"]').nth(expected - 1).wait_for()
        assert page.locator('[data-row="alert"]').count() == expected
    assert page.locator('[data-action="load-more"]').count() == 0
    tickets = _tickets(page)
    assert tickets == ["T-1161"] + [f"T-more-{n:03d}" for n in range(PAGE * 2 - 1, -1, -1)]
    page.evaluate(VISIBLE)
    page.evaluate(RECONNECT)
    settle(page)
    reads = _reads(requests_of(ctx)[mark:], world.origin)
    cursors = [q.get("cursor") for q in reads]
    assert len(reads) == 3 and cursors[0] is None and all(cursors[1:]) and cursors[1] != cursors[2]


def test_alert_list_o5_load_more_under_a_filter_sends_the_filter_with_every_cursor(world, browser):
    """Under `outcome=none` 51 rows make two pages, and both reads carry the filter; the world's malicious alert is in
    neither. (O5, O2)"""
    _more(world, PAGE + 1, prefix="T-none")
    ctx = _signed_in(browser, world)
    mark = len(requests_of(ctx))
    page = _open(world, ctx, f"{ALERTS}?outcome=none&fired_after=&fired_before=&tz={ZONE}")
    assert page.locator('[data-row="alert"]').count() == PAGE
    page.locator('[data-action="load-more"]').click()
    page.locator('[data-row="alert"]').nth(PAGE).wait_for()
    settle(page)
    assert page.locator('[data-row="alert"]').count() == PAGE + 1 and "T-1161" not in _tickets(page)
    reads = _reads(requests_of(ctx)[mark:], world.origin)
    assert [q.get("outcome") for q in reads] == ["none", "none"] and [bool(q.get("cursor")) for q in reads] == [False, True]


@pytest.mark.parametrize("failure", ["500", "not-json", "404"])
def test_alert_list_o5_a_failed_later_page_keeps_the_rows_says_to_reload_and_is_not_retried(world, browser, failure):
    """A later page answered 500, 404 or with a body that is not JSON: the 50 rows stay and the screen stays `ready` (not
    the error screen), "Couldn't load more alerts. Reload the page to try again." shows under them, and no read with
    that cursor is sent again, whatever the tab or network does; Load more is gone. (O5, usePagedRead)"""
    _more(world, PAGE)
    ctx = _signed_in(browser, world)
    answer = {"500": dict(status=500, body="x"), "not-json": dict(status=200, body="<html>"),
              "404": dict(status=404, body="{}")}[failure]
    ctx.route(lambda u: path_is(u, READ) and "cursor=" in u, lambda route: route.fulfill(**answer))
    mark = len(requests_of(ctx))
    page = _open(world, ctx, ALERTS)
    page.locator('[data-action="load-more"]').click()
    page.get_by_text("Couldn't load more alerts. Reload the page to try again.").wait_for()
    page.evaluate(VISIBLE)
    page.evaluate(RECONNECT)
    settle(page)
    assert page.locator('[data-row="alert"]').count() == PAGE
    assert shown(page) == "alerts" and page.locator('[data-screen="alerts"]').first.get_attribute("data-state") == "ready"
    assert len([q for q in _reads(requests_of(ctx)[mark:], world.origin) if q.get("cursor")]) == 1
    assert page.get_by_text("Couldn't load more alerts. Reload the page to try again.").count() == 1
    assert page.locator('[data-action="load-more"]').count() == 0


LATER_FAILED = "Couldn't load more alerts. Reload the page to try again."


#: Answers 200 with a JSON content type to a later page's read that are not a page of alerts (#1581 G8): not a
#: `{items, next_cursor}` object, an `items` that is not a list, a `next_cursor` that is neither text nor null, an entry that
#: is not an alert, and text that is not JSON at all.
NOT_A_PAGE = {
    "empty object": "{}", "null": "null", "an array": "[]", "a string": '"page"', "a number": "3",
    "items a number": '{"items":3,"next_cursor":null}', "items an object": '{"items":{},"next_cursor":null}',
    "items missing": '{"next_cursor":null}', "next_cursor missing": '{"items":[]}',
    "next_cursor a number": '{"items":[],"next_cursor":7}',
    "an entry null": '{"items":[null],"next_cursor":null}', "an entry a number": '{"items":[3],"next_cursor":null}',
    "an entry an empty object": '{"items":[{}],"next_cursor":null}',
    "an entry with mistyped fields": '{"items":[{"alert_id":5,"fired_at":7,"ticket":null}],"next_cursor":null}',
    "html with a JSON type": "<html>", "an empty body with a JSON type": "",
}


@pytest.mark.parametrize("body", NOT_A_PAGE.values(), ids=NOT_A_PAGE.keys())
def test_alert_list_o5_a_later_page_answered_200_with_a_body_that_is_not_a_page_is_that_pages_failure_never_thrown(
        world, browser, body):
    """The second page's read answered 200 with a body that is not a page of alerts: the screen shows exactly the rows of
    page 1 (the same ones, in the same order), "Couldn't load more alerts. Reload the page to try again." once, no Load more,
    and stays `ready` rather than the error screen. Design r3.1 (Flows, shell `usePagedRead`): a later page's failure,
    fault included, is returned as that page's state and never thrown, so the rows already shown stay; and "A later page
    that is not a page ... stays that page's state" (owner ruling: keep the Flows promise). (O5, G8)"""
    _more(world, PAGE)
    ctx = _signed_in(browser, world)
    ctx.route(lambda u: path_is(u, READ) and "cursor=" in u,
              lambda route: route.fulfill(status=200, content_type="application/json", body=body))
    page = _open(world, ctx, ALERTS)
    first = _rows(page)
    assert len(first) == PAGE
    page.locator('[data-action="load-more"]').click()
    page.get_by_text(LATER_FAILED).wait_for()
    settle(page)
    assert _rows(page) == first
    assert shown(page) == "alerts" and page.locator('[data-screen="alerts"]').first.get_attribute("data-state") == "ready"
    assert page.get_by_text(LATER_FAILED).count() == 1 and page.locator('[data-action="load-more"]').count() == 0


async def _plant_completed_without_outcome(dsn: str, tickets: list[str]) -> None:
    """For each ticket (its alert already stored), an investigation that is `completed` with its disposition set, written by
    SQL so the store's own finish does not set the alert's stored outcome: the alert's outcome stays null."""
    from defender.tests.support.shared._postgres1339 import execute

    for ticket in tickets:
        execute(dsn, """
            INSERT INTO jobs.investigations (id, tenant_id, alert_id, request_key, attempt, stage, created_at, finished_at,
                                             disposition, cost_usd, cost_is_lower_limit, update_ticket)
            SELECT gen_random_uuid(), tenant_id, id, 'planted', 1, 'completed', now(), now(), 'benign', 0, false, false
            FROM jobs.alerts WHERE vendor_ticket_id = %s""", (ticket,))
        [(outcome,)] = execute(dsn, "SELECT outcome FROM jobs.alerts WHERE vendor_ticket_id = %s", (ticket,))
        assert outcome is None, "premise: the planted alert has no stored outcome"


@pytest.mark.parametrize("where_", ["page one", "a later page"])
def test_alert_list_r33_a_completed_row_with_no_stored_outcome_is_drawn_as_completed_muted_on_page_one_and_on_a_later_page(
        world, browser, where_):
    """One alert whose newest investigation is `completed` and whose stored outcome is null (planted by SQL, past the store),
    among the rows of page 1 or on the second page: every row shows (the world's, the 60 others, in both pages), that row's
    status reads "completed" with `data-tone="muted"`, the state is `ready`, and Load more of the second page shows no
    "Couldn't load more". One such row never costs the screen its other rows. (r3.3 A completed row with no stored outcome)"""
    base = _at("2026-10-01T00:00:00Z")
    run_async(_seed, world.dsn, A, [
        (f"T-p-{n:03d}", (base + dt.timedelta(minutes=n)).isoformat(), ALERT_BYTES, []) for n in range(PAGE + 10)])
    planted = f"T-p-{PAGE + 8:03d}" if where_ == "page one" else "T-p-002"
    run_async(_plant_completed_without_outcome, world.dsn, [planted])
    page = _open(world, _signed_in(browser, world), ALERTS)
    assert page.locator('[data-row="alert"]').count() == PAGE
    first_page = [t.split("\n")[0].strip() for t in _tickets(page)]
    assert (planted in first_page) == (where_ == "page one"), "premise: the planted row is where the case says"
    page.locator('[data-action="load-more"]').click()
    _until_true(page, lambda: page.locator('[data-row="alert"]').count() == PAGE + 11, "every row of both pages shows")
    settle(page)
    assert page.locator('[data-screen="alerts"]').first.get_attribute("data-state") == "ready"
    assert page.get_by_text(LATER_FAILED).count() == 0
    row = page.locator('[data-row="alert"]').filter(has=page.locator('[data-field="ticket"]', has_text=planted))
    assert row.count() == 1
    cell = row.locator('[data-field="status"]')
    assert cell.inner_text().strip() == "completed" and cell.get_attribute("data-tone") == "muted"


def _load_all_pages(page: Any) -> int:
    """Press Load more until it goes or a later page fails, waiting for each page; the number of presses."""
    presses = 0
    while page.locator('[data-action="load-more"]').count() == 1:
        before = page.locator('[data-row="alert"]').count()
        page.locator('[data-action="load-more"]').click()
        presses += 1
        _until_true(page, lambda rows=before: page.locator('[data-row="alert"]').count() > rows
                    or page.get_by_text(LATER_FAILED).count() == 1, "the next page, or its failure")
        if page.get_by_text(LATER_FAILED).count() == 1:
            break
    return presses


def test_alert_list_o2_o5_o6_o7_every_set_of_filters_pages_to_exactly_its_rows_and_matching_nothing_is_no_match(
        world, browser):
    """For every non-empty subset of the form's filter fields (read from the form, so a new field must be given a value
    here): with more than one page of matching alerts and others that match some of the filters but not all, page 1 and
    every Load more show exactly the matching rows, newest first, and never "Couldn't load more"; with values that match
    nothing, the screen is `no-match` with the filter bar and its one row, never "No alerts yet". (O2, O5, O6, O7)"""
    outcomes = ("malicious", "benign")
    places = {"below": "2026-08-01T00:00:00Z", "in": "2026-09-01T00:00:00Z", "above": "2026-10-01T00:00:00Z"}
    records = [("T-1161", _at("2026-11-01T12:00:00Z"), "malicious")]  # the world's own alert
    alerts = []
    for outcome, (place, start) in itertools.product(outcomes, places.items()):
        for n in range(PAGE + 1):
            fired = _at(start) + dt.timedelta(minutes=n + 100 * outcomes.index(outcome))  # no two alike
            ticket = f"T-{outcome}-{place}-{n:02d}"
            records.append((ticket, fired, outcome))
            alerts.append((ticket, fired.isoformat(), ALERT_BYTES, [f"completed:{outcome}"]))
    run_async(_seed, world.dsn, A, alerts)
    paris = zoneinfo.ZoneInfo(ZONE)
    matching = {"outcome": "malicious", "fired_after": "2026-08-20T00:00", "fired_before": "2026-09-20T00:00"}
    nothing = {"outcome": "unresolved", "fired_after": "2030-01-01T00:00", "fired_before": "2000-01-01T00:00"}

    def expected(keys: tuple[str, ...]) -> list[str]:
        """The tickets the filters in `keys` keep, newest first, from the seed alone."""
        kept = [(fired, ticket) for ticket, fired, outcome in records
                if ("outcome" not in keys or outcome == matching["outcome"])
                and ("fired_after" not in keys
                     or fired >= dt.datetime.fromisoformat(matching["fired_after"]).replace(tzinfo=paris))
                and ("fired_before" not in keys
                     or fired < dt.datetime.fromisoformat(matching["fired_before"]).replace(tzinfo=paris))]
        return [ticket for _, ticket in sorted(kept, reverse=True)]

    ctx = _signed_in(browser, world)
    first = _open(world, ctx, ALERTS)
    controls = first.locator('form[data-form="filters"] [name]').evaluate_all("els => els.map(e => [e.name, e.type])")
    first.close()
    names = {name for name, _ in controls}
    fields = sorted(matching)
    assert set(fields) <= names, f"the form lacks a control for a filter: {sorted(set(fields) - names)}"
    assert ["tz", "hidden"] in controls, f"the form carries the zone as a hidden field: {controls}"
    subsets = [keys for size in range(1, len(fields) + 1) for keys in itertools.combinations(fields, size)]
    assert len(subsets) == 2 ** len(fields) - 1
    failures: list[str] = []
    for keys in subsets:
        assert len(expected(keys)) > PAGE, f"premise: {keys} must page"
        try:
            address = urllib.parse.urlencode({**{k: matching[k] if k in keys else "" for k in fields}, "tz": ZONE})
            page = _open(world, ctx, f"{ALERTS}?{address}")
            presses = _load_all_pages(page)
            if _tickets(page) != expected(keys) or presses < 1 or page.get_by_text(LATER_FAILED).count():
                failures.append(f"{keys}: {len(_tickets(page))} rows after {presses} presses, "
                                f"{len(expected(keys))} expected, later page failed: {page.get_by_text(LATER_FAILED).count()}")
            page.close()
            address = urllib.parse.urlencode({**{k: nothing[k] if k in keys else "" for k in fields}, "tz": ZONE})
            page = _open(world, ctx, f"{ALERTS}?{address}", state="no-match")
            if (page.get_by_text("No alerts match these filters").count() != 1 or page.locator('[data-row="alert"]').count()
                    or page.locator('select[name="outcome"]').count() != 1 or page.get_by_text("No alerts yet").count()):
                failures.append(f"{keys}: matching nothing did not show the no-match row with the filter bar")
            page.close()
        except Exception as error:  # noqa: BLE001 — a timeout is that subset's failure, and the rest still run
            failures.append(f"{keys}: {type(error).__name__}")
    assert failures == []


def test_alert_list_o5_a_later_page_that_fails_keeps_every_row_of_the_pages_before_it_whichever_page_it_is(
        world, browser):
    """201 alerts make five pages. With the read of page k answered 500, for each k from 2 to 5: the rows of pages 1 to
    k-1 stay (never fewer), the failure line shows once, Load more is gone, and the screen stays `ready`. (O5, usePagedRead)"""
    _more(world, PAGE * 4)
    ctx = _signed_in(browser, world)
    state = {"cursors": 0, "fail_at": 0}

    def answer(route: Any) -> None:
        state["cursors"] += 1
        if state["cursors"] == state["fail_at"]:
            route.fulfill(status=500, body="x")
        else:
            route.continue_()

    ctx.route(lambda u: path_is(u, READ) and "cursor=" in u, answer)
    pages = 5
    for k in range(2, pages + 1):
        state.update(cursors=0, fail_at=k - 1)
        page = _open(world, ctx, ALERTS)
        for shown_pages in range(1, k - 1):
            page.locator('[data-action="load-more"]').click()
            page.locator('[data-row="alert"]').nth(PAGE * (shown_pages + 1) - 1).wait_for()
        page.locator('[data-action="load-more"]').click()
        page.get_by_text(LATER_FAILED).wait_for()
        settle(page)
        assert page.locator('[data-row="alert"]').count() == PAGE * (k - 1), f"failing page {k}"
        assert page.get_by_text(LATER_FAILED).count() == 1 and page.locator('[data-action="load-more"]').count() == 0
        assert page.locator('[data-screen="alerts"]').first.get_attribute("data-state") == "ready"
        page.close()


# --- O6, O7, O12: empty states, the X, and an address the screen cannot read ------------------------------------------

def test_alert_list_o6_o12_a_tenant_with_no_alerts_and_no_filter_says_no_alerts_yet(world, browser):
    """Bob's tenant B holds no alert: `empty`, "No alerts yet", no rows and no filter bar. (O6, O12)"""
    page = _open(world, _signed_in(browser, world, account=world.accounts[BOB]), ALERTS_OF_B, state="empty")
    assert page.get_by_text("No alerts yet").count() == 1
    assert page.locator('[data-row="alert"]').count() == 0 and page.locator('select[name="outcome"]').count() == 0
    assert page.locator('[data-action="clear-filters"]').count() == 0
    _no_defender(page)


def test_alert_list_o6_o12_filters_matching_nothing_keep_the_bar_and_header_and_offer_a_clear_link(world, browser):
    """`outcome=benign` matches nothing in A: `no-match`, the filter bar and header stay, one "No alerts match these
    filters" row, and clear links to the bare path. (O6, O12)"""
    page = _open(world, _signed_in(browser, world), f"{ALERTS}?outcome=benign&fired_after=&fired_before=&tz={ZONE}",
                 state="no-match")
    assert page.get_by_text("No alerts match these filters").count() == 1
    assert page.locator('select[name="outcome"]').input_value() == "benign"
    assert page.locator("thead th").count() == 4 and page.locator('[data-action="apply"]').count() == 1
    assert page.locator('[data-row="alert"]').count() == 0
    assert {link.get_attribute("href") for link in page.locator('[data-action="clear-filters"]').all()} == {ALERTS}
    _no_defender(page)


def test_alert_list_o7_the_x_shows_only_when_an_outcome_or_a_time_is_set_and_tz_alone_sets_nothing(world, browser):
    """The X (clear all) shows for an outcome, for a time after, for a time before; an all-empty submit, no query, and a
    lone `tz` show none, and a lone `tz` on an empty tenant is `empty`, not `no-match`. (O7, O6)"""
    ctx = _signed_in(browser, world)
    for query in ("outcome=malicious", "fired_after=2026-01-01T00:00", "fired_before=2027-01-01T00:00"):
        page = _open(world, ctx, f"{ALERTS}?{query}")
        assert page.locator('[data-action="clear-filters"]').count() == 1, query
        assert page.locator('[data-action="clear-filters"]').get_attribute("href") == ALERTS
        page.close()
    for query in ("", "?outcome=&fired_after=&fired_before=&tz=", "?tz=Asia/Tokyo", f"?tz={ZONE}"):
        page = _open(world, ctx, f"{ALERTS}{query}")
        assert page.locator('[data-action="clear-filters"]').count() == 0, query
        assert _tickets(page) == ["T-1161"], query
        page.close()
    carol, _ = _carol(world, browser, (B,))
    page = _open(world, carol, f"{ALERTS_OF_B}?tz=Asia/Tokyo", state="empty")
    assert page.locator('[data-action="clear-filters"]').count() == 0


@pytest.mark.parametrize("query", [
    "outcome=evil", "outcome=Malicious", "fired_after=2026-11-12", "fired_before=2026-11-12T00:00:00",
    "tz=Mars/Phobos", "tz=Mars/Phobos&fired_after=2026-11-12T00:00",
    "outcome=benign&outcome=benign", "outcome=&outcome=benign", "fired_after=2026-11-12T00:00&fired_after=2026-11-12T00:00",
    "fired_before=&fired_before=", f"tz={ZONE}&tz={ZONE}"])
def test_alert_list_o7_o12_an_address_the_screen_cannot_read_is_invalid_sends_no_read_and_is_not_rewritten(
        world, browser, query):
    """Each address of an invalid kind (an unknown outcome or time format or zone, or a key twice): `invalid`, "These
    filters aren't valid" with the clear link only (no filter bar), no alerts read, the address as it was. (O7, O12)"""
    ctx = _signed_in(browser, world)
    mark = len(requests_of(ctx))
    page = _open(world, ctx, f"{ALERTS}?{query}", state="invalid")
    assert _plain(page.locator("body").inner_text()).count("These filters aren't valid") == 1
    assert page.locator('[data-action="clear-filters"]').first.get_attribute("href") == ALERTS
    assert page.locator('select[name="outcome"]').count() == 0 and page.locator('[data-row="alert"]').count() == 0
    settle(page)
    assert [c for c in api_calls(requests_of(ctx)[mark:], world.origin) if c[1] == READ] == []
    assert page.evaluate("location.pathname + location.search") == f"{ALERTS}?{query}"
    assert len(navigations_to(requests_of(ctx)[mark:], world.origin, ALERTS)) == 1, "the address was not left or rewritten"
    _no_defender(page)


def test_alert_list_o7_an_inverted_window_is_valid_and_matches_nothing_and_unknown_keys_are_ignored(world, browser):
    """`fired_after` later than `fired_before` is `no-match`, not `invalid`; an unknown key changes nothing. (O7, O12)"""
    ctx = _signed_in(browser, world)
    page = _open(world, ctx, f"{ALERTS}?fired_after=2026-12-01T00:00&fired_before=2026-01-01T00:00&tz={ZONE}",
                 state="no-match")
    assert page.get_by_text("No alerts match these filters").count() == 1 and page.locator('[data-row="alert"]').count() == 0
    page = _open(world, ctx, f"{ALERTS}?colour=red&outcome=malicious&tz={ZONE}")
    assert _tickets(page) == ["T-1161"] and page.locator('[data-action="clear-filters"]').count() == 1


def test_alert_list_o12_loading_then_ready_while_the_first_page_is_read(world, browser):
    """While page 1's read is held the screen is `loading`; once it is answered, `ready` with its rows. (O12)"""
    ctx = _signed_in(browser, world)
    held = _holding(ctx, lambda u: path_is(u, READ))
    page = _open(world, ctx, ALERTS, state="loading")
    _until_held(page, held)
    assert page.locator('[data-row="alert"]').count() == 0
    held[0].continue_()
    _state(page, "ready")
    assert _tickets(page) == ["T-1161"]


def test_alert_list_o12_not_available_when_page_one_answers_a_non_member_a_missing_tenant_or_404(world, browser):
    """Bob reading A's alerts and Ann reading a tenant that does not exist (the real API), and a page-1 read answered
    404 (intercepted): each `not-available`, never the error screen. No 403 reaches this read. (O12)"""
    bob = _signed_in(browser, world, account=world.accounts[BOB])
    _open(world, bob, ALERTS, state="not-available")
    ann = _signed_in(browser, world, account=world.accounts[ANN])
    _open(world, ann, f"/t/{UNKNOWN_TENANT}/alerts", state="not-available")
    ctx = _signed_in(browser, world, account=world.accounts[ANN])
    ctx.route(lambda u: path_is(u, READ), lambda route: route.fulfill(status=404, body="{}"))
    page = _open(world, ctx, ALERTS, state="not-available")
    assert page.locator('[data-row="alert"]').count() == 0
    _no_defender(page)


@pytest.mark.parametrize("answer", [dict(status=500, body="x"), dict(status=200, body="<html>")],
                         ids=["500", "not-json"])
def test_alert_list_o12_error_when_page_one_fails_otherwise(world, browser, answer):
    """Page 1 answered 500, or with a body that is not JSON: the screen is `error` and still the alerts screen. (O12)"""
    ctx = _signed_in(browser, world)
    ctx.route(lambda u: path_is(u, READ), lambda route: route.fulfill(**answer))
    page = _open(world, ctx, ALERTS, state="error")
    assert page.locator('[data-row="alert"]').count() == 0
    _no_defender(page)


def test_alert_list_o4_o12_a_401_on_page_one_reads_as_loading_while_the_sign_in_navigation_goes_nowhere_never_as_error(world, browser):
    """Page 1 answered 401 starts the navigation to sign-in; while it is not followed (aborted, so the document stays)
    the screen is `loading`, with no rows, and is never `error` or `not-available`. (O4, O12)"""
    ctx = _signed_in(browser, world)
    ctx.route(lambda u: path_is(u, READ), lambda route: route.fulfill(status=401, body="{}"))
    aborted = abort_login_navigation(ctx)
    page = ctx.new_page()
    page.goto(f"{world.origin}{ALERTS}")
    screen(page, "alerts")
    await_aborted(page, aborted)
    for _ in range(10):  # the read answers `gone` meanwhile; give a wrong state time to show itself
        assert page.locator('[data-screen="alerts"]').get_attribute("data-state") == "loading"
        page.wait_for_timeout(50)
    assert page.locator('[data-row="alert"]').count() == 0


def test_alert_list_o5_load_more_appends_every_page_of_a_long_list_and_drops_none(world, browser):
    """451 alerts (nine pages of 50 with the world's own): pressing Load more until it goes leaves every row on the
    screen, each once, newest first, so no number of pages evicts an earlier one. (O5)"""
    _more(world, PAGE * 9)
    ctx = _signed_in(browser, world)
    page = _open(world, ctx, ALERTS)
    assert _load_all_pages(page) == 9
    tickets = _tickets(page)
    assert len(tickets) == PAGE * 9 + 1 and len(set(tickets)) == len(tickets)
    assert tickets == ["T-1161"] + [f"T-more-{n:03d}" for n in range(PAGE * 9 - 1, -1, -1)]


# --- O4: the address through sign-in ---------------------------------------------------------------------------------

def test_alert_list_o4_signed_out_the_alerts_address_returns_to_its_path_without_the_query(world, context, requests):
    """Signed out, a filtered alerts address goes through sign-in and comes back to the path; the query is dropped, and
    the screen then reads the alerts. (O4)"""
    page = context.new_page()
    page.goto(f"{world.origin}{ALERTS}?outcome=malicious&tz={ZONE}")
    screen(page, "alerts")
    _state(page, "ready")
    assert logins(requests, world.origin) == [ALERTS]
    assert where(page) == (ALERTS, {})
    assert _tickets(page) == ["T-1161"]


# --- O8, O9: Home ----------------------------------------------------------------------------------------------------

def test_alert_list_o8_home_links_a_persons_one_tenant_as_alerts_and_it_opens_the_screen(world, context):
    """Ann (tenant A only): one link labelled "Alerts" to A's alerts address, which opens the alerts screen; no
    invite-only text, no invitation line, no Defender. (O8, O9)"""
    sign_in(world, context)
    page = _home(world, context)
    links = page.locator('a[href^="/t/"]')
    assert [(link.get_attribute("href"), _plain(link.inner_text())) for link in links.all()] == [(ALERTS, "Alerts")]
    text = _plain(page.locator("body").inner_text())
    assert "invite-only" not in text and "invited to a team" not in text
    _no_defender(page)
    links.click()
    screen(page, "alerts")


def test_alert_list_o8_home_labels_each_of_several_tenants_alerts_with_the_tenant_id(world, browser):
    """Ann in A and B: one link each, "Alerts — <tenant id>". (O8)"""
    run_async(_person, world.dsn, ANN, (B,))
    page = _home(world, _signed_in(browser, world))
    found = {link.get_attribute("href"): _plain(link.inner_text()) for link in page.locator('a[href^="/t/"]').all()}
    assert found == {ALERTS: f"Alerts — {A}", ALERTS_OF_B: f"Alerts — {B}"}


def test_alert_list_o8_home_lists_each_open_invitation_with_an_accept_button_and_no_invite_only_text(world, browser):
    """Carol, in no tenant, invited to A and B: one "You've been invited to a team." line and one Accept button per
    invitation, no alerts link, no invite-only text. (O8, O9)"""
    carol, _ = _carol(world, browser, (), (A, B))
    page = _home(world, carol)
    page.get_by_role("button", name="Accept", exact=True).first.wait_for()
    text = _plain(page.locator("body").inner_text())
    assert text.count("You've been invited to a team") == 2
    assert page.get_by_role("button", name="Accept", exact=True).count() == 2
    assert "invite-only" not in text and page.locator('a[href^="/t/"]').count() == 0
    _no_defender(page)


def test_alert_list_o8_home_shows_the_tenants_alerts_link_then_the_invitation_line(world, browser):
    """Ann in A and invited to B: the alerts link, then the invitation line with its button. (O8)"""
    run_async(_person, world.dsn, ANN, (), (B,))
    page = _home(world, _signed_in(browser, world))
    page.get_by_role("button", name="Accept", exact=True).wait_for()
    text = _plain(page.locator("body").inner_text())
    assert text.index("Alerts") < text.index("You've been invited to a team") and "invite-only" not in text


def test_alert_list_o8_o9_home_with_no_tenant_and_no_invitation_says_sluice_is_invite_only(world, browser):
    """A person with no tenant and no invitation: the invite-only text naming their email, and no alerts link or
    Accept button. (O8, O9)"""
    carol, _ = _carol(world, browser)
    page = _home(world, carol)
    text = _plain(page.locator("body").inner_text())
    assert "You haven't been added to a team yet" in text
    assert "Sluice is invite-only. Ask your administrator to invite carol@c.example." in text
    assert page.locator('a[href^="/t/"]').count() == 0
    assert page.get_by_role("button", name="Accept", exact=True).count() == 0
    _no_defender(page)


# --- O11: accept an invitation ---------------------------------------------------------------------------------------

def _accepts(requests: Any) -> list[str]:
    return [r.url for r in requests if r.method == "POST" and path_is(r.url, "/api/invitations")
            and urllib.parse.urlsplit(r.url).path.endswith("/accept")]


def test_alert_list_o11_accept_is_disabled_in_flight_then_loads_the_tenants_alerts_and_back_returns_home(world, browser):
    """Accept sends one POST and the button is disabled until it is answered; the success is a full load of the
    accepted tenant's alerts address (now readable by Carol), and Back returns to /home. (O11)"""
    carol, _ = _carol(world, browser, (), (B,))
    held = _holding(carol, lambda u: u.startswith(world.origin) and urllib.parse.urlsplit(u).path.endswith("/accept"))
    page = _home(world, carol)
    button = page.get_by_role("button", name="Accept", exact=True)
    mark = len(requests_of(carol))
    button.click()
    _until_held(page, held)
    _until_true(page, button.is_disabled, "Accept is disabled while its request is in flight")
    held[0].continue_()
    screen(page, "alerts")
    _state(page, "empty")
    assert where(page) == (ALERTS_OF_B, {})
    assert navigations_to(requests_of(carol)[mark:], world.origin, ALERTS_OF_B) == [{}], "a full load, not in-document"
    assert len(_accepts(requests_of(carol)[mark:])) == 1
    page.go_back()
    screen(page, "home")
    assert where(page) == ("/home", {})


def test_alert_list_o11_a_401_makes_the_sign_in_round_trip_back_to_home_with_the_invitation_open(world, browser):
    """An accept answered 401 (the session gone) takes the shell's one sign-in and comes back to /home, where the
    invitation is still open: nothing was accepted, and the accept is not sent again. (O11)"""
    carol, _ = _carol(world, browser, (), (B,))
    page = _home(world, carol)
    button = page.get_by_role("button", name="Accept", exact=True)
    button.wait_for()
    carol.clear_cookies()
    mark = len(requests_of(carol))
    button.click()
    for _ in range(WAIT_MS // 100):
        if logins(requests_of(carol)[mark:], world.origin):
            break
        page.wait_for_timeout(100)
    screen(page, "home")
    page.get_by_role("button", name="Accept", exact=True).wait_for()
    settle(page)
    assert logins(requests_of(carol)[mark:], world.origin) == ["/home"]
    assert where(page) == ("/home", {}) and len(_accepts(requests_of(carol)[mark:])) == 1
    assert page.get_by_role("button", name="Accept", exact=True).count() == 1


def test_alert_list_o11_a_404_says_the_invitation_is_no_longer_open_and_removes_the_button(world, browser):
    """The invitation withdrawn after Home loaded: Accept answers 404, "This invitation is no longer open." shows under
    the invitation, its button is gone, and the screen stays Home. (O11)"""
    carol, ids = _carol(world, browser, (), (B,))
    page = _home(world, carol)
    button = page.get_by_role("button", name="Accept", exact=True)
    button.wait_for()
    run_async(_revoke, world.dsn, ids[B])
    button.click()
    page.get_by_text("This invitation is no longer open.").wait_for()
    assert page.get_by_role("button", name="Accept", exact=True).count() == 0
    assert "You've been invited to a team" in _plain(page.locator("body").inner_text())
    assert shown(page) == "home" and where(page)[0] == "/home"


RELOAD = "Couldn't accept the invitation. Reload the page to try again."
REFUSED_ACCEPT = "You can't accept this invitation."


@pytest.mark.parametrize(("failure", "message"), [
    ("403", REFUSED_ACCEPT), ("422", REFUSED_ACCEPT), ("500", RELOAD), ("network", RELOAD)])
def test_alert_list_o11_accept_refusals_are_worded_by_kind_and_are_not_the_error_screen(world, browser, failure, message):
    """An accept answered 403 or 422 (any 4xx but 404) reads "You can't accept this invitation."; one answered 500, or not
    answered at all, reads "Couldn't accept the invitation. Reload the page to try again." (the other wording shows in
    neither case); under the invitation, the screen stays Home, not the error screen, and the button is gone. (O11, r3.3)"""
    carol, _ = _carol(world, browser, (), (B,))

    def refuse(route: Any) -> None:
        if failure == "network":
            route.abort("aborted")
        else:
            route.fulfill(status=int(failure), body="{}")

    carol.route(lambda u: u.startswith(world.origin) and urllib.parse.urlsplit(u).path.endswith("/accept"), refuse)
    page = _home(world, carol)
    page.get_by_role("button", name="Accept", exact=True).click()
    page.get_by_text(message).wait_for()
    settle(page)
    other = RELOAD if message == REFUSED_ACCEPT else REFUSED_ACCEPT
    assert page.get_by_text(message).count() == 1 and page.get_by_text(other).count() == 0
    assert shown(page) == "home" and where(page)[0] == "/home"
    assert page.get_by_role("button", name="Accept", exact=True).count() == 0, "the button goes after any failure"
    assert len(_accepts(requests_of(carol))) == 1


@pytest.mark.parametrize("first", ["held", "404", "500"])
def test_alert_list_o11_each_invitation_keeps_its_own_state_and_the_button_goes_after_any_non_success(
        world, browser, first):
    """Two invitations, the first Accept held in flight, answered 404 or 500: only the first is disabled (held) or shows
    its message and loses its button; the second stays enabled and its Accept POSTs its own id. (O11)"""
    carol, ids = _carol(world, browser, (), (A, B))
    answered: list[str] = []

    def answer(route: Any) -> None:
        answered.append(route.request.url)
        if len(answered) > 1:
            route.continue_()  # the second invitation's own accept reaches the real API
        elif first != "held":
            route.fulfill(status=int(first), body="{}")

    carol.route(lambda u: u.startswith(world.origin) and urllib.parse.urlsplit(u).path.endswith("/accept"), answer)
    page = _home(world, carol)
    buttons = page.get_by_role("button", name="Accept", exact=True)
    buttons.first.wait_for()
    assert buttons.count() == 2
    buttons.first.click()
    for _ in range(WAIT_MS // 50):
        if answered:
            break
        page.wait_for_timeout(50)
    assert len(answered) == 1
    message = {"404": "This invitation is no longer open.",
               "500": "Couldn't accept the invitation. Reload the page to try again."}.get(first)
    if first == "held":
        _until_true(page, buttons.nth(0).is_disabled, "the first Accept is disabled while its request is in flight")
        assert buttons.count() == 2
        assert buttons.nth(1).is_enabled(), "the other invitation's Accept stays enabled"
        second = buttons.nth(1)
    else:
        page.get_by_text(message).wait_for()
        _until_true(page, lambda: buttons.count() == 1, "the answered invitation's button goes")
        assert page.get_by_text(message).count() == 1
        assert buttons.first.is_enabled(), "the other invitation's Accept stays enabled"
        second = buttons.first
    second.click()
    for _ in range(WAIT_MS // 50):
        if len(answered) == 2:
            break
        page.wait_for_timeout(50)
    first_id, second_id = (urllib.parse.urlsplit(u).path.split("/")[-2] for u in answered)
    assert {first_id, second_id} == set(ids.values()) and first_id != second_id
