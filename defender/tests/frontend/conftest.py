"""#1161 the frontend's browser and ingress checks: the pinned Chromium, the running world (API child, ingress,
provider front channel) and the Q6 cookie-less request. Tools missing is a failure, never a skip (B11).

CSP (#1540 F8): every browser test fails on any `securitypolicyviolation` in any page of its context. `guard_csp(context)`
installs the report and returns the live list of violations (each "<directive> <blocked> @ <document>"); the `context`
fixture asserts it empty at teardown. A test that makes its own context calls `guard_csp` and asserts the list itself."""
from __future__ import annotations

import dataclasses
import datetime as dt
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from defender.tests.support.api._server1083 import (
    A,
    ANN,
    B,
    BOB,
    Child,
    Seeded,
    environment,
    free_port,
    seed_identity,
)
from defender.tests.support.api._signin1161 import FrontChannel, link_account
from defender.tests.support.frontend import _ingress1161 as ingress_harness
from defender.tests.support.frontend._browser1161 import Intercepted, record_requests, run_async, without_cookies_once
from defender.tests.support.jobs._jobs1342 import ALERT_BYTES, job_store, register_tenant
from defender.tests.support.shared._postgres1339 import (  # noqa: F401 — fixtures for this directory
    migrated_database,
)


WAIT_MS = 30_000
#: Reports a violation to Python. A binding (not an in-page array) survives navigations and closed tabs.
_CSP_BINDING = "__defenderCspViolation"
_CSP_LISTENER = ("window.addEventListener('securitypolicyviolation', e => window." + _CSP_BINDING +
                 "(e.violatedDirective + ' ' + e.blockedURI + ' @ ' + e.documentURI), true);")
_NOW = dt.datetime(2026, 11, 1, 12, tzinfo=dt.UTC)


def guard_csp(context: Any) -> list[str]:
    """Record every CSP violation any page of `context` reports, now and later, across navigations and closed tabs.
    Returns the list the violations are appended to."""
    violations: list[str] = []
    context.expose_binding(_CSP_BINDING, lambda source, message: violations.append(str(message)))
    context.add_init_script(_CSP_LISTENER)
    return violations


@pytest.fixture(scope="session")
def browser_tools() -> None:
    """Bun, Caddy, Playwright and its Chromium are all present, or the test fails (B11)."""
    ingress_harness.require_tools()


@pytest.fixture(scope="session")
def built_frontend(browser_tools: None) -> Path:
    """The frontend's `dist/`, built outside the checkout once per set of sources (`bun install --frozen-lockfile && bun run build`); fails when
    the build does. Its `node_modules/` is beside it."""
    return ingress_harness.build_frontend()


# Sync Playwright leaves a running event loop in the main thread while it is started, and any async test then fails
# ("Cannot run the event loop while another loop is running", probed with a session scope). So it is module-scoped:
# started for a module's tests, stopped before another module's. No async test shares a module with a browser test.
@pytest.fixture(scope="module")
def playwright_(browser_tools: None) -> Iterator[Any]:
    from playwright.sync_api import sync_playwright

    pw = sync_playwright().start()
    try:
        yield pw
    finally:
        pw.stop()


@pytest.fixture(scope="module")
def browser(playwright_: Any) -> Iterator[Any]:
    """The pinned headless Chromium."""
    chromium = playwright_.chromium.launch()
    try:
        yield chromium
    finally:
        chromium.close()


@pytest.fixture
def context(browser: Any) -> Iterator[Any]:
    """A fresh browser profile (no cookies, no storage), `WAIT_MS` default timeout; the test errors on any CSP violation."""
    ctx = browser.new_context()
    ctx.set_default_timeout(WAIT_MS)
    violations = guard_csp(ctx)
    try:
        yield ctx
        for page in ctx.pages:  # let a report still in flight arrive
            page.wait_for_timeout(100)
            break
    finally:
        ctx.close()
    assert not violations, f"F8: the page broke the ingress's CSP: {violations}"


@pytest.fixture
def requests(context: Any) -> list[Any]:
    """Every request `context` makes, in order."""
    return record_requests(context)


@pytest.fixture
def cookieless_once(playwright_: Any, context: Any) -> Callable[..., Intercepted]:
    """`cookieless_once(matches, skip=0)`: the (skip+1)th matching request reaches the real API without cookies (Q6)."""
    return lambda matches, skip=0: without_cookies_once(playwright_, context, matches, skip=skip)


async def _completed(dsn: str, tenant: str) -> str:
    """A `completed` investigation, disposition `malicious`, through the store's own claim and finish."""
    async with job_store(dsn) as store:
        alert = await store.insert_alert(tenant, vendor="elastic", vendor_ticket_id="T-1161", fired_at=_NOW,
                                         changed_at=_NOW, received_at=_NOW, raw=ALERT_BYTES)
        inv, _ = await store.create_investigation(tenant, str(alert.alert_id), "seed", actor="seed")
        await store.claim()
        await store.finish(tenant, inv.investigation_id, stage="completed", disposition="malicious", cost_usd=0.0)
    return str(inv.investigation_id)


@dataclasses.dataclass
class World:
    """The running system: `origin` is the ingress's (and the API's frontend origin); `front` the provider's front
    channel (its `default` is Ann's account unless a test says otherwise); `api` the program in a child, whose back
    channel is `FakeKeycloak` with the code grant. Tenants A and B; Ann (A) and Bob (B) with sign-in `accounts`; a
    completed investigation of A."""
    origin: str
    dsn: str
    seeded: Seeded
    accounts: dict[str, str]
    investigation: str
    api: Child
    front: FrontChannel

    def screen(self, investigation: str | None = None) -> str:
        """The investigation screen's address (S2)."""
        return f"/t/{A}/investigations/{investigation or self.investigation}"

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return httpx.get(f"{self.origin}{path}", **kwargs)


@pytest.fixture
def world(built_frontend: Path, migrated_database: str, tmp_path: Path) -> Iterator[World]:  # noqa: F811 — the imported fixture
    """API child + ingress launcher + front channel over a database of this test's own."""
    dsn = migrated_database
    register_tenant(dsn, A)
    register_tenant(dsn, B)
    seeded = run_async(seed_identity, dsn)
    accounts = {email: run_async(link_account, dsn, email) for email in (ANN, BOB)}
    investigation = run_async(_completed, dsn, A)
    front = FrontChannel()
    front.sign_in_as(accounts[ANN])
    port, api_port = free_port(), free_port()
    origin = f"http://localhost:{port}"
    environ = environment(tmp_path, dsn=dsn, port=api_port, origin=origin, front=front.origin)
    api = Child.faked(environ)  # spawned here, on the main thread (its parent-death signal follows the thread)
    try:
        with ingress_harness.ingress(f"127.0.0.1:{api_port}", built_frontend, tmp_path / "ingress", port=port):
            assert api.ready(path="/api/openapi.json"), api.ended().stderr
            yield World(origin, dsn, seeded, accounts, investigation, api, front)
    finally:
        api.kill()
        front.close()
