"""#1161 the frontend's browser and ingress checks: the pinned Chromium, the running world (API child, ingress,
provider front channel) and the Q6 cookie-less request. Tools missing is a failure, never a skip (B11).

Guards (#1540 F8, Am-5): the guarded context (`GuardedContext`) is the one owner of every suite-wide browser guard, and
`browser.new_context()` is the only way a test gets a context, so every context carries all of them and checks them when it
closes, however a test opens it (fixture, its own, the dev server's):
- CSP: no `securitypolicyviolation` in any page. `guard_csp(context)` looks up the list (each entry
  "<directive> <blocked> @ <document>"); a test that triggers a violation on purpose asserts it, then clears the list.
- No repeat: no load sent the same `GET` to `/api/*` twice. `requests_of(context)` looks up the context's request log; a test
  that repeats a read on purpose asserts it, then clears the log.
A new suite-wide guard goes into `GuardedContext`, not into an opt-in fixture."""
from __future__ import annotations

import dataclasses
import datetime as dt
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from defender.tests.frontend._flow1161 import assert_no_repeat
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
from defender.tests.support.frontend._browser1161 import (
    Intercepted,
    RequestLog,
    record_requests,
    run_async,
    without_cookies_once,
)
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


class GuardedContext:
    """A Playwright browser context with every suite-wide guard installed: every other attribute is the real context's.
    `violations` is the live CSP list and `requests` the live request log; `close()` closes it, then fails on either."""

    def __init__(self, context: Any) -> None:
        self._context = context
        self.violations: list[str] = []
        self.requests: RequestLog = record_requests(context)
        self.closed = False
        context.expose_binding(_CSP_BINDING, lambda source, message: self.violations.append(str(message)))
        context.add_init_script(_CSP_LISTENER)

    @property
    def playwright_context(self) -> Any:
        """The real context: what `page.context` returns for its pages."""
        return self._context

    def __getattr__(self, name: str) -> Any:
        return getattr(self._context, name)

    def close(self) -> None:
        if not self.closed:
            for page in self._context.pages:  # let a report still in flight arrive
                page.wait_for_timeout(100)
                break
            self._context.close()
            self.closed = True
        assert not self.violations, f"F8: the page broke the ingress's CSP: {self.violations}"
        assert_no_repeat(self.requests)


def guard_csp(context: Any) -> list[str]:
    """The live list of CSP violations any page of `context` (one the `browser` fixture made) has reported, across
    navigations and closed tabs. Not an installer: the fixture installed the guard when it made the context."""
    # Duck-typed: pytest imports this file as `conftest` and tests import it as `defender.tests.frontend.conftest`, so
    # there are two `GuardedContext` classes and `isinstance` would refuse the other module's.
    violations = getattr(context, "violations", None)
    assert isinstance(violations, list), "guard_csp: the context was not made by the `browser` fixture"
    return violations


def requests_of(context: Any) -> RequestLog:
    """The live log of every request any page of `context` (one the `browser` fixture made) has made, in order."""
    log = getattr(context, "requests", None)
    assert isinstance(log, RequestLog), "requests_of: the context was not made by the `browser` fixture"
    return log


class GuardedBrowser:
    """The pinned Chromium, whose every context carries F8's guard."""

    def __init__(self, chromium: Any) -> None:
        self._chromium = chromium
        self.made: list[GuardedContext] = []

    def new_context(self, **options: Any) -> GuardedContext:
        made = GuardedContext(self._chromium.new_context(**options))
        self.made.append(made)
        return made

    def new_page(self, **options: Any) -> Any:
        """A page of a guarded context of its own: Playwright's own `new_page` would open an unguarded one."""
        return self.new_context(**options).new_page()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chromium, name)


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
def chromium_(playwright_: Any) -> Iterator[Any]:
    """The pinned headless Chromium."""
    chromium = playwright_.chromium.launch()
    try:
        yield chromium
    finally:
        chromium.close()


@pytest.fixture
def browser(chromium_: Any) -> Iterator[GuardedBrowser]:
    """The browser whose every context fails its test on any CSP violation (F8), checked when the context closes; a context
    the test leaves open is closed (and so checked) at the test's end."""
    guarded = GuardedBrowser(chromium_)
    try:
        yield guarded
    finally:
        failures: list[AssertionError] = []
        for made in guarded.made:
            try:
                made.close()
            except AssertionError as error:
                failures.append(error)
        if failures:
            raise failures[0]


@pytest.fixture
def context(browser: GuardedBrowser) -> Iterator[GuardedContext]:
    """A fresh browser profile (no cookies, no storage), `WAIT_MS` default timeout; the test errors on any CSP violation."""
    ctx = browser.new_context()
    ctx.set_default_timeout(WAIT_MS)
    try:
        yield ctx
    finally:
        ctx.close()


@pytest.fixture
def requests(context: Any) -> RequestLog:
    """Every request `context` makes, in order: the context's own log (its close checks it, Am-5)."""
    return requests_of(context)


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


@pytest.fixture
def checked(built_frontend, tmp_path) -> Path:
    """A pristine copy of the frontend for this test alone (the same helper as every build case: `_copy`), so no verdict
    depends on what an earlier test ran in it, such as whether `generated/` already exists."""
    from defender.tests.frontend._gate_support import _copy

    return _copy(tmp_path, built_frontend)
