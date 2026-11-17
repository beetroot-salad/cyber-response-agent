"""#1161 piece 1, test-only: what the browser tests read off a page and its requests (B1, B8). Observation goes through
the markers the record names (`data-screen`, `data-reason`, `data-action`, `data-field`) and `location`."""
from __future__ import annotations

import urllib.parse
from typing import Any

from defender.tests.support.api._server1083 import SESSION_COOKIE
from defender.tests.support.frontend._browser1161 import path_is

WAIT_MS = 30_000
RETRY = '[data-action="retry"]'
SIGN_IN = '[data-action="sign-in"]'
SIGN_OUT = '[data-action="sign-out"]'
EMAIL = '[data-field="email"]'
FAILED = "sign-in-failed"
#: The `data-screen` values of the landing page (shape `root`), the signed-in home (`home`) and the error state (F4, PR2).
ROOT = "root"
HOME = "home"
ERROR = "error"
#: The shell makes the sessionStorage accessor throw, as a browser with storage denied does.
NO_STORAGE = ("Object.defineProperty(window, 'sessionStorage', {configurable: true,"
              " get() { throw new DOMException('denied', 'SecurityError'); }});")


def query_of(url_or_search: str) -> dict[str, str]:
    search = urllib.parse.urlsplit(url_or_search).query if "?" in url_or_search or "://" in url_or_search \
        else url_or_search.lstrip("?")
    return dict(urllib.parse.parse_qsl(search, keep_blank_values=True))


def logins(requests: list[Any], origin: str) -> list[str | None]:
    """The `return` parameter (None when absent) of each top-level navigation to `/api/auth/login` on `origin`, in order."""
    found: list[str | None] = []
    for r in requests:
        if r.is_navigation_request() and r.url.startswith(origin) and path_is(r.url, "/api/auth/login"):
            found.append(query_of(r.url).get("return"))
    return found


def api_calls(requests: list[Any], origin: str) -> list[tuple[str, str]]:
    """(method, path) of every request to the API outside the sign-in routes, in order."""
    return [(r.method, urllib.parse.urlsplit(r.url).path) for r in requests
            if r.url.startswith(origin) and path_is(r.url, "/api") and not path_is(r.url, "/api/auth")]


def _page_of(request: Any) -> int | None:
    """`id` of the page `request` was made from; None when its frame is gone."""
    try:
        return id(request.frame.page)
    except Exception:  # noqa: BLE001 — a request whose frame is gone belongs to no load we can name
        return None


def _is_main_frame_navigation(request: Any) -> bool:
    try:
        return bool(request.is_navigation_request()) and request.frame.parent_frame is None
    except Exception:  # noqa: BLE001
        return False


def repeated_api_gets(requests: list[Any]) -> list[str]:
    """`GET url` of each `/api/*` fetch a page's load sent twice. A load ends at a main-frame navigation request (any
    hop: the test's, the shell's, sign-in's) or at a `restore_from_cache` call (the context's `RequestLog` holds it)."""
    restores = set(getattr(requests, "restores", ()))
    seen: dict[int | None, set[str]] = {}
    repeats: list[str] = []
    for index, request in enumerate(requests):
        if index in restores:
            seen.clear()
        if _is_main_frame_navigation(request):
            seen.pop(_page_of(request), None)
            continue
        if request.method == "GET" and request.resource_type in ("fetch", "xhr") and path_is(request.url, "/api"):
            urls = seen.setdefault(_page_of(request), set())
            if request.url in urls:
                repeats.append(f"GET {request.url}")
            urls.add(request.url)
    return repeats


def assert_no_repeat(requests: list[Any]) -> None:
    """Within one load, no `GET` fetch to `/api/*` repeats a URL (Am-5 point 5), over every load the requests hold."""
    assert repeated_api_gets(requests) == [], "a load sent the same API read twice"


def auth_calls(requests: list[Any], origin: str, path: str) -> list[tuple[str, str]]:
    """(method, path) of every request to `origin` + `path` (an `/api/auth/...` route, e.g. `/api/auth/logout`), in
    order. `api_calls` leaves these routes out, so a logout POST is seen only here."""
    return [(r.method, urllib.parse.urlsplit(r.url).path) for r in requests
            if r.url.startswith(origin) and urllib.parse.urlsplit(r.url).path == path]


def navigations_to(requests: list[Any], origin: str, path: str) -> list[dict[str, str]]:
    """The query of each document navigation to `origin` + `path`, in order (redirect hops included)."""
    return [query_of(r.url) for r in requests
            if r.is_navigation_request() and r.url.startswith(origin) and urllib.parse.urlsplit(r.url).path == path]


def screen(page: Any, name: str) -> None:
    """Wait until the page shows the screen `name` (its root's `data-screen`)."""
    page.locator(f'[data-screen="{name}"]').first.wait_for()


def where(page: Any) -> tuple[str, dict[str, str]]:
    """The page's `location.pathname` and its query, read from the document."""
    pathname, search = page.evaluate("[location.pathname, location.search]")
    return str(pathname), query_of(str(search))


def reason(page: Any) -> str | None:
    return page.locator("[data-reason]").first.get_attribute("data-reason")


def shown(page: Any) -> str | None:
    """The `data-screen` of the screen the page shows now (None: none yet)."""
    marked = page.locator("[data-screen]")
    return marked.first.get_attribute("data-screen") if marked.count() else None


def cookie_names(context: Any) -> set[str]:
    return {c["name"] for c in context.cookies()}


def signed_in(context: Any) -> bool:
    return SESSION_COOKIE in cookie_names(context)


def sign_in(world: Any, context: Any) -> None:
    """Sign `context` in through the real flow (the front channel's default account), then close the tab used. It
    starts from `/home` (`/` is the public landing page and signs nobody in, F4) and waits for the home screen."""
    page = context.new_page()
    try:
        page.goto(f"{world.origin}/home")
        screen(page, HOME)
    finally:
        page.close()
    assert signed_in(context), "positive control: the sign-in set the session cookie"


def await_aborted(page: Any, aborted: list[str]) -> None:
    """Until the shell's navigation to sign-in has been tried (and aborted by `abort_login_navigation`)."""
    for _ in range(WAIT_MS // 100):
        if aborted:
            return
        page.wait_for_timeout(100)
    raise AssertionError("the shell never tried to navigate to sign-in")


def until(page: Any, expression: str) -> None:
    """Poll `expression` with `page.evaluate` until it is true. Not `wait_for_function`: it evals a string in the page,
    which the ingress's CSP forbids and the CSP guard reports as a violation."""
    for _ in range(WAIT_MS // 100):
        if page.evaluate(expression):
            return
        page.wait_for_timeout(100)
    raise AssertionError(f"never true: {expression}")


def settle(page: Any, ms: int = 700) -> None:
    """Long enough for an unwanted second sign-in or call to show itself."""
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(ms)
