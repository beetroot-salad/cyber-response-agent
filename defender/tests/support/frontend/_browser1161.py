"""#1161 piece 1, test-only: browser-side helpers for the frontend checks (design B8), over sync Playwright.

- `in_thread(fn, *args)`: run `fn` on a helper thread and return its result. Sync Playwright leaves a running event
  loop in the main thread, so `anyio.run(...)` there fails (harness defect H1): seed through this.
- `record_requests(context)`: every request the context makes, in order (a lambda, not `list.append`: H2).
- `without_cookies_once(pw, context, matches, ...)`: the Q6 mechanism, one request reaches the real API cookie-less.
- `abort_login_navigation(context)` and `restore_from_cache(page)`: B8's simulated back-forward-cache restore.

Probe result (Chromium headless shell 1255, Playwright 1.65.2, a mimic page over http://localhost):
`route.abort("aborted")` on the shell's navigation to `/api/auth/login` leaves the document in place (url, `window`
state and the shell-written `sessionStorage` record intact); the default `route.abort()` (ERR_FAILED) commits
`chrome-error://chromewebdata/` (an opaque origin: `sessionStorage` is denied), and a 204 answer moves `location.href`.
Dispatching `pageshow` with `persisted: true` then runs the shell's restore path. The simulation relies on the shell
not checking `event.isTrusted`. While a navigation is parked at the provider (`FrontChannel.hold`), `page.evaluate`
and locator reads block until it commits: read `page.url` and the context's cookies, nothing in the document."""
from __future__ import annotations

import threading
import urllib.parse
from collections.abc import Callable
from typing import Any, TypeVar

T = TypeVar("T")


def in_thread(fn: Callable[..., T], *args: Any) -> T:
    """`fn(*args)` on a fresh thread, its value returned or its exception raised here."""
    box: list[Any] = []

    def run() -> None:
        try:
            box.append((True, fn(*args)))
        except BaseException as error:  # noqa: BLE001 — handed to the caller
            box.append((False, error))

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    ok, value = box[0]
    if not ok:
        raise value
    return value  # type: ignore[no-any-return]


def run_async(fn: Callable[..., Any], *args: Any) -> Any:
    """An async function's result, run with anyio on a helper thread (H1)."""
    import anyio

    return in_thread(lambda: anyio.run(fn, *args))


def record_requests(context: Any) -> list[Any]:
    """The context's requests, appended as they are made (H2: a lambda, because the listener's return is used)."""
    seen: list[Any] = []
    context.on("request", lambda request: seen.append(request))
    return seen


def path_is(url: str, *prefixes: str) -> bool:
    """Whether the URL's path equals or lies under any of `prefixes` (`/api` matches `/api` and `/api/x`, not `/apix`)."""
    path = urllib.parse.urlsplit(url).path
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)


class Intercepted:
    """What `without_cookies_once` did: `urls` it answered, and the `cookie` header the page's request carried."""

    def __init__(self) -> None:
        self.urls: list[str] = []
        self.done = False


def without_cookies_once(pw: Any, context: Any, matches: Callable[[str], bool], *, skip: int = 0) -> Intercepted:
    """The (`skip`+1)th request of `context` whose URL satisfies `matches` reaches the real server cookie-less (Q6):
    a fresh `pw.request.new_context()` makes it and `route.fulfill(response=...)` answers the page, so the cookie jar
    is neither read nor changed; every other request goes on as it was. The server's `Set-Cookie` for that one
    request never reaches the browser, and the request is Playwright's own (the page's `Origin`/`Referer` are
    copied, `Cookie` is not)."""
    state = Intercepted()
    count = [0]

    def handle(route: Any) -> None:
        if state.done:
            return route.fallback()
        count[0] += 1
        if count[0] <= skip:
            return route.fallback()
        state.done = True
        request = route.request
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("cookie", "host", "content-length")}
        fresh = pw.request.new_context()
        try:
            response = fresh.fetch(request.url, method=request.method, headers=headers,
                                   data=request.post_data_buffer, max_redirects=0)
            state.urls.append(request.url)
            route.fulfill(response=response)
        finally:
            fresh.dispose()

    context.route(lambda url: matches(url), handle)
    return state


def abort_login_navigation(context: Any, login: str = "/api/auth/login") -> list[str]:
    """Abort the shell's navigation to `login` with `ERR_ABORTED`, so the document stays on its address with the
    attempt record the shell wrote. Returns the URLs aborted, in order (the test's signal that the shell tried)."""
    aborted: list[str] = []

    def handle(route: Any) -> None:
        aborted.append(route.request.url)
        route.abort("aborted")

    context.route(lambda url: path_is(url, login), handle)
    return aborted


def restore_from_cache(page: Any) -> None:
    """Dispatch `pageshow` with `persisted: true` on the document, as a restore from the back-forward cache does (the
    pinned browser cannot produce one: C44)."""
    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))")
