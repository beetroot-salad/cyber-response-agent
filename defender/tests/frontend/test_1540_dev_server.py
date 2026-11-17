"""#1540 F7: `bun run dev` serves the app on http://localhost:8000 (the origin the dev realm registers) and proxies `/api`
to `DEFENDER_INGRESS_API_UPSTREAM` (host:port), started for real in a built copy of the frontend, never the checkout,
against a stand-in API that answers every path with a JSON echo.

Two browser cases (Am-5: the dev build's doubled effects) drive the pinned Chromium at the dev server; there is no async
here, so the directory's module-scoped Playwright is safe.
Port 8000 is fixed by the design: a listener already there is a failure naming it (never a skip), and runs of this module
in other xdist workers wait for a file lock, so only one dev server exists at a time."""
from __future__ import annotations

import fcntl
import http.server
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from html.parser import HTMLParser
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

from defender.tests.frontend._flow1161 import HOME, api_calls, await_aborted, repeated_api_gets, settle
from defender.tests.support.frontend import _ingress1161 as harness
from defender.tests.support.frontend._browser1161 import abort_login_navigation, path_is, record_requests

ORIGIN = "http://localhost:8000"
START_TIMEOUT = 90.0


@dataclass
class StandInApi:
    """Answers every request with `{"method", "path"}` (path with its query, as received) and remembers each."""

    server: http.server.ThreadingHTTPServer
    received: list[tuple[str, str]] = field(default_factory=list)

    @property
    def upstream(self) -> str:
        return f"127.0.0.1:{self.server.server_address[1]}"


def _stand_in() -> StandInApi:
    api: StandInApi

    class Handler(http.server.BaseHTTPRequestHandler):
        def _echo(self) -> None:
            api.received.append((self.command, self.path))
            body = json.dumps({"method": self.command, "path": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = _echo  # noqa: N815 — the stdlib's names

        def log_message(self, *_: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    api = StandInApi(server)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return api


def _listening(port: int) -> bool:
    for host in ("127.0.0.1", "::1"):
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            continue
    return False


def _stop(process: subprocess.Popen[bytes]) -> None:
    """The whole process group: `bun run dev` starts the server as a child."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(10)
            return
        except subprocess.TimeoutExpired:
            continue


@dataclass
class Dev:
    copy: Path
    api: StandInApi


@pytest.fixture(scope="module")
def dev(built_frontend: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Dev]:
    """`bun run dev` in a copy of the frontend with the build's `node_modules`, upstream a stand-in API."""
    with open(Path(tempfile.gettempdir()) / "defender-dev-server-8000.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if _listening(8000):
            pytest.fail("port 8000 already has a listener: the dev server's port is fixed by the design (F7); stop it and rerun")
        copy = harness.copy_frontend(tmp_path_factory.mktemp("dev"), node_modules_from=harness.node_modules_of(built_frontend))
        api = _stand_in()
        log = (copy.parent / "dev-server.log").open("wb")
        process = subprocess.Popen(["bun", "run", "dev"], cwd=copy, stdout=log, stderr=subprocess.STDOUT,
                                   env={**os.environ, "DEFENDER_INGRESS_API_UPSTREAM": api.upstream}, start_new_session=True)
        try:
            deadline = time.monotonic() + START_TIMEOUT
            while True:
                tail = (copy.parent / "dev-server.log").read_text(errors="replace")[-2000:]
                assert process.poll() is None, f"`bun run dev` exited with {process.returncode}:\n{tail}"
                try:
                    httpx.get(f"{ORIGIN}/", timeout=2)
                    break
                except httpx.HTTPError:
                    assert time.monotonic() < deadline, f"nothing answered on {ORIGIN} within {START_TIMEOUT:.0f}s:\n{tail}"
                    time.sleep(0.3)
            yield Dev(copy, api)
        finally:
            _stop(process)
            api.server.shutdown()
            log.close()


def _source_index(copy: Path) -> str:
    for candidate in (copy / "index.html", copy / "public" / "index.html"):
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    pytest.fail(f"the copy has no index.html at {copy} or {copy / 'public'}")


def test_1540_f7_the_dev_server_answers_on_localhost_8000_with_the_apps_own_document(dev: Dev):
    """`/` is an HTML document carrying the copy's own title and root element. (F7)"""
    page = httpx.get(f"{ORIGIN}/", timeout=10)
    assert page.status_code == 200, page.status_code
    assert page.headers["content-type"].startswith("text/html"), page.headers["content-type"]
    assert "<html" in page.text.lower(), page.text[:200]
    source = _source_index(dev.copy)
    [title] = re.findall(r"<title>(.*?)</title>", source, re.S)
    [root] = re.findall(r'<body[^>]*>.*?\sid="([^"]+)"', source, re.S)[:1]
    assert f"<title>{title}</title>" in page.text, (title, page.text[:400])
    assert f'id="{root}"' in page.text, (root, page.text[:400])


@pytest.mark.parametrize("path", ["/api/me", "/api/tenants/x/investigations/y?z=1"])
def test_1540_f7_an_api_request_reaches_the_upstream_with_its_path_and_query_and_is_answered_back(dev: Dev, path):
    """`/api/...` is forwarded to `DEFENDER_INGRESS_API_UPSTREAM` as it came, and its answer returns. (F7)"""
    answer = httpx.get(f"{ORIGIN}{path}", timeout=10)
    assert answer.status_code == 200, answer.text[:200]
    assert answer.json() == {"method": "GET", "path": path}, answer.text[:200]
    assert ("GET", path) in dev.api.received, dev.api.received


class _ModuleScripts(HTMLParser):
    """The `src` of each module script the served document references."""

    def __init__(self) -> None:
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "script" and values.get("type") == "module" and values.get("src"):
            self.sources.append(str(values["src"]))


def _served_entry(copy: Path) -> tuple[str, Path]:
    """(the URL the served document loads a script from, the copy's own file of that name): the module scripts the
    document references that are files of the copy. Fails when it references none."""
    scripts = _ModuleScripts()
    scripts.feed(httpx.get(f"{ORIGIN}/", timeout=10).text)
    for src in scripts.sources:
        path = urllib.parse.urlsplit(src)
        if path.netloc or "node_modules" in path.path:
            continue
        candidate = copy / urllib.parse.unquote(path.path).lstrip("/")
        if candidate.is_file():
            return src, candidate
    pytest.fail(f"the served document references no module script that is a file of the copy: {scripts.sources}")


def test_1540_f7_an_edit_to_a_source_module_the_app_loads_is_served_without_restarting(dev: Dev):
    """With `bun run dev` running, a constant appended to the module the document loads as its script is in what the dev
    server serves for that module's URL within the timeout; before the edit it is not. (F7: the hot-reload loop)"""
    marker = f"zzHotReload{time.time_ns()}"
    url, source = _served_entry(dev.copy)
    original = source.read_text(encoding="utf-8")

    def served() -> str:
        return httpx.get(urllib.parse.urljoin(f"{ORIGIN}/", url), timeout=10).text

    assert marker not in served(), "control: the marker is absent before the edit"
    try:
        source.write_text(f'{original}\nexport const {marker} = "{marker}";\n', encoding="utf-8")
        deadline = time.monotonic() + 30
        while marker not in (body := served()):
            assert time.monotonic() < deadline, f"{url} never carried the edit within 30s: {body[:300]}"
            time.sleep(0.3)
    finally:
        source.write_text(original, encoding="utf-8")


#: Counts the page's writes to its tab storage (any key), as `window.__storageWrites`, from before the app's first script.
_COUNT_STORAGE_WRITES = """
    window.__storageWrites = 0;
    const setItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
        if (this === window.sessionStorage) window.__storageWrites += 1;
        return setItem.call(this, key, value);
    };
"""


def test_1540_am5_the_dev_loop_signs_a_signed_out_home_in_once_with_one_attempt_record(dev: Dev, browser):
    """Through `bun run dev` (the development build, StrictMode on), a signed-out `/home` (`/api/me` answers 401) makes
    exactly one navigation to sign-in, with `return=/home`, and writes its attempt record once: the doubled effects and
    renders of the development build reach none of B1. (Am-5 §1; "`bun run dev` (StrictMode active)")"""
    context = browser.new_context()
    context.set_default_timeout(30_000)
    seen: list[object] = []
    context.on("request", lambda r: seen.append(r))
    context.route(lambda u: path_is(u, "/api/me"), lambda route: route.fulfill(status=401, body="{}"))
    aborted = abort_login_navigation(context)
    context.add_init_script(_COUNT_STORAGE_WRITES)
    page = context.new_page()
    page.goto(f"{ORIGIN}/{HOME}")
    await_aborted(page, aborted)
    settle(page, 1500)
    assert len(aborted) == 1, aborted
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(aborted[0]).query).get("return") == ["/home"], aborted
    assert page.evaluate("window.__storageWrites") == 1
    assert page.evaluate("sessionStorage.length") == 1
    assert api_calls(seen, ORIGIN) == [("GET", "/api/me")]


_ME = {"kind": "person", "user": {"id": "6f1c1e3c-55a4-4a4e-9a51-000000000001", "email": "ann@example.test", "display_name": "Ann"},
       "tenants": [], "administrator": False, "invitations": []}
_TENANT, _INVESTIGATION = "6f1c1e3c-55a4-4a4e-9a51-000000000002", "6f1c1e3c-55a4-4a4e-9a51-000000000003"


def test_1540_am5_the_dev_loop_sends_a_signed_in_investigations_read_once(dev: Dev, browser):
    """Through `bun run dev`, signed in (`/api/me` and the read answered by routes), the investigation screen's read is
    sent once, and no `/api` GET repeats in the load. (Am-5 point 5: the development build's doubled effects)"""
    read = f"/api/tenants/{_TENANT}/investigations/{_INVESTIGATION}"
    context = browser.new_context()
    context.set_default_timeout(30_000)
    seen = record_requests(context)
    context.route(lambda u: path_is(u, "/api/me"), lambda route: route.fulfill(status=200, json=_ME))
    context.route(lambda u: path_is(u, read),
                  lambda route: route.fulfill(status=200, json={"status": "completed", "disposition": "malicious"}))
    page = context.new_page()
    page.goto(f"{ORIGIN}/t/{_TENANT}/investigations/{_INVESTIGATION}")
    page.locator('[data-field="status"]').wait_for()
    settle(page, 1500)
    assert [c for c in api_calls(seen, ORIGIN) if c == ("GET", read)] == [("GET", read)]
    assert repeated_api_gets(seen) == []
