"""#1540 F7: `bun run dev` serves the app on http://localhost:8000 (the origin the dev realm registers) and proxies `/api`
to `DEFENDER_INGRESS_API_UPSTREAM` (host:port), started for real in a built copy of the frontend, never the checkout,
against a stand-in API that answers every path with a JSON echo.

Not a browser module: no Playwright and no async here, though the directory's conftest module-scopes Playwright.
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
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

from defender.tests.support.frontend import _ingress1161 as harness

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


def test_1540_f7_a_path_outside_api_is_not_forwarded_to_the_upstream(dev: Dev):
    """`/apix` is not an API path: only `/api` and `/api/...` are proxied, as the ingress does. (F7)"""
    assert httpx.get(f"{ORIGIN}/api/me", timeout=10).json()["path"] == "/api/me", "control: /api/me is forwarded"
    httpx.get(f"{ORIGIN}/apix", timeout=10)
    httpx.get(f"{ORIGIN}/apix/y?a=1", timeout=10)
    assert [p for _, p in dev.api.received if p.startswith("/apix")] == []
