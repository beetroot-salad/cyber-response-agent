"""The lab edge (#1391 r6 L1), driven against real nginx in Docker.

One network holds a keyed edge, an open (frozen-frontend) edge, and one upstream container
answering under every service name the surface uses except `endpoint-query` (so host-state's
port shows an unreachable upstream). The upstream records what reached it; requests are sent as
raw bytes from inside the upstream container, so any target or header shape can be tried and
nothing depends on how the daemon's host reaches containers.

Needs a Docker daemon: skipped without one locally, a failure in CI.
"""
from __future__ import annotations

import base64
import json
import re
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PLAYGROUND = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
import render  # noqa: E402

SURFACE = json.loads((PLAYGROUND / "lab-surface.json").read_text())
KEY = "k3y-for-tests_0123456789"
UPSTREAM_IMAGE = "python:3.12-slim"
UNREACHABLE = "endpoint-query"

UPSTREAM = r'''
import json, socketserver, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
seen = []
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _any(self):
        if self.path == "/__seen":
            data = json.dumps(seen).encode()
        elif self.path == "/__reset":
            seen.clear(); data = b"[]"
        else:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("latin-1")
            seen.append({"method": self.command, "path": self.path, "body": body,
                         "headers": {k.lower(): v for k, v in self.headers.items()}})
            data = json.dumps({"ok": True, "path": self.path, "pad": "x" * 100}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = do_OPTIONS = _any
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(b"echo:" + data)
class T(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True
threading.Thread(target=T(("0.0.0.0", 9200), Echo).serve_forever, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
'''

CLIENT = r'''
import base64, json, socket, sys
out = []
for host, port, raw in json.loads(sys.stdin.read()):
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(base64.b64decode(raw))
    data = b""
    try:
        while chunk := s.recv(65536):
            data += chunk
    except socket.timeout:
        data += b"<timeout>"
    s.close()
    out.append(base64.b64encode(data).decode())
print(json.dumps(out))
'''


def _docker(*args: str, check: bool = True, timeout: int = 300, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check, timeout=timeout,
                          input=stdin)


def _have_docker() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.fixture(scope="module")
def lab():
    if not _have_docker():
        if os.environ.get("CI"):
            pytest.fail("the edge tests need Docker and CI has none")
        pytest.skip("no Docker daemon")
    tag = f"edge-test-{uuid.uuid4().hex[:8]}"
    image = f"soc-playground/edge:{tag}"
    _docker("build", "-q", "-f", str(PLAYGROUND / "edge/Dockerfile"), "-t", image, str(PLAYGROUND), timeout=600)
    _docker("network", "create", tag)
    names = {spec["service"] for spec in SURFACE["systems"].values()} - {UNREACHABLE}
    up, keyed, opened = f"{tag}-up", f"{tag}-keyed", f"{tag}-open"
    try:
        _docker("run", "-d", "--name", up, "--network", tag, *(a for n in sorted(names) for a in ("--network-alias", n)),
                UPSTREAM_IMAGE, "python", "-c", UPSTREAM)
        _docker("run", "-d", "--name", keyed, "--network", tag, "-e", f"V2_LAB_API_KEY={KEY}", image)
        _docker("run", "-d", "--name", opened, "--network", tag, image, "--no-key-check")
        lab = Lab(up=up, keyed=keyed, opened=opened, image=image, network=tag)
        lab.wait_ready()
        yield lab
    finally:
        _docker("rm", "-f", up, keyed, opened, check=False)
        _docker("network", "rm", tag, check=False)
        _docker("rmi", "-f", image, check=False)


class Lab:
    def __init__(self, *, up, keyed, opened, image, network):
        self.up, self.keyed, self.opened, self.image, self.network = up, keyed, opened, image, network

    def send(self, cases: list[tuple[str, int, bytes]]) -> list[bytes]:
        payload = json.dumps([[h, p, base64.b64encode(raw).decode()] for h, p, raw in cases])
        proc = _docker("exec", "-i", self.up, "python", "-c", CLIENT, timeout=600, stdin=payload)
        return [base64.b64decode(x) for x in json.loads(proc.stdout)]

    def seen(self) -> list[dict]:
        raw = self.send([("127.0.0.1", 8080, b"GET /__seen HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")])[0]
        return json.loads(raw.split(b"\r\n\r\n", 1)[1])

    def reset(self) -> None:
        self.send([("127.0.0.1", 8080, b"GET /__reset HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")])

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                replies = self.send([(self.opened, 8001, request("GET", "/__ready", key=None)),
                                     (self.keyed, 8001, request("GET", "/__ready"))])
                if all(status(r) == 200 for r in replies):
                    self.reset()
                    return
            except subprocess.CalledProcessError:
                pass
            time.sleep(1)
        logs = _docker("logs", self.keyed, check=False)
        raise AssertionError(f"the edge never came up: {logs.stdout} {logs.stderr}")


def request(method: str, target: str, *, key: str | None = KEY, body: bytes | None = None,
            extra: str = "") -> bytes:
    head = f"{method} {target} HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n"
    if key is not None:
        head += f"Authorization: Bearer {key}\r\n"
    if body is not None:
        head += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
    return (head + extra + "\r\n").encode() + (body or b"")


def status(reply: bytes) -> int:
    return int(reply.split(b" ", 2)[1])


def headers(reply: bytes) -> dict[str, str]:
    lines = reply.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")[1:]
    return {k.strip().lower(): v.strip() for k, v in (line.split(":", 1) for line in lines)}


HTTP = {name: spec for name, spec in SURFACE["systems"].items() if not spec.get("passthrough")}


def test_a_keyed_read_reaches_its_service_with_its_query_and_without_the_key(lab):
    lab.reset()
    reply, = lab.send([(lab.keyed, 8001, request("GET", "/hosts/web-1?view=full"))])
    assert status(reply) == 200
    seen, = lab.seen()
    assert seen["path"] == "/hosts/web-1?view=full"
    assert seen["headers"]["host"].startswith("cmdb:")
    assert "authorization" not in seen["headers"]


@pytest.mark.parametrize("key", [None, "wrong", ""], ids=["no-key", "wrong-key", "empty-key"])
def test_a_request_without_the_key_is_refused_before_anything_is_forwarded(lab, key):
    lab.reset()
    replies = lab.send([(lab.keyed, int(spec["port"]), request("GET", "/hosts/web-1", key=key))
                        for spec in HTTP.values()])
    assert [status(r) for r in replies] == [401] * len(HTTP)
    assert lab.seen() == []


OFF_SURFACE_PATHS = [
    "/admin", "/admin/reset", "/admin/overlay/web-1", "/%61dmin/overlay/web-1", "/hosts/web-1%2Faccounts",
    "/hosts/web-1%2faccounts", "/hosts/web-1%5Caccounts", "/hosts/web-1\\accounts", "/hosts/../admin/reset",
    "/hosts/./x", "/x%2e%2e/y", "/hosts/%2e%2e/admin", "/hosts/%00", "//admin/reset", "/x//admin/reset",
    "http://cmdb/admin/reset", "/admin#/hosts", "/hosts/..", "/hosts/.",
]


def test_every_call_off_the_declared_surface_is_refused_with_or_without_the_key(lab):
    """The class: every method on every HTTP port, over admin paths, encoded separators, dot
    segments, doubled slashes and non-origin targets, and every non-GET that is not that port's
    declared write."""
    lab.reset()
    cases = []
    for spec in HTTP.values():
        port = int(spec["port"])
        for edge in (lab.keyed, lab.opened):
            for method in ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"):
                body = b"{}" if method in ("POST", "PUT", "PATCH") else None
                for path in OFF_SURFACE_PATHS:
                    cases.append((edge, port, request(method, path, body=body)))
            declared = {(m, render._write_location(p)) for m, p in spec.get("writes", [])}
            for method in ("POST", "PUT", "DELETE", "PATCH"):
                for path in ("/tickets", "/changes", "/hooks/kibana-alerts", "/tickets/T-1/transitions", "/x",
                             "/lookup/more", "/tickets/T-1/comments/x"):

                    if any(method == m and re.match(rx, path) for m, rx in declared):
                        continue
                    cases.append((edge, port, request(method, path, body=b"{}")))
    replies = lab.send(cases)
    wrong = [(c[0], c[1], c[2].split(b"\r\n", 1)[0], r[:40]) for c, r in zip(cases, replies)
             if not r.startswith(b"HTTP/1.1 404") and not r.startswith(b"HTTP/1.1 400")]
    assert not wrong, wrong[:10]
    assert lab.seen() == []


@pytest.mark.parametrize(("system", "path"), [("threat-intel", "/lookup"), ("ticket", "/tickets/SOC-7/comments")])
def test_a_declared_write_is_forwarded_with_its_body(lab, system, path):
    lab.reset()
    port = int(SURFACE["systems"][system]["port"])
    body = b'{"values": ["http://x.example/a/b"]}'
    reply, = lab.send([(lab.keyed, port, request("POST", path, body=body))])
    assert status(reply) == 200
    seen, = lab.seen()
    assert (seen["method"], seen["path"], seen["body"]) == ("POST", path, body.decode())


def test_the_frozen_frontend_has_no_key_check_but_the_same_surface(lab):
    lab.reset()
    ok, admin = lab.send([(lab.opened, 8001, request("GET", "/hosts/web-1", key=None)),
                          (lab.opened, 8001, request("GET", "/admin/overlay/web-1", key=None))])
    assert (status(ok), status(admin)) == (200, 404)
    assert [s["path"] for s in lab.seen()] == ["/hosts/web-1"]


def test_elasticsearch_is_passed_through_as_bytes(lab):
    port = int(SURFACE["systems"]["elastic"]["port"])
    for edge in (lab.keyed, lab.opened):
        reply, = lab.send([(edge, port, b"\x16\x03\x01 not http")])
        assert reply.startswith(b"echo:\x16\x03\x01 not http")


def test_head_reports_the_upstreams_length(lab):
    get, head = lab.send([(lab.keyed, 8001, request("GET", "/hosts/web-1")),
                          (lab.keyed, 8001, request("HEAD", "/hosts/web-1"))])
    assert status(head) == 200
    assert headers(head)["content-length"] == headers(get)["content-length"] != "0"


def test_an_unreachable_service_is_answered_502_not_dropped(lab):
    port = int(SURFACE["systems"]["host-state"]["port"])
    reply, = lab.send([(lab.keyed, port, request("GET", "/hosts"))])
    assert status(reply) == 502


def test_an_ambiguous_body_length_is_refused_and_not_forwarded(lab):
    lab.reset()
    port = int(SURFACE["systems"]["threat-intel"]["port"])
    replies = lab.send([
        (lab.keyed, port, request("POST", "/lookup", body=b"{}", extra="Content-Length: 50\r\n")),
        (lab.keyed, port, request("POST", "/lookup", extra="Content-Length: abc\r\n")),
        (lab.keyed, port, request("POST", "/lookup", extra="Content-Length: -5\r\n")),
    ])
    assert [status(r) for r in replies] == [400, 400, 400]
    assert lab.seen() == []


@pytest.mark.parametrize("env", [[], ["-e", "V2_LAB_API_KEY="], ["-e", 'V2_LAB_API_KEY=a"b']],
                         ids=["unset", "empty", "unquotable"])
def test_the_live_edge_refuses_to_start_without_a_usable_key(lab, env):
    proc = _docker("run", "--rm", *env, lab.image, check=False, timeout=60)
    assert proc.returncode == 2, (proc.stdout, proc.stderr)


def test_the_edge_stops_promptly(lab):
    name = f"{lab.network}-stop"
    _docker("run", "-d", "--name", name, "--network", lab.network, lab.image, "--no-key-check")
    try:
        time.sleep(1)
        start = time.monotonic()
        _docker("stop", name)
        assert time.monotonic() - start < 5
    finally:
        _docker("rm", "-f", name, check=False)


def test_render_refuses_a_write_path_it_cannot_express_exactly():
    with pytest.raises(ValueError):
        render._write_location("/tickets/{id}/comments")
    assert render._write_location("/tickets/*/comments") == r"^/tickets/[^/]+/comments/?$"


def test_render_serves_every_port_of_the_surface_in_both_modes():
    for key_check in (True, False):
        conf = render.render(SURFACE, key_check=key_check)
        for spec in SURFACE["systems"].values():
            assert f"listen {spec['port']};" in conf
        assert ("Bearer ${V2_LAB_API_KEY}" in conf) is key_check
