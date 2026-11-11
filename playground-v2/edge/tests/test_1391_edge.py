"""#1391 r6 L1: the lab's edge admits only the lab tenant's declared surface, with the key.

Driven against real sockets on loopback (no Docker): an upstream that records what reaches it
stands in for each service.
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

EDGE = Path(__file__).resolve().parents[1] / "edge.py"
SURFACE = Path(__file__).resolve().parents[2] / "lab-surface.json"
_spec = importlib.util.spec_from_file_location("lab_edge_1391", EDGE)
edge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(edge)

KEY = "k3y-for-tests"


class Upstream:
    """An HTTP service that answers 200 with what it was asked."""

    def __init__(self):
        self.seen = []
        seen = self.seen

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _any(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                seen.append({"method": self.command, "path": self.path, "headers": dict(self.headers),
                             "body": body})
                data = json.dumps({"ok": True, "path": self.path}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = _any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.address = self.server.server_address


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(b"echo:" + data)


@pytest.fixture
def lab():
    """The edge over the real surface, every port moved to an ephemeral one, each system's
    upstream a recorder (elastic: a TCP echo)."""
    surface = json.loads(SURFACE.read_text())
    ups = {name: Upstream() for name, spec in surface["systems"].items() if not spec.get("passthrough")}
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    targets = {name: u.address for name, u in ups.items()}
    targets["elastic"] = echo.server_address
    for spec in surface["systems"].values():
        spec["port"] = 0

    def start(key):
        made = edge.servers(surface, bind="127.0.0.1", key=key, targets=targets)
        for s in made:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        return {name: s.server_address[1] for name, s in zip(surface["systems"], made)}

    yield start, ups, surface
    for u in ups.values():
        u.server.shutdown()
    echo.shutdown()


def ask(port, method, path, *, key=KEY, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Authorization": f"Bearer {key}"} if key is not None else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=headers)
    reply = conn.getresponse()
    data = reply.read()
    conn.close()
    return reply.status, data


def test_a_keyed_read_reaches_the_service_with_its_query_and_without_the_key(lab):
    start, ups, _ = lab
    ports = start(KEY)
    status, data = ask(ports["host-state"], "GET", "/hosts/web-1/files/sha256?path=%2Fetc%2Fhosts")
    assert status == 200 and json.loads(data)["ok"]
    seen = ups["host-state"].seen[-1]
    assert seen["path"] == "/hosts/web-1/files/sha256?path=%2Fetc%2Fhosts"
    assert "Authorization" not in seen["headers"] and "authorization" not in {k.lower() for k in seen["headers"]}


@pytest.mark.parametrize("key", [None, "wrong", ""], ids=["no-key", "wrong-key", "empty-key"])
def test_a_request_without_the_key_is_refused_before_anything_is_forwarded(lab, key):
    start, ups, _ = lab
    ports = start(KEY)
    status, _ = ask(ports["cmdb"], "GET", "/hosts/web-1", key=key)
    assert status == 401 and not ups["cmdb"].seen


def test_every_call_off_the_declared_surface_is_refused_with_or_without_the_key(lab):
    """The class: every method on every HTTP port, over admin paths, encoded separators and dot
    segments, and every non-GET that is not that port's declared write."""
    start, ups, surface = lab
    keyed = start(KEY)
    unkeyed = start(None)
    paths = ["/admin/reset", "/admin/overlay/web-1", "/%61dmin/overlay/web-1", "/hosts/web-1%2Faccounts",
             "/hosts/web-1%5Caccounts", "/hosts/../admin/reset", "/hosts/./x", "/x%2e%2e/y/..%2F",
             "//admin/reset", "/x//admin/reset", "http://cmdb/admin/reset", "/admin#/hosts", "/hosts/%2e%2e/admin"]
    for name, spec in surface["systems"].items():
        if spec.get("passthrough"):
            continue
        for ports in (keyed, unkeyed):
            for method in ("GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"):
                for path in paths:
                    body = b"{}" if method in ("POST", "PUT", "PATCH") else None
                    status, _ = ask(ports[name], method, path, body=body)
                    assert status == 404, (name, method, path, status)
            for method in ("POST", "PUT", "DELETE", "PATCH"):
                for path in ("/tickets", "/changes", "/hooks/kibana-alerts", "/tickets/T-1/transitions", "/x"):
                    if any(method == m and edge._segment_match(p, path) for m, p in spec["writes"]):
                        continue
                    status, _ = ask(ports[name], method, path, body=b"{}")
                    assert status == 404, (name, method, path, status)
        assert not ups[name].seen, f"{name} was reached: {ups[name].seen}"


@pytest.mark.parametrize(("system", "path"), [("threat-intel", "/lookup"), ("ticket", "/tickets/SOC-7/comments")])
def test_a_declared_write_is_forwarded_with_its_body(lab, system, path):
    start, ups, _ = lab
    ports = start(KEY)
    status, _ = ask(ports[system], "POST", path, body=b'{"values": ["http://x.example/a/b"]}')
    assert status == 200
    assert ups[system].seen[-1]["body"] == b'{"values": ["http://x.example/a/b"]}'
    status, _ = ask(ports[system], "POST", path + "/more", body=b"{}")
    assert status == 404


def test_the_frozen_edge_has_no_key_check_but_the_same_surface(lab):
    start, ups, _ = lab
    ports = start(None)
    assert ask(ports["cmdb"], "GET", "/hosts/web-1", key=None)[0] == 200
    assert ask(ports["cmdb"], "GET", "/admin/overlay/web-1", key=None)[0] == 404


def test_elasticsearch_is_passed_through_as_bytes(lab):
    start, _, _ = lab
    ports = start(KEY)
    with socket.create_connection(("127.0.0.1", ports["elastic"]), timeout=5) as sock:
        sock.sendall(b"\x16\x03\x01 not http")
        assert sock.recv(100) == b"echo:\x16\x03\x01 not http"


def test_the_edge_refuses_to_start_live_without_a_key(monkeypatch):
    monkeypatch.delenv(edge.KEY_ENV, raising=False)
    assert edge.main([]) == 2


def test_a_bad_content_length_is_refused_not_hung(lab):
    start, ups, surface = lab
    ports = start(KEY)
    for value in ("abc", "-5"):
        with socket.create_connection(("127.0.0.1", ports["threat-intel"]), timeout=5) as s:
            s.sendall(f"POST /lookup HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY}\r\n"
                      f"Content-Length: {value}\r\n\r\n".encode())
            assert s.recv(64).split(b" ")[1] == b"400", value
