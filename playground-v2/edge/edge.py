"""The lab's one ingress (#1391 r6 L1): every lab port the credential proxy reaches is published by
this program, live on the lab server's public address and frozen inside the frozen engine.

Per HTTP port it admits only what the lab tenant may declare: GET/HEAD on any path outside
`/admin`, plus the port's declared writes (`lab-surface.json`). Everything else is refused (404)
whatever the key, so the stubs' reset and chaos-overlay routes are never reachable from outside and
a run never reads the chaos fault an eval injected. A path is judged decoded: an encoded `/` or
`\\`, a `\\`, or a `.`/`..` segment is refused (the rule #1391 r5 T2 applies on the product side).
With the key check on (live), a request must also carry `Authorization: Bearer <V2_LAB_API_KEY>`
(401 otherwise); the header is stripped before forwarding. The frozen engine runs it with the key
check off: it is reached only through the operator's SSH forward.

A `passthrough` port (Elasticsearch) is forwarded as bytes: the upstream authenticates itself.

The key comes from the environment, never the command line (process monitors ship command lines).
Standard library only, so its tests need no Docker. Started as `python /app/edge.py`, never
`python app.py` (Shuffle's reaper kills that command).
"""
from __future__ import annotations

import argparse
import hmac
import http.client
import json
import os
import socket
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

SURFACE = Path(os.environ.get("V2_LAB_SURFACE", Path(__file__).resolve().with_name("lab-surface.json")))
KEY_ENV = "V2_LAB_API_KEY"
UPSTREAM_TIMEOUT_S = 60
#: Hop-by-hop headers (RFC 9110 7.6.1) and the credential: never forwarded.
_DROP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
         "transfer-encoding", "upgrade", "authorization", "host"}


def load_surface(path: Path = SURFACE) -> dict:
    return json.loads(Path(path).read_text())


def _segment_match(pattern: str, path: str) -> bool:
    want, got = pattern.strip("/").split("/"), path.strip("/").split("/")
    return len(want) == len(got) and all(w == "*" and g or w == g for w, g in zip(want, got))


def judge(method: str, raw_target: str, writes: list[list[str]]) -> bool:
    """True when `method raw_target` is on the declared surface (key aside)."""
    # Judge exactly the string that is forwarded: split only at `?`. `urlsplit` would read
    # `//admin/x` as authority `admin` and path `/x`, and pass absolute-form targets.
    raw_path = raw_target.split("?", 1)[0]
    if not raw_path.startswith("/") or raw_path.startswith("//") or "#" in raw_target:
        return False
    lowered = raw_path.lower()
    if "%2f" in lowered or "%5c" in lowered or "\\" in raw_path:
        return False
    path = unquote(raw_path)
    if "\\" in path or "\x00" in path:
        return False
    segments = path.split("/")[1:]
    if segments and segments[-1] == "":
        segments = segments[:-1]                    # one trailing slash is harmless
    if any(s in ("", ".", "..") for s in segments):
        return False
    if segments and segments[0] == "admin":
        return False
    if method in ("GET", "HEAD"):
        return True
    return any(method == m and _segment_match(p, path) for m, p in writes)


def key_ok(header: str | None, key: str) -> bool:
    if not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[len("Bearer "):].encode(), key.encode())


def make_handler(*, target: tuple[str, int], writes: list[list[str]], key: str | None) -> type:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "lab-edge"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # one line per request, no headers
            sys.stderr.write(f"edge :{self.server.server_address[1]} {fmt % args}\n")

        def _refuse(self, status: int, why: str) -> None:
            body = json.dumps({"detail": why}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self.close_connection = True

        def _handle(self) -> None:
            if key is not None and not key_ok(self.headers.get("Authorization"), key):
                return self._refuse(401, "a bearer key is required")
            if not judge(self.command, self.path, writes):
                return self._refuse(404, "not served")
            if self.headers.get("Transfer-Encoding"):
                return self._refuse(411, "a request body needs a Content-Length")
            raw_length = (self.headers.get("Content-Length") or "0").strip()
            if not raw_length.isdigit():
                return self._refuse(400, "a bad Content-Length")
            length = int(raw_length)
            body = self.rfile.read(length) if length else None
            headers = {k: v for k, v in self.headers.items() if k.lower() not in _DROP}
            upstream = http.client.HTTPConnection(*target, timeout=UPSTREAM_TIMEOUT_S)
            try:
                upstream.request(self.command, self.path, body=body, headers=headers)
                reply = upstream.getresponse()
                data = reply.read()
            except OSError as exc:
                return self._refuse(502, f"upstream unreachable: {type(exc).__name__}")
            finally:
                upstream.close()
            self.send_response(reply.status, reply.reason)
            for name, value in reply.getheaders():
                if name.lower() not in _DROP and name.lower() != "content-length":
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _handle

    return Handler


class _Pipe(socketserver.BaseRequestHandler):
    target: tuple[str, int]

    def handle(self) -> None:
        try:
            upstream = socket.create_connection(self.target, timeout=UPSTREAM_TIMEOUT_S)
        except OSError:
            return
        upstream.settimeout(None)
        self.request.settimeout(None)

        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while chunk := src.recv(65536):
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        other = threading.Thread(target=pump, args=(upstream, self.request), daemon=True)
        other.start()
        pump(self.request, upstream)
        other.join()
        upstream.close()


class _PipeServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class _HttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def servers(surface: dict, *, bind: str, key: str | None,
            targets: dict[str, tuple[str, int]] | None = None) -> list[socketserver.BaseServer]:
    """One server per system port. `targets` overrides where a system forwards (tests)."""
    made: list[socketserver.BaseServer] = []
    for system, spec in surface["systems"].items():
        port = int(spec["port"])
        default = (spec["service"], port if spec.get("passthrough") else int(surface["service_port"]))
        target = (targets or {}).get(system, default)
        if spec.get("passthrough"):
            handler = type(f"Pipe_{port}", (_Pipe,), {"target": target})
            made.append(_PipeServer((bind, port), handler))
        else:
            made.append(_HttpServer((bind, port), make_handler(target=target, writes=spec.get("writes", []),
                                                               key=key)))
    return made


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="The lab's keyed ingress (#1391 r6 L1)")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--no-key-check", action="store_true",
                        help="frozen engine only: reachable solely through the operator's SSH forward")
    args = parser.parse_args(argv)
    key = None
    if not args.no_key_check:
        key = os.environ.get(KEY_ENV, "")
        if not key:
            print(f"{KEY_ENV} is not set: the edge refuses to start without a key", file=sys.stderr)
            return 2
    running = servers(load_surface(), bind=args.bind, key=key)
    for server in running:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"edge: {len(running)} ports, key check {'off' if key is None else 'on'}", file=sys.stderr)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
