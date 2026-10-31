"""#1163 machinery: a recording fake upstream, the proxy served on loopback, and recording fakes
for the store, the signer, the verifier and the audit sink. None of them decides anything the
proxy is under test for: they inject inputs and record calls.
"""
from __future__ import annotations

import base64
import contextlib
import http.server
import json
import socket
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests.integrations.credential_proxy_1163._target import ACCESS_FILE

CANARY_KEY = "canary-static-key-1163-7f3a9c"
CANARY_SECRET = "canary-client-secret-1163-b2e4d8"
CLIENT_ID = "client-1163"
#: The http-proxy identity system's config.env: an access method and a timeout, no URL_BASE
#: and no bastion (the declaration holds the only base, r5 A2).
HTTP_PROXY_IDENTITY_ENV = 'IDENTITY_TRANSPORT="http-proxy"\nIDENTITY_TIMEOUT_SEC="5"\n'


@dataclass(frozen=True)
class Seen:
    method: str
    path: str
    headers: dict[str, str]
    body: str


Reply = tuple[int, dict[str, str], bytes]


class Upstream:
    """A loopback HTTP server that records every request. Unless `replies` names the path, it
    answers 200 with JSON echoing the path and the `Authorization` header it received."""

    def __init__(self) -> None:
        self.seen: list[Seen] = []
        self.replies: dict[str, Reply | Callable[[Seen], Reply]] = {}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                seen = Seen(self.command, self.path, dict(self.headers.items()),
                            self.rfile.read(length).decode("utf-8", "replace"))
                outer.seen.append(seen)
                reply = outer.replies.get(self.path.split("?", 1)[0])
                if callable(reply):
                    reply = reply(seen)
                if reply is None:
                    reply = (200, {"Content-Type": "application/json"}, json.dumps(
                        {"path": seen.path, "authorization": seen.headers.get("Authorization")}
                    ).encode())
                status, headers, body = reply
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_DELETE = do_PUT = do_HEAD = _serve  # noqa: N815 — http.server's dispatch names

            def log_message(self, *_: Any) -> None:
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def paths(self) -> list[str]:
        return [s.path for s in self.seen]


@contextlib.contextmanager
def upstream() -> Iterator[Upstream]:
    server = Upstream()
    try:
        yield server
    finally:
        server.close()


def free_port() -> int:
    """A loopback port nothing listens on once this returns (a closed proxy, a foreign port)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def serve_asgi(app: Any) -> Iterator[str]:
    """`app` served by uvicorn on a loopback port in a thread, for a caller that must reach it
    over real HTTP (the adapter's transport). Yields the base URL."""
    import uvicorn

    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline or not thread.is_alive():
            raise RuntimeError("the proxy did not start")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(10)


class FakeStore:
    """The proxy's store port: answers the credential set it was given for (tenant, system), or
    None, and records every read."""

    def __init__(self, sets: Mapping[tuple[str, str], Any] | None = None) -> None:
        self.sets: dict[tuple[str, str], Any] = dict(sets or {})
        self.reads: list[tuple[str, str]] = []

    def read(self, tenant_id: str, system: str) -> Any:
        self.reads.append((tenant_id, system))
        return self.sets.get((tenant_id, system))


class FakeSigner:
    """The launcher's transit-sign port: records each payload and answers a distinct signature."""

    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def sign(self, payload: bytes) -> str:
        self.payloads.append(payload)
        return f"vault:v1:fake-signature-{len(self.payloads)}"


class FakeVerifier:
    """The proxy's transit-verify port: answers `verdict` (True: every signature is valid) and
    records each (payload, signature) it was asked about."""

    def __init__(self, verdict: bool = True) -> None:
        self.verdict = verdict
        self.calls: list[tuple[bytes, str]] = []

    def verify(self, payload: bytes, signature: str) -> bool:
        self.calls.append((payload, signature))
        return self.verdict


@dataclass
class AuditRecorder:
    """The proxy's audit port: keeps every record it is handed."""

    records: list[dict[str, Any]] = field(default_factory=list)

    def record(self, entry: Mapping[str, Any]) -> None:
        self.records.append(dict(entry))


def claims_of(token: str) -> dict[str, Any]:
    """The claims a request token carries, read from the sketch's wire form
    `<base64url(JSON claims)>.<signature>` (a gap: the design names no wire format)."""
    payload, _, _signature = token.rpartition(".")
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def declaration(base: str, *, scheme: Mapping[str, Any] | None = None,
                reads: tuple[tuple[str, str], ...] = (),
                writes: tuple[tuple[str, str], ...] = ()) -> str:
    """An access declaration's text: one base (r5 A2); key names are the contract's choice.
    Data only: nothing here reads or judges one."""
    doc = {
        "access": "http-proxy",
        "base": base,
        "auth": dict(scheme or {"scheme": "bearer", "field": "api_key"}),
        "reads": [{"method": m, "path": p} for m, p in reads],
        "writes": [{"method": m, "path": p} for m, p in writes],
    }
    return json.dumps(doc, indent=2) + "\n"  # JSON is YAML; keeps the fixture free of a dumper


def oauth_scheme(token_url: str) -> dict[str, Any]:
    return {"scheme": "oauth-client-credentials", "token_url": token_url, "scopes": ["read"],
            "client_id_field": "client_id", "client_secret_field": "client_secret"}


def access_files(system: str, text: str, *, env: str | None = None) -> dict[str, str]:
    """Repo-relative files making `system` an http-proxy system: its declaration and, for
    identity, its config.env."""
    files = {ACCESS_FILE.format(system=system): text}
    if env is not None:
        files[f"settings/systems/{system}/config.env"] = env
    return files


def token_endpoint(issued: list[str]) -> Callable[[Seen], Reply]:
    """An OAuth token endpoint reply: a fresh access token per exchange, `AT-<n>`, valid an
    hour; each one issued is appended to `issued`."""
    def reply(_seen: Seen) -> Reply:
        issued.append(f"AT-{len(issued) + 1}-canary-1163")
        body = {"access_token": issued[-1], "token_type": "Bearer", "expires_in": 3600}
        return 200, {"Content-Type": "application/json"}, json.dumps(body).encode()
    return reply


def text_under(root: Path) -> str:
    """Every regular file under `root`, decoded leniently and joined: what a canary census
    reads."""
    parts = []
    for path in sorted(Path(root).rglob("*")):
        if path.is_file() and not path.is_symlink():
            parts.append(path.read_bytes().decode("utf-8", "replace"))
    return "\n".join(parts)
