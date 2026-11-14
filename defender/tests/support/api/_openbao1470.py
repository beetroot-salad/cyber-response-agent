"""#1470: a scripted OpenBao at the HTTP edge, for tests that drive the real `OpenBaoSecrets` (and the API's start check)
without a server — NO test functions.

It answers as OpenBao 2.4.1 was observed to (2026-11-14, a dev server with the writer policy `store_policies` gives):
`GET /v1/sys/seal-status` unauthenticated `{"initialized", "sealed", ...}`; a sealed server answers every other path 503
`{"errors": ["Vault is sealed"]}` (ASSUMED: not observed, the shared test server is not sealed; the 503 status is the
documented one and the not-stored/possibly-stored split rests on it); a token it does not know 403 `permission denied`; the writer's token cannot read a
value (`GET <mount>/data/...` is 403) but reads metadata (404 `{"errors": []}` for a path never written, else 200 with
`current_version` and `versions`); a write (`POST <mount>/data/<path>`) is 200 with the new version. It is a policy
stand-in only for those answers: it holds sets by path and version, nothing more.

- `ScriptedOpenBao(token=, mount=)`: the transport (sync and async); hand it to `serving(..., openbao_transport=...)` or to
  `OpenBaoSecrets(transport=...)`.
- State: `sealed`, `seal_status` (an answer or an exception raised for the seal-status read), `calls` (method, path
  after `/v1/`), `value_reads` (every read of a value: the writer's token must never make one), `stored(...)`.
- Script: `answer(method, contains, response_or_error, *, after=0, times=None)` makes a matching call answer so (an
  exception instance is raised, like a refused connection); `on_write` is awaited inside a write's handler after the set
  is saved and before it answers (a version saved by someone else in between).
- `listening()`: the same answers on a real loopback socket, for a child process."""
from __future__ import annotations

import contextlib
import dataclasses
import http.server
import threading
from collections.abc import Awaitable, Callable, Iterator
from typing import Any

import httpx

WRITER_TOKEN = "api-writer-token-1470"
KV_MOUNT = "secret"
_SEALED = {"errors": ["Vault is sealed"]}
_DENIED = {"errors": ["permission denied"]}


@dataclasses.dataclass
class _Rule:
    method: str | None
    contains: str
    answer: httpx.Response | Exception
    after: int
    times: int | None
    seen: int = 0
    fired: int = 0


class ScriptedOpenBao(httpx.BaseTransport, httpx.AsyncBaseTransport):
    def __init__(self, *, token: str = WRITER_TOKEN, mount: str = KV_MOUNT) -> None:
        self.token, self.mount = token, mount
        self.sealed = False
        self.seal_status: httpx.Response | Exception | None = None
        self.calls: list[tuple[str, str]] = []
        self.value_reads: list[str] = []
        self.on_write: Callable[[str], Awaitable[None]] | None = None
        self._sets: dict[str, list[dict[str, Any]]] = {}
        self._rules: list[_Rule] = []

    def answer(self, method: str | None, contains: str, answer: httpx.Response | Exception, *, after: int = 0,
               times: int | None = None) -> None:
        self._rules.append(_Rule(method, contains, answer, after, times))

    def plant(self, path: str, kind: str, fields: dict[str, str]) -> None:
        """A set already stored at `<tenant>/<system>/g<N>`."""
        self._sets.setdefault(path, []).append({"kind": kind, "fields": dict(fields)})

    def stored(self, path: str) -> dict[str, Any] | None:
        """The latest set at `path`, or None."""
        return self._sets[path][-1] if self._sets.get(path) else None

    def paths(self) -> list[str]:
        return sorted(self._sets)

    # --- answers --------------------------------------------------------------------------------

    def _scripted(self, request: httpx.Request) -> httpx.Response | Exception | None:
        for rule in self._rules:
            if rule.method not in (None, request.method) or rule.contains not in request.url.path:
                continue
            rule.seen += 1
            if rule.seen > rule.after and (rule.times is None or rule.fired < rule.times):
                rule.fired += 1
                return rule.answer
        return None

    def _handle(  # noqa: C901 — one branch per observed answer
            self, request: httpx.Request) -> tuple[httpx.Response | Exception, str | None]:
        """The answer, and the path of a set this call saved (so the async side awaits `on_write`)."""
        path = request.url.path.removeprefix("/v1/")
        self.calls.append((request.method, path))
        scripted = self._scripted(request)
        if scripted is not None:
            return scripted, None
        if path == "sys/seal-status":
            return self.seal_status or httpx.Response(200, json={"initialized": True, "sealed": self.sealed,
                                                                   "version": "2.4.1"}), None
        if self.sealed:
            return httpx.Response(503, json=_SEALED), None
        if request.headers.get("X-Vault-Token") != self.token:
            return httpx.Response(403, json=_DENIED), None
        if request.method in ("DELETE", "LIST") or request.url.params.get("list"):  # the writer policy grants neither
            return httpx.Response(403, json=_DENIED), None
        kind, _, rest = path.removeprefix(f"{self.mount}/").partition("/")
        if not path.startswith(f"{self.mount}/") or not rest:
            return httpx.Response(404, json={"errors": []}), None
        if kind == "metadata" and request.method == "GET":
            versions = self._sets.get(rest)
            if not versions:
                return httpx.Response(404, json={"errors": []}), None
            listing = {str(n): {"created_time": "2026-11-14T16:37:32Z", "deletion_time": "", "destroyed": False}
                       for n in range(1, len(versions) + 1)}
            return httpx.Response(200, json={"data": {"current_version": len(versions), "versions": listing}}), None
        if kind == "data" and request.method == "GET":
            self.value_reads.append(rest)  # the writer policy grants no read of a value
            return httpx.Response(403, json={"errors": ["1 error occurred:\n\t* permission denied\n\n"]}), None
        if kind == "data" and request.method in ("POST", "PUT"):
            body = httpx.Response(200, content=request.content).json()["data"]
            self._sets.setdefault(rest, []).append(body)
            return httpx.Response(200, json={"data": {"version": len(self._sets[rest]), "destroyed": False,
                                                        "deletion_time": "", "custom_metadata": None}}), rest
        return httpx.Response(404, json={"errors": []}), None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        answer, _ = self._handle(request)
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        answer, saved = self._handle(request)
        if isinstance(answer, Exception):
            raise answer
        if saved is not None and self.on_write is not None:
            await self.on_write(saved)
        return answer

    # --- a real socket --------------------------------------------------------------------------

    @contextlib.contextmanager
    def listening(self) -> Iterator[str]:
        """Serve these answers on 127.0.0.1 (for a child process); yields the address."""
        bao = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                request = httpx.Request(self.command, f"http://127.0.0.1{self.path}", headers=dict(self.headers),
                                        content=self.rfile.read(length))
                try:
                    answer = bao.handle_request(request)
                except httpx.HTTPError:
                    self.close_connection = True
                    return
                self.send_response(answer.status_code)
                self.send_header("Content-Length", str(len(answer.content)))
                self.end_headers()
                self.wfile.write(answer.content)

            do_GET = do_POST = do_PUT = _serve  # noqa: N815

            def log_message(self, *args: Any) -> None:
                return None

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()
