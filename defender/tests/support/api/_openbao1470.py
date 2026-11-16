"""#1470: a scripted OpenBao at the HTTP edge, for tests that drive the real `OpenBaoSecrets` (and the API's start check)
without a server — NO test functions.

It answers as OpenBao 2.4.1 was observed to (2026-11-14 and #1532's probes, a dev server):
`GET /v1/sys/seal-status` unauthenticated `{"initialized", "sealed", ...}`; a sealed server answers every other path 503
`{"errors": ["Vault is sealed"]}` whatever the token (observed, design C20, openbao 2.4.1 -dev); a token it does not know
403 `permission denied`. A known token's answers follow from the policies it holds, the policy check first:
- `default` (OpenBao's default policy) and the current `writer` (`store_policies`, #1532) grant `GET
  auth/token/lookup-self` (200 `{"data": {...}}`); `writer-pre-1532` (the writer policy before #1532) and `proxy` do
  not. A token holding a policy name with no policy behind it gets nothing from it.
- `writer` and `writer-pre-1532` grant, under the mount the policy was written for (`policy_mount`), a metadata read (404
  `{"errors": []}` for a path never written, else 200 with `current_version` and `versions`) and a write (`POST
  <mount>/data/<path>`, 200 with the new version); never a value read (403), a delete or a list.
- `proxy` grants a value read under its mount, nothing else this stand-in answers.
- A path no held policy covers is 403, whether or not its mount exists; a covered path on a mount that does not exist
  (`mounts`) is 404 `no handler for route` (#1532 probe).
It is a policy stand-in only for those answers: it holds sets by path and version, nothing more.

- `ScriptedOpenBao(token=, mount=, policies=, policy_mount=, mounts=)`: the transport (sync and async); hand it to
  `serving(..., openbao_transport=...)` or to `OpenBaoSecrets(transport=...)`. `mount` is the KV mount it serves;
  `policies` the token's (default: the current writer alone, minted without the default policy as the API's is);
  `policy_mount` the mount those policies were written for (default `mount`); `mounts` the KV mounts that exist
  (default `{mount}`).
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
from collections.abc import Awaitable, Callable, Iterable, Iterator
from typing import Any

import httpx

WRITER_TOKEN = "api-writer-token-1470"
KV_MOUNT = "secret"
_SEALED = {"errors": ["Vault is sealed"]}
_DENIED = {"errors": ["permission denied"]}
LOOKUP_SELF = "auth/token/lookup-self"
#: The policies a token may hold here (see the module docstring).
POLICIES = frozenset({"default", "writer", "writer-pre-1532", "proxy"})
_WRITERS = frozenset({"writer", "writer-pre-1532"})


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
    def __init__(self, *, token: str = WRITER_TOKEN, mount: str = KV_MOUNT, policies: Iterable[str] = ("writer",),
                 policy_mount: str | None = None, mounts: Iterable[str] | None = None) -> None:
        self.token, self.mount = token, mount
        self.policies = frozenset(policies)
        if not self.policies <= POLICIES:
            raise ValueError(f"unknown policies {sorted(self.policies - POLICIES)}")
        self.policy_mount = policy_mount if policy_mount is not None else mount
        self.mounts = frozenset(mounts) if mounts is not None else frozenset({mount})
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
        if path == LOOKUP_SELF and request.method == "GET":
            if self.policies & {"default", "writer"}:
                return httpx.Response(200, json={"data": {"id": "s.scripted", "policies": sorted(self.policies)}}), None
            return httpx.Response(403, json=_DENIED), None
        mount, _, below = path.partition("/")
        kind, _, rest = below.partition("/")
        if request.method in ("DELETE", "LIST") or request.url.params.get("list"):  # no policy here grants either
            return httpx.Response(403, json=_DENIED), None
        writes = bool(self.policies & _WRITERS) and kind in ("metadata", "data")
        reads = "proxy" in self.policies and kind == "data" and request.method == "GET"
        if mount != self.policy_mount or not rest or not (writes or reads):
            return httpx.Response(403, json=_DENIED), None  # the policy check comes before the mount's
        if mount not in self.mounts:
            return httpx.Response(404, json={"errors": [f"no handler for route \"{path}\". route entry not found."]}), None
        if kind == "metadata" and request.method == "GET":
            versions = self._sets.get(rest)
            if not versions:
                return httpx.Response(404, json={"errors": []}), None
            listing = {str(n): {"created_time": "2026-11-14T16:37:32Z", "deletion_time": "", "destroyed": False}
                       for n in range(1, len(versions) + 1)}
            return httpx.Response(200, json={"data": {"current_version": len(versions), "versions": listing}}), None
        if kind == "data" and request.method == "GET":
            if not reads:
                self.value_reads.append(rest)  # the writer policy grants no read of a value
                return httpx.Response(403, json={"errors": ["1 error occurred:\n\t* permission denied\n\n"]}), None
            if not self._sets.get(rest):
                return httpx.Response(404, json={"errors": []}), None
            return httpx.Response(200, json={"data": {"data": self._sets[rest][-1]}}), None
        if kind == "data" and request.method in ("POST", "PUT") and writes:
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
