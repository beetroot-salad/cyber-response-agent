"""#1470: a scripted OpenBao at the HTTP edge, for tests that drive the real `OpenBaoSecrets` (and the API's start check)
without a server — NO test functions.

It answers as OpenBao 2.4.1 was observed to (2026-11-14 and #1532's probes, a dev server):
`GET /v1/sys/seal-status` unauthenticated `{"initialized", "sealed", ...}`; a sealed server answers every other path 503
`{"errors": ["Vault is sealed"]}` whatever the token (observed, design C20, openbao 2.4.1 -dev); a token it does not know
403 `permission denied`. A known token's answers follow from the text of the policies it holds, checked as OpenBao
checks them (#1532 probes): the policy first (each request needs the capability its method maps to on a path a policy
pattern grants: GET read, POST/PUT create or update, DELETE delete, LIST list), then the mount (a KV path on a mount that
does not exist is 404 `no handler for route`), then the answer: a metadata read 404 `{"errors": []}` for a path never
written, else 200 with `current_version` and `versions`; a write 200 with the new version; a value read the set. The
policies are `store_policies`' own `writer` and `proxy` (for `policy_mount`), `writer-pre-1532` (the writer before
#1532), and `default` (OpenBao's default policy, as far as it matters here: lookup-self); any other name has nothing
behind it and grants nothing.
It is a policy stand-in only for those answers: it holds sets by path and version, nothing more.

- `ScriptedOpenBao(token=, mount=, policies=, policy_mount=, mounts=)`: the transport (sync and async); hand it to
  `serving(..., openbao_transport=...)` or to `OpenBaoSecrets(transport=...)`. `mount` is the KV mount it serves;
  `policies` the token's names (default: the current writer alone, minted without the default policy as the API's
  is);
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
import re
import threading
from collections.abc import Awaitable, Callable, Iterable, Iterator
from typing import Any

import httpx
from defender.credential_proxy._openbao import LOOKUP_SELF as LOOKUP_SELF
from defender.credential_proxy._openbao import store_policies

WRITER_TOKEN = "api-writer-token-1470"
KV_MOUNT = "secret"
_SEALED = {"errors": ["Vault is sealed"]}
_DENIED = {"errors": ["permission denied"]}
#: The writer policy as `store_policies` wrote it before #1532: no lookup-self.
WRITER_BEFORE_1532 = ('path "{kv}/data/*" {{\n  capabilities = ["create", "update"]\n}}\n'
                      'path "{kv}/metadata/*" {{\n  capabilities = ["read"]\n}}\n')
_DEFAULT_POLICY = f'path "{LOOKUP_SELF}" {{\n  capabilities = ["read"]\n}}\n'
_GRANT = re.compile(r'path "([^"]+)" \{\s*capabilities = \[([^\]]*)\]\s*\}')
_NEEDS = {"GET": {"read"}, "POST": {"create", "update"}, "PUT": {"create", "update"}, "DELETE": {"delete"},
          "LIST": {"list"}}


def policy_text(name: str, *, kv_mount: str) -> str:
    """The text behind policy `name` for a policy written for `kv_mount`; empty for a name with nothing behind it."""
    written = store_policies(kv_mount=kv_mount)
    return {"writer": written["writer"], "proxy": written["proxy"], "default": _DEFAULT_POLICY,
            "writer-pre-1532": WRITER_BEFORE_1532.format(kv=kv_mount)}.get(name, "")


def _grants(text: str) -> list[tuple[str, frozenset[str]]]:
    return [(path, frozenset(c.strip().strip('"') for c in caps.split(",") if c.strip()))
            for path, caps in _GRANT.findall(text)]


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
        self.policy_mount = policy_mount if policy_mount is not None else mount
        self.mounts = frozenset(mounts) if mounts is not None else frozenset({mount})
        self._granted = [g for name in sorted(self.policies) for g in _grants(policy_text(name, kv_mount=self.policy_mount))]
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

    def _allows(self, method: str, path: str) -> bool:
        """Does a held policy grant `method` on `path` (a pattern ending in `*` grants the paths it starts)?"""
        needs = _NEEDS.get(method, set())
        return any(caps & needs and (path == pattern or pattern.endswith("*") and path.startswith(pattern[:-1]))
                   for pattern, caps in self._granted)

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
        mount, _, below = path.partition("/")
        kind, _, rest = below.partition("/")
        method = "LIST" if request.url.params.get("list") else request.method
        if kind == "data" and method == "GET":
            self.value_reads.append(rest)  # every read of a value, granted or not: the writer must never make one
        if not self._allows(method, path):
            return httpx.Response(403, json=_DENIED), None  # the policy check comes before the mount's
        if path == LOOKUP_SELF:
            return httpx.Response(200, json={"data": {"id": "s.scripted", "policies": sorted(self.policies)}}), None
        if mount not in self.mounts:
            return httpx.Response(404, json={"errors": [f"no handler for route \"{path}\". route entry not found."]}), None
        if kind == "metadata" and method == "GET":
            versions = self._sets.get(rest)
            if not versions:
                return httpx.Response(404, json={"errors": []}), None
            listing = {str(n): {"created_time": "2026-11-14T16:37:32Z", "deletion_time": "", "destroyed": False}
                       for n in range(1, len(versions) + 1)}
            return httpx.Response(200, json={"data": {"current_version": len(versions), "versions": listing}}), None
        if kind == "data" and method == "GET":
            if not self._sets.get(rest):
                return httpx.Response(404, json={"errors": []}), None
            return httpx.Response(200, json={"data": {"data": self._sets[rest][-1]}}), None
        if kind == "data" and method in ("POST", "PUT"):
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
