"""#1363 O4, B3, B4: the proxy-side census of fault origins. `handle`, the proxy's one pipeline, is
driven over rows (one cause each, on a published tenant, real ports where a cause needs them); the
raise sites of every module under `credential_proxy/` are read from source and tied to rows by the
text of their detail. The label is the final record's `origin` (None: the system's own answer);
the proxy's refusals carry it as `.origin` on the exception, which is this contract's name for it."""
from __future__ import annotations

import ast
import base64
import contextlib
import json
import re
import socket
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import anyio
import httpx

from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import proxy

BASE = T.BASE_PATH
ORIGINS = ("system", "request", "setup", "access")
#: Tenants with an `exports/` folder holding nothing published, and with no folder at all.
GHOST = "0b8f6a52-1163-4c1e-9d0e-6f2b3a4c5d71"
NO_EXPORTS = "0b8f6a52-1163-4c1e-9d0e-6f2b3a4c5d72"
BASIC_SYSTEM = "basic-sys"
BROKEN_SYSTEM = "wiki"
OVERHEAD_SEC = 0.3


@dataclass
class Req:
    """What is handed to `handle`: the raw request, the Authorization header, and the ports and
    deps options the cause needs in place of the rig's."""

    raw: Any
    authorization: str | None
    store: Any = None
    verifier: Any = None
    audit: Any = None
    deps_kw: dict[str, Any] = field(default_factory=dict)
    arrived: float | None = None


@dataclass(frozen=True)
class Row:
    """One cause and the label its answer must carry: `request`, `setup`, `access`, or None (the
    system's own answer)."""

    id: str
    label: str | None
    make: Callable[[T.Rig], Req]
    #: The cause is a fault a port raised without a label: only the catch-all can read it `access`.
    unlabelled: bool = False


@dataclass
class Observed:
    row: str
    final: Any
    arrived: list[BaseException]
    details: list[str]


# --- driving `handle` ----------------------------------------------------------------------

def _watching() -> type:
    from defender.credential_proxy._app import _Proxy

    class Watching(_Proxy):
        """The real pipeline, remembering each exception that reaches `handle` from `_proxied`."""

        def __init__(self, deps: Any) -> None:
            super().__init__(deps)
            self.arrived: list[BaseException] = []

        def _proxied(self, *args: Any, **kw: Any) -> Any:
            try:
                return super()._proxied(*args, **kw)
            except BaseException as e:
                self.arrived.append(e)
                raise

    return Watching


def handle(deps: Any, authorization: str | None, raw: Any, *, arrived: float | None = None,
           via: Any = None) -> tuple[Any, list[BaseException]]:
    """The final record `handle` returns for `raw`, run on a worker thread of an event loop as the
    route runs it, and the exceptions that reached `handle`."""
    served = via if via is not None else _watching()(deps)

    async def main() -> Any:
        async def send(_chunk: bytes) -> None:
            return None

        return await anyio.to_thread.run_sync(lambda: served.handle(authorization, raw, send, arrived))

    return anyio.run(main), served.arrived


def observe(r: T.Rig, row: Row) -> Observed:
    req = row.make(r)
    deps = T.deps(r.data_root, req.store if req.store is not None else r.store,
                  verifier=req.verifier if req.verifier is not None else r.verifier,
                  audit=req.audit if req.audit is not None else r.audit, **req.deps_kw)
    final, arrived = handle(deps, req.authorization, req.raw, arrived=req.arrived)
    details = [final.detail or ""] + [str(getattr(e, "detail", e)) for e in arrived]
    return Observed(row.id, final, arrived, details)


def problems(row: Row, seen: Observed) -> list[str]:
    """What is wrong with `seen` against `row`: the wire label, and that every exception that
    reached `handle` already carried the cause's label (not left to the catch-all)."""
    label = T.label_of(seen.final)
    found = [] if label == row.label else [f"{row.id}: the final record's label is {label!r}, not {row.label!r}"]
    for e in [] if row.unlabelled else seen.arrived:
        carried = getattr(e, "origin", None)
        if carried != (row.label or "system") and not (row.label is None and getattr(e, "system_side", False)):
            found.append(f"{row.id}: {type(e).__name__} reached handle carrying origin {carried!r}")
    return found


# --- requests and tokens -------------------------------------------------------------------

def body(r: T.Rig, **over: Any) -> bytes:
    doc = {"system": "identity", "method": "GET", "url": f"{r.up.url}{BASE}/users/x", "headers": {},
           "body": None} | over
    return json.dumps(doc).encode("ascii")


def req(r: T.Rig, tok: str | None = None, **over: Any) -> Req:
    return Req(body(r, **over), f"Bearer {r.tok() if tok is None else tok}")


def under(r: T.Rig, tail: str) -> str:
    return f"{r.up.url}{BASE}{tail}"


def hand_token(doc: Any, signature: str = "vault:v1:sig") -> str:
    """A token in the wire form whose claims are `doc` as given, signed by nobody: only the
    shape checks that come before the signature's can see it."""
    payload = base64.urlsafe_b64encode(json.dumps(doc).encode()).decode().rstrip("=")
    return f"{payload}.{signature}"


def good_claims(r: T.Rig) -> dict[str, Any]:
    return {"tenant": r.t.tenant_id, "investigation": T.RUN_ID, "grant": [["identity", "r"]], "exp": 4102444800}


class Raises:
    """A port (store or verifier) that fails with `error`, whatever it is."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def read(self, tenant_id: str, system: str) -> Any:
        raise self.error

    def verify(self, payload: bytes, signature: str, *, tenant_id: str | None = None) -> bool:
        raise self.error


def openbao(handler: Callable[[httpx.Request], httpx.Response] | None = None, *,
            unreachable: bool = False) -> httpx.MockTransport:
    """An OpenBao that answers every call with `handler`, or cannot be reached."""
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    return httpx.MockTransport(down if unreachable else handler)


def answering(status: int, doc: Any = None) -> httpx.MockTransport:
    return openbao(lambda _r: httpx.Response(status, json=doc if doc is not None else {}))


def openbao_store(transport: httpx.MockTransport) -> Any:
    return proxy().OpenBaoStore(addr="http://openbao.invalid", token="t", mount="secret", transport=transport)


def openbao_verifier(transport: httpx.MockTransport) -> Any:
    return proxy().TransitVerifier(addr="http://openbao.invalid", token="t", transport=transport)


def stored(data: Any, version: Any = 1) -> httpx.MockTransport:
    """An OpenBao whose KV read answers a set with `data` as its body."""
    return answering(200, {"data": {"data": data, "metadata": {"version": version}}})


# --- the rows ------------------------------------------------------------------------------

def bearer_rows() -> list[Row]:  # noqa: C901, PLR0915 — one row per cause
    """Causes on the default rig: a bearer key on `identity`, a write route `POST /tickets`, a
    basic-auth `BASIC_SYSTEM`, an unparsable declaration at `BROKEN_SYSTEM`, a ghost tenant."""
    from defender.credential_proxy._app import _Unread

    def grant_rw(r: T.Rig) -> str:
        return r.tok({("identity", "rw")})

    def set_for(value: Any, system: str = "identity") -> Callable[[T.Rig], Req]:
        def make(r: T.Rig) -> Req:
            out = req(r, **({} if system == "identity" else {"system": system, "url": under(r, "/x")}),
                      tok=r.tok({(system, "r")}))
            out.store = H.FakeStore({(r.t.tenant_id, system): value} if value is not None else {})
            return out
        return make

    def answered(status: int) -> Callable[[T.Rig], Req]:
        def make(r: T.Rig) -> Req:
            r.up.replies[f"{BASE}/users/x"] = (status, {}, b"{}")
            return req(r)
        return make

    def port(error: BaseException, which: str) -> Callable[[T.Rig], Req]:
        def make(r: T.Rig) -> Req:
            out = req(r)
            setattr(out, which, Raises(error))
            return out
        return make

    def hand(doc_of: Callable[[T.Rig], Any], **kw: str) -> Callable[[T.Rig], Req]:
        return lambda r: Req(body(r), f"Bearer {hand_token(doc_of(r), **kw)}")

    def claims(**over: Any) -> Callable[[T.Rig], Any]:
        return lambda r: good_claims(r) | over

    def raw(value: Any) -> Callable[[T.Rig], Req]:
        return lambda r: Req(value, f"Bearer {r.tok()}")

    def late(r: T.Rig) -> Req:
        out = req(r)
        out.arrived = time.monotonic() - 1000
        return out

    def forged(tenant: str) -> Callable[[T.Rig], Req]:
        return lambda r: Req(body(r), f"Bearer {T.token(tenant, T.GRANT_R, signer=r.signer)}")

    def write(path: str, grant: str) -> Callable[[T.Rig], Req]:
        return lambda r: req(r, tok=r.tok({("identity", grant)}), method="POST", url=under(r, path), body="{}")

    def other_system(name: str) -> Callable[[T.Rig], Req]:
        return lambda r: req(r, tok=r.tok({(name, "r")}), system=name, url=under(r, "/x"))

    def url(tail: str) -> Callable[[T.Rig], Req]:
        return lambda r: req(r, url=under(r, tail))

    return [
        # request: this call is outside what the token and declaration allow, or the caller cut it
        Row("not-a-system-name", "request", lambda r: req(r, system="Not A System")),
        Row("token-does-not-grant-the-system", "request", lambda r: req(r, tok=r.tok({("cmdb", "r")}))),
        Row("url-whitespace", "request", url("/a b")),
        Row("url-does-not-parse", "request", lambda r: req(r, url="http://127.0.0.1:99999/x")),
        Row("url-login-part", "request", lambda r: req(r, url=f"http://u:p@{r.up.url.removeprefix('http://')}{BASE}/x")),
        Row("url-fragment", "request", url("/x#f")),
        Row("url-other-host", "request", lambda r: req(r, url=f"http://127.0.0.1:1{BASE}/x")),
        Row("url-dot-segment", "request", url("/a/../b")),
        Row("url-path-parameter", "request", url("/a;b")),
        Row("url-not-under-the-base", "request", lambda r: req(r, url=f"{r.up.url}/elsewhere")),
        Row("url-encoded-separator", "request", url("/a%2Fb")),
        Row("route-not-declared", "request", write("/nope", "rw")),
        Row("write-without-a-write-grant", "request", write("/tickets", "r")),
        Row("method-not-upper-case", "request", lambda r: req(r, method="get")),
        Row("request-too-large", "request", lambda r: Req(_Unread.TOO_LARGE, f"Bearer {r.tok()}")),
        Row("request-did-not-arrive-in-time", "request", lambda r: Req(_Unread.TOO_SLOW, f"Bearer {r.tok()}")),
        Row("caller-left-before-its-request-arrived", "request", lambda r: Req(_Unread.PEER_LEFT, f"Bearer {r.tok()}")),
        # setup: ours, for one system
        Row("no-credential-set-stored", "setup", set_for(None)),
        Row("no-declaration-for-a-granted-system", "setup", other_system("inventory")),  # no such folder in the export
        Row("declaration-not-valid", "setup", other_system(BROKEN_SYSTEM)),
        Row("credential-kind-does-not-fit", "setup", set_for(T.oauth_set())),
        Row("credential-field-missing", "setup", set_for(T.custom_set({"other": "x"}))),
        Row("credential-field-holds-a-control-character", "setup", set_for(T.custom_set({"api_key": "a\x01b"}))),
        Row("credential-field-not-ascii", "setup", set_for(T.custom_set({"api_key": "é"}))),
        Row("basic-username-holds-a-colon", "setup", set_for(T.basic_set(user="a:b"), BASIC_SYSTEM)),
        Row("store-answers-without-a-data-object", "setup",
            lambda r: _with(req(r), store=openbao_store(answering(200, {"data": None})))),
        Row("stored-set-not-in-the-stores-shape", "setup",
            lambda r: _with(req(r), store=openbao_store(stored({"kind": "static"})))),
        Row("stored-set-fields-not-text", "setup",
            lambda r: _with(req(r), store=openbao_store(stored({"kind": "static", "fields": {"api_key": 5}})))),
        Row("stored-set-version-not-a-whole-number", "setup",
            lambda r: _with(req(r), store=openbao_store(stored({"kind": "static", "fields": {"api_key": "k"}}, True)))),
        Row("deadline-spent-before-the-system-is-called", "setup", late),
        # access: ours, for the whole process
        Row("no-bearer-token", "access", lambda r: Req(body(r), None)),
        Row("authorization-is-not-bearer", "access", lambda r: Req(body(r), "Basic abc")),
        Row("signature-not-valid-for-the-tenant", "access",
            lambda r: req(r, tok=T.token(r.t.tenant_id, T.GRANT_R, signer=H.FakeSigner("other")))),
        Row("token-expired", "access", lambda r: req(r, tok=r.tok(expires_in=timedelta(minutes=-1)))),
        Row("token-too-long", "access", lambda r: Req(body(r), "Bearer " + "a" * 16385)),
        Row("token-not-in-the-wire-form", "access", lambda r: Req(body(r), "Bearer nodot")),
        Row("token-claims-do-not-decode", "access", lambda r: Req(body(r), "Bearer bm90IGpzb24.sig")),
        Row("token-claims-not-an-object", "access", hand(lambda _r: [1])),
        Row("token-claims-wrong-keys", "access", hand(lambda _r: {"tenant": "x"})),
        Row("token-names-no-tenant-id", "access", hand(claims(tenant="nope"))),
        Row("token-names-no-investigation", "access", hand(claims(investigation=""))),
        Row("token-expiry-not-whole-seconds", "access", hand(claims(exp="soon"))),
        Row("token-grant-not-a-list", "access", hand(claims(grant={}))),
        Row("token-grant-entry-malformed", "access", hand(claims(grant=[["identity"]]))),
        Row("token-grants-a-bad-system-name", "access", hand(claims(grant=[["Bad Name", "r"]]))),
        Row("token-grants-a-bad-mode", "access", hand(claims(grant=[["identity", "x"]]))),
        Row("token-grants-a-system-twice", "access", hand(claims(grant=[["identity", "r"], ["identity", "r"]]))),
        Row("tenant-has-no-exports-folder", "access", forged(NO_EXPORTS)),
        Row("tenant-has-nothing-published", "access", forged(GHOST)),
        Row("request-body-not-json", "access", raw(b"nope")),
        Row("request-not-an-object-of-the-right-keys", "access", raw(b"[]")),
        Row("request-text-fields-not-text", "access", lambda r: req(r, system=5)),
        Row("request-headers-not-an-object", "access", lambda r: req(r, headers=[1])),
        Row("request-header-name-not-a-header", "access", lambda r: req(r, headers={"bad name": "x"})),
        Row("request-body-not-text", "access", lambda r: req(r, body=5)),
        Row("request-timeout-not-a-positive-number", "access", lambda r: req(r, timeout_sec=-1)),
        Row("request-text-not-valid-unicode", "access", lambda r: req(r, system="\ud800")),
        Row("request-carries-its-own-credential-header", "request", lambda r: req(r, headers={"Authorization": "Bearer x"})),
        Row("audit-cannot-be-written", "access", lambda r: _with(req(r), audit=H.FailingAudit())),
        # a fault a port raises without a label reads access, whatever its kind
        Row("verifier-raises-a-plain-transport-fault", "access", port(_plain("transport"), "verifier"), unlabelled=True),
        Row("verifier-raises-a-plain-config-fault", "access", port(_plain("config"), "verifier"), unlabelled=True),
        Row("verifier-raises-something-unforeseen", "access", port(RuntimeError("unforeseen"), "verifier"), unlabelled=True),
        Row("store-raises-a-plain-transport-fault", "access", port(_plain("transport"), "store"), unlabelled=True),
        Row("store-raises-a-plain-config-fault", "access", port(_plain("config"), "store"), unlabelled=True),
        Row("store-raises-something-unforeseen", "access", port(RuntimeError("unforeseen"), "store"), unlabelled=True),
        # OpenBao unreachable or refusing the proxy: the whole process
        Row("verify-openbao-unreachable", "access", lambda r: _with(req(r), verifier=openbao_verifier(openbao(unreachable=True)))),
        Row("verify-openbao-failing", "access", lambda r: _with(req(r), verifier=openbao_verifier(answering(503)))),
        Row("verify-openbao-refuses-the-proxy", "access", lambda r: _with(req(r), verifier=openbao_verifier(answering(403)))),
        Row("verify-openbao-answers-without-a-data-object", "access", lambda r: _with(req(r), verifier=openbao_verifier(answering(200, {"data": None})))),
        Row("verify-openbao-answers-without-a-verdict", "access", lambda r: _with(req(r), verifier=openbao_verifier(answering(200, {"data": {"valid": "yes"}})))),
        Row("store-openbao-unreachable", "access", lambda r: _with(req(r), store=openbao_store(openbao(unreachable=True)))),
        Row("store-openbao-failing", "access", lambda r: _with(req(r), store=openbao_store(answering(503)))),
        Row("store-openbao-refuses-the-proxy", "access", lambda r: _with(req(r), store=openbao_store(answering(403)))),
        # the system's own answer: no label
        Row("system-answers-200", None, answered(200)),
        Row("system-answers-404", None, answered(404)),
        Row("system-answers-401", None, answered(401)),
        Row("system-answers-500", None, answered(500)),
    ]


def _with(out: Req, **ports: Any) -> Req:
    for name, value in ports.items():
        setattr(out, name, value)
    return out


def _plain(kind: str) -> BaseException:
    from defender.kit.faults import ConfigFault, TransportFault

    return (ConfigFault if kind == "config" else TransportFault)("a port failed")


def oauth_rows(aux: H.Upstream) -> list[Row]:
    """Causes in the token exchange of a system on `oauth-client-credentials`, the endpoint being `aux`."""
    def exchange(reply: H.Reply | None) -> Callable[[T.Rig], Req]:
        def make(r: T.Rig) -> Req:
            if reply is None:
                aux.replies["/token"] = H.token_endpoint([])
            else:
                aux.replies["/token"] = reply
            return req(r)
        return make

    json_ = {"Content-Type": "application/json"}
    return [
        Row("token-endpoint-failing", "setup", exchange((500, {}, b"{}"))),
        Row("token-endpoint-refuses-the-exchange", "setup", exchange((400, {}, b"{}"))),
        Row("token-endpoint-reply-withheld", "setup", exchange((200, json_, b"x" * 70000))),
        Row("token-endpoint-answers-without-json", "setup", exchange((200, {}, b"<html>"))),
        Row("token-endpoint-issues-no-access-token", "setup", exchange((200, json_, b"{}"))),
        Row("token-endpoint-issues-a-token-that-is-not-bearer", "setup",
            exchange((200, json_, b'{"access_token": "a", "token_type": "mac"}'))),
        Row("token-exchanged-and-the-system-answers", None, exchange(None)),
    ]


def dead_endpoint_rows() -> list[Row]:
    return [Row("token-endpoint-unreachable", "setup", lambda r: req(r))]


def slow_exchange_rows() -> list[Row]:
    return [Row("token-exchange-cut-by-the-deadline", "setup", lambda r: _with(req(r, timeout_sec=1), deps_kw={"proxy_overhead_sec": OVERHEAD_SEC}))]


def slow_system_rows(base: str) -> list[Row]:
    return [Row("system-leg-cut-by-the-deadline", None, lambda r: _with(
        req(r, timeout_sec=1, url=f"{base}{BASE}/users/x"), deps_kw={"proxy_overhead_sec": OVERHEAD_SEC}))]


def dead_system_rows(base: str) -> list[Row]:
    return [Row("system-unreachable", None, lambda r: req(r, url=f"{base}{BASE}/users/x"))]


def gate_wait(r: T.Rig, aux: H.Upstream) -> Observed:
    """A request queued behind another's slow token exchange, answered by its own deadline."""
    holding, release = threading.Event(), threading.Event()

    def slow(_seen: Any) -> H.Reply:
        holding.set()
        release.wait(5)
        return H.token_endpoint([])(_seen)

    aux.replies["/token"] = slow
    served = _watching()(T.deps(r.data_root, r.store, verifier=r.verifier, audit=r.audit,
                                proxy_overhead_sec=OVERHEAD_SEC))
    first = threading.Thread(target=lambda: handle(None, f"Bearer {r.tok()}", body(r, timeout_sec=5), via=served))
    first.start()
    try:
        assert holding.wait(10), "the first request never reached the token endpoint"
        final, _ = handle(None, f"Bearer {r.tok()}", body(r, timeout_sec=0.3), via=served)
    finally:
        release.set()
        first.join(10)
    return Observed("request-waits-out-another-requests-exchange", final, served.arrived,
                    [final.detail or ""] + [str(getattr(e, "detail", e)) for e in served.arrived])


GATE_ROW = Row("request-waits-out-another-requests-exchange", "setup", lambda _r: Req(b"", None))


@contextlib.contextmanager
def trickling(body_: bytes = b"{}", gap: float = 0.6, pieces: int = 10) -> Iterator[str]:
    """A loopback HTTP server answering 200 with `body_` one header line per `gap` seconds: no
    single wait is long, the whole reply outlasts any deadline used here."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()

    def one(conn: socket.socket) -> None:
        with conn:
            try:
                conn.recv(65536)
                parts = [b"HTTP/1.1 200 OK\r\n"] + [b"X-Slow: %d\r\n" % i for i in range(pieces)]
                parts.append(b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(body_), body_))
                for part in parts:
                    if stop.wait(gap):
                        return
                    conn.sendall(part)
            except OSError:
                return

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=one, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.getsockname()[1]}"
    finally:
        stop.set()
        srv.close()


# --- the census: raise sites read from source ------------------------------------------------

FAULT_CALLEES = frozenset({"Refused", "ConfigFault", "TransportFault", "ConfinementFault",
                           "UpstreamFault", "openbao_fault"})


@dataclass(frozen=True)
class Site:
    file: str
    qualname: str
    line: int
    text: str
    pattern: re.Pattern[str] | None


def _template(node: ast.AST) -> tuple[str, re.Pattern[str]] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, re.compile(re.escape(node.value), re.DOTALL)
    if isinstance(node, ast.JoinedStr):
        text = "".join(p.value if isinstance(p, ast.Constant) else "{}" for p in node.values)
        regex = "".join(re.escape(p.value) if isinstance(p, ast.Constant) else ".*" for p in node.values)
        return text, re.compile(regex, re.DOTALL)
    return None


def sites_in(source: str, file: str) -> list[Site]:
    """Every construction of a fault inside a function of `source`: the place a cause is named."""
    found: list[Site] = []
    stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def _scope(self, node: Any) -> None:
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_ClassDef = visit_FunctionDef = visit_AsyncFunctionDef = _scope  # noqa: N815 — ast's dispatch names

        def visit_Call(self, node: ast.Call) -> None:
            callee = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
            if callee in FAULT_CALLEES and stack:
                message = next((t for a in node.args if (t := _template(a)) is not None), None)
                found.append(Site(file, ".".join(stack), node.lineno, message[0] if message else "",
                                  message[1] if message else None))
            self.generic_visit(node)

    Visitor().visit(ast.parse(source))
    return found


def proxy_sites() -> list[Site]:
    """The sites of every module under `credential_proxy/`."""
    folder = Path(proxy().__file__).parent
    return [s for path in sorted(folder.glob("*.py")) for s in sites_in(path.read_text(encoding="utf-8"), path.name)]


#: Not on a proxied request's path: start-up, the launcher's signing and minting, the API's
#: secret writer, key and mount name checks that run before a request can reach them.
OFF_THE_PATH = {
    ("__main__.py", "operator_config"), ("_app.py", "ProxyDeps.__post_init__"), ("_app.py", "_openbao_token"),
    ("_app.py", "create_app_from_config"), ("_tokens.py", "mint_request_token"),
    ("_openbao.py", "_check_tenant"), ("_openbao.py", "_check_name"), ("_openbao.py", "_secret_path"),
    ("_openbao.py", "_OpenBao.__init__"), ("_openbao.py", "OpenBaoSecrets.put_credentials"),
}
#: Reached only outside a proxied request, or not reachable at all because an earlier check
#: refuses the same cause (each is judged by the unit cases beside the census where it can be).
UNREACHED = (
    ("_app.py", "_Proxy._current_export", "the request token names no tenant id"),
    ("_app.py", "_Proxy._current_export", "tenant {}: {}"),
    ("_credentials.py", "CredentialSet.__post_init__", "a credential set's kind"),
    ("_openbao.py", "_OpenBao._call", "OpenBao at {} is unreachable"),
)


def off_the_path(site: Site) -> bool:
    return (site.file == "_launcher.py" or (site.file, site.qualname) in OFF_THE_PATH
            or any((site.file, site.qualname) == (f, q) and site.text.startswith(t) for f, q, t in UNREACHED))


def untied(sites: Sequence[Site], seen: Sequence[Observed]) -> list[str]:
    """The sites on the path that no row's detail matches, and those with no message to match."""
    details = [d for o in seen for d in o.details]
    out = []
    for s in sites:
        if off_the_path(s):
            continue
        if s.pattern is None:
            out.append(f"{s.file} {s.qualname}:{s.line}: no message to tie to a row")
        elif not any(s.pattern.fullmatch(d) for d in details):
            out.append(f"{s.file} {s.qualname}:{s.line}: no row's detail matches {s.text!r}")
    return out
