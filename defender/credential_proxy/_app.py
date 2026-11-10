"""The credential proxy (#1163): one multi-tenant program between adapters and their systems.

`POST /v1/request` with `Authorization: Bearer <request token>` and the JSON body
`{system, method, url, headers, body}` (`headers` a name -> value object, `body` text or null).
The answer is always HTTP 200 in the reply format of `defender.kit.proxy_client` (#1412): the
upstream's body as body frames, passed on as it arrives, then one final record `{status, headers,
fault, detail, system_side, sent, body_whole, reader_fault}`. `status` is the upstream's status (null when nothing was
sent), `headers` its headers, `body_whole` whether the frames carried its whole body; `fault` is
null or the fault class the adapter raises (`ConfigFault`, `ConfinementFault`, `UpstreamFault`,
`TransportFault`); `detail` says why and never holds a secret value; `system_side` marks a status-less failure of the system's own call (#1404); `sent` is false only when the proxy never began the system's call or never connected to it, so the request cannot have reached it (#1374); `reader_fault` that the run itself cut the reply. Nothing is an answer until
the final record: the run discards the frames unless it says they are whole. The proxy does not
search or alter a reply for credentials; an upstream's echo reaches the run.

For each request (design "Proxy", in order, nothing sent or read before its check passes):
1. verify the token with the key of the tenant it names, and its expiry (O1, O8, A11); a tenant
   id that is not a canonical tenant UUID is refused before any OpenBao or exports path is built;
2. the system must be a system name and in the token's grant;
3. read the system's declaration from the export the tenant's `current` names, under
   `<data root>/<tenant id>/exports/` (A26), no link followed: never the clone's working tree,
   never another export (O2, P-2, H10);
4. the URL must be under the one declared base, the route a read or a granted write (O2, O3);
5. read the credential set; it must fit the declared scheme (A4); exchange an OAuth token if
   none is held (A8, A12);
6. send, following no redirect, passing the body on as it arrives, capped and never inflated
   (O7, #1383, #1412);
7. audit, before the final record: if it cannot be written the answer is withheld (A13). Withheld
   means the run is told to discard it: body frames have already gone, so this holds for the
   proxy's own client, not against something else reading the raw reply with the token (owner,
   #1412).

A run is waited on only so long: a body frame it has not taken within `CALLER_GRACE_SEC`, or a
departure, ends the read of the system (`_ReaderLeft`), whatever is left of the deadline."""
from __future__ import annotations

import dataclasses
import enum
import json
import logging
import math
import re
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import anyio
import httpx
from fastapi import FastAPI, Request
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect
from starlette.responses import Response
from starlette.types import Receive, Scope
from starlette.types import Send as AsgiSend

from defender import _clock, _io, tenancy
from defender.kit.proxy_client import PROXY_PATH, REPLY_CONTENT_TYPE, FinalRecord, encode_body, encode_final
from defender.configuration.issuer import DEPLOYMENT_ISSUER
from defender.kit.access import (
    CALLER_GRACE_SEC, HEADER, OAUTH_CLIENT_CREDENTIALS, PROXY_OVERHEAD_SEC, AccessDeclaration, Auth)
from defender.kit.faults import (
    ORIGIN_ACCESS,
    ORIGIN_REQUEST,
    ORIGIN_SETUP,
    is_proxy_label,
    AdapterFault,
    ConfigFault,
    TransportFault,
)
from defender.kit.tls import trust_of_ca
from defender.kit.verbs import is_system_name
from defender.records.formats import TenantRefused
from defender.credential_proxy._audit import AUDIT_KEYS, AuditSink, FileAuditSink
from defender.credential_proxy._credentials import (
    AccessTokens,
    CredentialSet,
    check_fit,
    static_headers,
)
from defender.credential_proxy._deadline import Deadline, answering
from defender.credential_proxy._openbao import OpenBaoStore, TransitVerifier
from defender.credential_proxy._refusal import CONFIG, TRANSPORT, UPSTREAM, Refused
from defender.credential_proxy._reply import Sink, StreamedReply, public_trust, stream_reply
from defender.credential_proxy._scope import Target, check_route, locate
from defender.credential_proxy._tokens import Claims, TokenVerifier, split_token

_logger = logging.getLogger(__name__)


class _ReaderLeft(Exception):
    """The run stopped taking the reply, or went away: why ends the sentence "... (`why`)"."""


#: The default cap on an upstream response body (decoded), in bytes; over it is `UpstreamFault`.
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
#: The most time, in seconds, a request may ask for its upstream call (r7 A21), and what it gets
#: when it asks none; over it is `TransportFault`.
DEFAULT_UPSTREAM_TIMEOUT_SEC = 30.0
#: How long a request may take to arrive in full (#1428 O2). Past it the proxy stops waiting and
#: closes the connection. An operator who raises the upstream timeout raises it too: it is never
#: shorter than the request's own longest deadline (see `create_app`).
REQUEST_BODY_SEC = 60.0
#: The most a request to the proxy may hold, in bytes.
MAX_REQUEST_BYTES = 16 * 1024 * 1024
#: The most of a request's path an audit line keeps.
_AUDIT_PATH_CAP = 512
_REQUEST_KEYS = frozenset({"system", "method", "url", "headers", "body", "timeout_sec"})
#: Request headers that describe the hop, not the request: never forwarded (httpx sets its own).
_HOP_HEADERS = frozenset({"host", "content-length", "connection", "keep-alive",
                          "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
                          "expect"})
#: Request headers that carry a credential: an adapter holds none, so one that sends one is
#: refused, as is one sending the declared header scheme's header.
_CREDENTIAL_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie"})
#: Response headers that describe the upstream hop, or the encoding of a body that is passed on
#: only when it has none (#1383).
_REPLY_HOP_HEADERS = frozenset({"content-length", "transfer-encoding", "connection",
                                "keep-alive", "content-encoding"})
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}")


class CredentialStore(Protocol):
    """The proxy's read of a (tenant, system)'s credential set; None when there is none. A store
    it cannot reach is `TransportFault`; one that refuses is `ConfigFault` (r7 A18)."""

    def read(self, tenant_id: str, system: str) -> CredentialSet | None: ...


@dataclass(frozen=True)
class ProxyDeps:
    """What the proxy runs over: the data root whose `<tenant id>/exports/` folders it reads (read
    only; it keeps no tenant list, A26), the credential store, the token verifier, the audit
    sink, the response cap (a test's seam, never configuration: the run is proven up to the
    shipped value, #1412) and upstream timeout, and the public trust's bundle."""

    data_root: Path
    store: CredentialStore
    verifier: TokenVerifier
    audit: AuditSink
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    upstream_timeout_sec: float = DEFAULT_UPSTREAM_TIMEOUT_SEC
    #: Seconds allowed on top of a request's timeout for the proxy's own calls (token check,
    #: credential read); the shipped value is `PROXY_OVERHEAD_SEC`, which the caller's wait assumes.
    proxy_overhead_sec: float = PROXY_OVERHEAD_SEC
    #: The PEM bundle a system without `ca` is verified against; None: the one httpx ships.
    public_ca_file: Path | None = None
    #: How long a request may take to arrive (a test's seam, never configuration).
    request_body_sec: float = REQUEST_BODY_SEC

    def __post_init__(self) -> None:
        if (isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int)
                or self.max_response_bytes < 1):
            raise ConfigFault("max_response_bytes must be a positive whole number")
        if not self.request_body_sec > 0:
            raise ConfigFault("request_body_sec must be positive")
        if not self.upstream_timeout_sec > 0:
            raise ConfigFault("upstream_timeout_sec must be positive")
        if not 0 < self.proxy_overhead_sec <= PROXY_OVERHEAD_SEC:
            # the caller's wait assumes at most the shipped allowance (`caller_wait_sec`)
            raise ConfigFault(f"proxy_overhead_sec must be positive and at most "
                              f"{PROXY_OVERHEAD_SEC}")


@dataclass(frozen=True)
class _Asked:
    """One request as the adapter's transport sent it."""

    system: str
    method: str
    url: str
    headers: Mapping[str, str]
    body: str | None = field(repr=False)
    #: The system's own timeout (r7 A21); None when the caller sent none.
    timeout_sec: float | None = None


@dataclass
class _Trail:
    """The audit record of one request, filled in as the request gets further."""

    tenant: str | None = None
    system: str | None = None
    investigation: str | None = None
    commit: str | None = None
    method: str | None = None
    path: str | None = None
    outcome: str | None = None
    #: The proxy began the target system's call and did not see its connect fail: the request may
    #: have reached the system (#1374). Not audited; stamped on every final record as `sent`.
    sent: bool = False

    def entry(self, fault: str | None) -> dict[str, Any]:
        record = {key: getattr(self, key) for key in AUDIT_KEYS}
        record["outcome"] = self.outcome if self.outcome is not None else fault
        return {"time": _clock.now_iso(), **record, "fault": fault}


def _refused_answer(fault: str, detail: str, *, origin: str | None,
                    system_side: bool = False) -> FinalRecord:
    """A refusal with no system status, and no body that counts. `system_side` marks the one kind
    that is the target system's (its call failed, #1404); unmarked, the refusal is the proxy's
    own and carries the label of whose failure it is (#1363 O4): `origin`, or `access` when
    the refusal came from somewhere that names none (a port's plain fault, the catch-all)."""
    label = None if system_side else (origin if is_proxy_label(origin) else ORIGIN_ACCESS)
    return FinalRecord(status=None, headers={}, fault=fault, detail=detail,
                       system_side=system_side, sent=False, body_whole=False, reader_fault=False,
                       origin=label)


class _Proxy:
    """The request pipeline over one `ProxyDeps`; holds the OAuth access tokens it obtains.
    Every network leg runs under the request's deadline (`Deadline.run`), on its own client over
    the one TLS context built here (#1375 O1)."""

    def __init__(self, deps: ProxyDeps) -> None:
        self.deps = deps
        # The one conversion of the data root this proxy is handed (A26); a tenant's exports are
        # joined under it by tenancy, never spelled here.
        self._root = tenancy.data_root_from_path(deps.data_root)
        ca_file = deps.public_ca_file
        self._trust = public_trust(None if ca_file is None else str(ca_file))
        self.access_tokens = AccessTokens()

    def handle(self, authorization: str | None, raw: bytes | _Unread, send: Sink,
               arrived: float | None = None) -> FinalRecord:
        """The final record of one request, audited before it is returned (A13); the upstream's
        body went to `send` meanwhile, on this thread's behalf, which stays with the request until
        the audit is written (P3). `arrived` is when it reached the proxy (monotonic), where its
        deadline starts (#1364); default now."""
        trail = _Trail()
        try:
            answer = self._proxied(authorization, raw, send, trail,
                                   time.monotonic() if arrived is None else arrived)
        except Refused as refused:
            answer = _refused_answer(refused.fault, refused.detail, origin=refused.origin,
                                     system_side=refused.system_side)
        except ConfigFault as fault:
            answer = _refused_answer(CONFIG, fault.detail, origin=fault.origin)
        except TransportFault as fault:
            answer = _refused_answer(TRANSPORT, fault.detail, origin=fault.origin)
        except Exception as e:  # noqa: BLE001 — A9: a request that cannot be processed is still classified and audited
            # r7 A18: nobody foresaw it, so nobody can say a retry fails too
            _logger.error("a request could not be processed (%s)", type(e).__name__)
            answer = _refused_answer(TRANSPORT, "the request could not be processed",
                                     origin=ORIGIN_ACCESS)
        try:
            self.deps.audit.record(trail.entry(answer.fault))
        except Exception as e:  # noqa: BLE001 — A13: any failure to audit fails the request closed
            _logger.error("the audit record could not be written (%s: %s); the answer is "
                          "withheld", type(e).__name__, e)
            answer = _refused_answer(TRANSPORT, "the proxy's audit could not be written; the "
                                                "answer is withheld", origin=ORIGIN_ACCESS)
        # Decided once, at the one send boundary (`_sent`), whatever answer follows (#1374).
        return dataclasses.replace(answer, sent=trail.sent)

    def _proxied(self, authorization: str | None, raw: bytes | _Unread, send: Sink,
                 trail: _Trail, began: float) -> FinalRecord:
        asked = _parse_request(raw)
        trail.system, trail.method = asked.system[:80], asked.method[:20]
        cap = self.deps.upstream_timeout_sec
        budget = cap if asked.timeout_sec is None else min(asked.timeout_sec, cap)
        deadline = Deadline(began + budget + self.deps.proxy_overhead_sec, per_wait=budget)
        with answering(deadline):
            return self._within(authorization, asked, send, trail, deadline)

    def _within(self, authorization: str | None, asked: _Asked, send: Sink, trail: _Trail,
                deadline: Deadline) -> FinalRecord:
        claims = self._verified(authorization)
        trail.tenant, trail.investigation = claims.tenant, claims.investigation
        if not is_system_name(asked.system):
            raise Refused(CONFIG, f"{asked.system[:80]!r} is not a system name", origin=ORIGIN_REQUEST)
        mode = claims.grant.get(asked.system)
        if mode is None:
            raise Refused(CONFIG, f"the request token does not grant {asked.system}", origin=ORIGIN_REQUEST)
        export = self._current_export(claims.tenant)
        trail.commit = export.commit
        declaration = self._declared(export, asked.system)
        target = locate(declaration, asked.url)
        trail.path = target.path[:_AUDIT_PATH_CAP]
        check_route(declaration, asked.system, asked.method, target.path, mode)
        headers = _forwarded(asked.headers, declaration.auth)
        creds = self._stored(claims.tenant, asked.system)
        if creds is None:
            raise Refused(CONFIG, f"no credential set is stored for {asked.system}", origin=ORIGIN_SETUP)
        check_fit(declaration.auth, creds, asked.system)
        trust = self._trust_of(declaration)
        access_token = None
        if declaration.auth.scheme == OAUTH_CLIENT_CREDENTIALS:
            access_token = self.access_tokens.token(claims.tenant, asked.system, declaration,
                                                    creds, deadline, trust)
            headers["Authorization"] = f"Bearer {access_token}"
        else:
            headers.update(static_headers(declaration.auth, creds, asked.system))
        answer = self._sent(asked, target, headers, send, trail, deadline, trust)
        if answer.status == 401 and access_token is not None:
            self.access_tokens.evict(claims.tenant, asked.system, access_token)
        return answer

    def _trust_of(self, declaration: AccessDeclaration) -> ssl.SSLContext:
        """The trust for every leg of `declaration` (#1391 O4, P4): its `ca` alone when it has
        one, else the public bundle built at start. Runs on the request's worker thread, where the
        `ca` context is built once per distinct text and cached."""
        return self._trust if declaration.ca is None else trust_of_ca(declaration.ca)

    def _verified(self, authorization: str | None) -> Claims:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme != "Bearer" or not token:
            raise Refused(CONFIG, "the request carries no bearer request token", origin=ORIGIN_ACCESS)
        try:
            payload, signature, claims = split_token(token)
            signed = self.deps.verifier.verify(payload, signature, tenant_id=claims.tenant)
        except AdapterFault as fault:
            # A token that does not parse, or a verifier that cannot answer: our access as a
            # whole, whatever the fault's class (#1363 B3: labelled at the call site).
            fault.origin = fault.origin or ORIGIN_ACCESS
            raise
        if not signed:
            raise Refused(CONFIG, "the request token's signature is not valid for the tenant "
                                  "it names", origin=ORIGIN_ACCESS)
        if claims.exp <= time.time():
            raise Refused(CONFIG, "the request token has expired", origin=ORIGIN_ACCESS)
        return claims

    def _declared(self, export: tenancy.TenantExport, system: str) -> AccessDeclaration:
        """The published declaration for `system`. A system with no usable declaration in the
        export is our setup for that one system (#1363 B3: labelled here, since
        `tenancy.read_export_access` is not the proxy's alone)."""
        try:
            return tenancy.read_export_access(export.path, system)
        except AdapterFault as fault:
            fault.origin = ORIGIN_SETUP
            raise

    def _stored(self, tenant_id: str, system: str) -> CredentialSet | None:
        """The credential set stored for `system`. The store labels its own per-system causes
        (`setup`); a fault it raises with no label is the store as a whole being unusable
        (OpenBao unreachable, or refusing the proxy): our access, whatever its class."""
        try:
            return self.deps.store.read(tenant_id, system)
        except AdapterFault as fault:
            fault.origin = fault.origin or ORIGIN_ACCESS
            raise

    def _current_export(self, tenant_id: str) -> tenancy.TenantExport:
        # The id is checked here too, not only by the verifier: no path is built from a claim
        # that is not a canonical tenant UUID (A26).
        if not tenancy.is_valid_tenant_id(tenant_id):
            raise Refused(CONFIG, "the request token names no tenant id", origin=ORIGIN_ACCESS)
        try:
            exports = tenancy.tenant_exports(self._root, tenant_id)
        except TenantRefused as refused:
            raise Refused(CONFIG, f"tenant {tenant_id}: {refused}", origin=ORIGIN_ACCESS) from None
        if not exports.is_dir() or exports.is_symlink():
            raise Refused(CONFIG, f"tenant {tenant_id} has no exports folder under the proxy's data "
                                  "root", origin=ORIGIN_ACCESS)
        try:
            return tenancy.current_export_at(exports, tenant_id)
        except tenancy.DeliveryRefused as refused:
            _logger.warning("tenant %s: %s", tenant_id, refused)
            raise Refused(CONFIG, f"tenant {tenant_id} has no published export to apply", origin=ORIGIN_ACCESS) from None

    def _sent(self, asked: _Asked, target: Target,  # noqa: PLR0913 — one call's state
              headers: dict[str, str], send: Sink,
              trail: _Trail, deadline: Deadline, trust: ssl.SSLContext) -> FinalRecord:
        cap = self.deps.max_response_bytes
        content = asked.body.encode("utf-8") if asked.body is not None else None
        what = f"calling {asked.system}"
        timeout = deadline.wait(what)

        answered: list[int] = []
        on_reader = False  # the leg is waiting for the run, not for the system

        def sent(status: int) -> None:
            trail.outcome = f"sent {status}"
            answered.append(status)

        async def passed_on(chunk: bytes) -> None:
            nonlocal on_reader
            on_reader = True
            await send(chunk)
            on_reader = False

        async def call() -> Any:
            trail.sent = True  # here, past the deadline's own check before the leg
            return await stream_reply(
                trust, asked.method, target.url, cap=cap, timeout=timeout, sink=passed_on,
                on_status=sent, headers=headers, content=content)

        try:
            reply = deadline.run(what, call, system_side=True)
        except _ReaderLeft as left:
            return _broken_reply(asked.system, answered[0], str(left), reader_fault=True)
        except Refused as cut:
            if on_reader:
                return _broken_reply(asked.system, answered[0], "the run was too slow reading it",
                                     reader_fault=True)
            if answered:
                return _broken_reply(asked.system, answered[0], cut.detail)
            raise
        except httpx.TransportError as e:
            if answered:
                return _broken_reply(asked.system, answered[0], type(e).__name__)
            # Never connected: nothing reached the system.
            trail.sent = not isinstance(e, httpx.ConnectError | httpx.ConnectTimeout)
            raise Refused(TRANSPORT, f"{asked.system} could not be reached or did not answer "
                                     f"({type(e).__name__})", system_side=True) from None
        return _record_of_reply(asked.system, reply)


def _record_of_reply(system: str, reply: StreamedReply) -> FinalRecord:
    """The final record of a reply that came to its end or was withheld: the upstream's status,
    its headers less the hop's, the fault its status makes, and whether the body went whole."""
    status, withheld = reply.status, reply.withheld
    fault = _fault_of(status)
    if fault is None:
        detail = None if withheld is None else f"{system} answered {withheld}"
        fault = None if withheld is None else UPSTREAM
    else:
        detail = f"{system} answered {status}" + (
            "" if withheld is None else f" with {withheld}, withheld")
    if reply.too_large and fault == UPSTREAM and status < 300:
        detail = f"{detail}; narrow the query so its reply is smaller"
    shown: dict[str, str] = {}
    for name, value in reply.headers:
        if name.lower() in _REPLY_HOP_HEADERS:
            continue
        shown[name] = f"{shown[name]}, {value}" if name in shown else value
    return FinalRecord(status=status, headers=shown, fault=fault, detail=detail,
                       system_side=False, sent=True, body_whole=withheld is None, reader_fault=False,
                       origin=None)


def _broken_reply(system: str, status: int, why: str, *, reader_fault: bool = False) -> FinalRecord:
    """The system answered `status` and then its reply broke (#1404), or the run cut it
    (`reader_fault`): the status stands, so a write it accepted is not reported as never made; no
    body counts."""
    return FinalRecord(status=status, headers={}, fault=TRANSPORT, system_side=False, sent=True,
                       detail=f"{system} answered {status} but its reply did not arrive whole ({why})",
                       body_whole=False, reader_fault=reader_fault, origin=None)


def _fault_of(status: int) -> str | None:
    """The fault class of an upstream status (O7, A9): a 401 with a credential attached is
    `ConfigFault`; another 3xx or 4xx `UpstreamFault`; a 5xx `TransportFault`."""
    if 200 <= status < 300:
        return None
    if status == 401:
        return CONFIG
    if status >= 500:
        return TRANSPORT
    return UPSTREAM


def _parse_request(raw: bytes | _Unread) -> _Asked:  # noqa: C901 — one flat shape check
    if raw is _Unread.TOO_LARGE:
        raise Refused(CONFIG, f"the request is over {MAX_REQUEST_BYTES} bytes", origin=ORIGIN_REQUEST)
    if raw is _Unread.TOO_SLOW:
        raise Refused(TRANSPORT, "the request did not arrive in time", origin=ORIGIN_REQUEST)
    if raw is _Unread.PEER_LEFT:
        raise Refused(TRANSPORT, "the caller left before its request arrived", origin=ORIGIN_REQUEST)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused(CONFIG, "the request body is not JSON within the parser's depth", origin=ORIGIN_ACCESS) from None
    if not isinstance(doc, dict) or not set(doc) <= _REQUEST_KEYS or not {
            "system", "method", "url"} <= set(doc):
        raise Refused(CONFIG, f"the request must be an object of {sorted(_REQUEST_KEYS)}", origin=ORIGIN_ACCESS)
    system, method, url = doc["system"], doc["method"], doc["url"]
    headers, body = doc.get("headers") or {}, doc.get("body")
    if not all(isinstance(v, str) for v in (system, method, url)):
        raise Refused(CONFIG, "the request's system, method and url must be text", origin=ORIGIN_ACCESS)
    if not isinstance(headers, dict):
        raise Refused(CONFIG, "the request's headers must be an object", origin=ORIGIN_ACCESS)
    for name, value in headers.items():
        if not _HEADER_NAME.fullmatch(name) or not isinstance(value, str) or not value.isascii() or any(
                ch in value for ch in "\r\n\0"):
            raise Refused(CONFIG, f"the request header {name[:80]!r} is not a header", origin=ORIGIN_ACCESS)
    if body is not None and not isinstance(body, str):
        raise Refused(CONFIG, "the request's body must be text or null", origin=ORIGIN_ACCESS)
    timeout = doc.get("timeout_sec")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int | float)
                                or not math.isfinite(timeout) or timeout <= 0):
        raise Refused(CONFIG, "the request's timeout_sec must be a positive number", origin=ORIGIN_ACCESS)
    if not _encodable(system, method, url, body, *headers.values()):
        # a lone surrogate: a malformed request, not one a retry could send (r7 A18)
        raise Refused(CONFIG, "the request holds text that is not valid Unicode", origin=ORIGIN_ACCESS)
    return _Asked(system=system, method=method, url=url, headers=headers, body=body,
                  timeout_sec=timeout)


def _encodable(*texts: str | None) -> bool:
    try:
        for text in texts:
            if text is not None:
                text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _forwarded(headers: Mapping[str, str], auth: Auth) -> dict[str, str]:
    """The adapter's headers to send on: hop headers dropped; a credential header refused."""
    own = {str(auth.header).lower()} if auth.scheme == HEADER else set()
    sent: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in _HOP_HEADERS:
            continue
        if lowered in _CREDENTIAL_HEADERS or lowered in own:
            raise Refused(CONFIG, f"the request carries its own {name} header; the proxy "
                                  "applies the declared credential", origin=ORIGIN_ACCESS)
        sent[name] = value
    return sent


class _Unread(enum.Enum):
    """Why a request body was not read to its end."""

    TOO_LARGE = enum.auto()
    TOO_SLOW = enum.auto()
    PEER_LEFT = enum.auto()


async def _body_of(request: Request, wait: float) -> bytes | _Unread:
    """The request body; or why it was not read: it passed `MAX_REQUEST_BYTES`, it had not all
    arrived `wait` seconds after the call (whether the peer went silent or trickled), or the peer
    left first."""
    body = bytearray()
    try:
        with anyio.fail_after(wait):
            async for chunk in request.stream():
                body += chunk
                if len(body) > MAX_REQUEST_BYTES:
                    return _Unread.TOO_LARGE
    except TimeoutError:
        return _Unread.TOO_SLOW
    except ClientDisconnect:
        return _Unread.PEER_LEFT
    return bytes(body)


class _Framed(Response):
    """The reply in the proxy's format. The response start goes first (the proxy's HTTP status is
    always 200, so it can precede every outcome); `handle` then runs on a worker thread with a
    send for each upstream chunk, which gives up on a run that left or takes none of it within
    `CALLER_GRACE_SEC` (`_ReaderLeft`); the final record goes last, under the same bound. A reader
    still stalled then sees the connection closed unfinished once it resumes (the timeout is not
    caught). Until it resumes or dies the socket and its unsent bytes stay for the delivery limit
    (`_connections`): a server closes only after flushing, and the ASGI interface offers no abort."""

    def __init__(self, work: Callable[[Sink], FinalRecord], *, close: bool = False) -> None:
        super().__init__(content=None, media_type=REPLY_CONTENT_TYPE)
        self._work = work
        self._close = close  # the proxy stopped reading the request: the connection ends with this reply (#1428)

    async def __call__(self, scope: Scope, receive: Receive, send: AsgiSend) -> None:
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", REPLY_CONTENT_TYPE.encode("ascii")),
                                *([(b"connection", b"close")] if self._close else [])]})

        request = Request(scope, receive)

        async def body(chunk: bytes) -> None:
            if await request.is_disconnected():  # a send to a departed run would do nothing
                raise _ReaderLeft("the run went away")
            try:
                with anyio.fail_after(CALLER_GRACE_SEC):
                    await send({"type": "http.response.body", "body": encode_body(chunk),
                                "more_body": True})
            except TimeoutError:
                raise _ReaderLeft(f"the run took none of it for {CALLER_GRACE_SEC} s") from None

        final = await run_in_threadpool(self._work, body)
        with anyio.fail_after(CALLER_GRACE_SEC):
            await send({"type": "http.response.body", "body": encode_final(final),
                        "more_body": False})


def create_app(deps: ProxyDeps) -> FastAPI:  # lint-dup: ok — the proxy's own ASGI app; api/app.py's `create_app` builds the unrelated platform API
    """The proxy as an ASGI app over `deps`."""
    proxy = _Proxy(deps)

    app = FastAPI(title="defender credential proxy", docs_url=None, redoc_url=None,
                  openapi_url=None)

    async def proxy_request(request: Request) -> _Framed:
        # The deadline runs from here: reading the body and waiting for a worker thread count
        # against it, as they count against the caller's wait (#1364).
        arrived = time.monotonic()
        # Never shorter than the request's own longest deadline: waiting for the body is part of it.
        wait = max(deps.request_body_sec, deps.upstream_timeout_sec + deps.proxy_overhead_sec)
        raw = await _body_of(request, wait)
        authorization = request.headers.get("authorization")
        return _Framed(lambda send: proxy.handle(authorization, raw, send, arrived),
                       close=isinstance(raw, _Unread))

    app.add_api_route(PROXY_PATH, proxy_request, methods=["POST"], response_model=None)
    return app


#: The operator configuration `create_app_from_config` takes (A13, A26): exactly one of
#: `openbao_token` and `openbao_token_file`, and every key of `CONFIG_KEYS`; the others optional.
CONFIG_KEYS = ("kv_mount", "data_root", "audit_path")
TOKEN_KEYS = ("openbao_token", "openbao_token_file")
OPTIONAL_CONFIG_KEYS = ("upstream_timeout_sec",)


def _openbao_token(config: Mapping[str, Any]) -> str:
    """The proxy role's OpenBao token: given in the config, or read from the file it names (the
    file's trailing newline dropped). Never from the environment."""
    given = [k for k in TOKEN_KEYS if k in config]
    if len(given) != 1:
        raise ConfigFault("credential proxy configuration: give one of openbao_token or "
                          "openbao_token_file")
    if given == ["openbao_token"]:
        return config["openbao_token"]
    where = config["openbao_token_file"]
    try:
        return _io.read_text_utf8(Path(where)).strip()
    except (OSError, TypeError, ValueError) as e:
        raise ConfigFault(f"credential proxy configuration: the OpenBao token file cannot be read "
                          f"({type(e).__name__})") from None


def create_app_from_config(config: Mapping[str, Any], *, openbao_addr: str | None = None,
                           transport: httpx.MockTransport | None = None) -> FastAPI:
    """The shipped proxy from the operator's settings: the OpenBao store and transit verifier
    (the proxy role's token, `kv_mount`), the data root whose tenants' `exports/` folders it reads
    (`data_root`, read only) and the append-only audit file (`audit_path`). OpenBao is the
    deployment's (`DEPLOYMENT_ISSUER`, https) on the fixed transit mount; `openbao_addr` and
    `transport` are a test's seam, never configuration. A missing or unknown key (the retired
    `tenant_keys`, `tenant_exports`, `transit_mount`, `openbao_addr` and `max_response_bytes`
    included) or a value of
    the wrong type is `ConfigFault`."""
    missing = [k for k in CONFIG_KEYS if k not in config]
    unknown = sorted(set(config) - set(CONFIG_KEYS) - set(TOKEN_KEYS) - set(OPTIONAL_CONFIG_KEYS))
    if missing or unknown:
        raise ConfigFault(f"credential proxy configuration: missing {missing}, unknown {unknown}")
    token = _openbao_token(config)
    addr = DEPLOYMENT_ISSUER.openbao_url if openbao_addr is None else openbao_addr
    extra = {k: config[k] for k in OPTIONAL_CONFIG_KEYS if k in config}
    try:
        data_root = config["data_root"]
        if not isinstance(data_root, str) or "\0" in data_root:
            raise TypeError("data_root")
        deps = ProxyDeps(
            data_root=Path(data_root),
            store=OpenBaoStore(addr=addr, token=token, mount=config["kv_mount"], transport=transport),
            verifier=TransitVerifier(addr=addr, token=token, transport=transport),
            audit=FileAuditSink(config["audit_path"]),
            **extra)
    except (TypeError, ValueError) as e:
        # a value of the wrong type (a quoted number, a path that is not text) or shape
        raise ConfigFault(f"credential proxy configuration: a value is not usable "
                          f"({type(e).__name__})") from None
    return create_app(deps)


__all__ = ["CONFIG_KEYS", "DEFAULT_MAX_RESPONSE_BYTES", "OPTIONAL_CONFIG_KEYS", "PROXY_PATH", "TOKEN_KEYS",
           "CredentialStore", "ProxyDeps", "create_app", "create_app_from_config"]
