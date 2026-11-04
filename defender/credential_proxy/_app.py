"""The credential proxy (#1163): one multi-tenant program between adapters and their systems.

`POST /v1/request` with `Authorization: Bearer <request token>` and the JSON body
`{system, method, url, headers, body}` (`headers` a name -> value object, `body` text or null).
The answer is always HTTP 200 with the JSON body `{status, headers, body, fault, detail}`:
`status` is the upstream's status (null when nothing was sent), `body` its body as text and
`headers` its headers, both with every secret value used replaced by a marker; `fault` is null or
the fault class the adapter raises (`ConfigFault`, `ConfinementFault`, `UpstreamFault`,
`TransportFault`); `detail` says why and never holds a secret value.

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
6. send, following no redirect, with the response's body capped and never inflated (O7, #1383);
7. scrub each secret value used from the answer (O4, N6);
8. audit, before answering: if the record cannot be written the answer is withheld (A13)."""
from __future__ import annotations

import json
import logging
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from defender import _clock, _io, tenancy
from defender.configuration.issuer import DEPLOYMENT_ISSUER
from defender.kit.access import HEADER, OAUTH_CLIENT_CREDENTIALS, PROXY_OVERHEAD_SEC, Auth
from defender.kit.faults import ConfigFault, TransportFault
from defender.kit.verbs import is_system_name
from defender.records.formats import TenantRefused
from defender.credential_proxy._audit import AUDIT_KEYS, AuditSink, FileAuditSink
from defender.credential_proxy._credentials import (
    AccessTokens,
    CredentialSet,
    check_fit,
    scrub_secrets,
    scrub_secret_bytes,
    secret_values,
    static_headers,
)
from defender.credential_proxy._deadline import Deadline, answering
from defender.credential_proxy._openbao import OpenBaoStore, TransitVerifier
from defender.credential_proxy._refusal import CONFIG, TRANSPORT, UPSTREAM, Refused
from defender.credential_proxy._reply import capped_reply, public_trust
from defender.credential_proxy._scope import Target, check_route, locate
from defender.credential_proxy._tokens import Claims, TokenVerifier, split_token

_logger = logging.getLogger(__name__)

#: The proxy's one endpoint.
PROXY_PATH = "/v1/request"
#: The default cap on an upstream response body (decoded), in bytes; over it is `UpstreamFault`.
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
#: The most time, in seconds, a request may ask for its upstream call (r7 A21), and what it gets
#: when it asks none; over it is `TransportFault`.
DEFAULT_UPSTREAM_TIMEOUT_SEC = 30.0
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
    sink, and the response cap and upstream timeout."""

    data_root: Path
    store: CredentialStore
    verifier: TokenVerifier
    audit: AuditSink
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    upstream_timeout_sec: float = DEFAULT_UPSTREAM_TIMEOUT_SEC
    #: Seconds allowed on top of a request's timeout for the proxy's own calls (token check,
    #: credential read); the shipped value is `PROXY_OVERHEAD_SEC`, which the caller's wait assumes.
    proxy_overhead_sec: float = PROXY_OVERHEAD_SEC

    def __post_init__(self) -> None:
        if (isinstance(self.max_response_bytes, bool) or not isinstance(self.max_response_bytes, int)
                or self.max_response_bytes < 1):
            raise ConfigFault("max_response_bytes must be a positive whole number")
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

    def entry(self, fault: str | None) -> dict[str, Any]:
        record = {key: getattr(self, key) for key in AUDIT_KEYS}
        record["outcome"] = self.outcome if self.outcome is not None else fault
        return {"time": _clock.now_iso(), **record, "fault": fault}


def _refused_answer(fault: str, detail: str, *, system_side: bool = False) -> dict[str, Any]:
    """A refusal with no system status. `system_side` marks the one kind that is the target
    system's (its call failed, #1404); unmarked, the refusal is the proxy's own."""
    return {"status": None, "headers": {}, "body": "", "fault": fault, "detail": detail,
            "system_side": system_side}


class _Proxy:
    """The request pipeline over one `ProxyDeps`; holds the OAuth access tokens it obtains.
    Every network leg runs under the request's deadline (`Deadline.run`), on its own client over
    the one TLS context built here (#1375 O1)."""

    def __init__(self, deps: ProxyDeps) -> None:
        self.deps = deps
        # The one conversion of the data root this proxy is handed (A26); a tenant's exports are
        # joined under it by tenancy, never spelled here.
        self._root = tenancy.data_root_from_path(deps.data_root)
        self._trust = public_trust()
        self.access_tokens = AccessTokens(self._trust)

    def handle(self, authorization: str | None, raw: bytes | None,
               arrived: float | None = None) -> dict[str, Any]:
        """The answer to one request, audited before it is returned (A13). `arrived` is when it
        reached the proxy (monotonic), where its deadline starts (#1364); default now."""
        trail = _Trail()
        try:
            answer = self._proxied(authorization, raw, trail,
                                   time.monotonic() if arrived is None else arrived)
        except Refused as refused:
            answer = _refused_answer(refused.fault, refused.detail,
                                     system_side=refused.system_side)
        except ConfigFault as fault:
            answer = _refused_answer(CONFIG, fault.detail)
        except TransportFault as fault:
            answer = _refused_answer(TRANSPORT, fault.detail)
        except Exception as e:  # noqa: BLE001 — A9: a request that cannot be processed is still classified and audited
            # r7 A18: nobody foresaw it, so nobody can say a retry fails too
            _logger.error("a request could not be processed (%s)", type(e).__name__)
            answer = _refused_answer(TRANSPORT, "the request could not be processed")
        try:
            self.deps.audit.record(trail.entry(answer["fault"]))
        except Exception as e:  # noqa: BLE001 — A13: any failure to audit fails the request closed
            _logger.error("the audit record could not be written (%s: %s); the answer is "
                          "withheld", type(e).__name__, e)
            return _refused_answer(TRANSPORT, "the proxy's audit could not be written; the "
                                              "answer is withheld")
        return answer

    def _proxied(self, authorization: str | None, raw: bytes | None,
                 trail: _Trail, began: float) -> dict[str, Any]:
        asked = _parse_request(raw)
        trail.system, trail.method = asked.system[:80], asked.method[:20]
        cap = self.deps.upstream_timeout_sec
        budget = cap if asked.timeout_sec is None else min(asked.timeout_sec, cap)
        deadline = Deadline(began + budget + self.deps.proxy_overhead_sec, per_wait=budget)
        with answering(deadline):
            return self._within(authorization, asked, trail, deadline)

    def _within(self, authorization: str | None, asked: _Asked, trail: _Trail,
                deadline: Deadline) -> dict[str, Any]:
        claims = self._verified(authorization)
        trail.tenant, trail.investigation = claims.tenant, claims.investigation
        if not is_system_name(asked.system):
            raise Refused(CONFIG, f"{asked.system[:80]!r} is not a system name")
        mode = claims.grant.get(asked.system)
        if mode is None:
            raise Refused(CONFIG, f"the request token does not grant {asked.system}")
        export = self._current_export(claims.tenant)
        trail.commit = export.commit
        declaration = tenancy.read_export_access(export.path, asked.system)
        target = locate(declaration, asked.url)
        trail.path = target.path[:_AUDIT_PATH_CAP]
        check_route(declaration, asked.system, asked.method, target.path, mode)
        headers = _forwarded(asked.headers, declaration.auth)
        creds = self.deps.store.read(claims.tenant, asked.system)
        if creds is None:
            raise Refused(CONFIG, f"no credential set is stored for {asked.system}")
        check_fit(declaration.auth, creds, asked.system)
        secrets = secret_values(creds)
        access_token = None
        if declaration.auth.scheme == OAUTH_CLIENT_CREDENTIALS:
            access_token = self.access_tokens.token(claims.tenant, asked.system, declaration,
                                                    creds, deadline)
            secrets += (access_token,)
            headers["Authorization"] = f"Bearer {access_token}"
        else:
            injected = static_headers(declaration.auth, creds, asked.system)
            headers.update(injected)
            # an upstream that echoes a Basic header back must not hand over its encoded form
            secrets += tuple(v.removeprefix("Basic ") for v in injected.values()
                             if v.startswith("Basic "))
        answer = self._sent(asked, target, headers, secrets, trail, deadline)
        if answer["status"] == 401 and access_token is not None:
            self.access_tokens.evict(claims.tenant, asked.system, access_token)
        return answer

    def _verified(self, authorization: str | None) -> Claims:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme != "Bearer" or not token:
            raise Refused(CONFIG, "the request carries no bearer request token")
        payload, signature, claims = split_token(token)
        if not self.deps.verifier.verify(payload, signature, tenant_id=claims.tenant):
            raise Refused(CONFIG, "the request token's signature is not valid for the tenant "
                                  "it names")
        if claims.exp <= time.time():
            raise Refused(CONFIG, "the request token has expired")
        return claims

    def _current_export(self, tenant_id: str) -> tenancy.TenantExport:
        # The id is checked here too, not only by the verifier: no path is built from a claim
        # that is not a canonical tenant UUID (A26).
        if not tenancy.is_valid_tenant_id(tenant_id):
            raise Refused(CONFIG, "the request token names no tenant id")
        try:
            exports = tenancy.tenant_exports(self._root, tenant_id)
        except TenantRefused as refused:
            raise Refused(CONFIG, f"tenant {tenant_id}: {refused}") from None
        if not exports.is_dir() or exports.is_symlink():
            raise Refused(CONFIG, f"tenant {tenant_id} has no exports folder under the proxy's data "
                                  "root")
        try:
            return tenancy.current_export_at(exports, tenant_id)
        except tenancy.DeliveryRefused as refused:
            _logger.warning("tenant %s: %s", tenant_id, refused)
            raise Refused(CONFIG, f"tenant {tenant_id} has no published export to apply") from None

    def _sent(self, asked: _Asked, target: Target,  # noqa: PLR0913 — one call's state
              headers: dict[str, str], secrets: tuple[str, ...],
              trail: _Trail, deadline: Deadline) -> dict[str, Any]:
        cap = self.deps.max_response_bytes
        content = asked.body.encode("utf-8") if asked.body is not None else None
        what = f"calling {asked.system}"
        timeout = deadline.wait(what)

        def sent(status: int) -> None:
            trail.outcome = f"sent {status}"

        try:
            reply = deadline.run(what, lambda: capped_reply(
                self._trust, asked.method, target.url, cap=cap, timeout=timeout,
                on_status=sent, headers=headers, content=content), system_side=True)
        except httpx.TransportError as e:
            raise Refused(TRANSPORT, f"{asked.system} could not be reached or did not answer "
                                     f"({type(e).__name__})", system_side=True) from None
        status, withheld = reply.status, reply.withheld
        fault = _fault_of(status)
        if fault is None:
            detail = None if withheld is None else f"{asked.system} answered {withheld}"
            fault = None if withheld is None else UPSTREAM
        else:
            detail = f"{asked.system} answered {status}" + (
                "" if withheld is None else f" with {withheld}, withheld")
        shown: dict[str, str] = {}
        for name, value in reply.headers:
            if name.lower() in _REPLY_HOP_HEADERS:
                continue
            name, value = scrub_secrets(name, secrets), scrub_secrets(value, secrets)
            shown[name] = f"{shown[name]}, {value}" if name in shown else value
        return {"status": status, "headers": shown,
                "body": scrub_secret_bytes(reply.body, secrets).decode("utf-8", "replace"),
                "fault": fault, "detail": detail}


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


def _parse_request(raw: bytes | None) -> _Asked:  # noqa: C901 — one flat shape check
    if raw is None:
        raise Refused(CONFIG, f"the request is over {MAX_REQUEST_BYTES} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused(CONFIG, "the request body is not JSON within the parser's depth") from None
    if not isinstance(doc, dict) or not set(doc) <= _REQUEST_KEYS or not {
            "system", "method", "url"} <= set(doc):
        raise Refused(CONFIG, f"the request must be an object of {sorted(_REQUEST_KEYS)}")
    system, method, url = doc["system"], doc["method"], doc["url"]
    headers, body = doc.get("headers") or {}, doc.get("body")
    if not all(isinstance(v, str) for v in (system, method, url)):
        raise Refused(CONFIG, "the request's system, method and url must be text")
    if not isinstance(headers, dict):
        raise Refused(CONFIG, "the request's headers must be an object")
    for name, value in headers.items():
        if not _HEADER_NAME.fullmatch(name) or not isinstance(value, str) or not value.isascii() or any(
                ch in value for ch in "\r\n\0"):
            raise Refused(CONFIG, f"the request header {name[:80]!r} is not a header")
    if body is not None and not isinstance(body, str):
        raise Refused(CONFIG, "the request's body must be text or null")
    timeout = doc.get("timeout_sec")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int | float)
                                or not math.isfinite(timeout) or timeout <= 0):
        raise Refused(CONFIG, "the request's timeout_sec must be a positive number")
    if not _encodable(system, method, url, body, *headers.values()):
        # a lone surrogate: a malformed request, not one a retry could send (r7 A18)
        raise Refused(CONFIG, "the request holds text that is not valid Unicode")
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
                                  "applies the declared credential")
        sent[name] = value
    return sent


async def _body_of(request: Request) -> bytes | None:
    """The request body, or None once it passes `MAX_REQUEST_BYTES`."""
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_REQUEST_BYTES:
            return None
    return bytes(body)


def create_app(deps: ProxyDeps) -> FastAPI:  # lint-dup: ok — the proxy's own ASGI app; api/app.py's `create_app` builds the unrelated platform API
    """The proxy as an ASGI app over `deps`."""
    proxy = _Proxy(deps)

    app = FastAPI(title="defender credential proxy", docs_url=None, redoc_url=None,
                  openapi_url=None)

    async def proxy_request(request: Request) -> JSONResponse:
        # The deadline runs from here: reading the body and waiting for a worker thread count
        # against it, as they count against the caller's wait (#1364).
        arrived = time.monotonic()
        raw = await _body_of(request)
        answer = await run_in_threadpool(proxy.handle, request.headers.get("authorization"),
                                         raw, arrived)
        return JSONResponse(answer)

    app.add_api_route(PROXY_PATH, proxy_request, methods=["POST"])
    return app


#: The operator configuration `create_app_from_config` takes (A13, A26): exactly one of
#: `openbao_token` and `openbao_token_file`, and every key of `CONFIG_KEYS`; the others optional.
CONFIG_KEYS = ("kv_mount", "data_root", "audit_path")
TOKEN_KEYS = ("openbao_token", "openbao_token_file")
OPTIONAL_CONFIG_KEYS = ("max_response_bytes", "upstream_timeout_sec")


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
    `tenant_keys`, `tenant_exports`, `transit_mount` and `openbao_addr` included) or a value of
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
