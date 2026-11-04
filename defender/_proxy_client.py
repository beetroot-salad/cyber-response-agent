"""The caller's side of the credential proxy (#1163): one POST of a request to it, and its
answer. Holds no credential and decides nothing: the proxy classifies every outcome and names its
fault class, which the caller raises as its own."""
from __future__ import annotations

import contextlib
import functools
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx

from defender._internal_http import internal_client, tls_trust
from defender.kit.access import HTTP_PROXY, caller_wait_sec
from defender.kit.faults import AdapterFault, ConfigFault, TransportFault
from defender.kit.settings import system_prefix
from defender.kit.verbs import VerbContext

if TYPE_CHECKING:
    from defender.kit.verbs import TenantRecord

#: The proxy's one endpoint.
PROXY_PATH = "/v1/request"


@dataclass(frozen=True)
class ProxyAnswer:
    """The proxy's answer: the upstream's status, headers and body (scrubbed), or the fault
    class the proxy refused or classified the request as, with its detail."""

    status: int
    headers: Mapping[str, str]
    body: str
    fault: str | None
    detail: str
    #: The proxy marked a status-less refusal as the target system's call failing (#1404).
    system_side: bool = False

    @property
    def from_system(self) -> bool:
        """The system's own answer or failure: it answered (any status) or the proxy marked it."""
        return bool(self.status) or self.system_side


@contextlib.contextmanager
def _the_proxys_own() -> Iterator[None]:
    """Every fault raised inside is the proxy's own (`proxy_own`, #1404): marked once around the
    whole exchange, so a raise site added later cannot be left blaming the system."""
    try:
        yield
    except AdapterFault as fault:
        fault.proxy_own = True
        raise


def proxy_call(  # noqa: PLR0913 — one request's per-call state
    proxy_url: str | None, token: str | None, *, system: str, method: str, url: str,
    headers: Mapping[str, str] | None = None, body: str | None = None, timeout_sec: int = 10,
) -> ProxyAnswer:
    """POST the request to the proxy with `token` and the system's `timeout_sec`, which the proxy
    runs the request inside (r7 A21); this call waits past the proxy's whole deadline.
    `TransportFault`, the proxy's own (`proxy_own`), when no address or token was handed to the
    caller, the proxy cannot be reached, or its answer is not the proxy's."""
    with _the_proxys_own():
        return _call(proxy_url, token, system=system, method=method, url=url, headers=headers,
                     body=body, timeout_sec=timeout_sec)


def _call(  # noqa: PLR0913 — one request's per-call state
    proxy_url: str | None, token: str | None, *, system: str, method: str, url: str,
    headers: Mapping[str, str] | None, body: str | None, timeout_sec: int,
) -> ProxyAnswer:
    if not proxy_url or not token:
        raise TransportFault("no credential proxy address or request token was handed to this call")
    try:
        response = _client().post(
            proxy_url.rstrip("/") + PROXY_PATH, headers={"Authorization": f"Bearer {token}"},
            json={"system": system, "method": method, "url": url,
                  "headers": dict(headers or {}), "body": body, "timeout_sec": timeout_sec},
            timeout=caller_wait_sec(timeout_sec))
    except httpx.HTTPError as e:
        raise TransportFault(f"credential proxy unreachable: {type(e).__name__}") from None
    try:
        data = response.json()
        answer = ProxyAnswer(
            status=int(data["status"] or 0), headers=dict(data.get("headers") or {}),
            body=str(data.get("body") or ""), fault=data.get("fault"),
            detail=str(data.get("detail") or ""), system_side=data.get("system_side") is True)
    except (ValueError, KeyError, TypeError):
        raise TransportFault(
            f"credential proxy answered HTTP {response.status_code} with no usable answer"
        ) from None
    if response.status_code != 200:
        raise TransportFault(f"credential proxy answered HTTP {response.status_code}")
    return answer


@functools.cache
def _client() -> httpx.Client:
    """The process's one pooled client to the proxy (`_internal_http`: no outbound web proxy)."""
    return internal_client(trust=tls_trust())


def token_of(ctx: VerbContext) -> str | None:
    """The request token `ctx` presents: its own, or one asked of its source now, inside the
    verb's call (r7 A20). A source that cannot mint raises its fault here."""
    if ctx.request_token is not None:
        return ctx.request_token
    source = ctx.token_source
    return None if source is None else source()


def request_body(body: object) -> str | None:
    """A JSON request body as the text the proxy forwards."""
    return None if body is None else json.dumps(body)


def uses_proxy(tenant: TenantRecord, system: str) -> bool:
    """Is `system` reached through the credential proxy? Decided once, from the record."""
    entry = tenant.systems.get(system)
    return (entry is not None and not isinstance(entry, ConfigFault)
            and entry.get(f"{system_prefix(system)}_TRANSPORT") == HTTP_PROXY)


def proxy_exchange(
    ctx: VerbContext, *, system: str, method: str, url: str, body: dict | None, timeout_sec: int,
) -> ProxyAnswer:
    """One JSON request to `system` through the credential proxy, with the token `ctx` presents;
    the proxy's answer as it came. A fault raised before the answer (no token minted, the proxy
    not reached) is the proxy's own (`proxy_own`)."""
    with _the_proxys_own():
        token = token_of(ctx)
    return proxy_call(
        ctx.proxy_url, token, system=system, method=method, url=url,
        headers={"Accept": "application/json"}
        | ({"Content-Type": "application/json"} if body is not None else {}),
        body=request_body(body), timeout_sec=timeout_sec)


__all__ = ["PROXY_PATH", "ProxyAnswer", "proxy_call", "proxy_exchange", "request_body", "token_of", "uses_proxy"]
