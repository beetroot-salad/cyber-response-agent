"""The caller's side of the credential proxy (#1163): one POST of a request to it, and its
answer. Holds no credential and decides nothing: the proxy classifies every outcome and names its
fault class, which the caller raises as its own."""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from defender.kit.access import CALLER_GRACE_SEC, PROXY_OVERHEAD_SEC
from defender.kit.faults import TransportFault

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


def proxy_call(  # noqa: PLR0913 — one request's per-call state
    proxy_url: str | None, token: str | None, *, system: str, method: str, url: str,
    headers: Mapping[str, str] | None = None, body: str | None = None, timeout_sec: int = 10,
) -> ProxyAnswer:
    """POST the request to the proxy with `token` and the system's `timeout_sec`, which the proxy
    runs the request inside (r7 A21); this call waits past the proxy's whole deadline.
    `TransportFault` when no address or token was handed to the caller, the proxy cannot be
    reached, or its answer is not the proxy's."""
    if not proxy_url or not token:
        raise TransportFault("no credential proxy address or request token was handed to this call")
    try:
        response = httpx.post(
            proxy_url.rstrip("/") + PROXY_PATH, headers={"Authorization": f"Bearer {token}"},
            json={"system": system, "method": method, "url": url,
                  "headers": dict(headers or {}), "body": body, "timeout_sec": timeout_sec},
            timeout=timeout_sec + PROXY_OVERHEAD_SEC + CALLER_GRACE_SEC)
    except httpx.HTTPError as e:
        raise TransportFault(f"credential proxy unreachable: {type(e).__name__}") from None
    try:
        data = response.json()
        answer = ProxyAnswer(
            status=int(data["status"] or 0), headers=dict(data.get("headers") or {}),
            body=str(data.get("body") or ""), fault=data.get("fault"),
            detail=str(data.get("detail") or ""))
    except (ValueError, KeyError, TypeError):
        raise TransportFault(
            f"credential proxy answered HTTP {response.status_code} with no usable answer"
        ) from None
    if response.status_code != 200:
        raise TransportFault(f"credential proxy answered HTTP {response.status_code}")
    return answer


def request_body(body: object) -> str | None:
    """A JSON request body as the text the proxy forwards."""
    return None if body is None else json.dumps(body)


__all__ = ["PROXY_PATH", "ProxyAnswer", "proxy_call", "request_body"]
