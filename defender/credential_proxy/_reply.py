"""One network leg to a tenant's system (the upstream call, the OAuth token exchange), read up
to a cap (#1163 O7, #1375 O3), over a TLS context built once (#1375 O1).

Building a TLS context loads a trust store and blocks the event loop every leg runs on, so the
proxy builds `public_trust()` once and each leg's fresh client reuses it. A fresh client per leg
keeps nothing from one request to the next: no connection, no cookie."""
from __future__ import annotations

import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import certifi
import httpx

from defender.kit.tls import client_trust


def public_trust(cafile: str | None = None) -> ssl.SSLContext:
    """The context a system without `ca` is verified with: the PEM bundle at `cafile`, by default
    the one httpx ships (certifi's). The environment is ignored (no `SSL_CERT_FILE`/`SSL_CERT_DIR`,
    no `SSLKEYLOGFILE`, #1375 O2), and nothing is inherited from Python's defaults (`client_trust`)."""
    return client_trust(cafile=cafile if cafile is not None else certifi.where())


@dataclass(frozen=True)
class CappedReply:
    """A reply's status, headers and body. The status and headers always arrive; the body is
    `withheld` (then empty) for a reason that reads after "answered": `more than N bytes`, or `a
    compressed body (gzip)` when it came compressed though none was asked for (#1383)."""

    status: int
    headers: list[tuple[str, str]]
    body: bytes
    withheld: str | None


async def capped_reply(trust: ssl.SSLContext, method: str, url: str, *, cap: int,  # noqa: PLR0913 — one leg's parts
                       timeout: float, on_status: Callable[[int], None] | None = None,
                       **send: Any) -> CappedReply:
    """`method` on `url` (`send`: `headers`, `content`, `data`) with a fresh client over `trust`,
    following no redirect and taking nothing from the environment. The reply is asked for
    uncompressed, whatever `send`'s headers ask; its body is read as it arrives on the wire, never
    decoded, and withheld once more than `cap` bytes have arrived, or at its first byte when it
    came compressed anyway: decoding would inflate a chunk whole before any cap (#1383). A reply
    with no body has nothing to withhold. `on_status` hears the status before the body is read.
    `httpx.HTTPError` as raised."""
    headers = httpx.Headers(send.pop("headers", None))
    headers["Accept-Encoding"] = "identity"
    async with httpx.AsyncClient(verify=trust, follow_redirects=False, trust_env=False) as client, \
            client.stream(method, url, timeout=timeout, headers=headers, **send) as reply:
        if on_status is not None:
            on_status(reply.status_code)
        coding = reply.headers.get("Content-Encoding", "")
        compressed = any(c.strip().lower() not in ("", "identity") for c in coding.split(","))
        body = bytearray()
        async for chunk in reply.aiter_raw():
            if compressed:
                return _withheld(reply, f"a compressed body ({coding.strip()})")
            body += chunk
            if len(body) > cap:
                return _withheld(reply, f"more than {cap} bytes")
        return CappedReply(reply.status_code, reply.headers.multi_items(), bytes(body), None)


def _withheld(reply: httpx.Response, why: str) -> CappedReply:
    return CappedReply(reply.status_code, reply.headers.multi_items(), b"", why)


__all__ = ["CappedReply", "capped_reply", "public_trust"]
