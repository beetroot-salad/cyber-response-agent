"""One network leg to a tenant's system (the upstream call, the OAuth token exchange), read up
to a cap (#1163 O7, #1375 O3), over a TLS context built once (#1375 O1).

Building a TLS context loads a trust store and blocks the event loop every leg runs on, so the
proxy builds `public_trust()` once and each leg's fresh client reuses it. A fresh client per leg
keeps nothing from one request to the next: no connection, no cookie."""
from __future__ import annotations

import ssl
from collections.abc import Awaitable, Callable
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


#: Statuses whose reply has no body, whatever its headers declare.
_NO_BODY_STATUSES = (204, 304)
#: Takes one chunk of reply body; returns once the chunk is on its way (it waits on a slow reader).
Sink = Callable[[bytes], Awaitable[None]]


@dataclass(frozen=True)
class StreamedReply:
    """A reply's status and headers, which always arrive, and whether its body was passed on
    whole: `withheld` is None, or the reason that reads after "answered" (`more than N bytes`, or
    `a compressed body (gzip)` when it came compressed though none was asked for, #1383).
    `too_large` is true for the first of those."""

    status: int
    headers: list[tuple[str, str]]
    withheld: str | None
    too_large: bool = False


@dataclass(frozen=True)
class CappedReply:
    """A reply held whole: `body` is empty when `withheld`."""

    status: int
    headers: list[tuple[str, str]]
    body: bytes
    withheld: str | None


def _declared(reply: httpx.Response) -> int | None:
    value = reply.headers.get("Content-Length", "").strip()
    return int(value) if value.isascii() and value.isdigit() else None


def _declares_over(reply: httpx.Response, cap: int) -> bool:
    declared = _declared(reply)
    return declared is not None and declared > cap


def _refusal_of_body(reply: httpx.Response, cap: int) -> StreamedReply | None:
    """Why a body is not passed on, whole or at all: it came compressed (decoding would inflate a
    chunk whole before any cap, #1383), or declares more than `cap`."""
    coding = reply.headers.get("Content-Encoding", "")
    if any(c.strip().lower() not in ("", "identity") for c in coding.split(",")):
        return _withheld(reply, f"a compressed body ({coding.strip()})")
    if _declares_over(reply, cap):
        return _withheld(reply, f"more than {cap} bytes", too_large=True)
    return None


async def stream_reply(trust: ssl.SSLContext, method: str, url: str, *, cap: int,  # noqa: PLR0913 — one leg's parts
                       timeout: float, sink: Sink, on_status: Callable[[int], None] | None = None,
                       **send: Any) -> StreamedReply:
    """`method` on `url` (`send`: `headers`, `content`, `data`) with a fresh client over `trust`,
    following no redirect and taking nothing from the environment. The reply is asked for
    uncompressed, whatever `send`'s headers ask. Its body is read as it arrives on the wire, never
    decoded, and each chunk is handed to `sink` before the next is read, so no more than a chunk
    is held. A reply that can have a body and declares more than `cap` is withheld at its headers,
    with no wait for a body that would be refused; a compressed one at its first body byte (an
    empty one has nothing to withhold); later, so is a reply whose bytes would pass `cap`: that
    chunk and the rest are never handed on. `on_status` hears the status before the body is read.
    `httpx.HTTPError` as raised, and whatever `sink` raises."""
    headers = httpx.Headers(send.pop("headers", None))
    headers["Accept-Encoding"] = "identity"
    async with httpx.AsyncClient(verify=trust, follow_redirects=False, trust_env=False) as client, \
            client.stream(method, url, timeout=timeout, headers=headers, **send) as reply:
        if on_status is not None:
            on_status(reply.status_code)
        if (method.upper() != "HEAD" and reply.status_code not in _NO_BODY_STATUSES
                and _declares_over(reply, cap) and (refused := _refusal_of_body(reply, cap)) is not None):
            return refused
        count = 0
        async for chunk in reply.aiter_raw():
            if count == 0 and (refused := _refusal_of_body(reply, cap)) is not None:
                return refused
            count += len(chunk)
            if count > cap:
                return _withheld(reply, f"more than {cap} bytes", too_large=True)
            await sink(chunk)
        return StreamedReply(reply.status_code, reply.headers.multi_items(), None)


async def capped_reply(trust: ssl.SSLContext, method: str, url: str, *, cap: int,  # noqa: PLR0913 — one leg's parts
                       timeout: float, on_status: Callable[[int], None] | None = None,
                       **send: Any) -> CappedReply:
    """`stream_reply` held whole, for a leg whose reply is small and never reaches the caller (the
    OAuth token exchange)."""
    body = bytearray()

    async def keep(chunk: bytes) -> None:
        body.extend(chunk)

    got = await stream_reply(trust, method, url, cap=cap, timeout=timeout, sink=keep,
                             on_status=on_status, **send)
    return CappedReply(got.status, got.headers, b"" if got.withheld else bytes(body), got.withheld)


def _withheld(reply: httpx.Response, why: str, *, too_large: bool = False) -> StreamedReply:
    return StreamedReply(reply.status_code, reply.headers.multi_items(), why, too_large)


__all__ = ["CappedReply", "Sink", "StreamedReply", "capped_reply", "public_trust", "stream_reply"]
