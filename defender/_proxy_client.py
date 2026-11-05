"""The credential proxy's reply format (#1412) and the caller's side of the proxy (#1163): one POST
of a request to it, and its answer. Holds no credential and decides nothing: the proxy classifies
every outcome and names its fault class, which the caller raises as its own.

A reply is frames, each `<tag: 1 byte><length: 4 bytes, big-endian><payload>`: zero or more body
frames (tag `B`, upstream bytes) and then exactly one final frame (tag `F`, a JSON `FinalRecord`).
Every frame is length-delimited and the final one ends the reply, so no upstream byte is ever read
as the proxy's own record (P2), and a reply that stops early, or runs on past its final frame, is
refused."""
from __future__ import annotations

import contextlib
import functools
import json
import struct
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass, fields
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
#: The media type of every reply the proxy makes; the caller refuses any other (O9).
REPLY_CONTENT_TYPE = "application/vnd.defender.proxy-reply"

_BODY, _FINAL = b"B", b"F"
_HEAD = struct.Struct(">cI")


@dataclass(frozen=True)
class FinalRecord:
    """The proxy's one record of how a request ended, last in the reply. Every field is
    required: no arm of the proxy and no fake of it can leave one out. `body_whole` is true if
    and only if the body frames carry the complete body (an empty one included). `sent` is false
    only when the proxy never began the system's call or never connected to it (#1374)."""

    status: int | None
    headers: Mapping[str, str]
    fault: str | None
    detail: str | None
    system_side: bool
    sent: bool
    body_whole: bool


_FIELDS = tuple(f.name for f in fields(FinalRecord))


@dataclass(frozen=True)
class DecodedReply:
    """A whole reply: the body frames' bytes, in order, and the final record."""

    chunks: list[bytes]
    final: FinalRecord


def encode_body(chunk: bytes) -> bytes:
    """`chunk`, upstream bytes, as one body frame."""
    return _HEAD.pack(_BODY, len(chunk)) + chunk


def encode_final(record: FinalRecord) -> bytes:
    """`record` as the final frame."""
    payload = json.dumps(asdict(record)).encode("utf-8")
    return _HEAD.pack(_FINAL, len(payload)) + payload


def decode_reply(raw: bytes) -> DecodedReply:
    """The frames of the whole reply `raw`. `ValueError` for anything malformed: a frame cut
    short, an unknown tag, no final frame, anything after it, a final record that is not exactly
    its fields. Nothing is allocated from a length prefix."""
    chunks: list[bytes] = []
    at, end = 0, len(raw)
    while at < end:
        if end - at < _HEAD.size:
            raise ValueError("a frame header is cut short")
        tag, size = _HEAD.unpack_from(raw, at)
        at += _HEAD.size
        if end - at < size:
            raise ValueError("a frame is cut short")
        payload, at = raw[at:at + size], at + size
        if tag == _BODY:
            chunks.append(payload)
        elif tag == _FINAL:
            if at != end:
                raise ValueError("bytes follow the final frame")
            return DecodedReply(chunks, _record_of(payload))
        else:
            raise ValueError("a frame has an unknown tag")
    raise ValueError("the reply has no final frame")


def _record_of(payload: bytes) -> FinalRecord:
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ValueError("the final frame is not JSON") from None
    if not isinstance(doc, dict) or set(doc) != set(_FIELDS):
        raise ValueError("the final record is not exactly its fields")
    status, headers, detail = doc["status"], doc["headers"], doc["detail"]
    if (isinstance(status, bool) or not (status is None or isinstance(status, int))
            or not isinstance(headers, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in headers.items())
            or not (doc["fault"] is None or isinstance(doc["fault"], str))
            or not (detail is None or isinstance(detail, str))
            or not all(isinstance(doc[k], bool) for k in ("system_side", "sent", "body_whole"))):
        raise ValueError("a field of the final record has the wrong type")
    return FinalRecord(**doc)


@dataclass(frozen=True)
class ProxyAnswer:
    """The proxy's answer: the upstream's status, headers and body, or the fault
    class the proxy refused or classified the request as, with its detail."""

    status: int
    headers: Mapping[str, str]
    body: str
    fault: str | None
    detail: str
    #: The proxy marked a status-less refusal as the target system's call failing (#1404).
    system_side: bool = False
    #: May the request have reached the target system (#1374)? False only when the proxy says it
    #: never began the system's call or never connected to it; an older proxy that does not say is
    #: taken as "may".
    sent: bool = True

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


@contextlib.contextmanager
def _before_sending() -> Iterator[None]:
    """Every transport fault raised inside happened before the request left the run, so it never
    reached the system (`maybe_delivered` false, #1374)."""
    try:
        yield
    except TransportFault as fault:
        fault.maybe_delivered = False
        raise


@_the_proxys_own()
def proxy_call(  # noqa: PLR0913 — one request's per-call state
    proxy_url: str | None, token: str | None, *, system: str, method: str, url: str,
    headers: Mapping[str, str] | None = None, body: str | None = None, timeout_sec: int = 10,
) -> ProxyAnswer:
    """POST the request to the proxy with `token` and the system's `timeout_sec`, which the proxy
    runs the request inside (r7 A21); `caller_wait_sec` bounds each wait for the proxy's bytes, and
    the proxy's own deadline bounds a healthy exchange. The whole reply is read, then decoded
    once; the body is kept only when the proxy's final record says it is whole. `TransportFault`,
    the proxy's own (`proxy_own`), when no address or token was handed to the caller, the proxy
    cannot be reached, its reply breaks, or its answer is not the proxy's."""
    if not proxy_url or not token:
        raise TransportFault("no credential proxy address or request token was handed to this call",
                             maybe_delivered=False)
    status_code, kind, raw = _post(proxy_url, token, {
        "system": system, "method": method, "url": url, "headers": dict(headers or {}),
        "body": body, "timeout_sec": timeout_sec}, caller_wait_sec(timeout_sec))
    if status_code != 200:
        raise TransportFault(f"credential proxy answered HTTP {status_code}")
    if kind != REPLY_CONTENT_TYPE:
        raise TransportFault("credential proxy answered in a format that is not the proxy's reply")
    try:
        reply = decode_reply(raw)
    except ValueError:
        raise TransportFault("credential proxy's reply broke: it is not whole") from None
    final = reply.final
    return ProxyAnswer(
        status=final.status or 0, headers=dict(final.headers),
        body=b"".join(reply.chunks).decode("utf-8", "replace") if final.body_whole else "",
        fault=final.fault, detail=final.detail or "", system_side=final.system_side,
        sent=final.sent)


def _post(proxy_url: str, token: str, doc: Mapping[str, object],
          timeout: float) -> tuple[int, str, bytes]:
    """(HTTP status, media type, whole body) of one POST. Failing before the response head is
    "unreachable"; failing after it is the reply breaking."""
    try:
        stream = _client().stream(
            "POST", proxy_url.rstrip("/") + PROXY_PATH,
            headers={"Authorization": f"Bearer {token}"}, json=doc, timeout=timeout)
        response = stream.__enter__()
    except httpx.HTTPError as e:
        # Never connected to the proxy: the request went nowhere (#1374). Any later failure may
        # follow the proxy's call to the system.
        raise TransportFault(
            f"credential proxy unreachable: {type(e).__name__}",
            maybe_delivered=not isinstance(e, httpx.ConnectError | httpx.ConnectTimeout),
        ) from None
    try:
        kind = response.headers.get("content-type", "").split(";")[0].strip().lower()
        return response.status_code, kind, b"".join(response.iter_raw())
    except httpx.HTTPError as e:
        raise TransportFault(
            f"credential proxy's reply broke: {type(e).__name__}") from None
    finally:
        stream.__exit__(None, None, None)


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
    with _the_proxys_own(), _before_sending():
        token = token_of(ctx)
    return proxy_call(
        ctx.proxy_url, token, system=system, method=method, url=url,
        headers={"Accept": "application/json"}
        | ({"Content-Type": "application/json"} if body is not None else {}),
        body=request_body(body), timeout_sec=timeout_sec)


__all__ = ["PROXY_PATH", "REPLY_CONTENT_TYPE", "DecodedReply", "FinalRecord", "ProxyAnswer", "decode_reply", "encode_body", "encode_final", "proxy_call", "proxy_exchange", "request_body", "token_of", "uses_proxy"]
