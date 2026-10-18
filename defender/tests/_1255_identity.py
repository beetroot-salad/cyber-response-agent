"""Detect literal and derived identities, including bounded decoding and decompression."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import uuid
import zlib
from collections.abc import Iterable, Mapping

_DIGESTS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s",
            "sha3_256")
_NAMESPACES = {"dns": uuid.NAMESPACE_DNS, "url": uuid.NAMESPACE_URL,
               "oid": uuid.NAMESPACE_OID, "x500": uuid.NAMESPACE_X500}
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_INFLATE_WBITS = (47, -15)
_INFLATE_CAP = 1 << 20
_INFLATE_BUDGET = 16 << 20


def derived_forms(token: str) -> dict[str, str]:
    """Generate digests, digest prefixes, namespace UUIDs, and byte encodings of a token."""
    raw = token.encode("utf-8")
    out: dict[str, str] = {}
    for name in _DIGESTS:
        digest = hashlib.new(name, raw).hexdigest()
        out[f"{name} hex"] = digest
        for width in (32, 16):
            if len(digest) > width:
                out[f"{name} hex[:{width}]"] = digest[:width]
    for ns_name, namespace in _NAMESPACES.items():
        for maker in (uuid.uuid3, uuid.uuid5):
            made = maker(namespace, token)
            out[f"{maker.__name__}({ns_name})"] = str(made)
            out[f"{maker.__name__}({ns_name}) hex"] = made.hex
    out["hex bytes"] = raw.hex()
    out["base64"] = base64.b64encode(raw).decode("ascii").rstrip("=")
    out["base64url"] = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    out["base32"] = base64.b32encode(raw).decode("ascii").rstrip("=")
    return out


def _b64(run: str) -> bytes | None:
    body = run.rstrip("=").replace("-", "+").replace("_", "/")
    body += "=" * (-len(body) % 4)
    try:
        return base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return None


def _inflated(raw: bytes, budget: list[int] | None = None) -> list[bytes]:
    """Decode zlib, gzip, and raw deflate within per-output and shared scan budgets."""
    left = budget if budget is not None else [_INFLATE_BUDGET]
    out: list[bytes] = []
    for wbits in _INFLATE_WBITS:
        if left[0] <= 0 or len(raw) < 2:
            break
        try:
            data = zlib.decompressobj(wbits).decompress(raw, min(_INFLATE_CAP, left[0]))
        except zlib.error:
            continue
        if data:
            left[0] -= len(data)
            out.append(data)
    return out


def _binary_views(raw: bytes, budget: list[int]) -> list[str]:
    """`raw` as text (UTF-8, undecodable bytes replaced), then each of its inflations."""
    return [raw.decode("utf-8", "replace"),
            *(data.decode("utf-8", "replace") for data in _inflated(raw, budget))]


def _views(text: str, depth: int, budget: list[int]) -> list[str]:
    views: list[str] = []
    for run in _B64_RUN.findall(text):
        for skip in range(4):
            raw = _b64(run[skip:])
            if raw:
                views += _binary_views(raw, budget)
    for run in _HEX_RUN.findall(text):
        views += _binary_views(bytes.fromhex(run), budget)
    if depth > 1:
        views += [inner for view in list(views) for inner in _views(view, depth - 1, budget)]
    return views


def decoded_views(text: str, *, depth: int = 2) -> list[str]:
    """Decode embedded base64 and hex, including bounded recursive decompression."""
    return _views(text, depth, [_INFLATE_BUDGET])


def encoded_form(text: str, token: str, *, views: list[str] | None = None,
                 ) -> tuple[str, int] | None:
    """Find a derived token spelling or decoded token, returning its encoding and offset."""
    lowered = text.lower()
    for how, form in derived_forms(token).items():
        at = text.find(form)
        if at < 0 and _is_hex(form):
            at = lowered.find(form)
        if at >= 0:
            return how, at
    if any(token in view for view in (views if views is not None else decoded_views(text))):
        return "inside an encoded run", 0
    return None


def encoded_hits(text: str, tokens: Mapping[str, str]) -> list[str]:
    """List identities found literally, in derived forms, or inside encoded data."""
    hits: list[str] = []
    views: list[str] | None = None
    for label, token in tokens.items():
        if not token:
            continue
        if token in text:
            hits.append(f"{label} (literal)")
            continue
        if views is None:
            views = decoded_views(text)
        found = encoded_form(text, token, views=views)
        if found is not None:
            hits.append(f"{label} ({found[0]})")
    return hits


def _is_hex(form: str) -> bool:
    return all(c in "0123456789abcdef-" for c in form)


def files_carrying(paths: Iterable[tuple[str, bytes]], tokens: Mapping[str, str],
                   ) -> dict[str, list[str]]:
    """Report identities in file text and whole-file compressed data."""
    found: dict[str, list[str]] = {}
    for rel, data in paths:
        hits = encoded_hits(data.decode("utf-8", "replace"), tokens)
        for whole in _inflated(data):
            hits += [f"{hit}, inflated file"
                     for hit in encoded_hits(whole.decode("utf-8", "replace"), tokens)]
        if hits:
            found[rel] = hits
    return found
