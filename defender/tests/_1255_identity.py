"""#1255 — an identity under its obvious encodings (O2, P3). Defines no tests.

A scan for an identity's LITERAL spelling is lexical: an implementation that writes a derived
form of it — a hex digest of the world token, a uuid3/uuid5 over it, its bytes in hex or base64,
or a record holding it base64-encoded inside a larger blob — carries the same identity past a
substring match (contract-repair findings F-Q1, F-P3b and R-2 of the #1255 adversary; the shape
of the lexical-where-structural deck entry from PR #1090). These helpers widen such a scan to
those forms, and see through zlib, gzip and raw-deflate compression of an encoded run or of a
whole file (finding F2-Q of pass 2: the join, zlib-compressed inside base64, decoded to bytes
that never spelled the id).

An encoded scan stays a lost cause against an implementation that wants to hide: any invertible
transform (XOR, a reversal, a cipher) beats it. It is the second check; where a test can say
what a folder may hold, the structural listing (`_1255_run_records`) is the first.

They decide nothing production owns: the identities scanned for are always the test's own (a
ledger's call ids, an episode's id and tokens, a layout's run ids), and every form below is a
stdlib transform of one. Stdlib only, so the twin check's child process can import it.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import uuid
import zlib
from collections.abc import Iterable, Mapping

#: The digests a writer reaches for to turn a name into an opaque id.
_DIGESTS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s",
            "sha3_256")
#: The stdlib's uuid namespaces (`uuid3` / `uuid5` over a name).
_NAMESPACES = {"dns": uuid.NAMESPACE_DNS, "url": uuid.NAMESPACE_URL,
               "oid": uuid.NAMESPACE_OID, "x500": uuid.NAMESPACE_X500}
#: A run of base64 (standard or url-safe) characters long enough to hold an encoded identity.
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
#: A run of hex digit pairs long enough to hold an encoded identity, not glued to more hex.
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
#: The compressed containers a writer reaches for, by `zlib` window bits: zlib or gzip (47 =
#: 32 + 15, the header picks which) and raw deflate (-15).
_INFLATE_WBITS = (47, -15)
#: The most bytes one decoded run (or one file) inflates to, and the most one scan inflates in
#: all: a large or hostile input costs a bounded scan, never unbounded memory.
_INFLATE_CAP = 1 << 20
_INFLATE_BUDGET = 16 << 20


def derived_forms(token: str) -> dict[str, str]:
    """`token`'s derived spellings, keyed by how each is made: every digest's hex (whole, and
    its 32- and 16-character prefixes — a truncated digest is the usual "short id"), uuid3 and
    uuid5 over it in each stdlib namespace (hyphenated and bare hex), and its UTF-8 bytes in hex,
    base64, url-safe base64 and base32 (unpadded)."""
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
    """`raw` decompressed as each container `_INFLATE_WBITS` names that accepts it (zlib, gzip,
    raw deflate), each output capped at `_INFLATE_CAP` bytes and all of them together at what
    is left of `budget` (a one-item list the caller shares across a scan; a fresh
    `_INFLATE_BUDGET` when left out). Bytes that are not a compressed stream inflate to
    nothing; a raw-deflate read of noise that happens to parse yields noise, which matches no
    identity."""
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
    """Every run of 16+ base64 or hex characters in `text`, decoded (UTF-8, undecodable bytes
    replaced) — what an identity written encoded inside a larger value reads as — and, where
    the decoded bytes are a zlib, gzip or raw-deflate stream, inflated (`_inflated`; one
    `_INFLATE_BUDGET` for the whole call). A run is tried from each of its first four offsets,
    since a base64 blob glued to a word starts mid-group. Decoded text is searched again,
    `depth` levels deep (a base64 record inside a JSON line inside compressed base64)."""
    return _views(text, depth, [_INFLATE_BUDGET])


def encoded_form(text: str, token: str, *, views: list[str] | None = None,
                 ) -> tuple[str, int] | None:
    """`(how, where)` when `text` carries `token` under an obvious encoding rather than
    literally: one of its derived forms (`derived_forms`; hex forms matched case-blind) at
    offset `where`, or inside a base64/hex run once decoded (`where` 0). `views` is
    `decoded_views(text)` when the caller already has it (one decode per text, not per
    token). `None` otherwise."""
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
    """Which of `tokens` (label -> identity) `text` carries in any spelling: literally, as one
    of its derived forms, or inside an encoded run. Each hit is `"<label> (<how>)"`."""
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
    """`{relative path: hits}` for every `(path, bytes)` whose content carries one of `tokens`
    in any spelling (`encoded_hits`) — read as text, and, where the whole file is a zlib, gzip
    or raw-deflate stream, as each inflation of it (a hit there is labelled `inflated file`)."""
    found: dict[str, list[str]] = {}
    for rel, data in paths:
        hits = encoded_hits(data.decode("utf-8", "replace"), tokens)
        for whole in _inflated(data):
            hits += [f"{hit}, inflated file"
                     for hit in encoded_hits(whole.decode("utf-8", "replace"), tokens)]
        if hits:
            found[rel] = hits
    return found
