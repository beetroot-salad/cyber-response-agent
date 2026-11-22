"""The evidence blob store: an S3-compatible bucket (Garage in dev and CI, Hetzner Object Storage in production) holding
objects encrypted server-side with the customer's own key (SSE-C), over `httpx` with a hand-written SigV4 signer (#1546).

One bucket, path-style addressing. Every object is written by one PUT (no multipart) under a 32-byte data key the caller
supplies and the store never keeps: reading, `head`-ing or downloading an object needs the same key. Keys and sizes are
the caller's; this module knows nothing of tenants, claims or the object layout.

Failures are `BlobStoreError`, one family: `status` is the HTTP status (None: no answer), `retryable` says whether the same
request may succeed later (no answer, a 5xx, or a throttle). A missing object is `BlobNotFound`. The data key, the
secret key and the signature never reach a message or a repr.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

from defender.kit.internal_http import internal_client, tls_trust

_S3_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
#: The bytes read from a file at a time while hashing and streaming it.
_CHUNK = 1 << 20
#: At most this much of an error body is kept in a message.
_DETAIL = 200
DATA_KEY_BYTES = 32


class BlobStoreError(Exception):
    """A request the store did not answer as asked: `status` is its HTTP status, None when it gave none."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status

    @property
    def retryable(self) -> bool:
        """The same request may succeed later: the store did not answer, failed (5xx) or throttled (429)."""
        return self.status is None or self.status >= 500 or self.status == 429


class BlobNotFound(BlobStoreError):
    """The object is not in the bucket (HTTP 404)."""


def _signing_key(secret: str, date: str, region: str) -> bytes:
    key = ("AWS4" + secret).encode()
    for part in (date, region, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return key


def _sse_headers(data_key: bytes) -> dict[str, str]:
    if not isinstance(data_key, bytes) or len(data_key) != DATA_KEY_BYTES:
        raise ValueError(f"an SSE-C data key is {DATA_KEY_BYTES} bytes")
    return {
        "x-amz-server-side-encryption-customer-algorithm": "AES256",
        "x-amz-server-side-encryption-customer-key": base64.b64encode(data_key).decode(),
        # S3 requires the key's MD5 as a transport check, not as a security measure.
        "x-amz-server-side-encryption-customer-key-md5": base64.b64encode(hashlib.md5(data_key).digest()).decode(),  # noqa: S324
    }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as source:
        while chunk := source.read(_CHUNK):
            yield chunk


class BlobStore:
    """A client of one bucket. `endpoint` is the store's base URL (no bucket, no trailing slash needed)."""

    def __init__(self, endpoint: str, bucket: str, access_key: str, secret_key: str, region: str, *,
                 timeout: float = 60.0) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.username or parts.password:
            raise ValueError("the blob store endpoint is an http(s) URL without credentials")
        if not (bucket and access_key and secret_key and region):
            raise ValueError("the blob store needs a bucket, an access key, a secret key and a region")
        self._endpoint = f"{parts.scheme}://{parts.netloc}"
        self._host = parts.netloc
        self._bucket = bucket
        self._access_key = access_key
        self._secret_key = secret_key
        self._region = region
        self._timeout = timeout
        self._http: httpx.Client | None = None

    def __repr__(self) -> str:
        return f"BlobStore(endpoint={self._endpoint!r}, bucket={self._bucket!r})"

    # --- requests -------------------------------------------------------------------------------------------------

    def _client(self) -> httpx.Client:
        if self._http is None:
            self._http = internal_client(trust=tls_trust(), timeout=self._timeout)
        return self._http

    def _signed(self, method: str, key: str, query: dict[str, str], payload_hash: str,
                extra: dict[str, str]) -> tuple[str, dict[str, str]]:
        path = f"/{self._bucket}" + (f"/{quote(key, safe='/~')}" if key else "")
        canonical_query = "&".join(f"{quote(k, safe='~')}={quote(v, safe='~')}" for k, v in sorted(query.items()))
        now = dt.datetime.now(dt.UTC)
        stamp, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        headers = {"host": self._host, "x-amz-content-sha256": payload_hash, "x-amz-date": stamp, **extra}
        names = sorted(headers)
        canonical = "\n".join([method, path, canonical_query,
                               "".join(f"{n}:{headers[n].strip()}\n" for n in names),
                               ";".join(names), payload_hash])
        scope = f"{date}/{self._region}/s3/aws4_request"
        to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
        signature = hmac.new(_signing_key(self._secret_key, date, self._region), to_sign.encode(),
                             hashlib.sha256).hexdigest()
        headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={self._access_key}/{scope}, "
                                    f"SignedHeaders={';'.join(names)}, Signature={signature}")
        return f"{self._endpoint}{path}" + (f"?{canonical_query}" if canonical_query else ""), headers

    def _send(self, method: str, key: str = "", *, query: dict[str, str] | None = None, body: bytes | Path = b"",
              sha256: str | None = None, headers: dict[str, str] | None = None, stream: bool = False) -> httpx.Response:
        """One signed request; a transport failure is a retryable `BlobStoreError`. `stream`: the body is left to read."""
        extra = dict(headers or {})
        if isinstance(body, Path):
            payload_hash = sha256 or _file_sha256(body)
            extra["content-length"] = str(body.stat().st_size)
            content: bytes | Iterator[bytes] = _chunks(body)
        else:
            payload_hash = sha256 or hashlib.sha256(body).hexdigest()
            content = body
        url, signed = self._signed(method, key, query or {}, payload_hash, extra)
        signed.pop("host")  # httpx sets it; it is signed all the same
        try:
            request = self._client().build_request(method, url, headers=signed, content=content)
            return self._client().send(request, stream=stream)
        except httpx.HTTPError as down:
            raise BlobStoreError(f"{method} on the evidence store failed: {type(down).__name__}") from down
        except OSError as unreadable:  # the file being sent could not be read
            raise BlobStoreError(f"{method} on the evidence store could not read its source: "
                                 f"{unreadable.strerror or type(unreadable).__name__}") from None

    @staticmethod
    def _check(reply: httpx.Response, what: str, ok: tuple[int, ...] = (200,)) -> httpx.Response:
        if reply.status_code in ok:
            return reply
        if not reply.is_closed:
            reply.read()
        detail = reply.text[:_DETAIL].replace("\n", " ")
        if reply.status_code == 404:
            raise BlobNotFound(f"{what}: no such object", status=404)
        raise BlobStoreError(f"{what}: the evidence store answered HTTP {reply.status_code} {detail}".rstrip(),
                             status=reply.status_code)

    # --- objects --------------------------------------------------------------------------------------------------

    def put(self, key: str, data: bytes | Path, *, data_key: bytes, sha256: str | None = None) -> None:
        """Store `data` (bytes, or a file streamed from disk) under `key`, encrypted with `data_key`, in one PUT.
        `sha256` (hex) is the data's digest when the caller already holds it; else it is computed here."""
        reply = self._send("PUT", key, body=data, sha256=sha256, headers=_sse_headers(data_key))
        self._check(reply, f"put {key}")

    def get(self, key: str, *, data_key: bytes) -> bytes:
        """The object's bytes; `BlobNotFound` when there is none."""
        reply = self._send("GET", key, headers=_sse_headers(data_key))
        return self._check(reply, f"get {key}").content

    def download(self, key: str, dest: Path, *, data_key: bytes) -> int:
        """Write the object to the new file `dest` (never overwriting: `FileExistsError`); its size. A partial file is
        removed when the transfer fails."""
        reply = self._send("GET", key, headers=_sse_headers(data_key), stream=True)
        try:
            self._check(reply, f"get {key}")
            size = 0
            try:
                with dest.open("xb") as out:
                    for chunk in reply.iter_bytes(_CHUNK):
                        out.write(chunk)
                        size += len(chunk)
            except httpx.HTTPError as down:
                dest.unlink(missing_ok=True)
                raise BlobStoreError(f"get {key} failed while reading: {type(down).__name__}") from down
            return size
        finally:
            reply.close()

    def head(self, key: str, *, data_key: bytes | None = None) -> int | None:
        """The object's size in bytes, or None when there is none. A keyed object needs its `data_key`."""
        reply = self._send("HEAD", key, headers=_sse_headers(data_key) if data_key is not None else None)
        if reply.status_code == 404:
            return None
        self._check(reply, f"head {key}")
        return int(reply.headers.get("content-length", "0"))

    def delete(self, key: str) -> None:
        """Remove the object; none there is not a fault."""
        self._check(self._send("DELETE", key), f"delete {key}", ok=(200, 204, 404))

    def keys(self, prefix: str = "") -> list[str]:
        """Every key under `prefix`, in the store's order (all pages)."""
        found: list[str] = []
        token = ""
        while True:
            query = {"list-type": "2", "prefix": prefix}
            if token:
                query["continuation-token"] = token
            reply = self._check(self._send("GET", query=query), f"list {prefix}")
            try:
                root = ET.fromstring(reply.content)  # noqa: S314 — the deployment's own store
            except ET.ParseError as bad:
                raise BlobStoreError("list: the evidence store's answer is not XML", status=reply.status_code) from bad
            found += [e.findtext(f"{_S3_NS}Key") or "" for e in root.iter(f"{_S3_NS}Contents")]
            if root.findtext(f"{_S3_NS}IsTruncated") != "true":
                return found
            token = root.findtext(f"{_S3_NS}NextContinuationToken") or ""
            if not token:
                raise BlobStoreError("list: a truncated page named no continuation", status=reply.status_code)

    def delete_prefix(self, prefix: str) -> int:
        """Remove every object under `prefix` (never the empty prefix: that is the bucket); how many were listed."""
        if not prefix:
            raise ValueError("delete_prefix needs a prefix: the empty one is the whole bucket")
        keys = self.keys(prefix)
        for key in keys:
            self.delete(key)
        return len(keys)


__all__ = ["DATA_KEY_BYTES", "BlobNotFound", "BlobStore", "BlobStoreError"]
