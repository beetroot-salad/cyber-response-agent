"""#1546 evidence-store test machinery: a real Garage (S3) to assert against and OpenBao key helpers.

Interface (other slices code against this; test-only, never imported by production):

Env (marker `garage`; skips where unset locally, fails where unset in CI; CI's test job exports them):
  DEFENDER_TEST_GARAGE_ENDPOINT   e.g. http://127.0.0.1:3900 (path-style addressing)
  DEFENDER_TEST_GARAGE_ACCESS_KEY / DEFENDER_TEST_GARAGE_SECRET_KEY / DEFENDER_TEST_GARAGE_BUCKET
  DEFENDER_TEST_GARAGE_REGION     optional, default `garage`
  The `openbao` marker's DEFENDER_TEST_OPENBAO_* variables serve the key helpers. Garage variables stay in
  `os.environ` (unlike OpenBao's), so a test may hand them on to a process it launches.

Fixtures (import into the directory's conftest: `from ...support.evidence._evidence1546 import garage, evidence_keys`):
  garage() -> Garage            this test's slice of the shared bucket; objects it tracked are deleted at the end
  evidence_keys(openbao) -> EvidenceKeys   transit keys `evidence-<tenant>`; destroyed at the end

Garage:
  .endpoint, .bucket, .access_key, .secret_key, .region, .tag      (tag: fresh per test)
  .tenant_prefix(tenant_id) -> "t/<tenant_id>/"   the store's key layout root; tracked for cleanup, so a test
                                    isolates by using a fresh tenant uuid (the store never needs a prefix of ours)
  .key(name) -> "s0-<tag>/<name>"   a key under this test's own prefix, for planted objects; tracked
  .track(prefix)                    also delete everything under `prefix` at the end
  .list(prefix="") -> list[str]     every key under `prefix` (paged)
  .head(key, *, sse_key=None) -> httpx.Response     (status 200 / 404; SSE-C HEAD needs the key)
  .get(key, *, sse_key=None) -> httpx.Response      response.content; a keyed object read without sse_key is 400
  .put(key, body, *, sse_key=None) -> httpx.Response   plant an object (raw, or SSE-C when sse_key given)
  .delete(key) / .delete_prefix(prefix)
  `sse_key` is the 32-byte customer key (bytes); the client sends it base64 with its MD5 as S3 requires.
  `new_sse_key() -> bytes`: random 32 bytes (module function).

EvidenceKeys (OpenBao `transit/`, for tests verifying wrapping only; production never calls this):
  .make(tenant_id)                  create transit key `evidence-<tenant_id>` (aes256-gcm96)
  .datakey(tenant_id) -> DataKey(plaintext: bytes, wrapped: str)   `transit/datakey/plaintext/<key>`
  .unwrap(tenant_id, wrapped, *, token=None) -> bytes             `transit/decrypt/<key>` (default root token)
  .destroy(tenant_id)               held by count across tests (the transit path is shared): the last holder deletes it
  .key_name(tenant_id) -> "evidence-<tenant_id>"   the design's naming rule, spelled here
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import hmac
import os
import tempfile
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote, urlsplit

import pytest

from defender.tests.support.shared._openbao1163 import TRANSIT_MOUNT, Bao

if TYPE_CHECKING:
    import httpx

ENDPOINT_ENV = "DEFENDER_TEST_GARAGE_ENDPOINT"
ACCESS_KEY_ENV = "DEFENDER_TEST_GARAGE_ACCESS_KEY"
SECRET_KEY_ENV = "DEFENDER_TEST_GARAGE_SECRET_KEY"
BUCKET_ENV = "DEFENDER_TEST_GARAGE_BUCKET"
REGION_ENV = "DEFENDER_TEST_GARAGE_REGION"

_S3_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def new_sse_key() -> bytes:
    return os.urandom(32)


def _sign_key(secret: str, date: str, region: str) -> bytes:
    key = ("AWS4" + secret).encode()
    for part in (date, region, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return key


@dataclass
class Garage:
    """A SigV4 S3 client (path-style, one `httpx` call per request) over one test's slice of the bucket."""

    endpoint: str
    access_key: str
    secret_key: str
    bucket: str
    region: str = "garage"
    tag: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    prefixes: list[str] = field(default_factory=list)

    def tenant_prefix(self, tenant_id: str) -> str:
        prefix = f"t/{tenant_id}/"
        self.track(prefix)
        return prefix

    def key(self, name: str) -> str:
        prefix = f"s0-{self.tag}/"
        self.track(prefix)
        return prefix + name

    def track(self, prefix: str) -> None:
        if prefix not in self.prefixes:
            self.prefixes.append(prefix)

    def _request(self, method: str, key: str = "", *, query: dict[str, str] | None = None,
                 body: bytes = b"", headers: dict[str, str] | None = None,
                 sse_key: bytes | None = None) -> httpx.Response:
        import httpx

        host = urlsplit(self.endpoint).netloc
        path = f"/{self.bucket}" + (f"/{quote(key, safe='/~')}" if key else "")
        canonical_query = "&".join(f"{quote(k, safe='~')}={quote(v, safe='~')}"
                                   for k, v in sorted((query or {}).items()))
        now = dt.datetime.now(dt.UTC)
        stamp, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body).hexdigest()
        hdrs = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": stamp}
        if sse_key is not None:
            hdrs["x-amz-server-side-encryption-customer-algorithm"] = "AES256"
            hdrs["x-amz-server-side-encryption-customer-key"] = base64.b64encode(sse_key).decode()
            hdrs["x-amz-server-side-encryption-customer-key-md5"] = base64.b64encode(
                hashlib.md5(sse_key).digest()).decode()  # noqa: S324 — S3 requires MD5 here
        hdrs.update({k.lower(): v for k, v in (headers or {}).items()})
        names = sorted(hdrs)
        canonical = "\n".join([method, path, canonical_query,
                               "".join(f"{n}:{hdrs[n].strip()}\n" for n in names),
                               ";".join(names), payload_hash])
        scope = f"{date}/{self.region}/s3/aws4_request"
        to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope,
                             hashlib.sha256(canonical.encode()).hexdigest()])
        signature = hmac.new(_sign_key(self.secret_key, date, self.region), to_sign.encode(),
                             hashlib.sha256).hexdigest()
        hdrs["authorization"] = (f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
                                 f"SignedHeaders={';'.join(names)}, Signature={signature}")
        url = f"{self.endpoint}{path}" + (f"?{canonical_query}" if canonical_query else "")
        return httpx.request(method, url, content=body, headers=hdrs, timeout=30)

    def list(self, prefix: str = "") -> list[str]:
        keys: list[str] = []
        token = ""
        while True:
            query = {"list-type": "2", "prefix": prefix}
            if token:
                query["continuation-token"] = token
            reply = self._request("GET", query=query)
            assert reply.status_code == 200, (reply.status_code, reply.text)
            root = ET.fromstring(reply.content)
            keys += [e.findtext(f"{_S3_NS}Key") or "" for e in root.iter(f"{_S3_NS}Contents")]
            if root.findtext(f"{_S3_NS}IsTruncated") != "true":
                return keys
            token = root.findtext(f"{_S3_NS}NextContinuationToken") or ""

    def head(self, key: str, *, sse_key: bytes | None = None) -> httpx.Response:
        return self._request("HEAD", key, sse_key=sse_key)

    def get(self, key: str, *, sse_key: bytes | None = None) -> httpx.Response:
        return self._request("GET", key, sse_key=sse_key)

    def put(self, key: str, body: bytes, *, sse_key: bytes | None = None) -> httpx.Response:
        reply = self._request("PUT", key, body=body, sse_key=sse_key)
        assert reply.status_code == 200, (reply.status_code, reply.text)
        return reply

    def delete(self, key: str) -> None:
        reply = self._request("DELETE", key)
        assert reply.status_code in (200, 204), (reply.status_code, reply.text)

    def delete_prefix(self, prefix: str) -> None:
        for key in self.list(prefix):
            self.delete(key)


def server() -> Garage:
    """The test server's client; skipped where no variable is set, but never in CI."""
    values = [os.environ.get(n) for n in (ENDPOINT_ENV, ACCESS_KEY_ENV, SECRET_KEY_ENV, BUCKET_ENV)]
    if not all(values):
        if os.environ.get("CI"):
            pytest.fail(f"{ENDPOINT_ENV}/{ACCESS_KEY_ENV}/{SECRET_KEY_ENV}/{BUCKET_ENV} are not set in "
                        "CI; the test job's Garage step provides them")
        pytest.skip(f"{ENDPOINT_ENV}/{ACCESS_KEY_ENV}/{SECRET_KEY_ENV}/{BUCKET_ENV} are not set")
    endpoint, access, secret, bucket = values
    return Garage(endpoint.rstrip("/"), access, secret, bucket,  # type: ignore[union-attr]
                  os.environ.get(REGION_ENV) or "garage")


@pytest.fixture
def garage() -> Iterator[Garage]:
    """This test's slice of the Garage bucket (marker `garage`)."""
    store = server()
    try:
        store.list("s0-probe/")  # reachable and the key may read the bucket; else fail, even locally
    except Exception as err:  # noqa: BLE001 — set but unreachable is a failure, not a skip
        pytest.fail(f"Garage at {store.endpoint} is set but unusable: {err!r}")
    try:
        yield store
    finally:
        for prefix in store.prefixes:
            store.delete_prefix(prefix)


@dataclass(frozen=True)
class DataKey:
    plaintext: bytes
    wrapped: str


@dataclass
class EvidenceKeys:
    """Transit helpers over the `openbao` fixture's server; test-only, to verify wrapping (A-O5)."""

    bao: Bao
    made: list[str] = field(default_factory=list)

    def key_name(self, tenant_id: str) -> str:
        return f"evidence-{tenant_id}"

    def make(self, tenant_id: str) -> None:
        """Create the key (or join it: creating a key that exists changes nothing). The transit path is the deployment's
        fixed one (A25), shared by every test and xdist worker, and many scenes share the published fixture's tenant id;
        so the key is held by count across processes and deleted when its last holder ends (`destroy`)."""
        with _key_hold(self.key_name(tenant_id)) as held:
            self.bao.ok("POST", f"{TRANSIT_MOUNT}/keys/{self.key_name(tenant_id)}", json={})
            held(+1)
        self.made.append(tenant_id)

    def datakey(self, tenant_id: str, *, token: str | None = None) -> DataKey:
        body = self.bao.ok("POST", f"{TRANSIT_MOUNT}/datakey/plaintext/{self.key_name(tenant_id)}",
                           token=token, json={"bits": 256})["data"]
        return DataKey(base64.b64decode(body["plaintext"]), body["ciphertext"])

    def unwrap(self, tenant_id: str, wrapped: str, *, token: str | None = None) -> bytes:
        body = self.bao.ok("POST", f"{TRANSIT_MOUNT}/decrypt/{self.key_name(tenant_id)}",
                           token=token, json={"ciphertext": wrapped})["data"]
        return base64.b64decode(body["plaintext"])

    def destroy(self, tenant_id: str) -> None:
        """Release this test's hold on the key; the last holder deletes it (another test's live key is never pulled)."""
        with _key_hold(self.key_name(tenant_id)) as held:
            if held(-1) > 0:
                return
            key = f"{TRANSIT_MOUNT}/keys/{self.key_name(tenant_id)}"
            self.bao.call("POST", f"{key}/config", json={"deletion_allowed": True})
            self.bao.call("DELETE", key)


@contextlib.contextmanager
def _key_hold(name: str) -> Iterator[Callable[[int], int]]:
    """A cross-process count of the tests holding transit key `name`, under an exclusive file lock: `held(delta)` adds
    `delta` and answers the new count (never below 0)."""
    folder = Path(tempfile.gettempdir()) / "defender-test-evidence-keys"
    folder.mkdir(exist_ok=True)
    count = folder / f"{name}.count"
    with open(folder / f"{name}.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            def held(delta: int) -> int:
                now = max(0, (int(count.read_text() or 0) if count.exists() else 0) + delta)
                count.write_text(str(now))
                return now

            yield held
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


@pytest.fixture
def evidence_keys(openbao: Bao) -> Iterator[EvidenceKeys]:
    """Evidence-key helpers on this test's OpenBao slice (marker `openbao`)."""
    keys = EvidenceKeys(openbao)
    try:
        yield keys
    finally:
        for tenant_id in keys.made:
            keys.destroy(tenant_id)
