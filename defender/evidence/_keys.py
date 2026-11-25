"""The tenant evidence key and its login (#1546, A-O5): OpenBao transit, one key `evidence-<T>` per tenant.

Each object is encrypted by the store under a fresh data key that this module asks OpenBao for (`datakey`) and keeps only as
the wrapped form the upload row records; `unwrap` gives the data key back for a read. The login is an AppRole of one
credential generation whose policy holds `datakey` and `decrypt` on the tenant's own key and nothing else; the lifecycle makes
it (beside the sign login), the helper holds it. Nothing here creates, rotates or destroys a key: that is the lifecycle's.

Faults are `EvidenceKeyError` (`status`: OpenBao's HTTP status, None when it gave none); a key that does not exist is
`EvidenceKeyMissing`. The secret id, the client token and the plaintext data key never reach a message or a repr.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Any

import httpx

from defender import tenancy
from defender.configuration.issuer import DEPLOYMENT_ISSUER, TRANSIT_MOUNT
from defender.kit.internal_http import internal_client, tls_trust

#: What a transit key's name starts with; the tenant id follows (the one naming rule).
KEY_PREFIX = "evidence-"
DATA_KEY_BITS = 256
_NOT_FOUND = "encryption key not found"

#: The deployment's templated policy for every generation's evidence login (`LifecycleConfig.evidence_policy`): `update` on
#: `datakey/plaintext` and `decrypt` of the key named by the login entity's own `tenant_id` metadata, as the sign login's
#: policy confines it (#1163 A25).
TEMPLATED_POLICY = (
    f'path "{TRANSIT_MOUNT}/datakey/plaintext/{KEY_PREFIX}{{{{identity.entity.metadata.tenant_id}}}}" {{\n'
    '  capabilities = ["update"]\n}\n'
    f'path "{TRANSIT_MOUNT}/decrypt/{KEY_PREFIX}{{{{identity.entity.metadata.tenant_id}}}}" {{\n'
    '  capabilities = ["update"]\n}\n')


class EvidenceKeyError(Exception):
    """OpenBao did not answer a login or a transit request as asked."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class EvidenceKeyMissing(EvidenceKeyError):
    """The tenant's `evidence-<T>` key does not exist."""


def key_name(tenant_id: str) -> str:
    """The transit key of `tenant_id`: a tenant id that is not a canonical tenant UUID is `ValueError`, so no path is
    built from it."""
    if not isinstance(tenant_id, str) or not tenancy.is_valid_tenant_id(tenant_id):
        raise ValueError("not a tenant id")
    return f"{KEY_PREFIX}{tenant_id}"


def approle_policy(tenant_id: str) -> str:
    """Policy text for a login of exactly `tenant_id`'s evidence key: `update` on its `datakey/plaintext` and `decrypt`
    paths, nothing else."""
    name = key_name(tenant_id)
    return (f'path "{TRANSIT_MOUNT}/datakey/plaintext/{name}" {{\n  capabilities = ["update"]\n}}\n'
            f'path "{TRANSIT_MOUNT}/decrypt/{name}" {{\n  capabilities = ["update"]\n}}\n')


@dataclass(frozen=True)
class DataKey:
    """A fresh data key: the bytes to encrypt one object with, and the form OpenBao wrapped them in (the only form kept)."""

    plaintext: bytes = field(repr=False)
    wrapped: str


class EvidenceKeys:
    """The evidence login of one credential generation: AppRole `role_id`/`secret_id` on the auth `mount` (its path, e.g.
    `approle`) of the OpenBao at `addr`. It logs in on first use and again when OpenBao refuses its token."""

    def __init__(self, addr: str, role_id: str, secret_id: str, mount: str, *, timeout: float = 10.0) -> None:
        if not (addr and role_id and secret_id and mount):
            raise ValueError("an evidence login needs an address, a role id, a secret id and an auth mount")
        self._addr = addr.rstrip("/")
        self._role_id = role_id
        self._secret_id = secret_id
        self._mount = mount.strip("/")
        self._timeout = timeout
        self._token: str | None = None
        self._http: httpx.Client | None = None

    def __repr__(self) -> str:
        return f"EvidenceKeys(addr={self._addr!r}, mount={self._mount!r})"

    # --- the wire -------------------------------------------------------------------------------------------------

    def _post(self, path: str, body: dict[str, Any], token: str | None) -> httpx.Response:
        if self._http is None:
            self._http = internal_client(trust=tls_trust(DEPLOYMENT_ISSUER.ca_cert), timeout=self._timeout)
        headers = {"X-Vault-Token": token} if token else {}
        try:
            return self._http.post(f"{self._addr}/v1/{path}", json=body, headers=headers)
        except httpx.HTTPError as down:  # never the request: its body holds the secret id
            raise EvidenceKeyError(f"OpenBao could not be reached: {type(down).__name__}") from down

    @staticmethod
    def _json(reply: httpx.Response) -> dict[str, Any]:
        try:
            body = reply.json()
        except ValueError:
            body = None
        return body if isinstance(body, dict) else {}

    def _login(self) -> str:
        reply = self._post(f"auth/{self._mount}/login", {"role_id": self._role_id, "secret_id": self._secret_id}, None)
        auth = self._json(reply).get("auth")
        token = auth.get("client_token") if isinstance(auth, dict) else None
        if reply.status_code != 200 or not isinstance(token, str) or not token:
            raise EvidenceKeyError(f"OpenBao refused the evidence login (HTTP {reply.status_code})",
                                   status=reply.status_code)
        self._token = token
        return token

    def _call(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """A transit call as the login: the `data` of its answer. A refused token is replaced once by a new login."""
        for attempt in (1, 2):
            token = self._token or self._login()
            reply = self._post(path, body, token)
            if reply.status_code == 403 and attempt == 1:
                self._token = None
                continue
            if reply.status_code == 200:
                data = self._json(reply).get("data")
                if isinstance(data, dict):
                    return data
                raise EvidenceKeyError("OpenBao's transit answer holds no data", status=200)
            errors = self._json(reply).get("errors")
            if reply.status_code == 400 and isinstance(errors, list) and _NOT_FOUND in errors:
                raise EvidenceKeyMissing("the tenant's evidence key does not exist", status=400)
            raise EvidenceKeyError(f"OpenBao answered the evidence key request with HTTP {reply.status_code}",
                                   status=reply.status_code)
        raise AssertionError("unreachable")  # pragma: no cover

    # --- the key --------------------------------------------------------------------------------------------------

    def datakey(self, tenant_id: str) -> DataKey:
        """A fresh 256-bit data key under `evidence-<T>`: `EvidenceKeyMissing` when the key is gone."""
        data = self._call(f"{TRANSIT_MOUNT}/datakey/plaintext/{key_name(tenant_id)}", {"bits": DATA_KEY_BITS})
        wrapped = data.get("ciphertext")
        try:
            plaintext = base64.b64decode(str(data.get("plaintext")), validate=True)
        except (binascii.Error, ValueError):
            plaintext = b""
        if not isinstance(wrapped, str) or len(plaintext) != DATA_KEY_BITS // 8:
            raise EvidenceKeyError("OpenBao's datakey answer is not a 256-bit key")
        return DataKey(plaintext, wrapped)

    def unwrap(self, tenant_id: str, wrapped: str) -> bytes:
        """The data key `wrapped` holds; a wrapped key of another tenant's key is refused (`EvidenceKeyError`)."""
        data = self._call(f"{TRANSIT_MOUNT}/decrypt/{key_name(tenant_id)}", {"ciphertext": wrapped})
        try:
            plaintext = base64.b64decode(str(data.get("plaintext")), validate=True)
        except (binascii.Error, ValueError):
            plaintext = b""
        if len(plaintext) != DATA_KEY_BITS // 8:
            raise EvidenceKeyError("OpenBao's decrypt answer is not a 256-bit key")
        return plaintext

    def exists(self, tenant_id: str) -> bool:
        """Is `evidence-<T>` in OpenBao? Asked with the login's own right (one datakey, thrown away): the login may not read
        the key's metadata. A login or an OpenBao that cannot answer is `EvidenceKeyError`, not False."""
        try:
            self.datakey(tenant_id)
        except EvidenceKeyMissing:
            return False
        return True


__all__ = ["KEY_PREFIX", "TEMPLATED_POLICY", "DataKey", "EvidenceKeyError", "EvidenceKeyMissing", "EvidenceKeys",
           "approle_policy", "key_name"]
