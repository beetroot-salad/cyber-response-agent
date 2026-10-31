"""OpenBao as the credential store and the token signer (#1163 H11, O5, A4, A11).

- Store: KV v2, one secret per (tenant, system) at `<kv mount>/data/<tenant>/<system>`, holding
  `{"kind": ..., "fields": {...}}`; a write replaces the whole set and moves the version on.
  The writer (`OpenBaoSecrets`, the API's port) may create, update and read metadata only; the
  proxy (`OpenBaoStore`) may read data only (`store_policies`).
- Tokens: transit, one key per tenant (`transit_key_for`). Each tenant's launcher login may sign
  with its own key only; the proxy may verify with every tenant's key and sign with none.

Every refusal, an unreachable or sealed server included, is `ConfigFault`, and no message holds
a token or a credential value. The server's own audit device records each credential write
(A4)."""
from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from typing import Any

import httpx

from defender import tenancy
from defender.kit.access import CREDENTIAL_KINDS
from defender.kit.faults import ConfigFault
from defender.kit.verbs import is_system_name
from defender.credential_proxy._credentials import CredentialSet

#: How long one call to OpenBao may take, in seconds.
OPENBAO_TIMEOUT_SEC = 10.0
#: A mount path or transit key name: what may stand inside a policy's path string.
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})*")


def transit_key_for(tenant_id: str) -> str:
    """The name of `tenant_id`'s transit key (A11): the one naming rule."""
    _check_tenant(tenant_id)
    return f"request-token-{tenant_id}"


def _check_tenant(tenant_id: object) -> str:
    if not isinstance(tenant_id, str) or not tenancy.is_valid_tenant_id(tenant_id):
        raise ConfigFault("not a tenant id")
    return tenant_id


def _check_name(value: object, what: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise ConfigFault(f"{what} {value!r} is not a mount path or key name")
    return value


def _secret_path(tenant_id: object, system: object) -> str:
    _check_tenant(tenant_id)
    if not isinstance(system, str) or not is_system_name(system):
        raise ConfigFault(f"{system!r} is not a system name")
    return f"{tenant_id}/{system}"


def store_policies(*, kv_mount: str, transit_mount: str,
                   tenant_keys: Mapping[str, str]) -> dict[str, str]:
    """The policy text for each role: `writer` (set a whole credential set, read metadata),
    `proxy` (read credential sets, verify with each tenant's key) and `launcher-<tenant_id>` per
    tenant (sign with that tenant's key only). Nothing grants list, delete, key read or
    export."""
    kv, transit = _check_name(kv_mount, "the KV mount"), _check_name(transit_mount,
                                                                      "the transit mount")
    keys = {_check_tenant(t): _check_name(k, "the transit key") for t, k in tenant_keys.items()}
    writer = (f'path "{kv}/data/*" {{\n  capabilities = ["create", "update"]\n}}\n'
              f'path "{kv}/metadata/*" {{\n  capabilities = ["read"]\n}}\n')
    proxy = f'path "{kv}/data/*" {{\n  capabilities = ["read"]\n}}\n' + "".join(
        f'path "{transit}/verify/{key}" {{\n  capabilities = ["update"]\n}}\n'
        for key in sorted(keys.values()))
    policies = {"writer": writer, "proxy": proxy}
    for tenant_id, key in sorted(keys.items()):
        policies[f"launcher-{tenant_id}"] = (
            f'path "{transit}/sign/{key}" {{\n  capabilities = ["update"]\n}}\n')
    return policies


class _OpenBao:
    """One login's calls to one OpenBao server. The token is never shown."""

    def __init__(self, *, addr: str, token: str, mount: str) -> None:
        if not isinstance(addr, str) or not addr.startswith(("http://", "https://")):
            raise ConfigFault("the OpenBao address must be an http(s) URL")
        if not isinstance(token, str) or not token or not token.isprintable():
            raise ConfigFault("the OpenBao token must be non-empty text")
        self.addr = addr.rstrip("/")
        self.mount = _check_name(mount, "the mount")
        self._token = token

    def __repr__(self) -> str:
        return f"{type(self).__name__}(addr={self.addr!r}, mount={self.mount!r})"

    __str__ = __repr__

    def _url(self, rest: str) -> str:
        return f"{self.addr}/v1/{self.mount}/{rest}"

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self._token}

    def _call(self, method: str, rest: str, what: str, json: Any = None) -> httpx.Response:
        try:
            with httpx.Client(timeout=OPENBAO_TIMEOUT_SEC, trust_env=False,
                              follow_redirects=False) as client:
                return client.request(method, self._url(rest), json=json,
                                      headers=self._headers())
        except httpx.HTTPError as e:
            raise ConfigFault(f"OpenBao at {self.addr} is unreachable for {what} "
                              f"({type(e).__name__})") from None

    async def _acall(self, method: str, rest: str, what: str,
                     json: Any = None) -> httpx.Response:
        try:
            async with httpx.AsyncClient(timeout=OPENBAO_TIMEOUT_SEC, trust_env=False,
                                         follow_redirects=False) as client:
                return await client.request(method, self._url(rest), json=json,
                                            headers=self._headers())
        except httpx.HTTPError as e:
            raise ConfigFault(f"OpenBao at {self.addr} is unreachable for {what} "
                              f"({type(e).__name__})") from None

    def _refused(self, reply: httpx.Response, what: str) -> ConfigFault:
        return ConfigFault(f"OpenBao at {self.addr} refused {what} ({reply.status_code})")


def _data_of(reply: httpx.Response) -> Mapping[str, Any]:
    try:
        doc = reply.json()
    except ValueError:
        doc = None
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, dict):
        raise ConfigFault(f"OpenBao answered {reply.status_code} without a data object")
    return data


class OpenBaoStore(_OpenBao):
    """The proxy's read of credential sets."""

    def read(self, tenant_id: str, system: str) -> CredentialSet | None:
        """`(tenant_id, system)`'s current set, or None when there is none."""
        path = _secret_path(tenant_id, system)
        what = f"the credential read of {system}"
        reply = self._call("GET", f"data/{path}", what)
        if reply.status_code == 404:
            return None
        if reply.status_code != 200:
            raise self._refused(reply, what)
        data = _data_of(reply)
        body, meta = data.get("data"), data.get("metadata")
        if body is None:  # the current version is deleted
            return None
        if not (isinstance(body, dict) and set(body) == {"kind", "fields"}
                and body["kind"] in CREDENTIAL_KINDS and isinstance(body["fields"], dict)
                and isinstance(meta, dict) and isinstance(meta.get("version"), int)):
            raise ConfigFault(f"the stored credential set of {system} is not in the store's "
                              "shape {kind, fields}")
        return CredentialSet(kind=body["kind"], fields=dict(body["fields"]),
                             version=meta["version"])


class OpenBaoSecrets(_OpenBao):
    """The API's write-only secret port: set a whole credential set with its kind, and ask
    whether one exists. It cannot read a value back."""

    async def put_credentials(self, tenant_id: str, system_id: str, kind: str,
                              credentials: Mapping[str, str]) -> None:
        """Replace `(tenant_id, system_id)`'s whole set with `credentials` of `kind`."""
        path = _secret_path(tenant_id, system_id)
        if kind not in CREDENTIAL_KINDS:
            raise ConfigFault(f"a credential set's kind must be one of {list(CREDENTIAL_KINDS)}")
        if not credentials or not all(isinstance(k, str) and isinstance(v, str) and v
                                      for k, v in credentials.items()):
            raise ConfigFault("a credential set must map one or more names to non-empty text")
        what = f"the credential write of {system_id}"
        reply = await self._acall("POST", f"data/{path}", what,
                                  json={"data": {"kind": kind, "fields": dict(credentials)}})
        if reply.status_code not in (200, 204):
            raise self._refused(reply, what)

    async def has_credentials(self, tenant_id: str, system_id: str) -> bool:
        """Does `(tenant_id, system_id)` have a current set? Asked of the metadata only."""
        path = _secret_path(tenant_id, system_id)
        what = f"the credential existence check of {system_id}"
        reply = await self._acall("GET", f"metadata/{path}", what)
        if reply.status_code == 404:
            return False
        if reply.status_code != 200:
            raise self._refused(reply, what)
        data = _data_of(reply)
        current = data.get("current_version")
        version = (data.get("versions") or {}).get(str(current))
        return (isinstance(current, int) and current > 0 and isinstance(version, dict)
                and not version.get("deletion_time") and not version.get("destroyed"))


class TransitSigner(_OpenBao):
    """The launcher's signer: signs with one tenant's transit `key`."""

    def __init__(self, *, addr: str, token: str, mount: str, key: str) -> None:
        super().__init__(addr=addr, token=token, mount=mount)
        self.key = _check_name(key, "the transit key")

    def __repr__(self) -> str:
        return (f"{type(self).__name__}(addr={self.addr!r}, mount={self.mount!r}, "
                f"key={self.key!r})")

    __str__ = __repr__

    def sign(self, payload: bytes) -> str:
        what = f"signing with {self.key}"
        reply = self._call("POST", f"sign/{self.key}", what,
                           json={"input": base64.b64encode(payload).decode("ascii")})
        if reply.status_code != 200:
            raise self._refused(reply, what)
        signature = _data_of(reply).get("signature")
        if not isinstance(signature, str) or not signature:
            raise ConfigFault(f"OpenBao answered {what} without a signature")
        return signature


class TransitVerifier(_OpenBao):
    """The proxy's verifier: checks a token with the key of the tenant it names (A11)."""

    def __init__(self, *, addr: str, token: str, mount: str, keys: Mapping[str, str]) -> None:
        super().__init__(addr=addr, token=token, mount=mount)
        self.keys = {_check_tenant(t): _check_name(k, "the transit key") for t, k in keys.items()}

    def __repr__(self) -> str:
        return (f"{type(self).__name__}(addr={self.addr!r}, mount={self.mount!r}, "
                f"tenants={len(self.keys)})")

    __str__ = __repr__

    def verify(self, payload: bytes, signature: str, *, tenant_id: str) -> bool:
        key = self.keys.get(tenant_id)
        if key is None:
            raise ConfigFault(f"no transit key is configured for tenant {tenant_id}")
        what = f"verifying with {key}"
        reply = self._call("POST", f"verify/{key}", what, json={
            "input": base64.b64encode(payload).decode("ascii"), "signature": signature})
        if reply.status_code != 200:
            raise self._refused(reply, what)
        valid = _data_of(reply).get("valid")
        if not isinstance(valid, bool):
            raise ConfigFault(f"OpenBao answered {what} without a verdict")
        return valid


__all__ = ["OpenBaoSecrets", "OpenBaoStore", "TransitSigner", "TransitVerifier",
           "store_policies", "transit_key_for"]
