"""#1163 A1/A11: a host process signs the request tokens it hands the credential proxy, in
process, through OpenBao's transit engine.

It logs in with the AppRole pair of the tenant's own issuer client config file (the file its
forge binding names; P-4: file-only, never environment) and signs only with that tenant's transit
key (`credential_proxy.transit_key_for`): the tenant's login may use no other tenant's key. The
login is made at the first signature, so a process that never needs a token never contacts
OpenBao. Nothing read here is placed in an environment, an argv, a log or a message."""
from __future__ import annotations

import base64
from pathlib import Path

import httpx

from defender.credential_proxy._openbao import openbao_fault, transit_key_for
from defender.kit.faults import ConfigFault, TransportFault
from defender.records.formats import TenantRefused
from defender.tenancy import (
    LOGIN_PATH,
    DeliveryRefused,
    ForgeBinding,
    IssuerConfig,
    Tenant,
    issuer_client,
    read_forge_binding,
    read_issuer_config,
)

#: The transit engine's mount in the issuer.
TRANSIT_MOUNT = "transit"


def _issuer_client(config: IssuerConfig, transport: httpx.BaseTransport | None,
                   **kw: object) -> httpx.Client:
    try:
        return issuer_client(config, transport, **kw)
    except DeliveryRefused as unusable:
        raise ConfigFault(str(unusable)) from None


class TenantRequestSigner:
    """Signs request-token payloads with `tenant`'s transit key, logged in as `tenant`."""

    def __init__(self, tenant: Tenant, config: IssuerConfig,
                 transport: httpx.BaseTransport | None) -> None:
        self._key = transit_key_for(str(tenant.id))
        self._config = config
        self._transport = transport
        self._client_token: str | None = None

    def sign(self, payload: bytes) -> str:
        """The transit signature over `payload`; `TransportFault` when OpenBao cannot be reached
        or answers 5xx (sealed included), `ConfigFault` when it refuses (r7 A18)."""
        for fresh in (self._client_token is None, True):
            if fresh:
                self._client_token = self._login()
            response = self._post_sign(payload)
            # an expired login (the AppRole token is short-lived) is refreshed once, not fatal
            if response.status_code not in (401, 403) or fresh:
                break
        signature = _signature_of(response)
        if signature is None:
            raise openbao_fault(response.status_code, _refusal("signing", response))
        return signature

    def _post_sign(self, payload: bytes) -> httpx.Response:
        client = _issuer_client(self._config, self._transport, headers={"X-Vault-Token": self._client_token})
        try:
            return client.post(
                f"{self._config.address}/v1/{TRANSIT_MOUNT}/sign/{self._key}",
                json={"input": base64.b64encode(payload).decode("ascii")}, follow_redirects=False)
        except httpx.HTTPError as down:
            raise TransportFault(
                f"OpenBao is unreachable for signing ({type(down).__name__})") from None
        finally:
            client.close()

    def _login(self) -> str:
        client = _issuer_client(self._config, self._transport)
        try:
            response = client.post(
                f"{self._config.address}{LOGIN_PATH}",
                json={"role_id": self._config.role_id, "secret_id": self._config.secret_id},
                follow_redirects=False)
        except httpx.HTTPError as down:
            raise TransportFault(
                f"OpenBao is unreachable for the issuer login ({type(down).__name__})") from None
        finally:
            client.close()
        token = None
        if response.status_code == 200:
            try:
                token = response.json()["auth"]["client_token"]
            except (ValueError, KeyError, TypeError):
                token = None
        if not isinstance(token, str) or not token:
            raise openbao_fault(response.status_code, _refusal("the issuer login", response))
        return token


def _signature_of(response: httpx.Response) -> str | None:
    if response.status_code != 200:
        return None
    try:
        signature = response.json()["data"]["signature"]
    except (ValueError, KeyError, TypeError):
        return None
    return signature if isinstance(signature, str) and signature else None


def _refusal(what: str, response: httpx.Response) -> str:
    sealed = " (OpenBao is sealed)" if response.status_code == 503 else ""
    return f"OpenBao refused {what}: HTTP {response.status_code}{sealed}"


def request_signer(
    tenant: Tenant, *, issuer_config: Path | None = None,
    transport: httpx.BaseTransport | None = None, binding: ForgeBinding | None = None,
) -> TenantRequestSigner:
    """The tenant's request-token signer, or `ConfigFault` when its row has no forge binding or
    its issuer client config file is missing or malformed (decided locally; nothing is sent)."""
    try:
        if binding is None:
            binding = read_forge_binding(tenant)
        config = read_issuer_config(Path(issuer_config) if issuer_config else binding.issuer_config)
    except (TenantRefused, DeliveryRefused) as unusable:
        raise ConfigFault(f"no usable issuer client config to sign request tokens: {unusable}"
                          ) from None
    return TenantRequestSigner(tenant, config, transport)


__all__ = ["TRANSIT_MOUNT", "TenantRequestSigner", "request_signer"]
