"""#1163 A24': a host process signs the request tokens it hands the credential proxy, in process,
through OpenBao's transit engine.

`request_signer(tenant_id, directory=)` is the one builder. Building it reads and sends nothing.
Each login reads the tenant's live generation from the tenant records (`directory`) and logs in as
that generation's sign-only AppRole (`sign_role_id`, with the secret from `sign_secret_file`;
`tenancy.approle_login`, the login the forge credential shares) at the deployment's OpenBao
address (https). The client token is held and reused; a sign answered 401 or 403 logs in again
once. The signer signs only with the tenant's own transit key (`transit_key_for`) on the fixed
transit mount, which the sign login's templated policy confines it to. Nothing read here is placed
in an environment, an argv, a log, a message or a repr.

Faults (r7 A18): no live generation, no recorded sign login, a missing or malformed secret file, a
cleartext address, or a login or sign refused (4xx, or a 2xx without what was asked) is
`ConfigFault`; OpenBao unreachable or answering 5xx (sealed included), or tenant records that
cannot be read, is `TransportFault`."""
from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import httpx

from defender import tenancy
from defender._internal_http import internal_client
from defender.configuration.issuer import DEPLOYMENT_ISSUER, TRANSIT_MOUNT
from defender.credential_proxy._openbao import OPENBAO_TIMEOUT_SEC, openbao_fault, transit_key_for
from defender.kit.faults import AdapterFault, ConfigFault, TransportFault

if TYPE_CHECKING:
    from defender.tenancy import TenantDirectory


def _login_fault(failed: tenancy.AppRoleLoginError) -> AdapterFault:
    """The fault a failed sign login is (module doc)."""
    if isinstance(failed, tenancy.LoginUnreachable):
        return TransportFault(str(failed))
    if isinstance(failed, tenancy.LoginRefused):
        return openbao_fault(failed.status, str(failed))
    return ConfigFault(f"no usable sign login to sign request tokens: {failed}")


class TenantRequestSigner:
    """Signs request-token payloads with the tenant's transit key, logged in as its live
    generation's sign login. Shows only the tenant it signs for."""

    def __init__(self, tenant_id: str, directory: TenantDirectory,
                 transport: httpx.BaseTransport | None) -> None:
        self._tenant_id = tenant_id
        self._directory = directory
        self._transport = transport
        self._client_token: str | None = None
        #: One pooled client for every sign, made at the first (building reads nothing, G2).
        self._http: httpx.Client | None = None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(tenant={self._tenant_id!r})"

    __str__ = __repr__

    def sign(self, payload: bytes) -> str:
        """The transit signature over `payload` (faults: module doc)."""
        key = transit_key_for(self._tenant_id)
        client = self._client()
        if self._client_token is None:
            self._client_token = self._login(client)
        response = self._post_sign(client, key, payload)
        # a held login that expired (the AppRole token is short-lived), or a refused one, gets one
        # fresh login: never a second
        if response.status_code in (401, 403):
            self._client_token = self._login(client)
            response = self._post_sign(client, key, payload)
        signature = _signature_of(response)
        if signature is None:
            raise openbao_fault(response.status_code, _refusal(f"signing with {key}", response))
        return signature

    def _client(self) -> httpx.Client:
        if self._http is None:
            self._http = internal_client(ca_cert=DEPLOYMENT_ISSUER.ca_cert, transport=self._transport,
                                         timeout=OPENBAO_TIMEOUT_SEC)
        return self._http

    def _login(self, client: httpx.Client) -> str:
        try:
            return tenancy.approle_login(self._directory, self._tenant_id, pair=tenancy.SIGN_LOGIN,
                                         address=DEPLOYMENT_ISSUER.openbao_url, client=client).client_token
        except tenancy.AppRoleLoginError as failed:
            raise _login_fault(failed) from None
        except tenancy.RecordsUnreachable as down:
            raise TransportFault(f"the tenant records could not be read for the sign login: {down}") from None

    def _post_sign(self, client: httpx.Client, key: str, payload: bytes) -> httpx.Response:
        address = DEPLOYMENT_ISSUER.openbao_url.rstrip("/")
        try:
            return client.post(f"{address}/v1/{TRANSIT_MOUNT}/sign/{key}",
                               json={"input": base64.b64encode(payload).decode("ascii")},
                               headers={"X-Vault-Token": self._client_token or ""})
        except httpx.HTTPError as down:
            raise TransportFault(
                f"OpenBao is unreachable for signing ({type(down).__name__})") from None


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


def request_signer(tenant_id: str, *, directory: TenantDirectory,
                   transport: httpx.BaseTransport | None = None) -> TenantRequestSigner:
    """The request signer of tenant `tenant_id` over its records `directory`: an object with
    `sign(payload: bytes) -> str`. Reads and sends nothing until its first sign; `transport` is
    the `httpx` transport OpenBao is reached by (a test's; none: the network)."""
    return TenantRequestSigner(str(tenant_id), directory, transport)


__all__ = ["TenantRequestSigner", "request_signer"]
