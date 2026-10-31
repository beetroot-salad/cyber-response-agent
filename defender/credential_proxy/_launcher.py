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

import ssl
from dataclasses import dataclass, field

from defender import _io
from defender.credential_proxy._openbao import transit_key_for
from defender.kit.faults import ConfigFault
from defender.records.formats import TenantRefused
from defender.tenancy import ForgeBinding, Tenant, read_forge_binding

LOGIN_PATH = "/v1/auth/approle/login"
IDENTITY_PATH = "/v1/identity/oidc"
ISSUER_TIMEOUT = 30.0

#: The transit engine's mount in the issuer.
TRANSIT_MOUNT = "transit"


@dataclass(frozen=True)
class IssuerConfig:
    """The tenant's issuer client config file (the one its forge binding names): OpenBao's
    address, the CA it is trusted by and the AppRole pair. The pair is never shown."""

    address: str
    ca_cert: Path
    role_id: str = field(repr=False)
    secret_id: str = field(repr=False)


def read_signing_config(path: Path) -> IssuerConfig:
    """The config at `path`, or `ConfigFault` naming what is wrong (never a value read from
    it). Decided locally; nothing is sent. The file is the operator's, JSON
    `{"issuer", "ca_cert", "role_id", "secret_id"}` (P-4: file-only, never environment). The run
    process must not import tenant delivery (#1108 P4 P-3), so it reads the file itself."""
    path = Path(path)
    try:
        text = _io.read_text_utf8(path)
    except OSError as unreadable:
        raise ConfigFault(
            f"the issuer client config {path} could not be read: "
            f"{unreadable.strerror or type(unreadable).__name__}") from None
    obj, bad_json = _io.load_json_artifact(text)
    if bad_json is not None or not isinstance(obj, dict):
        raise ConfigFault(f"the issuer client config {path} is not a JSON object")
    keys = ("issuer", "ca_cert", "role_id", "secret_id")
    missing = [k for k in keys if not isinstance(obj.get(k), str) or not obj[k]]
    if missing:
        raise ConfigFault(f"the issuer client config {path} lacks {', '.join(missing)}")
    address = obj["issuer"].rstrip("/").removesuffix(IDENTITY_PATH)
    if not address.lower().startswith("https://"):
        raise ConfigFault(f"the issuer client config {path} names a non-https issuer address")
    return IssuerConfig(address, Path(obj["ca_cert"]), obj["role_id"], obj["secret_id"])


def _issuer_client(config: IssuerConfig, transport: httpx.BaseTransport | None,
            **kw: object) -> httpx.Client:
    if transport is not None:
        return httpx.Client(transport=transport, timeout=ISSUER_TIMEOUT, **kw)  # type: ignore[arg-type]
    try:
        verify = ssl.create_default_context(cafile=str(config.ca_cert))
    except (OSError, ssl.SSLError) as bad:
        raise ConfigFault(f"the issuer client config's CA certificate {config.ca_cert} is "
                          f"unusable: {type(bad).__name__}") from None
    return httpx.Client(verify=verify, timeout=ISSUER_TIMEOUT, trust_env=False, **kw)  # type: ignore[arg-type]


class TenantRequestSigner:
    """Signs request-token payloads with `tenant`'s transit key, logged in as `tenant`."""

    def __init__(self, tenant: Tenant, config: IssuerConfig,
                 transport: httpx.BaseTransport | None) -> None:
        self._key = transit_key_for(str(tenant.id))
        self._config = config
        self._transport = transport
        self._client_token: str | None = None

    def sign(self, payload: bytes) -> str:
        """The transit signature over `payload`; `ConfigFault` when OpenBao refuses, is sealed
        or cannot be reached."""
        for fresh in (self._client_token is None, True):
            if fresh:
                self._client_token = self._login()
            response = self._post_sign(payload)
            # an expired login (the AppRole token is short-lived) is refreshed once, not fatal
            if response.status_code not in (401, 403) or fresh:
                break
        signature = _signature_of(response)
        if signature is None:
            raise ConfigFault(_refusal("signing", response))
        return signature

    def _post_sign(self, payload: bytes) -> httpx.Response:
        client = _issuer_client(self._config, self._transport, headers={"X-Vault-Token": self._client_token})
        try:
            return client.post(
                f"{self._config.address}/v1/{TRANSIT_MOUNT}/sign/{self._key}",
                json={"input": base64.b64encode(payload).decode("ascii")}, follow_redirects=False)
        except httpx.HTTPError as down:
            raise ConfigFault(
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
            raise ConfigFault(
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
            raise ConfigFault(_refusal("the issuer login", response))
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
        config = read_signing_config(Path(issuer_config) if issuer_config else binding.issuer_config)
    except TenantRefused as unusable:
        raise ConfigFault(f"no usable issuer client config to sign request tokens: {unusable}"
                          ) from None
    return TenantRequestSigner(tenant, config, transport)


__all__ = ["TRANSIT_MOUNT", "TenantRequestSigner", "request_signer"]
