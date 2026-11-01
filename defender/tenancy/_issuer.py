"""A tenant's issuer client config file (#1108 P4; #1163 A1, A11): the operator's one file per
tenant, named by path in the tenant row's forge binding (`issuer_config`; P-4: file-only, never
environment, never tenant content). JSON `{"issuer", "ca_cert", "role_id", "secret_id"}`, where
`issuer` is OpenBao's address and `ca_cert` the PEM file it is trusted by.

Read here once for both of its users: learning's delivery login and the run's request-token
signer. Each maps `DeliveryRefused` to its own fault. Nothing read here is ever put in an
environment, an argv, a box or a message."""
from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from defender import _io
from defender.tenancy._exports import DeliveryRefused

#: OpenBao's identity-token endpoint below its address, and its AppRole login.
IDENTITY_PATH = "/v1/identity/oidc"
LOGIN_PATH = "/v1/auth/approle/login"
#: Each issuer request's own bound.
ISSUER_TIMEOUT = 30.0


@dataclass(frozen=True)
class IssuerConfig:
    """The issuer client config file's content. `secret_id` (and `role_id`) never appear in a
    repr or a message."""

    address: str
    ca_cert: Path
    role_id: str = field(repr=False)
    secret_id: str = field(repr=False)


def read_issuer_config(path: Path) -> IssuerConfig:
    """The issuer client config at `path`, or `DeliveryRefused` naming what is wrong (never a
    value read from it). Decided locally: nothing is sent anywhere. `issuer` may be OpenBao's
    address or its identity endpoint (`<address>/v1/identity/oidc`); both name one issuer."""
    path = Path(path)
    try:
        text = _io.read_text_utf8(path)
    except FileNotFoundError:
        raise DeliveryRefused(f"no issuer client config file at {path}") from None
    except OSError as unreadable:
        raise DeliveryRefused(
            f"the issuer client config {path} could not be read: "
            f"{unreadable.strerror or type(unreadable).__name__}") from None
    obj, bad_json = _io.load_json_artifact(text)
    if bad_json is not None or not isinstance(obj, dict):
        raise DeliveryRefused(f"the issuer client config {path} is not a JSON object")
    keys = ("issuer", "ca_cert", "role_id", "secret_id")
    missing = [key for key in keys if not isinstance(obj.get(key), str) or not obj[key]]
    if missing:
        raise DeliveryRefused(f"the issuer client config {path} lacks {', '.join(missing)}")
    address = obj["issuer"].rstrip("/").removesuffix(IDENTITY_PATH)
    if not address.lower().startswith("https://"):
        raise DeliveryRefused(f"the issuer client config {path} names a non-https issuer address")
    return IssuerConfig(address=address, ca_cert=Path(obj["ca_cert"]), role_id=obj["role_id"],
                        secret_id=obj["secret_id"])


def issuer_client(config: IssuerConfig, transport: httpx.BaseTransport | None,
                  **kw: object) -> httpx.Client:
    """An HTTP client to the issuer trusting only the config's CA and no proxy or CA from the
    environment (P-4); with an injected `transport`, the transport owns the connection.
    `DeliveryRefused` when the CA file is unusable."""
    if transport is not None:
        return httpx.Client(transport=transport, timeout=ISSUER_TIMEOUT, **kw)  # type: ignore[arg-type]
    try:
        verify = ssl.create_default_context(cafile=str(config.ca_cert))
    except (OSError, ssl.SSLError) as bad:
        raise DeliveryRefused(
            f"the issuer client config's CA certificate {config.ca_cert} is unusable: "
            f"{type(bad).__name__}") from None
    return httpx.Client(verify=verify, timeout=ISSUER_TIMEOUT, trust_env=False, **kw)  # type: ignore[arg-type]


__all__ = ["IDENTITY_PATH", "ISSUER_TIMEOUT", "LOGIN_PATH", "IssuerConfig", "issuer_client",
           "read_issuer_config"]
