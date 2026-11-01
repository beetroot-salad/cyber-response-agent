"""A-ID (#1108 P4): a host-side delivery process logs in to the issuer (OpenBao) itself, with
AppRole, and gets the tenant's short-lived identity.

The login material is one operator file per tenant, named by path in the tenant row's forge
binding (`issuer_config`; P-4: file-only, never environment, never tenant content): JSON
`{"issuer", "ca_cert", "role_id", "secret_id"}`, where `issuer` is OpenBao's address and
`ca_cert` the PEM file it is trusted by. Which role signs the tenant's tokens and for which
Forgejo audience is the same binding.
Nothing read here is ever put in an environment, an argv, a box or a report line (O8).
"""

from __future__ import annotations

from pathlib import Path

import httpx

from defender.tenancy import (
    IDENTITY_PATH,
    LOGIN_PATH,
    ForgeBinding,
    IssuerConfig,
    Tenant,
    issuer_client,
    read_forge_binding,
    read_issuer_config,
)
from defender.records.formats import TenantRefused

from .auth import ForgejoAuthError, ForgejoIdentity
from .model import DeliveryRefused


def issuer_config_path(binding: ForgeBinding, override: Path | None = None) -> Path:
    """The issuer client config file a delivery process logs in with: the binding's own
    `issuer_config`, unless an in-process caller hands a stand-in `override`."""
    return Path(override) if override is not None else binding.issuer_config


def issuer_login(
    tenant: Tenant,
    *,
    issuer_config: Path | None = None,
    transport: httpx.BaseTransport | None = None,
    binding: ForgeBinding | None = None,
    config: IssuerConfig | None = None,
) -> ForgejoIdentity:
    """Log in to the issuer with the AppRole pair of the config file the forge binding names
    (`issuer_config`, an in-process stand-in for it) and return the tenant's identity: tokens for the forge binding's `issuer_role`, for its `audience`, checked by
    `ForgejoIdentity` as bound to this tenant. A missing or malformed config file, or a tenant
    row with no forge binding, is refused before any request (O9). A refused login is a
    `ForgejoAuthError` naming the HTTP status only; an unreachable issuer keeps its transport
    fault as the cause (a caller tells an outage from a refusal by it). A caller that has read
    the `binding` and its `config` already hands them in, so they are read once, never twice
    with a window between."""
    if binding is None:
        try:
            binding = read_forge_binding(tenant)
        except TenantRefused as unbound:
            raise DeliveryRefused(str(unbound)) from unbound
    if config is None:
        config = read_issuer_config(issuer_config_path(binding, issuer_config))
    login = issuer_client(config, transport)
    try:
        response = login.post(
            f"{config.address}{LOGIN_PATH}",
            json={"role_id": config.role_id, "secret_id": config.secret_id},
            follow_redirects=False,
        )
    except httpx.HTTPError as down:
        # Never the request (its body holds the secret) or the URL.
        raise ForgejoAuthError(
            f"the issuer AppRole login request failed: {type(down).__name__}"
        ) from down
    finally:
        login.close()
    if response.status_code != 200:
        raise ForgejoAuthError(
            f"the issuer refused the AppRole login (HTTP {response.status_code})"
        ) from httpx.HTTPStatusError(
            "login refused", request=response.request, response=response
        )
    try:
        body = response.json()
    except ValueError:
        body = None
    auth = body.get("auth") if isinstance(body, dict) else None
    token = auth.get("client_token") if isinstance(auth, dict) else None
    if not isinstance(token, str) or not token:
        raise ForgejoAuthError("the issuer's AppRole login returned no client token")
    client = issuer_client(config, transport, headers={"X-Vault-Token": token})
    try:
        return ForgejoIdentity(
            tenant_id=str(tenant.id),
            issuer=f"{config.address}{IDENTITY_PATH}",
            role=binding.issuer_role,
            audience=binding.audience,
            client=client,
        )
    except BaseException:
        # Never left open holding the issuer token when the identity is refused.
        client.close()
        raise
