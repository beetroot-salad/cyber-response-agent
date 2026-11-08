"""The tenant's forge credential on the execution host (#1214 P4, Flow 3): `forge_credential(T, purpose)`.

A host process that delivers to or publishes from a tenant's repository (the publish child, the
drains, the connect command) mints the tenant's short-lived forge token through this provider,
which replaces the row's forge binding and its per-tenant issuer config file. On every mint it
logs in to OpenBao as the delivery AppRole of the tenant's LIVE credential generation, read from the
tenant records (`TenantDirectory`) with its secret from the host secret file that generation records
(`tenancy.approle_login`, the one owner of that login, shared with #1163's request signer; the
generation's sign secret file is never read here), and asks for a token of the generation's OIDC role for its
audience. Nothing is cached across mints but the token itself while it is valid, so a credential
made before a rotation mints for the new generation once the old token has run out, and one made
before an offboarding mints nothing after it.

`config` carries the issuer: `issuer_url` (OpenBao's identity endpoint, https), `openbao_url` (its
address) and, optionally, `ca_cert` (the PEM file OpenBao is trusted by). A process that passes
none (every production one) uses the deployment's fixed service names
(`configuration.issuer.DEPLOYMENT_ISSUER`). The secret, the client token and the JWT never reach
an argv, an environment, a log line or a refusal.
"""

from __future__ import annotations

import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from defender import tenancy
from defender.kit.internal_http import internal_client, tls_trust
from defender.configuration.issuer import DEPLOYMENT_ISSUER

from .auth import CLOCK_SKEW, CredentialMisconfigured, ForgejoAuthError, ForgejoIdentity

if TYPE_CHECKING:
    from defender.records.formats import TenantId
    from defender.tenancy import TenantDirectory

#: Each issuer request's own bound.
ISSUER_TIMEOUT = 30.0


@dataclass
class TenantForgeCredential:
    """One tenant's forge credential (a `ForgeCredential`): `token()` mints through the tenant's
    live generation as it stands at that moment (module doc)."""

    tenant_id: TenantId
    purpose: str
    directory: TenantDirectory = field(repr=False)
    config: Any = field(repr=False)
    transport: httpx.BaseTransport | None = field(default=None, repr=False)
    clock: Callable[[], float] = field(default=time.time, repr=False)
    _identity: ForgejoIdentity | None = field(default=None, init=False, repr=False)

    def token(self, *, min_validity: float = CLOCK_SKEW) -> str:
        """A bearer JWT for the tenant's live generation valid for `min_validity` more seconds:
        the token already held while it lasts (nothing read), else a new login and mint for the
        generation that is live now. Refused (`ForgejoAuthError`) when the tenant has no live
        generation, its secret file cannot be read, or OpenBao refuses the login or the token."""
        held = self._identity
        if held is not None:
            current = held._current  # noqa: SLF001 — the identity's own cache, read to keep it across mints
            if current is not None and current.expires_at > self.clock() + min_validity:
                return current.value
        self.close()
        identity = self._login()
        self._identity = identity
        return identity.token(min_validity=min_validity)

    def close(self) -> None:
        """Close the OpenBao client the last login opened (its token is dropped with it)."""
        if self._identity is not None:
            self._identity.client.close()
            self._identity = None

    def _login(self) -> ForgejoIdentity:
        # Before the secret is read, let alone sent: a cleartext issuer URL gets nothing (the shared
        # login checks the OpenBao address itself, also before the read).
        if urlsplit(str(self.config.issuer_url)).scheme != "https":
            raise ForgejoAuthError("the issuer URL must be an HTTPS URL: the AppRole secret is never sent in cleartext")
        login = self._client()
        try:
            made = tenancy.approle_login(self.directory, self.tenant_id, pair=tenancy.DELIVERY_LOGIN,
                                         address=str(self.config.openbao_url), client=login)
        except (tenancy.LoginUnrecorded, tenancy.SecretFileUnusable) as unusable:
            raise CredentialMisconfigured(str(unusable)) from None
        except tenancy.NoLiveGeneration:
            raise ForgejoAuthError(
                f"tenant {self.tenant_id} has no live credential generation: no {self.purpose} credential "
                "can be minted for it (it is being created, or was offboarded)") from None
        except tenancy.AppRoleLoginError as failed:
            # The chain keeps the `httpx` error or the `HTTPStatusError` publish status sorts by.
            raise ForgejoAuthError(f"the issuer AppRole login failed: {failed}") from failed
        finally:
            login.close()
        audience = made.generation.audience
        if not audience:
            raise ForgejoAuthError(f"tenant {self.tenant_id}'s live credential generation records no audience")
        client = self._client(headers={"X-Vault-Token": made.client_token})
        try:
            return ForgejoIdentity(tenant_id=self.tenant_id, issuer=str(self.config.issuer_url).rstrip("/"),
                                   role=made.generation.oidc_role, audience=audience,
                                   client=client, clock=self.clock)
        except BaseException:
            client.close()
            raise

    def _client(self, **kw: Any) -> httpx.Client:
        if self.transport is not None:
            return internal_client(trust=tls_trust(), transport=self.transport, timeout=ISSUER_TIMEOUT, **kw)
        ca = getattr(self.config, "ca_cert", None)
        try:
            return internal_client(trust=tls_trust(ca), timeout=ISSUER_TIMEOUT, **kw)
        except (OSError, ssl.SSLError) as bad:
            raise ForgejoAuthError(f"the issuer CA certificate {ca} is unusable: {type(bad).__name__}") from None


def forge_credential(
    tenant_id: TenantId, purpose: str, *, directory: TenantDirectory, config: Any,
    transport: httpx.BaseTransport | None = None, clock: Callable[[], float] = time.time,
) -> TenantForgeCredential:
    """Tenant `tenant_id`'s forge credential for `purpose` (`publish`, `drain`, `connect`: named in
    refusals). Nothing is read or sent until its first `token()`. `config` is a test's issuer; with
    none, the deployment's (`DEPLOYMENT_ISSUER`)."""
    return TenantForgeCredential(tenant_id=tenant_id, purpose=purpose, directory=directory,
                                 config=DEPLOYMENT_ISSUER if config is None else config,
                                 transport=transport, clock=clock)
