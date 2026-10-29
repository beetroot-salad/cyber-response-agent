"""The tenant's forge credential on the execution host (#1214 P4, Flow 3): `forge_credential(T, purpose)`.

A host process that delivers to or publishes from a tenant's repository (the publish child, the
drains, the connect command) mints the tenant's short-lived forge token through this provider,
which replaces the row's forge binding and its per-tenant issuer config file. On every mint it
reads the tenant's LIVE credential generation from the tenant records (`TenantDirectory`) and the
AppRole secret from the host secret file that generation records, logs in to OpenBao with the
generation's `role_id` and that secret, and asks for a token of the generation's OIDC role for its
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
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from defender import _io
from defender.configuration.issuer import DEPLOYMENT_ISSUER

from .auth import CLOCK_SKEW, ForgejoAuthError, ForgejoIdentity

if TYPE_CHECKING:
    from defender.tenancy import TenantDirectory

#: OpenBao's AppRole login below its address.
LOGIN_PATH = "/v1/auth/approle/login"
#: Each issuer request's own bound.
ISSUER_TIMEOUT = 30.0


@dataclass
class TenantForgeCredential:
    """One tenant's forge credential (a `ForgeCredential`): `token()` mints through the tenant's
    live generation as it stands at that moment (module doc)."""

    tenant_id: str
    purpose: str
    directory: TenantDirectory = field(repr=False)
    config: Any = field(repr=False)
    transport: httpx.BaseTransport | None = field(default=None, repr=False)
    clock: Callable[[], float] = field(default=time.time, repr=False)
    _identity: ForgejoIdentity | None = field(default=None, init=False, repr=False)
    _salt: str | None = field(default=None, init=False, repr=False)

    def token(self, *, min_validity: float = CLOCK_SKEW) -> str:
        """A bearer JWT for the tenant's live generation valid for `min_validity` more seconds:
        the token already held while it lasts and its generation is still the live one, else a new
        login and mint. Refused (`ForgejoAuthError`) when the tenant has no live generation, its
        secret file cannot be read, or OpenBao refuses the login or the token."""
        live = self._live()
        held = self._identity
        if held is not None and self._salt == live.salt:
            current = held._current  # noqa: SLF001 — the identity's own cache, read to keep it across mints
            if current is not None and current.expires_at > self.clock() + min_validity:
                return current.value
        self.close()
        identity = self._login(live)
        self._identity, self._salt = identity, live.salt
        return identity.token(min_validity=min_validity)

    def close(self) -> None:
        """Close the OpenBao client the last login opened (its token is dropped with it)."""
        if self._identity is not None:
            self._identity.client.close()
            self._identity, self._salt = None, None

    def _live(self) -> Any:
        live = [g for g in self.directory.generations(self.tenant_id) if g.status == "live"]
        if not live:
            raise ForgejoAuthError(
                f"tenant {self.tenant_id} has no live credential generation: no {self.purpose} credential "
                "can be minted for it (it is being created, or was offboarded)")
        return live[0]

    def _secret(self, live: Any) -> str:
        path = Path(live.host_secret_file or "")
        if not live.host_secret_file or not path.is_absolute():
            raise ForgejoAuthError(
                f"tenant {self.tenant_id}'s live credential generation records no host secret file")
        try:
            data = _io.read_plain_bytes(path)
        except OSError as unreadable:
            raise ForgejoAuthError(
                f"tenant {self.tenant_id}'s host secret file {path} could not be read: "
                f"{unreadable.strerror or type(unreadable).__name__}") from None
        # The file holds the secret id and one newline (r9); bounded and no-follow by `read_plain_bytes`.
        secret = data.decode("utf-8", "replace").strip()
        if not secret or "\n" in secret:
            raise ForgejoAuthError(f"tenant {self.tenant_id}'s host secret file {path} does not hold one "
                                   "secret id")
        return secret

    def _login(self, live: Any) -> ForgejoIdentity:
        address = str(self.config.openbao_url).rstrip("/")
        # Before the secret is read, let alone sent: a cleartext issuer (either address) gets nothing.
        for name, url in (("OpenBao address", address), ("issuer URL", str(self.config.issuer_url))):
            if urlsplit(url).scheme != "https":
                raise ForgejoAuthError(f"the {name} must be an HTTPS URL: the AppRole secret is never sent in cleartext")
        secret = self._secret(live)
        login = self._client()
        try:
            response = login.post(f"{address}{LOGIN_PATH}", json={"role_id": live.role_id, "secret_id": secret},
                                  follow_redirects=False)
        except httpx.HTTPError as down:
            # Never the request (its body holds the secret).
            raise ForgejoAuthError(f"the issuer AppRole login request failed: {type(down).__name__}") from down
        finally:
            login.close()
        if response.status_code != 200:
            raise ForgejoAuthError(
                f"the issuer refused tenant {self.tenant_id}'s AppRole login (HTTP {response.status_code})"
            ) from httpx.HTTPStatusError("login refused", request=response.request, response=response)
        try:
            body = response.json()
        except ValueError:
            body = None
        auth = body.get("auth") if isinstance(body, dict) else None
        token = auth.get("client_token") if isinstance(auth, dict) else None
        if not isinstance(token, str) or not token:
            raise ForgejoAuthError("the issuer's AppRole login returned no client token")
        client = self._client(headers={"X-Vault-Token": token})
        try:
            return ForgejoIdentity(tenant_id=self.tenant_id, issuer=str(self.config.issuer_url).rstrip("/"),
                                   role=live.oidc_role, audience=live.audience, client=client, clock=self.clock)
        except BaseException:
            client.close()
            raise

    def _client(self, **kw: Any) -> httpx.Client:
        if self.transport is not None:
            return httpx.Client(transport=self.transport, timeout=ISSUER_TIMEOUT, **kw)
        ca = getattr(self.config, "ca_cert", None)
        if ca is None:
            return httpx.Client(timeout=ISSUER_TIMEOUT, **kw)
        try:
            verify = ssl.create_default_context(cafile=str(ca))
        except (OSError, ssl.SSLError) as bad:
            raise ForgejoAuthError(f"the issuer CA certificate {ca} is unusable: {type(bad).__name__}") from None
        return httpx.Client(verify=verify, timeout=ISSUER_TIMEOUT, **kw)


def forge_credential(
    tenant_id: str, purpose: str, *, directory: TenantDirectory, config: Any,
    transport: httpx.BaseTransport | None = None, clock: Callable[[], float] = time.time,
) -> TenantForgeCredential:
    """Tenant `tenant_id`'s forge credential for `purpose` (`publish`, `drain`, `connect`: named in
    refusals). Nothing is read or sent until its first `token()`. `config` is a test's issuer; with
    none, the deployment's (`DEPLOYMENT_ISSUER`)."""
    return TenantForgeCredential(tenant_id=str(tenant_id), purpose=purpose, directory=directory,
                                 config=DEPLOYMENT_ISSUER if config is None else config,
                                 transport=transport, clock=clock)
