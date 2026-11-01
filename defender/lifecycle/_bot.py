"""Acting as a tenant's bot (#1214 Flow 1.7, 1.8, DC-10): an AppRole login, a JWT read off the
generation's OIDC role, and that JWT as the credential the sealed git transport presents."""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from defender.lifecycle._job import answered, field_of

LOGIN = "/v1/auth/approle/login"


async def approle_login(openbao: httpx.AsyncClient, role_id: str, secret_id: str) -> str:
    """An OpenBao client token for the AppRole pair (the request carries no other token)."""
    done = answered(await openbao.post(LOGIN, json={"role_id": role_id, "secret_id": secret_id},
                                       headers={"X-Vault-Token": ""}))
    return str(field_of(done, "auth", "client_token"))


async def mint(openbao: httpx.AsyncClient, oidc_role: str, client_token: str) -> str:
    """A JWT of `oidc_role`, read with `client_token` (the templated policy allows the entity only its own)."""
    done = answered(await openbao.get(f"/v1/identity/oidc/token/{oidc_role}", headers={"X-Vault-Token": client_token}))
    return str(field_of(done, "data", "token"))


@dataclass(frozen=True)
class Minted:
    """A `ForgeCredential` holding one JWT just minted (its lifetime covers the one git call it is for)."""

    tenant_id: str
    jwt: str = field(repr=False)

    def token(self, *, min_validity: float = 30.0) -> str:  # noqa: ARG002 — minted for this call
        return self.jwt
