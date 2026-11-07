"""Acting as a tenant's bot (#1214 Flow 1.7, 1.8, DC-10): an AppRole login, a JWT read off the
generation's OIDC role, and that JWT as the credential the sealed git transport presents."""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from defender import _openbao_api as openbao
from defender.lifecycle._job import answered, field_of, send


async def log_in(bao: httpx.AsyncClient, role_id: str, secret_id: str) -> str:
    """An OpenBao client token for the AppRole pair (the request carries no other token)."""
    done = answered(await send(bao, openbao.log_in_with_approle(role_id, secret_id)))
    return str(field_of(done, "auth", "client_token"))


async def mint(bao: httpx.AsyncClient, oidc_role: str, client_token: str) -> str:
    """A JWT of `oidc_role`, read with `client_token` (the templated policy allows the entity only its own)."""
    done = answered(await send(bao, openbao.oidc_token(oidc_role, token=client_token)))
    return str(field_of(done, "data", "token"))


@dataclass(frozen=True)
class Minted:
    """A `ForgeCredential` holding one JWT just minted (its lifetime covers the one git call it is for)."""

    tenant_id: str
    jwt: str = field(repr=False)

    def token(self, *, min_validity: float = 30.0) -> str:  # noqa: ARG002 — minted for this call
        return self.jwt
