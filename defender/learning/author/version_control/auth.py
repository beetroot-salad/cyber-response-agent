"""Short-lived tenant identity for Forgejo Authorized Integrations.

The orchestrator supplies an authenticated Vault HTTP client. Vault owns workload login,
role ACLs and signing; Forgejo verifies signatures through the issuer's discovery/JWKS.
This client checks the returned token's binding and lifetime before using it. No credential
file, environment variable or provider-neutral credential framework is involved.
"""

from __future__ import annotations

import base64
import json
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from defender.tenancy._tenant import ISSUER_ROLE

TOKEN_TTL = 600
CLOCK_SKEW = 30


class ForgejoAuthError(Exception):
    """Vault did not provide a usable short-lived identity for this tenant."""


@dataclass(frozen=True, repr=False)
class AccessToken:
    value: str
    expires_at: float


def _claims(value: str) -> dict:
    """Read only the claims needed for local binding/lifetime checks. This is not signature
    verification: Forgejo performs it against Vault's published signing keys."""
    parts = value.split(".")
    if (
        len(value) > 16384
        or len(parts) != 3
        or any(not re.fullmatch(r"[A-Za-z0-9_-]+", part) for part in parts)
    ):
        raise ForgejoAuthError("Vault returned an invalid identity token")
    try:
        payload = base64.b64decode(
            parts[1] + "=" * (-len(parts[1]) % 4), altchars=b"-_", validate=True
        )
        claims = json.loads(payload)
    except (ValueError, UnicodeError) as e:
        raise ForgejoAuthError("Vault returned invalid identity claims") from e
    if not isinstance(claims, dict):
        raise ForgejoAuthError("Vault identity claims must be an object")
    return claims


def _timestamp(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise ForgejoAuthError("Vault identity has invalid lifetime claims")
    return float(value)


class ForgeCredential(Protocol):
    """What the forge client and the git transport read off a tenant's credential: the tenant
    it is for, and a bearer token valid for at least `min_validity` more seconds.
    `ForgejoIdentity` is the production one; a local harness with no issuer supplies its own."""

    @property
    def tenant_id(self) -> str: ...

    def token(self, *, min_validity: float = ...) -> str: ...


@dataclass
class ForgejoIdentity:
    """One tenant's authorized Vault role and Forgejo-generated audience.

    `client` must authenticate to Vault, with policy permitting this role only. The role's
    template signs `tenant_id`, and its client_id equals this integration's audience.
    The corresponding Forgejo integration restricts the audience and tenant claim to this
    tenant's repository. Cache tokens only while enough life remains for the operation.
    """

    tenant_id: str
    issuer: str
    role: str
    audience: str
    client: httpx.Client = field(repr=False)
    clock: Callable[[], float] = field(default=time.time, repr=False)
    _current: AccessToken | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        parsed = urlsplit(self.issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or self.issuer.endswith("/")
        ):
            raise ForgejoAuthError(
                "Vault issuer must be an HTTPS URL without credentials"
            )
        if not ISSUER_ROLE.fullmatch(self.role):
            raise ForgejoAuthError("Vault identity role must be a plain name")
        if not self.tenant_id or not self.audience:
            raise ForgejoAuthError(
                "Vault identity needs a tenant and a Forgejo audience"
            )

    def token(self, *, min_validity: float = CLOCK_SKEW) -> str:
        now = self.clock()
        if not math.isfinite(min_validity) or not 0 <= min_validity < TOKEN_TTL:
            raise ForgejoAuthError("The operation exceeds the short-lived token budget")
        if self._current is not None and self._current.expires_at > now + min_validity:
            return self._current.value
        try:
            response = self.client.get(
                f"{self.issuer}/token/{self.role}", follow_redirects=False, timeout=30.0
            )
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as e:
            # Never include a response body or an HTTP client's potentially secret URL.
            raise ForgejoAuthError("Vault identity token request failed") from e
        data = body.get("data") if isinstance(body, dict) else None
        value = data.get("token") if isinstance(data, dict) else None
        if not isinstance(value, str):
            raise ForgejoAuthError("Vault returned no identity token")
        now = self.clock()
        claims = _claims(value)
        audience = claims.get("aud")
        if (
            claims.get("iss") != self.issuer
            or claims.get("tenant_id") != self.tenant_id
            or not (audience == self.audience or audience == [self.audience])
        ):
            raise ForgejoAuthError(
                "Vault identity does not match this tenant and audience"
            )
        expiry = _timestamp(claims.get("exp"))
        issued = _timestamp(claims.get("iat"))
        not_before = _timestamp(claims.get("nbf", now))
        if (
            expiry <= now + min_validity
            or expiry - issued > TOKEN_TTL
            or expiry > now + TOKEN_TTL + CLOCK_SKEW
            or issued > now + CLOCK_SKEW
            or not_before > now + CLOCK_SKEW
        ):
            raise ForgejoAuthError(
                "Vault identity is expired, premature or not short-lived"
            )
        self._current = AccessToken(value=value, expires_at=float(expiry))
        return value
