"""Vault identity HTTP double. Git and Forgejo protocol tests receive real JWT-shaped values.

The fake clock is fixed so child processes obtain the same fixture token. These tokens are
not cryptographically verified here; the real Forgejo integration test covers verification.
"""

from __future__ import annotations

import base64
import json

import httpx

NOW = 1_800_000_000
ISSUER = "https://vault.test/v1/identity/oidc"
AUDIENCE = "forgejo-tenant-blue"


def token(
    tenant="blue",
    *,
    issued=NOW,
    ttl=600,
    audience=AUDIENCE,
    issuer=ISSUER,
    signature="fixture-signature",
    **claims,
):
    def encode(value):
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .decode()
            .rstrip("=")
        )

    payload = dict(
        iss=issuer,
        aud=audience,
        tenant_id=tenant,
        sub=f"entity-{tenant}",
        iat=issued,
        exp=issued + ttl,
    )
    payload.update(claims)
    return f"{encode({'alg': 'RS256', 'typ': 'JWT'})}.{encode(payload)}.{signature}"


TOKEN = token()


class VaultHTTP:
    def __init__(self, tenant="blue", *, value=None, now=NOW):
        self.tenant = tenant
        self.value = value
        self.now = now
        self.calls = []
        self.status = 200
        self.body = None
        self.client = httpx.Client(transport=httpx.MockTransport(self.reply))

    def reply(self, request):
        self.calls.append(request)
        assert str(request.url) == f"{ISSUER}/token/tenant-{self.tenant}"
        body = (
            self.body
            if self.body is not None
            else {
                "data": {
                    "token": self.value or token(self.tenant, issued=self.now),
                    "ttl": 600,
                }
            }
        )
        return httpx.Response(self.status, json=body)

    def identity(self):
        from defender.learning.author.version_control.auth import ForgejoIdentity

        return ForgejoIdentity(
            tenant_id=self.tenant,
            issuer=ISSUER,
            role=f"tenant-{self.tenant}",
            audience=AUDIENCE,
            client=self.client,
            clock=lambda: self.now,
        )


def identity(tenant="blue"):
    return VaultHTTP(tenant).identity()
