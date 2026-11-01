"""The deployment's issuer: OpenBao's address and the OIDC issuer it signs tenant tokens as (#1214).

Fixed, well-known service names, the same for every tenant and every deployment: the services
trust each other and the infrastructure owns routing (DNS, the compose network). They are neither
host settings (no environment variable names them) nor tenant records. Defined here once: the
forge credential (`forge_credential`: the publish child, the drains, the connect command) and the
lifecycle's settings (`LifecycleConfig`) both take them from this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#: OpenBao's address on the deployment's network.
OPENBAO_URL = "https://openbao:8200"
#: OpenBao's OIDC issuer: what Forgejo's integration trusts and every minted token names as `iss`.
ISSUER_URL = f"{OPENBAO_URL}/v1/identity/oidc"


@dataclass(frozen=True)
class DeploymentIssuer:
    """The issuer as `forge_credential` reads it: `issuer_url`, `openbao_url`, and `ca_cert`
    (None: OpenBao's certificate is trusted where the TLS client looks by default, which the
    infrastructure provides)."""

    issuer_url: str = ISSUER_URL
    openbao_url: str = OPENBAO_URL
    ca_cert: Path | None = None


#: The deployment's issuer.
DEPLOYMENT_ISSUER = DeploymentIssuer()
