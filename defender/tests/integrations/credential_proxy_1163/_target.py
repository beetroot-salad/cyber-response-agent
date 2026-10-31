"""#1163 sketch: every production name these cases need that the design does not name.

Imported at call time, never at collection, so a missing module is each case's own red. Every
name here is a WORKING choice made by the sketch author and listed as a gap in the contract map;
the case that forced it is named beside it.
"""
from __future__ import annotations

import importlib
from typing import Any


def proxy() -> Any:
    """The proxy package (new top-level, place in ORDER undecided). Names used:
    `create_app(ProxyDeps)` (Q1, S1-S6), `ProxyDeps(tenant_exports=, store=, verifier=, audit=)`
    (Q1), `CredentialSet(kind=, fields=, version=)` (Q1; kind stored, r5 A4), `mint_request_token(signer, tenant_id=,
    investigation=, grant=, expires_at=)` (Q1, S6), `OpenBaoStore(addr=, token=, mount=)` (B2),
    `TransitSigner/TransitVerifier(addr=, token=, mount=, key=)` (B3), `store_policies(kv_mount=,
    transit_mount=, key=)` (B1)."""
    return importlib.import_module("defender.credential_proxy")


def secrets_writer() -> Any:
    """The API's write-only secret port over OpenBao: `OpenBaoSecrets(addr=, token=, mount=)`
    with the existing `put_credentials` / `has_credentials` (B1)."""
    return importlib.import_module("defender.credential_proxy")


#: The run env key the http-proxy transport reads the proxy's address from (Q1).
PROXY_URL_ENV = "DEFENDER_CREDENTIAL_PROXY_URL"
#: The proxy's one endpoint for the http-proxy transport (S1): POST, `Authorization: Bearer
#: <request token>`, JSON `{system, method, url, headers, body}`; answers 200 with JSON
#: `{status, headers, body, fault, detail}`, `fault` one of None, "ConfigFault",
#: "ConfinementFault", "UpstreamFault".
PROXY_PATH = "/v1/request"
#: The access declaration's place in the tenant's settings (design's example path).
ACCESS_FILE = "settings/systems/{system}/access.yaml"
