"""#1163 repair (proxy side) against a real OpenBao: the transit verifier keeps each tenant's key
apart whichever tenant is listed first."""
from __future__ import annotations

import base64

import pytest

from defender.tests.integrations.credential_proxy_1163._target import proxy

pytestmark = pytest.mark.openbao

TENANT = "5c1b1163-7a2e-4d3f-9b8c-0e1f2a3b4c5d"
OTHER = "9d4e1163-0f6a-4b7c-8e2d-1a3b5c7d9e0f"


@pytest.mark.parametrize("order", [(TENANT, OTHER), (OTHER, TENANT)], ids=["a-first", "b-first"])
def test_b10_the_verifier_checks_a_signature_with_the_key_of_the_tenant_it_is_asked_for(
        openbao, order):
    """With two tenants' keys configured in either order, each tenant's signature verifies for
    that tenant only: for the other tenant, or an unconfigured one, it does not. O8, O1, A11."""
    keys = {tenant: proxy().transit_key_for(tenant) for tenant in order}
    policies = proxy().store_policies(kv_mount=openbao.kv_mount, transit_mount=openbao.transit_mount,
                                      tenant_keys=keys)
    tokens = {role: openbao.token_for(openbao.apply_policy(role, hcl))
              for role, hcl in policies.items()}
    signers = {}
    for tenant, key in keys.items():
        openbao.ok("POST", f"{openbao.transit_mount}/keys/{key}", json={"type": "ed25519"})
        signers[tenant] = proxy().TransitSigner(addr=openbao.addr, token=tokens[f"launcher-{tenant}"],
                                                mount=openbao.transit_mount, key=key)
    verifier = proxy().TransitVerifier(addr=openbao.addr, token=tokens["proxy"],
                                       mount=openbao.transit_mount, keys=keys)
    payload = base64.urlsafe_b64encode(b'{"claims": 1163}')
    signatures = {tenant: signer.sign(payload) for tenant, signer in signers.items()}

    verdicts = {(signed_by, asked_for): verifier.verify(payload, signatures[signed_by],
                                                         tenant_id=asked_for)
                for signed_by in keys for asked_for in keys}

    assert verdicts == {(a, b): a == b for a in keys for b in keys}
