"""#1163 repair (proxy side) against a real OpenBao: the transit verifier keeps each tenant's key
apart, and a tenant with no key is a fault, not a verdict (A11, A26)."""
from __future__ import annotations

import base64

import pytest

from defender.kit.faults import ConfigFault
from defender.tests.integrations.credential_proxy_1163._target import proxy, transit_verifier

pytestmark = pytest.mark.openbao


def test_b10_the_verifier_checks_a_signature_with_the_key_of_the_tenant_it_is_asked_for(openbao):
    """Each of two tenants' signatures verifies for that tenant only; for a tenant with no key
    (never made, or destroyed) the verifier raises ConfigFault instead of answering. O8, O1, A11,
    A26."""
    a, b, keyless = openbao.tenant(), openbao.tenant(), openbao.tenant(key=False)
    token = openbao.token_for(openbao.apply_policy(
        "proxy", proxy().store_policies(kv_mount=openbao.kv_mount)["proxy"]))
    verifier = transit_verifier(openbao.addr, token)
    payload = base64.urlsafe_b64encode(b'{"claims": 1163}')
    signatures = {tenant: openbao.signer(tenant).sign(payload) for tenant in (a, b)}

    verdicts = {(signed_by, asked_for): verifier.verify(payload, signatures[signed_by],
                                                         tenant_id=asked_for)
                for signed_by in (a, b) for asked_for in (a, b)}
    with pytest.raises(ConfigFault):
        verifier.verify(payload, signatures[a], tenant_id=keyless)
    openbao.destroy_key(b)
    with pytest.raises(ConfigFault):
        verifier.verify(payload, signatures[b], tenant_id=b)

    assert verdicts == {(x, y): x == y for x in (a, b) for y in (a, b)}
