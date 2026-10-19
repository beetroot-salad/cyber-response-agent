"""One rule for the tenant a request names."""
from __future__ import annotations


import pytest

from defender.tenancy import _tenant


def test_an_absent_or_malformed_request_is_refused() -> None:
    with pytest.raises(_tenant.TenantRefused, match="no default tenant"):
        _tenant.requested_tenant_id(None)
    with pytest.raises(_tenant.TenantRefused):
        _tenant.requested_tenant_id("../x")
    assert _tenant.requested_tenant_id("acme") == "acme"


