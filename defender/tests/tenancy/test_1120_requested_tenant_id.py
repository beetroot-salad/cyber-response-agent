"""One rule for the tenant a request names."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid


import pytest

from defender.tenancy import _tenant
from defender.records._tenant_id import TenantRefused


def test_an_absent_or_malformed_request_is_refused() -> None:
    with pytest.raises(TenantRefused, match="no default tenant"):
        _tenant.requested_tenant_id(None)
    with pytest.raises(TenantRefused):
        _tenant.requested_tenant_id("../x")
    assert _tenant.requested_tenant_id(fixture_uuid("tenant:acme")) == fixture_uuid("tenant:acme")


