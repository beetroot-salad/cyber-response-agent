"""Tenant refuses a construction without acceptance's token."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from pathlib import Path

import pytest

from defender.tenancy import _tenant
from defender.records._tenant_id import TenantId, TenantRefused


def test_a_forged_token_is_refused_by_the_guard(tmp_path: Path) -> None:
    """Every field supplied, `_token` a fresh object: `TenantRefused` naming acceptance."""
    with pytest.raises(TenantRefused, match="accept_tenant"):
        _tenant.Tenant(id=TenantId(fixture_uuid("tenant:acme")), data_root=tmp_path, _token=object())
