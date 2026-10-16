"""Tenant refuses a construction without acceptance's token."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import _tenant


def test_a_forged_token_is_refused_by_the_guard(tmp_path: Path) -> None:
    """Every field supplied, `_token` a fresh object: `TenantRefused` naming acceptance."""
    row = _tenant.TenantRow(tenant_id=_tenant.TenantId("acme"), created_at="2026-10-01T00:00:00Z")
    with pytest.raises(_tenant.TenantRefused, match="accept_tenant"):
        _tenant.Tenant(id=_tenant.TenantId("acme"), data_root=tmp_path, row=row,
                       _token=object())
