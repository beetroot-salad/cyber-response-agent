"""#1120 piece 1 — `Tenant` refuses a construction that does not hold acceptance's token
(code review, max: the spec's N10 run-time leg left the token out, so dataclass machinery
refused before the guard ran, and deleting the guard kept the suite green)."""
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
