"""#1120 piece 1 — one rule for the tenant a request names (code review, third pass): the
entry points share `_tenant.requested_tenant_id` instead of each spelling "`--tenant` is
required" (six copies had drifted apart in wording)."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import _tenant

_DEFENDER = Path(__file__).resolve().parents[1]
_REFUSAL_WORDS = "--tenant is required: "


def test_an_absent_or_malformed_request_is_refused() -> None:
    with pytest.raises(_tenant.TenantRefused, match="no default tenant"):
        _tenant.requested_tenant_id(None)
    with pytest.raises(_tenant.TenantRefused):
        _tenant.requested_tenant_id("../x")
    assert _tenant.requested_tenant_id("acme") == "acme"


