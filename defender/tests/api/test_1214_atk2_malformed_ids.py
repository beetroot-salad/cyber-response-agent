"""#1214 attack-2 D2: a tenant id off the grammar (here: too long, or carrying a NUL) is 404 on all four tenant routes, the
same answer as an unknown one, not 422 (r9 Endpoints '404 unknown tenant'; #1306 'the same answer for a malformed id')."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from defender.tests.api.test_1214_admin_tenants import _admin_world, _problem  # noqa: E402
from defender.tests.support.api._identity1306 import EMPTY  # noqa: E402


@pytest.mark.parametrize("tenant", ["a" * 64, "a" * 65, "a" * 300, "a%00b", "%00"],
                         ids=["64", "65", "300", "nul-inside", "nul"])
def test_a_tenant_id_off_the_grammar_is_404_on_every_tenant_route(tenant: str) -> None:
    """Get, resume, offboard and rotate answer 404 for it; a real tenant is answered (control) (O2, RC-3)."""
    world, ops = _admin_world()
    world.register(EMPTY)
    assert ops.get(f"/admin/tenants/{EMPTY}").status_code == 200, "control: a real tenant"
    for method, path in (("GET", ""), ("POST", "/resume"), ("POST", "/offboard"), ("POST", "/rotate-forge-credential")):
        _problem(ops.request(method, f"/admin/tenants/{tenant}{path}"), 404)
