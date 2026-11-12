"""#1214 attack-2 D2: a tenant id off the grammar (here: too long, or carrying a NUL) is refused on all four tenant routes,
never a 500. Since #1382 the refusal is 422 (a malformed id says nothing of any tenant), not the unknown tenant's 404.

#1214 attack-3 hole 12 (r9 Identity seam): `/me` lists an open invitation only to an `active` tenant, as it lists
memberships only of active tenants.
"""
from __future__ import annotations

import pytest

pytest.importorskip('fastapi')

from defender.tests.api.test_admin_tenants import _admin_world, _problem  # noqa: E402
from defender.tests.support.api._identity1306 import EMPTY  # noqa: E402
from defender.tests.support.api._identity1306 import LAB, ME, OPS, T1, T2, World, me  # noqa: E402


@pytest.mark.parametrize("tenant", ["a" * 64, "a" * 65, "a" * 300, "a%00b", "%00"],
                         ids=["64", "65", "300", "nul-inside", "nul"])
def test_a_tenant_id_off_the_grammar_is_422_on_every_tenant_route(tenant: str) -> None:
    """Get, resume, offboard and rotate answer 422 for it; a real tenant is answered (control) (O2, RC-3, #1382)."""
    world, ops = _admin_world()
    world.register(EMPTY)
    assert ops.get(f"/admin/tenants/{EMPTY}").status_code == 200, "control: a real tenant"
    for method, path in (("GET", ""), ("POST", "/resume"), ("POST", "/offboard"), ("POST", "/rotate-forge-credential")):
        _problem(ops.request(method, f"/admin/tenants/{tenant}{path}"), 422)


#: Invitations are written while a tenant is `active` (P-L), so the tenant then moves: a `creating` one never holds any.
STATES = ["offboarding", "offboarded"]


@pytest.mark.parametrize("state", STATES)
def test_me_omits_an_open_invitation_to_a_tenant_that_is_not_active(state: str) -> None:
    """An invitation made while the tenant was active is not shown once it is offboarding or offboarded; the active tenant's is (r9 Identity seam, P-L)."""
    world = World(administrators=[OPS], tenants={LAB: [ME]})
    member = world.sign_in(ME)
    world.register(T1)
    world.register(T2)
    world.seed_first_members(T1, [ME])
    world.seed_first_members(T2, [ME])
    assert {row["tenant_id"] for row in me(member)["invitations"]} == {T1, T2}  # control: both offered while active
    world.move_tenant(T1, state)
    assert [row["tenant_id"] for row in me(member)["invitations"]] == [T2]
