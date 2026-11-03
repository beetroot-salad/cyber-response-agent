"""#1214 attack-3 hole 12 (r9 Identity seam): `/me` lists an open invitation only to an `active` tenant, as it lists
memberships only of active tenants.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import LAB, ME, OPS, T1, T2, World, me  # noqa: E402

STATES = ["creating", "offboarding", "offboarded"]


@pytest.mark.parametrize("state", STATES)
def test_me_omits_an_open_invitation_to_a_tenant_that_is_not_active(state: str) -> None:
    """An invitation to a creating, offboarding or offboarded tenant is not shown; the active tenant's is (r9 Identity seam)."""
    world = World(administrators=[OPS], tenants={LAB: [ME]})
    member = world.sign_in(ME)
    world.register(T1, state=state)
    world.register(T2)
    world.seed_first_members(T1, [ME])
    world.seed_first_members(T2, [ME])
    assert [row["tenant_id"] for row in me(member)["invitations"]] == [T2]
