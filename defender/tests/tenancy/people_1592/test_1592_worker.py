"""#1592 r12 "The request worker": a poll carries out each user's open requests from the current wanted state and
deletes exactly the ids it took (OD-2, OD-4a, OD-7, PP-4, F6(a)).

The identity and tenancy memory twins share one store; Forgejo is `PeopleForge`; the sessions are a real database
built as the design's script describes (the worker's seam is `forge_sessions_dsn`, FC-4), so the module is marked
`postgres`. A poll is `await worker.poll()` (FC-3).
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import uuid

import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy._twin1496 import offboard_twin
from defender.tests.tenancy.people_1592._spec1592 import login_of, signed_in_data
from defender.tests.tenancy.people_1592._world1592 import NOW, T, U2, People

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


# --- removal -----------------------------------------------------------------------------------------


async def test_a_membership_ended_in_the_only_tenant_removes_suspends_and_ends_sessions(people: People):
    """Removal: Bob's only membership ends. One poll takes him out of T's team, sets `prohibit_login`, deletes his
    Forgejo sessions, and deletes the request. Alice, still a member, is untouched."""
    await people.tenant(T)
    bob = await people.person("bob@x.org", T)
    alice = await people.person("alice@x.org", T)
    await people.end(bob, T)
    assert (await people.open_requests()) == [(str(bob.id), T)]

    await people.step()

    assert people.forge.members(T) == {login_of(str(alice.id))}
    assert login_of(str(bob.id)) in people.forge.prohibit_login
    assert login_of(str(alice.id)) not in people.forge.prohibit_login
    assert people.sessions.keys() == {people.key("alice@x.org")}
    assert (await people.open_requests()) == []


async def test_a_person_kept_in_another_tenant_leaves_the_team_and_keeps_their_sessions(people: People):
    """OD-4a: Carol leaves T but stays in U2. She is out of T's team, still in U2's, not suspended, and her stamped
    session survives (she has no `signed_out_at`)."""
    await people.tenant(T)
    await people.tenant(U2)
    carol = await people.person("carol@x.org", T, U2)
    await people.end(carol, T)

    await people.step()

    login = login_of(str(carol.id))
    assert login not in people.forge.members(T)
    assert login in people.forge.members(U2)
    assert login not in people.forge.prohibit_login
    assert people.sessions.keys() == {people.key("carol@x.org")}
    assert (await people.open_requests()) == []


async def test_ended_then_reinvited_and_accepted_before_a_poll_stays_in_the_team(people: People):
    """Order: Erin's membership ends, she is re-invited and accepts, all before the worker runs. Her two (U, T)
    requests are carried out together from the current state: she stays in the team, unsuspended. (FC-9: the design's
    scenario stops at "re-invited", which leaves an `invited` row that the wanted rule does not count.)"""
    await people.tenant(T)
    erin = await people.person("erin@x.org", T)
    await people.end(erin, T)
    invitation = await people.identity.ensure_invitation(erin.id, T, invited_by=None, now=NOW)
    assert await people.identity.accept_invitation(invitation.id, now=NOW)
    assert len(await people.open_requests()) == 3

    await people.step()

    assert login_of(str(erin.id)) in people.forge.members(T)
    assert login_of(str(erin.id)) not in people.forge.prohibit_login
    assert people.sessions.keys() == {people.key("erin@x.org")}
    assert (await people.open_requests()) == []


# --- tenant requests --------------------------------------------------------------------------------


async def test_offboarding_a_creating_tenant_whose_team_is_absent_expands_to_nothing(people: People):
    """A (none, T) for a tenant still `creating`: its organisation answers 404, so the team is absent and has no
    members; T has no memberships. The request is expanded to nothing and deleted, and Forgejo is not written."""
    await people.tenant(T, state="creating", team=False)
    await offboard_twin(people.tenants, T)
    assert (await people.open_requests()) == [(None, T)]

    await people.step()
    await people.step()  # an expansion and its (U, T) rows may take a poll each: none here

    assert (await people.open_requests()) == []
    assert people.forge.writes() == []


async def test_an_unknown_p_login_in_the_team_is_wanted_nowhere_and_is_removed(people: People):
    """Activation's state commit records (none, T); its expansion takes in every well-formed `p-<id>` in T's team,
    known to the product or not. Xavier's id is unknown, so he is wanted nowhere: removed from the team, suspended,
    and his sessions deleted. A login that is not `p-<uuid>` (an administrator's) is logged and left."""
    await people.tenant(T)
    xavier = login_of(str(uuid.UUID(fixture_uuid("user:1592-xavier"))))
    people.forge.add_account(xavier, login_name="sub-of-nobody")
    people.forge.add_account("p-not-a-uuid")
    people.forge.team_members[(f"t-{T}", "members")] |= {xavier, "p-not-a-uuid"}
    people.sessions.plant("xavier0000000000", signed_in_data(people.forge.uid(xavier)),
                          signed_in_at=dt.datetime.now(dt.UTC))
    people.tenants._tenants[T] = dataclasses.replace(  # an activation in flight, as the twin's own row
        people.tenants._tenants[T], state="creating", pending_action="create", step="activate", step_actor="service")
    async with people.tenants.lock(T) as held:
        await held.commit(step=None, actor=None, state="active", pending_action=None)

    for _ in range(2):
        await people.step()

    assert people.forge.members(T) == {"p-not-a-uuid"}
    assert xavier in people.forge.prohibit_login
    assert "p-not-a-uuid" not in people.forge.prohibit_login
    assert people.sessions.keys() == set()
    assert (await people.open_requests()) == []


# --- never two runs for one user ---------------------------------------------------------------------


async def test_a_poll_never_starts_a_second_run_for_a_user_with_one_in_flight(people: People):
    """OD-7: Dave's run waits on Forgejo when his membership ends. A poll meanwhile starts no run for him; the first
    run deletes only the ids it took, so the newer request stays, and the next poll removes him."""
    await people.tenant(T)
    dave = await people.person("dave@x.org", T)
    login = login_of(str(dave.id))
    row = await people.identity.active_membership(dave.id, T)
    # the request the first run takes: a product sign-out of Dave's (he stays wanted in T)
    await people.identity.add_session("dave-product", dave.id, now=NOW, expires_at=NOW + dt.timedelta(days=7))
    await people.identity.sign_out(dave.id, "dave-product")
    path = f"/api/v1/users/{login}"
    gate = people.forge.gate("GET", path)

    people.worker = people.build()
    await people.worker.poll()  # r15: returns without waiting for the run it started
    for _ in range(100):
        if f"GET {path}" in people.forge.arrived:
            break
        await asyncio.sleep(0.01)
    assert f"GET {path}" in people.forge.arrived, "control: the first run reached Forgejo"
    assert await people.identity.end_membership(row.id, ended_by=None, now=NOW)

    await people.worker.poll()  # not settled: Dave's first run is still gated
    assert people.forge.arrived.count(f"GET {path}") == 1, "a second run started for Dave"

    gate.set()
    await asyncio.wait_for(people.worker.settle(), timeout=5)
    assert (await people.open_requests()) == [(str(dave.id), T)], "the run deleted a request recorded after it took its ids"

    await people.step()
    assert login not in people.forge.members(T)
    assert (await people.open_requests()) == []
