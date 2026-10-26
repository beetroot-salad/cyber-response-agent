"""#1306: identity and administrator actions as log events on `defender.identity.audit` (K11).

Events are read from each record's extras `action`, `actor`, `tenant_id`, `target`. Targets: an
invitation's id for member.invite / invitation.accept / invitation.revoke, the removed user's id
for member.remove, the tenant id for admin.invite, the user id for admin.flag.*."""
from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import (  # noqa: E402
    BOB,
    EMPTY,
    LAB,
    ME,
    NEW,
    NO_SUCH_ID,
    T1,
    SESSION_COOKIE,
    T2,
    UNKNOWN,
    World,
    AuditLog,
    Event,
    lab,
    two_tenants,
    user_id,
)


@pytest.fixture
def audit(caplog: Any) -> AuditLog:
    return AuditLog(caplog)


def test_inviting_logs_member_invite_with_the_inviter_and_the_invitation(audit: AuditLog) -> None:
    """One member.invite event, after the invitation exists (K11)."""
    world, ann, _ = two_tenants()
    mark = audit.mark()
    row = world.invite(ann, T1, NEW).json()["id"]
    assert audit.since(mark) == [Event("member.invite", user_id(ann), T1, row)]


def test_accepting_logs_invitation_accept_for_the_endpoint_and_for_each_tenant_at_first_sign_in(audit: AuditLog) -> None:
    """invitation.accept by the accepter, once per accepted invitation, at sign-in too (K11)."""
    world, ann, bob = two_tenants()
    row = world.invite(ann, T1, BOB).json()["id"]
    world.send_pending()
    mark = audit.mark()
    assert bob.post(f"/invitations/{row}/accept").status_code == 200
    assert audit.since(mark) == [Event("invitation.accept", user_id(bob), T1, row)]
    r1 = world.invite(ann, T1, NEW).json()["id"]
    r2 = world.invite(bob, T2, NEW).json()["id"]
    world.send_pending()
    mark = audit.mark()
    new = world.sign_in(NEW)
    assert sorted(audit.since(mark), key=lambda e: e.tenant_id or "") == sorted(
        [Event("invitation.accept", user_id(new), T1, r1), Event("invitation.accept", user_id(new), T2, r2)],
        key=lambda e: e.tenant_id or "")


def test_removing_and_revoking_log_who_did_it_to_what(audit: AuditLog) -> None:
    """member.remove (by another and by self) and invitation.revoke (K11)."""
    world, ann, bob = two_tenants()
    nina = world.member(ann, T1, "nina@n.example")
    row = world.invite(ann, T1, NEW).json()["id"]
    mark = audit.mark()
    assert ann.delete(f"/tenants/{T1}/invitations/{row}").status_code == 204
    assert audit.since(mark) == [Event("invitation.revoke", user_id(ann), T1, row)]
    mark = audit.mark()
    assert ann.delete(f"/tenants/{T1}/members/{user_id(nina)}").status_code == 204
    assert nina.get("/me").status_code == 200
    assert audit.since(mark) == [Event("member.remove", user_id(ann), T1, user_id(nina))]
    mark = audit.mark()
    assert bob.delete(f"/tenants/{T2}/members/{user_id(bob)}").status_code == 204
    assert audit.since(mark) == [Event("member.remove", user_id(bob), T2, user_id(bob))]


def test_the_bootstrap_logs_as_system_and_sign_in_logs_the_accept(audit: AuditLog) -> None:
    """The file's invitation and flag are `system` events; the later accept names the same invitation (K11, O8)."""
    world = lab()
    events = audit.events()
    [invited] = [e for e in events if e.action == "member.invite"]
    [flagged] = [e for e in events if e.action == "admin.flag.set"]
    assert (invited.actor, invited.tenant_id) == ("system", LAB)
    assert (flagged.actor, flagged.tenant_id) == ("system", None)
    mark = audit.mark()
    me_session = world.sign_in(ME)
    assert audit.since(mark) == [Event("invitation.accept", user_id(me_session), LAB, invited.target)]
    assert flagged.target == user_id(world.sign_in_admin())


def test_administrator_actions_log_platform_events_and_an_invite_also_logs_the_tenants_event(audit: AuditLog) -> None:
    """admin.tenants.list, admin.invite (+ member.invite for the tenant), admin.flag.clear (K11, O5)."""
    world = lab()
    world.register(EMPTY)
    ops = world.sign_in_admin()
    ops_id = user_id(ops)
    mark = audit.mark()
    assert ops.get("/admin/tenants").status_code == 200
    [listed] = audit.since(mark)
    assert (listed.action, listed.actor, listed.tenant_id) == ("admin.tenants.list", ops_id, None)
    mark = audit.mark()
    row = ops.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": NEW}).json()["id"]
    assert sorted(audit.since(mark), key=lambda e: e.action) == [
        Event("admin.invite", ops_id, None, EMPTY), Event("member.invite", ops_id, EMPTY, row)]
    mark = audit.mark()
    world.restart(administrators=[], tenants={LAB: [ME]})
    assert audit.since(mark) == [Event("admin.flag.clear", "system", None, ops_id)]


def test_a_refused_action_logs_nothing_while_the_same_action_done_properly_does(audit: AuditLog) -> None:
    """A refusal (409/404/403/401) leaves no trace; a write that fails is the next test (K11)."""
    world = lab()
    me_session, ops = world.sign_in(ME), world.sign_in_admin()
    mark = audit.mark()
    row = world.invite(me_session, LAB, NEW).json()["id"]
    assert audit.actions(mark) == ["member.invite"]  # control: the channel works
    foreign = world.client_with_cookie(me_session.cookies[SESSION_COOKIE], origin="https://evil.example")
    refusals = {
        "invite an active member": lambda: world.invite(me_session, LAB, ME),
        "remove nobody": lambda: me_session.delete(f"/tenants/{LAB}/members/{NO_SUCH_ID}"),
        "revoke nobody": lambda: me_session.delete(f"/tenants/{LAB}/invitations/{NO_SUCH_ID}"),
        "administrator accepts": lambda: ops.post(f"/invitations/{row}/accept"),
        "foreign origin": lambda: foreign.post(f"/tenants/{LAB}/invitations", json={"email": BOB}),
        "no session": lambda: world.client().post(f"/tenants/{LAB}/invitations", json={"email": BOB}),
        "admin invite into a tenant with members": lambda: ops.post(
            f"/admin/tenants/{LAB}/invitations", json={"email": BOB}),
        "admin invite into an unknown tenant": lambda: ops.post(
            f"/admin/tenants/{UNKNOWN}/invitations", json={"email": BOB}),
        "platform route as a member": lambda: me_session.get("/admin/tenants"),
    }
    for name, act in refusals.items():
        mark = audit.mark()
        assert act().status_code in (401, 403, 404, 409), name
        assert audit.since(mark) == [], name
    assert me_session.delete(f"/tenants/{LAB}/invitations/{row}").status_code == 204
    mark = audit.mark()
    assert me_session.delete(f"/tenants/{LAB}/invitations/{row}").status_code == 404  # repeat
    assert audit.since(mark) == []


@pytest.mark.parametrize(("write", "expected"), [
    ("ensure_invitation", "member.invite"),
    ("end_membership", "member.remove"),
    ("revoke_invitation", "invitation.revoke"),
])
def test_an_action_whose_write_fails_logs_no_event_and_the_retry_logs_one(
        audit: AuditLog, write: str, expected: str) -> None:
    """The event is written only after the change is in (K11): a failing repository write leaves no event."""
    world = World(tenants={LAB: [ME]}, failing_writes=True)
    member = world.sign_in(ME)
    nina = world.member(member, LAB, "nina@n.example")
    pending = world.invite(member, LAB, NEW).json()["id"]
    cookie = member.cookies[SESSION_COOKIE]
    acts = {
        "ensure_invitation": lambda c: c.post(f"/tenants/{LAB}/invitations", json={"email": BOB}),
        "end_membership": lambda c: c.delete(f"/tenants/{LAB}/members/{user_id(nina)}"),
        "revoke_invitation": lambda c: c.delete(f"/tenants/{LAB}/invitations/{pending}"),
    }
    act = acts[write]
    world.repo.failing.add(write)
    failing_browser = world.client_with_cookie(cookie, raise_errors=False)
    mark = audit.mark()
    assert act(failing_browser).status_code >= 400
    assert audit.since(mark) == []
    world.repo.failing.clear()  # control: the same action on the same channel succeeds and logs
    assert act(failing_browser).status_code in (202, 204)
    assert audit.actions(mark) == [expected]
