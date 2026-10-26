"""#1306: platform administrators — separate accounts, one-time code, narrow powers (O5, K10, DC-1, DC-5)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import (  # noqa: E402
    DAY,
    EMPTY,
    LAB,
    ME,
    NEW,
    NINA,
    NO_SUCH_ID,
    OPS,
    SESSION_COOKIE,
    UNKNOWN,
    invitation_id,
    invitation_rows,
    items,
    lab,
    me,
    same_invite_answer,
    tenants_of,
    user_id,
)


@pytest.mark.parametrize("has_code", [True, False])
def test_an_administrator_without_a_code_is_refused_and_setup_is_required_when_there_is_none(has_code: bool) -> None:
    """Password-only administrator sign-in -> 403, no session; an account with no code is made to set one up (O5)."""
    world = lab()
    account = world.signin.account_for(OPS)
    world.signin.has_otp_answers[account] = has_code
    browser = world.client()
    refused = world.sign_in_response(browser, OPS, amr=("pwd",))
    assert refused.status_code == 403
    assert SESSION_COOKIE not in browser.cookies
    assert world.signin.otp_required == ([] if has_code else [account])
    world.signin.has_otp_answers[account] = True
    assert me(world.sign_in(OPS, amr=("pwd", "otp")))["administrator"] is True  # control


def test_an_administrator_session_reads_platform_routes_and_holds_no_tenants() -> None:
    """An administrator lists all tenants and is in none (O5, K10)."""
    world = lab()
    world.register(EMPTY)
    ops = world.sign_in_admin()
    body = me(ops)
    assert (body["administrator"], body["tenants"], body["invitations"]) == (True, [], [])
    assert body["user"]["email"] == OPS
    assert sorted(t["tenant_id"] for t in items(ops.get("/admin/tenants"))) == sorted([LAB, EMPTY])


@pytest.mark.parametrize(("method", "path", "body"), [
    ("GET", "alerts", None), ("GET", "members", None), ("GET", "invitations", None),
    ("POST", "invitations", {"email": NEW}), ("DELETE", f"members/{NO_SUCH_ID}", None),
    ("DELETE", f"invitations/{NO_SUCH_ID}", None),
])
def test_an_administrator_gets_404_on_every_tenant_route(method: str, path: str, body: object) -> None:
    """Administrators can never read or act inside a tenant (O5, K10, P-D)."""
    world = lab()
    assert world.sign_in(ME).get(f"/tenants/{LAB}/members").status_code == 200  # control: a member
    ops = world.sign_in_admin()
    asked = ops.request(method, f"/tenants/{LAB}/{path}", json=body)
    unknown = ops.request(method, f"/tenants/{UNKNOWN}/{path}", json=body)
    assert asked.status_code == unknown.status_code == 404
    assert asked.text.replace(LAB, "{T}") == unknown.text.replace(UNKNOWN, "{T}")


def test_a_non_administrator_is_403_on_platform_routes_and_an_administrator_is_not() -> None:
    """Platform routes need the flag and a code-backed session (O1, O5)."""
    world = lab()
    world.register(EMPTY)
    me_session = world.sign_in(ME)
    assert me_session.get("/admin/tenants").status_code == 403
    assert me_session.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": NEW}).status_code == 403
    ops = world.sign_in_admin()
    assert ops.get("/admin/tenants").status_code == 200
    assert ops.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": NEW}).status_code == 202
    assert [r["email"] for r in invitation_rows(world.sign_in(ME), LAB)] == []  # nothing leaked into the lab


def test_an_administrator_invites_only_into_a_tenant_with_no_active_members() -> None:
    """Empty tenant 202, tenant with members 409, unknown or malformed 404; the invitee joins (O2, O5)."""
    world = lab()
    world.register(EMPTY)
    world.sign_in(ME)  # the lab now has an active member
    ops = world.sign_in_admin()
    assert ops.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": NEW}).status_code == 202
    assert ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": NINA}).status_code == 409
    assert ops.post(f"/admin/tenants/{UNKNOWN}/invitations", json={"email": NINA}).status_code == 404
    assert ops.post("/admin/tenants/not-a-tenant-id/invitations", json={"email": NINA}).status_code == 404
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1
    assert world.signin.sends_to(NINA) == 0
    assert tenants_of(world.sign_in(NEW)) == {EMPTY}


def test_a_tenant_left_with_no_active_members_can_be_recovered_by_an_administrator() -> None:
    """The last member leaves; the administrator invites a new first member (O4, O5)."""
    world = lab()
    me_session = world.sign_in(ME)
    assert me_session.delete(f"/tenants/{LAB}/members/{user_id(me_session)}").status_code == 204
    ops = world.sign_in_admin()
    assert ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": NEW}).status_code == 202
    world.send_pending()
    assert tenants_of(world.sign_in(NEW)) == {LAB}


def test_inviting_an_administrators_email_answers_alike_and_sends_nothing() -> None:
    """Same response and listing as any invitation; no email to the administrator (O5/P-E)."""
    world = lab()
    me_session = world.sign_in(ME)
    sent_before = world.signin.sends_to(OPS)
    admin_invite = world.invite(me_session, LAB, OPS)
    other_invite = world.invite(me_session, LAB, NEW)
    same_invite_answer(admin_invite, other_invite)
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1  # control: the pass did send
    assert world.signin.sends_to(OPS) == sent_before
    assert world.mail.sent == []
    rows = invitation_rows(me_session, LAB)
    assert {r["email"] for r in rows} == {OPS, NEW}
    assert len({frozenset(r) for r in rows}) == 1


@pytest.mark.parametrize(("days", "joins"), [(6, True), (8, False)])
def test_an_invitation_to_an_administrator_expires_seven_days_after_it_was_made(days: int, joins: bool) -> None:
    """Unsent, yet it lapses (DC-1): once un-flagged, a first sign-in joins only if it is under 7 days old."""
    world = lab()
    me_session = world.sign_in(ME)
    world.invite(me_session, LAB, OPS)
    world.clock.advance(DAY)
    world.restart(administrators=[], tenants={LAB: [ME]})  # DC-5: the file now lists nobody (no re-send yet due)
    world.clock.advance((days - 1) * DAY)
    assert tenants_of(world.sign_in(OPS)) == ({LAB} if joins else set())


def test_an_administrator_cannot_accept_an_invitation() -> None:
    """Acceptance refuses flagged users: 404, and the row stays open (K10, flow 3)."""
    world = lab()
    me_session = world.sign_in(ME)
    world.invite(me_session, LAB, OPS)
    row = invitation_id(me_session, LAB, OPS)
    ops = world.sign_in_admin()
    assert ops.post(f"/invitations/{row}/accept").status_code == 404
    assert tenants_of(ops) == set()
    assert [r["id"] for r in invitation_rows(me_session, LAB)] == [row]


def test_removing_an_email_from_the_file_removes_powers_at_the_next_request_after_start() -> None:
    """Un-flagged at start -> the live session loses platform powers; the account can then be invited (O5, DC-5)."""
    world = lab()
    ops = world.sign_in_admin()
    assert ops.get("/admin/tenants").status_code == 200
    world.restart(administrators=[], tenants={LAB: [ME]})
    refused = ops.get("/admin/tenants")
    assert refused.status_code == 403
    assert me(ops)["administrator"] is False
    me_session = world.sign_in(ME)
    world.invite(me_session, LAB, OPS)
    world.send_pending()
    assert [n.to for n in world.mail.sent] == [OPS]  # ops is active: our notification, not a set-password
    [invitation] = me(ops)["invitations"]
    assert ops.post(f"/invitations/{invitation['id']}/accept").status_code == 200
    assert tenants_of(ops) == {LAB}
