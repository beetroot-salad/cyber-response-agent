"""#1306: platform administrators — separate accounts, one-time code, narrow powers (O5, K10, DC-1, DC-5).

#1306 / #1214 r9: the deployment bootstrap file lists administrators only — ensure reachable, never re-invite (O8, DC-1, DC-5, Q3).
"""
from __future__ import annotations

from http import HTTPStatus
import contextlib
import re
import time

import pytest

pytest.importorskip('fastapi')

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
    Bootstrap,
    IdentityService,
    invitation_id,
    invitation_rows,
    items,
    lab,
    me,
    same_invite_answer,
    tenants_of,
    user_id,
)
from defender.tests.support.api._identity1306 import (  # noqa: E402
    DAY,
    HOUR,
    LAB,
    ME,
    OPS,
    SECOND,
    SEVEN_DAYS,
    Bootstrap,
    BootstrapRefused,
    IdentityService,
    World,
    invitation_id,
    lab,
    me,
    tenants_of,
    user_id,
)


# A forgotten `world.call` leaves a never-awaited coroutine; pytest reports its RuntimeWarning as an unraisable exception, so both are errors.
pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]


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


def test_a_refused_administrator_sign_in_does_not_activate_the_account() -> None:
    """Refused means refused: only the code-backed sign-in makes the administrator `active` (flow 2, O5)."""
    world = lab()
    world.signin.has_otp_answers[world.signin.account_for(OPS)] = True
    assert world.sign_in_response(world.client(), OPS, amr=("pwd",), name="Refused").status_code == 403
    refused = world.call(world.repo.user_by_email, OPS)
    assert (refused.status, refused.activated_at) == ("invited", None)
    assert refused.display_name != "Refused"
    world.sign_in_admin()
    assert world.call(world.repo.user_by_email, OPS).status == "active"  # control


def test_an_administrators_invitation_records_the_administrator_as_inviter() -> None:
    """`memberships.invited_by` is the user who invited: here the administrator (data model, O5)."""
    world = lab()
    me_session = world.sign_in(ME)
    assert me_session.delete(f"/tenants/{LAB}/members/{user_id(me_session)}").status_code == 204
    ops = world.sign_in_admin()
    invited = ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": NEW})
    assert invited.status_code == 202
    assert world.call(world.repo.membership, invited.json()["id"]).invited_by == user_id(ops)


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
    # The same 403 whatever the tenant: unknown, with members, malformed (no probing, O1/P-D).
    for tenant in (EMPTY, UNKNOWN, LAB, "not-a-tenant-id"):
        assert me_session.post(f"/admin/tenants/{tenant}/invitations", json={"email": NEW}).status_code == 403, tenant
    ops = world.sign_in_admin()
    assert ops.get("/admin/tenants").status_code == 200
    assert ops.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": NEW}).status_code == 202
    assert [r["email"] for r in invitation_rows(world.sign_in(ME), LAB)] == []  # nothing leaked into the lab


def test_the_identity_refusals_are_rfc_9457_problems() -> None:
    """401 without a cookie, 403 for a bad Origin, 403 for a member on a platform route, 409 on a tenant with members (F-4)."""
    world = lab()
    world.register(EMPTY)
    me_session = world.sign_in(ME)
    ops = world.sign_in_admin()
    refusals = [
        (401, world.client().get("/me")),
        (403, world.client_with_cookie(me_session.cookies[SESSION_COOKIE], origin="https://evil.example")
         .post(f"/tenants/{LAB}/invitations", json={"email": NEW})),
        (403, me_session.get("/admin/tenants")),
        (409, ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": NINA})),
    ]
    for code, response in refusals:
        assert response.status_code == code, response.text
        assert response.headers["content-type"] == "application/problem+json"
        problem = response.json()
        assert {"type", "title", "status", "detail"} <= set(problem)
        assert (problem["status"], problem["title"]) == (code, HTTPStatus(code).phrase)
    assert "www-authenticate" not in refusals[0][1].headers
    assert ops.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": NEW}).status_code == 202  # control


def test_an_administrators_invitation_calls_no_port_before_the_response() -> None:
    """P-E/DC-8 on the platform route too: the request writes rows; the sender sends afterwards (O2, O5)."""
    world = lab()
    world.register(EMPTY)
    world.sign_in(ME)
    ops = world.sign_in_admin()
    before = (list(world.signin.every_call), list(world.mail.attempts))
    for email in (NEW, ME):  # a new person, and an active one with an account
        assert ops.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": email}).status_code == 202
    assert (world.signin.every_call, world.mail.attempts) == before
    world.send_pending()  # control: both were pending
    assert world.signin.sends_to(NEW) == 1
    assert [n.to for n in world.mail.sent] == [ME]


def test_an_administrator_invites_only_into_a_tenant_with_no_active_members() -> None:
    """Empty tenant 202, tenant with members 409, unknown 404, malformed 422 (#1382); the invitee joins (O2, O5)."""
    world = lab()
    world.register(EMPTY)
    world.sign_in(ME)  # the lab now has an active member
    ops = world.sign_in_admin()
    assert ops.post(f"/admin/tenants/{EMPTY}/invitations", json={"email": NEW}).status_code == 202
    assert ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": NINA}).status_code == 409
    assert ops.post(f"/admin/tenants/{UNKNOWN}/invitations", json={"email": NINA}).status_code == 404
    assert ops.post("/admin/tenants/not-a-tenant-id/invitations", json={"email": NINA}).status_code == 422
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
    world.restart(administrators=[])  # DC-5: the file now lists nobody (no re-send yet due)
    world.clock.advance((days - 1) * DAY)
    assert tenants_of(world.sign_in(OPS)) == ({LAB} if joins else set())


def test_a_flagged_user_cannot_accept_even_through_a_session_without_a_code() -> None:
    """Acceptance refuses the flagged user, not only the code-backed session (K10, flow 3)."""
    world = lab()
    me_session = world.sign_in(ME)  # a password-only session, kept across the restart
    assert me_session.delete(f"/tenants/{LAB}/members/{user_id(me_session)}").status_code == 204
    world.restart(administrators=[OPS, ME])  # ME is now flagged
    ops = world.sign_in_admin()
    row = ops.post(f"/admin/tenants/{LAB}/invitations", json={"email": ME})
    assert row.status_code == 202
    assert me(me_session)["invitations"] == []
    assert me_session.post(f"/invitations/{row.json()['id']}/accept").status_code == 404
    assert tenants_of(me_session) == set()


def test_an_administrator_cannot_accept_an_invitation() -> None:
    """Acceptance refuses flagged users: 404, and the row stays open (K10, flow 3)."""
    world = lab()
    me_session = world.sign_in(ME)
    world.invite(me_session, LAB, OPS)
    row = invitation_id(me_session, LAB, OPS)
    ops = world.sign_in_admin()
    assert me(ops)["invitations"] == []  # an open row addressed to the administrator is not offered (K10)
    assert ops.post(f"/invitations/{row}/accept").status_code == 404
    assert tenants_of(ops) == set()
    assert [r["id"] for r in invitation_rows(me_session, LAB)] == [row]


def test_removing_an_email_from_the_file_removes_powers_at_the_next_request_after_start() -> None:
    """Un-flagged at start -> the live session loses platform powers; the account can then be invited (O5, DC-5)."""
    world = lab()
    ops = world.sign_in_admin()
    assert ops.get("/admin/tenants").status_code == 200
    world.restart(administrators=[])
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


def test_an_unflagging_made_by_another_process_takes_effect_at_this_processs_next_request() -> None:
    """P-A: the flag is read on every request; a session already used keeps no stale powers (O5, DC-5)."""
    world = lab()
    ops = world.sign_in_admin()
    assert ops.get("/admin/tenants").status_code == 200  # the session has been used
    other_process = IdentityService(world.repo, signin=world.signin, mail=world.mail, clock=world.clock,
                                    bootstrap=Bootstrap(administrators=()))
    world.call(other_process.start)  # another API process, started with OPS removed from the file
    assert ops.get("/admin/tenants").status_code == 403
    assert me(ops)["administrator"] is False


X = "x@x.example"


FILE = {"administrators": [OPS]}


def test_the_first_start_creates_the_administrators_account_and_sends_one_email() -> None:
    """The file makes only the administrator: an account needing a password and a code, one send, no tenant person (Q3, O8)."""
    world = lab()
    accounts = {a.email: a for a in world.signin.accounts.values()}
    assert OPS in accounts
    assert accounts[OPS].required_actions == {"set_password", "set_up_otp"}
    assert world.signin.sends_to(OPS) == 1
    assert world.mail.sent == []
    bare = World(administrators=[OPS])  # control: the file alone, no seeded first member
    assert {a.email for a in bare.signin.accounts.values()} == {OPS}
    assert all(lifespan == SEVEN_DAYS for _, lifespan in bare.signin.set_password_sent)


def test_the_lab_people_sign_in_and_the_administrator_signs_in_twice() -> None:
    """me joins the lab; ops is refused with the password only, then admitted with the code (O5, O8)."""
    world = lab()
    assert tenants_of(world.sign_in(ME)) == {LAB}
    world.signin.has_otp_answers[world.signin.account_for(OPS)] = True
    assert world.sign_in_response(world.client(), OPS, amr=("pwd",)).status_code == 403
    ops = world.sign_in(OPS, amr=("pwd", "otp"))
    body = me(ops)
    assert (body["administrator"], body["tenants"]) == (True, [])


def test_restarts_send_nothing_to_active_people_even_after_the_member_leaves_the_lab() -> None:
    """Restart is not re-invite: no email, no new invitation, even after `me` left (O8)."""
    world = lab()
    me_session = world.sign_in(ME)
    world.sign_in_admin()
    world.restart(**FILE)
    sent = world.signin.sends_to(OPS) + world.signin.sends_to(ME)
    assert me_session.delete(f"/tenants/{LAB}/members/{user_id(me_session)}").status_code == 204
    world.restart(**FILE)
    assert world.signin.sends_to(OPS) + world.signin.sends_to(ME) == sent
    assert world.mail.sent == []
    assert tenants_of(world.sign_in(ME)) == set()


def test_an_administrator_still_invited_gets_a_fresh_email_only_when_the_last_is_over_seven_days_old() -> None:
    """Under/at 7 days nothing; over it a fresh set-password email for the administrator, and none for a first member the file no longer lists (O8, DC-3, Q3)."""
    world = lab()
    sent_at = world.clock.now
    for at in (6 * DAY, SEVEN_DAYS - SECOND, SEVEN_DAYS):  # "older than 7 days": not yet at exactly 7
        world.clock.now = sent_at + at
        world.restart(**FILE)
        assert world.signin.sends_to(OPS) == 1, at
    world.clock.advance(SECOND)
    world.restart(**FILE)
    assert world.signin.sends_to(OPS) == 2
    assert world.signin.sends_to(ME) == 1  # replaced behaviour: the bootstrap no longer nudges first members
    world.sign_in_admin()
    world.clock.advance(8 * DAY)
    world.restart(**FILE)
    assert world.signin.sends_to(OPS) == 2  # active now


def test_start_only_marks_sends_pending_and_calls_no_port() -> None:
    """The bootstrap marks sends as pending; only the sender sends (O8, flow 1)."""
    world = World(administrators=[OPS], start=False)
    world.call(world.service.start)
    assert (world.signin.every_call, world.mail.attempts) == ([], [])
    world.send_pending()  # control: it is pending
    assert world.signin.sends_to(OPS) == 1


def test_sends_that_failed_are_made_after_a_restart_and_only_once() -> None:
    """Sends that failed before a restart go out once the failure backoff has passed (O8, flow 1)."""
    world = World(administrators=[OPS], failing_sends=1)
    assert world.signin.sends_to(OPS) == 0
    world.clock.advance(HOUR + SECOND)
    world.restart(**FILE)
    assert world.signin.sends_to(OPS) == 1
    world.clock.advance(HOUR + SECOND)
    world.send_pending()
    assert world.signin.sends_to(OPS) == 1  # sent once, not again


def test_a_dropped_send_is_re_requested_when_the_person_is_later_listed_as_administrator() -> None:
    """A revoked, never-sent invite is dropped; listing the person later gets exactly one email (O8, flow 1)."""
    world = lab()
    me_session = world.sign_in(ME)
    assert world.invite(me_session, LAB, X).status_code == 202
    revoked = me_session.delete(f"/tenants/{LAB}/invitations/{invitation_id(me_session, LAB, X)}")
    assert revoked.status_code == 204
    world.send_pending()
    world.clock.advance(HOUR + SECOND)
    world.send_pending()
    assert (world.signin.sends_to(X), world.mail.sent) == (0, [])  # dropped, nothing pending
    world.restart(administrators=[OPS, X])
    assert world.signin.sends_to(X) == 1
    world.restart(administrators=[OPS, X])
    assert world.signin.sends_to(X) == 1  # control: not again at the next start


def test_a_file_that_still_has_a_tenants_section_makes_no_first_member() -> None:
    """Q3: whether refused or ignored, a `tenants` section invites nobody and registers no tenant (GAP-D-1: refuse vs ignore is unspecified)."""
    world = World(administrators=[OPS])
    with contextlib.suppress(TypeError, BootstrapRefused):  # GAP-D-1: either answer is allowed
        world.call(IdentityService(
            world.repo, signin=world.signin, mail=world.mail, clock=world.clock,
            bootstrap=Bootstrap(administrators=(OPS,), tenants={LAB: (ME,)}),  # type: ignore[call-arg]
        ).start)
    world.send_pending()
    assert ME not in {a.email for a in world.signin.accounts.values()}
    assert world.signin.sends_to(ME) == 0
    assert world.call(world.tenants.tenants) == []
    control = lab()  # control: the same people exist when seeded (the harness), so the check above can fail
    assert ME in {a.email for a in control.signin.accounts.values()}


@pytest.mark.parametrize("signed_in", [False, True])
def test_start_refuses_to_newly_flag_someone_who_is_invited_or_active_in_a_tenant(signed_in: bool) -> None:
    """The file may not make a member (invited or active) an administrator (O8, K10)."""
    world = lab()
    if signed_in:
        world.sign_in(ME)
    with pytest.raises(BootstrapRefused, match=re.escape(ME)):
        world.restart(administrators=[OPS, ME])


def test_start_flags_someone_whose_membership_ended_and_keeps_an_invited_administrator_flagged() -> None:
    """Refusal is only for invited/active rows, and never for an already-flagged administrator (O8, DC-1)."""
    world = lab()
    me_session = world.sign_in(ME)
    world.invite(me_session, LAB, OPS)  # an invitation to a flagged administrator
    world.restart(**FILE)  # DC-1: not refused
    assert me(world.sign_in_admin())["administrator"] is True
    assert me_session.delete(f"/tenants/{LAB}/members/{user_id(me_session)}").status_code == 204
    world.restart(administrators=[OPS, ME])  # ended row: allowed
    # K10/O5: the flag alone is not power; ME's earlier password-only session has none
    assert me_session.get("/admin/tenants").status_code == 403
    assert me(me_session)["administrator"] is False
    world.signin.has_otp_answers[world.signin.account_for(ME)] = True
    fresh = world.sign_in(ME, amr=("pwd", "otp"))  # control: the code-backed session has them
    assert me(fresh)["administrator"] is True
    assert fresh.get("/admin/tenants").status_code == 200


def test_a_session_that_used_a_code_before_its_user_was_flagged_has_powers_once_flagged() -> None:
    """The session records whether a code was used, flagged or not; powers = flagged now and a code-backed session (O5, DC-5)."""
    world = lab()
    with_code = world.sign_in(ME, amr=("pwd", "otp"))
    password_only = world.sign_in(ME)
    assert me(with_code)["administrator"] is False  # not flagged yet
    assert with_code.delete(f"/tenants/{LAB}/members/{user_id(with_code)}").status_code == 204
    world.restart(administrators=[OPS, ME])
    assert me(with_code)["administrator"] is True
    assert with_code.get("/admin/tenants").status_code == 200
    assert me(password_only)["administrator"] is False  # control


def test_emails_in_the_file_are_compared_lower_cased() -> None:
    """Mixed-case file entries name the same lower-cased person (O8)."""
    world = World(administrators=["OPS@X.example"])
    assert {a.email for a in world.signin.accounts.values()} == {OPS}


def test_the_app_does_not_start_when_the_bootstrap_refuses() -> None:
    """A refused file stops start-up: entering the lifespan raises BootstrapRefused and nothing is sent (O8, DC-4)."""
    world = World(administrators=[OPS], tenants={LAB: [ME]}, start=False)
    world.build(administrators=[OPS, ME], tenants={})  # ME is invited in the lab: the file may not flag them
    with pytest.raises(BootstrapRefused, match=re.escape(ME)), world.lifespan_client():
        pass
    assert (world.signin.every_call, world.mail.attempts) == ([], [])


def test_entering_the_apps_lifespan_runs_start_and_the_senders_first_pass() -> None:
    """The real app starts the bootstrap and sends without anyone calling either (DC-4)."""
    world = World(administrators=[OPS], start=False)
    assert world.signin.accounts == {}
    with world.lifespan_client():
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and world.signin.sends_to(OPS) < 1:
            time.sleep(0.02)
        assert world.signin.sends_to(OPS) == 1
        assert me(world.sign_in_admin())["administrator"] is True


@pytest.mark.parametrize("email", ["a\x00b@x.example", " ", ""])
def test_a_bootstrap_file_naming_an_unstorable_or_blank_email_is_refused_at_load(email: str) -> None:
    """#1349 B1.3: refused as the file is read, not when the database or the mail sender meets it."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Bootstrap(administrators=(email,))
    assert Bootstrap(administrators=(" Ops@X.example ",)).administrators == ("ops@x.example",)
    # a non-breaking space copied from a web page is trimmed, so the administrator stays the same person
    assert Bootstrap(administrators=("ops@x.example\u00a0",)).administrators == ("ops@x.example",)
