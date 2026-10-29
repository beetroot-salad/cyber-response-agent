"""#1306 / #1214 r9: the deployment bootstrap file lists administrators only — ensure reachable, never re-invite (O8, DC-1, DC-5, Q3)."""
from __future__ import annotations

import contextlib
import re
import time

import pytest

pytest.importorskip("fastapi")

# A forgotten `world.call` leaves a never-awaited coroutine; pytest reports its RuntimeWarning as an unraisable exception, so both are errors.
pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]


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
