"""#1306: the deployment bootstrap file — ensure reachable, never re-invite (O8, DC-1, DC-5)."""
from __future__ import annotations

import re
import time

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from defender.tests.support.api._identity1306 import (  # noqa: E402
    BOB,
    DAY,
    EMPTY,
    LAB,
    ME,
    NINA,
    OPS,
    SECOND,
    SEVEN_DAYS,
    T2,
    BootstrapRefused,
    World,
    items,
    lab,
    me,
    tenants_of,
    user_id,
)

FILE = {"administrators": [OPS], "tenants": {LAB: [ME]}}


def test_the_first_start_creates_two_invited_people_with_accounts_and_one_email_each() -> None:
    """Lab scenario: an administrator account that also needs a code, a member account, one send each (O8)."""
    world = lab()
    accounts = {a.email: a for a in world.signin.accounts.values()}
    assert set(accounts) == {OPS, ME}
    assert accounts[OPS].required_actions == {"set_password", "set_up_otp"}
    assert accounts[ME].required_actions == {"set_password"}
    assert (world.signin.sends_to(OPS), world.signin.sends_to(ME)) == (1, 1)
    assert all(lifespan == SEVEN_DAYS for _, lifespan in world.signin.set_password_sent)
    assert world.mail.sent == []


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
    assert len(world.signin.set_password_sent) == 2
    assert me_session.delete(f"/tenants/{LAB}/members/{user_id(me_session)}").status_code == 204
    world.restart(**FILE)
    assert len(world.signin.set_password_sent) == 2
    assert world.mail.sent == []
    assert tenants_of(world.sign_in(ME)) == set()


def test_a_person_still_invited_gets_a_fresh_email_only_when_the_last_is_over_seven_days_old() -> None:
    """Under 7 days nothing; over 7 days a fresh set-password email for each still-invited person (O8)."""
    world = lab()
    world.clock.advance(6 * DAY)
    world.restart(**FILE)
    assert (world.signin.sends_to(OPS), world.signin.sends_to(ME)) == (1, 1)
    world.clock.advance(DAY + SECOND)
    world.restart(**FILE)
    assert (world.signin.sends_to(OPS), world.signin.sends_to(ME)) == (2, 2)
    me_session = world.sign_in(ME)  # a fresh link lets a late person join
    assert tenants_of(me_session) == {LAB}
    world.clock.advance(8 * DAY)
    world.restart(**FILE)
    assert (world.signin.sends_to(OPS), world.signin.sends_to(ME)) == (3, 2)  # me is active now


def test_one_person_gets_at_most_one_email_per_start() -> None:
    """Fresh-send rule and a new first-member invitation together still send once (O8)."""
    world = lab()
    world.clock.advance(8 * DAY)
    world.restart(administrators=[OPS], tenants={LAB: [ME], T2: [ME]})
    assert world.signin.sends_to(ME) == 2  # the first start's, plus exactly one
    assert world.signin.sends_to(OPS) == 2
    assert tenants_of(world.sign_in(ME)) == {LAB, T2}


def test_a_send_that_never_went_out_is_made_at_the_next_start() -> None:
    """'Never went out' counts as older than 7 days (O8)."""
    world = World(administrators=[OPS], tenants={LAB: [ME]}, failing_sends=2)
    world.restart(**FILE)
    world.send_pending()
    assert (world.signin.sends_to(OPS), world.signin.sends_to(ME)) == (1, 1)


def test_first_members_are_invited_only_into_a_tenant_that_never_had_a_membership() -> None:
    """A later-added first member is not invited into the lab; a brand-new listed tenant is (O8)."""
    world = lab()
    me_session = world.sign_in(ME)
    assert me_session.delete(f"/tenants/{LAB}/members/{user_id(me_session)}").status_code == 204
    world.restart(administrators=[OPS], tenants={LAB: [ME, NINA], T2: [BOB]})
    assert NINA not in {a.email for a in world.signin.accounts.values()}
    assert world.signin.sends_to(ME) == 1
    assert tenants_of(world.sign_in(BOB)) == {T2}  # control: the new tenant's first member


def test_listed_tenants_are_registered_once_and_may_have_no_members() -> None:
    """Registered if new; a listed tenant with no members is allowed; restarts add nothing (O8)."""
    world = World(administrators=[OPS], tenants={LAB: [ME], EMPTY: []})
    world.register(T2)
    world.restart(administrators=[OPS], tenants={LAB: [ME], EMPTY: [], T2: []})
    ops = world.sign_in_admin()
    listed = [t["tenant_id"] for t in items(ops.get("/admin/tenants"))]
    assert sorted(listed) == sorted([LAB, EMPTY, T2])


def test_start_refuses_an_email_listed_as_administrator_and_first_member_and_names_it() -> None:
    """No safe automatic choice: refuse to start naming the email (O8)."""
    with pytest.raises(BootstrapRefused, match=re.escape(ME)):
        World(administrators=[ME], tenants={LAB: [ME]})


@pytest.mark.parametrize("signed_in", [False, True])
def test_start_refuses_to_newly_flag_someone_who_is_invited_or_active_in_a_tenant(signed_in: bool) -> None:
    """The file may not make a member (invited or active) an administrator (O8, K10)."""
    world = lab()
    if signed_in:
        world.sign_in(ME)
    with pytest.raises(BootstrapRefused, match=re.escape(ME)):
        world.restart(administrators=[OPS, ME], tenants={LAB: []})


def test_start_flags_someone_whose_membership_ended_and_keeps_an_invited_administrator_flagged() -> None:
    """Refusal is only for invited/active rows, and never for an already-flagged administrator (O8, DC-1)."""
    world = lab()
    me_session = world.sign_in(ME)
    world.invite(me_session, LAB, OPS)  # an invitation to a flagged administrator
    world.restart(**FILE)  # DC-1: not refused
    assert me(world.sign_in_admin())["administrator"] is True
    assert me_session.delete(f"/tenants/{LAB}/members/{user_id(me_session)}").status_code == 204
    world.restart(administrators=[OPS, ME], tenants={LAB: []})  # ended row: allowed
    world.signin.has_otp_answers[world.signin.account_for(ME)] = True
    assert me(world.sign_in(ME, amr=("pwd", "otp")))["administrator"] is True


def test_a_malformed_tenant_id_in_the_file_refuses_the_start() -> None:
    """The error names the tenant id (O8)."""
    with pytest.raises(BootstrapRefused, match="not-a-tenant-id"):
        World(tenants={"not-a-tenant-id": [ME]})


def test_emails_in_the_file_are_compared_lower_cased() -> None:
    """Mixed-case file entries name the same lower-cased people (O8)."""
    world = World(administrators=["OPS@X.example"], tenants={LAB: ["Me@X.example"]})
    assert {a.email for a in world.signin.accounts.values()} == {OPS, ME}


def test_entering_the_apps_lifespan_runs_start_and_the_senders_first_pass() -> None:
    """The real app starts the bootstrap and sends without anyone calling either (DC-4)."""
    world = World(administrators=[OPS], tenants={LAB: [ME]}, start=False)
    assert world.signin.accounts == {}
    with TestClient(world.app):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and world.signin.sends_to(ME) + world.signin.sends_to(OPS) < 2:
            time.sleep(0.02)
        assert (world.signin.sends_to(OPS), world.signin.sends_to(ME)) == (1, 1)
        assert tenants_of(world.sign_in(ME)) == {LAB}
