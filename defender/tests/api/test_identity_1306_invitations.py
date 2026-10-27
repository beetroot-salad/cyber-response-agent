"""#1306: inviting a person into a tenant — the request, the listing and expiry (O2, P-E, flow 1)."""
from __future__ import annotations

import datetime as _dt

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
    DAY,
    HOUR,
    NEW,
    NINA,
    SEVEN_DAYS,
    SECOND,
    T0,
    T1,
    T2,
    invitation_rows,
    same_invite_answer,
    tenants_of,
    two_tenants,
    me,
)


def _when(row: dict[str, object]) -> _dt.datetime:
    return _dt.datetime.fromisoformat(str(row["created_at"]).replace("Z", "+00:00"))


def test_an_invitation_answers_alike_for_new_existing_and_invited_people_before_any_send() -> None:
    """Same response for a new, an active and an already-invited person; no port call of any kind first (O2/P-E, DC-8)."""
    world, ann, bob = two_tenants()
    assert world.invite(bob, T2, NINA).status_code == 202  # nina: invited elsewhere, nothing sent yet
    calls, mails, accounts = list(world.signin.every_call), list(world.mail.attempts), len(world.signin.create_calls)
    new = world.invite(ann, T1, "New@N.example")
    active = world.invite(ann, T1, BOB)
    invited_elsewhere = world.invite(ann, T1, NINA)
    same_invite_answer(new, active)
    same_invite_answer(new, invited_elsewhere)
    assert new.json()["email"] == NEW
    assert new.json()["status"] == "invited"
    assert (world.signin.every_call, world.mail.attempts, len(world.signin.create_calls)) == (calls, mails, accounts)


def test_the_listing_shows_id_email_status_and_created_at_and_sends_change_nothing() -> None:
    """Rows are exactly id/email/status/created_at, unchanged by a send or a re-invite (P-E, DC-7)."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, NEW)
    world.invite(ann, T1, BOB)
    before = invitation_rows(ann, T1)
    assert {r["email"] for r in before} == {NEW, BOB}
    for row in before:
        assert set(row) == {"id", "email", "status", "created_at"}
        assert row["status"] == "invited"
        assert _when(row) == T0
    world.clock.advance(HOUR)
    world.send_pending()
    assert invitation_rows(ann, T1) == before
    assert world.invite(ann, T1, NEW).status_code == 202  # a re-invite: still one row, original date
    world.send_pending()
    assert invitation_rows(ann, T1) == before


def test_an_expired_invitation_stays_in_the_listing_as_invited() -> None:
    """Expiry is not a status: an expired row is still listed `invited` (DC-7)."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, NEW)
    world.send_pending()
    world.clock.advance(SEVEN_DAYS + DAY)
    afresh = world.sign_in(ANN)
    [row] = invitation_rows(afresh, T1)
    assert (row["email"], row["status"]) == (NEW, "invited")


def test_inviting_an_active_member_of_this_tenant_is_409_and_adds_no_row() -> None:
    """An active member cannot be invited again, in any letter case; another tenant can (O2)."""
    world, ann, bob = two_tenants()
    refused = world.invite(ann, T1, "ANN@a.example")
    assert refused.status_code == 409
    assert invitation_rows(ann, T1) == []
    assert world.invite(bob, T2, ANN).status_code == 202  # positive control, same email elsewhere
    assert [r["email"] for r in invitation_rows(bob, T2)] == [ANN]


def test_the_listing_is_per_tenant_and_only_for_its_members() -> None:
    """Each tenant lists only its own open invitations (O2, P-D)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, NEW)
    assert [r["email"] for r in invitation_rows(ann, T1)] == [NEW]
    assert invitation_rows(bob, T2) == []
    assert bob.get(f"/tenants/{T1}/invitations").status_code == 404


def test_an_invitation_lasts_seven_days_from_the_actual_send_not_the_request() -> None:
    """Expiry counts from the send (O2)."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, NEW)
    world.clock.advance(2 * DAY)
    world.send_pending()
    world.clock.advance(5 * DAY + HOUR)  # T0 + 7d 1h: past a request-based expiry
    assert tenants_of(world.sign_in(NEW)) == {T1}


def test_an_invitation_is_open_until_exactly_seven_days_after_its_send() -> None:
    """The row is open while `expires_at > now`: accepted a second before 7 days, not at 7 days (flow 2)."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, NEW)
    world.invite(ann, T1, NINA)
    world.send_pending()
    sent_at = world.clock.now
    world.clock.now = sent_at + SEVEN_DAYS - SECOND
    assert tenants_of(world.sign_in(NEW)) == {T1}
    world.clock.now = sent_at + SEVEN_DAYS
    assert tenants_of(world.sign_in(NINA)) == set()


def test_me_offers_an_invitation_until_exactly_seven_days_after_its_send() -> None:
    """`/me` lists open (unexpired) invitations, open while `expires_at > now`: shown a second before 7 days, not at 7 days."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, BOB)
    world.send_pending()
    sent_at = world.clock.now
    world.clock.now = sent_at + SEVEN_DAYS - SECOND
    assert [r["tenant_id"] for r in me(world.sign_in(BOB))["invitations"]] == [T1]
    world.clock.now = sent_at + SEVEN_DAYS
    assert me(world.sign_in(BOB))["invitations"] == []


def test_a_row_whose_send_is_still_pending_does_not_expire() -> None:
    """Nothing went out, so nothing has started to run out (O2)."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, NEW)
    world.clock.advance(10 * DAY)
    afresh = world.sign_in(ANN)  # ann's own session ended with the jump
    assert [r["email"] for r in invitation_rows(afresh, T1)] == [NEW]
    world.send_pending()
    assert tenants_of(world.sign_in(NEW)) == {T1}


def test_re_inviting_after_expiry_sends_a_fresh_set_password_email_that_works() -> None:
    """A repeat invitation re-sends; the new link works though the first lapsed (O2)."""
    world, ann, _ = two_tenants()
    first = world.invite(ann, T1, NEW)
    world.send_pending()
    world.clock.advance(8 * DAY)
    afresh = world.sign_in(ANN)
    again = world.invite(afresh, T1, NEW)
    same_invite_answer(first, again)
    world.send_pending()
    assert world.signin.sends_to(NEW) == 2
    assert tenants_of(world.sign_in(NEW)) == {T1}


def test_lost_then_resent_invitations_join_every_tenant_the_fresh_send_covers() -> None:
    """Lost or expired email: T1 day 0, T2 day 5, re-send day 9 -> a fresh email covers both (O2)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, NEW)
    world.send_pending()
    world.clock.advance(5 * DAY)
    bob = world.sign_in(BOB)
    world.invite(bob, T2, NEW)
    world.send_pending()
    world.clock.advance(4 * DAY)
    bob = world.sign_in(BOB)
    world.invite(bob, T2, NEW)
    world.send_pending()
    assert world.signin.sends_to(NEW) == 3
    assert tenants_of(world.sign_in(NEW)) == {T1, T2}
