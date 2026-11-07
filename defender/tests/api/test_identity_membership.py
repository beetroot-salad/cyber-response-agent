"""#1306: accepting, removing, revoking, signing out and belonging to several tenants (flows 3, 5, 6, 7, O3, O4).

#1306: inviting a person into a tenant — the request, the listing and expiry (O2, P-E, flow 1).
"""
from __future__ import annotations

import datetime as _dt

import pytest

pytest.importorskip('fastapi')

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
    DAY,
    HOUR,
    NEW,
    NINA,
    SEVEN_DAYS,
    SECOND,
    SESSION_COOKIE,
    T1,
    T2,
    World,
    invitation_rows,
    is_cleared,
    items,
    me,
    set_cookie,
    tenants_of,
    two_tenants,
    user_id,
)
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


# A forgotten `world.call` leaves a never-awaited coroutine; pytest reports its RuntimeWarning as an unraisable exception, so both are errors.
pytestmark = [
    pytest.mark.filterwarnings("error:coroutine .* was never awaited:RuntimeWarning"),
    pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning"),
]


def _open_invitation(world: World, inviter, tenant: str, invitee) -> str:  # type: ignore[no-untyped-def]
    """Invite bob-like active `invitee`, run the sender, and return the invitation id from /me."""
    world.invite(inviter, tenant, BOB)
    world.send_pending()
    [row] = [r for r in me(invitee)["invitations"] if r["tenant_id"] == tenant]
    return str(row["id"])


def test_an_active_user_accepts_an_invitation_from_me_once() -> None:
    """An active person accepts while signed in; a second accept finds nothing (flow 3)."""
    world, ann, bob = two_tenants()
    row = _open_invitation(world, ann, T1, bob)
    assert bob.get(f"/tenants/{T1}/alerts").status_code == 404
    assert bob.post(f"/invitations/{row}/accept").status_code == 200
    assert tenants_of(bob) == {T1, T2}
    assert me(bob)["invitations"] == []
    assert bob.get(f"/tenants/{T1}/alerts").status_code == 200
    assert bob.post(f"/invitations/{row}/accept").status_code == 404


def test_an_expired_invitation_cannot_be_accepted_until_a_re_send_renews_it() -> None:
    """Expired -> not listed in /me and accept is 404; a re-send makes it open again (flow 3, O2)."""
    world, ann, bob = two_tenants()
    row = _open_invitation(world, ann, T1, bob)
    world.clock.advance(SEVEN_DAYS + SECOND)
    bob, ann = world.sign_in(BOB), world.sign_in(ANN)
    assert me(bob)["invitations"] == []
    assert bob.post(f"/invitations/{row}/accept").status_code == 404
    assert tenants_of(bob) == {T2}
    world.invite(ann, T1, BOB)
    world.send_pending()
    assert [r["id"] for r in me(bob)["invitations"]] == [row]
    assert bob.post(f"/invitations/{row}/accept").status_code == 200


def test_an_invitation_whose_notification_has_not_gone_out_does_not_expire() -> None:
    """Pending send -> no clock running -> still joinable ten days on (O2)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, BOB)
    world.clock.advance(10 * DAY)
    bob = world.sign_in(BOB)
    # Only the first sign-in (invited -> active) accepts invitations (O2); an active user accepts.
    assert tenants_of(bob) == {T2}
    [row] = me(bob)["invitations"]
    assert row["tenant_id"] == T1
    assert bob.post(f"/invitations/{row['id']}/accept").status_code == 200
    assert tenants_of(bob) == {T1, T2}


def test_a_notified_invitation_lasts_seven_days_from_the_send_not_the_request() -> None:
    """Expiry counts from the actual send on the notification path too (O2, flow 1)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, BOB)
    world.clock.advance(2 * DAY)
    world.send_pending()  # the notification goes out on day 2
    world.clock.advance(5 * DAY + HOUR)  # T0 + 7d 1h: past a request-based expiry
    bob = world.sign_in(BOB)
    [row] = me(bob)["invitations"]
    assert bob.post(f"/invitations/{row['id']}/accept").status_code == 200
    assert tenants_of(bob) == {T1, T2}


def test_an_invitation_into_a_tenant_that_does_not_exist_is_neither_offered_nor_accepted() -> None:
    """/me lists, and accept and first sign-in take, only invitations whose tenant exists (flows 2, 3)."""
    world = World(tenants={T1: [ANN], T2: [BOB]}, failing_writes=True)
    ann, bob = world.sign_in(ANN), world.sign_in(BOB)
    row = world.invite(bob, T2, ANN).json()["id"]
    world.invite(ann, T1, NEW)
    world.invite(bob, T2, NEW)
    world.send_pending()
    assert [r["id"] for r in me(ann)["invitations"]] == [row]  # control: offered while T2 exists
    world.repo.missing_tenants.add(T2)
    assert me(ann)["invitations"] == []
    assert ann.post(f"/invitations/{row}/accept").status_code == 404
    assert tenants_of(ann) == {T1}
    assert tenants_of(world.sign_in(NEW)) == {T1}
    world.repo.missing_tenants.clear()  # control: the same row, its tenant back, is accepted
    assert ann.post(f"/invitations/{row}/accept").status_code == 200
    assert tenants_of(ann) == {T1, T2}


def test_removing_a_member_ends_only_that_membership() -> None:
    """Removal by another member ends one membership; other tenants and the session survive (flow 5, O4)."""
    world, ann, bob = two_tenants()
    bob.post(f"/invitations/{_open_invitation(world, ann, T1, bob)}/accept")
    bob_id = user_id(bob)
    assert {m["email"] for m in items(ann.get(f"/tenants/{T1}/members"))} == {ANN, BOB}
    assert ann.delete(f"/tenants/{T1}/members/{bob_id}").status_code == 204
    assert {m["email"] for m in items(ann.get(f"/tenants/{T1}/members"))} == {ANN}
    assert bob.get(f"/tenants/{T1}/alerts").status_code == 404
    assert bob.get(f"/tenants/{T2}/alerts").status_code == 200
    assert tenants_of(bob) == {T2}
    assert ann.delete(f"/tenants/{T1}/members/{bob_id}").status_code == 404  # already ended


def test_the_member_list_shows_active_members_only_never_an_invitee() -> None:
    """`GET /members` lists active rows; an invitee, existing or new, shows nowhere in it until acceptance (endpoints, P-E)."""
    world, ann, bob = two_tenants()
    revoked = world.invite(ann, T1, NINA).json()["id"]
    world.invite(ann, T1, BOB)
    world.invite(ann, T1, NEW)
    assert ann.delete(f"/tenants/{T1}/invitations/{revoked}").status_code == 204
    world.send_pending()
    listed = ann.get(f"/tenants/{T1}/members")
    assert [m["email"] for m in items(listed)] == [ANN]
    assert "Bob" not in listed.text
    assert BOB not in listed.text
    world.clock.advance(SEVEN_DAYS + SECOND)  # the invitations expire, still not members
    ann = world.sign_in(ANN)
    assert [m["email"] for m in items(ann.get(f"/tenants/{T1}/members"))] == [ANN]
    bob = world.sign_in(BOB)
    world.invite(ann, T1, BOB)
    world.send_pending()
    [row] = [r for r in me(bob)["invitations"] if r["tenant_id"] == T1]
    assert bob.post(f"/invitations/{row['id']}/accept").status_code == 200
    assert {m["email"] for m in items(ann.get(f"/tenants/{T1}/members"))} == {ANN, BOB}  # control


def test_a_membership_records_who_invited_it_and_who_ended_it() -> None:
    """`invited_by` is the inviting member (None, the system, for the bootstrap); `ended_by` is whoever removed it (data model, O4)."""
    world, ann, bob = two_tenants()
    ann_id, bob_id = user_id(ann), user_id(bob)
    [ann_row] = world.call(world.repo.memberships_of_user, ann_id)
    assert ann_row.invited_by is None
    nina_row = world.invite(ann, T1, NINA).json()["id"]
    assert world.call(world.repo.membership, nina_row).invited_by == ann_id
    world.send_pending()
    nina = world.sign_in(NINA)
    assert ann.delete(f"/tenants/{T1}/members/{user_id(nina)}").status_code == 204
    assert world.call(world.repo.membership, nina_row).ended_by == ann_id
    bob_row = _open_invitation(world, ann, T1, bob)
    assert world.call(world.repo.membership, bob_row).invited_by == ann_id
    assert bob.post(f"/invitations/{bob_row}/accept").status_code == 200
    assert bob.delete(f"/tenants/{T1}/members/{bob_id}").status_code == 204
    assert world.call(world.repo.membership, bob_row).ended_by == bob_id


def test_a_member_can_remove_themselves_and_then_be_invited_again() -> None:
    """Self-removal is allowed; inviting again adds a fresh invitation that works (flow 5, O4)."""
    world, ann, bob = two_tenants()
    bob.post(f"/invitations/{_open_invitation(world, ann, T1, bob)}/accept")
    assert bob.delete(f"/tenants/{T1}/members/{user_id(bob)}").status_code == 204
    assert me(bob)["user"]["email"] == BOB  # still signed in
    assert tenants_of(bob) == {T2}
    again = _open_invitation(world, ann, T1, bob)
    assert bob.post(f"/invitations/{again}/accept").status_code == 200
    assert tenants_of(bob) == {T1, T2}


def test_the_last_member_may_leave_a_tenant() -> None:
    """There is no last-member rule (O4)."""
    world, ann, _ = two_tenants()
    assert ann.delete(f"/tenants/{T1}/members/{user_id(ann)}").status_code == 204
    assert tenants_of(ann) == set()
    assert ann.get(f"/tenants/{T1}/members").status_code == 404


def test_revoking_an_invitation_marks_it_gone_once_and_a_new_invitation_is_a_new_row() -> None:
    """Revoke is 204 once, then 404; the invitee cannot accept it; re-inviting works (flow 6, O4)."""
    world, ann, bob = two_tenants()
    row = _open_invitation(world, ann, T1, bob)
    assert ann.delete(f"/tenants/{T1}/invitations/{row}").status_code == 204
    assert invitation_rows(ann, T1) == []
    assert ann.delete(f"/tenants/{T1}/invitations/{row}").status_code == 404
    assert bob.post(f"/invitations/{row}/accept").status_code == 404
    assert me(bob)["invitations"] == []
    fresh = _open_invitation(world, ann, T1, bob)
    assert fresh != row
    assert bob.post(f"/invitations/{fresh}/accept").status_code == 200


def test_an_accepted_invitation_cannot_be_revoked() -> None:
    """Revoke is conditional on `invited`: an accepted row is not revoked (flow 6)."""
    world, ann, bob = two_tenants()
    row = _open_invitation(world, ann, T1, bob)
    bob.post(f"/invitations/{row}/accept")
    assert ann.delete(f"/tenants/{T1}/invitations/{row}").status_code == 404
    assert tenants_of(bob) == {T1, T2}


def test_sign_out_ends_this_session_and_leaves_other_devices_signed_in() -> None:
    """Sign-out deletes this session only and clears the cookie (flow 7, O6)."""
    world = World(tenants={T1: [ANN]})
    laptop, phone = world.sign_in(ANN), world.sign_in(ANN)
    old = laptop.cookies[SESSION_COOKIE]
    out = laptop.post("/auth/logout")
    assert out.status_code == 204
    assert is_cleared(set_cookie(out, SESSION_COOKIE) or "")
    assert SESSION_COOKIE not in laptop.cookies
    assert world.client_with_cookie(old).get("/me").status_code == 401
    assert phone.get("/me").status_code == 200


def test_one_session_reaches_every_tenant_a_person_belongs_to() -> None:
    """The SOC analyst: invited to a second tenant, accepts, uses both; removal from one leaves the other (O3)."""
    world, ann, bob = two_tenants()
    nina = world.member(ann, T1, NINA)
    world.invite(bob, T2, ANN)
    world.send_pending()
    [invitation] = me(ann)["invitations"]
    assert ann.post(f"/invitations/{invitation['id']}/accept").status_code == 200
    assert tenants_of(ann) == {T1, T2}
    assert ann.get(f"/tenants/{T1}/alerts").status_code == ann.get(f"/tenants/{T2}/alerts").status_code == 200
    assert bob.get(f"/tenants/{T1}/alerts").status_code == 404  # T2-only member
    assert nina.delete(f"/tenants/{T1}/members/{user_id(ann)}").status_code == 204
    assert ann.get(f"/tenants/{T2}/alerts").status_code == 200
    assert ann.get(f"/tenants/{T1}/alerts").status_code == 404


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


@pytest.mark.parametrize("email", ["a\x00b@n.example", "new\x00@n.example"])
def test_an_email_the_database_cannot_store_is_invalid_input_and_invites_nobody(email: str) -> None:
    """#1349 B1.1: a 422 like any malformed email, not a server error."""
    world, ann, _ = two_tenants()
    assert world.invite(ann, T1, email).status_code == 422
    assert [r["email"] for r in invitation_rows(ann, T1)] == []
    assert world.invite(ann, T1, NEW).status_code == 202  # positive control


def test_the_published_email_pattern_is_plain_enough_for_any_regex_engine() -> None:
    """#1349: the OpenAPI schema carries the pattern to clients; `\\p{..}` means something else in JavaScript."""
    from defender.api.models import InviteCreate

    pattern = InviteCreate.model_json_schema()["properties"]["email"]["pattern"]
    assert "\\p" not in pattern, pattern


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
