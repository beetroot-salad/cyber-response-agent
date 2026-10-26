"""#1306: accepting, removing, revoking, signing out and belonging to several tenants (flows 3, 5, 6, 7, O3, O4)."""
from __future__ import annotations

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
