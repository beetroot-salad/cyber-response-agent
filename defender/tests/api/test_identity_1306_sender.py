"""#1306: the sender — the only code that sends — and its re-checks (flow 1, O2, DC-3)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import (  # noqa: E402
    BOB,
    NEW,
    NINA,
    SEVEN_DAYS,
    T1,
    T2,
    InjectedFailure,
    Notice,
    invitation_id,
    tenants_of,
    two_tenants,
)


def test_the_sender_sends_set_password_to_a_new_person_and_our_notice_to_an_active_one() -> None:
    """A new person gets an account and one set-password email; an active one a notification (O2)."""
    world, ann, _ = two_tenants()
    accounts, sent = len(world.signin.accounts), len(world.signin.set_password_sent)
    world.invite(ann, T1, NEW)
    bob_row = world.invite(ann, T1, BOB).json()["id"]
    world.send_pending()
    assert len(world.signin.accounts) == accounts + 1
    assert world.signin.account_of(NEW).required_actions == {"set_password"}
    assert world.signin.set_password_sent[sent:] == [(world.signin.account_for(NEW), SEVEN_DAYS)]
    assert world.mail.sent == [Notice(to=BOB, tenant_id=T1, invitation_id=bob_row)]


def test_a_person_invited_to_several_tenants_gets_one_account_and_one_set_password_email() -> None:
    """The sender works per user, not per invitation (flow 1)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, NEW)
    world.invite(bob, T2, NEW)
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1
    assert [a.email for a in world.signin.accounts.values()].count(NEW) == 1
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1  # nothing stays pending


def test_every_re_invitation_re_sends_to_an_invited_person_and_to_an_active_one() -> None:
    """Repeating an invitation re-sends the right email each time (O2)."""
    world, ann, _ = two_tenants()
    for _ in range(2):
        world.invite(ann, T1, NEW)
        world.invite(ann, T1, BOB)
        world.send_pending()
    assert world.signin.sends_to(NEW) == 2
    assert [n.to for n in world.mail.sent] == [BOB, BOB]
    assert len({n.invitation_id for n in world.mail.sent}) == 1  # one row, not one per invite


@pytest.mark.parametrize("kind", ["set_password", "notice"])
def test_a_re_invite_arriving_during_a_send_stays_pending(kind: str) -> None:
    """A send does not swallow a request that arrived while it ran (DC-3, flow 1)."""
    world, ann, _ = two_tenants()
    person = NEW if kind == "set_password" else BOB
    again = lambda: world.invite(ann, T1, person)  # noqa: E731
    sent = lambda: world.signin.sends_to(NEW) if kind == "set_password" else len(world.mail.sent)  # noqa: E731
    world.invite(ann, T1, person)
    if kind == "set_password":
        world.signin.during_send = again
    else:
        world.mail.during_notice = again
    world.send_pending()
    assert sent() == 1
    world.send_pending()
    assert sent() == 2
    world.send_pending()
    assert sent() == 2  # control: once the second is recorded nothing stays pending


@pytest.mark.parametrize("kind", ["set_password", "notice"])
def test_a_re_invite_at_the_same_instant_as_the_last_send_is_still_sent(kind: str) -> None:
    """The clock does not move, yet the second request is not swallowed (DC-3)."""
    world, ann, _ = two_tenants()
    person = NEW if kind == "set_password" else BOB
    for _ in range(2):
        world.invite(ann, T1, person)
        world.send_pending()
    got = world.signin.sends_to(NEW) if kind == "set_password" else len(world.mail.sent)
    assert got == 2


def test_a_revoked_invitation_is_dropped_by_the_sender_but_the_account_is_still_created() -> None:
    """Re-check before the send: revoked -> no email; an unlisted invitee, so not kept alive by the file (flow 1)."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, NEW)
    world.invite(ann, T1, NINA)
    ann.delete(f"/tenants/{T1}/invitations/{invitation_id(ann, T1, NEW)}")
    world.send_pending()
    assert world.signin.sends_to(NINA) == 1  # positive control, same pass
    assert world.signin.sends_to(NEW) == 0
    assert world.signin.account_for(NEW)  # r6 order: the account precedes the re-check
    world.send_pending()
    assert world.signin.sends_to(NEW) == 0  # dropped for good, not retried
    world.invite(ann, T1, NEW)  # a later invitation reuses the person and the account
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1
    assert [a.email for a in world.signin.accounts.values()].count(NEW) == 1


def test_one_live_invitation_is_enough_to_send_when_another_was_revoked() -> None:
    """The re-check asks whether any invited row is left (flow 1)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, NEW)
    world.invite(bob, T2, NEW)
    ann.delete(f"/tenants/{T1}/invitations/{invitation_id(ann, T1, NEW)}")
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1
    assert tenants_of(world.sign_in(NEW)) == {T2}


def test_a_revoked_invitation_sends_no_notification_to_an_active_person() -> None:
    """The notification path re-checks the row too (flow 1)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, BOB)
    world.invite(ann, T1, NEW)
    ann.delete(f"/tenants/{T1}/invitations/{invitation_id(ann, T1, BOB)}")
    world.send_pending()
    assert world.mail.sent == []
    assert world.signin.sends_to(NEW) == 1
    assert bob.get("/me").json()["invitations"] == []


@pytest.mark.parametrize("kind", ["set_password", "notice"])
def test_a_failed_send_stays_pending_and_is_retried_until_it_goes_out(kind: str) -> None:
    """Failure leaves the request pending; the next run sends once and then stops (flow 1)."""
    world, ann, _ = two_tenants()
    person = NEW if kind == "set_password" else BOB
    world.invite(ann, T1, person)
    if kind == "set_password":
        world.signin.fail_sends = 1
    else:
        world.mail.fail_notices = 1
    got = lambda: world.signin.sends_to(NEW) if kind == "set_password" else len(world.mail.sent)  # noqa: E731
    world.send_pending()
    assert got() == 0
    world.send_pending()
    assert got() == 1
    world.send_pending()
    assert got() == 1
    assert all(isinstance(e, InjectedFailure) for e in world.sender_errors)


def test_a_crash_between_creating_the_account_and_recording_it_is_retried_without_a_second_account() -> None:
    """Create-or-find on the username: the retry finds the account and sends once (P-C, flow 1)."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, NEW)
    world.signin.crash_after_create = 1
    world.send_pending()
    assert world.signin.sends_to(NEW) == 0
    world.send_pending()
    assert world.signin.sends_to(NEW) == 1
    assert [a.email for a in world.signin.accounts.values()].count(NEW) == 1
    asked = [u for u in world.signin.create_calls if u == world.signin.account_of(NEW).username]
    assert len(asked) == 2  # the same username both times
    assert tenants_of(world.sign_in(NEW)) == {T1}


def test_an_unrelated_person_is_not_sent_anything_by_a_pass() -> None:
    """Control: a pass with nothing pending calls neither port (flow 1)."""
    world, _, _ = two_tenants()
    calls, mails = world.signin.calls(), len(world.mail.sent)
    world.send_pending()
    assert (world.signin.calls(), len(world.mail.sent)) == (calls, mails)
    assert world.sender_errors == []
