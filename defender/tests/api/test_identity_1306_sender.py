"""#1306: the sender — the only code that sends — and its re-checks (flow 1, O2, DC-3)."""
from __future__ import annotations

import datetime as _dt
import threading
import time
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender.tests.support.api._identity1306 import (  # noqa: E402
    ANN,
    BOB,
    HOUR,
    LAB,
    ME,
    OPS,
    InjectedFailure,
    NEW,
    NINA,
    SECOND,
    SEVEN_DAYS,
    T1,
    T2,
    Notice,
    World,
    me,
    invitation_id,
    tenants_of,
    two_tenants,
    wait_until,
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
def test_a_second_sender_skips_what_the_first_is_sending_and_a_re_invite_is_not_held_up(kind: str) -> None:
    """While a send is at Keycloak or the mail server, another sender does not take it, and a re-invite still lands (flow 1, r9)."""
    world, ann, _ = two_tenants()
    person = NEW if kind == "set_password" else BOB
    world.invite(ann, T1, person)
    inside: list[Any] = []

    def inside_the_send() -> None:
        inside.append(world.invite(ann, T1, person).status_code)
        now = world.clock()
        claim = world.repo.claim_set_password if kind == "set_password" else world.repo.claim_notification
        inside.append(claim(now=now, hold_until=now + HOUR))

    if kind == "set_password":
        world.signin.during_send = inside_the_send
    else:
        world.mail.during_notice = inside_the_send
    world.send_pending()
    assert inside[0] == 202, "the re-invite was held up by the send"
    assert inside[1] is None, "a second sender could take the send that was in flight"


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
    """Re-check before the send: revoked -> no email, the sent counter advanced; an unlisted invitee, so not kept alive by the file (flow 1)."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, NEW)
    world.invite(ann, T1, NINA)
    ann.delete(f"/tenants/{T1}/invitations/{invitation_id(ann, T1, NEW)}")
    world.send_pending()
    assert world.signin.sends_to(NINA) == 1  # positive control, same pass
    assert world.signin.sends_to(NEW) == 0
    assert world.signin.account_for(NEW)  # r6 order: the account precedes the re-check
    dropped = world.repo.user_by_email(NEW)  # fixed details: a dropped send advances its sent counter
    assert dropped.set_password_sent_seq == dropped.set_password_requested_seq > 0
    assert dropped.set_password_sent_at is None
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
    """A port failure does not raise out of the pass; the retry within an hour sends once and then stops (flow 1)."""
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
    world.clock.advance(HOUR + SECOND)
    world.send_pending()
    assert got() == 1
    world.clock.advance(HOUR + SECOND)
    world.send_pending()
    assert got() == 1


@pytest.mark.parametrize("kind", ["set_password", "notice"])
def test_a_send_that_keeps_failing_is_retried_at_most_an_hour_after_each_failure(kind: str) -> None:
    """The backoff is capped: ten failures in a row, each retried by the pass an hour later; then it goes out (F-3)."""
    world, ann, _ = two_tenants()
    person = NEW if kind == "set_password" else BOB
    world.invite(ann, T1, person)
    if kind == "set_password":
        world.signin.fail_sends_to.add(NEW)
        tried = lambda: world.signin.attempts_to(NEW)  # noqa: E731
    else:
        world.mail.fail_notices_to.add(BOB)
        tried = lambda: world.mail.attempts.count(BOB)  # noqa: E731
    world.send_pending()
    assert tried() == 1
    for failures in range(1, 11):
        world.clock.advance(HOUR)
        world.send_pending()
        assert tried() == failures + 1, f"not retried within an hour of failure {failures}"
    world.signin.fail_sends_to.clear()
    world.mail.fail_notices_to.clear()
    world.clock.advance(HOUR)
    world.send_pending()
    sent = world.signin.sends_to(NEW) if kind == "set_password" else len(world.mail.sent)
    assert sent == 1


@pytest.mark.parametrize("kind", ["set_password", "notice"])
def test_a_failed_send_is_retried_with_backoff_not_by_a_pass_at_the_same_instant(kind: str) -> None:
    """Retried with backoff: a second pass at the very instant of the failure does not try again (flow 1, F-3)."""
    world, ann, _ = two_tenants()
    person = NEW if kind == "set_password" else BOB
    world.invite(ann, T1, person)
    if kind == "set_password":
        world.signin.fail_sends_to.add(NEW)
        tried = lambda: world.signin.attempts_to(NEW)  # noqa: E731
    else:
        world.mail.fail_notices_to.add(BOB)
        tried = lambda: world.mail.attempts.count(BOB)  # noqa: E731
    world.send_pending()
    assert tried() == 1
    world.send_pending()
    world.send_pending()
    assert tried() == 1, "retried at once, without any backoff"
    world.clock.advance(HOUR)
    world.send_pending()
    assert tried() == 2  # control: the retry comes within the hour


@pytest.mark.parametrize("kind", ["set_password", "notice"])
def test_a_send_in_backoff_does_not_hold_back_one_requested_after_it_failed(kind: str) -> None:
    """A failure fails only that person's (or row's) send: a later invitation still goes out at the next pass (F-3)."""
    world, ann, bob = two_tenants()
    if kind == "set_password":
        world.signin.fail_sends_to.add(NEW)
        world.invite(ann, T1, NEW)
    else:
        world.mail.fail_notices_to.add(BOB)
        world.invite(ann, T1, BOB)
    world.send_pending()  # fails; that send is now backing off
    world.clock.advance(SECOND)
    if kind == "set_password":
        world.invite(ann, T1, NINA)
    else:
        world.invite(bob, T2, ANN)
    world.send_pending()
    if kind == "set_password":
        assert (world.signin.sends_to(NEW), world.signin.sends_to(NINA)) == (0, 1)
    else:
        assert [n.to for n in world.mail.sent] == [ANN]


def test_an_invite_racing_the_invitees_first_sign_in_still_reaches_them() -> None:
    """The kind of send follows the user's status under the user-row lock: an invitee who signs in while
    the invite runs is either joined by that sign-in or sent our notification (flow 1, O2)."""
    world = World(tenants={T1: [ANN], T2: [BOB]}, failing_writes=True)
    ann, bob = world.sign_in(ANN), world.sign_in(BOB)
    world.invite(ann, T1, NEW)
    world.send_pending()  # NEW has an account and is still invited
    browser = world.client()
    state = world.begin_signin(browser)
    signed_in: list[Any] = []

    def sign_in() -> None:
        signed_in.append(world.sign_in_response(browser, NEW, state=state, begin=False))

    def between_the_read_and_the_request() -> None:
        racer = threading.Thread(target=sign_in)
        racer.start()
        racer.join(timeout=2)  # an implementation that holds the user-row lock makes it wait

    world.repo.after["ensure_user"] = between_the_read_and_the_request
    assert world.invite(bob, T2, NEW).status_code == 202
    assert "ensure_user" not in world.repo.after  # control: the race was run inside the invite
    assert wait_until(lambda: bool(signed_in)), "the racing sign-in never finished"
    assert signed_in[0].status_code == 303, signed_in[0].text
    world.send_pending()
    joined = {t["tenant_id"] for t in me(browser)["tenants"]}
    notified = [n for n in world.mail.sent if n.to == NEW and n.tenant_id == T2]
    assert T1 in joined
    assert T2 in joined or len(notified) == 1, "the T2 invitation was never sent nor joined"


@pytest.mark.parametrize("error", ["sign-in-unavailable", "any-exception", "any-exception-on-create"])
@pytest.mark.parametrize("failing", [NEW, NINA])
def test_a_set_password_send_that_fails_does_not_stop_the_next_persons_in_the_same_pass(
        failing: str, error: str) -> None:
    """Containment per person, whichever is first and whatever the exception; retried within the hour (flow 1)."""
    world, ann, _ = two_tenants()
    other = NINA if failing == NEW else NEW
    world.invite(ann, T1, NEW)
    world.invite(ann, T1, NINA)
    if error == "any-exception":
        world.signin.raise_on_send_to[failing] = InjectedFailure("not a SignInUnavailable")
    elif error == "any-exception-on-create":
        world.signin.raise_on_create_to[failing] = InjectedFailure("not a SignInUnavailable")
    else:
        world.signin.fail_sends_to.add(failing)
    world.send_pending()
    assert (world.signin.sends_to(failing), world.signin.sends_to(other)) == (0, 1)
    world.signin.raise_on_send_to.clear()
    world.signin.raise_on_create_to.clear()
    world.signin.fail_sends_to.clear()
    world.clock.advance(HOUR + SECOND)
    world.send_pending()
    assert (world.signin.sends_to(failing), world.signin.sends_to(other)) == (1, 1)


@pytest.mark.parametrize("failing", [ANN, BOB])
def test_a_notification_that_fails_does_not_stop_the_next_ones_in_the_same_pass(failing: str) -> None:
    """Containment per row: two active people are notified, one fails, the other still goes out (flow 1)."""
    world, ann, bob = two_tenants()
    world.invite(ann, T1, BOB)
    world.invite(bob, T2, ANN)
    world.mail.fail_notices_to.add(failing)
    world.send_pending()
    assert {n.to for n in world.mail.sent} == {BOB, ANN} - {failing}
    world.mail.fail_notices_to.clear()
    world.clock.advance(HOUR + SECOND)
    world.send_pending()
    assert sorted(n.to for n in world.mail.sent) == [ANN, BOB]


def test_a_crash_between_creating_the_account_and_recording_it_is_retried_without_a_second_account() -> None:
    """Create-or-find on the username: the retry finds the account and sends once (P-C, flow 1)."""
    world, ann, _ = two_tenants()
    world.invite(ann, T1, NEW)
    world.signin.crash_after_create = 1
    world.send_pending()
    assert world.signin.sends_to(NEW) == 0
    world.clock.advance(HOUR + SECOND)
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


INTERVAL = _dt.timedelta(milliseconds=50)


def test_the_apps_lifespan_keeps_sending_what_is_invited_after_it_started() -> None:
    """The periodic sender (every send_interval) sends a set-password email for an invite made after start (F-7, flow 1)."""
    world = World(tenants={T1: [ANN]}, start=False, send_interval=INTERVAL)
    with world.lifespan_client() as browser:
        assert wait_until(lambda: world.signin.sends_to(ANN) == 1)
        world.sign_in(ANN, browser=browser)
        assert world.invite(browser, T1, NEW).status_code == 202
        assert wait_until(lambda: world.signin.sends_to(NEW) == 1)
        time.sleep(3 * INTERVAL.total_seconds())
        assert world.signin.sends_to(NEW) == 1  # control: once recorded, nothing stays pending


def test_the_lifespan_makes_its_first_pass_at_once_not_after_one_interval() -> None:
    """With an hour between passes the start-up pass still sends what is pending (F-7, DC-4)."""
    world = World(administrators=[OPS], tenants={LAB: [ME]}, start=False, send_interval=HOUR)
    with world.lifespan_client():
        assert wait_until(lambda: world.signin.sends_to(OPS) == 1 and world.signin.sends_to(ME) == 1)
        leaving = time.monotonic()
    # Prompt shutdown (S-2): leaving the lifespan stops the loop even partway through the hour.
    assert time.monotonic() - leaving < 2


def test_between_passes_the_loop_waits_its_interval() -> None:
    """After the start-up pass, nothing is sent until send_interval has passed (F-7)."""
    world = World(tenants={T1: [ANN]}, start=False, send_interval=HOUR)
    with world.lifespan_client() as browser:
        assert wait_until(lambda: world.signin.sends_to(ANN) == 1)
        world.sign_in(ANN, browser=browser)
        assert world.invite(browser, T1, NEW).status_code == 202
        time.sleep(0.5)
        assert world.signin.sends_to(NEW) == 0
    world.send_pending()  # control: it was pending and sendable all along
    assert world.signin.sends_to(NEW) == 1


def test_a_periodic_pass_that_raises_does_not_stop_the_loop() -> None:
    """A pass that raises (repository failure) is survived: later passes run and a later invite is sent (F-7, flow 1)."""
    world = World(tenants={T1: [ANN]}, start=False, send_interval=INTERVAL, failing_writes=True)
    with world.lifespan_client() as browser:
        assert wait_until(lambda: world.signin.sends_to(ANN) == 1)
        world.sign_in(ANN, browser=browser)
        world.repo.failing.add("claim_set_password")
        assert wait_until(lambda: world.repo.refusals.get("claim_set_password", 0) >= 2)  # raised, again
        world.repo.failing.clear()
        assert world.invite(browser, T1, NEW).status_code == 202
        assert wait_until(lambda: world.signin.sends_to(NEW) == 1)


def test_after_the_lifespan_exits_nothing_more_is_sent() -> None:
    """Shutdown stops the sender: an invite made afterwards stays pending until a pass is run by hand (F-7)."""
    world = World(tenants={T1: [ANN]}, start=False, send_interval=INTERVAL)
    with world.lifespan_client():
        assert wait_until(lambda: world.signin.sends_to(ANN) == 1)
    ann = world.sign_in(ANN)
    assert world.invite(ann, T1, NEW).status_code == 202
    time.sleep(5 * INTERVAL.total_seconds())
    assert world.signin.sends_to(NEW) == 0
    world.send_pending()  # control: it was pending and sendable all along
    assert world.signin.sends_to(NEW) == 1
