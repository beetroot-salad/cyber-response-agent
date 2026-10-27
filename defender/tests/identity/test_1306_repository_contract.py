"""#1306 IdentityRepository contract: one suite over the in-memory and the PostgreSQL repository (DC-4).

The PostgreSQL run is marked `postgres` and needs DEFENDER_TEST_POSTGRES_DSN. CI's test job
starts a PostgreSQL service and sets it, so both runs happen on every push; there an unset DSN
fails rather than skips, so a broken service cannot turn the PostgreSQL half green by absence.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import os
import threading
import uuid
from collections.abc import Iterator

import pytest

from defender.identity import DataRuleViolation, InMemoryIdentityRepository
from defender.records._tenant_id import TenantId
from defender.tests.support.shared._fixture_uuid import fixture_uuid

DSN_ENV = "DEFENDER_TEST_POSTGRES_DSN"
NOW = dt.datetime(2026, 10, 26, 12, 0, tzinfo=dt.UTC)
WEEK = dt.timedelta(days=7)
HOUR = dt.timedelta(hours=1)
HOLD = dt.timedelta(minutes=5)
T1 = TenantId(fixture_uuid("tenant:t1"))
T2 = TenantId(fixture_uuid("tenant:t2"))
T_UNREGISTERED = TenantId(fixture_uuid("tenant:unregistered"))


def _postgres_repo(dsn: str, schema: str):
    from defender.identity.postgres import PostgresIdentityRepository

    return PostgresIdentityRepository(dsn, schema=schema)


def _claim_user(repo, now=NOW):
    return repo.claim_set_password(now=now, hold_until=now + HOLD)


def _claim_row(repo, now=NOW):
    return repo.claim_notification(now=now, hold_until=now + HOLD)


def _dsn() -> str:
    """The test database's address; skipped where none is set, but never in CI."""
    dsn = os.environ.get(DSN_ENV)
    if not dsn:
        if os.environ.get("CI"):
            pytest.fail(f"{DSN_ENV} is not set in CI; the test job's PostgreSQL service provides it")
        pytest.skip(f"{DSN_ENV} is not set")
    pytest.importorskip("psycopg")
    return dsn


def _drop_schema(dsn: str, schema: str) -> None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


@pytest.fixture(
    params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)],
)
def repo(request) -> Iterator[object]:
    if request.param == "memory":
        yield InMemoryIdentityRepository()
        return
    dsn = _dsn()
    schema = f"t_{uuid.uuid4().hex}"
    r = _postgres_repo(dsn, schema)
    try:
        r.register_tenant(T1)
        r.register_tenant(T2)
        yield r
    finally:
        r.close()
        _drop_schema(dsn, schema)


@pytest.fixture
def seeded(repo):
    """Memory repo with T1 and T2 registered (the postgres fixture registers them itself)."""
    repo.register_tenant(T1)
    repo.register_tenant(T2)
    return repo


def _user(repo, email="ann@x.org", **kw):
    return repo.add_user(email, created_at=NOW, **kw)


def _invited(repo, user, tenant=T1, **kw):
    return repo.ensure_invitation(user.id, tenant, invited_by="system", now=NOW, **kw)


def _active(repo, user, tenant=T1):
    return repo.add_membership(user.id, tenant, status="active", invited_by="system", created_at=NOW, accepted_at=NOW)


# --- tenants ---------------------------------------------------------------------------------


def test_register_tenant_is_idempotent_and_decides_existence(seeded):
    """register_tenant twice is one tenant; an unregistered id does not exist (O8, DC-4)."""
    seeded.register_tenant(T1)
    assert seeded.tenant_exists(T1) is True
    assert seeded.tenant_exists(T_UNREGISTERED) is False


def test_a_membership_in_an_unregistered_tenant_is_refused(seeded):
    """A membership row needs a registered tenant (tenants table is referenced)."""
    u = _user(seeded)
    with pytest.raises(DataRuleViolation):
        _invited(seeded, u, T_UNREGISTERED)
    with pytest.raises(DataRuleViolation):
        seeded.add_membership(u.id, T_UNREGISTERED, status="invited", invited_by="system", created_at=NOW)


def test_a_membership_for_an_unknown_user_is_refused(seeded):
    """A membership row needs an existing user."""
    with pytest.raises(DataRuleViolation):
        seeded.ensure_invitation("no-such-user", T1, invited_by="system", now=NOW)


def test_ever_had_a_membership_survives_revoke_and_end(seeded):
    """O8: 'ever had a membership row' is false only for a tenant with none, even after revoke/end."""
    assert seeded.tenant_has_ever_had_membership(T1) is False
    assert seeded.tenant_has_ever_had_membership(T2) is False
    u = _user(seeded)
    row = _invited(seeded, u)
    assert seeded.tenant_has_ever_had_membership(T1) is True
    assert seeded.tenant_has_ever_had_membership(T2) is False
    assert seeded.revoke_invitation(row.id) is True
    assert seeded.tenant_has_ever_had_membership(T1) is True


def test_active_members_counts_only_active_rows(seeded):
    """O5: only an `active` row makes 'has active members'; invited, revoked and ended do not."""
    a, b, c = _user(seeded, "a@x.org"), _user(seeded, "b@x.org"), _user(seeded, "c@x.org")
    assert seeded.tenant_has_active_members(T1) is False
    inv = _invited(seeded, a)
    assert seeded.tenant_has_active_members(T1) is False
    seeded.revoke_invitation(inv.id)
    assert seeded.tenant_has_active_members(T1) is False
    mem = _active(seeded, b)
    assert seeded.tenant_has_active_members(T1) is True
    assert seeded.tenant_has_active_members(T2) is False
    seeded.end_membership(mem.id, ended_by=b.id, now=NOW)
    assert seeded.tenant_has_active_members(T1) is False
    _active(seeded, c)
    assert seeded.tenant_has_active_members(T1) is True


# --- users -----------------------------------------------------------------------------------


def test_emails_are_stored_lower_cased_and_found_in_any_case(seeded):
    """Emails are unique and stored lower-cased (O2, data model)."""
    u = seeded.ensure_user("Ann@X.Org", now=NOW)
    assert u.email == "ann@x.org"
    assert u.status == "invited"
    assert seeded.user_by_email("ANN@x.org").id == u.id
    assert seeded.user(u.id).email == "ann@x.org"
    assert seeded.user_by_email("other@x.org") is None


def test_ensure_user_reuses_the_user_of_an_existing_email_in_any_case(seeded):
    """One insert wins, the other reuses it: ensure_user of a known email, any case, is the same user."""
    first = seeded.ensure_user("ann@x.org", now=NOW)
    again = seeded.ensure_user("ANN@x.ORG", now=NOW + dt.timedelta(hours=1))
    assert again.id == first.id
    assert again.created_at == first.created_at
    other = seeded.ensure_user("bob@x.org", now=NOW)  # positive control: a new email is a new user
    assert other.id != first.id
    assert seeded.user_by_email("ANN@X.ORG").id == first.id


def test_the_seeder_refuses_a_duplicate_email_in_any_case(seeded):
    """The email unique rule is held by the repository itself, not left to the service."""
    _user(seeded, "ann@x.org")
    with pytest.raises(DataRuleViolation):
        _user(seeded, "Ann@X.org")


def test_a_signin_account_is_recorded_once(seeded):
    """signin_account_id is unique and recorded once (data model)."""
    a, b = _user(seeded, "a@x.org"), _user(seeded, "b@x.org")
    assert seeded.record_signin_account(a.id, "acct-1") is True
    assert seeded.user(a.id).signin_account_id == "acct-1"
    assert seeded.user_by_signin_account("acct-1").id == a.id
    assert seeded.record_signin_account(a.id, "acct-2") is False  # recorded once
    assert seeded.user(a.id).signin_account_id == "acct-1"
    assert seeded.record_signin_account(b.id, "acct-1") is False  # unique
    assert seeded.user(b.id).signin_account_id is None
    assert seeded.user_by_signin_account("acct-2") is None


def test_activation_is_conditional_and_stamps_activated_at(seeded):
    """invited -> active applies once; `active` carries activated_at (status/timestamp rule)."""
    u = _user(seeded)
    assert u.activated_at is None
    assert seeded.activate_user(u.id, display_name="Ann", now=NOW) is True
    got = seeded.user(u.id)
    assert (got.status, got.activated_at, got.display_name) == ("active", NOW, "Ann")
    later = NOW + dt.timedelta(days=1)
    assert seeded.activate_user(u.id, display_name="Other", now=later) is False
    got = seeded.user(u.id)
    assert (got.activated_at, got.display_name) == (NOW, "Ann")


def test_the_platform_admin_flag_follows_set_platform_admin(seeded):
    """O5: the flag lives on the user row and can be set and cleared."""
    u = _user(seeded)
    assert u.is_platform_admin is False
    seeded.set_platform_admin(u.id, True)
    assert seeded.user(u.id).is_platform_admin is True
    seeded.set_platform_admin(u.id, False)
    assert seeded.user(u.id).is_platform_admin is False


# --- memberships -----------------------------------------------------------------------------


def test_an_invitation_inserts_one_invited_row_with_no_expiry_yet(seeded):
    """Flow 1 step 2: a new invited row; expiry waits for the send (K6, DC-3)."""
    u = _user(seeded)
    row = _invited(seeded, u)
    assert (row.user_id, row.tenant_id, row.status, row.invited_by) == (u.id, T1, "invited", "system")
    assert (row.created_at, row.expires_at, row.accepted_at) == (NOW, None, None)


def test_inviting_twice_yields_one_row(seeded):
    """Flow 1: repeat invitation finds the `invited` row for (user, tenant) (O2, DC-8)."""
    u = _user(seeded)
    first = _invited(seeded, u)
    second = seeded.ensure_invitation(u.id, T1, invited_by=u.id, now=NOW + dt.timedelta(days=1))
    assert second.id == first.id
    assert second.invited_by == "system"
    assert [m.id for m in seeded.memberships_of_tenant(T1)] == [first.id]


def test_an_invitation_can_carry_an_expiry_from_the_start(seeded):
    """DC-1: a flagged invitee's row is inserted with expires_at = created_at + 7 days; finding it again does not renew it."""
    u = _user(seeded)
    row = _invited(seeded, u, expires_at=NOW + WEEK)
    assert row.expires_at == NOW + WEEK
    later = NOW + dt.timedelta(days=3)
    again = seeded.ensure_invitation(u.id, T1, invited_by="system", now=later, expires_at=later + WEEK)
    assert again.id == row.id
    assert (again.expires_at, seeded.membership(row.id).expires_at) == (NOW + WEEK, NOW + WEEK)


def test_inviting_an_active_member_reports_it_and_adds_no_row(seeded):
    """Flow 1 step 2: already an active member -> the repository reports it (409 above)."""
    u = _user(seeded)
    active = _active(seeded, u)
    assert seeded.ensure_invitation(u.id, T1, invited_by="system", now=NOW) is None
    assert [m.id for m in seeded.memberships_of_tenant(T1)] == [active.id]
    other = seeded.ensure_invitation(u.id, T2, invited_by="system", now=NOW)  # control: another tenant
    assert other is not None
    assert other.status == "invited"


@pytest.mark.parametrize("how", ["revoked", "ended"])
def test_a_finished_row_is_never_reopened_a_new_invitation_adds_a_row(seeded, how):
    """K6: ended and revoked rows do not block a new invited row and are not reopened."""
    u = _user(seeded)
    if how == "revoked":
        old = _invited(seeded, u)
        assert seeded.revoke_invitation(old.id) is True
    else:
        old = _active(seeded, u)
        assert seeded.end_membership(old.id, ended_by=u.id, now=NOW) is True
    new = seeded.ensure_invitation(u.id, T1, invited_by="system", now=NOW)
    assert new.id != old.id
    assert new.status == "invited"
    assert seeded.membership(old.id).status == how
    assert seeded.accept_invitation(old.id, now=NOW) is False
    assert seeded.membership(old.id).status == how


def test_the_seeder_holds_one_live_row_per_user_and_tenant(seeded):
    """K6 partial unique index: a second invited-or-active row is refused; finished rows do not count."""
    u = _user(seeded)
    first = _invited(seeded, u)
    for status, extra in (("invited", {}), ("active", {"accepted_at": NOW})):
        with pytest.raises(DataRuleViolation):
            seeded.add_membership(u.id, T1, status=status, invited_by="system", created_at=NOW, **extra)
    seeded.revoke_invitation(first.id)
    _active(seeded, u)  # control: allowed once the first is revoked
    with pytest.raises(DataRuleViolation):
        seeded.add_membership(u.id, T1, status="invited", invited_by="system", created_at=NOW)
    for _ in range(2):  # many finished rows are fine
        seeded.add_membership(
            u.id, T1, status="ended", invited_by="system", created_at=NOW, accepted_at=NOW, ended_at=NOW, ended_by="system"
        )
    seeded.add_membership(u.id, T1, status="revoked", invited_by="system", created_at=NOW)


@pytest.mark.parametrize(
    "kw",
    [
        {"status": "active"},
        {"status": "ended", "ended_at": NOW},
        {"status": "ended", "ended_by": "system"},
    ],
)
def test_a_status_without_its_timestamps_is_refused(seeded, kw):
    """Data model CHECK: active => accepted_at; ended => ended_at and ended_by."""
    u = _user(seeded)
    with pytest.raises(DataRuleViolation):
        seeded.add_membership(u.id, T1, invited_by="system", created_at=NOW, **kw)


def test_accept_applies_once_and_stamps_accepted_at(seeded):
    """Flow 2/3: conditional invited -> active; a second accept reports not-applied (O4, K6)."""
    u = _user(seeded)
    row = _invited(seeded, u)
    later = NOW + dt.timedelta(hours=1)
    assert seeded.accept_invitation(row.id, now=later) is True
    got = seeded.membership(row.id)
    assert (got.status, got.accepted_at) == ("active", later)
    assert seeded.accept_invitation(row.id, now=later) is False
    assert seeded.membership(row.id).accepted_at == later
    assert seeded.active_membership(u.id, T1).id == row.id


def test_accept_needs_an_unexpired_row_or_no_expiry(seeded):
    """Acceptance requires expires_at > now; a row with a pending send has no expiry and is acceptable (O2)."""
    cases = [
        ("open", NOW + dt.timedelta(seconds=1), True),
        ("at the boundary", NOW, False),
        ("expired", NOW - dt.timedelta(seconds=1), False),
    ]
    for label, expires_at, applies in cases:
        u = _user(seeded, f"{label.replace(' ', '')}@x.org")
        row = seeded.add_membership(
            u.id, T1, status="invited", invited_by="system", created_at=NOW - WEEK, expires_at=expires_at
        )
        assert seeded.accept_invitation(row.id, now=NOW) is applies, label
        assert seeded.membership(row.id).status == ("active" if applies else "invited"), label
    pending = _invited(seeded, _user(seeded, "pending@x.org"))  # no expires_at: the send is still pending
    assert pending.expires_at is None
    assert seeded.accept_invitation(pending.id, now=NOW + 30 * WEEK) is True


def test_a_revoke_that_applied_first_makes_a_later_accept_not_apply(seeded):
    """Flow 2 / DC-8: a revocation that commits first wins; the conditional accept reports not-applied."""
    u = _user(seeded)
    row = _invited(seeded, u)
    assert seeded.revoke_invitation(row.id) is True
    assert seeded.accept_invitation(row.id, now=NOW) is False
    assert seeded.membership(row.id).status == "revoked"
    assert seeded.active_membership(u.id, T1) is None


def test_revoke_requires_invited(seeded):
    """Flow 6: revoke is conditional on `invited`; an accepted, ended or revoked row is untouched."""
    a, b = _user(seeded, "a@x.org"), _user(seeded, "b@x.org")
    invited = _invited(seeded, a)
    active = _active(seeded, b)
    assert seeded.revoke_invitation(active.id) is False
    assert seeded.membership(active.id).status == "active"
    assert seeded.revoke_invitation(invited.id) is True
    assert seeded.revoke_invitation(invited.id) is False
    seeded.end_membership(active.id, ended_by=b.id, now=NOW)
    assert seeded.revoke_invitation(active.id) is False
    assert seeded.membership(active.id).status == "ended"
    assert seeded.revoke_invitation("no-such-row") is False


def test_remove_requires_active_and_records_who_and_when(seeded):
    """Flow 5: active -> ended with ended_at and ended_by; conditional on `active` (O4)."""
    a, b = _user(seeded, "a@x.org"), _user(seeded, "b@x.org")
    invited = _invited(seeded, a)
    active = _active(seeded, b)
    assert seeded.end_membership(invited.id, ended_by=a.id, now=NOW) is False
    assert seeded.membership(invited.id).status == "invited"
    later = NOW + dt.timedelta(days=2)
    assert seeded.end_membership(active.id, ended_by=a.id, now=later) is True
    got = seeded.membership(active.id)
    assert (got.status, got.ended_at, got.ended_by) == ("ended", later, a.id)
    assert seeded.end_membership(active.id, ended_by=b.id, now=later) is False
    assert seeded.membership(active.id).ended_by == a.id
    assert seeded.active_membership(b.id, T1) is None
    assert seeded.end_membership("no-such-row", ended_by=a.id, now=NOW) is False


def test_membership_lookups_are_per_user_and_per_tenant(seeded):
    """The per-request query (flow 4) and the listings read rows of one user or one tenant."""
    a, b = _user(seeded, "a@x.org"), _user(seeded, "b@x.org")
    a1, a2, b1 = _active(seeded, a, T1), _invited(seeded, a, T2), _invited(seeded, b, T1)
    assert {m.id for m in seeded.memberships_of_user(a.id)} == {a1.id, a2.id}
    assert {m.id for m in seeded.memberships_of_tenant(T1)} == {a1.id, b1.id}
    assert seeded.active_membership(a.id, T1).id == a1.id
    assert seeded.active_membership(a.id, T2) is None  # invited is not active


def test_people_of_a_tenant_are_its_rows_in_one_status_with_their_users(seeded):
    """The member and invitation listings read one tenant's rows of one status, each with its user."""
    a, b, c = _user(seeded, "a@x.org"), _user(seeded, "b@x.org"), _user(seeded, "c@x.org")
    a1, b1 = _active(seeded, a, T1), _invited(seeded, b, T1)
    _active(seeded, c, T2)  # another tenant
    gone = _invited(seeded, c, T1)
    seeded.revoke_invitation(gone.id)
    assert [(m.id, u) for m, u in seeded.people_of_tenant(T1, "active")] == [(a1.id, seeded.user(a.id))]
    assert [(m.id, u) for m, u in seeded.people_of_tenant(T1, "invited")] == [(b1.id, seeded.user(b.id))]
    assert [m.id for m, _ in seeded.people_of_tenant(T1, "revoked")] == [gone.id]
    assert seeded.active_membership(b.id, T1) is None
    assert seeded.membership("no-such-row") is None


# --- send counters (DC-3) --------------------------------------------------------------------


def test_nothing_is_pending_until_requested(seeded):
    """DC-3: a send is pending only while requested_seq > sent_seq."""
    u = _user(seeded)
    _invited(seeded, u)
    assert (u.set_password_requested_seq, u.set_password_sent_seq) == (0, 0)
    claimed = _claim_user(seeded)
    assert claimed is None
    claimed = _claim_row(seeded)
    assert claimed is None


def test_a_requested_set_password_is_claimed_until_settled_as_sent(seeded):
    """DC-3: request bumps requested_seq; settling with the read value clears pending and stamps sent_at."""
    u = _user(seeded)
    assert seeded.request_set_password(u.id, now=NOW) == 1
    claimed = _claim_user(seeded)
    assert claimed.id == u.id
    assert (claimed.set_password_requested_seq, claimed.set_password_sent_seq) == (1, 0)
    assert claimed.set_password_requested_at == NOW
    sent = NOW + dt.timedelta(minutes=1)
    assert seeded.settle_set_password(u.id, 1, sent_at=sent) is True
    got = seeded.user(u.id)
    assert (got.set_password_sent_seq, got.set_password_sent_at) == (1, sent)
    claimed = _claim_user(seeded)
    assert claimed is None


def test_a_re_send_during_a_send_stays_pending(seeded):
    """DC-3/DC-8: CAS of sent_seq to the value read; a request that arrived mid-send is still pending."""
    u = _user(seeded)
    seeded.request_set_password(u.id, now=NOW)
    claimed = _claim_user(seeded)
    read = claimed.set_password_requested_seq
    assert seeded.request_set_password(u.id, now=NOW + dt.timedelta(seconds=5)) == 2  # arrives mid-send
    assert seeded.settle_set_password(u.id, read, sent_at=NOW + dt.timedelta(seconds=9)) is True
    claimed = _claim_user(seeded)
    assert claimed.id == u.id
    assert (claimed.set_password_sent_seq, claimed.set_password_requested_seq) == (1, 2)
    assert seeded.settle_set_password(u.id, 2, sent_at=NOW + dt.timedelta(seconds=20)) is True
    claimed = _claim_user(seeded)
    assert claimed is None


def test_a_stale_settle_does_not_apply(seeded):
    """DC-3: a compare-and-set with a read that is not ahead of sent_seq reports not-applied and changes nothing."""
    u = _user(seeded)
    seeded.request_set_password(u.id, now=NOW)
    seeded.request_set_password(u.id, now=NOW)
    t_sent = NOW + dt.timedelta(minutes=1)
    assert seeded.settle_set_password(u.id, 2, sent_at=t_sent) is True
    assert seeded.settle_set_password(u.id, 1, sent_at=t_sent + dt.timedelta(minutes=1)) is False
    assert seeded.settle_set_password(u.id, 2, sent_at=t_sent + dt.timedelta(minutes=1)) is False
    got = seeded.user(u.id)
    assert (got.set_password_sent_seq, got.set_password_sent_at) == (2, t_sent)


@pytest.mark.parametrize("kind", ["set_password", "notification"])
def test_a_settle_beyond_what_was_requested_does_not_apply(seeded, kind):
    """Fixed details: a settle applies only when sent_seq < read_seq <= requested_seq; a read past requested_seq changes nothing."""
    u = _user(seeded)
    row = _invited(seeded, u)
    if kind == "set_password":
        seeded.request_set_password(u.id, now=NOW)
        settle, counter = seeded.settle_set_password, (lambda: seeded.user(u.id).set_password_sent_seq)
        target = u.id
    else:
        seeded.request_notification(row.id, now=NOW)
        settle, counter = seeded.settle_notification, (lambda: seeded.membership(row.id).notify_sent_seq)
        target = row.id
    assert settle(target, 2, sent_at=NOW, expires_at=NOW + WEEK) is False
    assert counter() == 0
    assert seeded.membership(row.id).expires_at is None
    assert settle(target, 1, sent_at=NOW, expires_at=NOW + WEEK) is True  # control: the requested value applies
    assert counter() == 1


def test_a_dropped_send_advances_the_counter_without_a_send_time(seeded):
    """Fixed details: a dropped send advances sent_seq; set_password_sent_at stays the real send time."""
    u = _user(seeded)
    row = _invited(seeded, u)
    seeded.request_set_password(u.id, now=NOW)
    assert seeded.settle_set_password(u.id, 1, expires_at=NOW + WEEK) is True  # dropped: no send time
    got = seeded.user(u.id)
    assert (got.set_password_sent_seq, got.set_password_sent_at) == (1, None)
    assert seeded.membership(row.id).expires_at is None  # nothing went out, so nothing runs out
    claimed = _claim_user(seeded)
    assert claimed is None


def test_a_real_send_sets_the_expiry_of_the_users_invited_rows_only(seeded):
    """Flow 1 step 4: expires_at = given time on the user's `invited` rows; revoked/active rows are untouched."""
    u = _user(seeded)
    invited = _invited(seeded, u, T1)
    revoked_row = seeded.add_membership(u.id, T1, status="revoked", invited_by="system", created_at=NOW)
    active_row = _active(seeded, u, T2)
    other = _user(seeded, "o@x.org")
    others_row = _invited(seeded, other, T1)
    seeded.request_set_password(u.id, now=NOW)
    expiry = NOW + WEEK
    assert seeded.settle_set_password(u.id, 1, sent_at=NOW, expires_at=expiry) is True
    assert seeded.membership(invited.id).expires_at == expiry
    assert seeded.membership(revoked_row.id).expires_at is None
    assert seeded.membership(active_row.id).expires_at is None
    assert seeded.membership(others_row.id).expires_at is None
    # a stale settle does not touch expiry
    assert seeded.settle_set_password(u.id, 1, sent_at=NOW, expires_at=NOW + 2 * WEEK) is False
    assert seeded.membership(invited.id).expires_at == expiry


def test_an_activated_user_has_no_pending_set_password(seeded):
    """Data model: a set-password send is pending only while the user is `invited`."""
    u = _user(seeded)
    seeded.request_set_password(u.id, now=NOW)
    seeded.activate_user(u.id, display_name="Ann", now=NOW)
    claimed = _claim_user(seeded)
    assert claimed is None


def test_a_requested_notification_is_claimed_until_settled_as_sent(seeded):
    """DC-3 for the row: notify counters; settling stamps notified_at and the row's expires_at."""
    u = _user(seeded)
    row = _invited(seeded, u)
    assert seeded.request_notification(row.id, now=NOW) == 1
    claimed = _claim_row(seeded)
    assert claimed.id == row.id
    assert (claimed.notify_requested_seq, claimed.notify_sent_seq) == (1, 0)
    sent = NOW + dt.timedelta(minutes=1)
    assert seeded.settle_notification(row.id, 1, sent_at=sent, expires_at=sent + WEEK) is True
    got = seeded.membership(row.id)
    assert (got.notify_sent_seq, got.notified_at, got.expires_at) == (1, sent, sent + WEEK)
    claimed = _claim_row(seeded)
    assert claimed is None


def test_a_re_notify_during_a_send_stays_pending_and_a_stale_settle_does_not_apply(seeded):
    """DC-3/DC-8 for notifications."""
    u = _user(seeded)
    row = _invited(seeded, u)
    seeded.request_notification(row.id, now=NOW)
    assert seeded.request_notification(row.id, now=NOW) == 2
    assert seeded.settle_notification(row.id, 1, sent_at=NOW) is True
    claimed = _claim_row(seeded)
    assert claimed.id == row.id
    assert claimed.notify_requested_seq == 2
    assert seeded.settle_notification(row.id, 2, sent_at=NOW) is True
    assert seeded.settle_notification(row.id, 1, sent_at=NOW) is False
    assert seeded.membership(row.id).notify_sent_seq == 2


def test_a_dropped_notification_advances_without_a_send_time(seeded):
    """Fixed details: dropping a notification advances the counter, notified_at stays null, no expiry set."""
    u = _user(seeded)
    row = _invited(seeded, u)
    seeded.request_notification(row.id, now=NOW)
    assert seeded.settle_notification(row.id, 1, expires_at=NOW + WEEK) is True  # dropped: no send time
    got = seeded.membership(row.id)
    assert (got.notify_sent_seq, got.notified_at, got.expires_at) == (1, None, None)


def test_a_notification_settle_sets_the_expiry_of_that_row_only(seeded):
    """Fixed details: a notification's expires_at goes on that one row; the user's other pending rows keep none."""
    u = _user(seeded, status="active")
    r1, r2 = _invited(seeded, u, T1), _invited(seeded, u, T2)
    seeded.request_notification(r1.id, now=NOW)
    seeded.request_notification(r2.id, now=NOW)
    assert seeded.settle_notification(r1.id, 1, sent_at=NOW, expires_at=NOW + WEEK) is True
    assert seeded.membership(r1.id).expires_at == NOW + WEEK
    assert seeded.membership(r2.id).expires_at is None
    claimed = _claim_row(seeded)  # control: the other is still pending
    assert claimed.id == r2.id


def test_a_notification_is_pending_only_while_the_row_is_invited(seeded):
    """Data model: revoked rows are skipped by pending sends."""
    a, b = _user(seeded, "a@x.org"), _user(seeded, "b@x.org")
    gone, kept = _invited(seeded, a), _invited(seeded, b)
    seeded.request_notification(gone.id, now=NOW)
    seeded.request_notification(kept.id, now=NOW)
    seeded.revoke_invitation(gone.id)
    claimed = _claim_row(seeded)
    assert claimed.id == kept.id
    assert seeded.settle_notification(kept.id, 1, sent_at=NOW) is True
    claimed = _claim_row(seeded)
    assert claimed is None


def test_a_claimed_user_is_skipped_by_a_second_claimant_until_the_hold_runs_out(seeded):
    """Flow 1 (r9): a claim holds the user until `hold_until`; another claimant gets the next one or nothing."""
    a, b = _user(seeded, "a@x.org"), _user(seeded, "b@x.org")
    seeded.request_set_password(a.id, now=NOW)
    assert _claim_user(seeded).id == a.id
    assert _claim_user(seeded) is None
    seeded.request_set_password(b.id, now=NOW)
    assert _claim_user(seeded).id == b.id
    assert seeded.user(a.id).set_password_next_try_at == NOW + HOLD
    assert _claim_user(seeded, NOW + HOLD - dt.timedelta(seconds=1)) is None
    assert _claim_user(seeded, NOW + HOLD).id in {a.id, b.id}  # control: a crashed sender's hold runs out


@pytest.mark.parametrize("kind", ["set_password", "notification"])
def test_a_deferred_send_is_due_again_at_its_next_try_and_a_settle_clears_the_attempts(seeded, kind):
    """Flow 1 (r9): a failed send counts an attempt and waits for its next try; a settle starts over."""
    u = _user(seeded)
    row = _invited(seeded, u)
    later = NOW + dt.timedelta(minutes=30)
    if kind == "set_password":
        seeded.request_set_password(u.id, now=NOW)
        claim, defer, settle, target = _claim_user, seeded.defer_set_password, seeded.settle_set_password, u.id
        state = lambda: (seeded.user(u.id).set_password_attempts, seeded.user(u.id).set_password_next_try_at)  # noqa: E731
    else:
        seeded.request_notification(row.id, now=NOW)
        claim, defer, settle, target = _claim_row, seeded.defer_notification, seeded.settle_notification, row.id
        state = lambda: (seeded.membership(row.id).notify_attempts, seeded.membership(row.id).notify_next_try_at)  # noqa: E731
    assert claim(seeded).id == target
    defer(target, until=later)
    assert state() == (1, later)
    assert claim(seeded, later - dt.timedelta(seconds=1)) is None
    again = claim(seeded, later)
    assert again.id == target
    assert (again.set_password_attempts if kind == "set_password" else again.notify_attempts) == 1
    defer(target, until=later + HOUR)
    assert state() == (2, later + HOUR)
    assert settle(target, 1, sent_at=later + HOUR) is True
    assert state() == (0, None)


def test_a_claim_skips_what_the_caller_names(seeded):
    """Flow 1: `skip` leaves those users out of this claim."""
    a, b = _user(seeded, "a@x.org"), _user(seeded, "b@x.org")
    seeded.request_set_password(a.id, now=NOW)
    seeded.request_set_password(b.id, now=NOW)
    assert seeded.claim_set_password(now=NOW, hold_until=NOW + HOLD, skip={a.id}).id == b.id
    assert seeded.claim_set_password(now=NOW, hold_until=NOW + HOLD, skip={b.id}).id == a.id


# --- sessions --------------------------------------------------------------------------------


def _session(repo, value="raw-session-value", user=None, **kw):
    user = user or _user(repo)
    return user, repo.add_session(value, user.id, now=NOW, expires_at=NOW + WEEK, **kw)


def test_a_session_is_found_by_its_value_and_only_the_hash_is_kept(seeded):
    """O6: sessions are looked up by the hash of the value; the raw value is never stored."""
    value = "raw-session-value-0123456789"
    user, stored = _session(seeded, value, used_otp=True)
    found = seeded.session_by_value(value)
    assert found.user_id == user.id
    assert found.used_otp is True
    assert (found.created_at, found.last_seen_at, found.expires_at) == (NOW, NOW, NOW + WEEK)
    for row in (stored, found):
        assert all(value not in str(v) for v in dataclasses.asdict(row).values())
        assert row.token_hash != value
    assert seeded.session_by_value(value + "x") is None
    assert seeded.session_by_value("") is None
    _, other = _session(seeded, "another-value", user=user)
    assert other.token_hash != found.token_hash
    assert seeded.session_by_value("another-value").token_hash == other.token_hash
    # F-9: the hash is the lowercase hex SHA-256 of the value, whatever its length
    for raw, row in ((value, found), ("another-value", other)):
        assert row.token_hash == hashlib.sha256(raw.encode()).hexdigest()
    assert len(value) != len("another-value")


def test_a_session_needs_an_existing_user(seeded):
    """sessions.user_id references users."""
    with pytest.raises(DataRuleViolation):
        seeded.add_session("v", "no-such-user", now=NOW, expires_at=NOW + WEEK)


def test_sign_out_deletes_that_session_only(seeded):
    """O6/flow 7: delete the session row; other devices stay signed in."""
    user, _ = _session(seeded, "device-1")
    _session(seeded, "device-2", user=user)
    assert seeded.delete_session("device-1") is True
    assert seeded.session_by_value("device-1") is None
    assert seeded.session_by_value("device-2").user_id == user.id
    assert seeded.delete_session("device-1") is False


def test_last_seen_is_written_only_when_older_than_five_minutes(seeded):
    """O6/flow 4: conditional update, at most one write per 5 minutes."""
    _session(seeded, "v")
    assert seeded.touch_session("v", now=NOW + dt.timedelta(minutes=4, seconds=59)) is False
    assert seeded.session_by_value("v").last_seen_at == NOW
    t1 = NOW + dt.timedelta(minutes=5, seconds=1)
    assert seeded.touch_session("v", now=t1) is True
    assert seeded.session_by_value("v").last_seen_at == t1
    assert seeded.touch_session("v", now=t1 + dt.timedelta(minutes=1)) is False
    assert seeded.session_by_value("v").last_seen_at == t1
    assert seeded.touch_session("never-issued", now=t1) is False


# --- PostgreSQL only: database concurrency -------------------------------------------------


@pytest.fixture
def two_connections() -> Iterator[tuple[object, object]]:
    dsn = _dsn()
    schema = f"t_{uuid.uuid4().hex}"
    first = _postgres_repo(dsn, schema)
    second = _postgres_repo(dsn, schema)
    try:
        first.register_tenant(T1)
        yield first, second
    finally:
        first.close()
        second.close()
        _drop_schema(dsn, schema)


@pytest.mark.postgres
def test_concurrent_ensure_user_of_one_new_email_converge_on_one_user(two_connections):
    """Data model: the email unique index makes concurrent invites converge; one insert wins, the other reuses."""
    barrier = threading.Barrier(2)
    results: list = []
    errors: list = []

    def run(r, email):
        try:
            barrier.wait(timeout=10)
            results.append(r.ensure_user(email, now=NOW))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    for i in range(10):  # repeat to give the race a chance to happen
        email = f"New{i}@X.org"
        results.clear()
        barrier = threading.Barrier(2)
        threads = [threading.Thread(target=run, args=(r, email)) for r in two_connections]
        [t.start() for t in threads]
        [t.join(timeout=20) for t in threads]
        assert not errors
        assert len(results) == 2
        assert results[0].id == results[1].id
        assert results[0].email == email.lower()


@pytest.mark.postgres
def test_two_senders_claiming_at_once_get_the_user_once(two_connections):
    """Flow 1 (r9): FOR UPDATE SKIP LOCKED then the hold — two claims racing for one pending user, one wins."""
    first, second = two_connections
    for i in range(10):  # repeat to give the race a chance to happen
        u = first.add_user(f"p{i}@x.org", created_at=NOW)
        first.request_set_password(u.id, now=NOW)
        barrier, got = threading.Barrier(2), []

        def claim(r, barrier=barrier, got=got):
            barrier.wait(timeout=10)
            got.append(_claim_user(r))

        threads = [threading.Thread(target=claim, args=(r,)) for r in two_connections]
        [t.start() for t in threads]
        [t.join(timeout=20) for t in threads]
        assert sorted((c.id if c else "") for c in got) == ["", u.id]
        assert first.settle_set_password(u.id, 1, sent_at=NOW) is True


@pytest.mark.postgres
def test_a_mixed_case_schema_is_used_as_given():
    """Fixed details: the schema name is quoted the same way everywhere, so `Identity_X` is not folded."""
    dsn = _dsn()
    schema = f"Identity_{uuid.uuid4().hex}"
    r = _postgres_repo(dsn, schema)
    try:
        r.register_tenant(T1)
        u = r.ensure_user("Mixed@X.org", now=NOW)
        assert r.user_by_email("mixed@x.org").id == u.id
        assert r.tenants() == [str(T1)]
    finally:
        r.close()
        _drop_schema(dsn, schema)