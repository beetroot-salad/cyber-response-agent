"""#1306 IdentityRepository contract: one suite over the in-memory and the PostgreSQL repository (DC-4).

The PostgreSQL run is marked `postgres` and needs DEFENDER_TEST_POSTGRES_DSN. CI's test job
starts a PostgreSQL service and sets it, so both runs happen on every push; there an unset DSN
fails rather than skips, so a broken service cannot turn the PostgreSQL half green by absence.
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import hashlib
import uuid
from collections.abc import AsyncIterator, Iterator

import pytest

from defender.identity import DataRuleViolation, InMemoryIdentityRepository
from defender.records._tenant_id import TenantId
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._pglocks1339 import (
    TIMEOUT,
    connections,
    holding_row,
    holding_user_insert,
    until,
    until_blocked,
)
from defender.tests.support.shared._postgres1339 import database, execute

pytestmark = pytest.mark.anyio

NOW = dt.datetime(2026, 10, 26, 12, 0, tzinfo=dt.UTC)
WEEK = dt.timedelta(days=7)
HOUR = dt.timedelta(hours=1)
HOLD = dt.timedelta(minutes=5)
T1 = TenantId(fixture_uuid("tenant:t1"))
T2 = TenantId(fixture_uuid("tenant:t2"))
T_UNREGISTERED = TenantId(fixture_uuid("tenant:unregistered"))


def _postgres(dsn: str):
    from defender.identity.postgres import PostgresIdentityRepository

    return PostgresIdentityRepository(dsn)


def _claim_user(repo, now=NOW):
    return repo.claim_set_password(now=now, hold_until=now + HOLD)


def _claim_row(repo, now=NOW):
    return repo.claim_notification(now=now, hold_until=now + HOLD)


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
def backend(request) -> Iterator[str | None]:
    """`None` for the in-memory repository, else the DSN of a migrated database of this test's own."""
    if request.param == "memory":
        yield None
        return
    with database(migrated=True) as dsn:
        yield dsn


@pytest.fixture
async def repo(backend) -> AsyncIterator[object]:
    """The repository under test; its engine connects and closes inside the test's loop."""
    r = InMemoryIdentityRepository() if backend is None else _postgres(backend)
    try:
        yield r
    finally:
        await r.close()


@pytest.fixture
async def seeded(repo):
    """The repository with T1 and T2 registered."""
    await repo.register_tenant(T1, now=NOW)
    await repo.register_tenant(T2, now=NOW)
    return repo


async def _user(repo, email="ann@x.org", **kw):
    return await repo.add_user(email, created_at=NOW, **kw)


async def _invited(repo, user, tenant=T1, **kw):
    return await repo.ensure_invitation(user.id, tenant, invited_by="system", now=NOW, **kw)


async def _active(repo, user, tenant=T1):
    return await repo.add_membership(user.id, tenant, status="active", invited_by="system", created_at=NOW, accepted_at=NOW)


# --- tenants ---------------------------------------------------------------------------------


async def test_register_tenant_is_idempotent_and_decides_existence(seeded):
    """register_tenant twice is one tenant; an unregistered id does not exist (O8, DC-4)."""
    await seeded.register_tenant(T1, now=NOW + HOUR)
    assert await seeded.tenant_exists(T1) is True
    assert await seeded.tenant_exists(T_UNREGISTERED) is False


@pytest.mark.postgres
async def test_register_tenant_stores_the_given_time_and_keeps_the_first(pg_dsn):
    """D: `tenants.created_at` is the `now` the caller passed; registering again does not move it."""
    repo = _postgres(pg_dsn)
    try:
        await repo.register_tenant(T1, now=NOW)
        await repo.register_tenant(T1, now=NOW + HOUR)
    finally:
        await repo.close()
    assert execute(pg_dsn, "SELECT created_at FROM identity.tenants WHERE id = %s", (str(T1),)) == [(NOW,)]


async def test_a_membership_in_an_unregistered_tenant_is_refused(seeded):
    """A membership row needs a registered tenant (tenants table is referenced)."""
    u = await _user(seeded)
    with pytest.raises(DataRuleViolation):
        await _invited(seeded, u, T_UNREGISTERED)
    with pytest.raises(DataRuleViolation):
        await seeded.add_membership(u.id, T_UNREGISTERED, status="invited", invited_by="system", created_at=NOW)


async def test_a_membership_for_an_unknown_user_is_refused(seeded):
    """A membership row needs an existing user."""
    with pytest.raises(DataRuleViolation):
        await seeded.ensure_invitation("no-such-user", T1, invited_by="system", now=NOW)


async def test_ever_had_a_membership_survives_revoke_and_end(seeded):
    """O8: 'ever had a membership row' is false only for a tenant with none, even after revoke/end."""
    assert await seeded.tenant_has_ever_had_membership(T1) is False
    assert await seeded.tenant_has_ever_had_membership(T2) is False
    u = await _user(seeded)
    row = await _invited(seeded, u)
    assert await seeded.tenant_has_ever_had_membership(T1) is True
    assert await seeded.tenant_has_ever_had_membership(T2) is False
    assert await seeded.revoke_invitation(row.id) is True
    assert await seeded.tenant_has_ever_had_membership(T1) is True


async def test_active_members_counts_only_active_rows(seeded):
    """O5: only an `active` row makes 'has active members'; invited, revoked and ended do not."""
    a, b, c = await _user(seeded, "a@x.org"), await _user(seeded, "b@x.org"), await _user(seeded, "c@x.org")
    assert await seeded.tenant_has_active_members(T1) is False
    inv = await _invited(seeded, a)
    assert await seeded.tenant_has_active_members(T1) is False
    await seeded.revoke_invitation(inv.id)
    assert await seeded.tenant_has_active_members(T1) is False
    mem = await _active(seeded, b)
    assert await seeded.tenant_has_active_members(T1) is True
    assert await seeded.tenant_has_active_members(T2) is False
    await seeded.end_membership(mem.id, ended_by=b.id, now=NOW)
    assert await seeded.tenant_has_active_members(T1) is False
    await _active(seeded, c)
    assert await seeded.tenant_has_active_members(T1) is True


# --- users -----------------------------------------------------------------------------------


async def test_emails_are_stored_lower_cased_and_found_in_any_case(seeded):
    """Emails are unique and stored lower-cased (O2, data model)."""
    u = await seeded.ensure_user("Ann@X.Org", now=NOW)
    assert u.email == "ann@x.org"
    assert u.status == "invited"
    assert (await seeded.user_by_email("ANN@x.org")).id == u.id
    assert (await seeded.user(u.id)).email == "ann@x.org"
    assert await seeded.user_by_email("other@x.org") is None


async def test_ensure_user_reuses_the_user_of_an_existing_email_in_any_case(seeded):
    """One insert wins, the other reuses it: ensure_user of a known email, any case, is the same user."""
    first = await seeded.ensure_user("ann@x.org", now=NOW)
    again = await seeded.ensure_user("ANN@x.ORG", now=NOW + dt.timedelta(hours=1))
    assert again.id == first.id
    assert again.created_at == first.created_at
    other = await seeded.ensure_user("bob@x.org", now=NOW)  # positive control: a new email is a new user
    assert other.id != first.id
    assert (await seeded.user_by_email("ANN@X.ORG")).id == first.id


async def test_the_seeder_refuses_a_duplicate_email_in_any_case(seeded):
    """The email unique rule is held by the repository itself, not left to the service."""
    await _user(seeded, "ann@x.org")
    with pytest.raises(DataRuleViolation):
        await _user(seeded, "Ann@X.org")


@pytest.mark.parametrize("email", [
    "a\x00b@x.org",    # NUL: PostgreSQL text cannot hold it
    "a\ud800b@x.org",  # a lone surrogate: not UTF-8 at all
    "",
    " \t\u00a0",       # nothing left once trimmed
])
async def test_an_email_the_database_cannot_store_or_that_is_blank_is_refused_and_nothing_is_written(seeded, email):
    """#1349 B1.2: both repositories refuse it alike, rather than one failing in the database."""
    with pytest.raises(DataRuleViolation):
        await seeded.ensure_user(email, now=NOW)
    with pytest.raises(DataRuleViolation):
        await _user(seeded, email)
    with pytest.raises(DataRuleViolation):
        await seeded.user_by_email(email)
    assert await seeded.user_by_email("ann@x.org") is None
    plain = await seeded.ensure_user(" \tAnn@X.org\r\n", now=NOW)  # positive control: whitespace is trimmed
    assert plain.email == "ann@x.org"


@pytest.mark.parametrize("email", ["ann@x.org\u00a0", "\u3000Ann@X.org", "\u2028ann@x.org\u2009",
                                   "ann@x.org\n\u00a0", "\u00a0\nann@x.org"])  # in any order
async def test_unicode_whitespace_around_an_email_is_trimmed(seeded, email):
    """#1349: a non-breaking or other Unicode space pasted around an address is not part of it."""
    assert (await seeded.ensure_user(email, now=NOW)).email == "ann@x.org"
    assert (await seeded.user_by_email("ann@x.org")) is not None


async def test_a_signin_account_is_recorded_once(seeded):
    """signin_account_id is unique and recorded once (data model)."""
    a, b = await _user(seeded, "a@x.org"), await _user(seeded, "b@x.org")
    assert await seeded.record_signin_account(a.id, "acct-1") is True
    assert (await seeded.user(a.id)).signin_account_id == "acct-1"
    assert (await seeded.user_by_signin_account("acct-1")).id == a.id
    assert await seeded.record_signin_account(a.id, "acct-2") is False  # recorded once
    assert (await seeded.user(a.id)).signin_account_id == "acct-1"
    assert await seeded.record_signin_account(b.id, "acct-1") is False  # unique
    assert (await seeded.user(b.id)).signin_account_id is None
    assert await seeded.user_by_signin_account("acct-2") is None


async def test_activation_is_conditional_and_stamps_activated_at(seeded):
    """invited -> active applies once; `active` carries activated_at (status/timestamp rule)."""
    u = await _user(seeded)
    assert u.activated_at is None
    assert await seeded.activate_user(u.id, display_name="Ann", now=NOW) is True
    got = await seeded.user(u.id)
    assert (got.status, got.activated_at, got.display_name) == ("active", NOW, "Ann")
    later = NOW + dt.timedelta(days=1)
    assert await seeded.activate_user(u.id, display_name="Other", now=later) is False
    got = await seeded.user(u.id)
    assert (got.activated_at, got.display_name) == (NOW, "Ann")


async def test_the_platform_admin_flag_follows_set_platform_admin(seeded):
    """O5: the flag lives on the user row and can be set and cleared."""
    u = await _user(seeded)
    assert u.is_platform_admin is False
    await seeded.set_platform_admin(u.id, True)
    assert (await seeded.user(u.id)).is_platform_admin is True
    await seeded.set_platform_admin(u.id, False)
    assert (await seeded.user(u.id)).is_platform_admin is False


# --- memberships -----------------------------------------------------------------------------


async def test_an_invitation_inserts_one_invited_row_with_no_expiry_yet(seeded):
    """Flow 1 step 2: a new invited row; expiry waits for the send (K6, DC-3)."""
    u = await _user(seeded)
    row = await _invited(seeded, u)
    assert (row.user_id, row.tenant_id, row.status, row.invited_by) == (u.id, T1, "invited", "system")
    assert (row.created_at, row.expires_at, row.accepted_at) == (NOW, None, None)


async def test_inviting_twice_yields_one_row(seeded):
    """Flow 1: repeat invitation finds the `invited` row for (user, tenant) (O2, DC-8)."""
    u = await _user(seeded)
    first = await _invited(seeded, u)
    second = await seeded.ensure_invitation(u.id, T1, invited_by=u.id, now=NOW + dt.timedelta(days=1))
    assert second.id == first.id
    assert second.invited_by == "system"
    assert [m.id for m in await seeded.memberships_of_tenant(T1)] == [first.id]


async def test_an_invitation_can_carry_an_expiry_from_the_start(seeded):
    """DC-1: a flagged invitee's row is inserted with expires_at = created_at + 7 days; finding it again does not renew it."""
    u = await _user(seeded)
    row = await _invited(seeded, u, expires_at=NOW + WEEK)
    assert row.expires_at == NOW + WEEK
    later = NOW + dt.timedelta(days=3)
    again = await seeded.ensure_invitation(u.id, T1, invited_by="system", now=later, expires_at=later + WEEK)
    assert again.id == row.id
    assert (again.expires_at, (await seeded.membership(row.id)).expires_at) == (NOW + WEEK, NOW + WEEK)


async def test_inviting_an_active_member_reports_it_and_adds_no_row(seeded):
    """Flow 1 step 2: already an active member -> the repository reports it (409 above)."""
    u = await _user(seeded)
    active = await _active(seeded, u)
    assert await seeded.ensure_invitation(u.id, T1, invited_by="system", now=NOW) is None
    assert [m.id for m in await seeded.memberships_of_tenant(T1)] == [active.id]
    other = await seeded.ensure_invitation(u.id, T2, invited_by="system", now=NOW)  # control: another tenant
    assert other is not None
    assert other.status == "invited"


@pytest.mark.parametrize("how", ["revoked", "ended"])
async def test_a_finished_row_is_never_reopened_a_new_invitation_adds_a_row(seeded, how):
    """K6: ended and revoked rows do not block a new invited row and are not reopened."""
    u = await _user(seeded)
    if how == "revoked":
        old = await _invited(seeded, u)
        assert await seeded.revoke_invitation(old.id) is True
    else:
        old = await _active(seeded, u)
        assert await seeded.end_membership(old.id, ended_by=u.id, now=NOW) is True
    new = await seeded.ensure_invitation(u.id, T1, invited_by="system", now=NOW)
    assert new.id != old.id
    assert new.status == "invited"
    assert (await seeded.membership(old.id)).status == how
    assert await seeded.accept_invitation(old.id, now=NOW) is False
    assert (await seeded.membership(old.id)).status == how


async def test_the_seeder_holds_one_live_row_per_user_and_tenant(seeded):
    """K6 partial unique index: a second invited-or-active row is refused; finished rows do not count."""
    u = await _user(seeded)
    first = await _invited(seeded, u)
    for status, extra in (("invited", {}), ("active", {"accepted_at": NOW})):
        with pytest.raises(DataRuleViolation):
            await seeded.add_membership(u.id, T1, status=status, invited_by="system", created_at=NOW, **extra)
    await seeded.revoke_invitation(first.id)
    await _active(seeded, u)  # control: allowed once the first is revoked
    with pytest.raises(DataRuleViolation):
        await seeded.add_membership(u.id, T1, status="invited", invited_by="system", created_at=NOW)
    for _ in range(2):  # many finished rows are fine
        await seeded.add_membership(
            u.id, T1, status="ended", invited_by="system", created_at=NOW, accepted_at=NOW, ended_at=NOW, ended_by="system"
        )
    await seeded.add_membership(u.id, T1, status="revoked", invited_by="system", created_at=NOW)


@pytest.mark.parametrize(
    "kw",
    [
        {"status": "active"},
        {"status": "ended", "ended_at": NOW},
        {"status": "ended", "ended_by": "system"},
    ],
)
async def test_a_status_without_its_timestamps_is_refused(seeded, kw):
    """Data model CHECK: active => accepted_at; ended => ended_at and ended_by."""
    u = await _user(seeded)
    with pytest.raises(DataRuleViolation):
        await seeded.add_membership(u.id, T1, invited_by="system", created_at=NOW, **kw)


async def test_a_status_outside_the_model_is_refused_and_nothing_is_stored(seeded):
    """Data model CHECK: a user's and a membership's status is one of the model's; both stores refuse the rest alike."""
    with pytest.raises(DataRuleViolation):
        await seeded.add_user("bogus@example.com", created_at=NOW, status="bogus")
    assert await seeded.user_by_email("bogus@example.com") is None

    u = await _user(seeded)
    with pytest.raises(DataRuleViolation):
        await seeded.add_membership(u.id, T1, status="bogus", invited_by="system", created_at=NOW)
    assert await seeded.memberships_of_tenant(T1) == []


async def test_accept_applies_once_and_stamps_accepted_at(seeded):
    """Flow 2/3: conditional invited -> active; a second accept reports not-applied (O4, K6)."""
    u = await _user(seeded)
    row = await _invited(seeded, u)
    later = NOW + dt.timedelta(hours=1)
    assert await seeded.accept_invitation(row.id, now=later) is True
    got = await seeded.membership(row.id)
    assert (got.status, got.accepted_at) == ("active", later)
    assert await seeded.accept_invitation(row.id, now=later) is False
    assert (await seeded.membership(row.id)).accepted_at == later
    assert (await seeded.active_membership(u.id, T1)).id == row.id


async def test_accept_needs_an_unexpired_row_or_no_expiry(seeded):
    """Acceptance requires expires_at > now; a row with a pending send has no expiry and is acceptable (O2)."""
    cases = [
        ("open", NOW + dt.timedelta(seconds=1), True),
        ("at the boundary", NOW, False),
        ("expired", NOW - dt.timedelta(seconds=1), False),
    ]
    for label, expires_at, applies in cases:
        u = await _user(seeded, f"{label.replace(' ', '')}@x.org")
        row = await seeded.add_membership(
            u.id, T1, status="invited", invited_by="system", created_at=NOW - WEEK, expires_at=expires_at
        )
        assert await seeded.accept_invitation(row.id, now=NOW) is applies, label
        assert (await seeded.membership(row.id)).status == ("active" if applies else "invited"), label
    pending = await _invited(seeded, (await _user(seeded, "pending@x.org")))  # no expires_at: the send is still pending
    assert pending.expires_at is None
    assert await seeded.accept_invitation(pending.id, now=NOW + 30 * WEEK) is True


async def test_a_revoke_that_applied_first_makes_a_later_accept_not_apply(seeded):
    """Flow 2 / DC-8: a revocation that commits first wins; the conditional accept reports not-applied."""
    u = await _user(seeded)
    row = await _invited(seeded, u)
    assert await seeded.revoke_invitation(row.id) is True
    assert await seeded.accept_invitation(row.id, now=NOW) is False
    assert (await seeded.membership(row.id)).status == "revoked"
    assert await seeded.active_membership(u.id, T1) is None


async def test_revoke_requires_invited(seeded):
    """Flow 6: revoke is conditional on `invited`; an accepted, ended or revoked row is untouched."""
    a, b = await _user(seeded, "a@x.org"), await _user(seeded, "b@x.org")
    invited = await _invited(seeded, a)
    active = await _active(seeded, b)
    assert await seeded.revoke_invitation(active.id) is False
    assert (await seeded.membership(active.id)).status == "active"
    assert await seeded.revoke_invitation(invited.id) is True
    assert await seeded.revoke_invitation(invited.id) is False
    await seeded.end_membership(active.id, ended_by=b.id, now=NOW)
    assert await seeded.revoke_invitation(active.id) is False
    assert (await seeded.membership(active.id)).status == "ended"
    assert await seeded.revoke_invitation("no-such-row") is False


async def test_remove_requires_active_and_records_who_and_when(seeded):
    """Flow 5: active -> ended with ended_at and ended_by; conditional on `active` (O4)."""
    a, b = await _user(seeded, "a@x.org"), await _user(seeded, "b@x.org")
    invited = await _invited(seeded, a)
    active = await _active(seeded, b)
    assert await seeded.end_membership(invited.id, ended_by=a.id, now=NOW) is False
    assert (await seeded.membership(invited.id)).status == "invited"
    later = NOW + dt.timedelta(days=2)
    assert await seeded.end_membership(active.id, ended_by=a.id, now=later) is True
    got = await seeded.membership(active.id)
    assert (got.status, got.ended_at, got.ended_by) == ("ended", later, a.id)
    assert await seeded.end_membership(active.id, ended_by=b.id, now=later) is False
    assert (await seeded.membership(active.id)).ended_by == a.id
    assert await seeded.active_membership(b.id, T1) is None
    assert await seeded.end_membership("no-such-row", ended_by=a.id, now=NOW) is False


async def test_membership_lookups_are_per_user_and_per_tenant(seeded):
    """The per-request query (flow 4) and the listings read rows of one user or one tenant."""
    a, b = await _user(seeded, "a@x.org"), await _user(seeded, "b@x.org")
    a1, a2, b1 = await _active(seeded, a, T1), await _invited(seeded, a, T2), await _invited(seeded, b, T1)
    assert {m.id for m in await seeded.memberships_of_user(a.id)} == {a1.id, a2.id}
    assert {m.id for m in await seeded.memberships_of_tenant(T1)} == {a1.id, b1.id}
    assert (await seeded.active_membership(a.id, T1)).id == a1.id
    assert await seeded.active_membership(a.id, T2) is None  # invited is not active


async def test_people_of_a_tenant_are_its_rows_in_one_status_with_their_users(seeded):
    """The member and invitation listings read one tenant's rows of one status, each with its user."""
    a, b, c = await _user(seeded, "a@x.org"), await _user(seeded, "b@x.org"), await _user(seeded, "c@x.org")
    a1, b1 = await _active(seeded, a, T1), await _invited(seeded, b, T1)
    await _active(seeded, c, T2)  # another tenant
    gone = await _invited(seeded, c, T1)
    await seeded.revoke_invitation(gone.id)
    assert [(m.id, u) for m, u in await seeded.people_of_tenant(T1, "active")] == [(a1.id, await seeded.user(a.id))]
    assert [(m.id, u) for m, u in await seeded.people_of_tenant(T1, "invited")] == [(b1.id, await seeded.user(b.id))]
    assert [m.id for m, _ in await seeded.people_of_tenant(T1, "revoked")] == [gone.id]
    assert await seeded.active_membership(b.id, T1) is None
    assert await seeded.membership("no-such-row") is None


# --- send counters (DC-3) --------------------------------------------------------------------


async def test_nothing_is_pending_until_requested(seeded):
    """DC-3: a send is pending only while requested_seq > sent_seq."""
    u = await _user(seeded)
    await _invited(seeded, u)
    assert (u.set_password_requested_seq, u.set_password_sent_seq) == (0, 0)
    claimed = await _claim_user(seeded)
    assert claimed is None
    claimed = await _claim_row(seeded)
    assert claimed is None


async def test_a_requested_set_password_is_claimed_until_settled_as_sent(seeded):
    """DC-3: request bumps requested_seq; settling with the read value clears pending and stamps sent_at."""
    u = await _user(seeded)
    assert await seeded.request_set_password(u.id, now=NOW) == 1
    claimed = await _claim_user(seeded)
    assert claimed.id == u.id
    assert (claimed.set_password_requested_seq, claimed.set_password_sent_seq) == (1, 0)
    assert claimed.set_password_requested_at == NOW
    sent = NOW + dt.timedelta(minutes=1)
    assert await seeded.settle_set_password(u.id, 1, sent_at=sent) is True
    got = await seeded.user(u.id)
    assert (got.set_password_sent_seq, got.set_password_sent_at) == (1, sent)
    claimed = await _claim_user(seeded)
    assert claimed is None


async def test_a_re_send_during_a_send_stays_pending(seeded):
    """DC-3/DC-8: CAS of sent_seq to the value read; a request that arrived mid-send is still pending."""
    u = await _user(seeded)
    await seeded.request_set_password(u.id, now=NOW)
    claimed = await _claim_user(seeded)
    read = claimed.set_password_requested_seq
    assert await seeded.request_set_password(u.id, now=NOW + dt.timedelta(seconds=5)) == 2  # arrives mid-send
    assert await seeded.settle_set_password(u.id, read, sent_at=NOW + dt.timedelta(seconds=9)) is True
    claimed = await _claim_user(seeded)
    assert claimed.id == u.id
    assert (claimed.set_password_sent_seq, claimed.set_password_requested_seq) == (1, 2)
    assert await seeded.settle_set_password(u.id, 2, sent_at=NOW + dt.timedelta(seconds=20)) is True
    claimed = await _claim_user(seeded)
    assert claimed is None


async def test_a_stale_settle_does_not_apply(seeded):
    """DC-3: a compare-and-set with a read that is not ahead of sent_seq reports not-applied and changes nothing."""
    u = await _user(seeded)
    await seeded.request_set_password(u.id, now=NOW)
    await seeded.request_set_password(u.id, now=NOW)
    t_sent = NOW + dt.timedelta(minutes=1)
    assert await seeded.settle_set_password(u.id, 2, sent_at=t_sent) is True
    assert await seeded.settle_set_password(u.id, 1, sent_at=t_sent + dt.timedelta(minutes=1)) is False
    assert await seeded.settle_set_password(u.id, 2, sent_at=t_sent + dt.timedelta(minutes=1)) is False
    got = await seeded.user(u.id)
    assert (got.set_password_sent_seq, got.set_password_sent_at) == (2, t_sent)


@pytest.mark.parametrize("kind", ["set_password", "notification"])
async def test_a_settle_beyond_what_was_requested_does_not_apply(seeded, kind):
    """Fixed details: a settle applies only when sent_seq < read_seq <= requested_seq; a read past requested_seq changes nothing."""
    u = await _user(seeded)
    row = await _invited(seeded, u)
    if kind == "set_password":
        await seeded.request_set_password(u.id, now=NOW)
        settle = seeded.settle_set_password

        async def counter():
            return (await seeded.user(u.id)).set_password_sent_seq
        target = u.id
    else:
        await seeded.request_notification(row.id, now=NOW)
        settle = seeded.settle_notification

        async def counter():
            return (await seeded.membership(row.id)).notify_sent_seq
        target = row.id
    assert await settle(target, 2, sent_at=NOW, expires_at=NOW + WEEK) is False
    assert await counter() == 0
    assert (await seeded.membership(row.id)).expires_at is None
    assert await settle(target, 1, sent_at=NOW, expires_at=NOW + WEEK) is True  # control: the requested value applies
    assert await counter() == 1


async def test_a_dropped_send_advances_the_counter_without_a_send_time(seeded):
    """Fixed details: a dropped send advances sent_seq; set_password_sent_at stays the real send time."""
    u = await _user(seeded)
    row = await _invited(seeded, u)
    await seeded.request_set_password(u.id, now=NOW)
    assert await seeded.settle_set_password(u.id, 1, expires_at=NOW + WEEK) is True  # dropped: no send time
    got = await seeded.user(u.id)
    assert (got.set_password_sent_seq, got.set_password_sent_at) == (1, None)
    assert (await seeded.membership(row.id)).expires_at is None  # nothing went out, so nothing runs out
    claimed = await _claim_user(seeded)
    assert claimed is None


async def test_a_real_send_sets_the_expiry_of_the_users_invited_rows_only(seeded):
    """Flow 1 step 4: expires_at = given time on the user's `invited` rows; revoked/active rows are untouched."""
    u = await _user(seeded)
    invited = await _invited(seeded, u, T1)
    revoked_row = await seeded.add_membership(u.id, T1, status="revoked", invited_by="system", created_at=NOW)
    active_row = await _active(seeded, u, T2)
    other = await _user(seeded, "o@x.org")
    others_row = await _invited(seeded, other, T1)
    await seeded.request_set_password(u.id, now=NOW)
    expiry = NOW + WEEK
    assert await seeded.settle_set_password(u.id, 1, sent_at=NOW, expires_at=expiry) is True
    assert (await seeded.membership(invited.id)).expires_at == expiry
    assert (await seeded.membership(revoked_row.id)).expires_at is None
    assert (await seeded.membership(active_row.id)).expires_at is None
    assert (await seeded.membership(others_row.id)).expires_at is None
    # a stale settle does not touch expiry
    assert await seeded.settle_set_password(u.id, 1, sent_at=NOW, expires_at=NOW + 2 * WEEK) is False
    assert (await seeded.membership(invited.id)).expires_at == expiry


async def test_an_activated_user_has_no_pending_set_password(seeded):
    """Data model: a set-password send is pending only while the user is `invited`."""
    u = await _user(seeded)
    await seeded.request_set_password(u.id, now=NOW)
    await seeded.activate_user(u.id, display_name="Ann", now=NOW)
    claimed = await _claim_user(seeded)
    assert claimed is None


async def test_a_requested_notification_is_claimed_until_settled_as_sent(seeded):
    """DC-3 for the row: notify counters; settling stamps notified_at and the row's expires_at."""
    u = await _user(seeded)
    row = await _invited(seeded, u)
    assert await seeded.request_notification(row.id, now=NOW) == 1
    claimed = await _claim_row(seeded)
    assert claimed.id == row.id
    assert (claimed.notify_requested_seq, claimed.notify_sent_seq) == (1, 0)
    sent = NOW + dt.timedelta(minutes=1)
    assert await seeded.settle_notification(row.id, 1, sent_at=sent, expires_at=sent + WEEK) is True
    got = await seeded.membership(row.id)
    assert (got.notify_sent_seq, got.notified_at, got.expires_at) == (1, sent, sent + WEEK)
    claimed = await _claim_row(seeded)
    assert claimed is None


async def test_a_re_notify_during_a_send_stays_pending_and_a_stale_settle_does_not_apply(seeded):
    """DC-3/DC-8 for notifications."""
    u = await _user(seeded)
    row = await _invited(seeded, u)
    await seeded.request_notification(row.id, now=NOW)
    assert await seeded.request_notification(row.id, now=NOW) == 2
    assert await seeded.settle_notification(row.id, 1, sent_at=NOW) is True
    claimed = await _claim_row(seeded)
    assert claimed.id == row.id
    assert claimed.notify_requested_seq == 2
    assert await seeded.settle_notification(row.id, 2, sent_at=NOW) is True
    assert await seeded.settle_notification(row.id, 1, sent_at=NOW) is False
    assert (await seeded.membership(row.id)).notify_sent_seq == 2


async def test_a_dropped_notification_advances_without_a_send_time(seeded):
    """Fixed details: dropping a notification advances the counter, notified_at stays null, no expiry set."""
    u = await _user(seeded)
    row = await _invited(seeded, u)
    await seeded.request_notification(row.id, now=NOW)
    assert await seeded.settle_notification(row.id, 1, expires_at=NOW + WEEK) is True  # dropped: no send time
    got = await seeded.membership(row.id)
    assert (got.notify_sent_seq, got.notified_at, got.expires_at) == (1, None, None)


async def test_a_notification_settle_sets_the_expiry_of_that_row_only(seeded):
    """Fixed details: a notification's expires_at goes on that one row; the user's other pending rows keep none."""
    u = await _user(seeded, status="active")
    r1, r2 = await _invited(seeded, u, T1), await _invited(seeded, u, T2)
    await seeded.request_notification(r1.id, now=NOW)
    await seeded.request_notification(r2.id, now=NOW)
    assert await seeded.settle_notification(r1.id, 1, sent_at=NOW, expires_at=NOW + WEEK) is True
    assert (await seeded.membership(r1.id)).expires_at == NOW + WEEK
    assert (await seeded.membership(r2.id)).expires_at is None
    claimed = await _claim_row(seeded)  # control: the other is still pending
    assert claimed.id == r2.id


async def test_a_notification_is_pending_only_while_the_row_is_invited(seeded):
    """Data model: revoked rows are skipped by pending sends."""
    a, b = await _user(seeded, "a@x.org"), await _user(seeded, "b@x.org")
    gone, kept = await _invited(seeded, a), await _invited(seeded, b)
    await seeded.request_notification(gone.id, now=NOW)
    await seeded.request_notification(kept.id, now=NOW)
    await seeded.revoke_invitation(gone.id)
    claimed = await _claim_row(seeded)
    assert claimed.id == kept.id
    assert await seeded.settle_notification(kept.id, 1, sent_at=NOW) is True
    claimed = await _claim_row(seeded)
    assert claimed is None


async def test_a_claimed_user_is_skipped_by_a_second_claimant_until_the_hold_runs_out(seeded):
    """Flow 1 (r9): a claim holds the user until `hold_until`; another claimant gets the next one or nothing."""
    a, b = await _user(seeded, "a@x.org"), await _user(seeded, "b@x.org")
    await seeded.request_set_password(a.id, now=NOW)
    assert (await _claim_user(seeded)).id == a.id
    assert await _claim_user(seeded) is None
    await seeded.request_set_password(b.id, now=NOW)
    assert (await _claim_user(seeded)).id == b.id
    assert (await seeded.user(a.id)).set_password_next_try_at == NOW + HOLD
    assert await _claim_user(seeded, NOW + HOLD - dt.timedelta(seconds=1)) is None
    assert (await _claim_user(seeded, NOW + HOLD)).id in {a.id, b.id}  # control: a crashed sender's hold runs out


@pytest.mark.parametrize("kind", ["set_password", "notification"])
async def test_a_deferred_send_is_due_again_at_its_next_try_and_a_settle_clears_the_attempts(seeded, kind):
    """Flow 1 (r9): a failed send counts an attempt and waits for its next try; a settle starts over."""
    u = await _user(seeded)
    row = await _invited(seeded, u)
    later = NOW + dt.timedelta(minutes=30)
    if kind == "set_password":
        await seeded.request_set_password(u.id, now=NOW)
        claim, defer, settle, target = _claim_user, seeded.defer_set_password, seeded.settle_set_password, u.id

        async def state():
            got = await seeded.user(u.id)
            return got.set_password_attempts, got.set_password_next_try_at
    else:
        await seeded.request_notification(row.id, now=NOW)
        claim, defer, settle, target = _claim_row, seeded.defer_notification, seeded.settle_notification, row.id

        async def state():
            got = await seeded.membership(row.id)
            return got.notify_attempts, got.notify_next_try_at
    assert (await claim(seeded)).id == target
    await defer(target, until=later)
    assert await state() == (1, later)
    assert await claim(seeded, later - dt.timedelta(seconds=1)) is None
    again = await claim(seeded, later)
    assert again.id == target
    assert (again.set_password_attempts if kind == "set_password" else again.notify_attempts) == 1
    await defer(target, until=later + HOUR)
    assert await state() == (2, later + HOUR)
    assert await settle(target, 1, sent_at=later + HOUR) is True
    assert await state() == (0, None)


async def test_a_claim_skips_what_the_caller_names(seeded):
    """Flow 1: `skip` leaves those users out of this claim."""
    a, b = await _user(seeded, "a@x.org"), await _user(seeded, "b@x.org")
    await seeded.request_set_password(a.id, now=NOW)
    await seeded.request_set_password(b.id, now=NOW)
    assert (await seeded.claim_set_password(now=NOW, hold_until=NOW + HOLD, skip={a.id})).id == b.id
    assert (await seeded.claim_set_password(now=NOW, hold_until=NOW + HOLD, skip={b.id})).id == a.id


# --- sessions --------------------------------------------------------------------------------


async def _session(repo, value="raw-session-value", user=None, **kw):
    user = user or await _user(repo)
    return user, await repo.add_session(value, user.id, now=NOW, expires_at=NOW + WEEK, **kw)


async def test_a_session_is_found_by_its_value_and_only_the_hash_is_kept(seeded):
    """O6: sessions are looked up by the hash of the value; the raw value is never stored."""
    value = "raw-session-value-0123456789"
    user, stored = await _session(seeded, value, used_otp=True)
    found = await seeded.session_by_value(value)
    assert found.user_id == user.id
    assert found.used_otp is True
    assert (found.created_at, found.last_seen_at, found.expires_at) == (NOW, NOW, NOW + WEEK)
    for row in (stored, found):
        assert all(value not in str(v) for v in dataclasses.asdict(row).values())
        assert row.token_hash != value
    assert await seeded.session_by_value(value + "x") is None
    assert await seeded.session_by_value("") is None
    _, other = await _session(seeded, "another-value", user=user)
    assert other.token_hash != found.token_hash
    assert (await seeded.session_by_value("another-value")).token_hash == other.token_hash
    # F-9: the hash is the lowercase hex SHA-256 of the value, whatever its length
    for raw, row in ((value, found), ("another-value", other)):
        assert row.token_hash == hashlib.sha256(raw.encode()).hexdigest()
    assert len(value) != len("another-value")


async def test_a_session_needs_an_existing_user(seeded):
    """sessions.user_id references users."""
    with pytest.raises(DataRuleViolation):
        await seeded.add_session("v", "no-such-user", now=NOW, expires_at=NOW + WEEK)


async def test_purging_removes_exactly_the_sessions_sign_in_would_refuse_as_expired(seeded):
    """#1349 B2: a session is gone once `now >= expires_at` (the same boundary `authenticate`
    refuses at) and kept a moment before; the count says how many went; a second purge is a no-op."""
    user = await _user(seeded)
    for value, expires in (("past", NOW - HOUR), ("at-now", NOW), ("just-alive", NOW + dt.timedelta(microseconds=1))):
        await seeded.add_session(value, user.id, now=NOW - WEEK, expires_at=expires)
    assert await seeded.purge_expired_sessions(now=NOW) == 2
    assert await seeded.session_by_value("past") is None
    assert await seeded.session_by_value("at-now") is None
    assert (await seeded.session_by_value("just-alive")).user_id == user.id
    assert await seeded.purge_expired_sessions(now=NOW) == 0


async def test_sign_out_deletes_that_session_only(seeded):
    """O6/flow 7: delete the session row; other devices stay signed in."""
    user, _ = await _session(seeded, "device-1")
    await _session(seeded, "device-2", user=user)
    assert await seeded.delete_session("device-1") is True
    assert await seeded.session_by_value("device-1") is None
    assert (await seeded.session_by_value("device-2")).user_id == user.id
    assert await seeded.delete_session("device-1") is False


async def test_last_seen_is_written_only_when_older_than_five_minutes(seeded):
    """O6/flow 4: conditional update, at most one write per 5 minutes."""
    await _session(seeded, "v")
    assert await seeded.touch_session("v", now=NOW + dt.timedelta(minutes=4, seconds=59)) is False
    assert (await seeded.session_by_value("v")).last_seen_at == NOW
    t1 = NOW + dt.timedelta(minutes=5, seconds=1)
    assert await seeded.touch_session("v", now=t1) is True
    assert (await seeded.session_by_value("v")).last_seen_at == t1
    assert await seeded.touch_session("v", now=t1 + dt.timedelta(minutes=1)) is False
    assert (await seeded.session_by_value("v")).last_seen_at == t1
    assert await seeded.touch_session("never-issued", now=t1) is False


# --- P4: returned models are detached copies -------------------------------------------------


def _values(model: object) -> dict[str, object]:
    """Every field of a returned model, read now (a detached model with an unloaded field raises here)."""
    return {f.name: getattr(model, f.name) for f in dataclasses.fields(model)}  # type: ignore[arg-type]


def _mutate(model: object) -> None:
    """Change every field of `model` to a different value."""
    for name, value in _values(model).items():
        if isinstance(value, bool):
            changed: object = not value
        elif isinstance(value, int):
            changed = value + 1
        elif isinstance(value, dt.datetime):
            changed = value + dt.timedelta(days=1)
        elif name == "status":  # another status the model accepts; the models refuse any other value
            changed = "invited" if value == "active" else "active"
        elif isinstance(value, str):
            changed = value + "-mutated"
        else:
            changed = "mutated"
        setattr(model, name, changed)


def _models(result: object) -> list[object]:
    """The models inside a returned value: one, a list of them, or a list of (membership, user) pairs."""
    if isinstance(result, list | tuple):
        return [m for item in result for m in _models(item)]
    return [] if result is None else [result]


SESSION_VALUES = ("sess-v", "new-sess-v")


def _refs(models: list[object]) -> list[tuple[str, str]]:
    """How to look each model up again: ("user", id), ("membership", id) or ("session", raw value)."""
    out = []
    for m in models:
        if hasattr(m, "email"):
            out.append(("user", m.id))
        elif hasattr(m, "token_hash"):
            [value] = [v for v in SESSION_VALUES if hashlib.sha256(v.encode()).hexdigest() == m.token_hash]
            out.append(("session", value))
        else:
            out.append(("membership", m.id))
    return out


async def _stored(repo, refs: list[tuple[str, str]]) -> dict[tuple[str, str], dict[str, object]]:
    """Every referenced record, re-read through the repository's own lookups."""
    lookups = {"user": repo.user, "membership": repo.membership, "session": repo.session_by_value}
    return {ref: _values(await lookups[ref[0]](ref[1])) for ref in refs}


P4_CASES = {
    "add_user": lambda r, w: r.add_user("new@x.org", created_at=NOW),
    "add_membership": lambda r, w: r.add_membership(
        w["bob"].id, T2, status="active", invited_by="system", created_at=NOW, accepted_at=NOW),
    "add_session": lambda r, w: r.add_session("new-sess-v", w["bob"].id, now=NOW, expires_at=NOW + WEEK),
    "ensure_user_new": lambda r, w: r.ensure_user("fresh@x.org", now=NOW),
    "ensure_user_existing": lambda r, w: r.ensure_user("ANN@x.org", now=NOW),
    "ensure_invitation_new": lambda r, w: r.ensure_invitation(w["ann"].id, T2, invited_by="system", now=NOW),
    "ensure_invitation_existing": lambda r, w: r.ensure_invitation(w["ann"].id, T1, invited_by="system", now=NOW),
    "user": lambda r, w: r.user(w["ann"].id),
    "user_by_email": lambda r, w: r.user_by_email("ann@x.org"),
    "user_by_signin_account": lambda r, w: r.user_by_signin_account("acct-ann"),
    "membership": lambda r, w: r.membership(w["inv"].id),
    "active_membership": lambda r, w: r.active_membership(w["bob"].id, T1),
    "session_by_value": lambda r, w: r.session_by_value("sess-v"),
    "platform_admins": lambda r, w: r.platform_admins(),
    "memberships_of_user": lambda r, w: r.memberships_of_user(w["ann"].id),
    "memberships_of_tenant": lambda r, w: r.memberships_of_tenant(T1),
    "people_of_tenant": lambda r, w: r.people_of_tenant(T1, "invited"),
    "claim_set_password": lambda r, w: _claim_user(r),
    "claim_notification": lambda r, w: _claim_row(r),
}


@pytest.mark.parametrize("case", sorted(P4_CASES))
async def test_a_returned_model_is_fully_readable_and_changing_it_changes_nothing_stored(seeded, case):
    """P4 (O4): every field of every model a method returns is readable, and mutating it stores nothing."""
    ann = await _user(seeded, "ann@x.org")
    bob = await _user(seeded, "bob@x.org", status="active")
    carol = await _user(seeded, "carol@x.org", is_platform_admin=True)
    assert await seeded.record_signin_account(ann.id, "acct-ann") is True
    inv = await _invited(seeded, ann)
    await _active(seeded, bob)
    await _session(seeded, "sess-v", user=ann)
    await seeded.request_set_password(ann.id, now=NOW)
    await seeded.request_notification(inv.id, now=NOW)
    world = {"ann": ann, "bob": bob, "carol": carol, "inv": inv}

    returned = _models(await P4_CASES[case](seeded, world))
    assert returned, f"{case} returned nothing to check"
    before_values = [_values(m) for m in returned]
    refs = _refs([*world.values(), *returned])
    stored = await _stored(seeded, refs)

    for m in returned:
        _mutate(m)
    assert [_values(m) for m in returned] != before_values  # control: the mutation took on the copies
    await seeded.ensure_user("later@x.org", now=NOW)  # a later committed write must not carry the edits along
    assert await _stored(seeded, refs) == stored


async def test_a_model_returned_twice_is_two_copies(seeded):
    """P4: two reads of one record give separate objects; editing one leaves the other as it was."""
    u = await _user(seeded)
    first, second = await seeded.user(u.id), await seeded.user(u.id)
    assert first is not second
    first.display_name = "Edited"
    assert second.display_name == (await seeded.user(u.id)).display_name == ""


# --- PostgreSQL only: database concurrency -------------------------------------------------
# Each race is held at one point by a raw connection and released on purpose, so the interleaving
# is the same on every run: the operation is started, the test waits until the server shows it
# blocked, then lets it go.


@pytest.fixture
def pg_dsn() -> Iterator[str]:
    with database(migrated=True) as dsn:
        yield dsn


@pytest.fixture
async def two_repositories(pg_dsn) -> AsyncIterator[tuple[object, object]]:
    """Two repositories, so two engines and two sets of connections, over one database."""
    first, second = _postgres(pg_dsn), _postgres(pg_dsn)
    try:
        await first.register_tenant(T1, now=NOW)
        yield first, second
    finally:
        await first.close()
        await second.close()


@pytest.mark.postgres
async def test_ensure_user_of_an_email_being_inserted_elsewhere_waits_and_reuses_that_user(two_repositories, pg_dsn):
    """Data model: while another insert of the email is uncommitted, ensure_user waits, then reuses that user."""
    first, second = two_repositories
    template = await first.ensure_user("template@x.org", now=NOW)
    other = str(uuid.UUID(int=0xA11CE))
    async with holding_user_insert(pg_dsn, like_email=template.email, email="new@x.org", user_id=other):
        pending = asyncio.ensure_future(second.ensure_user("New@X.org", now=NOW))
        await until_blocked(pg_dsn, 1)
        assert not pending.done()
    got = await asyncio.wait_for(pending, TIMEOUT)
    assert (got.id, got.email) == (other, "new@x.org")
    assert (await first.user_by_email("NEW@x.org")).id == other
    assert await first.ensure_user("new@x.org", now=NOW + HOUR) == got  # control: a later call reuses it too


@pytest.mark.postgres
@pytest.mark.parametrize("kind", ["set_password", "notification"])
async def test_a_claim_skips_a_row_another_claimant_holds_and_does_not_wait(two_repositories, pg_dsn, kind):
    """Flow 1 (r9): FOR UPDATE SKIP LOCKED — a held row is passed over at once, then claimed once it is released."""
    first, second = two_repositories
    u = await first.add_user("p@x.org", created_at=NOW)
    if kind == "set_password":
        await first.request_set_password(u.id, now=NOW)
        claim, table, row_id = _claim_user, "users", u.id
    else:
        row = await first.ensure_invitation(u.id, T1, invited_by="system", now=NOW)
        await first.request_notification(row.id, now=NOW)
        claim, table, row_id = _claim_row, "memberships", row.id
    async with holding_row(pg_dsn, table, row_id):
        assert await asyncio.wait_for(claim(second), 5) is None  # skipped, not waited for
    claimed = await claim(second)
    assert claimed.id == row_id
    assert await claim(first) is None  # held now by the claim itself
    settled = (await first.settle_set_password(u.id, 1, sent_at=NOW) if kind == "set_password"
               else await first.settle_notification(row_id, 1, sent_at=NOW, expires_at=NOW + WEEK))
    assert settled is True


@pytest.mark.postgres
@pytest.mark.parametrize("started_first", ["revoke", "accept"])
async def test_a_revoke_racing_an_accept_on_one_invitation_applies_exactly_one(two_repositories, pg_dsn, started_first):
    """O6d: with both waiting on the invited row, whichever is let through applies and the other reports not-applied."""
    first, second = two_repositories
    u = await first.add_user("race@x.org", created_at=NOW)
    row = await first.ensure_invitation(u.id, T1, invited_by="system", now=NOW)
    operations = {"revoke": lambda: first.revoke_invitation(row.id), "accept": lambda: second.accept_invitation(row.id, now=NOW)}
    order = [started_first, "accept" if started_first == "revoke" else "revoke"]
    async with holding_row(pg_dsn, "memberships", row.id):
        tasks = {}
        for count, name in enumerate(order, start=1):
            tasks[name] = asyncio.ensure_future(operations[name]())
            await until_blocked(pg_dsn, count)  # each is held at the row before the next starts
        assert not any(t.done() for t in tasks.values())
    results = {name: await asyncio.wait_for(t, TIMEOUT) for name, t in tasks.items()}
    assert sorted(results.values()) == [False, True], results
    after = await first.membership(row.id)
    assert (after.status, after.accepted_at) == (("revoked", None) if results["revoke"] else ("active", NOW))


@pytest.mark.postgres
async def test_closing_a_repository_disposes_its_engine(pg_dsn):
    """Lifecycle (E): close releases every database connection the repository opened."""
    repo = _postgres(pg_dsn)
    await repo.register_tenant(T1, now=NOW)
    await repo.ensure_user("a@x.org", now=NOW)

    async def idle() -> bool:
        return await connections(pg_dsn) == 0

    assert await connections(pg_dsn) > 0  # control: the repository does hold connections while open
    await repo.close()
    await until(idle)


@pytest.mark.postgres
async def test_a_returned_datetime_is_utc_whatever_zone_the_database_defaults_to(pg_dsn):
    """P4: the database's own time zone never shows in what the repository returns (every offset is zero)."""
    name = execute(pg_dsn, "SELECT current_database()")[0][0]
    execute(pg_dsn, f'ALTER DATABASE "{name}" SET timezone TO \'Pacific/Chatham\'')
    repo = _postgres(pg_dsn)
    try:
        await repo.register_tenant(T1, now=NOW)
        ann = await repo.add_user("ann@x.org", created_at=NOW)
        row = await repo.ensure_invitation(ann.id, T1, invited_by="system", now=NOW)
        await repo.accept_invitation(row.id, now=NOW)
        await repo.request_set_password(ann.id, now=NOW)
        models = _models([
            await repo.user(ann.id), await repo.membership(row.id),
            await repo.add_session("tz-sess", ann.id, now=NOW, expires_at=NOW + WEEK),
            await _claim_user(repo)])
    finally:
        await repo.close()
    # control: the zone is in force for a plain connection, so a naive read would have shown it
    assert execute(pg_dsn, "SELECT created_at FROM identity.users")[0][0].utcoffset() != dt.timedelta(0)
    stamps = [v for m in models for v in _values(m).values() if isinstance(v, dt.datetime)]
    assert len(stamps) >= 6
    assert [v for v in stamps if v.utcoffset() != dt.timedelta(0)] == []
