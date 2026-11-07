# ruff: noqa: F811  — the #1306 contract's fixtures are imported, as in test_1214_atk1_repository.py
"""#1307 IdentityRepository contract for programs and their credentials, memory and PostgreSQL (P-I, P-G, O4, O5).

Forced choices (FC-7, extending the support module's list; the design names no repository method):
`add_program(tenant_id, *, display_name, created_by, now) -> User`;
`add_membership(..., role="admin")` (the seeder takes the role; people default `admin`);
`add_credential(program_id, *, kind, name, created_by, expires_at, now, key_hash=None) -> row` (keys `live`; OAuth
`pending` with `pending_deadline = now + 10 min`; over the cap, for a non-program, without an active membership, or
a key without its hash / an OAuth client with one -> `DataRuleViolation`);
`go_live(credential_id, *, service_account_id, now) -> bool`; `revoke_credential(credential_id, *, revoked_by, now) -> bool`;
`credentials_of_program(program_id)`; `credential_by_id(id)` / `credential_by_hash(key_hash)` -> row or None (any state);
`programs_of_tenant(tenant_id) -> list[User]` (active programs); `remove_program(program_id, *, removed_by, now) -> bool`
(one write: membership ended and every credential revoked); `touch_credential(id, *, now) -> bool` (as `touch_session`);
`revoke_stale_pending(*, now) -> list[credential id]`. Rows carry the design's fields (`state`, `kind`, `key_hash`,
`service_account_id`, `pending_deadline`, `last_used_at`, `revoked_at`, `revoked_by`, ...).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib

import pytest

from defender.identity import DataRuleViolation
from defender.tests.identity.test_1306_repository_contract import (  # noqa: F401  (fixtures)
    HOUR,
    NO_SUCH_ROW,
    NOW,
    T1,
    T2,
    _active,
    _invited,
    _user,
    backend,
    pg_dsn,
    repo,
    seeded,
    tenants,
    two_repositories,
)
from defender.tests.support.shared._pglocks1339 import TIMEOUT, holding_row, until_blocked

pytestmark = pytest.mark.anyio

DAY = dt.timedelta(days=1)
EXPIRES = NOW + 90 * DAY
DEADLINE = dt.timedelta(minutes=10)
SA = "9a8b7c6d-0000-4000-8000-0000000005a1"


async def _program(repo, admin, tenant=T1, name="SOAR prod"):
    return await repo.add_program(tenant, display_name=name, created_by=admin.id, now=NOW)


def _key(n: int) -> str:
    return hashlib.sha256(f"dfk_key-{n}".encode()).hexdigest()


async def _add_key(repo, program, admin, n, *, expires_at=EXPIRES, now=NOW):
    return await repo.add_credential(program.id, kind="key", name=f"k{n}", created_by=admin.id,
                                     expires_at=expires_at, now=now, key_hash=_key(n))


async def _add_oauth(repo, program, admin, n, *, expires_at=EXPIRES, now=NOW):
    return await repo.add_credential(program.id, kind="oauth_client", name=f"o{n}", created_by=admin.id,
                                     expires_at=expires_at, now=now)


async def _states(repo, program) -> dict[str, str]:
    return {r.id: r.state for r in await repo.credentials_of_program(program.id)}


# --- the program row -------------------------------------------------------------------------------

async def test_a_program_is_an_active_automation_member_with_no_email(seeded):
    """A program: kind program, no email, always active, creator recorded, one active `automation` membership (O4, O3)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    assert (program.kind, program.email, program.status, program.created_by) == ("program", None, "active", admin.id)
    assert program.display_name == "SOAR prod"
    assert await seeded.user(program.id) == program
    [membership] = await seeded.memberships_of_user(program.id)
    assert (membership.tenant_id, membership.status, membership.role) == (T1, "active", "automation")
    assert (await seeded.active_membership(program.id, T1)).id == membership.id
    second = await _program(seeded, admin, name="Another")  # two programs, both with no email
    assert second.id != program.id
    assert second.email is None


async def test_a_person_is_kind_person_with_an_admin_membership(seeded):
    """Control for the program row: people default to kind person, no creator, and `admin` memberships (O3)."""
    ann = await _user(seeded)
    invited = await _invited(seeded, await _user(seeded, "bob@x.org"))
    active = await _active(seeded, ann)
    assert (ann.kind, ann.created_by, ann.email) == ("person", None, "ann@x.org")
    assert (invited.role, active.role) == ("admin", "admin")


@pytest.mark.parametrize("attempt", [
    pytest.param(lambda r, p, a: r.set_platform_admin(p.id, True), id="platform-admin-flag"),
    pytest.param(lambda r, p, a: r.ensure_invitation(p.id, T2, invited_by=None, now=NOW), id="invitation"),
    pytest.param(lambda r, p, a: r.add_membership(p.id, T2, status="active", invited_by=None, created_at=NOW,
                                                  accepted_at=NOW, role="admin"), id="admin-membership"),
    pytest.param(lambda r, p, a: r.add_membership(a.id, T2, status="active", invited_by=None, created_at=NOW,
                                                  accepted_at=NOW, role="automation"), id="person-automation"),
    pytest.param(lambda r, p, a: r.add_user(None, created_at=NOW), id="person-without-email"),
    pytest.param(lambda r, p, a: r.add_credential(a.id, kind="key", name="k", created_by=a.id, expires_at=EXPIRES,
                                                  now=NOW, key_hash=_key(9)), id="credential-of-a-person"),
    pytest.param(lambda r, p, a: r.add_credential(NO_SUCH_ROW, kind="key", name="k", created_by=a.id,
                                                  expires_at=EXPIRES, now=NOW, key_hash=_key(9)), id="credential-of-nobody"),
    pytest.param(lambda r, p, a: r.add_credential(p.id, kind="key", name="k", created_by=a.id, expires_at=EXPIRES,
                                                  now=NOW), id="key-without-hash"),
    pytest.param(lambda r, p, a: r.add_credential(p.id, kind="oauth_client", name="o", created_by=a.id,
                                                  expires_at=EXPIRES, now=NOW, key_hash=_key(9)), id="oauth-with-hash"),
    pytest.param(lambda r, p, a: r.add_credential(p.id, kind="password", name="x", created_by=a.id, expires_at=EXPIRES,
                                                  now=NOW, key_hash=_key(9)), id="unknown-kind"),
])
async def test_a_write_the_data_rules_forbid_is_refused_and_changes_nothing(seeded, attempt):
    """Program never admin / invited / platform admin; people never automation; a key iff its hash; credentials only for programs (W2, O3, O5)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    before = (await seeded.user(program.id), await seeded.user(admin.id), await seeded.memberships_of_user(program.id),
              await seeded.memberships_of_user(admin.id), await seeded.credentials_of_program(program.id))
    with pytest.raises(DataRuleViolation):
        await attempt(seeded, program, admin)
    after = (await seeded.user(program.id), await seeded.user(admin.id), await seeded.memberships_of_user(program.id),
             await seeded.memberships_of_user(admin.id), await seeded.credentials_of_program(program.id))
    assert after == before
    control = await _add_key(seeded, program, admin, 1)  # the same repository accepts the lawful write
    assert control.state == "live"


# --- people queries ignore programs (P-I) --------------------------------------------------------------

async def test_people_queries_see_only_people_and_program_queries_only_programs(seeded):
    """has-active-members, people_of_tenant: persons only; memberships_of_tenant: both; programs_of_tenant: active programs of that tenant (P-I)."""
    ann = await _user(seeded)
    ann_membership = await _active(seeded, ann)
    soar = await _program(seeded, ann)
    other_tenant = await _program(seeded, ann, tenant=T2, name="Elsewhere")
    assert await seeded.tenant_has_active_members(T1) is True
    assert [(m.id, u.id) for m, u in await seeded.people_of_tenant(T1, "active")] == [(ann_membership.id, ann.id)]
    assert {m.user_id for m in await seeded.memberships_of_tenant(T1)} == {ann.id, soar.id}
    assert [p.id for p in await seeded.programs_of_tenant(T1)] == [soar.id]
    assert [p.id for p in await seeded.programs_of_tenant(T2)] == [other_tenant.id]
    assert await seeded.end_membership(ann_membership.id, ended_by=ann.id, now=NOW) is True
    assert await seeded.tenant_has_active_members(T1) is False  # the program does not make a tenant "have members"
    assert await seeded.people_of_tenant(T1, "active") == []
    assert (await seeded.active_membership(soar.id, T1)) is not None  # still the program's own membership


# --- credentials -------------------------------------------------------------------------------------

async def test_a_credential_row_holds_what_the_design_lists_and_no_secret(seeded):
    """Key: live, hash kept, no deadline; OAuth: pending with a 10-minute deadline; both expire; copies are detached (O5, P-G)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    key = await _add_key(seeded, program, admin, 1)
    oauth = await _add_oauth(seeded, program, admin, 1)
    assert (key.program_id, key.kind, key.name, key.state, key.key_hash) == (program.id, "key", "k1", "live", _key(1))
    assert (key.created_by, key.created_at, key.expires_at, key.pending_deadline, key.last_used_at) == (admin.id, NOW, EXPIRES, None, None)
    assert (oauth.kind, oauth.state, oauth.key_hash, oauth.service_account_id) == ("oauth_client", "pending", None, None)
    assert oauth.pending_deadline == NOW + DEADLINE
    assert (oauth.revoked_at, oauth.revoked_by) == (None, None)
    key.name = "edited"
    assert (await seeded.credential_by_id(key.id)).name == "k1"
    assert {r.id for r in await seeded.credentials_of_program(program.id)} == {key.id, oauth.id}
    assert [r.id for r in await seeded.credentials_of_program((await _program(seeded, admin, name="Empty")).id)] == []


async def test_a_credential_is_found_by_its_hash_or_id_in_any_state(seeded):
    """Lookups by key hash and by id return the row (revoked included: its state decides use); unknown -> None (Keys, Audit)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    key = await _add_key(seeded, program, admin, 1)
    other = await _add_key(seeded, program, admin, 2)
    assert (await seeded.credential_by_hash(_key(1))).id == key.id
    assert (await seeded.credential_by_id(other.id)).key_hash == _key(2)
    assert await seeded.credential_by_hash(_key(3)) is None
    assert await seeded.credential_by_id(NO_SUCH_ROW) is None
    assert await seeded.revoke_credential(key.id, revoked_by=admin.id, now=NOW + HOUR) is True
    assert (await seeded.credential_by_hash(_key(1))).state == "revoked"
    assert (await seeded.credential_by_id(key.id)).state == "revoked"


@pytest.mark.parametrize("frees", ["revoked", "expired-at-the-instant", "pending-deadline-at-the-instant", "pending-revoked"])
async def test_at_most_two_credentials_are_usable_or_pending_within_their_deadline(seeded, frees):
    """The cap counts live-unexpired and in-deadline pending rows, computed from `now`, never from a purge (O5, cap)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    soon = NOW + 30 * DAY
    first = await _add_key(seeded, program, admin, 1, expires_at=soon)
    second = await _add_oauth(seeded, program, admin, 2)
    with pytest.raises(DataRuleViolation):  # control: both slots are held
        await _add_key(seeded, program, admin, 3)
    assert len(await seeded.credentials_of_program(program.id)) == 2
    now = NOW
    if frees == "revoked":
        assert await seeded.revoke_credential(first.id, revoked_by=admin.id, now=NOW) is True
    elif frees == "pending-revoked":
        assert await seeded.revoke_credential(second.id, revoked_by=admin.id, now=NOW) is True
    elif frees == "expired-at-the-instant":
        now = soon
        await seeded.revoke_credential(second.id, revoked_by=admin.id, now=NOW)  # keep one slot free of the pending row
        await _add_key(seeded, program, admin, 4, now=NOW)
        with pytest.raises(DataRuleViolation):
            await _add_key(seeded, program, admin, 5, now=soon - dt.timedelta(seconds=1))
    else:
        now = NOW + DEADLINE
        await seeded.revoke_credential(first.id, revoked_by=admin.id, now=NOW)
        await _add_key(seeded, program, admin, 4, now=NOW)
        with pytest.raises(DataRuleViolation):
            await _add_key(seeded, program, admin, 5, now=NOW + DEADLINE - dt.timedelta(seconds=1))
    third = await _add_key(seeded, program, admin, 6, now=now, expires_at=now + 90 * DAY)
    assert third.state == "live"
    if frees == "expired-at-the-instant":
        assert (await seeded.credential_by_id(first.id)).state == "live"  # expiry changes no state (W4)


async def test_the_cap_is_per_program(seeded):
    """Another program of the tenant has its own two slots (O5)."""
    admin = await _user(seeded)
    one, two = await _program(seeded, admin), await _program(seeded, admin, name="Second")
    await _add_key(seeded, one, admin, 1)
    await _add_key(seeded, one, admin, 2)
    assert (await _add_key(seeded, two, admin, 3)).state == "live"


async def test_pending_goes_live_once_and_records_the_service_account(seeded):
    """`go_live` is conditional on `pending`, before the deadline; it records the token's `sub` (Create step 4)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    row = await _add_oauth(seeded, program, admin, 1)
    assert await seeded.go_live(row.id, service_account_id=SA, now=NOW + DEADLINE - dt.timedelta(seconds=1)) is True
    live = await seeded.credential_by_id(row.id)
    assert (live.state, live.service_account_id) == ("live", SA)
    assert await seeded.go_live(row.id, service_account_id="other", now=NOW) is False
    assert (await seeded.credential_by_id(row.id)).service_account_id == SA
    key = await _add_key(seeded, program, admin, 2)
    assert await seeded.go_live(key.id, service_account_id=SA, now=NOW) is False  # a key is never pending
    assert await seeded.go_live(NO_SUCH_ROW, service_account_id=SA, now=NOW) is False


@pytest.mark.parametrize("how", ["revoked", "deadline", "membership-ended"])
async def test_pending_stays_pending_or_revoked_when_its_conditions_fail(seeded, how):
    """Not still pending, at/after its deadline, or the program's membership ended -> no `live` row (Create step 4, removal race)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    row = await _add_oauth(seeded, program, admin, 1)
    now = NOW
    if how == "revoked":
        assert await seeded.revoke_credential(row.id, revoked_by=admin.id, now=NOW) is True
    elif how == "deadline":
        now = NOW + DEADLINE
    else:
        membership = await seeded.active_membership(program.id, T1)
        assert await seeded.end_membership(membership.id, ended_by=admin.id, now=NOW) is True
    assert await seeded.go_live(row.id, service_account_id=SA, now=now) is False
    after = await seeded.credential_by_id(row.id)
    assert (after.state, after.service_account_id) == (("revoked" if how == "revoked" else "pending"), None)
    fine = await _add_oauth(seeded, (await _program(seeded, admin, name="Fine")), admin, 2)
    assert await seeded.go_live(fine.id, service_account_id=SA, now=NOW) is True  # control


async def test_no_credential_is_added_for_a_program_whose_membership_ended(seeded):
    """Insert requires the program's membership to be active (one lock per program)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    membership = await seeded.active_membership(program.id, T1)
    await seeded.end_membership(membership.id, ended_by=admin.id, now=NOW)
    with pytest.raises(DataRuleViolation):
        await _add_key(seeded, program, admin, 1)
    assert await seeded.credentials_of_program(program.id) == []


async def test_revoking_is_conditional_and_keeps_the_first_revocation(seeded):
    """Revoke applies to a live or pending row once; it records who and when (O5)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    row = await _add_key(seeded, program, admin, 1)
    later = NOW + HOUR
    assert await seeded.revoke_credential(row.id, revoked_by=admin.id, now=later) is True
    got = await seeded.credential_by_id(row.id)
    assert (got.state, got.revoked_at, got.revoked_by) == ("revoked", later, admin.id)
    assert await seeded.revoke_credential(row.id, revoked_by=None, now=later + HOUR) is False
    assert (await seeded.credential_by_id(row.id)).revoked_by == admin.id
    assert await seeded.revoke_credential(NO_SUCH_ROW, revoked_by=admin.id, now=NOW) is False


async def test_last_used_is_written_only_when_older_than_five_minutes(seeded):
    """Key check: a conditional update, at most one write per 5 minutes (Keys)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    row = await _add_key(seeded, program, admin, 1)
    first = NOW + dt.timedelta(seconds=30)
    assert await seeded.touch_credential(row.id, now=first) is True  # never used: written
    assert (await seeded.credential_by_id(row.id)).last_used_at == first
    assert await seeded.touch_credential(row.id, now=first + dt.timedelta(minutes=4, seconds=59)) is False
    assert (await seeded.credential_by_id(row.id)).last_used_at == first
    later = first + dt.timedelta(minutes=5, seconds=1)
    assert await seeded.touch_credential(row.id, now=later) is True
    assert (await seeded.credential_by_id(row.id)).last_used_at == later
    assert await seeded.touch_credential(NO_SUCH_ROW, now=later) is False


async def test_a_stale_pending_credential_is_revoked_by_the_system_and_nothing_else(seeded):
    """The purge revokes `pending` rows at or past their deadline, with no actor, and returns them (Reconciliation)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    stale = await _add_oauth(seeded, program, admin, 1)
    key = await _add_key(seeded, program, admin, 2)
    at = NOW + DEADLINE
    assert await seeded.revoke_stale_pending(now=at - dt.timedelta(seconds=1)) == []
    assert await seeded.revoke_stale_pending(now=at) == [stale.id]
    got = await seeded.credential_by_id(stale.id)
    assert (got.state, got.revoked_at, got.revoked_by) == ("revoked", at, None)
    assert (await seeded.credential_by_id(key.id)).state == "live"
    assert await seeded.revoke_stale_pending(now=at + HOUR) == []
    other = await _add_oauth(seeded, program, admin, 3, now=at)
    await seeded.go_live(other.id, service_account_id=SA, now=at)
    assert await seeded.revoke_stale_pending(now=at + 2 * HOUR) == []  # a live OAuth row is not pending


# --- removal is one write -----------------------------------------------------------------------------

async def test_removing_a_program_ends_its_membership_and_revokes_every_credential(seeded):
    """One write: membership ended (who, when) and live and pending credentials revoked; the user row, an earlier
    revocation, other programs and people stay as they were (O6)."""
    admin = await _user(seeded)
    member = await _active(seeded, admin)
    program = await _program(seeded, admin)
    other = await _program(seeded, admin, name="Other")
    old, pending = await _add_key(seeded, program, admin, 1), await _add_oauth(seeded, program, admin, 2)
    await seeded.revoke_credential(old.id, revoked_by=admin.id, now=NOW)
    live = await _add_key(seeded, program, admin, 3, now=NOW)
    kept = await _add_key(seeded, other, admin, 4)
    later = NOW + HOUR
    assert await seeded.remove_program(program.id, removed_by=admin.id, now=later) is True
    assert await seeded.active_membership(program.id, T1) is None
    [membership] = await seeded.memberships_of_user(program.id)
    assert (membership.status, membership.ended_at, membership.ended_by) == ("ended", later, admin.id)
    states = {r.id: (r.state, r.revoked_at, r.revoked_by) for r in await seeded.credentials_of_program(program.id)}
    assert states == {old.id: ("revoked", NOW, admin.id), live.id: ("revoked", later, admin.id),
                      pending.id: ("revoked", later, admin.id)}
    assert (await seeded.user(program.id)).kind == "program"  # the row stays: the audit names it
    assert (await seeded.credential_by_id(kept.id)).state == "live"
    assert (await seeded.active_membership(other.id, T1)) is not None
    assert (await seeded.active_membership(admin.id, T1)).id == member.id
    assert await seeded.programs_of_tenant(T1) == [await seeded.user(other.id)]
    assert await seeded.remove_program(program.id, removed_by=admin.id, now=later + HOUR) is False
    assert (await seeded.memberships_of_user(program.id))[0].ended_at == later


@pytest.mark.postgres
@pytest.mark.parametrize("first", ["remove", "create"])
async def test_a_removal_and_a_credential_creation_for_one_program_are_ordered_by_the_program_lock(
        two_repositories, pg_dsn, first):
    """Both wait on the program's user row; whichever goes first, no usable or pending credential survives the removal (one lock per program)."""
    one, two = two_repositories
    admin = await _user(one)
    program = await _program(one, admin)
    operations = {"remove": lambda: one.remove_program(program.id, removed_by=admin.id, now=NOW),
                  "create": lambda: _add_oauth(two, program, admin, 1)}
    order = [first, "create" if first == "remove" else "remove"]
    async with holding_row(pg_dsn, "users", program.id):
        tasks = {}
        for count, name in enumerate(order, start=1):
            tasks[name] = asyncio.ensure_future(operations[name]())
            await until_blocked(pg_dsn, count)
        assert not any(t.done() for t in tasks.values())
    results = await asyncio.gather(*(asyncio.wait_for(t, TIMEOUT) for t in tasks.values()), return_exceptions=True)
    outcome = dict(zip(tasks, results, strict=True))
    assert outcome["remove"] is True
    if first == "create":
        assert outcome["create"].state == "pending"
    else:
        assert isinstance(outcome["create"], DataRuleViolation), outcome["create"]
    assert await one.active_membership(program.id, T1) is None
    assert {r.state for r in await one.credentials_of_program(program.id)} <= {"revoked"}
