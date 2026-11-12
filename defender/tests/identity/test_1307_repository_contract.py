# ruff: noqa: F811  — the #1306 contract's fixtures are imported, as in test_1214_atk1_repository.py
"""#1307 IdentityRepository contract for programs and their credentials, memory and PostgreSQL (P-I, P-G, O4, O5).

#1454 amends this contract: a program is a `programs` row, not a users row with a membership (P-J). Its row is read as
`id, tenant_id, display_name, created_by, created_at, removed_at (None while active), removed_by`; `program(id)`
answers at any status; one admitting read per use (`admit_by_key`, `admit_by_client`, `admit_by_credential`) replaces
`credential_by_hash` and `program_standing`; `revoke_stale_pending` answers `(credential id, tenant)` pairs; a write that makes
something live in a tenant (`add_program`, `ensure_invitation`) raises `TenantNotActive` unless the tenant is `active`.

Forced choices (FC-7, extending the support module's list; the design names no repository method):
`add_program(tenant_id, *, display_name, created_by, now) -> Program`;
`add_membership(..., role="admin")` (the seeder takes the role; people default `admin`);
`add_credential(program_id, *, kind, name, created_by, expires_at, now, key_hash=None) -> row` (keys `live`; OAuth
`pending` with `pending_deadline = now + 10 min`; None, writing nothing, for a removed program; over the cap, for a non-program, or
a key without its hash / an OAuth client with one -> `DataRuleViolation`, the cap as its subclass `CredentialCapReached`);
`go_live(credential_id, *, service_account_id, now) -> bool`; `revoke_credential(credential_id, *, revoked_by, now) -> bool`;
`credentials_of_program(program_id)`; `credential_by_id(id)` / `credential_by_hash(key_hash)` -> row or None (any state);
`programs_of_tenant(tenant_id) -> list[User]` (active programs); `remove_program(program_id, *, removed_by, now) -> list[credential id] | None`
(one write: membership ended and every credential revoked; the ids it revoked, oldest first, or None when nothing was
removed); `touch_credential(id, *, now) -> bool` (as `touch_session`);
`revoke_stale_pending(*, now) -> list[credential id]`.
Expiry-warning outbox (F7, one claimable send per (credential, threshold), thresholds 14 and 3 days):
`claim_expiry_warning(*, now, hold_until) -> ExpiryWarning | None` (`.credential_id`, `.threshold`: a `timedelta`) takes a
usable credential whose `expires_at - threshold <= now`, whose threshold was not passed when it was created
(`expires_at - threshold > created_at`: one falling at the very moment of creation has passed) and is unsettled and not held; it returns the TIGHTEST such threshold and
settles the looser due ones unsent (W6); it moves the send's next try to `hold_until` (Postgres: `FOR UPDATE SKIP LOCKED`);
`settle_expiry_warning(credential_id, threshold) -> bool` (once); `defer_expiry_warning(credential_id,
threshold, *, until)` (a failed send's retry); `warning_deliveries(credential_id, threshold) -> set[user id]` and
`record_warning_delivery(credential_id, threshold, person_id, *, sent_at)` (who a send has reached, so a retry mails
only the rest; #1450 review). Reconciliation's keep-set read:
`oauth_credentials_to_keep(*, now) -> set[credential id]` (OAuth rows `live` with `expires_at > now`, or `pending` with
`pending_deadline > now`; never keys, never revoked). The claim and the keep-set count only a credential whose program is
in standing (#1450 review; #1454 O-D). Rows carry the design's fields (`state`, `kind`, `key_hash`,
`service_account_id`, `pending_deadline`, `last_used_at`, `revoked_at`, `revoked_by`, ...).
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import hashlib

import pytest

from defender.identity import DataRuleViolation
from defender.records.formats import TenantId, UserId
from defender.tests.identity.test_identity_repository_contract import (  # noqa: F401  (fixtures)
    HOUR,
    NO_SUCH_ROW,
    NO_SUCH_USER,
    NOW,
    T1,
    T2,
    T_UNREGISTERED,
    _active,
    _invited,
    _seed_tenant,
    _user,
    backend,
    pg_dsn,
    repo,
    seeded,
    tenants,
    two_repositories,
)
from defender.tests.support.identity._tenant_states1454 import NOT_ACTIVE, leave_active
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._pglocks1339 import TIMEOUT, blocked, holding_row, until, until_blocked

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


# --- the program row (P-J, P-K) ----------------------------------------------------------------------

def _as_user(program) -> UserId:
    """A program's id read as a user id: what a caller would pass if it confused the two kinds."""
    return UserId(str(program.id))


async def test_a_program_is_a_row_of_its_tenant_with_its_creator_and_no_users_row(seeded):
    """A program holds its tenant, name, creator and no removal time (active); no users row or membership exists for it (P-J, P-K, O-B)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    assert (program.tenant_id, program.display_name, program.removed_at) == (T1, "SOAR prod", None)
    assert (program.created_by, program.created_at, program.removed_at, program.removed_by) == (admin.id, NOW, None, None)
    assert await seeded.program(program.id) == program
    assert await seeded.user(_as_user(program)) is None
    assert await seeded.memberships_of_user(_as_user(program)) == []
    second = await _program(seeded, admin, name="Another")  # control: two programs, each its own row
    assert second.id != program.id
    assert await seeded.program(UserId(fixture_uuid("program:nobody"))) is None


async def test_a_person_has_an_admin_membership_and_no_kind(seeded):
    """Control for the program row: people carry a required email, `admin` memberships and no `kind` or creator (O-B, R1)."""
    ann = await _user(seeded)
    invited = await _invited(seeded, await _user(seeded, "bob@x.org"))
    active = await _active(seeded, ann)
    assert ann.email == "ann@x.org"
    assert (hasattr(ann, "kind"), hasattr(ann, "created_by")) == (False, False)
    assert (invited.role, active.role) == ("admin", "admin")


@pytest.mark.parametrize("attempt", [
    pytest.param(lambda r, p, a: r.ensure_invitation(_as_user(p), T2, invited_by=None, now=NOW), id="invitation-of-a-program"),
    pytest.param(lambda r, p, a: r.add_membership(_as_user(p), T2, status="active", invited_by=None, created_at=NOW,
                                                  accepted_at=NOW, role="admin"), id="membership-of-a-program"),
    pytest.param(lambda r, p, a: r.add_membership(a.id, T2, status="active", invited_by=None, created_at=NOW,
                                                  accepted_at=NOW, role="automation"), id="person-automation"),
    pytest.param(lambda r, p, a: r.add_user(None, created_at=NOW), id="person-without-email"),
    pytest.param(lambda r, p, a: r.add_program(T1, display_name="By nobody", created_by=NO_SUCH_USER, now=NOW),
                 id="program-by-nobody"),
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
    """A program is never invited or a member; people never `automation`, never without email; a key iff its hash; credentials only for programs (O-B, R1)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)

    async def snapshot():
        return (await seeded.user(admin.id), await seeded.memberships_of_user(admin.id), await seeded.memberships_of_tenant(T2),
                await seeded.programs_of_tenant(T1), await seeded.credentials_of_program(program.id))

    before = await snapshot()
    with pytest.raises(DataRuleViolation):
        await attempt(seeded, program, admin)
    assert await snapshot() == before
    control = await _add_key(seeded, program, admin, 1)  # the same repository accepts the lawful write
    assert control.state == "live"


async def test_a_program_cannot_be_made_platform_admin_because_it_is_no_user(seeded):
    """Setting the flag on a program's id changes no row and creates none; on a person it applies (O-B)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    before = (await seeded.programs_of_tenant(T1), await seeded.user(admin.id))
    await seeded.set_platform_admin(_as_user(program), True)
    assert await seeded.user(_as_user(program)) is None
    assert (await seeded.programs_of_tenant(T1), await seeded.user(admin.id)) == before
    await seeded.set_platform_admin(admin.id, True)  # control: a person takes it
    assert (await seeded.user(admin.id)).is_platform_admin is True


# --- people queries hold only people (O-B) ----------------------------------------------------------------

async def test_the_people_reads_hold_only_people_and_the_program_reads_only_active_programs_of_the_tenant(seeded):
    """After programs exist, member count, members list and rescue read answer people only; `programs_of_tenant` lists the tenant's active programs (O-B, O-E)."""
    ann = await _user(seeded)
    ann_membership = await _active(seeded, ann)
    soar = await _program(seeded, ann)
    other_tenant = await _program(seeded, ann, tenant=T2, name="Elsewhere")
    gone = await _program(seeded, ann, name="Gone")
    assert await seeded.remove_program(gone.id, removed_by=ann.id, now=NOW) is not None
    assert await seeded.tenant_has_active_members(T1) is True
    assert [(m.id, u.id) for m, u in await seeded.people_of_tenant(T1, "active")] == [(ann_membership.id, ann.id)]
    assert [m.id for m in await seeded.memberships_of_tenant(T1)] == [ann_membership.id]
    assert await seeded.memberships_of_tenant(T2) == []
    assert [p.id for p in await seeded.programs_of_tenant(T1)] == [soar.id]
    assert [p.id for p in await seeded.programs_of_tenant(T2)] == [other_tenant.id]
    assert await seeded.end_membership(ann_membership.id, ended_by=ann.id, now=NOW) is True
    assert await seeded.tenant_has_active_members(T1) is False  # the program does not make a tenant "have members"
    assert await seeded.people_of_tenant(T1, "active") == []
    assert [p.id for p in await seeded.programs_of_tenant(T1)] == [soar.id]  # control: the program is still there


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


async def test_a_credential_is_found_by_its_id_in_any_state_and_admitted_by_its_hash_while_usable(seeded):
    """The id lookup returns the row revoked or not; the key hash admits it while usable and not once revoked; unknown -> None (Keys, O-C)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    key = await _add_key(seeded, program, admin, 1)
    other = await _add_key(seeded, program, admin, 2)
    assert (await seeded.admit_by_key(_key(1), now=NOW))[0].id == key.id
    assert (await seeded.credential_by_id(other.id)).key_hash == _key(2)
    assert await seeded.admit_by_key(_key(3), now=NOW) is None
    assert await seeded.credential_by_id(NO_SUCH_ROW) is None
    assert await seeded.revoke_credential(key.id, revoked_by=admin.id, now=NOW + HOUR) is True
    assert await seeded.admit_by_key(_key(1), now=NOW + HOUR) is None
    assert (await seeded.credential_by_id(key.id)).state == "revoked"
    assert (await seeded.admit_by_key(_key(2), now=NOW + HOUR))[0].id == other.id  # control: the sibling still admits


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


@pytest.mark.parametrize("how", ["revoked", "deadline", "program-removed"])
async def test_pending_stays_pending_or_revoked_when_its_conditions_fail(seeded, how):
    """Not still pending, at/after its deadline, or the program removed (which revokes it) -> no `live` row (Create step 4, O-E)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    row = await _add_oauth(seeded, program, admin, 1)
    now = NOW
    if how == "revoked":
        assert await seeded.revoke_credential(row.id, revoked_by=admin.id, now=NOW) is True
    elif how == "deadline":
        now = NOW + DEADLINE
    else:
        assert await seeded.remove_program(program.id, removed_by=admin.id, now=NOW) == [row.id]
    assert await seeded.go_live(row.id, service_account_id=SA, now=now) is False
    after = await seeded.credential_by_id(row.id)
    assert (after.state, after.service_account_id) == (("pending" if how == "deadline" else "revoked"), None)
    fine = await _add_oauth(seeded, (await _program(seeded, admin, name="Fine")), admin, 2)
    assert await seeded.go_live(fine.id, service_account_id=SA, now=NOW) is True  # control


async def test_no_credential_is_added_for_a_removed_program(seeded):
    """Insert requires the program `active` (one lock per program); a removed one answers None and nothing is written
    (#1450 review: removed is an answer, so the service can say 404); a sibling program takes one (O-E)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    assert await seeded.remove_program(program.id, removed_by=admin.id, now=NOW) is not None
    assert await _add_key(seeded, program, admin, 1) is None
    assert await _add_oauth(seeded, program, admin, 2) is None
    assert await seeded.credentials_of_program(program.id) == []
    assert (await _add_key(seeded, await _program(seeded, admin, name="Sibling"), admin, 3)).state == "live"  # control


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


async def test_a_stale_pending_credential_is_revoked_by_the_system_and_answered_with_its_tenant(seeded):
    """The purge revokes `pending` rows at or past their deadline, with no actor, and answers each with its program's tenant (O-F)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    elsewhere = await _program(seeded, admin, tenant=T2, name="Elsewhere")
    stale = await _add_oauth(seeded, program, admin, 1)
    stale_elsewhere = await _add_oauth(seeded, elsewhere, admin, 5)
    key = await _add_key(seeded, program, admin, 2)
    at = NOW + DEADLINE
    assert await seeded.revoke_stale_pending(now=at - dt.timedelta(seconds=1)) == []
    assert sorted(await seeded.revoke_stale_pending(now=at)) == sorted([(stale.id, T1), (stale_elsewhere.id, T2)])
    got = await seeded.credential_by_id(stale.id)
    assert (got.state, got.revoked_at, got.revoked_by) == ("revoked", at, None)
    assert (await seeded.credential_by_id(key.id)).state == "live"
    assert await seeded.revoke_stale_pending(now=at + HOUR) == []
    other = await _add_oauth(seeded, program, admin, 3, now=at)
    await seeded.go_live(other.id, service_account_id=SA, now=at)
    assert await seeded.revoke_stale_pending(now=at + 2 * HOUR) == []  # a live OAuth row is not pending


async def test_the_tenant_of_each_credential_is_read_in_one_call_whatever_its_program_has_become(seeded, backend, tenants):
    """Each id of ours maps to its program's tenant, also once the program is removed or its tenant left `active`; an id that is none is left out (O-F)."""
    admin = await _user(seeded)
    mine = await _program(seeded, admin, name="Mine")
    elsewhere = await _program(seeded, admin, tenant=T2, name="Elsewhere")
    removed = await _program(seeded, admin, name="Removed")
    key = await _add_key(seeded, mine, admin, 1)
    oauth = await _add_oauth(seeded, elsewhere, admin, 2)
    gone = await _add_key(seeded, removed, admin, 3)
    assert await seeded.remove_program(removed.id, removed_by=admin.id, now=NOW) is not None
    assert dict(await seeded.tenants_of_credentials([key.id, oauth.id, gone.id, NO_SUCH_ROW])) == {
        key.id: T1, oauth.id: T2, gone.id: T1}
    assert dict(await seeded.tenants_of_credentials([])) == {}
    assert dict(await seeded.tenants_of_credentials([NO_SUCH_ROW])) == {}
    await leave_active(backend, tenants, T2, "offboarded")
    assert dict(await seeded.tenants_of_credentials([key.id, oauth.id])) == {key.id: T1, oauth.id: T2}


# --- the schema, not a recheck, keeps a credential from authenticating a person (P-J) ------------------------------------------

@pytest.mark.parametrize("owner", ["person", "program"])
async def test_a_credential_belongs_to_a_program_and_never_to_a_person(seeded, backend, owner):
    """A credential row names a `programs` row: a program's is stored; a person's id is refused (PostgreSQL: by the foreign key,
    whatever wrote the row; memory: `DataRuleViolation`) (P-J, O-B)."""
    import uuid

    admin = await _user(seeded)
    program = await _program(seeded, admin)
    holder = program if owner == "program" else admin
    if backend is None:
        if owner == "program":
            assert (await _add_key(seeded, holder, admin, 1)).state == "live"
        else:
            with pytest.raises(DataRuleViolation):
                await _add_key(seeded, holder, admin, 1)
        return
    import psycopg
    from defender.tests.support.shared._postgres1339 import execute

    insert = """INSERT INTO identity.program_credentials (id, program_id, kind, name, state, key_hash, created_by,
                created_at, expires_at) VALUES (%s, %s, 'key', 'raw', 'live', %s, %s, %s, %s)"""  # noqa: S608
    params = (str(uuid.uuid4()), holder.id, _key(1), admin.id, NOW, EXPIRES)
    if owner == "program":
        execute(backend, insert, params)
        assert [r.name for r in await seeded.credentials_of_program(program.id)] == ["raw"]
    else:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            execute(backend, insert, params)
        assert await seeded.credentials_of_program(admin.id) == []


# --- names Postgres text cannot hold are refused by the repository (A2) --------------------------------------------------------

#: What PostgreSQL text cannot hold, embedded in otherwise valid names so that blankness is never the reason for a refusal.
UNHOLDABLE = [f"{head}{bad}{tail}" for bad in ("\x00", "\ud800", "\udbff", "\udc00", "\udfff") for head, tail in (("", ""), ("a", ""), ("", "b"), ("a", "b"))]
HOLDABLE = ["SOAR prod", "Zoë", "\U0001f600 emoji"]


async def test_a_name_that_postgres_text_cannot_hold_is_refused_for_programs_and_credentials(seeded):
    """NUL and lone surrogates in a program's display name or a credential's name -> `DataRuleViolation`, nothing stored; names
    without them (an astral character, accents) are stored (A2). The oracle is the one the emails and request ids already use."""
    from defender._text import postgres_can_hold

    assert not any(postgres_can_hold(n) for n in UNHOLDABLE)
    assert all(postgres_can_hold(n) for n in HOLDABLE)
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    for name in UNHOLDABLE:
        with pytest.raises(DataRuleViolation):
            await _program(seeded, admin, name=name)
        with pytest.raises(DataRuleViolation):
            await seeded.add_credential(program.id, kind="key", name=name, created_by=admin.id, expires_at=EXPIRES, now=NOW,
                                        key_hash=_key(1))
        with pytest.raises(DataRuleViolation):
            await seeded.add_credential(program.id, kind="oauth_client", name=name, created_by=admin.id, expires_at=EXPIRES, now=NOW)
    assert [p.id for p in await seeded.programs_of_tenant(T1)] == [program.id]
    assert await seeded.credentials_of_program(program.id) == []
    for name in HOLDABLE:  # control: the same calls with holdable names
        assert (await _program(seeded, admin, name=name)).display_name == name
    assert (await seeded.add_credential(program.id, kind="key", name=HOLDABLE[1], created_by=admin.id, expires_at=EXPIRES, now=NOW,
                                        key_hash=_key(2))).name == HOLDABLE[1]


# --- one rule for "usable" (O5, W4) -------------------------------------------------------------------------------------

EVAL = NOW + 30 * DAY
AROUND = (-dt.timedelta(seconds=1), dt.timedelta(0), dt.timedelta(seconds=1))


def _usable(row, now) -> bool:
    """The one rule, written once for this test: `live` and not yet expired. Expiry is computed, never a state (W4)."""
    return row.state == "live" and row.expires_at > now


def _holds_a_slot(row, now) -> bool:
    """Counts toward the cap and keeps a realm client: usable, or `pending` and still before its deadline."""
    return _usable(row, now) or (row.state == "pending" and row.pending_deadline is not None and row.pending_deadline > now)


async def _shape(repo, admin, n, kind, state, expiry, deadline):
    """A program holding one filler key (a live credential far from expiry) and one row of this shape at the instant `EVAL`:
    `expiry` and `deadline` are offsets of the row's expiry and (for an OAuth row) its deadline from `EVAL`."""
    program = await _program(repo, admin, name=f"{kind}-{state}-{expiry}-{deadline}-{n}")
    await repo.add_credential(program.id, kind="key", name="filler", created_by=admin.id, expires_at=EVAL + 90 * DAY,
                              now=NOW, key_hash=_key(1000 + n))
    expires_at = EVAL + expiry
    if kind == "key":
        row = await repo.add_credential(program.id, kind="key", name="subject", created_by=admin.id, expires_at=expires_at,
                                        now=NOW, key_hash=_key(n))
        created = NOW
    else:
        created = EVAL - DEADLINE + deadline  # the row's deadline is `created + 10 minutes`: `EVAL + deadline`
        row = await repo.add_credential(program.id, kind="oauth_client", name="subject", created_by=admin.id,
                                        expires_at=expires_at, now=created)
        if state in ("live",):
            assert await repo.go_live(row.id, service_account_id=SA, now=created) is True
    if state == "revoked":
        assert await repo.revoke_credential(row.id, revoked_by=admin.id, now=created) is True
    return program


async def test_one_usable_rule_decides_the_cap_the_keep_set_and_the_purge(seeded):
    """Over keys and OAuth credentials, `pending`, `live` and `revoked`, with expiry and deadline just before, at and just after the
    instant asked about: the per-program cap, `oauth_credentials_to_keep` and `revoke_stale_pending` all agree with one rule, written
    once here (usable = `live` and `expires_at > now`; a slot is held by a usable row or a `pending` row with `pending_deadline >
    now`). A purge revokes exactly the `pending` rows at or past their deadline and changes no other field of any row: a live row
    past its expiry stays `live` with no `revoked_at`, because expiry is computed, never written (O5, W4)."""
    admin = await _user(seeded)
    shapes = [("key", state, e, None) for state in ("live", "revoked") for e in AROUND]
    shapes += [("oauth_client", "pending", e, d) for e in AROUND for d in AROUND]
    shapes += [("oauth_client", "live", e, d) for e in AROUND for d in AROUND]
    shapes += [("oauth_client", "revoked", e, AROUND[0]) for e in AROUND]
    programs = [await _shape(seeded, admin, n, *shape) for n, shape in enumerate(shapes)]
    rows = [r for p in programs for r in await seeded.credentials_of_program(p.id)]

    keep = {r.id for r in rows if r.kind == "oauth_client" and _holds_a_slot(r, EVAL)}
    assert keep  # control: both outcomes occur
    assert keep != {r.id for r in rows if r.kind == "oauth_client"}
    assert await seeded.oauth_credentials_to_keep(now=EVAL) == keep

    refused = []
    for n, program in enumerate(programs):  # the cap: a third credential is refused iff two slots are held
        held = sum(_holds_a_slot(r, EVAL) for r in await seeded.credentials_of_program(program.id))
        try:
            await seeded.add_credential(program.id, kind="key", name="third", created_by=admin.id, expires_at=EVAL + 90 * DAY,
                                        now=EVAL, key_hash=_key(2000 + n))
            accepted = True
        except DataRuleViolation:
            accepted = False
        if accepted != (held < 2):
            refused.append((program.display_name, held, accepted))
    assert refused == []
    assert {_holds_a_slot(r, EVAL) for p in programs for r in await seeded.credentials_of_program(p.id)} == {True, False}

    before = {r.id: r for p in programs for r in await seeded.credentials_of_program(p.id)}
    stale = {r.id for r in before.values() if r.state == "pending" and r.pending_deadline <= EVAL}
    assert stale  # control: some pending rows are stale, some are not
    assert stale != {r.id for r in before.values() if r.state == "pending"}
    assert set(await seeded.revoke_stale_pending(now=EVAL)) == {(i, T1) for i in stale}  # every program is T1's
    for p in programs:
        for after in await seeded.credentials_of_program(p.id):
            was = before[after.id]
            expected = dataclasses.replace(was, state="revoked", revoked_at=EVAL, revoked_by=None) if was.id in stale else was
            assert after == expected, (p.display_name, was, after)
    assert await seeded.oauth_credentials_to_keep(now=EVAL) == keep  # the purge changed nothing the rule counts
    assert await seeded.revoke_stale_pending(now=EVAL) == []


# --- removal is one write -----------------------------------------------------------------------------

async def test_removing_a_program_marks_it_removed_and_revokes_every_credential(seeded):
    """One write: the removal time and who removed it, live and pending credentials revoked; an earlier revocation, other
    programs and people stay as they were; a second removal changes nothing (O-E)."""
    admin = await _user(seeded)
    member = await _active(seeded, admin)
    program = await _program(seeded, admin)
    other = await _program(seeded, admin, name="Other")
    old, pending = await _add_key(seeded, program, admin, 1), await _add_oauth(seeded, program, admin, 2)
    await seeded.revoke_credential(old.id, revoked_by=admin.id, now=NOW)
    live = await _add_key(seeded, program, admin, 3, now=NOW)
    kept = await _add_key(seeded, other, admin, 4)
    later = NOW + HOUR
    assert await seeded.remove_program(program.id, removed_by=admin.id, now=later) is not None
    removed = await seeded.program(program.id)  # the row stays: the audit names it
    assert (removed.removed_at, removed.removed_by) == (later, admin.id)
    assert (removed.tenant_id, removed.display_name, removed.created_by) == (T1, "SOAR prod", admin.id)
    states = {r.id: (r.state, r.revoked_at, r.revoked_by) for r in await seeded.credentials_of_program(program.id)}
    assert states == {old.id: ("revoked", NOW, admin.id), live.id: ("revoked", later, admin.id),
                      pending.id: ("revoked", later, admin.id)}
    assert (await seeded.credential_by_id(kept.id)).state == "live"
    assert (await seeded.program(other.id)).removed_at is None
    assert [m.id for m in await seeded.memberships_of_tenant(T1)] == [member.id]
    assert [p.id for p in await seeded.programs_of_tenant(T1)] == [other.id]
    assert await seeded.remove_program(program.id, removed_by=None, now=later + HOUR) is None
    again = await seeded.program(program.id)
    assert (again.removed_at, again.removed_by) == (later, admin.id)


async def test_the_system_removes_a_program_of_a_tenant_that_has_left_active(seeded, backend, tenants):
    """Offboarding reads the tenant's active programs and removes them after the tenant left `active`: both still work, `removed_by` is none (O-E)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    key = await _add_key(seeded, program, admin, 1)
    await leave_active(backend, tenants, T1, "offboarding")
    assert [p.id for p in await seeded.programs_of_tenant(T1)] == [program.id]
    assert await seeded.remove_program(program.id, removed_by=None, now=NOW + HOUR) == [key.id]
    removed = await seeded.program(program.id)
    assert (removed.removed_at, removed.removed_by) == (NOW + HOUR, None)
    assert (await seeded.credential_by_id(key.id)).revoked_by is None
    assert await seeded.programs_of_tenant(T1) == []


async def test_removing_a_program_answers_the_credentials_it_revoked_and_no_others(seeded):
    """The removal names what it revoked, read inside its own write: the live and pending ones; not
    one already revoked, not another program's (O8; #1450 review: the audit takes this list, never a read before)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    other = await _program(seeded, admin, name="Other")
    revoked_before = await _add_key(seeded, program, admin, 1)
    await seeded.revoke_credential(revoked_before.id, revoked_by=admin.id, now=NOW)
    live = await _add_key(seeded, program, admin, 2)
    pending = await _add_oauth(seeded, program, admin, 3)
    await _add_key(seeded, other, admin, 4)
    revoked = await seeded.remove_program(program.id, removed_by=admin.id, now=NOW + HOUR)
    assert sorted(revoked) == sorted([live.id, pending.id])  # same `created_at`: their order is by id
    assert await seeded.remove_program(program.id, removed_by=admin.id, now=NOW + HOUR) is None


@pytest.mark.postgres
@pytest.mark.parametrize("first", ["remove", "create"])
async def test_a_removal_and_a_credential_creation_for_one_program_are_ordered_by_the_program_lock(
        two_repositories, pg_dsn, first):
    """Both wait on the program's own row; whichever goes first, no usable or pending credential survives the removal (one lock per program, O-E)."""
    one, two = two_repositories
    admin = await _user(one)
    program = await _program(one, admin)
    operations = {"remove": lambda: one.remove_program(program.id, removed_by=admin.id, now=NOW),
                  "create": lambda: _add_oauth(two, program, admin, 1)}
    order = [first, "create" if first == "remove" else "remove"]
    async with holding_row(pg_dsn, "programs", program.id):
        tasks = {}
        for count, name in enumerate(order, start=1):
            tasks[name] = asyncio.ensure_future(operations[name]())
            await until_blocked(pg_dsn, count)
        assert not any(t.done() for t in tasks.values())
    results = await asyncio.gather(*(asyncio.wait_for(t, TIMEOUT) for t in tasks.values()), return_exceptions=True)
    outcome = dict(zip(tasks, results, strict=True))
    assert outcome["remove"] is not None
    if first == "create":
        assert outcome["create"].state == "pending"
    else:
        assert outcome["create"] is None, outcome["create"]  # removed: an answer, not a refusal
    assert (await one.program(program.id)).removed_at == NOW
    assert {r.state for r in await one.credentials_of_program(program.id)} <= {"revoked"}


# --- expiry-warning outbox (O7, D5, W6) ------------------------------------------------------------------

HOLD = dt.timedelta(minutes=5)
FOURTEEN, THREE = 14 * DAY, 3 * DAY


def _claim_warning(repo, now):
    return repo.claim_expiry_warning(now=now, hold_until=now + HOLD)


async def _timed_key(repo, program, admin, n, lifetime):
    return await _add_key(repo, program, admin, n, expires_at=NOW + lifetime)


async def test_each_threshold_is_claimed_once_when_due_held_while_claimed_and_retried_when_deferred(seeded):
    """Not due before 14 days out; then one claim per (credential, threshold): held while claimed, back after the hold
    or a deferral, gone once settled; the 3-day one follows (O7, D5)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    key = await _timed_key(seeded, program, admin, 1, 30 * DAY)
    due14 = key.expires_at - FOURTEEN
    assert await _claim_warning(seeded, due14 - dt.timedelta(seconds=1)) is None
    claimed = await _claim_warning(seeded, due14)
    assert (claimed.credential_id, claimed.threshold) == (key.id, FOURTEEN)
    assert await _claim_warning(seeded, due14 + HOLD / 2) is None  # held by the claim
    assert (await _claim_warning(seeded, due14 + HOLD)).threshold == FOURTEEN  # the holder died: at least once
    assert await seeded.defer_expiry_warning(key.id, FOURTEEN, until=due14 + 2 * HOUR) is None
    assert await _claim_warning(seeded, due14 + HOUR) is None
    assert (await _claim_warning(seeded, due14 + 2 * HOUR)).threshold == FOURTEEN
    assert await seeded.settle_expiry_warning(key.id, FOURTEEN) is True
    assert await seeded.settle_expiry_warning(key.id, FOURTEEN) is False  # once
    assert await _claim_warning(seeded, key.expires_at - FOURTEEN + 6 * DAY) is None  # 14-day done, 3-day not yet due
    due3 = key.expires_at - THREE
    third = await _claim_warning(seeded, due3)
    assert (third.credential_id, third.threshold) == (key.id, THREE)
    assert await seeded.settle_expiry_warning(key.id, THREE) is True
    assert await _claim_warning(seeded, key.expires_at - dt.timedelta(minutes=1)) is None


@pytest.mark.parametrize(("lifetime_days", "first_claim"), [(20, FOURTEEN), (15, FOURTEEN), (14, THREE), (10, THREE), (7, THREE)])
async def test_a_threshold_passed_when_the_credential_was_created_is_never_claimed(seeded, lifetime_days, first_claim):
    """Created with 14, 10 or 7 days left: only the 3-day send exists (a threshold falling at the very moment of creation
    has passed: no warning about a credential just made); with 15 or 20: the 14-day one first (D5, D11; #1450 review)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    key = await _timed_key(seeded, program, admin, 1, lifetime_days * DAY)
    assert await _claim_warning(seeded, NOW) is None
    claimed = await _claim_warning(seeded, key.expires_at - first_claim)
    assert claimed.threshold == first_claim
    await seeded.settle_expiry_warning(key.id, first_claim)
    if first_claim == FOURTEEN:
        assert (await _claim_warning(seeded, key.expires_at - THREE)).threshold == THREE
    else:
        assert await _claim_warning(seeded, key.expires_at - THREE + HOUR) is None  # no 14-day send is left over


async def test_a_claim_after_both_thresholds_passed_takes_only_the_tightest_and_the_looser_never_returns(seeded):
    """First claim 2 days before expiry: the 3-day send only; the 14-day one is settled unsent, never claimed later (W6)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    key = await _timed_key(seeded, program, admin, 1, 60 * DAY)
    late = key.expires_at - 2 * DAY
    claimed = await _claim_warning(seeded, late)
    assert (claimed.credential_id, claimed.threshold) == (key.id, THREE)
    assert await _claim_warning(seeded, late) is None  # held; and no 14-day send is waiting behind it
    assert await seeded.settle_expiry_warning(key.id, THREE) is True
    assert await _claim_warning(seeded, late + HOUR) is None  # the passed 14-day threshold never comes back


async def test_the_earliest_due_warning_is_claimed_first_and_one_claim_takes_one_credential(seeded):
    """Three credentials due at once: three claims, earliest due first, each a different credential; a fourth finds
    nothing (O7; one row per claim, #1450 review)."""
    admin = await _user(seeded)
    keys = [await _timed_key(seeded, await _program(seeded, admin, name=f"P{n}"), admin, n, (30 - n) * DAY)
            for n in range(3)]
    at = keys[0].expires_at - FOURTEEN  # the latest-expiring key's moment: all three are due
    claimed = [await _claim_warning(seeded, at) for _ in range(3)]
    assert [c.credential_id for c in claimed] == [k.id for k in reversed(keys)]
    assert await _claim_warning(seeded, at) is None


async def test_a_warnings_deliveries_are_kept_per_person_and_threshold(seeded):
    """Who a send reached is kept per (credential, threshold); recording one twice keeps one; another threshold or
    credential starts empty (#1450 review: a retry mails only the admins not yet reached)."""
    admin = await _user(seeded)
    other = await _user(seeded, email="other@a.example")
    program = await _program(seeded, admin)
    key = await _timed_key(seeded, program, admin, 1, 30 * DAY)
    sibling = await _timed_key(seeded, program, admin, 2, 30 * DAY)
    assert await seeded.warning_deliveries(key.id, FOURTEEN) == set()
    await seeded.record_warning_delivery(key.id, FOURTEEN, admin.id, sent_at=NOW)
    await seeded.record_warning_delivery(key.id, FOURTEEN, admin.id, sent_at=NOW + HOUR)  # again: no error
    await seeded.record_warning_delivery(key.id, FOURTEEN, other.id, sent_at=NOW)
    assert await seeded.warning_deliveries(key.id, FOURTEEN) == {admin.id, other.id}
    assert await seeded.warning_deliveries(key.id, THREE) == set()
    assert await seeded.warning_deliveries(sibling.id, FOURTEEN) == set()


@pytest.mark.parametrize("state", ["revoked", "expired", "pending", "removed-with-its-program"])
async def test_only_a_usable_credential_has_a_warning_to_claim(seeded, state):
    """Revoked, expired, still-`pending` credentials and those revoked by their program's removal are not claimed (O7)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    other = await _program(seeded, admin, name="Control")
    control = await _timed_key(seeded, other, admin, 9, 30 * DAY)  # same channel: a usable one is claimed
    if state == "pending":
        row = await _add_oauth(seeded, program, admin, 1, expires_at=NOW + 30 * DAY)
    else:
        row = await _timed_key(seeded, program, admin, 1, 30 * DAY)
    at = row.expires_at - FOURTEEN
    if state == "revoked":
        await seeded.revoke_credential(row.id, revoked_by=admin.id, now=NOW)
    elif state == "removed-with-its-program":
        await seeded.remove_program(program.id, removed_by=admin.id, now=NOW)
    elif state == "expired":
        at = row.expires_at
    claimed = await _claim_warning(seeded, at)
    if state == "expired":
        assert claimed is None  # the control expires with it
    else:
        assert claimed.credential_id == control.id
        assert await _claim_warning(seeded, at) is None  # nothing else is waiting


async def test_the_keep_set_is_the_oauth_credentials_that_are_usable_or_pending_within_their_deadline(seeded):
    """Reconciliation keeps clients of live-unexpired and in-deadline pending OAuth rows; not keys, revoked, expired
    or past-deadline rows, and not at the very instant (usable = `expires_at > now`) (Reconciliation)."""
    admin = await _user(seeded)
    live_program = await _program(seeded, admin, name="Live")
    live = await _add_oauth(seeded, live_program, admin, 1, expires_at=NOW + 30 * DAY)
    await seeded.go_live(live.id, service_account_id=SA, now=NOW)
    pending = await _add_oauth(seeded, live_program, admin, 2)
    program = await _program(seeded, admin, name="Others")
    key = await _add_key(seeded, program, admin, 3)
    revoked = await _add_oauth(seeded, program, admin, 4)
    await seeded.revoke_credential(revoked.id, revoked_by=admin.id, now=NOW)
    assert await seeded.oauth_credentials_to_keep(now=NOW) == {live.id, pending.id}
    assert key.id not in await seeded.oauth_credentials_to_keep(now=NOW)
    assert await seeded.oauth_credentials_to_keep(now=NOW + DEADLINE) == {live.id}  # deadline instant: no longer pending
    assert await seeded.oauth_credentials_to_keep(now=live.expires_at - dt.timedelta(seconds=1)) == {live.id}
    assert await seeded.oauth_credentials_to_keep(now=live.expires_at) == set()  # expiry instant: unusable
    removed = await _program(seeded, admin, name="Removed")
    gone = await _add_oauth(seeded, removed, admin, 5)
    await seeded.go_live(gone.id, service_account_id=SA, now=NOW)
    await seeded.remove_program(removed.id, removed_by=admin.id, now=NOW)
    assert gone.id not in await seeded.oauth_credentials_to_keep(now=NOW)


# --- PostgreSQL only: two processes on one warning --------------------------------------------------------

@pytest.mark.postgres
async def test_a_warning_claim_skips_a_credential_another_process_holds_and_does_not_wait(two_repositories, pg_dsn):
    """`FOR UPDATE SKIP LOCKED`: a held credential row is passed over at once, then claimed once released (O7, outbox)."""
    first, second = two_repositories
    admin = await _user(first)
    program = await _program(first, admin)
    key = await _timed_key(first, program, admin, 1, 30 * DAY)
    at = key.expires_at - FOURTEEN
    async with holding_row(pg_dsn, "program_credentials", key.id):
        assert await asyncio.wait_for(_claim_warning(second, at), 5) is None
    claimed = await _claim_warning(second, at)
    assert (claimed.credential_id, claimed.threshold) == (key.id, FOURTEEN)
    assert await _claim_warning(first, at) is None  # held by the claim itself


@pytest.mark.postgres
async def test_two_processes_claiming_at_once_get_one_warning_between_them(two_repositories):
    """Two claimants racing for one due send: exactly one gets it; the other sees nothing (O7, one claimable send)."""
    first, second = two_repositories
    admin = await _user(first)
    program = await _program(first, admin)
    key = await _timed_key(first, program, admin, 1, 30 * DAY)
    at = key.expires_at - FOURTEEN
    got = await asyncio.gather(_claim_warning(first, at), _claim_warning(second, at))
    assert sorted(c is None for c in got) == [False, True]
    [won] = [c for c in got if c is not None]
    assert (won.credential_id, won.threshold) == (key.id, FOURTEEN)




# --- #1454: one admitting read per use, and the one standing rule (O-C, O-D) ---------------------------------------------

async def test_one_call_admits_a_program_by_key_by_client_or_by_credential_while_the_credential_is_usable(seeded):
    """Each admitting read returns the credential and its program; a wrong service account, an unknown key and a revoked credential admit nothing (O-C)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    key = await _add_key(seeded, program, admin, 1)
    oauth = await _add_oauth(seeded, program, admin, 2)
    assert await seeded.go_live(oauth.id, service_account_id=SA, now=NOW) is True
    for admitted, credential in ((await seeded.admit_by_key(_key(1), now=NOW), key),
                                 (await seeded.admit_by_client(oauth.id, service_account_id=SA, now=NOW), oauth),
                                 (await seeded.admit_by_credential(key.id, now=NOW), key),
                                 (await seeded.admit_by_credential(oauth.id, now=NOW), oauth)):
        assert admitted is not None
        assert (admitted[0].id, admitted[1].id, admitted[1].tenant_id, admitted[1].display_name) == (
            credential.id, program.id, T1, "SOAR prod")
    assert await seeded.admit_by_key(_key(9), now=NOW) is None
    assert await seeded.admit_by_client(oauth.id, service_account_id="someone-else", now=NOW) is None
    assert await seeded.admit_by_client(NO_SUCH_ROW, service_account_id=SA, now=NOW) is None
    assert await seeded.admit_by_credential(NO_SUCH_ROW, now=NOW) is None
    for credential in (key, oauth):
        assert await seeded.revoke_credential(credential.id, revoked_by=admin.id, now=NOW) is True
    assert await seeded.admit_by_key(_key(1), now=NOW) is None
    assert await seeded.admit_by_client(oauth.id, service_account_id=SA, now=NOW) is None
    assert await seeded.admit_by_credential(key.id, now=NOW) is None


EV = NOW + 30 * DAY
#: (kind, state, expiry offset from EV, deadline offset from EV) of the credential in one cell of the standing matrix.
CELLS = ([("key", "live", e, None) for e in AROUND] + [("key", "revoked", AROUND[1], None)]
         + [("oauth_client", "live", e, None) for e in AROUND] + [("oauth_client", "revoked", AROUND[1], None)]
         + [("oauth_client", "pending", None, d) for d in AROUND])
#: A program removed with a credential of each shape: removal revokes it, so what is read back is `revoked` (O-E).
REMOVED_CELLS = [("key", "live", AROUND[2], None), ("oauth_client", "live", AROUND[2], None), ("oauth_client", "pending", None, AROUND[2])]


async def _cell(repo, admin, tenant, n, cell, *, removed):
    """One program of `tenant` holding exactly one credential of shape `cell` as it stands at `EV`; the program is removed afterwards if asked.
    A key and a live OAuth row are made at `NOW` (so both warning thresholds fall after their creation); a `pending` row is made
    so that its deadline is `EV + deadline`, and expires at `EV + 14 days`, so its 14-day warning is due exactly at `EV`."""
    kind, state, expiry, deadline = cell
    program = await _program(repo, admin, tenant=tenant, name=f"p{n}")
    created = NOW if deadline is None else EV - DEADLINE + deadline
    expires_at = EV + 14 * DAY if expiry is None else EV + expiry
    if kind == "key":
        row = await _add_key(repo, program, admin, n, expires_at=expires_at, now=created)
    else:
        row = await _add_oauth(repo, program, admin, n, expires_at=expires_at, now=created)
        if state == "live":
            assert await repo.go_live(row.id, service_account_id=SA, now=created) is True
    if state == "revoked":
        assert await repo.revoke_credential(row.id, revoked_by=admin.id, now=created) is True
    if removed:
        assert await repo.remove_program(program.id, removed_by=admin.id, now=created) is not None
    return program, row.id


async def _build_matrix(repo, backend, tenants, admin):
    """One program per cell of CELLS (and REMOVED_CELLS) in each tenant state; each tenant leaves `active` only after its programs
    and credentials were made. Returns (program, credential id, tenant state, removed, n) per program."""
    tenant_of = {"active": T1}
    for state in NOT_ACTIVE:
        tenant_of[state] = TenantId(fixture_uuid(f"tenant:1454-{state}"))
        await _seed_tenant(backend, tenants, tenant_of[state])
    built = []
    for state, tenant in tenant_of.items():
        for removed, cells in ((False, CELLS), (True, REMOVED_CELLS)):
            for cell in cells:
                program, credential_id = await _cell(repo, admin, tenant, len(built), cell, removed=removed)
                built.append((program, credential_id, state, removed, len(built)))
    for state in NOT_ACTIVE:
        await leave_active(backend, tenants, tenant_of[state], state)
    return built


async def _admissions_that_disagree(repo, rows, expected, program_of, key_hash_of):
    """The (use, shape) of every admitting read that admitted a credential it should not, refused one it should admit, or returned another pair."""
    wrong = []
    for c, row in rows.items():
        by_secret = (await repo.admit_by_key(key_hash_of[c], now=EV) if row.kind == "key"
                     else await repo.admit_by_client(c, service_account_id=SA, now=EV))
        for use, got in (("by-secret", by_secret), ("by-credential", await repo.admit_by_credential(c, now=EV))):
            if (got is not None) != expected[c]:
                wrong.append((use, row.kind, row.state, row.expires_at - EV, expected[c]))
            elif got is not None and (got[0].id, got[1].id, got[1].tenant_id) != (c, program_of[c].id, program_of[c].tenant_id):
                wrong.append((use, "wrong pair", c))
    return wrong


async def test_every_use_of_a_credential_agrees_with_the_standing_of_its_program_and_its_own_predicate(seeded, backend, tenants):
    """Over credential state x expiry/deadline x program status x tenant state, authentication (by key, by client, by credential), the
    expiry-warning claim and the keep-set each admit exactly standing (program `active`, tenant `active`) and their own credential
    predicate: usable for the first three, usable or pending within its deadline for the keep-set (O-C, O-D).
    Removed-program cells read back `revoked`; the program-status rule alone is observed by the raw-write test below."""
    built = await _build_matrix(seeded, backend, tenants, await _user(seeded))
    rows = {credential_id: await seeded.credential_by_id(credential_id) for _, credential_id, _, _, _ in built}
    standing = {credential_id: state == "active" and not removed for _, credential_id, state, removed, _ in built}
    program_of = {credential_id: program for program, credential_id, _, _, _ in built}
    key_hash_of = {credential_id: _key(n) for _, credential_id, _, _, n in built}
    usable = {c: standing[c] and _usable(rows[c], EV) for c in rows}
    kept = {c: standing[c] and rows[c].kind == "oauth_client" and _holds_a_slot(rows[c], EV) for c in rows}
    assert {True, False} == set(usable.values()) == set(kept.values()) == set(standing.values())  # controls: every channel both ways
    assert any(kept[c] and not usable[c] for c in rows)  # a pending row within its deadline is kept though not usable

    assert await _admissions_that_disagree(seeded, rows, usable, program_of, key_hash_of) == []
    assert await seeded.oauth_credentials_to_keep(now=EV) == {c for c in rows if kept[c]}
    claimed = []
    while (claim := await _claim_warning(seeded, EV)) is not None:
        claimed.append(claim.credential_id)
    assert sorted(claimed) == sorted(c for c in rows if usable[c])  # each exactly once


@pytest.mark.postgres
async def test_a_program_removed_with_a_usable_credential_left_is_admitted_warned_and_kept_by_none(seeded, backend):
    """Whatever wrote it: a `removed` program row whose credentials were left usable admits, warns and keeps nothing; its sibling does (O-D)."""
    from defender.tests.support.shared._postgres1339 import execute

    if backend is None:
        pytest.skip("only a raw write leaves a removed program's credentials usable; the in-memory repository has none")
    admin = await _user(seeded)
    stale = await _program(seeded, admin, name="Stale")
    sibling = await _program(seeded, admin, name="Sibling")
    rows = {}
    for program, n in ((stale, 1), (sibling, 3)):
        key = await _timed_key(seeded, program, admin, n, 30 * DAY)
        oauth = await _add_oauth(seeded, program, admin, n + 1, expires_at=NOW + 30 * DAY)
        assert await seeded.go_live(oauth.id, service_account_id=SA, now=NOW) is True
        rows[program.id] = (key, oauth)
    execute(backend, "UPDATE identity.programs SET removed_at = %s WHERE id = %s", (NOW, str(stale.id)))
    key, oauth = rows[stale.id]
    assert await seeded.admit_by_key(_key(1), now=NOW) is None
    assert await seeded.admit_by_client(oauth.id, service_account_id=SA, now=NOW) is None
    assert await seeded.admit_by_credential(key.id, now=NOW) is None
    assert await seeded.oauth_credentials_to_keep(now=NOW) == {rows[sibling.id][1].id}
    at = NOW + 30 * DAY - FOURTEEN
    assert {(await _claim_warning(seeded, at)).credential_id, (await _claim_warning(seeded, at)).credential_id} == {
        r.id for r in rows[sibling.id]}
    assert await _claim_warning(seeded, at) is None
    assert (await seeded.admit_by_key(_key(3), now=NOW))[1].id == sibling.id  # control


# --- #1454: a write that makes something live holds the tenant active (P-L) -----------------------------------------------

async def _leave(state, backend, tenants, tenant) -> TenantId:
    """`tenant` after it left `active` for `state`; the unregistered tenant for "absent"."""
    if state == "absent":
        return T_UNREGISTERED
    await leave_active(backend, tenants, tenant, state)
    return tenant


@pytest.mark.parametrize("state", [*NOT_ACTIVE, "absent"])
async def test_a_program_is_not_created_in_a_tenant_that_is_not_active(seeded, backend, tenants, state):
    """Creating a program in an offboarding, offboarded or absent tenant raises `TenantNotActive` (a data-rule violation) and writes nothing; T1 accepts (P-L)."""
    from defender.identity import TenantNotActive

    assert issubclass(TenantNotActive, DataRuleViolation)
    admin = await _user(seeded)
    tenant = await _leave(state, backend, tenants, T2)
    with pytest.raises(TenantNotActive):
        await _program(seeded, admin, tenant=tenant)
    assert await seeded.programs_of_tenant(tenant) == []
    assert (await _program(seeded, admin)).tenant_id == T1  # control


@pytest.mark.parametrize("state", [*NOT_ACTIVE, "absent"])
async def test_a_person_is_not_invited_to_a_tenant_that_is_not_active(seeded, backend, tenants, state):
    """Inviting into an offboarding, offboarded or absent tenant raises `TenantNotActive` and adds no membership; an invitation made while it was active stays and revokes (P-L, O-E)."""
    from defender.identity import TenantNotActive

    ann, bob = await _user(seeded), await _user(seeded, "bob@x.org")
    earlier = None if state == "absent" else await _invited(seeded, ann, T2)
    tenant = await _leave(state, backend, tenants, T2)
    with pytest.raises(TenantNotActive):
        await seeded.ensure_invitation(bob.id, tenant, invited_by=ann.id, now=NOW)
    assert [m.id for m in await seeded.memberships_of_tenant(tenant)] == ([] if earlier is None else [earlier.id])
    if earlier is not None:
        assert (await seeded.membership(earlier.id)).status == "invited"
        assert await seeded.revoke_invitation(earlier.id) is True  # offboarding revokes what is open
    assert (await _invited(seeded, bob)).status == "invited"  # control: T1 is active


@pytest.mark.parametrize("state", NOT_ACTIVE)
async def test_an_invitation_is_not_accepted_once_its_tenant_left_active(seeded, backend, tenants, state):
    """Accepting returns False and leaves the row `invited` after the tenant left `active`; another tenant's invitation accepts (P-L)."""
    ann = await _user(seeded)
    leaving, staying = await _invited(seeded, ann, T2), await _invited(seeded, ann, T1)
    await leave_active(backend, tenants, T2, state)
    assert await seeded.accept_invitation(leaving.id, now=NOW) is False
    assert (await seeded.membership(leaving.id)).status == "invited"
    assert await seeded.accept_invitation(staying.id, now=NOW) is True  # control


async def _pl_write(repo, write, admin, invitee, invitation):
    """The P-L write, held by the caller at its own row: what it made (a program id, the invitee's id, the accepted row's id), None when
    it returned False, or the `DataRuleViolation` it raised."""
    try:
        if write == "program":
            return (await _program(repo, admin)).id
        if write == "invitation":
            return (await repo.ensure_invitation(invitee.id, T1, invited_by=admin.id, now=NOW)).user_id
        return invitation.id if await repo.accept_invitation(invitation.id, now=NOW) else None
    except DataRuleViolation as refusal:
        return refusal


async def _pl_end_tenant_reads(repo, write):
    """What `end_tenant` reads of T1 for that write: active programs, memberships' users, or active memberships."""
    if write == "program":
        return [p.id for p in await repo.programs_of_tenant(T1)]
    if write == "invitation":
        return [m.user_id for m in await repo.memberships_of_tenant(T1)]
    return [m.id for m in await repo.memberships_of_tenant(T1) if m.status == "active"]


def _pl_refused(write, made) -> bool:
    """Whether the P-L write was refused: False/None for accepting, `TenantNotActive` for the creates."""
    if write == "accept":
        return made is None
    from defender.identity import TenantNotActive  # imported here so the accept cases run before the class exists

    return isinstance(made, TenantNotActive)


@pytest.mark.postgres
@pytest.mark.parametrize("write", ["program", "invitation", "accept"])
async def test_a_write_held_at_its_row_leaves_the_offboarding_step_nothing_to_miss(two_repositories, pg_dsn, write):
    """C14, write first (held at its own row): what the offboarding step reads after the offboard commits is what stays live, and the
    write is refused exactly when its row is not live (P-L, O-E)."""
    from defender.database import async_engine
    from defender.tenancy.models import offboard

    one, _ = two_repositories
    admin, invitee = await _user(one), await _user(one, "bob@x.org")
    invitation = await _invited(one, invitee) if write == "accept" else None
    held = ("memberships", invitation.id) if write == "accept" else ("users", admin.id)  # the write's own row
    engine = async_engine(pg_dsn)

    async def offboarding_then_step_reads():
        async with engine.begin() as conn:
            assert (await offboard(conn, T1)).state == "offboarding"
        return await _pl_end_tenant_reads(one, write)

    async def release_now() -> bool:  # when to release the row only; it selects no assertion
        return step.done() or await blocked(pg_dsn) == 2

    try:
        async with holding_row(pg_dsn, *held):
            attempt = asyncio.ensure_future(_pl_write(one, write, admin, invitee, invitation))
            await until_blocked(pg_dsn, 1)
            step = asyncio.ensure_future(offboarding_then_step_reads())
            await until(release_now)
        made = await asyncio.wait_for(attempt, TIMEOUT)
        step_read = await asyncio.wait_for(step, TIMEOUT)
        live = await _pl_end_tenant_reads(one, write)
        assert live == step_read, (live, step_read)  # (a) nothing became live after the offboarding step read
        assert _pl_refused(write, made) == (made not in live), (made, live)  # (b)
    finally:
        await engine.dispose()


@pytest.mark.postgres
@pytest.mark.parametrize("write", ["program", "invitation", "accept"])
async def test_a_write_after_an_uncommitted_offboard_waits_then_is_refused(two_repositories, pg_dsn, write):
    """C14, offboard first (transaction still open): the write blocks on the tenant row, then is refused on commit and nothing is
    live (P-L, O-E)."""
    from defender.database import async_engine
    from defender.tenancy.models import offboard

    one, _ = two_repositories
    admin, invitee = await _user(one), await _user(one, "bob@x.org")
    invitation = await _invited(one, invitee) if write == "accept" else None
    engine = async_engine(pg_dsn)
    try:
        async with engine.begin() as conn:  # the offboard stays open (uncommitted) while the write starts
            assert (await offboard(conn, T1)).state == "offboarding"
            attempt = asyncio.ensure_future(_pl_write(one, write, admin, invitee, invitation))
            await until_blocked(pg_dsn, 1)  # the write waits on the tenant row
            assert not attempt.done()
            assert await _pl_end_tenant_reads(one, write) == []  # nothing the write made is live while it waits (P-L: the check is in the write's own transaction)
        made = await asyncio.wait_for(attempt, TIMEOUT)
        if write == "accept":
            assert made is None, made
        else:
            from defender.identity import TenantNotActive  # imported here so the setup runs before the class exists

            assert isinstance(made, TenantNotActive), made
        assert await _pl_end_tenant_reads(one, write) == []
    finally:
        await engine.dispose()


@pytest.mark.postgres
async def test_an_accept_waits_for_an_offboard_that_wrote_first_then_returns_false(two_repositories, pg_dsn):
    """C14 for accepting, offboard first: the accept waits on the tenant row, then returns False and the row stays `invited` (P-L)."""
    from defender.database import async_engine
    from defender.tenancy.models import offboard

    one, _ = two_repositories
    invitation = await _invited(one, await _user(one))
    engine = async_engine(pg_dsn)
    try:
        async with engine.begin() as conn:
            await offboard(conn, T1)
            attempt = asyncio.ensure_future(one.accept_invitation(invitation.id, now=NOW))
            await until_blocked(pg_dsn, 1)
            assert not attempt.done()
            assert (await one.membership(invitation.id)).status == "invited"  # still invited while the accept waits
        assert await asyncio.wait_for(attempt, TIMEOUT) is False
        assert (await one.membership(invitation.id)).status == "invited"
    finally:
        await engine.dispose()
