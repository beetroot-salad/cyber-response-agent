# ruff: noqa: F811  — the #1306 contract's fixtures are imported, as in test_1214_atk1_repository.py
"""#1307 IdentityRepository contract for programs and their credentials, memory and PostgreSQL (P-I, P-G, O4, O5) — sketch.

Forced choice (FC-7): `add_program(tenant_id, *, display_name, created_by, now) -> User`;
`add_credential(program_id, *, kind, name, created_by, expires_at, now, key_hash=None) -> row`
(keys `live`; OAuth `pending` with `pending_deadline = now + 10 min`); `go_live(credential_id, *,
service_account_id, now) -> bool`; `revoke_credential(credential_id, *, revoked_by, now) -> bool`;
`credentials_of_program(program_id)`. Over the cap or for a person -> `DataRuleViolation`.
"""
from __future__ import annotations

import datetime as dt
import hashlib

import pytest

from defender.identity import DataRuleViolation
from defender.tests.identity.test_1306_repository_contract import (  # noqa: F401  (fixtures)
    NOW,
    T1,
    _user,
    backend,
    repo,
    seeded,
    tenants,
)

pytestmark = pytest.mark.anyio

EXPIRES = NOW + dt.timedelta(days=90)
PENDING_DEADLINE = dt.timedelta(minutes=10)
SA = "9a8b7c6d-0000-4000-8000-0000000005a1"


async def _program(repo, admin):
    return await repo.add_program(T1, display_name="SOAR prod", created_by=admin.id, now=NOW)


def _key(n: int) -> str:
    return hashlib.sha256(f"dfk_key-{n}".encode()).hexdigest()


async def test_a_program_is_an_active_automation_member_but_not_a_person_of_the_tenant(seeded):
    """Program rows: kind program, no email, active automation membership; people queries ignore it (O4, P-I)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    assert (program.kind, program.email, program.status, program.created_by) == ("program", None, "active", admin.id)
    membership = await seeded.active_membership(program.id, T1)
    assert membership is not None
    assert membership.role == "automation"
    assert await seeded.tenant_has_active_members(T1) is False
    assert await seeded.people_of_tenant(T1, "active") == []


async def test_at_most_two_credentials_are_usable_or_pending_within_their_deadline(seeded):
    """The cap counts usable and in-deadline pending rows only (O5, B1)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    await seeded.add_credential(program.id, kind="key", name="k1", created_by=admin.id,
                                expires_at=EXPIRES, now=NOW, key_hash=_key(1))
    pending = await seeded.add_credential(program.id, kind="oauth_client", name="o1", created_by=admin.id,
                                          expires_at=EXPIRES, now=NOW)
    assert pending.state == "pending"
    with pytest.raises(DataRuleViolation):
        await seeded.add_credential(program.id, kind="key", name="k2", created_by=admin.id,
                                    expires_at=EXPIRES, now=NOW, key_hash=_key(2))
    later = NOW + PENDING_DEADLINE + dt.timedelta(seconds=1)
    third = await seeded.add_credential(program.id, kind="key", name="k2", created_by=admin.id,
                                        expires_at=EXPIRES, now=later, key_hash=_key(2))
    assert third.state == "live"
    assert await seeded.go_live(pending.id, service_account_id=SA, now=later) is False


async def test_pending_goes_live_only_while_still_pending(seeded):
    """`pending -> live` is conditional: a revoked row stays revoked (Create step 4, removal race)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    racing = await seeded.add_credential(program.id, kind="oauth_client", name="o1", created_by=admin.id,
                                         expires_at=EXPIRES, now=NOW)
    assert await seeded.revoke_credential(racing.id, revoked_by=admin.id, now=NOW) is True
    assert await seeded.go_live(racing.id, service_account_id=SA, now=NOW) is False
    fine = await seeded.add_credential(program.id, kind="oauth_client", name="o2", created_by=admin.id,
                                       expires_at=EXPIRES, now=NOW)
    assert await seeded.go_live(fine.id, service_account_id=SA, now=NOW) is True
    states = {r.id: r.state for r in await seeded.credentials_of_program(program.id)}
    assert states == {racing.id: "revoked", fine.id: "live"}


async def test_no_credential_can_belong_to_a_person(seeded):
    """A credential's program must be a user of kind program (P-F)."""
    admin = await _user(seeded)
    with pytest.raises(DataRuleViolation):
        await seeded.add_credential(admin.id, kind="key", name="k", created_by=admin.id,
                                    expires_at=EXPIRES, now=NOW, key_hash=_key(9))
