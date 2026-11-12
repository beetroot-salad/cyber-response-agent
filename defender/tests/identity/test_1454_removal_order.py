# ruff: noqa: F811  — the #1306 contract's fixtures are imported, as in test_1307_repository_contract.py
"""#1454 O-A: `remove_program` answers the credentials it revoked oldest first (by `created_at`, then id), in both repositories;
the audit takes its order from this answer (a removal's lines read in the order the credentials were made)."""
from __future__ import annotations

import pytest

from defender.tests.identity.test_1307_repository_contract import HOUR, NOW, _add_key, _add_oauth, _program, _user
from defender.tests.identity.test_identity_repository_contract import (  # noqa: F401  (fixtures)
    backend,
    pg_dsn,
    repo,
    seeded,
    tenants,
)

pytestmark = pytest.mark.anyio


async def test_removing_a_program_answers_the_credentials_it_revoked_oldest_first(seeded):
    """Two credentials made an hour apart: the answer lists the older one first, and a credential revoked earlier is not in it (O-A)."""
    admin = await _user(seeded)
    program = await _program(seeded, admin)
    gone = await _add_key(seeded, program, admin, 3, now=NOW)
    await seeded.revoke_credential(gone.id, revoked_by=admin.id, now=NOW)
    older = await _add_oauth(seeded, program, admin, 1, now=NOW)
    newer = await _add_key(seeded, program, admin, 2, now=NOW + HOUR)
    assert await seeded.remove_program(program.id, removed_by=admin.id, now=NOW + 2 * HOUR) == [older.id, newer.id]
