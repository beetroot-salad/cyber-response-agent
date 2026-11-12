# ruff: noqa: F811  — the #1306 contract's fixtures are imported, as in test_1307_repository_contract.py
"""#1454 PostgreSQL, same-side concurrency and atomicity of the program writes (O-E, cap). One lock per program: concurrent
credential creations wait on the program's row one at a time, so the cap of two holds however many race; and removal is ONE
transaction: a failure in its credential update leaves the program `active` and its credentials untouched, so it can be retried."""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.exc import DBAPIError

from defender.identity.errors import CredentialCapReached
from defender.tests.identity.test_1307_repository_contract import NOW, _add_key, _program, _states, _user
from defender.tests.identity.test_identity_repository_contract import pg_dsn, two_repositories  # noqa: F401  (fixtures)
from defender.tests.support.shared._pglocks1339 import TIMEOUT, holding_row, until_blocked
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

CREDENTIAL_CAP = 2
RACERS = 4


async def test_concurrent_credential_creations_held_on_the_program_row_succeed_exactly_cap_times(two_repositories, pg_dsn):
    """Four creations for one program, all waiting on its row, then released: exactly two succeed, the other two raise
    `CredentialCapReached`, and two credentials are usable afterwards (the program lock is exclusive, not shared) (O-E, cap)."""
    one, two = two_repositories
    admin = await _user(one)
    program = await _program(one, admin)
    async with holding_row(pg_dsn, "programs", program.id):
        tasks = [asyncio.ensure_future(_add_key(one if n % 2 else two, program, admin, n)) for n in range(1, RACERS + 1)]
        await until_blocked(pg_dsn, RACERS)
        assert not any(t.done() for t in tasks)
    results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), TIMEOUT)
    refused = [r for r in results if isinstance(r, CredentialCapReached)]
    made = [r for r in results if not isinstance(r, BaseException)]
    assert (len(made), len(refused)) == (CREDENTIAL_CAP, RACERS - CREDENTIAL_CAP), results
    usable = [r for r in await one.credentials_of_program(program.id) if r.state == "live"]
    assert sorted(r.id for r in usable) == sorted(r.id for r in made)


async def test_removal_whose_credential_update_fails_leaves_the_program_active_and_can_be_retried(two_repositories, pg_dsn):
    """A failure in the credentials' revoking update undoes the status change with it (one transaction): the program is still
    `active`, its credential `live`; once the fault is gone the same removal succeeds and answers what it revoked (O-E)."""
    one, _ = two_repositories
    admin = await _user(one)
    program = await _program(one, admin)
    key = await _add_key(one, program, admin, 1)
    execute(pg_dsn, """CREATE FUNCTION identity.refuse_update() RETURNS trigger LANGUAGE plpgsql
                       AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$;
                       CREATE TRIGGER refuse_update BEFORE UPDATE ON identity.program_credentials
                       FOR EACH ROW EXECUTE FUNCTION identity.refuse_update()""")
    with pytest.raises(DBAPIError):
        await one.remove_program(program.id, removed_by=admin.id, now=NOW)
    assert (await one.program(program.id)).status == "active"
    assert await _states(one, program) == {key.id: "live"}
    assert [p.id for p in await one.programs_of_tenant(program.tenant_id)] == [program.id]
    execute(pg_dsn, "DROP TRIGGER refuse_update ON identity.program_credentials")
    assert await one.remove_program(program.id, removed_by=admin.id, now=NOW) == [key.id]  # not "already removed"
    assert (await one.program(program.id)).status == "removed"
    assert await _states(one, program) == {key.id: "revoked"}
