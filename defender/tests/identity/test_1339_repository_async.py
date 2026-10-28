"""#1339 the identity repository on async SQLAlchemy: returned models are detached copies (P4, O4),
and a revoke racing an accept applies once (O6d).

Both repositories are async. An engine lives in the loop that made it: the `repo` fixture builds and
closes the PostgreSQL repository inside the test's loop, on a database of the test's own.
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
from collections.abc import AsyncIterator, Iterator

import pytest

from defender.identity import InMemoryIdentityRepository
from defender.records._tenant_id import TenantId
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import database

NOW = dt.datetime(2026, 10, 26, 12, 0, tzinfo=dt.UTC)
WEEK = dt.timedelta(days=7)
T1 = TenantId(fixture_uuid("tenant:t1"))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _postgres(dsn: str):
    from defender.identity.postgres import PostgresIdentityRepository

    return PostgresIdentityRepository(dsn)


@pytest.fixture(params=["memory", pytest.param("postgres", marks=pytest.mark.postgres)])
def backend(request) -> Iterator[str | None]:
    """`None` for the in-memory repository, else a migrated database's DSN (made off the event loop)."""
    if request.param == "memory":
        yield None
        return
    with database(migrated=True) as dsn:
        yield dsn


@pytest.fixture
async def repo(backend) -> AsyncIterator[object]:
    r = InMemoryIdentityRepository() if backend is None else _postgres(backend)
    try:
        await r.register_tenant(T1)
        yield r
    finally:
        await r.close()


def _values(model: object) -> dict[str, object]:
    """Every field of a returned model, read now (a detached model with an unloaded field raises here)."""
    return {f.name: getattr(model, f.name) for f in dataclasses.fields(model)}


# --- P4 returned models are detached copies --------------------------------------------------------


@pytest.mark.anyio
async def test_a_returned_model_is_fully_readable_and_changing_it_changes_nothing_stored(repo):
    """Every field of a returned user, membership and session is set; mutating them is not stored (P4, O4)."""
    user = await repo.ensure_user("Ann@X.org", now=NOW)
    row = await repo.ensure_invitation(user.id, T1, invited_by="system", now=NOW)
    session = await repo.add_session("raw-session-value", user.id, now=NOW, expires_at=NOW + WEEK)

    stored_user, stored_row, stored_session = _values(user), _values(row), _values(session)
    assert {k: stored_user[k] for k in ("email", "display_name", "status", "signin_account_id",
                                        "is_platform_admin", "set_password_requested_seq",
                                        "set_password_attempts", "created_at", "activated_at")} == {
        "email": "ann@x.org", "display_name": "", "status": "invited", "signin_account_id": None,
        "is_platform_admin": False, "set_password_requested_seq": 0, "set_password_attempts": 0,
        "created_at": NOW, "activated_at": None}
    assert {k: stored_row[k] for k in ("user_id", "tenant_id", "status", "invited_by", "created_at",
                                       "notify_requested_seq", "expires_at", "accepted_at")} == {
        "user_id": user.id, "tenant_id": str(T1), "status": "invited", "invited_by": "system",
        "created_at": NOW, "notify_requested_seq": 0, "expires_at": None, "accepted_at": None}
    assert (stored_session["user_id"], stored_session["created_at"], stored_session["expires_at"]) == (
        user.id, NOW, NOW + WEEK)

    user.display_name, user.status = "Mallory", "active"
    row.status = "revoked"
    session.expires_at = NOW - WEEK
    again = await repo.user(user.id)
    assert _values(again) == stored_user
    assert _values(await repo.membership(row.id)) == stored_row
    assert _values(await repo.session_by_value("raw-session-value")) == stored_session

    again.display_name = "Mallory"  # a model from a lookup is a copy too
    assert (await repo.user_by_email("ann@x.org")).display_name == ""


# --- O6d revoke racing accept on PostgreSQL ------------------------------------------------------


@pytest.fixture
def shared_database() -> Iterator[str]:
    with database(migrated=True) as dsn:
        yield dsn


@pytest.fixture
async def two_repositories(shared_database) -> AsyncIterator[tuple[object, object]]:
    """Two repositories, so two engines and two connections, over one database."""
    first, second = _postgres(shared_database), _postgres(shared_database)
    try:
        await first.register_tenant(T1)
        yield first, second
    finally:
        await first.close()
        await second.close()


@pytest.mark.postgres
@pytest.mark.anyio
async def test_a_revoke_racing_an_accept_on_one_invitation_applies_exactly_one(two_repositories):
    """Concurrent revoke and accept of one `invited` row: exactly one reports applied, and the row shows it (O6d)."""
    first, second = two_repositories
    for i in range(10):  # repeat to give the race a chance to happen
        user = await first.ensure_user(f"race{i}@x.org", now=NOW)
        row = await first.ensure_invitation(user.id, T1, invited_by="system", now=NOW)
        revoked, accepted = await asyncio.gather(
            first.revoke_invitation(row.id), second.accept_invitation(row.id, now=NOW))
        assert [revoked, accepted].count(True) == 1, (revoked, accepted)
        after = await first.membership(row.id)
        assert (after.status, after.accepted_at) == (("revoked", None) if revoked else ("active", NOW))
