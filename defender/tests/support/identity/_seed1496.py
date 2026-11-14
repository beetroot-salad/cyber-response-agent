"""Seeders for the two identity repositories (#1496): a person or a membership planted as written, not requested.
They were the repositories' own methods while the demo server seeded through them; no production code seeds, so they
live with the tests. Each takes the in-memory twin or the PostgreSQL repository and refuses anything else by name.
Both enforce the data rules the repositories keep (an email address, the membership fields, one live membership per
person and tenant), as the twin's checks and the database's constraints do."""
from __future__ import annotations

import datetime as _dt
from typing import Any

from defender.identity import DataRuleViolation, InMemoryIdentityRepository
from defender.identity.memory import _LIVE, _copy
from defender.identity.models import Membership, MembershipStatus, PersonRole, User, UserStatus
from defender.identity.postgres import PostgresIdentityRepository
from defender.records.formats import TenantId, UserId


def check_membership_fields(
    status: MembershipStatus, *, accepted_at: _dt.datetime | None, ended_at: _dt.datetime | None,
) -> None:
    """The rule that ties a status to its timestamps, as the SQL schema's CHECK carries it: the twin keeps no such check
    of its own, so the seeder does, on both repositories alike."""
    if status == "active" and accepted_at is None:
        raise DataRuleViolation("an active membership needs accepted_at")
    if status == "ended" and ended_at is None:
        raise DataRuleViolation("an ended membership needs ended_at")


def _refused(repo: Any) -> TypeError:
    return TypeError(f"no identity seeder for {type(repo).__name__}: pass the in-memory twin or the PostgreSQL repository")


async def seed_user(
    repo: Any, email: str | None, *, created_at: _dt.datetime, status: UserStatus = "invited",
    display_name: str = "", signin_account_id: str | None = None, is_platform_admin: bool = False,
) -> User:
    """A person as given."""
    if email is None:
        raise DataRuleViolation("a person needs an email address")
    fields = dict(created_at=created_at, status=status, display_name=display_name,
                  signin_account_id=signin_account_id, is_platform_admin=is_platform_admin)
    if isinstance(repo, InMemoryIdentityRepository):
        return _copy(repo._new_user(email, **fields))  # noqa: SLF001 — test support: the twin's own insert
    if isinstance(repo, PostgresIdentityRepository):
        user = User.new(email, **fields)  # type: ignore[arg-type]
        async with repo._tx() as s:  # noqa: SLF001 — test support: the repository's own transaction
            s.add(user)
        return user
    raise _refused(repo)


async def seed_membership(  # noqa: PLR0913 — every membership column a case plants
    repo: Any, user_id: UserId, tenant_id: TenantId, *, status: MembershipStatus, invited_by: UserId | None,
    created_at: _dt.datetime, expires_at: _dt.datetime | None = None,
    accepted_at: _dt.datetime | None = None, ended_at: _dt.datetime | None = None,
    ended_by: UserId | None = None, role: PersonRole = "admin",
) -> Membership:
    """A membership as given."""
    check_membership_fields(status, accepted_at=accepted_at, ended_at=ended_at)
    fields = dict(user_id=user_id, tenant_id=tenant_id, status=status, invited_by=invited_by, created_at=created_at,
                  expires_at=expires_at, accepted_at=accepted_at, ended_at=ended_at, ended_by=ended_by, role=role)
    if isinstance(repo, InMemoryIdentityRepository):
        repo._refuse_dangling(user_id, tenant_id)  # noqa: SLF001 — test support: the twin's own checks
        repo._refuse_unknown_actor(invited_by, ended_by)  # noqa: SLF001
        if status in _LIVE and repo._live_row(user_id, tenant_id) is not None:  # noqa: SLF001
            raise DataRuleViolation("the user already has a live membership in this tenant")
        return _copy(repo._insert_membership(**fields))  # noqa: SLF001
    if isinstance(repo, PostgresIdentityRepository):
        row = Membership(**fields)  # type: ignore[arg-type]
        async with repo._tx() as s:  # noqa: SLF001 — test support: the repository's own transaction
            s.add(row)
        return row
    raise _refused(repo)
