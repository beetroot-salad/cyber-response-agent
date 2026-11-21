"""#1592 S2 machinery (slice-owned, NO test functions): clean starts, members, the scripted lock, a faulting identity
read, a counting sessions port, and log helpers. Production names are imported inside functions."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from defender.tests.support.identity._seed1496 import seed_membership, seed_user
from defender.tests.tenancy.people_1592._spec1592 import login_of, org_of, people_worker, sessions_port
from defender.tests.tenancy.people_1592._world1592 import NOW, People


async def settled(people: People, limit: int = 6) -> None:
    """Drain the requests seeding recorded (an expansion's rows run a poll later), then forget the calls so a case
    sees only its own. Control: the table is empty afterwards."""
    for _ in range(limit):
        await people.step()
        if not await people.open_requests():
            break
    assert await people.open_requests() == [], "control: the seeding requests did not drain"
    people.forge.calls.clear()
    people.forge.arrived.clear()


async def member(people: People, email: str, *tenants: str, account: bool = True, in_team: bool = True,
                 sub: bool = True, display_name: str = "") -> Any:
    """An active member of `tenants`, optionally with no Forgejo account, no team place, or no sub."""
    user = await seed_user(people.identity, email, created_at=NOW, status="active",
                           display_name=display_name or email.split("@")[0],
                           signin_account_id=f"sub-{email}" if sub else None)
    login = login_of(user.id)
    if account:
        people.forge.add_account(login, login_name=f"sub-{email}")
    for tenant in tenants:
        await seed_membership(people.identity, user.id, tenant, status="active", invited_by=None, created_at=NOW,
                              accepted_at=NOW)
        if in_team and account and (org_of(tenant), "members") in people.forge.team_members:
            people.forge.team_members[(org_of(tenant), "members")].add(login)
    return user


def use(people: People, *, tenants: Any = None, identity: Any = None, sessions: Any = None, **config: Any) -> Any:
    """Replace the world's worker by one over the given seams (a scripted lock, a faulting identity, ...)."""
    import dataclasses

    cfg = dataclasses.replace(people.config, **config) if config else people.config
    port = sessions if sessions is not None else (
        people.sessions_port if people.sessions_port is not None else sessions_port(people.sessions.dsn))
    people.worker = people_worker(tenants or people.tenants, identity=identity or people.identity, forge=people.forge,
                                  sessions=port, config=cfg, clock=people.clock)
    return people.worker


def errors(caplog: Any) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]


async def until(predicate: Any, timeout: float = 5.0) -> bool:
    """Wait for `predicate()` (sync or async); True once it holds, False at `timeout`."""
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        got = predicate()
        if asyncio.iscoroutine(got):
            got = await got
        if got:
            return True
        await asyncio.sleep(0.01)
    return False


class ScriptedLock:
    """A tenants object whose `people_lock` answers the bool a test sets; everything else is the real store's."""

    def __init__(self, real: Any, held: bool = True) -> None:
        self._real = real
        self.held = held
        self.asked = 0

    async def people_lock(self) -> bool:
        self.asked += 1
        return self.held

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class FaultingIdentity:
    """The identity port with some reads raising a connection error (handed only to the worker)."""

    def __init__(self, real: Any, *failing: str) -> None:
        self._real = real
        self._failing = set(failing)

    def __getattr__(self, name: str) -> Any:
        if name not in self._failing:
            return getattr(self._real, name)

        async def fail(*_a: Any, **_k: Any) -> Any:
            raise ConnectionError(f"identity {name} unreachable")

        return fail


class CountingSessions:
    """A sessions port that counts the calls of each method and delegates."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.calls: dict[str, int] = {}

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._real, name)
        if not callable(target):
            return target

        def counted(*a: Any, **k: Any) -> Any:
            self.calls[name] = self.calls.get(name, 0) + 1
            return target(*a, **k)

        return counted
