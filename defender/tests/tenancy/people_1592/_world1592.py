"""#1592 shared machinery (r15), NO test functions: the worker's world (`People`) and its fixtures `people` (the
identity and tenancy memory twins over one store), `pg_people` (both PostgreSQL repositories over one migrated
database) and `sessions` (a real Forgejo sessions database), via conftest.

`step()` is one poll then `settle()`; `steps(n)` repeats it a bounded number of times. Nothing here loops until the
requests are gone, so a retry case sees each attempt. A case that gates a run calls `worker.poll()` itself and must
not settle until it opens the gate.

One worker stands for one process (#1592 fidelity review 1, C3-C6): `settled()` drains the seeding requests with a
setup worker over a repository of its own and closes it, so the PostgreSQL lock it took is released; the case's worker
is built at its first `step()` from the seams then current (`sessions_port`, `config`) and rebuilt when they change;
`build()` makes a second process, over a repository of its own on PostgreSQL. `errors(caplog)` reads the log after the
last `settled()`, so the setup worker's lock-gain error (OD-12: a first take is a change) is not a case's.
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.identity._seed1496 import seed_membership, seed_user
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy._twin1496 import seed_tenant
from defender.tests.tenancy.people_1592._sessions1592 import shipped_sessions_database
from defender.tests.tenancy.people_1592._spec1592 import (
    Clock,
    PeopleForge,
    Req,
    RequestLog,
    Sessions,
    login_of,
    org_of,
    pairs,
    people_config,
    people_worker,
    repo_of,
    requests_port,
    session_key,
    sessions_port,
    signed_in_data,
)

NOW = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.UTC)
T = fixture_uuid("tenant:1592-worker-t")
U2 = fixture_uuid("tenant:1592-worker-u")
#: How long a step waits for the worker's tasks before the case fails (a hung run is a red, not a hang).
SETTLE_TIMEOUT = 5.0


@dataclasses.dataclass
class People:
    tenants: Any
    identity: Any
    forge: PeopleForge
    sessions: Sessions
    config: Any
    clock: Clock
    dsn: str | None = None
    #: the sessions port the worker gets; `None` builds the product's port over `sessions.dsn`.
    sessions_port: Any = None
    worker: Any = None
    #: the `caplog` of the case (the fixtures set it), for the log baseline `settled()` takes
    caplog: Any = None
    #: repositories `build()` opened for second processes, closed at teardown
    opened: list[Any] = dataclasses.field(default_factory=list)
    #: the seams the case's worker was built from, so a changed seam rebuilds it
    _seams: tuple[Any, Any] | None = None

    # seeding ----------------------------------------------------------------------------------------
    async def tenant(self, tenant: str, *, state: str = "active", team: bool = True, wired: bool = True) -> None:
        """A tenant wired at `t-<T>/knowledge`; with `team`, Forgejo has organisation `t-<T>` and an empty `members`."""
        if self.dsn is None:
            extra = {"repo": repo_of(tenant), "origin": f"http://forge.test/{repo_of(tenant)}.git"} if wired else {}
            await seed_tenant(self.tenants, tenant, created_at=NOW, state=state, **extra)
        else:
            from defender.tests.support.shared._postgres1339 import execute

            job = {"active": (None, None, None), "creating": ("create", "names", "service")}[state]
            execute(self.dsn, """INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor)
                                 VALUES (%s, %s, %s, %s, %s, %s)""", (tenant, NOW, state, *job))
            if wired:
                execute(self.dsn, "INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES (%s, %s, %s)",
                        (tenant, repo_of(tenant), f"http://forge.test/{repo_of(tenant)}.git"))
        if team:
            self.forge.add_team(tenant)

    async def person(self, email: str, *tenants: str, session: bool = True) -> Any:
        """A signed-in product user, an active member of `tenants`, whose account and team places the worker made
        earlier (`p-<id>` in each tenant's team); with `session`, one Forgejo session `s-<name>` stamped 5 min ago."""
        user = await seed_user(self.identity, email, created_at=NOW, status="active", signin_account_id=f"sub-{email}")
        login = login_of(user.id)
        self.forge.add_account(login, login_name=f"sub-{email}")
        for tenant in tenants:
            await seed_membership(self.identity, user.id, tenant, status="active", invited_by=None, created_at=NOW,
                                  accepted_at=NOW)
            self.forge.team_members[(org_of(tenant), "members")].add(login)
        if session:
            self.sessions.plant(self.key(email), signed_in_data(self.forge.uid(login)),
                                signed_in_at=dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5))
        return user

    @staticmethod
    def key(email: str) -> str:
        return session_key(f"s-{email.split('@')[0]}")

    # product writes ---------------------------------------------------------------------------------
    async def end(self, user: Any, tenant: str) -> None:
        row = await self.identity.active_membership(user.id, tenant)
        assert await self.identity.end_membership(row.id, ended_by=None, now=NOW)

    async def sign_out(self, user: Any) -> None:
        """A product sign-out with no product session left (the design's `sign_out` stamps either way)."""
        await self.identity.sign_out(user.id, f"no-session-{user.id}")

    # the worker -------------------------------------------------------------------------------------
    def own_repository(self) -> Any:
        """A tenants repository of its own: on PostgreSQL a new connection set, so its lock is its own process's; the
        memory twin has one store, which is one process, so it is the world's."""
        if self.dsn is None:
            return self.tenants
        from defender.tenancy.postgres import PostgresTenantRepository

        repository = PostgresTenantRepository(self.dsn)
        self.opened.append(repository)
        return repository

    def build(self, tenants: Any = None, **config: Any) -> Any:
        """A worker over `tenants`; with none, a second process (a repository of its own, see `own_repository`)."""
        port = self.sessions_port if self.sessions_port is not None else sessions_port(self.sessions.dsn)
        cfg = dataclasses.replace(self.config, **config) if config else self.config
        return people_worker(tenants if tenants is not None else self.own_repository(), identity=self.identity,
                             forge=self.forge, sessions=port, config=cfg, clock=self.clock)

    async def step(self) -> None:
        """One poll, then every task it started (`settle()`), bounded by `SETTLE_TIMEOUT`. The case's worker is built
        here, over the world's repository, from the seams as they are now."""
        if self.worker is None or self._seams != (self.sessions_port, self.config):
            self.worker = self.build(self.tenants)
            self._seams = (self.sessions_port, self.config)
        await self.worker.poll()
        await asyncio.wait_for(self.worker.settle(), timeout=SETTLE_TIMEOUT)

    async def steps(self, n: int) -> None:
        for _ in range(n):
            await self.step()

    # observing --------------------------------------------------------------------------------------
    async def open_requests(self) -> list[tuple[str | None, str | None]]:
        """The open requests as sorted `(user, tenant)` pairs, through the port."""
        return sorted(pairs(await self.requests()).elements(), key=str)

    async def requests(self) -> list[Req]:
        return await requests_port(self.tenants)

    def log(self) -> RequestLog:
        return RequestLog(lambda: requests_port(self.tenants))


@pytest.fixture
def sessions() -> Iterator[Sessions]:
    with shipped_sessions_database() as s:
        yield s


@pytest.fixture
async def people(tmp_path: Path, data_root: Path, sessions: Sessions, caplog: Any) -> AsyncIterator[People]:
    """The memory twins over one store, `PeopleForge`, and a real sessions database."""
    from defender.identity import InMemoryIdentityRepository
    from defender.tenancy import InMemoryTenantRepository

    tenants: Any = InMemoryTenantRepository()
    world = People(tenants, InMemoryIdentityRepository(tenants=tenants), PeopleForge(tmp_path / "forge"), sessions,
                   people_config(tmp_path, data_root, sessions_dsn=sessions.dsn), Clock(), caplog=caplog)
    yield world
    await world.identity.close()


@pytest.fixture
async def pg_people(tmp_path: Path, data_root: Path, sessions: Sessions, caplog: Any) -> AsyncIterator[People]:
    """Both PostgreSQL repositories over one migrated database (the lock, the triggers' requests, the parity cases)."""
    from defender.identity.postgres import PostgresIdentityRepository
    from defender.tenancy.postgres import PostgresTenantRepository
    from defender.tests.support.shared._postgres1339 import database

    with database(migrated=True) as dsn:
        world = People(PostgresTenantRepository(dsn), PostgresIdentityRepository(dsn), PeopleForge(tmp_path / "forge"),
                       sessions, people_config(tmp_path, data_root, sessions_dsn=sessions.dsn), Clock(), dsn=dsn,
                       caplog=caplog)
        try:
            yield world
        finally:
            await world.identity.close()
            await world.tenants.close()
            for repository in world.opened:
                await repository.close()
