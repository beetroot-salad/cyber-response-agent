"""Carrying out one person's people requests (#1592 "The request worker"): the step table, run from the current wanted
state, removals before grants. Each step runs only when every input it needs was read; a failed or skipped step is
logged with the user, the tenant and the step, and keeps the requests.

| Step | Does | Needs |
| R | `wanted_tenants(U)`, sub, `signed_out_at` | - |
| A | `GET /users/p-<U>`: absent, or its id and `prohibit_login` | - |
| L(T) | T's team `members`: found, absent or failed | - |
| 1 | remove `p-<U>` from each named T where U is not wanted (404 is done) | R, L(T) |
| 2 | suspend, when U is wanted nowhere and the account exists | R, A |
| 3 | delete U's stamped sessions: all when wanted nowhere, else those before `signed_out_at` | R, A, sessions |
| 4 | create the account, when U is wanted somewhere and has none | R, A |
| 5 | the account's standing, when U is wanted somewhere: unsuspended and limited, sent on every run | R, A or 4 |
| 6 | add `p-<U>` to each named T where U is wanted (an absent team is an error) | R, 5, L(T) |

Step 5 is sent whatever the account reads, so an account whose limits were never set (step 4's creation ignores
them, P20) is limited by the next run, and nobody joins a team before their account's standing is set in that run.
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as _dt
import functools
import logging
from collections.abc import Awaitable, Callable, Collection
from typing import Any

import httpx

from defender.lifecycle._eligibility import single_team_id, teams_named
from defender.lifecycle._job import StepFailed, answered
from defender.lifecycle._sessions import SessionRow, UnreadableSession, session_uid
from defender.records.formats import TenantId, UserId, login_of

#: The team of a tenant's organisation that holds its people (and alone may merge `main`, #1163 A23 amended).
MEMBERS = "members"

_logger = logging.getLogger(__name__)


async def team_lookup(tenants: Any, forge: httpx.AsyncClient, tenant: TenantId) -> int | None:
    """T's team `members`: its id when found; None when absent (T has no wiring, its organisation answers 404, or no
    team is named exactly `members`). Any other answer raises (the lookup failed)."""
    wiring = await tenants.forge_wiring(tenant)
    if wiring is None:
        return None
    org = wiring.repo.split("/", 1)[0]
    named = await teams_named(forge, org, MEMBERS, absent_org_ok=True)
    return single_team_id(named, org, MEMBERS) if named else None


@dataclasses.dataclass(frozen=True)
class Wanted:
    """Step R: where U is wanted, U's sub and display name, and when U last signed out of the product."""

    tenants: frozenset[TenantId]
    sub: str | None
    display_name: str
    signed_out_at: _dt.datetime | None


@dataclasses.dataclass
class Account:
    """U's Forgejo account as step A read it (or step 4 made it)."""

    uid: int | None
    prohibit_login: bool


#: An input that could not be read.
FAILED = object()


class PersonRun:
    """One run of one user's requests over the worker's seams (`ports`: tenants, identity, forge, forge_sessions, config).
    `carry_out()` is True when every step succeeded."""

    def __init__(self, ports: Any, user: UserId, named: Collection[TenantId]) -> None:
        self._p = ports
        self._user = user
        self._login = login_of(user)
        self._named = sorted(named)
        self._ok = True

    async def carry_out(self) -> bool:
        wanted = await self._step("R", None, self._wanted)
        if wanted is FAILED:
            return False
        account = await self._step("A", None, self._account)
        teams = {t: await self._step("L", t, functools.partial(team_lookup, self._p.tenants, self._p.forge, t))
                 for t in self._named}
        await self._removals(wanted, account, teams)
        await self._grants(wanted, account, teams)
        return self._ok

    # --- reading the inputs ---------------------------------------------------------------------------------------
    async def _step(self, step: str, tenant: TenantId | None, act: Callable[[], Awaitable[Any]]) -> Any:
        """One input read or step: its result, or FAILED (logged) when it raised."""
        try:
            return await act()
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 — any failure is that input's: the steps needing it are skipped
            self._failed(step, tenant, error)
            return FAILED

    def _failed(self, step: str, tenant: TenantId | None, error: BaseException | str) -> None:
        self._missed(step, tenant, f"failed, retried at a later poll: {error}")

    def _skipped(self, step: str, tenant: TenantId | None = None) -> None:
        self._missed(step, tenant, "skipped: an input it needs failed")

    def _missed(self, step: str, tenant: TenantId | None, how: str) -> None:
        self._ok = False
        where = f" for tenant {tenant}" if tenant is not None else ""
        _logger.error("people request of user %s: step %s%s %s", self._user, step, where, how)

    async def _wanted(self) -> Wanted:
        tenants = await self._p.identity.wanted_tenants(self._user)
        user = await self._p.identity.user(self._user)
        if user is None:
            return Wanted(frozenset(), None, "", None)
        return Wanted(frozenset(tenants), user.signin_account_id, user.display_name, user.signed_out_at)

    async def _account(self) -> Account | None:
        found = await self._p.forge.get(f"/api/v1/users/{self._login}")
        if found.status_code == 404:
            return None
        body = answered(found).json()
        uid = body.get("id") if isinstance(body, dict) else None
        if not isinstance(uid, int) or isinstance(uid, bool):
            raise StepFailed(f"the account {self._login} answered no numeric id")
        return Account(uid, body.get("prohibit_login") is True)

    # --- removals: steps 1, 2, 3 ----------------------------------------------------------------------------------
    async def _removals(self, wanted: Wanted, account: Any, teams: dict[TenantId, Any]) -> None:
        for tenant in self._named:
            if tenant not in wanted.tenants:
                await self._remove(tenant, teams[tenant])
        nowhere = not wanted.tenants
        if account is FAILED:
            if nowhere or wanted.signed_out_at is not None:
                self._skipped("2/3")
            return
        if nowhere and account is not None and not account.prohibit_login \
                and await self._step("2", None, self._suspend) is not FAILED:
            account.prohibit_login = True
        if account is not None and (nowhere or wanted.signed_out_at is not None):
            await self._step("3", None, lambda: self._end_sessions(wanted, account))

    async def _remove(self, tenant: TenantId, team: Any) -> None:
        if team is FAILED:
            self._skipped("1", tenant)
        elif team is not None:
            await self._step("1", tenant, lambda: self._call(
                "DELETE", f"/api/v1/teams/{team}/members/{self._login}", 404))

    async def _suspend(self) -> None:
        await self._call("PATCH", f"/api/v1/admin/users/{self._login}", json={"prohibit_login": True})

    async def _end_sessions(self, wanted: Wanted, account: Account) -> None:
        rows = await self._p.forge_sessions.signed_in_rows()
        gone: list[str] = []
        unreadable: list[SessionRow] = []
        for row in rows:
            try:
                uid = session_uid(row.data)
            except UnreadableSession:
                unreadable.append(row)
                continue
            if uid == account.uid and (not wanted.tenants or (
                    wanted.signed_out_at is not None and row.signed_in_at < wanted.signed_out_at)):
                gone.append(row.key)
        await self._p.forge_sessions.delete([*gone, *(r.key for r in unreadable)])
        for row in unreadable:
            _logger.warning("people request of user %s: deleted an unreadable Forgejo session signed in at %s",
                            self._user, row.signed_in_at.isoformat())

    # --- grants: steps 4, 5, 6 ------------------------------------------------------------------------------------
    async def _grants(self, wanted: Wanted, account: Any, teams: dict[TenantId, Any]) -> None:
        if not wanted.tenants:
            return
        if account is FAILED:
            self._skipped("4/5/6")
            return
        if account is None:
            account = await self._step("4", None, lambda: self._create(wanted))
        if account is FAILED:
            self._skipped("5")
        elif await self._step("5", None, self._standing) is FAILED:
            account = FAILED
        for tenant in self._named:
            if tenant in wanted.tenants:
                await self._add(tenant, account, teams[tenant])

    async def _create(self, wanted: Wanted) -> Account:
        """Step 4: the person account, restricted at creation (P20); step 5 then sets the limits creation ignores."""
        if not wanted.sub:
            raise StepFailed("the user is wanted but has no sign-in account (sub): no Forgejo account is made")
        await self._call("POST", "/api/v1/admin/users", json={
            "username": self._login, "login_name": wanted.sub, "source_id": self._p.config.keycloak_source_id,
            "restricted": True, "must_change_password": False, "email": f"{self._login}@people.invalid",
            "full_name": wanted.display_name})
        return Account(None, prohibit_login=False)

    async def _standing(self) -> None:
        """Step 5: a wanted person's account may sign in, and may create no repository or organisation."""
        await self._call("PATCH", f"/api/v1/admin/users/{self._login}",
                         json={"prohibit_login": False, "max_repo_creation": 0, "allow_create_organization": False})

    async def _add(self, tenant: TenantId, account: Any, team: Any) -> None:
        if account is FAILED or team is FAILED:
            self._skipped("6", tenant)
        elif team is None:
            self._failed("6", tenant, f"tenant {tenant} has no team {MEMBERS} to add {self._login} to")
        else:
            await self._step("6", tenant, lambda: self._call("PUT", f"/api/v1/teams/{team}/members/{self._login}"))

    async def _call(self, method: str, path: str, *ok: int, json: dict[str, Any] | None = None) -> None:
        answered(await self._p.forge.request(method, path, json=json), *ok)
