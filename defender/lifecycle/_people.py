"""The request worker (#1592 OD-2, OD-9, OD-12): it carries out the recorded people requests with Forgejo admin calls
and the sessions database, and runs the cap job on Forgejo's sessions. An asyncio task in the management service
process, beside the job pass, taking no tenant lock; the only writer of person accounts, the `members` teams'
membership and `prohibit_login`.

Each poll first confirms or takes the worker's one lock (`people_lock()`); without it the poll starts nothing, and on
losing it the worker cancels everything it started, which deletes no ids. Every change between holding and not
holding is one error line. Holding it, a poll reads the open requests, starts an expansion for each tenant's
(none, T) requests (one per tenant at a time), starts runs for users in turn, at most `people_concurrency` in flight
and never two for one user, and runs the cap job when it is due. A user whose runs keep failing waits ever longer
between attempts: none after the first failure, then 1, 3, 7, ... polls, at most `MAX_SKIPPED_POLLS`; a request
recorded for them since their last failed run ends the wait. It returns without waiting for what it started;
`settle()` waits."""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as _dt
import functools
import itertools
import logging
from collections.abc import Callable, Coroutine
from typing import Any

import httpx

from defender.lifecycle._eligibility import listed_logins
from defender.lifecycle._people_run import PersonRun, team_lookup
from defender.lifecycle.config import LifecycleConfig
from defender.records.formats import PeopleRequestId, TenantId, UserId, user_of

_logger = logging.getLogger(__name__)

#: The most polls a user whose runs keep failing waits between attempts (about a minute at the default poll).
MAX_SKIPPED_POLLS = 31


@dataclasses.dataclass
class _Tries:
    """A user's runs since their last one that finished (kept in the process; lost at restart, harmlessly): the last
    attempt's place in the worker's sequence, the failures in a row, the polls still to skip, and the request ids the
    last failed run took (a request outside them ends the wait)."""

    attempted: int = -1
    failures: int = 0
    wait: int = 0
    failed_on: frozenset[Any] = frozenset()

    def skips(self, rows: list[Any]) -> bool:
        """Whether this poll skips the user: while `wait` lasts, unless `rows` holds a request the failed run did not."""
        if not self.wait:
            return False
        if {r.id for r in rows} - self.failed_on:
            self.wait = 0
            return False
        self.wait -= 1
        return True

    def failed(self, rows: list[Any]) -> None:
        """After a failed run: no wait the first time, then 1, 3, 7, ... polls, at most `MAX_SKIPPED_POLLS`."""
        self.failures += 1
        self.wait = min(2 ** min(self.failures - 1, 16) - 1, MAX_SKIPPED_POLLS)
        self.failed_on = frozenset(r.id for r in rows)


class PeopleWorker:
    """`tenants` the tenancy repository (the requests, the wiring, the lock), `identity` the identity repository (the
    wanted state), `forge` an `httpx.AsyncClient` with the admin token (`_process.forge_people`), `sessions` the
    sessions port (`PostgresForgeSessions` or its twin), `clock` the time the cap job is scheduled by."""

    def __init__(self, tenants: Any, *, identity: Any, forge: httpx.AsyncClient, sessions: Any,  # noqa: PLR0913 — the pinned seams
                 config: LifecycleConfig, clock: Callable[[], _dt.datetime]) -> None:
        self.tenants, self.identity, self.forge, self.forge_sessions = tenants, identity, forge, sessions
        self.config, self._clock = config, clock
        #: None until the first poll asks: the first answer is a change either way, and is logged.
        self._holding: bool | None = None
        self._runs: dict[UserId, asyncio.Task[None]] = {}
        self._expanding: dict[TenantId, asyncio.Task[None]] = {}
        self._capping: asyncio.Task[None] | None = None
        self._last_cap: _dt.datetime | None = None
        self._tries: dict[UserId, _Tries] = {}
        self._sequence = itertools.count()
        self._tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        """`poll()` every `people_poll`, until cancelled; what it started is cancelled with it."""
        try:
            while True:
                try:
                    await self.poll()
                except Exception:  # noqa: BLE001 — a failed poll never ends the worker: the next one retries
                    _logger.exception("people worker: a poll failed")
                await asyncio.sleep(self.config.people_poll)
        finally:
            self._cancel_all()

    async def poll(self) -> None:
        """Confirm the lock, then start expansions, runs and (when due) the cap job, and return without waiting."""
        if not await self._confirm_lock():
            return
        try:
            requests = await self.tenants.open_people_requests()
        except Exception as error:  # noqa: BLE001 — the requests stay; the next poll reads them again
            _logger.error("people worker: the requests could not be read: %s", error)
            return
        self._start_expansions(requests)
        self._start_runs(requests)
        self._start_cap()

    async def cap(self) -> int:
        """The cap job once: rows signed in longer than `forge_session_cap` ago, and unstamped rows holding the `uid`
        entry, deleted with no decoding. The number deleted."""
        deleted = int(await self.forge_sessions.cap(self.config.forge_session_cap))
        if deleted:
            _logger.info("people worker: the cap job ended %d Forgejo session(s)", deleted)
        return deleted

    async def settle(self) -> None:
        """Wait for every task the worker has started (runs, expansions, the cap job)."""
        while pending := [t for t in self._tasks if not t.done()]:
            await asyncio.gather(*pending, return_exceptions=True)

    async def close(self) -> None:
        self._cancel_all()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.forge.aclose()
        await self.forge_sessions.close()

    # --- the lock (OD-12) -----------------------------------------------------------------------------------------
    async def _confirm_lock(self) -> bool:
        failure: str | None = None
        try:
            held = bool(await self.tenants.people_lock())
        except Exception as error:  # noqa: BLE001 — a lock the database cannot answer for is not held
            held, failure = False, f"the database could not be asked: {error}"
        if held != self._holding:
            self._log_change(held, failure)
            self._holding = held
        if not held:
            self._cancel_all()
        return held

    def _log_change(self, held: bool, failure: str | None) -> None:
        if held:
            _logger.error("people worker: took the people lock; carrying out the people requests")
        elif self._holding:
            _logger.error("people worker: lost the people lock (%s): its runs are cancelled, their requests kept",
                          failure or "its hold ended")
        else:
            _logger.error("people worker: standby, the people lock is not held (%s): no request is carried out",
                          failure or "another session holds it")

    def _cancel_all(self) -> None:
        for task in self._tasks:
            task.cancel()

    def _spawn(self, work: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task = asyncio.ensure_future(work)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # --- tenant requests: expansion -------------------------------------------------------------------------------
    def _start_expansions(self, requests: list[Any]) -> None:
        by_tenant: dict[TenantId, list[Any]] = {}
        for request in requests:
            if request.user_id is None and request.tenant_id is not None:
                by_tenant.setdefault(request.tenant_id, []).append(request)
        for tenant, rows in by_tenant.items():
            if tenant not in self._expanding:
                task = self._spawn(self._expand(tenant, rows))
                self._expanding[tenant] = task
                task.add_done_callback(functools.partial(_forget, self._expanding, tenant))

    async def _expand(self, tenant: TenantId, rows: list[Any]) -> None:
        """(none, T) becomes (U, T) for every user with any membership row of T and every well-formed `p-<id>` login in
        T's team, at the (none, T) request's own `requested_at`, in one transaction that deletes the (none, T) rows."""
        try:
            users = await self._people_of(tenant)
            if not self._holding:
                return
            await self.tenants.edit_people_requests(
                delete=[PeopleRequestId(r.id) for r in rows], add=[(u, tenant) for u in sorted(users)],
                requested_at=min(r.requested_at for r in rows))
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 — the (none, T) request stays and is expanded at a later poll
            _logger.error("people request of tenant %s: expansion failed, retried at a later poll: %s", tenant, error)

    async def _people_of(self, tenant: TenantId) -> set[UserId]:
        team = await team_lookup(self.tenants, self.forge, tenant)
        logins = [] if team is None else await listed_logins(
            self.forge, f"/api/v1/teams/{team}/members", f"the members of tenant {tenant}'s team")
        users = {m.user_id for m in await self.identity.memberships_of_tenant(tenant)}
        for login in logins:
            user = user_of(login)
            if user is None:
                _logger.warning("people request of tenant %s: the team login %s is not p-<user id>: left as it is",
                                tenant, login)
            else:
                users.add(user)
        return users

    # --- user requests: runs (OD-9) -------------------------------------------------------------------------------
    def _start_runs(self, requests: list[Any]) -> None:
        by_user: dict[UserId, list[Any]] = {}
        for request in requests:
            if request.user_id is not None:
                by_user.setdefault(request.user_id, []).append(request)
        due = [u for u in by_user if u not in self._runs and not (u in self._tries and self._tries[u].skips(by_user[u]))]
        waiting = sorted(due, key=lambda u: self._turn(u, by_user[u]))
        for user in waiting[:max(0, self.config.people_concurrency - len(self._runs))]:
            self._tries.setdefault(user, _Tries()).attempted = next(self._sequence)
            task = self._spawn(self._run(user, by_user[user]))
            self._runs[user] = task
            task.add_done_callback(functools.partial(_forget, self._runs, user))

    def _turn(self, user: UserId, rows: list[Any]) -> tuple[int, _dt.datetime]:
        """Users never attempted first, by their oldest request; then by their last attempt, oldest first."""
        return (self._tries[user].attempted if user in self._tries else -1, min(r.requested_at for r in rows))

    async def _run(self, user: UserId, rows: list[Any]) -> None:
        """Carry out the requests `rows` of `user` and delete exactly their ids if every step succeeded; a request
        recorded after they were read stays for a later run."""
        named = {r.tenant_id for r in rows if r.tenant_id is not None}
        try:
            done = await PersonRun(self, user, named).carry_out()
            if done and self._holding:
                await self.tenants.edit_people_requests(delete=[PeopleRequestId(r.id) for r in rows])
                self._tries.pop(user, None)
                return
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 — the requests stay; the user goes to the back
            _logger.error("people request of user %s: the run failed, retried at a later poll: %s", user, error)
        self._tries.setdefault(user, _Tries()).failed(rows)

    # --- the cap job ------------------------------------------------------------------------------------------------
    def _start_cap(self) -> None:
        """At the first poll that holds the lock, then at the first poll `forge_cap_every` after the last run began."""
        now = self._clock()
        if self._capping is not None and not self._capping.done():
            return
        if self._last_cap is not None and now - self._last_cap < _dt.timedelta(seconds=self.config.forge_cap_every):
            return
        self._last_cap = now
        self._capping = self._spawn(self._cap_logged())

    async def _cap_logged(self) -> None:
        try:
            await self.cap()
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 — the cap job runs again when next due
            _logger.error("people worker: the cap job on Forgejo's sessions failed: %s", error)


def _forget(table: dict[Any, asyncio.Task[None]], key: Any, task: asyncio.Task[None]) -> None:
    """A finished task leaves the table it was entered in (a run's user, an expansion's tenant)."""
    if table.get(key) is task:
        del table[key]
