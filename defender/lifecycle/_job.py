"""The job both actors work (#1214 P6, DC-3, DC-4, DC-14): the step lists, and one pass.

A pass (`Actor.work`) takes up every tenant whose current step is the actor's, with no failure,
that no other worker holds: it takes the tenant's lock (`TenantRepository.lock`, which re-reads the
row on the lock's own connection), checks the re-read row, and runs steps while they stay the
actor's. Each step body ends with ONE fenced commit through the hold (`HeldTenant.commit`) that
records what it learnt and names the next step; handing to the other actor is committing a step of
theirs. A step's exception becomes the tenant's failure with the step's restart point, and the pass
goes on with the next tenant. A fence that misses (`FenceMissed`: the job moved, or the lock's
connection failed) ends the work on the tenant with nothing more written, a failure included.

Failure text names the step and the external answer (status and message), never a secret: every
secret value a step handles is registered with `Actor.secret` and blanked out of the text."""
from __future__ import annotations

import datetime as _dt
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

import httpx

from defender.tenancy import FenceMissed, Generation, HeldTenant, TenantRepository, claimable_now

_logger = logging.getLogger(__name__)

SERVICE, HOST = "service", "host"
#: Each action's step list (DC-3): step -> the step after it and its actor; (None, None) ends it.
NEXT: Mapping[str, Mapping[str, tuple[str | None, str | None]]] = {
    "create": {
        "names": ("provider", SERVICE), "provider": ("repo", SERVICE), "repo": ("bot", SERVICE),
        "bot": ("integration", SERVICE), "integration": ("template", SERVICE), "template": ("wrap", SERVICE),
        "wrap": ("install", HOST), "install": ("sweep", SERVICE), "sweep": ("prepare", HOST),
        "prepare": ("activate", SERVICE), "activate": (None, None)},
    "rotate": {
        "names": ("provider", SERVICE), "provider": ("bot", SERVICE), "bot": ("integration", SERVICE),
        "integration": ("wrap", SERVICE), "wrap": ("install", HOST), "install": ("sweep", SERVICE),
        "sweep": ("retire", SERVICE), "retire": ("remove_old_file", HOST), "remove_old_file": (None, None)},
    "offboard": {"offboard": ("teardown", HOST), "teardown": ("finish", SERVICE), "finish": ("delete_repo", SERVICE)},
    "delete_repo": {"delete_repo": (None, None)},
}
#: The longest failure text recorded.
_FAILURE_LIMIT = 600


def _storable(text: str) -> str:
    """`text` as the database stores it: no NUL (PostgreSQL text refuses it) and no character UTF-8
    cannot encode (a lone surrogate from an external answer), each replaced by `?`. The failure is
    always recorded, whatever the external answer carried."""
    return text.replace("\x00", "?").encode("utf-8", errors="replace").decode("utf-8")


def next_step(held: HeldTenant) -> tuple[str | None, str | None]:
    """The step after the held tenant's current one, and its actor."""
    record = held.record
    return NEXT[str(record.pending_action)][str(record.step)]


class StepFailed(Exception):
    """A step met an answer it cannot go on from. The message is the failure's text (after the
    step's name); `restart` is the restart point (step, actor) when it is not the step itself
    (DC-4: an install that unwrapped restarts at `wrap`)."""

    def __init__(self, message: str, *, restart: tuple[str, str] | None = None) -> None:
        super().__init__(message)
        self.restart = restart


def answered(response: httpx.Response, *ok: int) -> httpx.Response:
    """`response` when its status is a success or one of `ok`, else `StepFailed` naming the call,
    the status and the answer's message."""
    if response.is_success or response.status_code in ok:
        return response
    request = response.request
    raise StepFailed(f"{request.method} {request.url.path} answered {response.status_code}{_message(response)}")


def _message(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return ""
    said: Any = body.get("message") or body.get("errors") if isinstance(body, dict) else None
    if isinstance(said, list):
        said = "; ".join(str(s) for s in said)
    return f": {said}" if said else ""


def field_of(response: httpx.Response, *path: str) -> Any:
    """The value at `path` in the answer's JSON, or `StepFailed` naming what is missing."""
    try:
        value: Any = response.json()
    except ValueError:
        value = None
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    if value is None:
        request = response.request
        raise StepFailed(f"{request.method} {request.url.path} answered no {'.'.join(path)}")
    return value


def only(generations: list[Generation], status: str) -> Generation:
    """The tenant's one generation in `status`, or `StepFailed`."""
    found = [g for g in generations if g.status == status]
    if len(found) != 1:
        raise StepFailed(f"expected one {status} generation, found {len(found)}")
    return found[0]


Step = Callable[[HeldTenant], Awaitable[None]]


class Actor:
    """One pass of the job for one actor (`SERVICE` or `HOST`); subclasses name their steps."""

    actor: str = ""

    def __init__(self, tenants: TenantRepository, *, clock: Callable[[], _dt.datetime],
                 secrets: tuple[str, ...] = ()) -> None:
        self._tenants = tenants
        self._clock = clock
        self._standing_secrets = tuple(s for s in secrets if s)
        self._secrets: set[str] = set()

    def steps(self) -> Mapping[str, Step]:
        raise NotImplementedError

    def secret(self, value: str) -> str:
        """Register `value` as a secret of the running step (kept out of its failure text)."""
        if value:
            self._secrets.add(value)
        return value

    async def work(self) -> int:
        """One pass (DC-14): the number of steps run, failed ones included. A tenant whose lock cannot
        be taken or given back (its connection failed) is logged and left for the next pass."""
        ran = 0
        for tenant_id in await self._tenants.claimable(self.actor, now=self._clock()):
            try:
                async with self._tenants.lock(tenant_id) as held:
                    if held is None or not claimable_now(held.record, self.actor, self._clock()):
                        continue  # another worker holds it, or the job moved since the listing
                    ran += await self._run(held)
            except Exception:  # noqa: BLE001 — one tenant's lock failing never ends the pass for the others
                _logger.exception("tenant %s: the %s could not work on it this pass", tenant_id, self.actor)
        return ran

    async def _run(self, held: HeldTenant) -> int:
        ran = 0
        steps = self.steps()
        while claimable_now(held.record, self.actor, self._clock()):
            step = str(held.record.step)
            self._secrets = set()
            try:
                body = steps.get(step)
                if body is None:
                    raise StepFailed(f"the {self.actor} has no step {step!r}")
                await body(held)
            except FenceMissed as missed:
                _logger.warning("tenant %s: %s stopped at %s: %s", held.tenant_id, self.actor, step, missed)
                return ran + 1
            except Exception as failed:  # noqa: BLE001 — DC-14: any step failure becomes the tenant's failure
                await self._record_failure(held, step, failed)
                return ran + 1
            ran += 1
        return ran

    async def _record_failure(self, held: HeldTenant, step: str, failed: Exception) -> None:
        restart = failed.restart if isinstance(failed, StepFailed) and failed.restart else (step, self.actor)
        text = self._failure_text(step, failed)
        _logger.error("tenant %s: %s step %s failed: %s", held.tenant_id, self.actor, step, text)
        try:
            await held.fail(text, step=restart[0], actor=restart[1])
        except FenceMissed as missed:
            _logger.warning("tenant %s: the failure of %s was not recorded: %s", held.tenant_id, step, missed)
        except Exception:  # noqa: BLE001 — recording a failure never ends the pass: the other tenants are still served
            _logger.exception("tenant %s: the failure of %s could not be recorded", held.tenant_id, step)

    def _failure_text(self, step: str, failed: Exception) -> str:
        said = str(failed) if isinstance(failed, StepFailed) else f"{type(failed).__name__}: {failed}"
        text = _storable(f"{step}: {said}".replace("\n", " ")).strip()
        for secret in sorted({*self._secrets, *self._standing_secrets}, key=len, reverse=True):
            text = text.replace(secret, "<secret>")
        return text if len(text) <= _FAILURE_LIMIT else text[:_FAILURE_LIMIT - 3] + "..."
