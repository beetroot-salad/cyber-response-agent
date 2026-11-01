"""The tenant's last publish outcome (#1108 P4 O-SEE), kept in PostgreSQL (`tenancy.publish_status`,
#1214 O6) and reached through the host's `TenantDirectory`.

Every publish trigger records its outcome — the refusal with its kind (`transient`, an outage that
may pass by itself, or `operator`, one that needs a human), or the commit it published (which
clears the refusal) — so `tenant.py check` can say why `current` trails `origin/main` instead of
staying silent. Host processes write it (P2): the publish child, the run launcher for the outcomes
only it sees (a publish child that crashed or was stopped), the drains and the connect command, all
through the same `record_report`. Best effort: an outcome that cannot be recorded is logged, and
never hides or changes the outcome itself.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from defender._text import one_line

if TYPE_CHECKING:
    from defender.tenancy._directory import TenantDirectory

_logger = logging.getLogger(__name__)

TRANSIENT = "transient"
OPERATOR = "operator"
#: The launch-time publish's report vocabulary (OD2): each line's first word. Defined once here,
#: below both the child that writes a line and run start that reads it.
FRESH = "fresh"
STALE_PREFIX = "stale:"
STALE_TRANSIENT = f"{STALE_PREFIX}{TRANSIENT}"
STALE_OPERATOR = f"{STALE_PREFIX}{OPERATOR}"
MISCONFIGURED = "misconfigured"


def record_report(directory: TenantDirectory | None, tenant_id: object, line: str, *, by: str) -> None:
    """The outcome a launch-time publish report `line` states, recorded as `by`'s: `fresh`
    publishes its commit; `stale:transient` is a transient refusal; `stale:operator` and
    `misconfigured` need a human. The one recorder for every trigger, so the recorded outcome is
    always the reported one. With no directory (an in-process caller that has none) nothing is
    recorded."""
    if directory is None:
        return
    tenant = str(tenant_id)
    try:
        directory._call(lambda repository: repository.record_publish_status(tenant, line, by=by))  # noqa: SLF001 — this package's own facade
    except Exception:  # noqa: BLE001 — best effort: a status that cannot be written never hides the outcome
        _logger.warning("the publish outcome of tenant %s could not be recorded", tenant, exc_info=True)


def record_published(directory: TenantDirectory | None, tenant_id: object, commit: str, *, by: str) -> None:
    """A publish by `by` (the trigger) succeeded at `commit`: any earlier refusal is over."""
    record_report(directory, tenant_id, f"{FRESH} {commit}", by=by)


def record_refusal(directory: TenantDirectory | None, tenant_id: object, *, kind: str, reason: str,
                   by: str) -> None:
    """A publish by `by` was refused: `kind` (`TRANSIENT` or `OPERATOR`) and why."""
    if kind not in (TRANSIENT, OPERATOR):
        raise ValueError(f"{kind!r} is not a publish refusal kind")
    record_report(directory, tenant_id, f"{STALE_PREFIX}{kind} {one_line(reason)}", by=by)


def read_status(directory: TenantDirectory, tenant_id: object) -> dict[str, Any] | None:
    """The last publish outcome recorded (`by`, then `published`, or `refused` with `kind`), or
    `None` when none is."""
    tenant = str(tenant_id)
    return directory._call(lambda repository: repository.publish_status(tenant))  # noqa: SLF001 — this package's own facade
