"""The job store's audit events: structured log events on their own logger, emitted after the
change commits (O13). An event can be lost in a crash between the commit and this write, which the
design accepts. Beside `identity.audit`; the API's list of actions is amended to match."""

from __future__ import annotations

import logging
from typing import Literal

from defender import _log
from defender.identity.audit import SYSTEM

AuditAction = Literal[
    "investigation.start", "investigation.cancel", "investigation.delete", "investigation.claim",
    "investigation.finish", "investigation.takeover", "investigation.retry", "alert_mapping.update",
    "learning_job.start", "learning_job.claim", "learning_job.finish", "learning_job.takeover", "learning_job.retry",
    "learning_post_step",
]

__all__ = ["SYSTEM", "AuditAction", "announce"]

_audit = logging.getLogger("defender.jobs.audit")


def announce(
    action: AuditAction, *, actor: str, tenant_id: str, target: str, detail: str | None = None,
    credential_id: str | None = None,
) -> None:
    """Write one audit event; `credential_id` is the program credential the actor's request came in on, if any. The tenant is bound to the log scope while it is written (#1342
    r7 D-ag): the formatter drops a tenant id passed as a plain extra, so the line would carry
    only whatever tenant its caller had bound."""
    with _log.log_context(tenant_id=tenant_id):
        _audit.info(
            "%s", action,
            extra={"action": action, "actor": actor, "tenant_id": tenant_id, "target": target, "detail": detail,
                   "credential_id": credential_id})
