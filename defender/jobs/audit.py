"""The job store's audit events: structured log events on their own logger, emitted after the
change commits (O13). An event can be lost in a crash between the commit and this write, which the
design accepts. Beside `identity.audit`; the API's list of actions is amended to match."""

from __future__ import annotations

import logging
from typing import Literal

from defender.identity.audit import SYSTEM

AuditAction = Literal[
    "investigation.start", "investigation.cancel", "investigation.delete", "investigation.claim",
    "investigation.finish",
]

__all__ = ["SYSTEM", "AuditAction", "announce"]

_audit = logging.getLogger("defender.jobs.audit")


def announce(action: AuditAction, *, actor: str, tenant_id: str, target: str, detail: str | None = None) -> None:
    _audit.info(
        "%s", action,
        extra={"action": action, "actor": actor, "tenant_id": tenant_id, "target": target, "detail": detail})
