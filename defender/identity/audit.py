"""Identity and administrator actions as structured log events (K11).

One dedicated logger, written after the change commits. The API cannot read the audit back;
retention belongs to the deployment. An event can be lost in a crash between the commit and
this write, which the design accepts."""

from __future__ import annotations

import logging
from typing import Literal

AuditAction = Literal[
    "member.invite", "invitation.accept", "member.remove", "invitation.revoke",
    "admin.tenants.list", "admin.invite", "admin.flag.set", "admin.flag.clear",
]

SYSTEM = "system"
_audit = logging.getLogger("defender.identity.audit")


def emit(action: AuditAction, *, actor: str, tenant_id: str | None, target: str | None) -> None:
    _audit.info(
        "%s", action,
        extra={"action": action, "actor": actor, "tenant_id": tenant_id, "target": target})
