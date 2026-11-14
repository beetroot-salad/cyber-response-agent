"""The mail port for a server with no mail relay: each notice goes to the log, naming what would have been sent."""

from __future__ import annotations

import datetime as _dt
import logging

from defender.records.formats import CredentialId, MembershipId, ProgramId, TenantId

_logger = logging.getLogger(__name__)


class LoggedMail:
    """Writes the two notices the identity service mails (an existing user's invitation, a credential's expiry
    warning) to the log. Dev only: a real mail sender comes with production (#1083 N10)."""

    async def notify_invitation(self, to: str, tenant_id: TenantId, invitation_id: MembershipId) -> None:
        _logger.info("invitation %s to %s for tenant %s (not sent: no mail relay)", invitation_id, to, tenant_id)

    async def notify_credential_expiry(
        self, to: str, tenant_id: TenantId, program_id: ProgramId, credential_id: CredentialId,
        expires_at: _dt.datetime,
    ) -> None:
        _logger.info("credential %s of program %s expires %s; warning to %s for tenant %s (not sent: no mail relay)",
                     credential_id, program_id, expires_at.isoformat(), to, tenant_id)
