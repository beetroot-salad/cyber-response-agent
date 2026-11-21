"""The census findings `tenant.py check --folder` reports about a tenant repo (#1366 O1, O9; #1471).

Re-exported from `learning.leads.tenant_census`, which holds them so the readiness container entry (`run.py`, below
`cli`) can ask them too, plus the retired parts a repo still holds (`leftover_findings`, O9): the retired
`settings/systems/` folder, `settings/case-record.yaml` and `settings/lead-zero.yaml`, reported, never opened. A
tenant's stored records are judged by the readiness check, which asks the launch itself."""
from __future__ import annotations

from pathlib import Path

from defender.learning.leads.tenant_census import (
    feedback_findings,
    registry_findings,
    registry_grant_findings,
    retired_findings,
)
from defender.tenancy import SETTINGS_HALF


def leftover_findings(knowledge: Path) -> list[str]:
    """O9: the retired parts a tenant repo's `settings/` still holds (`retired_findings`)."""
    return retired_findings(Path(knowledge) / SETTINGS_HALF)


__all__ = [
    "feedback_findings",
    "leftover_findings",
    "registry_findings",
    "registry_grant_findings",
]
