"""#1106 — ONE run's tenant, resolved once at the entry point and handed inward as one value.

WHY A BUNDLE. Everything a run takes from its tenant — the folder, the grants projected from its
table, item 3's dispatch identity — is read from files an operator can edit at any moment. Read
in pieces (the entry point checks the table, the driver re-reads the lead-zero config, a
registry re-coalesces a missing grant), each piece can see a different file and each gap is
filled a different way. Resolved here, once, before the box and before any model call, every
later frame takes the VALUE and reads nothing again; there is no "no grant handed in" case left
to handle.

`resolve_run_tenant` is also where the run-start refusals live (D3, M5), each one naming the
file an operator edits. It raises; the entry point (`run.py`) and the replay harness decide how
a refusal is reported.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from defender._corpus import QueryTemplate, iter_query_templates, query_catalog_dir
from defender._tenants import TenantDir
from defender.runtime.verb_dispositions import RunGrants, require_gather_query, run_grants
from defender.runtime.verb_grant import VerbGrant

if TYPE_CHECKING:
    from defender.runtime.lead_zero import CorrelationDispatch


def table_pointer(tenant_id: str) -> str:
    """The MODEL-FACING name of a tenant's verb-disposition table — what a DENIED refusal and
    ORIENT's withheld-lead note say. It names the tenant and the file inside its folder, never
    the resolved host path: the settings half is host-only, and the host's layout (and the
    prompt prefix built over it) must not change with the machine the run is on. Operator
    messages print `RunGrants.path` instead."""
    return f"settings/verb-grants.yaml of tenant {tenant_id!r}"


@dataclasses.dataclass(frozen=True)
class RunTenant:
    """One run's tenant: its folder, its grants, and item 3's dispatch identity.

    `correlation` is `None` for a run resolved as one that dispatches no lead-zero (a resumed
    sibling world: turn-0 work is skipped), and otherwise the identity the run-start agreement
    check stood behind (#1003) — a `CorrelationDispatch` whose `system` is `None` when the
    table withholds the lead."""

    dir: TenantDir
    grants: RunGrants
    correlation: CorrelationDispatch | None

    @property
    def tenant_id(self) -> str:
        return self.dir.tenant_id

    @property
    def settings(self) -> Path:
        return self.dir.settings

    @property
    def agent(self) -> Path:
        return self.dir.agent

    @property
    def table_pointer(self) -> str:
        """This tenant's table as the model is told of it (`table_pointer`)."""
        return table_pointer(self.tenant_id)


def catalog_templates(defender_dir: Path) -> list[QueryTemplate]:
    """The query catalog of the tree a run reads, walked once."""
    return list(iter_query_templates(query_catalog_dir(defender_dir)))


def correlation_dispatch(
    settings: Path, templates: Iterable[QueryTemplate], grant: VerbGrant,
) -> CorrelationDispatch:
    """Item 3's dispatch identity for one tenant: its `lead-zero.yaml` id, resolved against
    `templates` and checked for agreement with `grant`, its table's correlation grant (#1003).
    Raises `LeadZeroConfigError`, `CorrelationDispatchError` or `GrantError`, each naming the
    file."""
    from defender.runtime import lead_zero as lead_zero_mod
    from defender.runtime.lead_zero_config import lead_zero_config_path, load_correlation_template

    return lead_zero_mod.resolve_correlation_dispatch(
        load_correlation_template(lead_zero_config_path(settings)), templates, grant,
    )


def refusals() -> tuple[type[Exception], ...]:
    """Every exception `resolve_run_tenant` refuses a tenant with — each names the file an
    operator edits, so a caller reports `str(e)` and needs no per-kind wording."""
    from defender.runtime.lead_zero import CorrelationDispatchError
    from defender.runtime.lead_zero_config import LeadZeroConfigError
    from defender.runtime.verb_dispositions import DispositionError
    from defender.runtime.verb_grant import GrantError

    return (DispositionError, LeadZeroConfigError, CorrelationDispatchError, GrantError)


def resolve_run_tenant(
    tenant: TenantDir, *, defender_dir: Path, dispatches_lead_zero: bool,
) -> RunTenant:
    """Load `tenant`'s grants and check them, before the run dir, the box and any model call.

    Refused (one of `refusals()`): a table that does not load; one under which gather can
    query nothing (`require_gather_query` — a `health-check` grant alone reaches no data); and,
    when `dispatches_lead_zero`, a lead-zero config the catalog or the table disagrees with.
    `dispatches_lead_zero` is False for a resumed sibling: it dispatches no turn-0 lead, so a
    template demoted since the source run must not refuse it."""
    grants = run_grants(tenant.settings)
    require_gather_query(grants)
    correlation = (
        correlation_dispatch(tenant.settings, catalog_templates(defender_dir), grants.correlation)
        if dispatches_lead_zero else None
    )
    return RunTenant(dir=tenant, grants=grants, correlation=correlation)


__all__ = [
    "RunTenant",
    "catalog_templates",
    "correlation_dispatch",
    "refusals",
    "resolve_run_tenant",
    "table_pointer",
]
