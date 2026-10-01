"""One run's tenant, resolved once at the entry point and handed inward as one value.

The accepted tenant (`_tenant.accept_tenant`), its grants and item 3's dispatch identity come
from operator-editable files. Resolving them once, before the box and any model call, means
every later frame sees the same values instead of re-reading files that may have changed.

`resolve_run_tenant` is run start's readiness function: it holds the run-start refusals, each
naming the file an operator edits. `tenant.py setup` calls the same function, so a tenant setup
passes is one a run can start with.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from defender._corpus import QueryTemplate, iter_query_templates, query_catalog_dir
from defender._tenant import Tenant, TenantId, TenantRefused, accept_tenant
from defender.runtime.verb_dispositions import RunGrants, require_gather_query, run_grants
from defender.runtime.verb_grant import GrantError, VerbGrant

if TYPE_CHECKING:
    from defender.runtime.lead_zero import CorrelationDispatch


def table_pointer(tenant_id: str) -> str:
    """The model-facing name of a tenant's verb-disposition table. Never the resolved host
    path: the settings half is host-only and the prompt must not vary by machine. Operator
    messages print `RunGrants.path` instead."""
    from defender.runtime.verbs import TABLE_POINTER

    return f"{TABLE_POINTER}, tenant {tenant_id!r}"


@dataclasses.dataclass(frozen=True)
class RunReadiness:
    """What run start's readiness function establishes about a tenant's settings: its grants,
    and item 3's dispatch identity (`None` for a run that dispatches no lead zero)."""

    grants: RunGrants
    correlation: CorrelationDispatch | None


@dataclasses.dataclass(frozen=True)
class RunTenant:
    """One run's tenant: the accepted `Tenant`, its grants, and item 3's dispatch identity.

    `correlation` is `None` for a run that dispatches no lead zero (a resumed sibling),
    otherwise the checked `CorrelationDispatch`, whose `system` is `None` when the table
    withholds the lead."""

    tenant: Tenant
    grants: RunGrants
    correlation: CorrelationDispatch | None

    @property
    def tenant_id(self) -> TenantId:
        return self.tenant.id

    @property
    def settings(self) -> Path:
        return self.tenant.settings

    @property
    def agent(self) -> Path:
        return self.tenant.agent

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
    `templates` and checked for agreement with `grant`, its table's correlation grant.
    Raises `LeadZeroConfigError`, `CorrelationDispatchError` or `GrantError`, each naming the
    file an operator edits — `lead-zero.yaml` — whichever of the three disagrees."""
    from defender.runtime import lead_zero as lead_zero_mod
    from defender.runtime.lead_zero_config import lead_zero_config_path, load_correlation_template

    config = lead_zero_config_path(settings)
    template_id = load_correlation_template(config)
    return lead_zero_mod.resolve_correlation_dispatch(
        template_id, templates, grant, source=config)


def refusals() -> tuple[type[Exception], ...]:
    """Every exception `resolve_run_tenant` refuses a tenant with — each names the file an
    operator edits, so a caller reports `str(e)` and needs no per-kind wording."""
    from defender.runtime.lead_zero import CorrelationDispatchError
    from defender.runtime.lead_zero_config import LeadZeroConfigError
    from defender.runtime.verb_dispositions import DispositionError

    return (DispositionError, LeadZeroConfigError, CorrelationDispatchError, GrantError)


def resolve_tenant(
    data_root: Path, tenant_id: str, *, defender_dir: Path, dispatches_lead_zero: bool,
    box_mounted: tuple[Path, ...] = (),
) -> RunTenant:
    """`tenant_id` under `data_root`, accepted and ready to run, or `TenantRefused`.

    The acceptance is `_tenant.accept_tenant` (the one frame every entry point shares; the
    settings half outside `defender_dir` and every `box_mounted` tree, e.g. the runs base),
    then run start's readiness function over the accepted tenant's settings."""
    tenant = accept_tenant(
        data_root, tenant_id, defender_dir=defender_dir, box_mounted=box_mounted)
    return run_tenant_for(
        tenant, defender_dir=defender_dir, dispatches_lead_zero=dispatches_lead_zero)


def run_tenant_for(
    tenant: Tenant, *, defender_dir: Path, dispatches_lead_zero: bool,
) -> RunTenant:
    """An accepted tenant, ready to run — or `TenantRefused` carrying run start's refusal."""
    ready = resolve_run_tenant_or_refuse(
        tenant.settings, tenant_id=tenant.id, defender_dir=defender_dir,
        dispatches_lead_zero=dispatches_lead_zero)
    return RunTenant(tenant=tenant, grants=ready.grants, correlation=ready.correlation)


def resolve_run_tenant_or_refuse(
    settings: Path, *, tenant_id: TenantId, defender_dir: Path, dispatches_lead_zero: bool,
) -> RunReadiness:
    """`resolve_run_tenant`, its refusal re-raised as the one tenant refusal: `TenantRefused`
    naming the tenant and carrying the readiness function's own message verbatim."""
    try:
        return resolve_run_tenant(
            settings, defender_dir=defender_dir, dispatches_lead_zero=dispatches_lead_zero)
    except refusals() as refusal:
        raise TenantRefused(f"tenant {tenant_id!r}: {refusal}") from refusal


def resolve_run_tenant(
    settings: Path, *, defender_dir: Path, dispatches_lead_zero: bool,
) -> RunReadiness:
    """Run start's readiness function: load a tenant's grants from its `settings` folder and
    check them, before the run dir, the box and any model call. `tenant.py setup` calls it too.

    Refused (one of `refusals()`): a table that does not load; one under which gather can
    query nothing (`require_gather_query` — a `health-check` grant alone reaches no data); and,
    when `dispatches_lead_zero`, a lead-zero config the catalog or the table disagrees with.
    `dispatches_lead_zero` is False for a resumed sibling: it dispatches no turn-0 lead, so a
    template demoted since the source run must not refuse it."""
    grants = run_grants(settings)
    require_gather_query(grants)
    correlation = (
        correlation_dispatch(settings, catalog_templates(defender_dir), grants.correlation)
        if dispatches_lead_zero else None
    )
    return RunReadiness(grants=grants, correlation=correlation)


__all__ = [
    "RunReadiness",
    "RunTenant",
    "TenantRefused",
    "resolve_tenant",
    "catalog_templates",
    "correlation_dispatch",
    "refusals",
    "resolve_run_tenant",
    "resolve_run_tenant_or_refuse",
    "run_tenant_for",
    "table_pointer",
]
