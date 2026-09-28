"""One run's tenant, resolved once at the entry point and handed inward as one value.

The tenant's folder, grants and item 3's dispatch identity come from operator-editable files.
Resolving them once, before the box and any model call, means every later frame sees the same
values instead of re-reading files that may have changed.

`resolve_run_tenant` holds the run-start refusals, each naming the file an operator edits; the
caller decides how to report them.
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
    """The model-facing name of a tenant's verb-disposition table. Never the resolved host
    path: the settings half is host-only and the prompt must not vary by machine. Operator
    messages print `RunGrants.path` instead."""
    from defender.runtime.verbs import TABLE_POINTER

    return f"{TABLE_POINTER}, tenant {tenant_id!r}"


@dataclasses.dataclass(frozen=True)
class RunTenant:
    """One run's tenant: its folder, its grants, and item 3's dispatch identity.

    `correlation` is `None` for a run that dispatches no lead zero (a resumed sibling),
    otherwise the checked `CorrelationDispatch`, whose `system` is `None` when the table
    withholds the lead."""

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
    `templates` and checked for agreement with `grant`, its table's correlation grant.
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


class TenantRefused(Exception):
    """The one refusal `resolve_tenant` raises: every reason a tenant cannot be used, from its
    id and folder (`TenantDirError`) to its table and lead-zero config (`refusals()`), each
    message naming the file an operator edits. Entry points catch THIS and report it."""


def resolve_tenant(
    tenants_root: Path, tenant_id: str, *, defender_dir: Path, dispatches_lead_zero: bool,
    box_mounted: tuple[Path, ...] = (),
) -> RunTenant:
    """`tenant_id` under `tenants_root`, checked whole, or `TenantRefused`. @owns tenant acceptance

    Every entry point accepts a tenant through here, so none accepts one another refuses:
      * the folder and id rules (`_tenants.tenant_dir`);
      * the folder is not inside a tree a box mounts (`defender_dir`, plus `box_mounted`,
        e.g. the runs base): the settings half is host-only;
      * the content rules (`resolve_run_tenant`)."""
    from defender._tenants import TenantDirError, tenant_dir

    try:
        folder = tenant_dir(tenants_root, tenant_id)
    except TenantDirError as refusal:
        raise TenantRefused(str(refusal)) from refusal
    for mounted in (Path(defender_dir), *box_mounted):
        if folder.settings.is_relative_to(Path(mounted).resolve()):
            raise TenantRefused(
                f"tenant {tenant_id!r}'s folder {folder.settings.parent} is inside {mounted}, "
                "which a box mounts — the settings half is host-only; keep the tenants root "
                "outside the code tree and the runs base")
    try:
        return resolve_run_tenant(
            folder, defender_dir=defender_dir, dispatches_lead_zero=dispatches_lead_zero)
    except refusals() as refusal:
        raise TenantRefused(f"tenant {tenant_id!r}: {refusal}") from refusal


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
    "TenantRefused",
    "resolve_tenant",
    "catalog_templates",
    "correlation_dispatch",
    "refusals",
    "resolve_run_tenant",
    "table_pointer",
]
