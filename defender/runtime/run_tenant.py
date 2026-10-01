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
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender._corpus import QueryTemplate, iter_query_templates, query_catalog_dir
from defender._tenant import TenantId, TenantRefused
from defender._tenants import TenantDir
from defender.runtime import tenant_settings
from defender.runtime.tenant_settings import (
    ElasticSettings,
    SecretLookup,
    SystemConfig,
)
from defender.runtime.verb_dispositions import RunGrants, require_gather_query, run_grants
from defender.runtime.verb_grant import VerbGrant
from defender.scripts.adapters.faults import ConfigFault
from defender.scripts.case_history import case_ticket
from defender.scripts.case_history.case_ticket import CaseMapping, CaseTicketError

if TYPE_CHECKING:
    from defender.runtime.lead_zero import CorrelationDispatch


def table_pointer(tenant_id: str) -> str:
    """The MODEL-FACING name of a tenant's verb-disposition table — what a DENIED refusal and
    ORIENT's withheld-lead note say. It names the tenant and the file inside its folder, never
    the resolved host path: the settings half is host-only, and the host's layout (and the
    prompt prefix built over it) must not change with the machine the run is on. Operator
    messages print `RunGrants.path` instead."""
    from defender.runtime.verbs import TABLE_POINTER

    return f"{TABLE_POINTER}, tenant {tenant_id!r}"


@dataclasses.dataclass(frozen=True)
class RunTenant:
    """One run's tenant: its folder, its grants, item 3's dispatch identity, and what its settings
    say (#1107).

    `correlation` is `None` for a run resolved as one that dispatches no lead-zero (a resumed
    sibling world: turn-0 work is skipped), and otherwise the identity the run-start agreement
    check stood behind (#1003) — a `CorrelationDispatch` whose `system` is `None` when the
    table withholds the lead."""

    dir: TenantDir
    grants: RunGrants
    correlation: CorrelationDispatch | None
    #: One entry per folder under `settings/systems/`, each `config.env` parsed ONCE here,
    #: verbatim (keys as written, prefix included): a `SystemConfig`, or the `ConfigFault` for why
    #: there is none. A fault is kept, never raised at resolve — that system is down, the run is
    #: not refused (O5). Asking for a system with no folder gets the "not configured" fault.
    systems: Mapping[str, SystemConfig | ConfigFault]
    #: The named view of the corpus engine's system folder — the one place platform code interprets
    #: its config keys. `None` when the tenant has no such folder.
    elastic: ElasticSettings | ConfigFault | None  # lint-shippable: ok — the record's field name (#1107)
    #: `systems/case-history/mapping.yaml`, loaded once; a bad file is kept as its error.
    ticket_mapping: CaseMapping | CaseTicketError
    #: Resolves a secret only if THIS tenant's systems declare it; read per lookup (O2's exemption).
    secrets: SecretLookup

    @property
    def tenant_id(self) -> TenantId:
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


def resolve_tenant(
    tenants_root: Path, tenant_id: str, *, defender_dir: Path, dispatches_lead_zero: bool,
    box_mounted: tuple[Path, ...] = (),
) -> RunTenant:
    """`tenant_id` under `tenants_root`, checked whole, or `TenantRefused`. @owns tenant acceptance

    THE ONE FRAME every entry point accepts a tenant through — a run, a resumed sibling, the
    branch launcher, `defender-policy` — so none can accept a tenant another refuses:
      * the folder and id rules (`_tenants.tenant_dir`: grammar, no link anywhere inside) —
        its `TenantDirError` is itself a `TenantRefused`;
      * the folder is not inside a tree a box mounts — `defender_dir`, bound read-only into
        every box, and whatever else the caller names in `box_mounted` (a run passes its runs
        base, whose run dirs are the box's rw bind): the settings half is host-only, and a
        tenants root placed there would hand the model every tenant's endpoints;
      * the content rules (`resolve_run_tenant`)."""
    from defender._tenants import tenant_dir

    folder = tenant_dir(tenants_root, tenant_id)
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
    return RunTenant(dir=tenant, grants=grants, correlation=correlation,
                     **resolved_settings(tenant))


def resolved_settings(tenant: TenantDir) -> dict[str, Any]:
    """The four parts of the record built from the tenant's settings folder — each system's
    `config.env` (`systems`), the corpus-engine view, the case-history mapping
    (`ticket_mapping`) and the secret lookup (`secrets`) — as the keyword arguments `RunTenant`
    takes. Read ONCE, here, when a run (or a launch) begins; nothing ever raises for a part's
    content (O5): a part that cannot stand is carried as the fault that says why."""
    systems = tenant_settings.read_systems(tenant.settings)
    tenant_settings.warn_missing_access_method(tenant.tenant_id, systems)
    try:
        ticket_mapping: CaseMapping | CaseTicketError = case_ticket.load_case_mapping(
            tenant.settings)
    except CaseTicketError as error:
        ticket_mapping = error
    return {
        "systems": systems,
        "elastic": tenant_settings.elastic_view(systems),  # lint-shippable: ok — the record's field name (#1107)
        "ticket_mapping": ticket_mapping,
        "secrets": SecretLookup(
            tenant.settings.parent.parent, tenant.tenant_id,
            tenant_settings.declared_secrets(systems)),
    }


__all__ = [
    "CaseMapping",
    "ElasticSettings",
    "RunTenant",
    "SecretLookup",
    "SystemConfig",
    "TenantRefused",
    "resolve_tenant",
    "catalog_templates",
    "correlation_dispatch",
    "refusals",
    "resolve_run_tenant",
    "resolved_settings",
    "table_pointer",
]
