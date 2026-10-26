"""One run's tenant, resolved once at the entry point and handed inward as one value.

The accepted tenant (`_tenant.accept_tenant`), its grants and item 3's dispatch identity come
from operator-editable files. Resolving them once, before the box and any model call, means
every later frame sees the same values instead of re-reading files that may have changed.

`resolve_run_tenant` is run start's readiness function: it holds the run-start refusals, each
naming the file an operator edits. `tenant.py setup` calls the same function, so a tenant setup
passes is one a run can start with.
"""
from __future__ import annotations

from defender.records._locations import DataRoot, RunsBase, EpisodesRoot

import dataclasses
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender.knowledge._corpus import QueryTemplate, iter_query_templates
from defender.knowledge._knowledge import KnowledgePaths
from defender.tenancy._tenant import Tenant, accept_tenant, clone_halves
from defender.records._tenant_id import TenantId, TenantRefused
from defender.tenancy._tenants import AGENT_HALF
from defender.runtime.verb_dispositions import RunGrants, require_gather_query, run_grants
from defender.runtime.verb_grant import GrantError, VerbGrant
from defender.runtime import tenant_settings
from defender.runtime.case_ticket import CaseMapping, CaseTicketError, load_case_mapping
from defender.kit.settings import SystemConfig
from defender.kit.faults import ConfigFault

if TYPE_CHECKING:
    from defender.runtime.lead_zero import CorrelationDispatch


def table_pointer(tenant_id: str) -> str:
    """The model-facing name of a tenant's verb-disposition table. Never the resolved host
    path: the settings half is host-only and the prompt must not vary by machine. Nor the
    tenant's name (#1255 O3: the tenant is host layout, and the model sees one view on every
    host), so every tenant's pointer reads the same; `tenant_id` is the table whose pointer
    this is, not text for the model. Operator messages print `RunGrants.path` instead."""
    from defender.runtime.verbs import TABLE_POINTER

    del tenant_id  # not rendered: see above
    return TABLE_POINTER


@dataclasses.dataclass(frozen=True)
class RunReadiness:
    """What run start's readiness function establishes about a tenant's settings: its grants,
    and item 3's dispatch identity (`None` for a run that dispatches no lead zero)."""

    grants: RunGrants
    correlation: CorrelationDispatch | None


@dataclasses.dataclass(frozen=True)
class RunTenant:
    """One run's tenant: the accepted `Tenant`, its grants, item 3's dispatch identity, and what
    its settings say (#1107).

    `correlation` is `None` for a run that dispatches no lead zero (a resumed sibling),
    otherwise the checked `CorrelationDispatch`, whose `system` is `None` when the table
    withholds the lead."""

    tenant: Tenant
    grants: RunGrants
    correlation: CorrelationDispatch | None
    #: One entry per folder under `settings/systems/`, each `config.env` parsed ONCE here,
    #: verbatim (keys as written, prefix included): a `SystemConfig`, or the `ConfigFault` for why
    #: there is none. A fault is kept, never raised at resolve: resolution is not refused for it
    #: (O5). At run start each granted system's own settings check judges this record (#1256);
    #: a system it faults is down for the run, and a start at which no granted system is usable
    #: is refused by the run's start check (O-8), never here (D4). Asking for a system with no
    #: folder gets the "not configured" fault.
    systems: Mapping[str, SystemConfig | ConfigFault]
    #: `systems/case-history/mapping.yaml`, loaded once; a bad file is kept as its error.
    ticket_mapping: CaseMapping | CaseTicketError
    #: The run's knowledge, one export commit (#1108 P4, O-B): the agent root the run reads (its
    #: run copy's `stage/agent/`) and the settings it was resolved from (the copy's `settings/`).
    #: `None` only for a record resolved over the tenant's own folder (`clone_halves`).
    agent_root: Path | None = None
    settings_root: Path | None = None
    #: The startup token run start staged beside `agent_root` (U9: the copy's `stage/<token>`),
    #: which the run's box reads back to prove its bind; `None` when nothing was staged.
    stage_token: Path | None = None

    @property
    def tenant_id(self) -> TenantId:
        return self.tenant.id

    @property
    def settings(self) -> Path:
        return self.settings_root if self.settings_root is not None else clone_halves(self.tenant)[1]

    @property
    def agent(self) -> Path:
        return self.agent_root if self.agent_root is not None else clone_halves(self.tenant)[0]

    @property
    def table_pointer(self) -> str:
        """This tenant's table as the model is told of it (`table_pointer`)."""
        return table_pointer(self.tenant_id)


def catalog_templates(agent_root: Path) -> list[QueryTemplate]:
    """The query catalog of the agent root a run reads (#1108 P4: its run copy's), walked once."""
    return list(iter_query_templates(KnowledgePaths(agent_root).catalog_dir))


def _agent_beside(settings: Path) -> Path:
    """The agent half beside a `settings/` half (a clone's or an export's `<root>/agent/`): the
    agent root of a resolve that names none."""
    return Path(settings).parent / AGENT_HALF


def correlation_dispatch(
    settings: Path, templates: Iterable[QueryTemplate], grant: VerbGrant,
) -> CorrelationDispatch:
    """Item 3's dispatch identity for one tenant: its `lead-zero.yaml` id, resolved against
    `templates` and checked for agreement with `grant`, its table's correlation grant.
    Raises `LeadZeroConfigError`, `CorrelationDispatchError` or `GrantError`, each naming the
    file an operator edits: `verb-grants.yaml` for a correlation grant of the wrong shape,
    `lead-zero.yaml` for everything else."""
    from defender.runtime import lead_zero as lead_zero_mod
    from defender.runtime.lead_zero_config import lead_zero_config_path, load_correlation_template
    from defender.runtime.verb_dispositions import dispositions_path

    config = lead_zero_config_path(settings)
    template_id = load_correlation_template(config)
    return lead_zero_mod.resolve_correlation_dispatch(
        template_id, templates, grant, source=config, table=dispositions_path(settings))


def refusals() -> tuple[type[Exception], ...]:
    """Every exception `resolve_run_tenant` refuses a tenant with — each names the file an
    operator edits, so a caller reports `str(e)` and needs no per-kind wording."""
    from defender.runtime.lead_zero import CorrelationDispatchError
    from defender.runtime.lead_zero_config import LeadZeroConfigError
    from defender.runtime.verb_dispositions import DispositionError

    return (DispositionError, LeadZeroConfigError, CorrelationDispatchError, GrantError)


def resolve_tenant(
    data_root: DataRoot, tenant_id: str, *, defender_dir: Path, dispatches_lead_zero: bool,
    box_mounted: tuple[Path | RunsBase | EpisodesRoot, ...] = (),
) -> RunTenant:
    """`tenant_id` under `data_root`, accepted and ready, or `TenantRefused` — resolved over the
    tenant's own folder (`clone_halves`), for a caller that names no export.

    The acceptance is `_tenant.accept_tenant` (the one frame every entry point shares; the
    settings half outside `defender_dir` and every `box_mounted` tree, e.g. the runs base),
    then run start's readiness function over the accepted tenant's settings."""
    tenant = accept_tenant(
        data_root, tenant_id, defender_dir=defender_dir, box_mounted=box_mounted)
    return run_tenant_for(tenant, dispatches_lead_zero=dispatches_lead_zero)


def run_tenant_for(  # noqa: PLR0913 — the tenant, its two roots, the staged token, the flag
    tenant: Tenant, *, dispatches_lead_zero: bool, agent_root: Path | None = None,
    settings_root: Path | None = None, stage_token: Path | None = None,
    defender_dir: Path | None = None,
) -> RunTenant:
    """An accepted tenant, ready to run — or `TenantRefused` carrying run start's refusal.

    `agent_root`/`settings_root` are the two halves of the one export the run reads (#1108 P4,
    O-B: run start hands its run copy's); each defaults to the tenant's own folder
    (`clone_halves`). `defender_dir` is accepted for callers that still pass it and is not read:
    the code tree holds no catalog (O1)."""
    del defender_dir
    clone_agent, clone_settings = clone_halves(tenant)
    settings = Path(settings_root) if settings_root is not None else clone_settings
    agent = Path(agent_root) if agent_root is not None else clone_agent
    ready = resolve_run_tenant_or_refuse(
        settings, tenant_id=tenant.id, agent_root=agent,
        dispatches_lead_zero=dispatches_lead_zero)
    return RunTenant(tenant=tenant, grants=ready.grants, correlation=ready.correlation,
                     agent_root=agent, settings_root=settings, stage_token=stage_token,
                     **resolved_settings(tenant, settings_root=settings))


def resolve_run_tenant_or_refuse(
    settings: Path, *, tenant_id: TenantId, dispatches_lead_zero: bool,
    agent_root: Path | None = None, defender_dir: Path | None = None,
) -> RunReadiness:
    """`resolve_run_tenant`, its refusal re-raised as the one tenant refusal: `TenantRefused`
    naming the tenant and carrying the readiness function's own message verbatim."""
    del defender_dir
    try:
        return resolve_run_tenant(
            settings, agent_root=agent_root, dispatches_lead_zero=dispatches_lead_zero)
    except refusals() as refusal:
        raise TenantRefused(f"tenant {tenant_id!r}: {refusal}") from refusal


def resolve_run_tenant(
    settings: Path, *, dispatches_lead_zero: bool, agent_root: Path | None = None,
    defender_dir: Path | None = None,
) -> RunReadiness:
    """Run start's readiness function: load a tenant's grants from its `settings` folder and
    check them, before the run dir, the box and any model call. `tenant.py setup` calls it too.

    The lead-zero template is resolved against `agent_root`'s catalog (#1108 P4, O2: the run
    copy's, never the product tree's), by default the agent half beside `settings`.
    `defender_dir` is accepted for callers that still pass it and is not read.

    Refused (one of `refusals()`): a table that does not load; one under which gather can
    query nothing (`require_gather_query` — a `health-check` grant alone reaches no data); and,
    when `dispatches_lead_zero`, a lead-zero config the catalog or the table disagrees with.
    `dispatches_lead_zero` is False for a resumed sibling: it dispatches no turn-0 lead, so a
    template demoted since the source run must not refuse it."""
    del defender_dir
    agent = Path(agent_root) if agent_root is not None else _agent_beside(settings)
    grants = run_grants(settings)
    require_gather_query(grants)
    correlation = (
        correlation_dispatch(settings, catalog_templates(agent), grants.correlation)
        if dispatches_lead_zero else None
    )
    return RunReadiness(grants=grants, correlation=correlation)


def resolved_settings(tenant: Tenant, *, settings_root: Path | None = None) -> dict[str, Any]:
    """The parts of the record built from a settings folder — `settings_root` (the run copy's,
    #1108 P4), by default the accepted tenant's own (`clone_halves`): each system's `config.env`
    (`systems`) and the case-history mapping (`ticket_mapping`) — as the keyword arguments
    `RunTenant` takes. Read ONCE, here, when a run (or a launch) begins; nothing ever raises for a
    part's content (O5): a part that cannot stand is carried as the fault that says why."""
    settings = Path(settings_root) if settings_root is not None else clone_halves(tenant)[1]
    systems = tenant_settings.read_systems(settings)
    try:
        ticket_mapping: CaseMapping | CaseTicketError = load_case_mapping(settings)
    except CaseTicketError as error:
        # The text only: the caught error's traceback and cause (the OSError, with its host
        # path) must not ride the record.
        ticket_mapping = CaseTicketError(str(error))
    return {
        "systems": systems,
        "ticket_mapping": ticket_mapping,
    }


__all__ = [
    "CaseMapping",
    "RunReadiness",
    "RunTenant",
    "SystemConfig",
    "TenantRefused",
    "resolve_tenant",
    "catalog_templates",
    "correlation_dispatch",
    "refusals",
    "resolve_run_tenant",
    "resolve_run_tenant_or_refuse",
    "resolved_settings",
    "run_tenant_for",
    "table_pointer",
]
