"""One run's tenant, resolved once at the entry point and handed inward as one value.

The accepted tenant (`_tenant.accept_tenant`), its grants and item 3's dispatch identity come
from operator-editable files. Resolving them once, before the box and any model call, means
every later frame sees the same values instead of re-reading files that may have changed.

`resolve_run_tenant` is run start's readiness function: it holds the run-start refusals, each
naming the file an operator edits.

`entry_directory` is every host entry point's tenant directory (#1214 Flow 4): the one it is
given, else one over the database `DEFENDER_DATABASE_DSN` names, after the light version check.
"""
from __future__ import annotations

from defender.records.formats import DataRoot, RunsBase, EpisodesRoot

import contextlib
import dataclasses
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from defender.knowledge import QueryTemplate, iter_query_templates
from defender.knowledge import KnowledgePaths
from defender.tenancy import Tenant, accept_tenant, clone_halves
from defender.records.formats import TenantId, TenantRefused
from defender.tenancy import AGENT_HALF
from defender.tenancy import RecordsUnreachable
from defender.systems.verb_dispositions import RunGrants, require_gather_query, run_grants
from defender.systems.verb_grant import GrantError, VerbGrant
from defender import tenancy
from defender.tenancy import tenant_settings
from defender.tenancy.case_ticket import CaseMapping, CaseTicketError, load_case_mapping
from defender.kit.access import HTTP_PROXY, AccessDeclaration
from defender.kit.settings import SystemConfig, system_prefix
from defender.kit.faults import ConfigFault

if TYPE_CHECKING:
    from defender.systems.correlation import CorrelationDispatch
    from defender.tenancy import TenantDirectory
    from defender.tenancy.models import ForgeWiring


def table_pointer(tenant_id: str) -> str:
    """The model-facing name of a tenant's verb-disposition table. Never the resolved host
    path: the settings half is host-only and the prompt must not vary by machine. Nor the
    tenant's name (#1255 O3: the tenant is host layout, and the model sees one view on every
    host), so every tenant's pointer reads the same; `tenant_id` is the table whose pointer
    this is, not text for the model. Operator messages print `RunGrants.path` instead."""
    from defender.systems.verbs import TABLE_POINTER

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
    #: One entry per `http-proxy` system (its `config.env` says so), each `access.yaml` parsed
    #: ONCE here: the `AccessDeclaration`, or the `ConfigFault` for why there is none (#1163).
    #: Adapters, the ticket writer and the run-start settings check read this, never the file.
    access: Mapping[str, AccessDeclaration | ConfigFault] = dataclasses.field(
        default_factory=lambda: MappingProxyType({}))
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
    from defender.systems import correlation
    from defender.systems.lead_zero_config import lead_zero_config_path, load_correlation_template
    from defender.systems.verb_dispositions import dispositions_path

    config = lead_zero_config_path(settings)
    template_id = load_correlation_template(config)
    return correlation.resolve_correlation_dispatch(
        template_id, templates, grant, source=config, table=dispositions_path(settings))


def refusals() -> tuple[type[Exception], ...]:
    """Every exception `resolve_run_tenant` refuses a tenant with — each names the file an
    operator edits, so a caller reports `str(e)` and needs no per-kind wording."""
    from defender.systems.correlation import CorrelationDispatchError
    from defender.systems.lead_zero_config import LeadZeroConfigError
    from defender.systems.verb_dispositions import DispositionError

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
    check them, before the run dir, the box and any model call.

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


#: The database addresses this process has checked the schema revision of (r10: the version check
#: runs at the first acceptance in a process only; a failed check is not remembered).
_VERSION_CHECKED: set[str] = set()


def _check_version_once(dsn: str) -> None:
    """The light version check, once per process per address (r10 Finding 9)."""
    if dsn not in _VERSION_CHECKED:
        _check_version(dsn)
        _VERSION_CHECKED.add(dsn)


class Admitted:
    """The value of one host acceptance (r10.1 C3): the accepted `tenant`, the `directory` it was
    admitted through (run, the drain's per-claim check and credential and revert's delivery read
    it after) and the tenant's forge `wiring`. The acceptance already holds the tenant's host lock;
    `with admitted:` releases it when the block ends. Only `host_tenant` makes one."""

    __slots__ = ("_release", "directory", "tenant", "wiring")

    def __init__(self, tenant: Tenant, directory: TenantDirectory, wiring: ForgeWiring,
                 release: contextlib.ExitStack) -> None:
        self.tenant, self.directory, self.wiring, self._release = tenant, directory, wiring, release

    def __enter__(self) -> Admitted:
        return self

    def __exit__(self, *_exc: object) -> None:
        self._release.close()


def host_tenant(  # noqa: PLR0913 — the request (root, id), the records seam and the folder rules' inputs
    data_root: DataRoot, raw_id: object, *, directory: TenantDirectory | None = None,
    defender_dir: Path | None = None, box_mounted: Iterable[Path | RunsBase | EpisodesRoot] = (),
    clone_tree: bool = True,
) -> Admitted:
    """The one host acceptance (r10 A1): the only way a host entry point gets its tenant.

    Checked now, at the call, in this order: the id's grammar; the data root's placement; this
    process recorded and the tenant's host lock held shared (`host_lock.hold_shared`: a nested
    acceptance reuses the open hold; while prepare or teardown holds it exclusive it waits, with
    no timeout, saying so once on stderr); the database's schema revision (the first acceptance
    in the process only); the tenant's record, read once (`active`, its forge wiring recorded);
    the folder rules (`accept_tenant`). A refusal at any step is `TenantRefused` (an unreachable
    database its `RecordsUnreachable`) and releases what was taken (O-A6). The returned value
    holds the lock until `with admitted:` ends (r10.1 C3).

    `directory` is the tenant records a test or a launcher hands in; a production process passes
    none and reads them from `DEFENDER_DATABASE_DSN`. Refused in the lifecycle's own process
    (r10.1 C6, A4): prepare holds the lock exclusive there, so a shared hold would wait on itself."""
    from defender import tenancy
    from defender._paths import process_defender_dir
    from defender.tenancy import host_lock

    if tenancy.in_lifecycle_process():
        raise TenantRefused("the host acceptance never runs in the lifecycle process: prepare holds the "
                            "tenant's host lock exclusive there, and the lifecycle loads a tenant with the "
                            "folder rules only")
    tenant_id = tenancy.requested_tenant_id(raw_id)
    tenancy.refuse_unplaceable_data_root(data_root)
    held = contextlib.ExitStack()
    try:
        held.enter_context(host_lock.hold_shared(tenancy.data_root_for_child(data_root), tenant_id))
    except OSError as unheld:
        raise TenantRefused(f"tenant {tenant_id}'s host lock could not be taken: "
                            f"{unheld.strerror or type(unheld).__name__}") from None
    try:
        # A1 order: the version check runs only now, with the hold taken (`host_directory` calls it
        # when no directory is handed in).
        records = tenancy.host_directory(directory, check_version=_check_version_once)
        wiring = tenancy.admit_tenant(records, tenant_id)
        tenant = accept_tenant(data_root, tenant_id,
                               defender_dir=defender_dir if defender_dir is not None else process_defender_dir(),
                               box_mounted=box_mounted, clone_tree=clone_tree)
    except BaseException:
        held.close()
        raise
    return Admitted(tenant, records, wiring, held)


def entry_directory(given: TenantDirectory | None) -> TenantDirectory:
    """The `TenantDirectory` a host entry point admits its tenant through: `given`, else one over
    `DEFENDER_DATABASE_DSN` once the database is at this code's revision (#1339's light check,
    run once at process start and never a migration). No directory and no address, or a database
    at another revision (named with this code's), is `TenantRefused`; a database that cannot be
    reached is its `RecordsUnreachable`, which a caller may treat as transient."""
    from defender import tenancy

    return tenancy.host_directory(given, check_version=_check_version)


def _check_version(dsn: str) -> None:
    from defender.migrations import DatabaseUnreachable, RevisionMismatch, check_version

    try:
        check_version(dsn)
    except RevisionMismatch as behind:
        raise TenantRefused(str(behind)) from behind
    except DatabaseUnreachable as down:
        raise RecordsUnreachable(str(down)) from down


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
        "access": _read_access(settings, systems),
    }


def _read_access(
    settings: Path, systems: Mapping[str, SystemConfig | ConfigFault],
) -> Mapping[str, AccessDeclaration | ConfigFault]:
    """The declaration of every system whose `config.env` names the `http-proxy` access method."""
    out: dict[str, AccessDeclaration | ConfigFault] = {}
    for name, entry in systems.items():
        if isinstance(entry, ConfigFault) or entry.get(f"{system_prefix(name)}_TRANSPORT") != HTTP_PROXY:
            continue
        try:
            out[name] = tenancy.read_access(settings, name)
        except ConfigFault as fault:
            out[name] = ConfigFault(str(fault))  # the text only, as the other parts do
    return MappingProxyType(out)


__all__ = [
    "CaseMapping",
    "RecordsUnreachable",
    "RunReadiness",
    "RunTenant",
    "SystemConfig",
    "TenantRefused",
    "resolve_tenant",
    "catalog_templates",
    "correlation_dispatch",
    "Admitted",
    "entry_directory",
    "host_tenant",
    "refusals",
    "resolve_run_tenant",
    "resolve_run_tenant_or_refuse",
    "resolved_settings",
    "run_tenant_for",
    "table_pointer",
]
