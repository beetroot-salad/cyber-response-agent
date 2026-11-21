"""What the readiness check reports about a tenant's records (#1366 R8, R12, O1, C3, C5, O9 leftovers).

The readiness worker asks this module and reports what it returns beside its other findings (the repo, the publish,
the alert mapping, the registry). One finding per line; `[]` is clean. Every judgement here is one run start or the
record store already makes, asked again over the tenant's current records:

- each record judged as the store judges a write (`system_rules.system_faults`: an adapter an upgrade removed,
  settings an upgrade invalidated, a declaration that does not parse);
- the grants table against the records (R12): a catalog system granted with no record is an orphaned grant, one whose
  record is disabled is granted but disabled; an ungranted unrecorded system is silent; a grant on a system the catalog
  lacks is the census's phantom, as today;
- the case record judged as run start judges it (`case_system.judge_case_system`, C3) over the tenant's systems (O1);
- each record's credentials at its current generation, asked of the operator's secret store when the caller holds a
  login for it (R13);
- the grant census over the tenant's own systems (`census_findings`, O1);
- the retired `settings/systems/` folder, `settings/case-record.yaml` and `settings/lead-zero.yaml` left in the repo
  (`leftover_findings`, O9):
  reported, never opened."""
from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Callable, Collection, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender.kit.access import AccessDeclaration
from defender.kit.faults import ConfigFault
from defender.systems import case_system
from defender.systems.catalog import Catalog, TenantSystems
from defender.system_rules import system_faults
from defender.systems.run_tenant import record_settings
from defender.systems.verb_dispositions import DispositionError, dispositions_path, load_dispositions
from defender.systems.verbs import RegistryError, is_platform_served
from defender.tenancy import AGENT_HALF, SETTINGS_HALF
from defender.tenancy.case_record import CASE_RECORD_REL
from defender.tenancy.models import TenantRecords

if TYPE_CHECKING:
    from defender.cli._tenant_census import TableFindings
    from defender.kit.settings import SystemConfig
    from defender.tenancy import TenantDirectory
    from defender.records.formats import TenantId

#: The retired parts of a tenant repo's `settings/` (O9): read by nothing since #1366.
RETIRED_SYSTEMS = "systems"
RETIRED_CASE_RECORD = CASE_RECORD_REL
#: Retired by #1503: the step-zero lead binds no saved query, so nothing names one.
RETIRED_LEAD_ZERO = "lead-zero.yaml"

#: THE words of R13's finding (a record holds no credential; they are set for its generation through the API).
NO_CREDENTIALS = "no credentials at the current generation"


@dataclasses.dataclass(frozen=True)
class RecordsCheck:
    """The record findings of one tenant, and the records they were read from. `systems` are the systems the census
    judges: every recorded one and the platform-served ones."""

    lines: list[str]
    records: TenantRecords

    @property
    def systems(self) -> frozenset[str]:
        return frozenset(self.records.systems)


@dataclasses.dataclass(frozen=True)
class _CaseRecordOf:
    """What run start's case judgement reads off a run's tenant (`case_system.judge_case_system`), built from the same
    records (`run_tenant.record_settings`): `tenant check`'s caller of the one case judgement (C3)."""

    agent: Path
    records: TenantRecords
    systems: Mapping[str, SystemConfig]
    access: Mapping[str, AccessDeclaration | ConfigFault]
    case_record: Any


def records_check(tenant_id: TenantId, directory: TenantDirectory, *, knowledge: Path, secrets: Any,
                  defender_dir: Path) -> RecordsCheck:
    """`check <id>`'s record findings for `tenant_id`, read through `directory` (the CLI's, over
    `DEFENDER_DATABASE_DSN`). `knowledge` is the tenant's repo (its grants table, its agent half); `secrets` the
    operator's OpenBao login (`has_credentials`), or None when the command was given none; `defender_dir` the running
    checkout, whose adapters are the catalog."""
    records = directory.current_records(tenant_id)
    try:
        catalog = Catalog.of_checkout(defender_dir)
    except RegistryError as unreadable:
        return RecordsCheck([f"the tenant's records were not judged: the running checkout's adapters cannot be read "
                             f"({unreadable})"], records)
    lines: list[str] = []
    for _system, record in sorted(records.systems.items()):
        lines += system_faults(record, catalog=catalog)
    lines += grant_findings(records, catalog, Path(knowledge) / SETTINGS_HALF)
    lines += _case_findings(tenant_id, records, catalog, agent=Path(knowledge) / AGENT_HALF, defender_dir=defender_dir)
    lines += credential_findings(tenant_id, records, secrets)
    return RecordsCheck(lines, records)


def grant_findings(records: TenantRecords, catalog: Catalog, settings: Path) -> list[str]:
    """R12's `check` column over the grants table in `settings`: each catalog system a role is granted that has no
    current record (never recorded, or deleted: an orphaned grant) or whose record is disabled (granted but disabled).
    A table that does not load is the census's finding, not repeated here."""
    try:
        rows = load_dispositions(dispositions_path(settings))
    except DispositionError:
        return []
    table = dispositions_path(settings)
    granted = sorted({d.system for d in rows if d.roles and d.system in catalog and not is_platform_served(d.system)})
    lines: list[str] = []
    for system in granted:
        record = records.systems.get(system)
        if record is None:
            lines.append(f"system {system}: orphaned grant — {table} grants its verbs but the tenant has no record "
                         f"of it (never recorded, or deleted): runs ignore the grant. Record the system "
                         f"(`PUT /systems/{system}`) or withdraw the grant")
        elif not record.enabled:
            lines.append(f"system {system}: granted but disabled — {table} grants its verbs but its record is "
                         "disabled: runs ignore the grant. Enable the record or withdraw the grant")
    return lines


def _case_findings(tenant_id: TenantId, records: TenantRecords, catalog: Catalog, *, agent: Path,
                   defender_dir: Path) -> list[str]:
    """The case record judged as run start judges it, over the tenant's systems (C3, O1). No case record: none."""
    if records.case is None:
        return []
    record = _CaseRecordOf(agent=agent, records=records, **record_settings(records))
    try:
        case_system.judge_case_system(record, defender_dir=defender_dir,
                                      roster=TenantSystems.of(records, catalog).roster)
    except case_system.CaseSettingsFault as fault:
        return [str(fault)]
    return []


def credential_findings(tenant_id: object, records: TenantRecords, secrets: Any) -> list[str]:
    """R13: each recorded system with no credential set at its record's current generation, asked of `secrets` (the
    operator's OpenBao login). With none (`check` given no login) the question is not asked and nothing is reported:
    the caller that holds a login hands it in."""
    systems = sorted(records.systems.items())
    if not systems or secrets is None:
        return []

    async def asked() -> list[str]:
        # One event loop for every ask, and one pooled client opened and closed on it.
        lines: list[str] = []
        async with secrets.pooled():
            for system, record in systems:
                try:
                    held = await secrets.has_credentials(str(tenant_id), system, generation=record.credential_generation)
                except Exception as e:  # noqa: BLE001 — a store that cannot answer is a finding, not a crash
                    lines.append(f"system {system}: its credentials could not be checked ({type(e).__name__}: {e})")
                    continue
                if not held:
                    lines.append(f"system {system}: {NO_CREDENTIALS} ({record.credential_generation}): set them with "
                                 f"`PUT /systems/{system}/credentials` for version {record.version}")
        return lines

    return asyncio.run(asked())


def census_findings(table: TableFindings, systems: Collection[str] | None) -> TableFindings:
    """`table` (the grants table judged against the whole checkout's census) narrowed to the tenant's systems (O1):
    a verb of a system the tenant has no record of, decided by nobody or withheld with no reason, is not the tenant's
    finding (R12 'ungranted rows for unrecorded systems: silent'). A row no adapter declares stays a phantom whatever
    the records say. `systems` None (a folder with no records: `check --folder`, the census lint): unchanged."""
    if systems is None:
        return table
    mine = set(systems)

    def kept(pairs: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
        return tuple(p for p in pairs if p[0] in mine or is_platform_served(p[0]))

    gaps = dataclasses.replace(table.gaps, undecided=kept(table.gaps.undecided), unreasoned=kept(table.gaps.unreasoned))
    return dataclasses.replace(table, gaps=gaps)


def leftover_findings(knowledge: Path) -> list[str]:
    """O9: the retired parts a tenant repo's `settings/` still holds (`retired_findings`)."""
    return retired_findings(Path(knowledge) / SETTINGS_HALF)


def retired_findings(settings: Path) -> list[str]:
    """O9: the retired `settings/systems/` folder, `settings/case-record.yaml` and (#1503) `settings/lead-zero.yaml`
    a tenant's `settings` still holds. Each is reported as retired and ignored; neither is opened, so an unreadable one
    is reported the same."""
    settings = Path(settings)
    lines: list[str] = []
    if (settings / RETIRED_SYSTEMS).is_symlink() or (settings / RETIRED_SYSTEMS).exists():
        lines.append(f"settings/{RETIRED_SYSTEMS}/ is retired and ignored: the tenant's systems are records "
                     "(`GET /systems` lists them); remove the folder from the repo")
    if (settings / RETIRED_CASE_RECORD).is_symlink() or (settings / RETIRED_CASE_RECORD).exists():
        lines.append(f"settings/{RETIRED_CASE_RECORD} is retired and ignored: the case record is a record "
                     "(`PUT /case-record` replaces it); remove the file from the repo")
    if (settings / RETIRED_LEAD_ZERO).is_symlink() or (settings / RETIRED_LEAD_ZERO).exists():
        lines.append(f"settings/{RETIRED_LEAD_ZERO} is retired and ignored: the step-zero lead writes its own "
                     "correlation query; remove the file from the repo")
    return lines


def feedback_findings(settings: Path) -> list[str]:
    """The feedback setting in `settings` (#1414 O1): an unreadable file, or one naming an unknown outcome."""
    from defender.tenancy import feedback_setting

    try:
        feedback_setting.load_feedback_outcomes(Path(settings))
    except feedback_setting.FeedbackSettingError as bad:
        return [str(bad)]
    return []


def registry_findings(agent: Path) -> list[str]:
    """The tacit-knowledge registry file under `agent` judged by what `tacit_cli check` fails on (a whole-file
    refusal or a dropped entry, #1390 O7), whether or not the grant table reaches `lookup` (A10). Date-dependent notes
    stay advisory, so a tenant's CI does not go red by the calendar."""
    from defender.systems import tacit_registry

    path = tacit_registry.registry_path(Path(agent))
    return [f"{tacit_registry.SYSTEM} registry: {why}" for why in tacit_registry.read_registry(path).problems]


def registry_grant_findings(agent: Path, settings: Path, *, note: Callable[[str], None] | None = None) -> list[str]:
    """The registry file under `agent` against the grant table in `settings`, which only this check holds together:
    `lookup` granted with no file behind it fails. Entries with no `lookup` grant only earn a note (`note`, when given),
    since a tenant may write them before it grants the verb. An unloadable table is reported where the table is
    judged, so it costs only this comparison."""
    from defender.systems import tacit_registry
    from defender.systems.verb_dispositions import run_grants

    try:
        gather = run_grants(Path(settings)).gather
    except DispositionError:
        return []
    granted = any(system == tacit_registry.SYSTEM and verb == "lookup" for system, verb, _ in gather.entries)
    read = tacit_registry.read_registry(tacit_registry.registry_path(Path(agent)))
    if granted and read.absent:
        return [f"{tacit_registry.SYSTEM} registry: gather is granted `lookup`, but there is no "
                "registry file for it to read"]
    if read.entries and not granted and note is not None:
        note(f"note: {tacit_registry.SYSTEM} registry holds {len(read.entries)} entr(ies), but "
             "gather is not granted `lookup`, so none of them is consulted yet")
    return []


def readiness_census(agent: Path, settings: Path, *, systems: Collection[str], defender_dir: Path
                     ) -> list[tuple[str, str]]:
    """The census warnings of a readiness check (#1471 R4, R13-3), as `(kind, sentence)` pairs, one per finding line:
    a tenant's published copy (its `agent` and `settings` halves) judged as `check --folder` judges a repo, narrowed to
    the tenant's `systems` (`census_findings`): the retired files, the grant census both ways against the code tree at
    `defender_dir`, the tacit registry and its grants, the feedback setting. Not reported: a refused platform-served
    adapter name, and the committed `.tenant-id` (a copy is no clone). `CensusUnavailable` when the census cannot be
    taken (or the table, which run start loads first, does not load)."""
    from defender.cli import _tenant_census

    census = _tenant_census.take_census(Path(defender_dir))
    try:
        table = census_findings(_tenant_census.table_findings(Path(settings), census), systems)
    except DispositionError as unloadable:
        raise _tenant_census.CensusUnavailable(str(unloadable)) from None
    name = f"{SETTINGS_HALF}/{dispositions_path(Path(settings)).name}"
    none: tuple[tuple[str, str], ...] = ()

    def only(**kept: tuple[tuple[str, str], ...]) -> list[str]:
        gaps = dataclasses.replace(table.gaps, **{"undecided": none, "phantom": none, "unreasoned": none, **kept})
        return dataclasses.replace(table, gaps=gaps).lines(name)

    found = [("retired_file", line) for line in retired_findings(Path(settings))]
    # An unreasoned gap cannot reach here (the table's loader refuses it, R13-3); were one to, it is a verb decided by
    # nobody.
    found += [("verb_undecided", line) for line in only(undecided=table.gaps.undecided, unreasoned=table.gaps.unreasoned)]
    found += [("verb_undeclared", line) for line in only(phantom=table.gaps.phantom)]
    found += [("tacit_registry", line) for line in registry_findings(Path(agent))]
    found += [("tacit_grant", line) for line in registry_grant_findings(Path(agent), Path(settings))]
    found += [("feedback_setting", line) for line in feedback_findings(Path(settings))]
    return found


__all__ = [
    "NO_CREDENTIALS",
    "RecordsCheck",
    "census_findings",
    "credential_findings",
    "feedback_findings",
    "grant_findings",
    "leftover_findings",
    "readiness_census",
    "records_check",
    "registry_findings",
    "registry_grant_findings",
    "retired_findings",
]
