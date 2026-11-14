"""What `tenant.py check <id>` reports about a tenant's records (#1366 R8, R12, O1, C3, C5, O9 leftovers).

The CLI's `check_tenant` asks this module and prints what it returns beside its other findings (the repo, the publish,
the alert mapping, the registry). One finding per line; `[]` is clean. Every judgement here is one run start or the
record store already makes, asked again over the tenant's current records:

- not imported (R8): the one finding naming `tenant.py import`, and nothing judged from the retired folders, which
  stand for a full set of systems and a case record;
- each record judged as the store judges a write (`record_judgement.system_faults`: an adapter an upgrade removed,
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
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender.kit.access import AccessDeclaration
from defender.kit.faults import ConfigFault
from defender.systems import case_system
from defender.systems.catalog import Catalog, TenantSystems
from defender.systems.record_judgement import system_faults
from defender.systems.run_tenant import not_imported_text, record_settings
from defender.systems.verb_dispositions import DispositionError, dispositions_path, load_dispositions
from defender.systems.verbs import RegistryError, is_platform_served
from defender.tenancy import AGENT_HALF, SETTINGS_HALF
from defender.tenancy.case_ticket import CASE_RECORD_REL
from defender.tenancy.models import TenantRecords

if TYPE_CHECKING:
    from defender.cli._tenant_census import TableFindings
    from defender.kit.settings import SystemConfig
    from defender.tenancy import TenantDirectory
    from defender.records.formats import TenantId

#: The retired parts of a tenant repo's `settings/` (O9): read by nothing since the import.
RETIRED_SYSTEMS = "systems"
RETIRED_CASE_RECORD = CASE_RECORD_REL
#: Retired by #1503: the step-zero lead binds no saved query, so nothing names one.
RETIRED_LEAD_ZERO = "lead-zero.yaml"

#: THE words of R13's finding (a fresh import copies no credential).
NO_CREDENTIALS = "no credentials at the current generation"


@dataclasses.dataclass(frozen=True)
class RecordsCheck:
    """The record findings of one tenant, and the records they were read from (`None`: the tenant is not imported, and
    `lines` is the import finding alone). `systems` are the systems the census judges: every recorded one and the
    platform-served ones."""

    lines: list[str]
    records: TenantRecords | None

    @property
    def systems(self) -> frozenset[str] | None:
        return None if self.records is None else frozenset(self.records.systems)


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
    if not records.imported:
        return RecordsCheck([not_imported_text(tenant_id)], None)
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
                         f"(`tenant.py set-system`) or withdraw the grant")
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
                                      roster=TenantSystems.of(records, catalog, tenant_id=tenant_id).roster)
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
    lines: list[str] = []
    for system, record in systems:
        try:
            held = asyncio.run(secrets.has_credentials(str(tenant_id), system,
                                                       generation=record.credential_generation))
        except Exception as e:  # noqa: BLE001 — a store that cannot answer is a finding, not a crash
            lines.append(f"system {system}: its credentials could not be checked ({type(e).__name__}: {e})")
            continue
        if not held:
            lines.append(f"system {system}: {NO_CREDENTIALS} ({record.credential_generation}): set them with "
                         f"`tenant.py set-credentials` for version {record.version}")
    return lines


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
    """O9: the retired `settings/systems/` folder, `settings/case-record.yaml` and (#1503) `settings/lead-zero.yaml`
    a tenant repo still holds. Each is
    reported as retired and ignored; neither is opened, so an unreadable one is reported the same."""
    settings = Path(knowledge) / SETTINGS_HALF
    lines: list[str] = []
    if (settings / RETIRED_SYSTEMS).is_symlink() or (settings / RETIRED_SYSTEMS).exists():
        lines.append(f"settings/{RETIRED_SYSTEMS}/ is retired and ignored: the tenant's systems are records since "
                     "the import (`tenant.py systems` lists them); remove the folder from the repo")
    if (settings / RETIRED_CASE_RECORD).is_symlink() or (settings / RETIRED_CASE_RECORD).exists():
        lines.append(f"settings/{RETIRED_CASE_RECORD} is retired and ignored: the case record is a record since the "
                     "import (`tenant.py set-case` replaces it); remove the file from the repo")
    if (settings / RETIRED_LEAD_ZERO).is_symlink() or (settings / RETIRED_LEAD_ZERO).exists():
        lines.append(f"settings/{RETIRED_LEAD_ZERO} is retired and ignored: the step-zero lead writes its own "
                     "correlation query; remove the file from the repo")
    return lines


__all__ = [
    "NO_CREDENTIALS",
    "RecordsCheck",
    "census_findings",
    "credential_findings",
    "grant_findings",
    "leftover_findings",
    "records_check",
]
