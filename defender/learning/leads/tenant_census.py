"""The grant census a tenant's settings are held to, beyond acceptance (moved from `cli/_tenant_census.py` and
`cli/_tenant_records_check.py` for #1471, which re-export it: the readiness container entry, `run.py`, sits below `cli`)
— ONE rule for its surfaces: the readiness check (a tenant's admin, over the API, `readiness_census`), `check --folder`
(a tenant repo's CI) and `tooling/lint/lint_verb_disposition_census.py` (the product repo's CI, over the template and
the fixture). The surfaces share the judgement of which gaps count, not an exit status: the lint exits 2 when the census
was never taken (the gate could not run); `check --folder` reports it as one more finding, exit 1, and still judges
everything that needs no census (`folder_findings`); the readiness check ends `failed`/`census_unavailable` (R13-3)."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Collection, Mapping
from pathlib import Path

from defender._paths import adapters_under
from defender.learning.leads.declared_systems import declared_systems_over, read_adapters
from defender.learning.leads import LeadAuthorError
from defender.systems.verb_dispositions import (
    CensusGaps,
    Disposition,
    DispositionError,
    census_gaps,
    dispositions_path,
    load_dispositions,
)
from defender.systems.verbs import RosterRead, is_platform_served
from defender.tenancy import SETTINGS_HALF
from defender.tenancy.case_record import CASE_RECORD_REL

#: The retired parts of a tenant repo's `settings/` (O9): read by nothing since #1366.
RETIRED_SYSTEMS = "systems"
RETIRED_CASE_RECORD = CASE_RECORD_REL
#: Retired by #1503: the step-zero lead binds no saved query, so nothing names one.
RETIRED_LEAD_ZERO = "lead-zero.yaml"


class CensusUnavailable(Exception):
    """The census could not be taken. Its message names what failed and what to fix: the
    running checkout's adapters are unreadable, or one of them is an adapter the cold verb read
    saw nothing in. A census that silently lacked a system would print "clean" over a system
    nobody decided."""


@dataclasses.dataclass(frozen=True)
class Census:
    """The running checkout's declared verbs, by system."""

    systems: frozenset[str]
    walked: dict[str, frozenset[str]]
    #: Adapter names the roster refused, with why (a reserved name is a finding, #1390 A11).
    refused: Mapping[str, str] = dataclasses.field(default_factory=dict)


def take_census(defender_dir: Path) -> Census:
    """The census of the code tree at `defender_dir` (its adapters, read cold), or
    `CensusUnavailable`. The system set is the roster's (adapters and platform-served): the committed system markers it
    once also read were the product tree's system skills, which #1108 P4 moved into the tenant,
    so taking it starts no git. One roster read serves both the system set and the verb walk, so
    a tree changing between two reads cannot score one read's systems against the other's
    verbs."""
    adapters = adapters_under(defender_dir)
    try:
        roster = read_adapters(adapters)
    except LeadAuthorError as e:
        raise CensusUnavailable(f"the running checkout's adapters cannot be read: {e}") from e
    systems = declared_systems_over(roster)
    walked = {s: roster.declared_verbs(s) for s in sorted(systems)}
    blind = _unreadable_adapters(roster, walked)
    if blind:
        detail = "; ".join(f"{s}: {roster.unparsed[s]}" for s in blind if s in roster.unparsed)
        raise CensusUnavailable(
            f"the running checkout's adapters under {adapters}: {list(blind)} have an adapter the cold verb reader saw no verb in, so no census "
            "over them was taken and their absence from a table means nothing. The adapter "
            "does not parse, or declares `VERBS` as something other than a top-level dict "
            "literal — an annotated assignment (`VERBS: dict[str, Verb] = {...}`) or a table "
            "built in a loop declares nothing to the reader. Fix the adapter"
            + (f" ({detail})" if detail else ""))
    return Census(systems=systems, walked=walked, refused=dict(roster.refused))


def _unreadable_adapters(
    roster: RosterRead, walked: dict[str, frozenset[str]]
) -> tuple[str, ...]:
    """Systems that have an adapter the walk read no verb out of — the census's fail-open hole.

    The roster's cold read answers `frozenset()` for an adapter it cannot see into. That is
    right for `ModuleVerbRegistry`, where an unreadable table refuses every grant, but here an
    empty walk yields no `undecided` and would print "clean" over an undecided system. Adapter
    presence (`roster.adapter_files`) separates this from an MCP-path system, which is declared by
    its committed `execution.md` marker and has no adapter module by design."""
    return tuple(s for s in sorted(walked)
                 if not walked[s] and s in roster.adapter_files and s not in roster.no_verbs)


@dataclasses.dataclass(frozen=True)
class FolderFindings:
    """What one tenant's settings are held to with no census: the table loaded (the loader
    refuses a correlation grant of the wrong shape, so nothing more is judged here).
    `dispositions` are the rows that were judged — a caller reporting on the table reads them
    here, never by loading the table a second time."""

    dispositions: tuple[Disposition, ...]


@dataclasses.dataclass(frozen=True)
class TableFindings:
    """One tenant's table judged against a census: its residue in both directions, beside
    everything `FolderFindings` holds it to. Clean when `lines` is empty."""

    folder: FolderFindings
    gaps: CensusGaps

    @property
    def dispositions(self) -> tuple[Disposition, ...]:
        return self.folder.dispositions

    @property
    def rows(self) -> int:
        return len(self.dispositions)

    def lines(self, table: Path | str) -> list[str]:
        """Each finding as one line naming the pair and what to do in `table`."""
        out = [f"{system}.{verb}: declared by an adapter, decided by nobody. Add a row to "
               f"{table} granting it to a role, or `roles: []` with a reason if it is "
               "deliberately reachable by no one." for system, verb in self.gaps.undecided]
        out += [f"{system}.{verb}: the table decides a verb no adapter declares. Remove the "
                f"row from {table}, or restore the verb." for system, verb in self.gaps.phantom]
        out += [f"{system}.{verb}: granted to nobody with no reason given."
                for system, verb in self.gaps.unreasoned]
        return out


def table_findings(settings: Path, census: Census) -> TableFindings:
    """`settings`' grant table against `census`. Raises
    `DispositionError` naming the table when it does not load."""
    folder = folder_findings(settings)
    return TableFindings(folder=folder, gaps=census_gaps(census.walked, folder.dispositions))


def folder_findings(settings: Path) -> FolderFindings:
    """`settings` judged by every rule that needs no census: the table loads. The step-zero lead
    binds no saved query (#1503), so no catalog is read. Raises `DispositionError` naming the
    table when it does not load."""
    return FolderFindings(dispositions=load_dispositions(dispositions_path(settings)))


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
    census = take_census(Path(defender_dir))
    try:
        table = census_findings(table_findings(Path(settings), census), systems)
    except DispositionError as unloadable:
        raise CensusUnavailable(str(unloadable)) from None
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
    "Census",
    "CensusUnavailable",
    "FolderFindings",
    "RETIRED_CASE_RECORD",
    "RETIRED_LEAD_ZERO",
    "RETIRED_SYSTEMS",
    "TableFindings",
    "census_findings",
    "feedback_findings",
    "folder_findings",
    "readiness_census",
    "registry_findings",
    "registry_grant_findings",
    "retired_findings",
    "table_findings",
    "take_census",
]
