"""The grant census a tenant's settings are held to, beyond
acceptance — ONE rule for its two surfaces: `tenant.py check` (an operator, or a tenant repo's
CI) and `tooling/lint/lint_verb_disposition_census.py` (the product repo's CI, over the template
and the fixture). The surfaces share the judgement of which gaps count, not an exit status: the
lint exits 2 when the census was never taken (the gate could not run); `check` reports it as one
more finding, exit 1, and still judges everything that needs no census (`folder_findings`)."""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from pathlib import Path

from defender._paths import adapters_under
from defender.learning.leads.declared_systems import declared_systems_over, read_adapters
from defender.learning.leads import LeadAuthorError
from defender.systems.verb_dispositions import (
    CensusGaps,
    Disposition,
    census_gaps,
    dispositions_path,
    load_dispositions,
)
from defender.systems.verbs import RosterRead


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


__all__ = [
    "Census",
    "CensusUnavailable",
    "FolderFindings",
    "TableFindings",
    "folder_findings",
    "table_findings",
    "take_census",
]
