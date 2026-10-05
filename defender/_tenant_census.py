"""The grant census and the lead-zero agreement a tenant's settings are held to, beyond
acceptance — ONE rule for its two surfaces: `tenant.py check` (an operator, or a tenant repo's
CI) and `scripts/lint/lint_verb_disposition_census.py` (the product repo's CI, over the template
and the fixture). The surfaces share the judgement of which gaps count, not an exit status: the
lint exits 2 when the census was never taken (the gate could not run); `check` reports it as one
more finding, exit 1, and still judges everything that needs no census (`folder_findings`).

The census is the RUNNING checkout's: every verb its adapters declare must be decided by the
tenant's table, and every row of the table must name a declared verb. It is taken from the code
that runs, never from the tenant — a tenant cannot vouch for which systems exist. A gap does not
stop a run (an undecided verb is simply not granted), so it is a finding here and never a
refusal at setup or run start.

The census reads this machine's git and the running checkout, never the tenant's folder, so a
census that cannot be taken is never the folder's doing: `CensusUnavailable` names which of the
two failed. What the folder alone decides — its table loads, its lead-zero config agrees with the
table and the running catalog — is judged without a census, so losing the census costs only the
judgement that needs it.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

from defender import _git
from defender._corpus import QueryTemplate, is_established
from defender._paths import adapters_under
from defender.learning.leads.declared_systems import declared_systems_over, read_adapters
from defender.learning.leads._errors import LeadAuthorError
from defender.runtime import lead_zero as lead_zero_mod
from defender.runtime.lead_zero._spec import correlation_grant
from defender.runtime.lead_zero_config import LeadZeroConfigError, lead_zero_config_path
from defender.runtime.run_tenant import catalog_templates, correlation_dispatch
from defender.runtime.verb_dispositions import (
    CensusGaps,
    Disposition,
    census_gaps,
    dispositions_path,
    load_dispositions,
)
from defender.runtime.verb_grant import GrantError
from defender.runtime.verbs import RosterRead


class CensusUnavailable(Exception):
    """The census could not be taken. Its message names the side that failed and what to fix:
    this machine's git (absent from PATH, or not runnable), or the running checkout (its
    adapters unreadable, one the cold verb read saw nothing in, or its committed system markers
    unresolvable). A census that silently lacked a system would print "clean" over a system
    nobody decided."""


@dataclasses.dataclass(frozen=True)
class Census:
    """The running checkout's declared verbs, by system, and its query catalog."""

    systems: frozenset[str]
    walked: dict[str, frozenset[str]]
    catalog: list[QueryTemplate]


def take_census(defender_dir: Path, repo_root: Path) -> Census:
    """The census of the code tree at `defender_dir` (its adapters, read cold) and `repo_root`
    (its committed system markers), or `CensusUnavailable`. One roster read serves both the
    system set and the verb walk, so a tree changing between two reads cannot score one
    read's systems against the other's verbs."""
    adapters = adapters_under(defender_dir)
    try:
        roster = read_adapters(adapters)
    except LeadAuthorError as e:
        raise CensusUnavailable(f"the running checkout's adapters cannot be read: {e}") from e
    try:
        systems = declared_systems_over(roster, repo_root)
    except LeadAuthorError as e:
        raise CensusUnavailable(
            f"the running checkout {repo_root} cannot resolve its declared systems: {e}") from e
    except OSError as e:
        # The marker half is a committed-tree read through git, and git did not start.
        raise CensusUnavailable(
            f"{_git.unstarted(e)} on this machine, so the running checkout's committed system markers cannot "
            f"be read ({e})") from e
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
    return Census(systems=systems, walked=walked, catalog=catalog_templates(defender_dir))


def _unreadable_adapters(
    roster: RosterRead, walked: dict[str, frozenset[str]]
) -> tuple[str, ...]:
    """Systems that have an adapter the walk read no verb out of — the census's fail-open hole.

    The roster's cold read answers `frozenset()` for an adapter it cannot see into. That is
    right for `ModuleVerbRegistry`, where an unreadable table refuses every grant, but here an
    empty walk yields no `undecided` and would print "clean" over an undecided system. Adapter
    presence (`roster.accepted`) separates this from an MCP-path system, which is declared by
    its committed `execution.md` marker and has no adapter module by design."""
    return tuple(s for s in sorted(walked) if not walked[s] and s in roster.accepted)


@dataclasses.dataclass(frozen=True)
class FolderFindings:
    """What one tenant's settings are held to with no census: the table loaded, and the
    lead-zero config's disagreement with it and the running catalog, if any. Clean when `lines`
    is empty. `dispositions` are the rows that were judged — a caller reporting on the table
    reads them here, never by loading the table a second time."""

    dispositions: tuple[Disposition, ...]
    lead_zero_fault: str | None

    def lines(self) -> list[str]:
        return [] if self.lead_zero_fault is None else [f"lead-zero: {self.lead_zero_fault}"]


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
    def lead_zero_fault(self) -> str | None:
        return self.folder.lead_zero_fault

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
        return out + self.folder.lines()


def table_findings(settings: Path, census: Census) -> TableFindings:
    """`settings`' grant table against `census`, and its lead-zero config against the census's
    catalog. Raises `DispositionError` naming the table when it does not load."""
    folder = _folder_findings(settings, census.catalog)
    return TableFindings(folder=folder, gaps=census_gaps(census.walked, folder.dispositions))


def folder_findings(settings: Path, defender_dir: Path) -> FolderFindings:
    """`settings` judged by every rule that needs no census, for a caller whose census could
    not be taken: the table loads, and the lead-zero config agrees with it and with the catalog
    of the tree at `defender_dir` (a plain walk of its files, no git). Raises
    `DispositionError` naming the table when it does not load."""
    return _folder_findings(settings, catalog_templates(defender_dir))


def _folder_findings(settings: Path, catalog: list[QueryTemplate]) -> FolderFindings:
    rows = load_dispositions(dispositions_path(settings))
    return FolderFindings(dispositions=rows,
                          lead_zero_fault=_lead_zero_fault(settings, rows, catalog))


def _lead_zero_fault(settings: Path, rows: tuple, catalog: list[QueryTemplate]) -> str | None:
    """The folder's lead-zero config: it names an established catalog template — even when
    the table withholds the lead, since a withheld lead's id is never consulted at run start
    and would surface only once an operator grants it — and, when the lead is granted, that
    template's pair is the one granted (the run-start agreement check,
    `run_tenant.correlation_dispatch`). `None` when both hold."""
    try:
        template_id = correlation_dispatch(settings, catalog, correlation_grant(rows)).template_id
    except (LeadZeroConfigError, lead_zero_mod.CorrelationDispatchError, GrantError) as e:
        return str(e)
    if not any(t.id == template_id and is_established(t) for t in catalog):
        return (f"{lead_zero_config_path(settings)}: correlation_template {template_id!r} names no "
                "established template in the catalog (the table withholds the lead, so no run "
                "consults it yet)")
    return None


__all__ = [
    "Census",
    "CensusUnavailable",
    "FolderFindings",
    "TableFindings",
    "folder_findings",
    "table_findings",
    "take_census",
]
