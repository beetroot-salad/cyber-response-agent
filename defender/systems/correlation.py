"""The correlation lead's grant and dispatch identity: the table's projection for the lead and the
one system it reaches, checked once at run start. The lead binds no saved query; it writes its
own (#1503). `investigation.lead_zero._spec` re-exports the two grant functions."""
from __future__ import annotations

from pathlib import Path
from defender._model import model

from defender._agent_role import CORRELATION_GRANT_HOLDER
from defender.systems.verb_dispositions import HEALTH_CHECK, Disposition, grant_for
from defender.systems.verb_grant import GrantError, VerbGrant


def correlation_grant(rows: tuple[Disposition, ...]) -> VerbGrant:
    """Item 3's grant: the verb-disposition table's projection for the correlation lead.

    The table can grant or withhold; `resolve_correlation_dispatch` checks the grant's shape at
    run start. A function over rows, not a constant, because each run projects its own
    tenant's table.
    """
    return grant_for(CORRELATION_GRANT_HOLDER, rows)


def correlation_system(grant: VerbGrant) -> str | None:
    """The one system item 3 is dispatched against, or `None` when there is nothing to dispatch.

    `None` when the grant holds nothing but `health-check`: the table withheld the lead, which
    degrades the run (item 3 is skipped and ORIENT says so) rather than stopping it.
    Health-check alone is not a target either: the lead would spend its budget on a ping.

    Raises on two systems (the loader already refuses that; this guards other grants): the
    system selects the template tier and cache lane, so it must be authored, not picked.
    """
    systems = sorted({s for s, v, _ in grant.entries if v != HEALTH_CHECK})
    if not systems:
        return None
    if len(systems) != 1:
        raise GrantError(
            f"the correlation grant for role {grant.role!r} reaches {len(systems)} systems "
            f"({systems}) — the dispatched system is derived from it and only a single-system "
            "grant determines one."
        )
    return systems[0]


@model(frozen=True)
class CorrelationDispatch:
    """Item 3's dispatch identity, derived once at run start from the table's grant alone and
    carried to the frames that act on it rather than re-derived there.

    `system is None` means the table withheld the lead. Otherwise the lead runs against
    `system` with the holder's one query pair, and writes its own query: no tenant binds it a
    saved one (#1503).
    """

    system: str | None
    grant: VerbGrant


def _pair(system: str, verb: str) -> str:
    """A pair as the table loader spells it, so an operator can grep for it."""
    return f"{system}.{verb}"


def resolve_correlation_dispatch(grant: VerbGrant, *, table: Path | None = None) -> CorrelationDispatch:
    """The lead's dispatch identity from `grant`: one system and one query pair, or withheld."""
    def at(message: str) -> str:
        return message if table is None else f"{table}: {message}"

    try:
        system = correlation_system(grant)
    except GrantError as two_systems:
        raise GrantError(at(str(two_systems))) from two_systems
    if system is None:
        return CorrelationDispatch(system=None, grant=grant)
    # The loader already refuses a second query verb; this guards grants built elsewhere.
    query_pairs = sorted((s, v) for s, v, _ in grant.entries if v != HEALTH_CHECK)
    if len(query_pairs) != 1:
        raise GrantError(at(
            f"the correlation grant for role {grant.role!r} holds {len(query_pairs)} query "
            f"pairs ({[_pair(s, v) for s, v in query_pairs]}) — the lead is dispatched with ONE "
            "query verb, so only a one-query-pair grant determines it."))
    return CorrelationDispatch(system=system, grant=grant)

