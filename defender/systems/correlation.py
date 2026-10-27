"""The correlation lead's grant and dispatch identity: the table's projection for the lead, and the
configured template resolved against the deployment's own catalog and checked for agreement with
it, once, at run start. `investigation.lead_zero._spec` re-exports the two grant functions."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from defender._model import model

from defender._agent_role import CORRELATION_GRANT_HOLDER
from defender.knowledge._corpus import QueryTemplate, is_established
from defender.systems.verb_dispositions import HEALTH_CHECK, Disposition, grant_for
from defender.systems.verb_grant import GrantError, VerbGrant


def correlation_grant(rows: tuple[Disposition, ...]) -> VerbGrant:
    """Item 3's grant: the verb-disposition table's projection for the correlation lead.

    The table can grant or withhold; the granted pair must match the configured template,
    which `resolve_correlation_dispatch` checks at run start. A function over rows, not a
    constant, because each run projects its own tenant's table.
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


class CorrelationDispatchError(Exception):
    """Raised at run start when config, table and catalog disagree; the run stops before any
    prompt is built."""


@model(frozen=True)
class CorrelationDispatch:
    """Item 3's dispatch identity, derived once at run start and carried to the frames that
    act on it rather than re-derived there.

    `system is None` means the table withheld the lead and the id was not checked. Otherwise
    `template_id` resolved to exactly one established template filed under `system` and
    binding the holder's one query pair.
    """

    template_id: str
    system: str | None
    grant: VerbGrant


def _pair(system: str, verb: str) -> str:
    """A pair as the table loader spells it, so an operator can grep for it."""
    return f"{system}.{verb}"


def resolve_correlation_dispatch(
    template_id: str, templates: Iterable[QueryTemplate], grant: VerbGrant, *,
    source: Path | None = None, table: Path | None = None,
) -> CorrelationDispatch:
    """Resolve `template_id` against `templates` and check it agrees with `grant`."""
    def at(message: str, where: Path | None = source) -> str:
        return message if where is None else f"{where}: {message}"

    try:
        system = correlation_system(grant)
    except GrantError as two_systems:
        raise GrantError(at(str(two_systems), table)) from two_systems
    if system is None:
        return CorrelationDispatch(template_id, None, grant)
    # The loader already refuses a second query verb; this guards grants built elsewhere.
    query_pairs = sorted((s, v) for s, v, _ in grant.entries if v != HEALTH_CHECK)
    if len(query_pairs) != 1:
        raise GrantError(at(
            f"the correlation grant for role {grant.role!r} holds {len(query_pairs)} query "
            f"pairs ({[_pair(s, v) for s, v in query_pairs]}) — the template is checked "
            "against ONE, and only a one-query-pair grant determines it.",
            table,
        ))
    table_system, table_verb = query_pairs[0]
    granted = _pair(table_system, table_verb)

    matches = [t for t in templates if t.id == template_id and is_established(t)]
    if not matches:
        raise CorrelationDispatchError(at(
            f"lead-zero config names correlation template {template_id!r}, which resolves "
            "to no established template in this deployment's catalog (a draft, a demoted or "
            "a renamed file does not count, nor does a file the catalog walk skipped as "
            "malformed — see any `warn: skipping` line above) — the lead would be told to "
            f"bind a template its index cannot list, while the table grants {granted} to it"
        ))
    if len(matches) > 1:
        paths = ", ".join(str(t.path) for t in matches)
        raise CorrelationDispatchError(at(
            f"correlation template {template_id!r} is carried by {len(matches)} established "
            f"files ({paths}) — the catalog does not say which one the lead binds; give all "
            "but one of them another id"
        ))
    template = matches[0]

    from defender.knowledge._query_rules import resolve_query_id

    # The query tool's own bind-time rule. A refused id would be recorded under the untagged
    # fallback, losing the template identity the learning loop keys on.

    if resolve_query_id(template.system, template.verb, template_id) != template_id:
        raise CorrelationDispatchError(at(
            f"correlation template {template_id!r} at {template.path} carries an id the "
            f"lead could not bind as its own on {template.system!r}, the system the file is "
            "filed under (a template id is `{system}.{kebab-name}`, and its prefix must be "
            "that system) — fix the file's id or its location, not the table"
        ))
    if template.verb == "":
        raise CorrelationDispatchError(at(
            f"correlation template {template_id!r} at {template.path} is malformed: it "
            "declares no `verb:` in its front matter, so the pair it binds cannot be compared "
            "with the table's grant — fix the template, not the table"
        ))
    if (template.system, template.verb) != (table_system, table_verb):
        raise CorrelationDispatchError(at(
            f"the correlation template and the verb-disposition table disagree: template "
            f"{template_id!r} binds {_pair(template.system, template.verb)}, but the table "
            f"grants {granted} to the lead. Either move the holder's rows to the template's "
            "pair or configure a template that binds the granted one"
        ))
    return CorrelationDispatch(template_id, system, grant)
