"""Item 3's dispatch identity: the configured template, resolved against the deployment's own
catalog and checked for agreement with the table's grant, once, at run start.

The table (`verb-grants.yaml`) decides whether the correlation lead runs and under which pair;
the config (`lead-zero.yaml`) decides which template it binds. They are authored separately and
can disagree, and a silent disagreement makes the lead burn its whole request budget trying to
bind a template its grant-filtered index cannot list.

The check is composed of the lead's own predicates (`_corpus.is_established` for the index,
`resolve_query_id` for the query tool) rather than a second spelling of them, which could
accept an id the lead cannot bind. It runs on every run, since the operator who can author the
mismatch never runs CI. It lives here, not in the table loader, because the loader cannot name
the template without an import cycle and has no catalog.
"""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from defender._model import model

from defender._corpus import QueryTemplate, is_established
from defender.runtime.verb_dispositions import HEALTH_CHECK
from defender.runtime.verb_grant import GrantError, VerbGrant

from ._spec import correlation_system


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
    """Resolve `template_id` against `templates` and check it agrees with `grant`.

    When the grant holds no query verb the lead is skipped and the id is not consulted: a
    withholding degrades the run rather than stopping it.

    Otherwise, refuse — naming both sides — when:
      (a) the id resolves to no established template, or to more than one (a catalog fault);
      (b) `resolve_query_id` would not hand the id back verbatim on the system the file is
          filed under (a fault in the file, not the table);
      (c) the template declares no `verb:` (a malformed template, not a table mismatch);
      (d) `(template.system, template.verb)` is not exactly the holder's one query pair.

    The grant passes through unchanged: the config selects a template, only the table grants.
    `source`, when given, is the config file the id was read from, and `table` the grant
    table the grant was loaded from: each refusal opens with the file its fault is in, so an
    operator is told which one to edit — the table for a grant of the wrong shape, the config
    for everything about the template it names.
    """
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

    from defender.scripts.gather_tools.record_query import resolve_query_id

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
