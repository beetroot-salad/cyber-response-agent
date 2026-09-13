"""Item 3's dispatch identity: the configured template, resolved against the deployment's own
catalog and checked for AGREEMENT with the table's grant, once, at run start (#1003).

The table (`verb-grants.yaml`) decides whether the correlation lead runs and under which
pair; the config (`lead-zero.yaml`) decides which template it binds. Each is authored on its
own, per deployment, so they can disagree — and before #1003 a disagreement was silent: a
table moving the holder to another vendor's search verb, or to a sibling verb on the same
vendor, loaded clean, derived that system, and the lead was told to bind a template its
grant-filtered index could not list. It spent all eight requests discovering that and
reported a truncated session with no findings.

ONE RESOLVER, NOT TWO. The invariant this module promises is exactly "the id the lead is told
to bind is one its own machinery will bind": listed by the index it reads
(`tools_gather._template_index`, filtered on `_corpus.is_established`) and handed back
verbatim by the query tool when it passes the id on its `query` call
(`query_tool.resolve_query_id`). So the check is composed of those two predicates, and
nothing here respells the id grammar, the established-tier filter or the id-to-file rule —
a second spelling of any of them is an id the check accepts and the lead cannot bind, which
is the silent burn again with a green check in front of it.

Repo CI pins the same join on the repo's own copies (`test_gather_template_discovery.py`).
This module is the runtime-side twin: the operator who can author the mismatch never runs
CI, so the check runs on every run that will dispatch the lead, over the tree the run reads,
before any prompt is built.

WHY HERE AND NOT IN THE TABLE LOADER: `_spec` imports `verb_dispositions`, so the loader
cannot name the template without a cycle — and the loader has no catalog to resolve it
against. The three narrowing rules in `_refuse_incoherent_narrowing` are unchanged; this is a
fourth, one level up, where the catalog is visible.

Sibling-free like `_spec`: imports it and nothing else in the package. The query tool is
imported at the call, the way the rest of the package reaches the gather machinery.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from defender._corpus import QueryTemplate, is_established
from defender.runtime.verb_dispositions import HEALTH_CHECK
from defender.runtime.verb_grant import GrantError, VerbGrant

from ._spec import correlation_system


class CorrelationDispatchError(Exception):
    """Raised at run start for a config/table/catalog trio no dispatch can honestly be built
    from. One class for every arm because every arm has the same correct handling: stop,
    before any prompt is built, naming what disagreed."""


@dataclass(frozen=True)
class CorrelationDispatch:
    """Item 3's dispatch identity, derived once at run start from three inputs — the config's
    id, the catalog walk, and the table's holder rows — and CARRIED to the two frames that
    act on it (`prepare_correlation_lead`, `dispatch_correlation`) rather than re-derived
    there from module constants.

    `system` and `grant` are the table's projections exactly as `_spec` derives them at
    import; `template_id` is the config's. `system is None` means the table withheld the
    lead, and then nothing about the id was checked. Whenever `system` is set, the check
    resolved `template_id` to exactly one established template filed under `system` and
    binding the holder's one query pair — so the system the lead is dispatched on, labelled
    with and cache-keyed by IS the template's, by construction.
    """

    template_id: str
    system: str | None
    grant: VerbGrant


def _pair(system: str, verb: str) -> str:
    """The spelling the table loader names a pair by — what an operator greps the table for."""
    return f"{system}.{verb}"


def resolve_correlation_dispatch(
    template_id: str, templates: Iterable[QueryTemplate], grant: VerbGrant,
) -> CorrelationDispatch:
    """Resolve `template_id` against `templates` and check it agrees with `grant`.

    WITHHELD FIRST: when the grant holds no query verb the lead is skipped (ORIENT says so),
    and the id is NOT consulted — `templates` is never iterated. A withholding is a decision
    an author wrote a reason for; it degrades the run rather than stopping it, and a typo in
    a config the lead will not read is not this run's problem.

    Otherwise, refuse — naming both sides — when:
      (a) the id resolves to no established template (`is_established`, the index's own
          filter), or to more than one — two files carrying the id is a catalog fault, said
          as such, never settled by which sorts first;
      (b) the query tool would not hand the id back verbatim as the lead's own id on the
          system the file is filed under (`resolve_query_id`): not `{system}.{kebab}`, or a
          prefix naming another system than the directory — the location invariant the
          corpus lints (`_scaffold_rules._id_findings`), met here at bind time. Said as a
          fault in the FILE, never as a table mismatch;
      (c) the resolved template declares no `verb:` — said as a MALFORMED TEMPLATE, never as
          a mismatch on an empty verb, which would send the operator to the table for a
          fault in the file;
      (d) `(template.system, template.verb)` is not exactly the holder's one query pair.

    The grant is handed through unchanged: the config SELECTS a template, only the table
    grants (#1003 O5). No value of the id reaches this function's output as a wider grant.
    """
    system = correlation_system(grant)
    if system is None:
        return CorrelationDispatch(template_id, None, grant)
    # The holder's one query pair. The loader refuses a second query verb for this holder, so
    # this is a single pair for any grant that came through it; the raise is this function's
    # own contract for one that did not, as `correlation_system`'s is for two systems.
    query_pairs = sorted((s, v) for s, v, _ in grant.entries if v != HEALTH_CHECK)
    if len(query_pairs) != 1:
        raise GrantError(
            f"the correlation grant for role {grant.role!r} holds {len(query_pairs)} query "
            f"pairs ({[_pair(s, v) for s, v in query_pairs]}) — the template is checked "
            "against ONE, and only a one-query-pair grant determines it."
        )
    table_system, table_verb = query_pairs[0]
    granted = _pair(table_system, table_verb)

    matches = [t for t in templates if t.id == template_id and is_established(t)]
    if not matches:
        raise CorrelationDispatchError(
            f"lead-zero config names correlation template {template_id!r}, which resolves "
            "to no established template in this deployment's catalog (a draft, a demoted or "
            "a renamed file does not count, nor does a file the catalog walk skipped as "
            "malformed — see any `warn: skipping` line above) — the lead would be told to "
            f"bind a template its index cannot list, while the table grants {granted} to it"
        )
    if len(matches) > 1:
        paths = ", ".join(str(t.path) for t in matches)
        raise CorrelationDispatchError(
            f"correlation template {template_id!r} is carried by {len(matches)} established "
            f"files ({paths}) — the catalog does not say which one the lead binds; give all "
            "but one of them another id"
        )
    template = matches[0]

    from ..query_tool import resolve_query_id

    # THE bind-time rule, not a restatement of it: what the lead's `query` call does with a
    # `query_id`. Held against the system the file is FILED under, which is the system the
    # lead is dispatched on once (d) below holds — so an id this arm accepts is one the tool
    # records verbatim, and one it refuses would have been recorded under the untagged
    # fallback, losing the template identity the learning loop keys on.
    if resolve_query_id(template.system, template.verb, template_id) != template_id:
        raise CorrelationDispatchError(
            f"correlation template {template_id!r} at {template.path} carries an id the "
            f"lead could not bind as its own on {template.system!r}, the system the file is "
            "filed under (a template id is `{system}.{kebab-name}`, and its prefix must be "
            "that system) — fix the file's id or its location, not the table"
        )
    if template.verb == "":
        raise CorrelationDispatchError(
            f"correlation template {template_id!r} at {template.path} is malformed: it "
            "declares no `verb:` in its front matter, so the pair it binds cannot be compared "
            "with the table's grant — fix the template, not the table"
        )
    if (template.system, template.verb) != (table_system, table_verb):
        raise CorrelationDispatchError(
            f"the correlation template and the verb-disposition table disagree: template "
            f"{template_id!r} binds {_pair(template.system, template.verb)}, but the table "
            f"grants {granted} to the lead. Either move the holder's rows to the template's "
            "pair or configure a template that binds the granted one"
        )
    return CorrelationDispatch(template_id, system, grant)
