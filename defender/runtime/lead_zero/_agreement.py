"""Item 3's dispatch identity: the configured template, resolved against the deployment's own
catalog and checked for AGREEMENT with the table's grant, once, at run start (#1003).

The table (`verb-grants.yaml`) decides whether the correlation lead runs and under which
pair; the config (`lead-zero.yaml`) decides which template it binds. Each is authored on its
own, per deployment, so they can disagree — and before #1003 a disagreement was silent: a
table moving the holder to another vendor's search verb, or to a sibling verb on the same
vendor, loaded clean, derived that system, and the lead was told to bind a template its
grant-filtered index could not list. It spent all eight requests discovering that and
reported a truncated session with no findings.

Repo CI pins the join on the repo's own copies (`test_gather_template_discovery.py`). This
module is the runtime-side twin: the operator who can author the mismatch never runs CI, so
the check runs on every run, over the tree the run reads, before any prompt is built.

WHY HERE AND NOT IN THE TABLE LOADER: `_spec` imports `verb_dispositions`, so the loader
cannot name the template without a cycle — and the loader has no catalog to resolve it
against. The three narrowing rules in `_refuse_incoherent_narrowing` are unchanged; this is a
fourth, one level up, where the catalog is visible.

WHY NOT AT IMPORT: `_spec` is the vocabulary leaf; the catalog walk is warn-and-skip on a
malformed file and belongs where `_dispatch_catalogs` already walks it at run start.

Sibling-free like `_spec`: imports it and nothing else in the package.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from defender._corpus import QueryTemplate
from defender.runtime.verb_dispositions import HEALTH_CHECK
from defender.runtime.verb_grant import VerbGrant
from defender.runtime.verbs import is_system_name

from ._spec import correlation_system

class CorrelationDispatchError(Exception):
    """Raised at run start for a config/table/catalog trio no dispatch can honestly be built
    from. One class for every arm because every arm has the same correct handling: stop,
    before any prompt is built, naming what disagreed."""


@dataclass(frozen=True)
class CorrelationDispatch:
    """Item 3's dispatch identity, derived once at run start from three inputs — the config's
    id, the catalog walk, and the table's holder rows.

    `system` and `grant` are the table's projections exactly as `_spec` derives them at
    import; `template` is the catalog record the check compared against, and `None` only when
    the table withheld the lead (`system is None`). Whenever `template` is set,
    `template.system == system` by the check, so the system the lead is dispatched on,
    labelled with and cache-keyed by IS the template's — one derivation, not two.
    """

    template_id: str
    system: str | None
    grant: VerbGrant
    template: QueryTemplate | None


def _is_template_id(template_id: str) -> bool:
    """`{system}.{kebab}`: a well-formed system name, one dot, one kebab segment. The kebab
    half is screened by the SAME predicate as the prefix — it shares the system alphabet
    (lowercase, digits, hyphens) and the bound, and this repo keeps that shape in one place
    (`verbs.is_system_name`, #914) rather than respelling it. `partition` on the first dot
    means a second dot lands in the remainder and fails: `system.foo.bar` would otherwise be
    a second path component wherever an id becomes a catalog location."""
    prefix, sep, remainder = template_id.partition(".")
    return bool(sep) and is_system_name(prefix) and is_system_name(remainder)


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
      (a) the id is not `{system}.{kebab}` with a well-formed system prefix, or resolves to
          no ESTABLISHED, non-draft template (both halves, the way `_template_index` filters:
          a `_draft/` copy is not in the index the lead is told to read, whatever its status
          says);
      (b) the resolved template declares no `verb:` — said as a MALFORMED TEMPLATE, never as
          a mismatch on an empty verb, which would send the operator to the table for a
          fault in the file;
      (c) `(template.system, template.verb)` is not exactly the holder's one query pair.

    The grant is handed through unchanged: the config SELECTS a template, only the table
    grants (#1003 O5). No value of the id reaches this function's output as a wider grant.
    """
    system = correlation_system(grant)
    if system is None:
        return CorrelationDispatch(template_id, None, grant, None)
    # The holder's one query pair. `correlation_system` already refused a multi-system grant,
    # and the loader refused a second query verb, so this is a single pair by construction.
    query_pairs = sorted((s, v) for s, v, _ in grant.entries if v != HEALTH_CHECK)
    table_system, table_verb = query_pairs[0]

    if not _is_template_id(template_id):
        raise CorrelationDispatchError(
            f"lead-zero config names correlation template {template_id!r}, which is not a "
            "template id (`{system}.{kebab-name}`) — nothing in the catalog can be resolved "
            f"from it, while the table grants {_pair(table_system, table_verb)} to the lead"
        )
    matches = [
        t for t in templates
        if t.id == template_id and t.status == "established" and "_draft" not in t.path.parts
    ]
    if not matches:
        raise CorrelationDispatchError(
            f"lead-zero config names correlation template {template_id!r}, which resolves "
            "to no established template in this deployment's catalog (a draft, a demoted or "
            "a renamed file does not count) — the lead would be told to bind a template its "
            f"index cannot list, while the table grants {_pair(table_system, table_verb)} to it"
        )
    template = matches[0]
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
            f"grants {_pair(table_system, table_verb)} to the lead. Either move the holder's "
            "rows to the template's pair or configure a template that binds the granted one"
        )
    return CorrelationDispatch(template_id, system, grant, template)
