"""Point an elastic query at a world's view of the corpus.

The event stream is the one system where a world is staged rather than patched: its documents
are prepared before the query runs, and Elasticsearch does its own filtering, aggregation and
sorting over them. Nothing here composes a result, so aggregations over a mutated world are
correct by construction and two queries touching one fact read the same documents.

A world's view is `base − exclude + inject`. Removal is required: a world's difference can be an
absence (e.g. whether some activity recurs outside the alert window), which an additive-only
pipeline cannot express.

Redirection has two paths: `esql` carries the index in a `FROM` clause inside the query body;
only `query` and `alerts` take an `index` parameter.

`query`/`alerts` run their index through `confine_index`; `esql` confines nothing. A world view
is named outside the pattern it stages (see `confinement.VIEW_NAMESPACE`), so the confined path
admits it by declaration: the estate registry hands the adapter a ctx naming the world, and
`confine_index` resolves that world's views and no sibling's.

Time window: a branched run is pinned to its branch point's moment. `query`/`alerts` close an
omitted upper bound at that moment (`elastic_adapter._bounded_end`); a present bound is a
scenario-timeline value the model chose and is never rewritten. `esql` has its window inside the
body, so the bound is appended as its own pipe stage (`elastic_adapter.bounded_esql`), which can
only narrow and never edits the model's `WHERE`. The bound rides the wire, not the evidence: the
asked form is what `esql_payload` echoes and what is recorded, keeping payloads byte-comparable
with the capture. Telling the run the date is not enough, because the model writing these
queries is the GATHER subagent, whose deps carry no clock and whose prompt renders none.
"""

from __future__ import annotations


import re
from defender._model import model
from typing import Any

from defender._world_label import world_view_fault
from defender.scripts.adapters.confinement import (
    ViewNameError,
    world_view,
)
from defender.scripts.adapters.esql_text import split_first_command
from defender.scripts.adapters.faults import USAGE_EXIT_CODE, AdapterFault

#: The leading `FROM` command. ES|QL requires it first, so this is a leading-clause
#: substitution: everything after the first pipe is never touched.
_FROM = re.compile(r"\A(?P<lead>\s*FROM\s+)(?P<rest>.*)\Z", re.IGNORECASE | re.DOTALL)
#: `FROM <sources> METADATA <fields>` — the one suffix that may follow the source list inside
#: the same command, and it must survive the rewrite.
#:
#: Whitespace-delimited, not `\b`: `-` and `.` are non-word characters, so `\bMETADATA\b` would
#: match inside an index name like `logs-metadata-*`.
_METADATA = re.compile(r"(?:(?<=\s)|\A)METADATA(?=\s|\Z)", re.IGNORECASE)

#: Verbs whose index is a parameter rather than part of the query body.
PARAM_INDEXED = ("query", "alerts")

#: Which config key each param-indexed verb defaults its index to, mirroring
#: `elastic_adapter.query`/`alerts`. A call that omits `index` is not indexless — it is
#: addressing THIS, and a stager that cannot see it would have to refuse a shipped template.
_DEFAULT_INDEX_ATTR = {"query": "events_index", "alerts": "alerts_index"}


#: The two keys naming this deployment's corpus, in the order the pair is always read in.
PATTERN_KEYS = ("ELASTIC_EVENTS_INDEX", "ELASTIC_ALERTS_INDEX")  # lint-shippable: ok — the per-vendor config keys the read adapter loads  # noqa: E501


def configured_patterns(elastic: Any) -> tuple[str, ...]:
    """The two corpus patterns a tenant configures, in a stable order — the record's Elastic
    view's `events_index` and `alerts_index` (#1107), handed in by the caller.

    ONE reading of the pair the whole design keys on: the overlay-key gate, the staging
    namespace guard and the manifest loader all ask which patterns exist, and three independent
    readings would let a config edit widen one and narrow another. They all come through here,
    from the record resolved once when the run (or the launch) began — never the file as it is
    now and never the process environment, so an exported variable cannot widen what a world may
    stage into.

    A tenant with no usable Elastic part (`None`, or the `ConfigFault` the record carries instead
    of a view) configures NO pattern: the empty tuple, which every caller already refuses (the
    launcher's preflight, the foreign-view test), so a part that could not stand admits no view
    as any world's own."""
    from defender.runtime.tenant_settings import ElasticSettings

    if not isinstance(elastic, ElasticSettings):
        return ()
    return tuple(p for p in (elastic.events_index, elastic.alerts_index) if p)


def check_world_id(world_id: str) -> None:
    """Refuse a world whose id no view of this corpus could be named with, before it serves.

    The id reaches `world_view` unfiltered on every staged call, so a bad id (a space, `*`,
    upper case) would refuse the whole event stream and read as a sibling that asked nothing.
    """
    if (why := world_view_fault(world_id)) is not None:
        raise StagingError(why)


def stages(verb: str) -> bool:
    """Does retargeting this verb do anything? (`health-check` reaches no corpus.)"""
    return verb in PARAM_INDEXED or verb == "esql"


class StagingError(AdapterFault):
    """A query that cannot be pointed at a world's view.

    An `AdapterFault` with the usage exit code: an unrecognised exception would be filed as an
    infra code, which the circuit breaker counts as an outage in the sibling but not its base.
    Every refusal here names something the caller can act on.
    """

    exit_code = USAGE_EXIT_CODE


@model(frozen=True)
class _FromClause:
    """One ES|QL query's leading `FROM`, split into the parts a retarget needs.

    One parse shared by `source_pattern` and `rewrite_from`, so they cannot read the same query
    differently.
    """

    lead: str      #: `FROM` and the whitespace after it, exactly as written
    sources: str   #: the source list, stripped
    suffix: str    #: ` METADATA …` when the command carries one, else empty
    gap: str       #: the author's whitespace before the next pipe stage
    tail: str      #: everything from the first real separator on, separator included


def _parse_from(query: str, origin: str) -> _FromClause:
    # Quote-aware split: a `|` inside a quoted source name is data.
    head, tail = split_first_command(query)
    m = _FROM.match(head)
    if m is None:
        raise StagingError(f"{origin} does not open with FROM: {query[:80]!r}")
    rest = m.group("rest")
    meta = _METADATA.search(rest)
    head = rest[: meta.start()] if meta else rest
    sources = head.strip()
    if not sources:
        raise StagingError(f"{origin} names no source after FROM: {query[:80]!r}")
    return _FromClause(
        lead=m.group("lead"), sources=sources,
        # Keep the author's whitespace before `METADATA` (possibly a newline) so the rewrite
        # reflows nothing. There is always at least one character: an `\A` match leaves
        # `sources` empty and is refused above.
        suffix=f"{head[len(head.rstrip()):]}{rest[meta.start():].rstrip()}" if meta else "",
        # The author's whitespace before the pipe, measured on both branches so `METADATA _id`
        # is not joined onto the next stage's line.
        gap=rest[len(rest.rstrip()):], tail=tail)


#: ES|QL metadata fields that put a corpus identity into the rows. `_index` names the concrete
#: index each row came from, so it would differ base-vs-sibling inside `values` (evidence, which
#: `restore` must never rewrite).
#:
#: `_id` is not here: an id is scoped by an index rather than naming one, and a view carrying the
#: same documents carries the same ids. If views are ever built by re-minting ids, add it.
_IDENTIFYING_METADATA = ("_index",)


def refuse_identifying_metadata(clause: str, query: str) -> None:
    """Refuse an ES|QL query whose rows would carry the corpus identity.

    `restore` only rewrites fields a verb echoes, never `values` (the documents). `METADATA
    _index` puts the index name in a column, so every sibling row would differ from the base by
    the harness's own naming, indistinguishable from a real world difference. Refusing at least
    lands in the ledger. No committed template selects `_index`.
    """
    # Split on commas too: `METADATA _index, _id` would otherwise tokenize to `_index,`.
    fields = clause.replace(",", " ").split()
    named = [f for f in _IDENTIFYING_METADATA if f in fields]
    if named:
        raise StagingError(
            f"this ES|QL query selects {named} in its METADATA clause, which puts the corpus "
            f"identity into the result ROWS: {query[:80]!r}. A staged world reads a different "
            "index by construction, so those rows would differ from the base's by this seam's "
            "own naming — and rows are evidence, which the retarget's inverse must not "
            "rewrite. Drop the field, or address this corpus in a query that does not select it")


def rewrite_from(query: str, view: str) -> str:
    """Retarget an ES|QL query's leading `FROM` at `view`, preserving everything else.

    Only the source list moves; a `METADATA` suffix and every downstream pipe stage are kept.
    """
    c = _parse_from(query, "this ES|QL query")
    return f"{c.lead}{view}{c.suffix}{c.gap}{c.tail}"


def _one_source(
    expression: str, origin: str, *, unquote: bool = False, verbatim: bool = False,
) -> str:
    """The single corpus `expression` addresses, or a refusal.

    A comma list is refused whole: staging only some sources would leave the query reading the
    unstaged base for the rest, the world's difference silently missing from part of the
    evidence. (`confine_index` likewise refuses rather than narrows.)

    `unquote` strips quotes on the ES|QL path only, where they are syntax; a view built from a
    quoted source would be a name no index answers to.

    `verbatim` (the `index` parameter) strips neither quotes nor whitespace: the base run hands
    that value to `confine_index` as-is and faults on `'"logs-*"'` or `" logs-* "`, so trimming
    here would serve a sibling what its base was refused.
    """
    source = expression if verbatim else expression.strip()
    if "," in source:
        raise StagingError(
            f"{origin} addresses several corpora ({source!r}) and cannot be staged whole — "
            "retargeting only some of them would leave the query reading the unstaged base "
            "for the rest, with the world's difference silently missing from that half")
    if unquote and len(source) >= 2 and source[0] == source[-1] and source[0] in "\"'":
        source = source[1:-1].strip()
    return source


def source_pattern(verb: str, params: dict, ctx: Any = None) -> str | None:
    """Where this call addresses its corpus, by whichever route the verb carries it.

    An omitted `index` resolves through the run's own config, the same key the adapter falls
    back to. Shipped templates rely on that default, so refusing would drop a whole evidence
    class from the sibling while the base kept it — a difference owned by the stager, not the
    world.

    Falsy counts as omitted, matching the adapter's `index or config[index_key]`. A truthy
    non-string index is a broken call and is refused (the base run faults on it too).
    """
    if verb in PARAM_INDEXED:
        index = params.get("index")
        if index:
            if not isinstance(index, str):
                raise StagingError(
                    f"{verb} was called with index={index!r}, which names no corpus — an "
                    "explicit index has to be a string, and reading the run's configured "
                    "default instead would stage a corpus this call never asked for")
            return _one_source(index, f"{verb}'s index parameter", verbatim=True)
        if ctx is None:
            return None
        from defender.runtime.tenant_settings import ElasticSettings, elastic_problem
        from defender.scripts.adapters.faults import ConfigFault

        elastic = ctx.tenant.elastic
        if not isinstance(elastic, ElasticSettings):
            # The record carries a part that could not stand as a value, never raised at resolve
            # (O5): the call it is read for faults here, as the adapter's own would — with a new
            # instance, so the record's own fault is never handed a traceback.
            raise ConfigFault(str(elastic) if isinstance(elastic, ConfigFault)
                              else str(elastic_problem(elastic)))
        return _one_source(
            getattr(elastic, _DEFAULT_INDEX_ATTR[verb]), f"{verb}'s configured default index")
    if verb != "esql":
        return None
    body = params.get("query")
    if not isinstance(body, str):
        raise StagingError(f"esql params carry no query body: {params!r}")
    return _one_source(
        _parse_from(body, "this ES|QL query").sources, "this ES|QL query's FROM clause",
        unquote=True)


def view_name(base_pattern: str, world_id: str) -> str:
    """The alias a world's queries read, as a refusal this seam can record.

    The naming rule is `confinement.world_view`, kept beside `confine_index` so the names built
    and the names admitted cannot drift apart. This wrapper converts its `ValueError` into a
    `StagingError` (usage exit code), so the call is recorded `refused` rather than tripping the
    circuit breaker.
    """
    try:
        return world_view(base_pattern, world_id)
    except ViewNameError as bad_name:
        raise StagingError(str(bad_name)) from bad_name


#: Which payload field each staged verb echoes its corpus identity back in — what `restore`
#: needs to know. Both echoes are model-facing (`search_envelope`'s `index`, `esql_payload`'s
#: query text), so an unrestored staged call shows the model a corpus name it never wrote.
_ECHOED_FIELD = {"query": "index", "alerts": "index", "esql": "query"}


def restore(verb: str, payload: Any, asked: dict, prepared: dict, ctx: Any = None) -> Any:
    """`payload` with the corpus identity `redirect` replaced put back.

    The inverse of `redirect`. Without it every staged payload differs base-vs-sibling in a
    field no world touched, so ΔO over the event stream is non-zero on every row. It also stops
    the echoed view name from re-entering as a query: a lead narrowing the template it was
    served would re-bind it, `redirect` would stage it twice, and `confine_index` would refuse.

    Field-targeted, never textual: detection alerts carry their rule's own index patterns, which
    are evidence. And only when the field still holds exactly what was sent; an unfamiliar shape
    is left alone. An echo field missing from `_ECHOED_FIELD` therefore stays unrestored, which
    `test_the_restored_payload_matches_the_base` catches by deriving the shape from the adapter.
    """
    field = _ECHOED_FIELD.get(verb)
    if field is None or not isinstance(payload, dict) or field not in payload:
        return payload
    if payload[field] != prepared.get(field):
        return payload
    asked_identity = _asked_identity(verb, asked, ctx)
    if asked_identity is None:
        # Without a `ctx` an omitted `index` has no resolvable pattern; writing `None` back
        # would invent `index: null`. Leave the payload alone (`redirect` refuses this input).
        return payload
    return {**payload, field: asked_identity}


def _asked_identity(verb: str, asked: dict, ctx: Any = None) -> Any:
    """What the echoed field would have held had this call never been staged.

    For `esql`, the query text as sent (the base passes it through untouched). For the
    param-indexed verbs, the source the call addressed, which for an omitted index is the
    configured default — exactly what `source_pattern` answers.
    """
    if verb == "esql":
        return asked.get("query")
    return source_pattern(verb, asked, ctx)


def declares(overlay: Any, base_pattern: str) -> bool:
    """Does this world's overlay stage `base_pattern`?

    Key equality, never reach: staging creates one alias per overlay key, so a narrower source
    under a declared wildcard has no view of its own, and retargeting it to the wide alias would
    answer with the wide corpus. It reads the base instead, recorded as `passthrough`.

    An absent overlay is not "declares nothing"; `redirect` handles that case.
    """
    table = getattr(overlay, "elastic", None) or {}
    return base_pattern in table


def redirect(verb: str, params: dict, world_id: str | None, ctx: Any = None, *,
             overlay: Any = None) -> dict:
    """`params` pointed at `world_id`'s view of whatever corpus they already address.

    `world_id is None` is the base world: params come back untouched, so a base-versus-sibling
    difference is exactly the sibling's staging.

    The base pattern is read off the call, or for an index-less `query`/`alerts` from the run's
    configured default via `source_pattern`. With no `ctx` that default cannot be resolved, and
    the call is refused rather than staged on a guess.

    `overlay` narrows retargeting to the patterns the world declares (`declares`). An undeclared
    pattern has no alias, and retargeting to it would silently return zero hits (`_search` sets
    `ignore_unavailable=true`); it reads the base instead, recorded `passthrough`. With no
    overlay supplied, a touching world stages every corpus its calls address — "not told" is
    not "declares nothing".

    The index-less refusal takes precedence over passthrough: "could not tell whether this is
    declared" is not "not declared". Fail closed.
    """
    # `stages(verb)`, the same predicate `applier.apply` uses, so a verb cannot report STAGED
    # on a call passed through here untouched.
    if world_id is None or not stages(verb):
        return params
    if verb in PARAM_INDEXED:
        base = source_pattern(verb, params, ctx)
        if base is None:
            raise StagingError(
                f"{verb} addresses its corpus through the run's configured default, which "
                "cannot be retargeted from here — pass an explicit index to stage this world")
        if overlay is not None and not declares(overlay, base):
            return params
        return {**params, "index": view_name(base, world_id)}
    # One parse for both the source list and the METADATA suffix. `rewrite_from` keeps its own
    # parse as the public splice.
    body = params.get("query")
    if not isinstance(body, str):
        raise StagingError(f"esql params carry no query body: {params!r}")
    clause = _parse_from(body, "this ES|QL query")
    base = _one_source(clause.sources, "this ES|QL query's FROM clause", unquote=True)
    if overlay is not None and not declares(overlay, base):
        return params
    view = view_name(base, world_id)
    # Before the rewrite, so the refusal quotes the query the model wrote.
    refuse_identifying_metadata(clause.suffix, body)
    return {**params, "query": rewrite_from(body, view)}
