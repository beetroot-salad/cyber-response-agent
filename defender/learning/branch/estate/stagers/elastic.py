"""Point an elastic query at a world's view of the corpus.

The event stream is the one system where a world is STAGED rather than patched: its documents
are prepared before the query runs, and Elasticsearch does its own filtering, aggregation and
sorting over them. That is why nothing here composes a result — a `STATS COUNT(*) BY source.ip`
over a mutated world is correct by construction, where a composed answer would be a guess, and
two queries touching the same fact cannot disagree because they read the same documents.

A world's view is `base − exclude + inject`. **Removal is not optional**: the 2026-08-16
turn-N experiment's world B was an absence — whether the `nc` activity has a recurring cadence
outside the alert window — and an additive-only pipeline cannot express that at all.

REDIRECTION IS TWO PATHS, because elastic's index targeting is not uniform. Of the 15 committed
templates under `skills/gather/queries/elastic/`, 12 are `esql`, where the index lives in a
`FROM` clause inside the query BODY; only `query` and `alerts` take an `index` parameter.

One asymmetry the caller has to know about, and it is pre-existing rather than introduced here:
`query`/`alerts` run their index through `confine_index`, so a world view must fall inside the
run's configured patterns — a branched run declares its own. `esql` (elastic_adapter.py's
`esql`) confines nothing, so its `FROM` reaches wherever it is pointed.
"""

from __future__ import annotations

import re
from typing import Any

from defender.scripts.adapters.esql_text import split_first_command
from defender.scripts.adapters.faults import USAGE_EXIT_CODE, AdapterFault

#: The leading `FROM` command. ES|QL requires it FIRST, which is what makes this a
#: leading-clause substitution rather than general query-language surgery: everything after the
#: first pipe is another command and is never touched.
_FROM = re.compile(r"\A(?P<lead>\s*FROM\s+)(?P<rest>.*)\Z", re.IGNORECASE | re.DOTALL)
#: `FROM <sources> METADATA <fields>` — the one suffix that may follow the source list inside
#: the same command, and it must survive the rewrite.
#:
#: WHITESPACE-DELIMITED, not `\b`-delimited. `-` and `.` are non-word characters, so `\bMETADATA\b`
#: matches INSIDE an ordinary index name: `FROM logs-metadata-*` split as `logs-` plus a
#: `METADATA metadata-*` suffix, staging half the query against the base corpus and emitting a
#: two-source `FROM` — the silent half-retarget `_one_source` refuses a comma list to prevent —
#: while `FROM metadata-events-*` was refused outright as naming no source.
_METADATA = re.compile(r"(?:(?<=\s)|\A)METADATA(?=\s|\Z)", re.IGNORECASE)

#: Verbs whose index is a PARAMETER rather than part of the query body.
PARAM_INDEXED = ("query", "alerts")

#: Which config key each param-indexed verb defaults its index to, mirroring
#: `elastic_adapter.query`/`alerts`. A call that omits `index` is not indexless — it is
#: addressing THIS, and a stager that cannot see it would have to refuse a shipped template.
_DEFAULT_INDEX_KEY = {"query": "ELASTIC_EVENTS_INDEX", "alerts": "ELASTIC_ALERTS_INDEX"}


def stages(verb: str) -> bool:
    """Does retargeting this verb do anything?

    `health-check` reaches no corpus, so a world stages nothing for it — and reporting it as
    STAGED would put a decision in the ledger that names the system honestly and the CALL
    wrongly.
    """
    return verb in PARAM_INDEXED or verb == "esql"


class StagingError(AdapterFault):
    """A query that cannot be pointed at a world's view.

    An `AdapterFault` carrying the USAGE code, not a bare exception. It is raised from inside
    the served verb body, so `QueryCapture` is what meets it — and its catch-all maps an
    unrecognised exception to `DEFAULT_FAULT_EXIT`, which is 2, which is in
    `circuit_breaker.INFRA_EXIT_CODES`. A capability refusal would therefore have been counted
    as an environment outage: two of them trip the breaker for the whole system and five abort
    the run, so the pair would measure "the estate was up for the base and down for the
    sibling" — the contamination the base/sibling design exists to exclude. Every refusal here
    also names something the caller can act on (pass an explicit index; address one corpus;
    open with FROM), which is what the usage class means.
    """

    exit_code = USAGE_EXIT_CODE


def rewrite_from(query: str, view: str) -> str:
    """Retarget an ES|QL query's leading `FROM` at `view`, preserving everything else.

    Only the source list moves. A `METADATA` suffix belongs to the same command and is kept, as
    is every downstream pipe stage — the query the defender wrote is the query that runs, over
    a different corpus.
    """
    # QUOTE-AWARE, not `partition('|')`: a `|` inside a quoted source name
    # (`FROM "logs|weird"`) is DATA, and splitting there cuts the source in half.
    head, tail = split_first_command(query)
    m = _FROM.match(head)
    if m is None:
        raise StagingError(
            f"ES|QL query does not open with FROM, so its corpus cannot be retargeted: "
            f"{query[:80]!r}")
    rest = m.group("rest")
    meta = _METADATA.search(rest)
    suffix = f" {rest[meta.start():].rstrip()}" if meta else ""
    # The whitespace between the command and the pipe is the author's formatting — usually the
    # newline that puts each pipe stage on its own line. Taken from `rest` in BOTH branches:
    # measuring it only on the no-METADATA path silently joined `METADATA _id` to the following
    # `| WHERE`, turning a two-line query into one.
    gap = rest[len(rest.rstrip()):]
    return f"{m.group('lead')}{view}{suffix}{gap}{tail}"


def _one_source(expression: str, origin: str) -> str:
    """The single corpus `expression` addresses, or a refusal.

    A COMMA LIST IS REFUSED WHOLE, never partially retargeted. ES|QL admits `FROM a-*, b-*`,
    and staging only the sources a world happens to have a view for leaves the query reading
    the unstaged base for the rest — the world's difference silently absent from half the
    evidence, in a run that looks like it worked. Refusing whole is also the doctrine
    `confine_index` already applies to a multi-index expression (§7 R5): refuse rather than
    silently narrow.

    Quotes are stripped rather than carried. A view is a name this module constructs, so
    appending to a quoted source would build `"logs-*"-w-A` — a name no index answers to.
    """
    source = expression.strip()
    if "," in source:
        raise StagingError(
            f"{origin} addresses several corpora ({source!r}) and cannot be staged whole — "
            "retargeting only some of them would leave the query reading the unstaged base "
            "for the rest, with the world's difference silently missing from that half")
    if len(source) >= 2 and source[0] == source[-1] and source[0] in "\"'":
        source = source[1:-1].strip()
    return source


def source_pattern(verb: str, params: dict, ctx: Any = None) -> str | None:
    """Where this call addresses its corpus, by whichever route the verb carries it.

    An omitted `index` is resolved through the RUN'S OWN CONFIG, the same file and key the
    adapter would have fallen back to. `elastic_adapter.query`/`alerts` declare
    `index: str | None = None` on purpose and a shipped template relies on it —
    `correlate-alerts-by-entity.md` is `params: [end, start]` and its prose says "the verb
    defaults its `index` to …, so there is no FROM to write". Refusing that call would drop a
    whole evidence class from the sibling while the base kept it: a base-vs-sibling difference
    that is the STAGER'S, not the world's, which is the one kind this seam must never create.
    """
    if verb in PARAM_INDEXED:
        index = params.get("index")
        if isinstance(index, str) and index:
            return _one_source(index, f"{verb}'s index parameter")
        if ctx is None:
            return None
        from defender.scripts.adapters.elastic_adapter import load_config

        return _one_source(
            load_config(ctx)[_DEFAULT_INDEX_KEY[verb]], f"{verb}'s configured default index")
    if verb != "esql":
        return None
    body = params.get("query")
    if not isinstance(body, str):
        raise StagingError(f"esql params carry no query body: {params!r}")
    m = _FROM.match(split_first_command(body)[0])
    if m is None:
        raise StagingError(f"ES|QL query does not open with FROM: {body[:80]!r}")
    rest = m.group("rest")
    meta = _METADATA.search(rest)
    listed = (rest[: meta.start()] if meta else rest).strip()
    if not listed:
        raise StagingError(f"ES|QL query names no source after FROM: {body[:80]!r}")
    return _one_source(listed, "this ES|QL query's FROM clause")


def view_name(base_pattern: str, world_id: str) -> str:
    """The alias a world's queries read.

    Per WORLD, never shared: siblings reading one view would see each other's staged documents,
    and the pair would be measuring contamination rather than a difference.

    The stem must be a NAME an alias can carry, and two degenerate patterns are not. `*` trims
    to the empty string, so the view would be `-w-A` — a leading `-` is an exclusion pattern to
    ES|QL and an illegal first character for an index or alias, so the staged query resolves to
    no sources at all. A pattern wildcarded anywhere but the tail (`logs-*-2026`) keeps its `*`
    inside the derived name, which no alias answers to. Both are refused rather than guessed,
    for the reason the no-index arm below is: a view nobody reads runs the sibling green
    against the BASE corpus while reporting a world that was never applied.
    """
    stem = base_pattern.rstrip("*").rstrip("-.")
    if not stem or "*" in stem:
        raise StagingError(
            f"{base_pattern!r} does not reduce to an alias name (got {stem!r}) — a world view "
            "is built by suffixing the corpus it stages, and a bare wildcard or one that is "
            "not a trailing suffix leaves nothing to suffix")
    return f"{stem}-w-{world_id}"


def redirect(verb: str, params: dict, world_id: str | None, ctx: Any = None) -> dict:
    """`params` pointed at `world_id`'s view of whatever corpus they already address.

    `world_id is None` is the base world — it stages nothing, so its params come back untouched
    and its payloads ARE the estate's. That is what makes a base-versus-sibling difference read
    as exactly the sibling's staging, with no third thing to subtract.

    The base pattern is read off the CALL rather than from config, so the view is derived from
    what this query actually asked for. A `query`/`alerts` call that leaves `index` unset is
    addressing the config default, which this frame cannot see — refused rather than guessed,
    because guessing wrong stages a world into an index nobody reads.
    """
    if world_id is None or verb not in (*PARAM_INDEXED, "esql"):
        return params
    base = source_pattern(verb, params, ctx)
    if base is None:
        raise StagingError(
            f"{verb} addresses its corpus through the run's configured default, which cannot "
            "be retargeted from here — pass an explicit index to stage this world")
    view = view_name(base, world_id)
    if verb in PARAM_INDEXED:
        return {**params, "index": view}
    return {**params, "query": rewrite_from(params["query"], view)}
