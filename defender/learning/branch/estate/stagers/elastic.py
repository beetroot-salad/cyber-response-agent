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

#: The leading `FROM` command. ES|QL requires it FIRST, which is what makes this a
#: leading-clause substitution rather than general query-language surgery: everything after the
#: first pipe is another command and is never touched.
_FROM = re.compile(r"\A(?P<lead>\s*FROM\s+)(?P<rest>.*)\Z", re.IGNORECASE | re.DOTALL)
#: `FROM <sources> METADATA <fields>` — the one suffix that may follow the source list inside
#: the same command, and it must survive the rewrite.
_METADATA = re.compile(r"\bMETADATA\b", re.IGNORECASE)

#: Verbs whose index is a PARAMETER rather than part of the query body.
PARAM_INDEXED = ("query", "alerts")


class StagingError(Exception):
    """A query that cannot be pointed at a world's view."""


def rewrite_from(query: str, view: str) -> str:
    """Retarget an ES|QL query's leading `FROM` at `view`, preserving everything else.

    Only the source list moves. A `METADATA` suffix belongs to the same command and is kept, as
    is every downstream pipe stage — the query the defender wrote is the query that runs, over
    a different corpus.
    """
    head, sep, tail = query.partition("|")
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
    return f"{m.group('lead')}{view}{suffix}{gap}{sep}{tail}"


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


def source_pattern(verb: str, params: dict) -> str | None:
    """Where this call addresses its corpus, by whichever route the verb carries it."""
    if verb in PARAM_INDEXED:
        index = params.get("index")
        if not isinstance(index, str) or not index:
            return None
        return _one_source(index, f"{verb}'s index parameter")
    if verb != "esql":
        return None
    body = params.get("query")
    if not isinstance(body, str):
        raise StagingError(f"esql params carry no query body: {params!r}")
    m = _FROM.match(body.partition("|")[0])
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
    """
    return f"{base_pattern.rstrip('*').rstrip('-.')}-w-{world_id}"


def redirect(verb: str, params: dict, world_id: str | None) -> dict:
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
    base = source_pattern(verb, params)
    if base is None:
        raise StagingError(
            f"{verb} addresses its corpus through the run's configured default, which cannot "
            "be retargeted from here — pass an explicit index to stage this world")
    view = view_name(base, world_id)
    if verb in PARAM_INDEXED:
        return {**params, "index": view}
    return {**params, "query": rewrite_from(params["query"], view)}
