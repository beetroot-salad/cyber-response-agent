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
`query`/`alerts` run their index through `confine_index` and `esql` (elastic_adapter.py's
`esql`) confines nothing, so its `FROM` reaches wherever it is pointed. A world view is named
OUTSIDE the pattern it stages — see `confinement.VIEW_NAMESPACE` for why a view the pattern
still reaches lets the base run collect every sibling's staged documents — so the confined
half cannot be admitted by reach and is admitted by DECLARATION instead: the estate registry
hands the adapter a ctx naming the world, and `confine_index` resolves that world's views and
no sibling's.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from defender.scripts.adapters.confinement import (
    ViewNameError,
    refuse_unnameable_world,
    world_view,
)
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


def check_world_id(world_id: str) -> None:
    """Refuse a world whose id no view of this corpus could be named with — BEFORE it serves.

    The id reaches `world_view` unfiltered on every staged call, so an id carrying a space, a
    `*` or upper case does not refuse one query, it refuses the whole event stream: every
    `esql`/`query`/`alerts` call lands as a `refused` row while the base world keeps all of it.
    That reads as a sibling that asked nothing rather than as a world that cannot be named, and
    it is the same silent-measurement shape the `touches` check is placed early to catch. Asked
    once, where the world arrives, because the answer cannot vary per call.
    """
    try:
        refuse_unnameable_world(world_id)
    except ViewNameError as bad_name:
        raise StagingError(str(bad_name)) from bad_name


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


@dataclass(frozen=True)
class _FromClause:
    """One ES|QL query's leading `FROM`, split into the parts a retarget needs.

    ONE parse, because there was nearly two: `source_pattern` read the source list out of this
    clause and `rewrite_from` read the `METADATA` suffix out of the same one, each re-running
    `split_first_command` → `_FROM.match` → `_METADATA.search` and each raising its own wording
    for the same "does not open with FROM". `redirect` calls both on every staged query, so a
    fix to the METADATA-boundary rule — the one `_METADATA`'s own comment says a `\\b` spelling
    gets silently wrong — could land in one copy and leave the other reading the same query
    differently, which is the half-retarget this module refuses everywhere else.
    """

    lead: str      #: `FROM` and the whitespace after it, exactly as written
    sources: str   #: the source list, stripped
    suffix: str    #: ` METADATA …` when the command carries one, else empty
    gap: str       #: the author's whitespace before the next pipe stage
    tail: str      #: everything from the first real separator on, separator included


def _parse_from(query: str, origin: str) -> _FromClause:
    # QUOTE-AWARE, not `partition('|')`: a `|` inside a quoted source name
    # (`FROM "logs|weird"`) is DATA, and splitting there cuts the source in half.
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
        # The author's whitespace BEFORE `METADATA` is carried, not normalised to one space,
        # for the same reason `gap` below carries the whitespace before the pipe: `FROM logs-*\n
        # METADATA _id` is a two-line command, and rebuilding it as `FROM wv-a-logs METADATA
        # _id` reflows text no world touched. `_METADATA` only matches after whitespace or at
        # the start of `rest`, and an `\A` match leaves `sources` empty and is refused above, so
        # there is always at least one character here.
        suffix=f"{head[len(head.rstrip()):]}{rest[meta.start():].rstrip()}" if meta else "",
        # The whitespace between the command and the pipe is the author's formatting — usually
        # the newline that puts each pipe stage on its own line. Taken from `rest` in BOTH
        # branches: measuring it only on the no-METADATA path silently joined `METADATA _id` to
        # the following `| WHERE`, turning a two-line query into one.
        gap=rest[len(rest.rstrip()):], tail=tail)


#: The ES|QL metadata fields that carry a corpus identity INTO THE ROWS. `_index` is the
#: concrete index each row came from, so a query selecting it answers with names that differ
#: base-vs-sibling — in `payload["values"]`, which is evidence and which `restore` must never
#: rewrite.
#:
#: `_id` is deliberately NOT here, and the distinction is the staging mechanism's. An id is
#: SCOPED BY an index rather than naming one, and a view that carries the same documents
#: carries the same ids — so `METADATA _id` answers identically base-vs-sibling and refusing it
#: would cost the sibling a whole class of query the base still serves, which is the difference
#: this module exists not to create. If a world's view is ever built by RE-MINTING ids instead
#: of by aliasing or by preserving them on copy, this tuple is the line that has to change.
_IDENTIFYING_METADATA = ("_index",)


def refuse_identifying_metadata(clause: str, query: str) -> None:
    """Refuse an ES|QL query whose ROWS would carry the corpus identity.

    `restore` puts back the identity the retarget replaced, but only in the fields a verb is
    known to ECHO — never in `values`, because those are the documents and rewriting them is
    editing evidence. `FROM … METADATA _index` puts the index name in a column, so the sibling's
    rows differ from the base's by the harness's own naming and nothing in the seam can undo it.

    REFUSED rather than served, and this is the one place that trade goes this way. Everywhere
    else the module bends to keep a sibling's evidence — a refusal costs the pair a query the
    base still answers, which is the difference this seam exists not to create. Here serving it
    costs the same thing invisibly: ΔO reads a difference in every row and no reader can tell
    it from the world's. A refusal at least lands in the ledger saying so.

    No committed template selects `_index` (all 12 `esql` templates go through `FROM <pattern>`
    with no METADATA clause at all), so today this costs nothing and speaks up if one arrives.
    """
    # COMMA-DELIMITED as well as space-delimited: `METADATA _index, _id` tokenizes to
    # `_index,` on a bare `split()`, so the field named FIRST in a list would not match itself.
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

    Only the source list moves. A `METADATA` suffix belongs to the same command and is kept, as
    is every downstream pipe stage — the query the defender wrote is the query that runs, over
    a different corpus.
    """
    c = _parse_from(query, "this ES|QL query")
    return f"{c.lead}{view}{c.suffix}{c.gap}{c.tail}"


def _one_source(
    expression: str, origin: str, *, unquote: bool = False, verbatim: bool = False,
) -> str:
    """The single corpus `expression` addresses, or a refusal.

    A COMMA LIST IS REFUSED WHOLE, never partially retargeted. ES|QL admits `FROM a-*, b-*`,
    and staging only the sources a world happens to have a view for leaves the query reading
    the unstaged base for the rest — the world's difference silently absent from half the
    evidence, in a run that looks like it worked. Refusing whole is also the doctrine
    `confine_index` already applies to a multi-index expression (§7 R5): refuse rather than
    silently narrow.

    Quotes are stripped rather than carried, but ONLY on the ES|QL path (`unquote`), because
    only there are they syntax. A view is a name this module constructs, so appending to a
    quoted source would build `"logs-*"-w-A` — a name no index answers to.

    The `index` PARAMETER is not ES|QL text and carries no quoting rule: `_search_verb` hands
    its value to `confine_index` verbatim, so `index='"logs-*"'` is a `ConfinementFault` on the
    base run. Stripping there too staged and SERVED a call the base refuses — a base-vs-sibling
    difference owned by the harness rather than the world, in the permissive direction.

    `verbatim` is that rule applied to WHITESPACE as well as to quotes, and it is the same
    argument: `confine_index(" logs-* ")` faults on the base run because `_reach_ok` compares
    the string it is given, so trimming here built a well-formed view and served a sibling the
    answer its base was refused. The ES|QL path and the run's configured default keep the trim —
    there the surrounding text is the language's or the config reader's, not the caller's value.
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

    An omitted `index` is resolved through the RUN'S OWN CONFIG, the same file and key the
    adapter would have fallen back to. `elastic_adapter.query`/`alerts` declare
    `index: str | None = None` on purpose and a shipped template relies on it —
    `correlate-alerts-by-entity.md` is `params: [end, start]` and its prose says "the verb
    defaults its `index` to …, so there is no FROM to write". Refusing that call would drop a
    whole evidence class from the sibling while the base kept it: a base-vs-sibling difference
    that is the STAGER'S, not the world's, which is the one kind this seam must never create.

    FALSY IS OMITTED, and that reading is the ADAPTER'S rather than this module's opinion:
    `_search_verb` resolves `index or config[index_key]`, so `index=""` and an explicit
    `index=None` address the configured default exactly as an absent one does — both are
    declarable, since the param is `str | None = None` and `validate_params` passes both.
    Refusing them here would answer a call the base run serves in full with a `refused` row on
    every sibling, which is the harness-owned difference the paragraph above forbids. A present
    value that is TRUTHY and not a string is a broken CALL and stays refused: `_search_verb`
    hands it to `confine_index`, which faults on the base run too, so the two arms agree.
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
        from defender.scripts.adapters.elastic_adapter import load_config

        return _one_source(
            load_config(ctx)[_DEFAULT_INDEX_KEY[verb]], f"{verb}'s configured default index")
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

    The RULE is `confinement.world_view` and lives there, next to `confine_index`, because the
    two halves of a world view are one decision: the name is built OUTSIDE every configured
    pattern — so the base run and the siblings that do not stage the event stream cannot reach
    it through the pattern it came from — and it is therefore admitted by declaration rather
    than by reach. Split across two modules, a naming change here would silently stop matching
    the names confinement admits there, and every staged read would fault as out of bounds.

    What is this module's is the ERROR CLASS. `world_view` raises a plain `ValueError`: naming
    is not confinement, and it has no view on how a refusal reaches a model. Here it becomes a
    `StagingError` — an `AdapterFault` carrying the USAGE code — so `redirect`'s caller records
    it as a REFUSED row and the circuit breaker does not read a capability refusal as the
    estate being down for this sibling and up for its base.
    """
    try:
        return world_view(base_pattern, world_id)
    except ViewNameError as bad_name:
        raise StagingError(str(bad_name)) from bad_name


#: Which payload field each staged verb ECHOES its corpus identity back in — the inverse of
#: the two redirection paths, and the whole of what `restore` needs to know.
#:
#: The echo is not incidental. `search_envelope`'s docstring calls `index` "the contract a lead
#: reads and a payload on disk keeps", and `esql_payload` returns the query text because
#: `sql.py`'s ES|QL idiom reads it back. Both are model-facing, so on a staged call both hand a
#: sibling a corpus name its model never wrote.
_ECHOED_FIELD = {"query": "index", "alerts": "index", "esql": "query"}


def restore(verb: str, payload: Any, asked: dict, prepared: dict, ctx: Any = None) -> Any:
    """`payload` with the corpus identity `redirect` replaced put back.

    THE INVERSE OF `redirect`, and it lives beside it so the two are authored together. A
    retarget that is not undone here leaves every staged payload differing base-vs-sibling in a
    field NO WORLD TOUCHED: identical corpora, identical rows, and a `query` reading `FROM
    wv-a-logs-falco.alerts` against the base's `FROM logs-falco.alerts-*`. ΔO over the event
    stream — where most of a run's evidence lives — is then non-zero on every row, and "the
    sibling saw something different" stops meaning anything.

    It also stops the payload from re-entering as a query. A lead that narrows the template it
    was just served — which `falco-alerts.md`'s own "Narrowing examples" section tells it to do
    — re-binds the echoed text, `redirect` stages the already-staged name to
    `wv-a-wv-a-logs-falco.alerts`, and `confine_index` refuses it. The base run narrows and
    gets an answer; the sibling faults. That is a base-vs-sibling difference belonging to the
    HARNESS rather than the world, which is the one kind this seam must never create.

    FIELD-TARGETED, never textual. A detection alert carries its own rule's parameters, and
    this environment's `v2-sshd-failed-auth-burst.json` declares `index: ["logs-system.auth-*"]`
    — so replacing the pattern wherever it appears in a payload would rewrite a field inside
    the EVIDENCE. Only the field the verb is known to echo is touched.

    ONLY WHEN THE FIELD STILL HOLDS WHAT WE SENT. If the echo does not carry the staged
    identity, this module did not put it there and has no business rewriting it — a payload
    shape it does not understand is left alone rather than edited on a guess. The cost of that
    rule is the one thing it cannot catch: an echo field nobody listed stays un-restored, and
    ΔO reads it as a world difference forever. `test_the_restored_payload_matches_the_base`
    derives the shape from the ADAPTER rather than restating it, so a new echo is a red test.
    """
    field = _ECHOED_FIELD.get(verb)
    if field is None or not isinstance(payload, dict) or field not in payload:
        return payload
    if payload[field] != prepared.get(field):
        return payload
    asked_identity = _asked_identity(verb, asked, ctx)
    if asked_identity is None:
        # FAILS CLOSED, the way `redirect` does on the SAME missing input. Without a `ctx` an
        # omitted `index` has no resolvable base pattern, and writing the `None` back would put
        # `index: null` into the payload the model reads and the row a cross-world comparison
        # pairs on — a corpus identity no run ever had. `redirect` refuses that input outright
        # ("pass an explicit index to stage this world"); the mirror leaves the payload alone,
        # which is this function's own rule for a shape it cannot account for.
        return payload
    return {**payload, field: asked_identity}


def _asked_identity(verb: str, asked: dict, ctx: Any = None) -> Any:
    """What the echoed field would have held had this call never been staged.

    For `esql` that is the query text the model sent, verbatim — the base run passes its body
    through untouched, so the asked form IS the base's.

    For the param-indexed verbs it is the SOURCE the call addressed, which is not always the
    `index` parameter: `_search_verb` resolves `index or config[index_key]`, so an omitted
    index means the run's configured default and that is what the base run's payload echoes.
    `source_pattern` already answers exactly that question, through the same file and key.
    """
    if verb == "esql":
        return asked.get("query")
    return source_pattern(verb, asked, ctx)


def redirect(verb: str, params: dict, world_id: str | None, ctx: Any = None) -> dict:
    """`params` pointed at `world_id`'s view of whatever corpus they already address.

    `world_id is None` is the base world — it stages nothing, so its params come back untouched
    and its payloads ARE the estate's. That is what makes a base-versus-sibling difference read
    as exactly the sibling's staging, with no third thing to subtract.

    The base pattern is read off the CALL where the call carries one, so the view is derived
    from what this query actually asked for. A `query`/`alerts` call that leaves `index` unset
    is addressing the RUN'S CONFIGURED DEFAULT, and `source_pattern` reads that same key from
    that same file rather than guessing — see its docstring for why refusing instead would drop
    a whole evidence class from the sibling while the base kept it. The refusal below is what
    remains: a frame with no `ctx` to read the config through cannot resolve the default, and a
    view built on a guess stages a world into an index nobody reads.
    """
    # `stages(verb)` rather than a second spelling of the same set: `applier.apply` already
    # asks it to decide whether a call was staged, so two independently-written complements
    # here would let a verb report STAGED on a call this function passed through untouched.
    if world_id is None or not stages(verb):
        return params
    if verb in PARAM_INDEXED:
        base = source_pattern(verb, params, ctx)
        if base is None:
            raise StagingError(
                f"{verb} addresses its corpus through the run's configured default, which "
                "cannot be retargeted from here — pass an explicit index to stage this world")
        return {**params, "index": view_name(base, world_id)}
    # ONE CLAUSE for the source list AND the METADATA suffix. Read through `source_pattern`
    # and then a second time for the suffix, this arm ran `split_first_command` →
    # `_FROM.match` → `_METADATA.search` twice over the same text before `rewrite_from` ran it
    # a third — which is also the drift `_FromClause`'s docstring says the single parse exists
    # to prevent, reintroduced by the caller. `rewrite_from` keeps its own parse: it is the
    # splice's one public spelling and the tests read it directly.
    body = params.get("query")
    if not isinstance(body, str):
        raise StagingError(f"esql params carry no query body: {params!r}")
    clause = _parse_from(body, "this ES|QL query")
    view = view_name(
        _one_source(clause.sources, "this ES|QL query's FROM clause", unquote=True), world_id)
    # BEFORE the rewrite, so the refusal names the query the model wrote rather than one it
    # has never seen. A `METADATA` clause selecting the corpus identity survives into the rows,
    # which `restore` cannot follow it into — see `refuse_identifying_metadata`.
    refuse_identifying_metadata(clause.suffix, body)
    return {**params, "query": rewrite_from(body, view)}
