"""#920 PR 1 — pointing an elastic query at a world's view of the corpus.

The event stream is the ONE system a world is staged into rather than patched: its documents
are prepared before the query runs, and Elasticsearch does its own filtering, aggregation and
sorting over them. Nothing composes a result, which is what makes a `STATS COUNT(*) BY
source.ip` over a mutated world correct by construction and what keeps two queries touching one
fact from disagreeing.

That only holds if the retarget is a SUBSTITUTION and nothing else. The query the defender
wrote has to be the query that runs — same pipe stages, same `METADATA` clause, same
whitespace — over a different corpus. So the sweep here is over the REAL committed templates
(`skills/gather/queries/elastic/*.md`), not over queries invented for the test: those 12 ES|QL
bodies are what a gather lead actually sends, and a rewrite that mangles a multi-line `STATS`
would be a scenario that silently measures nothing.

Redirection is TWO PATHS, because elastic's index targeting is not uniform: `query` and
`alerts` carry an `index` PARAM, while `esql` carries its corpus in a `FROM` clause inside the
query body. Both are pinned, as are the two refusals around the param path. A call that OMITS
`index` is addressing the run's configured default, and with a `ctx` in hand the stager reads
that same key from that same file (#946) rather than dropping a shipped template's whole
evidence class from the sibling; with no `ctx` there is nothing to read and it refuses, because
guessing wrong stages a world into an index nobody reads. A call whose `index` is PRESENT and
unusable is a different fact — a broken call, refused outright, since quietly substituting the
default would serve the sibling a corpus the model never named while the base took the fault.

The base world (`world_id=None`) is the null case that makes a sibling comparison readable: it
stages nothing, so its payloads ARE the estate's and a base-versus-sibling difference is
exactly the sibling's staging, with no third thing to subtract.

WHAT THIS FILE DOES NOT OWN. Whether staging happens at all — the `touches` gate, the applier's
decision vocabulary, the ledger — is `test_920_estate_seam.py`, which also drives one
retargeted call all the way into a real adapter body. Here the subject is the rewrite itself,
so the tests are over the stager's own functions and stay hermetic by construction.
"""
from __future__ import annotations

import re

import pytest

from defender._paths import PATHS
from defender.learning.branch.estate.stagers import elastic
from defender.scripts.adapters import confinement
from defender.learning.branch.estate.stagers.dispatch import STAGERS
from defender.runtime.verbs import VerbContext

#: The run context the stager reads config through — the SHIPPED tree, because the keys it
#: resolves (`ELASTIC_EVENTS_INDEX`/`ELASTIC_ALERTS_INDEX`) are the ones the adapter falls back
#: to, and a fixture of our own would pin the stager against a file no run ever reads.
_CTX = VerbContext(defender_dir=PATHS.defender_dir, run_dir=PATHS.defender_dir, env={})

#: The committed elastic catalog: 15 templates, 12 of them ES|QL. Both numbers are asserted
#: below rather than merely derived, because a corpus that shrank to one template would make
#: every parametrized case below pass over less and stay green.
#: Off `PATHS.catalog_dir`, not a fifth hand-spelling of the four segments it already owns:
#: a catalog relocation would otherwise leave this glob empty, `COMMITTED` empty, and every
#: parametrized case below silently collecting zero.
CATALOG = PATHS.catalog_dir / "elastic"
TEMPLATE_FILES = 15
ESQL_TEMPLATES = 12

#: The fenced ES|QL body of a committed template. Deliberately naive — an ```esql fence is the
#: catalog's own marker for "this is the query that runs", and a reader that had to understand
#: the surrounding prose would be a second parser to keep true.
_FENCE = re.compile(r"^```esql\n(.*?)^```", re.MULTILINE | re.DOTALL)


def committed_esql() -> list[tuple[str, str]]:
    """Every `(template stem, ES|QL body)` the shipped catalog carries."""
    return [
        (path.stem, body)
        for path in sorted(CATALOG.glob("*.md"))
        for body in _FENCE.findall(path.read_text(encoding="utf-8"))
    ]


COMMITTED = committed_esql()


def leading_source(body: str) -> str:
    """The corpus a committed template addresses, read off its first line.

    The test's OWN oracle, and deliberately not the stager's: every committed template opens
    with a bare `FROM <pattern>` on its own line, so a split is the whole of what the answer
    requires here. Calling `source_pattern` to compute the expected value would mean the
    assertion and the implementation could only ever agree.
    """
    first = body.splitlines()[0]
    assert first.startswith("FROM "), f"committed template does not open with FROM: {first!r}"
    return first[len("FROM "):].strip()


# the committed corpus: every template retargets, with its pipes intact

def test_the_committed_catalog_is_the_corpus_this_sweep_claims():
    """    15 committed templates, 12 of them ES|QL — the split the two redirection paths are sized
    against, and the guard on every parametrized case below."""
    assert len(list(CATALOG.glob("*.md"))) == TEMPLATE_FILES
    assert len(COMMITTED) == ESQL_TEMPLATES


@pytest.mark.parametrize(("stem", "body"), COMMITTED, ids=[s for s, _ in COMMITTED])
def test_every_committed_template_retargets_and_nothing_else_moves(stem, body):
    """    A real template comes back with its source list replaced and EVERY OTHER BYTE identical.

    The strongest form the claim can take: the rewritten query must equal the original with the
    first occurrence of the source pattern — the one in the leading `FROM` — swapped for the
    view. That covers the multi-line `STATS ... BY ...` blocks, the `WHERE` continuation lines,
    the trailing `| SORT`, and the exact whitespace of each, without the test having to
    enumerate them. `stem` rides along so a failure names the template."""
    base = leading_source(body)
    view = elastic.view_name(base, "w1")

    out = elastic.redirect("esql", {"query": body}, "w1")["query"]

    assert out == body.replace(base, view, 1), stem
    assert out.splitlines()[0] == f"FROM {view}"
    assert out.partition("|")[2] == body.partition("|")[2]


@pytest.mark.parametrize(("stem", "body"), COMMITTED, ids=[s for s, _ in COMMITTED])
def test_every_committed_template_reads_its_own_corpus(stem, body):
    """    `source_pattern` names the index the template itself addresses.

    The view is derived from what the query ASKED FOR rather than from config, so this is the
    input to every rewrite above: a stager that read the wrong pattern would stage a real
    world into a plausible-looking index nobody queries."""
    assert elastic.source_pattern("esql", {"query": body}) == leading_source(body), stem


def test_the_catalog_spans_more_than_one_corpus():
    """    The 12 templates address several distinct index patterns, including the dotted internal
    alerts index.

    A sweep over 12 templates that all read `logs-*` would be one case run twelve times; this
    is what makes the parametrization worth its cost, and it is also what pins that
    `view_name`'s trimming has to cope with more than one shape."""
    patterns = {leading_source(body) for _, body in COMMITTED}

    assert len(patterns) >= 8
    assert ".internal.alerts-security.alerts-default-*" in patterns


# the view name: per world, derived from the pattern

@pytest.mark.parametrize(("pattern", "world_id", "expected"), [
    ("logs-system.auth-*", "b", "wv-b-logs-system.auth-"),
    ("logs-*", "a", "wv-a-logs-"),
    (".internal.alerts-security.alerts-default-*", "z",
     "wv-z-.internal.alerts-security.alerts-default-"),
    ("logs-zeek.connection", "a", "wv-a-logs-zeek.connection"),
])
def test_a_view_name_trims_the_pattern_and_carries_the_world(pattern, world_id, expected):
    """    The alias a world's queries read: the pattern's trailing wildcard and separator trimmed,
    then prefixed with the namespace and the world id.

    Spelled as literals so the rule is legible here rather than only in the code — the sweep
    above uses `view_name` to build its expectation, and this is what keeps that from being
    circular."""
    assert elastic.view_name(pattern, world_id) == expected


@pytest.mark.parametrize("pattern", [
    "logs-*", ".internal.alerts-security.alerts-default-*", "logs-system.auth-*",
])
def test_a_world_view_falls_outside_the_pattern_it_was_derived_from(pattern):
    """    No configured pattern reaches the view built from it.

    THE reason the namespace is a prefix. A view SUFFIXED onto its own corpus — `logs-*` ->
    `logs-w-a` — is still matched by `logs-*`, and the callers that issue the base pattern
    verbatim are not siblings of each other: the BASE world stages nothing, so `redirect`
    hands its params back untouched, and so does any sibling whose `touches` omits the event
    stream. Both would read `wv-a-…` and `wv-b-…` alongside the estate's own documents —
    every world's staged difference in one answer, which is the pair measuring contamination
    rather than a difference, and it is the one thing the per-world view exists to prevent.

    Asserted through the SAME reach model `confine_index` evaluates a pattern with, so this
    cannot pass against a laxer notion of matching than the adapter's."""
    for world_id in ("a", "b"):
        view = elastic.view_name(pattern, world_id)

        assert not confinement._reach_ok(view, pattern), view


def test_two_siblings_never_share_a_view():
    """    Two worlds off one pattern get two different aliases.

    Per world, never shared: siblings reading one view would see each other's staged documents,
    and the pair would be measuring contamination rather than a difference."""
    a = elastic.view_name("logs-system.auth-*", "a")
    b = elastic.view_name("logs-system.auth-*", "b")

    assert a != b


# the ES|QL rewrite: what belongs to the FROM command, and what does not

def test_a_metadata_clause_survives_with_its_following_newline():
    """    `FROM <sources> METADATA <fields>` keeps the METADATA suffix AND the newline after it.

    The suffix belongs to the same command, so it moves with the rewrite. The newline is the
    author's formatting and is measured off the same text in both branches — taking it only on
    the no-METADATA path joined `METADATA _id` to the following `| WHERE`, turning a two-line
    query into one. Pinned as the exact string, because "METADATA is still in there somewhere"
    would pass on the joined query too."""
    body = 'FROM logs-system.auth-* METADATA _id, _index\n| WHERE user.name == "root"\n| LIMIT 5'

    out = elastic.rewrite_from(body, "wv-b-logs-system.auth-")

    assert out == (
        'FROM wv-b-logs-system.auth- METADATA _id, _index\n'
        '| WHERE user.name == "root"\n| LIMIT 5'
    )


def test_a_metadata_clause_is_not_mistaken_for_the_corpus():
    """    `source_pattern` reads the sources ALONE out of a `FROM ... METADATA ...` command.

    The other half of the same asymmetry: a reader that returned `logs-system.auth-* METADATA
    _id` would derive a view name with a metadata field baked into it, and stage the world into
    an index that cannot exist."""
    body = "FROM logs-system.auth-* METADATA _id\n| LIMIT 1"

    assert elastic.source_pattern("esql", {"query": body}) == "logs-system.auth-*"
    assert elastic.redirect("esql", {"query": body}, "b")["query"].splitlines()[0] \
        == "FROM wv-b-logs-system.auth- METADATA _id"


def test_only_the_leading_from_moves_even_when_a_pipe_stage_names_one():
    """    Everything after the first pipe is another command and is never touched — including a
    string literal that happens to spell `FROM logs-*`.

    This is a leading-CLAUSE substitution, not query-language surgery. A rewrite implemented as
    a global replace would silently edit a defender's own `EVAL`ed note, and the sibling's
    evidence would then differ from the base run's for a reason that has nothing to do with the
    world."""
    body = 'FROM logs-*\n| EVAL note = "read FROM logs-* earlier"\n| LIMIT 1'

    out = elastic.redirect("esql", {"query": body}, "w1")["query"]

    assert out == 'FROM wv-w1-logs-\n| EVAL note = "read FROM logs-* earlier"\n| LIMIT 1'


def test_a_multi_source_from_is_not_left_half_staged():
    """    A `FROM a-*, b-*` query must not come back with one source staged and one not.

    Half-staged is the worst of the three outcomes: the world's difference is silently absent
    from part of the evidence, the query still runs, and the sibling reports a measurement over
    a corpus that is partly the base run's. Refusing is a correct answer here — a query that
    cannot be pointed at a world's view is exactly what `StagingError` is for.

    The demand is the REFUSAL, not the absence of the first source. Asserting only
    `"logs-system.auth-*" not in out` is satisfied by the very output this test is named after:
    `FROM wv-b-logs-system.auth-, logs-nginx.access-*` drops the first spelling and leaves the
    second reading the unstaged base. Swallowing the refusal into `out = ""` made it weaker
    still — any unrelated `StagingError`, including a regression that refused every ES|QL body,
    passed."""
    body = "FROM logs-system.auth-*, logs-nginx.access-*\n| STATS COUNT(*)"

    with pytest.raises(elastic.StagingError) as refusal:
        elastic.redirect("esql", {"query": body}, "b")

    assert "several corpora" in str(refusal.value), (
        "the refusal names some other fault, so this passes without the multi-source rule "
        f"ever running: {refusal.value}")


def test_a_lowercased_from_still_retargets():
    """    ES|QL's `FROM` is case-insensitive, and so is the rewrite; the author's own casing
    survives.

    Model-written ad-hoc queries are not spelled to the catalog's house style, and a stager
    that only recognised the uppercase spelling would refuse a valid query — which, at the seam
    where refusing means the sibling cannot run, is the expensive direction to be wrong in."""
    out = elastic.redirect("esql", {"query": "from logs-*\n| LIMIT 1"}, "w1")["query"]

    assert out == "from wv-w1-logs-\n| LIMIT 1"


@pytest.mark.parametrize("body", [
    "STATS COUNT(*) BY host.name",
    "| WHERE host.name == \"x\"",
    "",
])
def test_an_esql_body_that_does_not_open_with_from_is_refused(body):
    """    A query with no leading `FROM` has no corpus to retarget, and is refused by name.

    ES|QL requires `FROM` first, so this is a malformed query rather than an unusual one —
    refusing is what keeps a world from being staged around a query that was never going to
    run."""
    with pytest.raises(elastic.StagingError, match="FROM"):
        elastic.redirect("esql", {"query": body}, "w1")


def test_an_esql_call_carrying_no_query_body_is_refused():
    """    `esql` params with no string `query` are refused rather than treated as an empty corpus.

    The params reaching this frame are a model's, so the missing-key and wrong-type cases are
    real; a `None` body that fell through would raise later, inside a rewrite, naming
    neither."""
    with pytest.raises(elastic.StagingError, match="no query body"):
        elastic.redirect("esql", {"limit": 5}, "w1")


# the param-indexed path: `query` and `alerts`

@pytest.mark.parametrize("verb", ["query", "alerts"])
def test_the_param_indexed_verbs_retarget_through_the_index_param(verb):
    """    `query` and `alerts` carry their corpus as a PARAM, so the retarget replaces `index` and
    leaves every other param alone.

    The second of the two redirection paths, and the reason there are two: these verbs have no
    `FROM` to rewrite. The caller's own dict must come back unmutated — the params are recorded
    into the family's ledger row, and a `prepare` that edited in place would rewrite a base
    recording every sibling replays."""
    params = {"index": "logs-system.auth-*", "q": 'user.name:"root"', "size": 50}

    prepared = elastic.redirect(verb, dict(params), "w1")

    assert prepared == {**params, "index": "wv-w1-logs-system.auth-"}
    assert params["index"] == "logs-system.auth-*"


@pytest.mark.parametrize("verb", ["query", "alerts"])
def test_a_param_indexed_call_with_no_index_is_refused_not_guessed(verb):
    """    A `query`/`alerts` call that leaves `index` unset is addressing the run's configured
    default, which this frame cannot see — so it is refused.

    Guessing is the expensive failure: a wrong guess stages the world into an index nobody
    reads, and the sibling then runs green against the BASE corpus while reporting a world that
    was never applied. The refusal says what to do instead."""
    with pytest.raises(elastic.StagingError, match="explicit index"):
        elastic.redirect(verb, {"q": "*"}, "w1")


def test_an_index_that_is_not_a_real_pattern_is_refused():
    """    An `index` that is PRESENT, truthy and not a string is refused, with or without a `ctx`.

    Not the same case as a missing one, and that is the whole point. An omitted `index` names
    the run's configured default and the stager reads it (#946); a present-but-junk one names
    nothing, and quietly reading the default for it would serve the sibling a staged view of a
    corpus the model never asked for while the base handed `index=42` to the adapter and took
    the fault — a base-vs-sibling difference belonging to the STAGER, which is the one kind
    this seam must never create."""
    with pytest.raises(elastic.StagingError, match="explicit index"):
        elastic.redirect("query", {"index": 42}, "w1")

    with pytest.raises(elastic.StagingError, match="explicit index"):
        elastic.redirect("query", {"index": 42}, "w1", _CTX)


@pytest.mark.parametrize("index", ["", None])
def test_a_falsy_index_addresses_the_default_the_way_the_adapter_reads_it(index):
    """    `index=""` and an explicit `index=None` are OMITTED, because that is what the adapter
    makes of them.

    `elastic_adapter._search_verb` resolves `index or config[index_key]`, and `index` is
    declared `str | None = None`, so `validate_params` admits both spellings and the base run
    answers them in full off the configured corpus. A stager that called them malformed would
    record a `refused` row on every sibling for a call the base served — the harness-owned
    base-vs-sibling difference this seam exists not to manufacture, arriving through the door
    the `42` case above holds shut."""
    prepared = elastic.redirect("query", {"index": index, "native_query": "*"}, "w1", _CTX)

    from defender.scripts.adapters.elastic_adapter import load_config

    assert prepared["index"] == elastic.view_name(
        load_config(_CTX)["ELASTIC_EVENTS_INDEX"], "w1")

    # Without a ctx there is no config to read the default through, which is the one refusal
    # that remains — and it is the SAME refusal an omitted `index` gets, not a malformed one.
    with pytest.raises(elastic.StagingError, match="configured default"):
        elastic.redirect("query", {"index": index, "native_query": "*"}, "w1")


@pytest.mark.parametrize("verb", ["query", "alerts"])
def test_an_omitted_index_resolves_through_the_runs_own_config(verb):
    """    With a `ctx` in hand, an omitted `index` is read from the run's config, not refused.

    `elastic_adapter.query`/`alerts` declare `index: str | None = None` on purpose and a shipped
    template relies on it — `correlate-alerts-by-entity.md` is `params: [end, start]`. Refusing
    that call would drop a whole evidence class from the sibling while the base kept it. The
    view is derived from the SAME key the adapter would have fallen back to, so the staged
    corpus is the one the call was really addressing.

    Production always passes a `ctx` (`WorldApplier.prepare` threads it), so this is the live
    path; the `ctx=None` refusal above is the one that remains for a frame with nothing to read
    the config through."""
    key = {"query": "ELASTIC_EVENTS_INDEX", "alerts": "ELASTIC_ALERTS_INDEX"}[verb]
    from defender.scripts.adapters.elastic_adapter import load_config

    expected = elastic.view_name(load_config(_CTX)[key], "w1")

    prepared = elastic.redirect(verb, {"native_query": "*"}, "w1", _CTX)

    assert prepared == {"native_query": "*", "index": expected}
    assert expected.startswith("wv-w1-")


# the inverse: what the payload echoes back

@pytest.mark.parametrize(("verb", "asked"), [
    ("esql", {"query": "FROM logs-falco.alerts-*\n| STATS events = COUNT(*)"}),
    ("query", {"index": "logs-*", "native_query": "*"}),
    ("alerts", {"index": ".internal.alerts-security.alerts-default-*", "native_query": "*"}),
])
def test_the_restored_payload_matches_the_base_it_is_compared_against(verb, asked):
    """    A staged call's payload, restored, is byte-identical to the base's over identical evidence.

    THE demand behind `restore`, and it is asserted against payloads the REAL adapter builds —
    `search_envelope` and `esql_payload`, called here the way the verbs call them — rather than
    against a shape this test restates. An echo field that moves, or a new one, then fails here
    instead of silently leaving ΔO non-zero on every row of the event stream forever.

    Identical wire data for both worlds, so the two payloads have no honest reason to differ:
    anything left over is the harness's own identity leaking into the measurement."""
    # provenance: `search_envelope`'s docstring ("the contract a lead reads and a payload on
    # disk keeps"); `esql_payload` returns the query text because `sql.py`'s idiom reads it.
    from defender.scripts.adapters.elastic_adapter import esql_payload, search_envelope

    wire = {"columns": [{"name": "events"}], "values": [[3]]}
    docs = [{"host": "office-ws-1"}]

    def payload_for(world_id):
        prepared = elastic.redirect(verb, asked, world_id, _CTX)
        if verb == "esql":
            return prepared, esql_payload(prepared["query"], wire)
        return prepared, search_envelope(prepared["index"], docs, 1, False, "desc")

    _base_prepared, base = payload_for(None)
    prepared, staged = payload_for("w1")

    assert staged != base, (
        "the staged payload does not echo its corpus at all, so this pins nothing — the "
        "parametrized verb no longer carries the identity `restore` exists to take back")
    assert elastic.restore(verb, staged, asked, prepared, _CTX) == base


def test_restore_leaves_a_payload_it_did_not_stage_alone():
    """    A payload whose echo does not hold what we sent is returned untouched.

    The rule that keeps the inverse from corrupting EVIDENCE. A detection alert carries its own
    rule's parameters, and this environment's `v2-sshd-failed-auth-burst.json` declares
    `index: ["logs-system.auth-*"]` — so a textual replace over a payload would rewrite a field
    inside a document. Only the field the verb is known to echo is touched, and only when it
    still holds the staged identity this module put there.

    The cost of the rule is the failure it cannot catch — an echo field nobody listed stays
    un-restored — which is why the test above derives its shape from the adapter."""
    asked = {"index": "logs-*", "native_query": "*"}
    prepared = elastic.redirect("query", asked, "w1", _CTX)
    evidence = {"index": "somewhere-else", "hits": [{"rule": {"index": ["logs-*"]}}]}

    assert elastic.restore("query", evidence, asked, prepared, _CTX) == evidence


@pytest.mark.parametrize(("a", "b"), [("logs-*", "logs.*"), ("logs-*", "logs*"),
                                      ("logs.*", "logs*")])
def test_two_corpora_that_differ_only_in_their_separator_get_two_views(a, b):
    """    Patterns differing only by the character before the wildcard do not share one view.

    The stem was trimmed of its separator as well as its wildcard, so `logs-*`, `logs.*` and
    `logs*` all reduced to `logs`: three distinct corpora on one alias and — because the ledger
    memoizes on the prepared params — one base recording answering for all three. A world
    staging two of them would stage into one view, and a query for the narrow corpus would read
    the wide one's documents, which is the contamination the per-world name exists to prevent
    arriving through the corpus half of the name instead."""
    assert elastic.view_name(a, "w1") != elastic.view_name(b, "w1")


def test_a_world_id_carrying_the_delimiter_is_refused():
    """    A world id holding `-` is refused where the world is named, not resolved by a parse.

    `wv-{id}-{stem}` is written by `view_name` and read back by `confine_index`. With the
    delimiter free to appear in an id, that read is ambiguous exactly where it must not be:
    world `a-logs-nginx`'s view of `logs-*` is `wv-a-logs-nginx-logs-`, which parses equally
    well as world `a`'s view of `logs-nginx-logs-*` — so the boundary that keeps siblings apart
    hands A a name B staged into."""
    with pytest.raises(elastic.StagingError, match="delimiter"):
        elastic.view_name("logs-*", "a-logs-nginx")


@pytest.mark.parametrize("clause", ["METADATA _index", "METADATA _id, _index",
                                    "METADATA _index, _id"])
def test_a_query_whose_rows_would_carry_the_corpus_identity_is_refused(clause):
    """    An ES|QL query selecting `_index` is refused rather than staged.

    `restore` puts the asked identity back into the fields a verb ECHOES — never into
    `values`, because those are the documents and rewriting them is editing evidence. A
    `METADATA _index` clause puts the index name in a COLUMN, so the sibling's rows would
    differ from the base's by this seam's own naming with nothing able to undo it, and ΔO would
    read a difference in every row that no reader could tell from the world's.

    The comma form is parametrized because the field named first in a list tokenizes with the
    comma attached — `_index,` — and a bare `split()` would not match it against itself."""
    with pytest.raises(elastic.StagingError, match="METADATA"):
        elastic.redirect("esql", {"query": f"FROM logs-* {clause}\n| LIMIT 1"}, "w1")

    # The clause itself is not the problem: one that names no corpus identity still stages.
    assert elastic.redirect(
        "esql", {"query": "FROM logs-* METADATA _id\n| LIMIT 1"}, "w1")["query"].startswith(
            "FROM wv-w1-logs- METADATA _id")


def test_a_pattern_that_reaches_into_the_view_namespace_is_refused(tmp_path):
    """    A corpus pattern that would still reach the view built from it is refused, not staged.

    The prefix buys disjointness for every pattern that names a corpus, and a pattern reaching
    into the namespace itself takes it back — `wv-*` derives `wv-a-wv`, which `wv-*` matches.
    That is the finding-2 shape exactly, one config away, so the property is CHECKED where the
    name is built rather than assumed from the spelling. A refusal here costs a sibling this
    system's evidence and says so; the alternative costs the base run its isolation and says
    nothing."""
    with pytest.raises(elastic.StagingError, match="still reaches"):
        elastic.view_name(f"{confinement.VIEW_NAMESPACE}-*", "a")


@pytest.mark.parametrize("pattern", ['logs|weird', 'my logs-*', 'a"b', "a<b"])
def test_a_pattern_that_is_not_a_legal_name_is_refused_rather_than_spliced(pattern):
    """    A corpus whose name an alias cannot carry is refused, not suffixed.

    `_one_source` strips the quotes a source needs when its name carries a space or a `|`, and
    the view is written back UNQUOTED — a view is a name this module builds, and `"logs-*"-w-A`
    answers to nothing. So `FROM "logs|weird"` would come back as `FROM logs|weird-w-A`, where
    the `|` is now a COMMAND SEPARATOR and the query is cut in half: the exact case the
    quote-aware splitter exists to read correctly, corrupted one step after it read it."""
    with pytest.raises(elastic.StagingError, match="cannot hold"):
        elastic.view_name(pattern, "a")


def test_source_pattern_reads_the_route_each_verb_carries():
    """    Where a call addresses its corpus depends on the verb, and `source_pattern` answers for
    exactly the three verbs that have one.

    A verb outside the elastic corpus vocabulary answers `None` rather than raising: it has no
    corpus to point anywhere, which is a different fact from a malformed query."""
    assert elastic.source_pattern("query", {"index": "logs-*"}) == "logs-*"
    assert elastic.source_pattern("alerts", {"index": "logs-*"}) == "logs-*"
    assert elastic.source_pattern("esql", {"query": "FROM logs-*"}) == "logs-*"
    assert elastic.source_pattern("health-check", {"index": "logs-*"}) is None
    assert elastic.source_pattern("query", {}) is None


# the null cases: the base world, and a verb with no corpus

@pytest.mark.parametrize(("verb", "params"), [
    ("esql", {"query": "FROM logs-system.auth-*\n| LIMIT 5"}),
    ("query", {"index": "logs-system.auth-*", "q": "*"}),
    ("alerts", {"index": ".internal.alerts-security.alerts-default-*"}),
])
def test_the_base_world_is_left_exactly_as_it_asked(verb, params):
    """    `world_id is None` is the base world: it stages nothing, so its params come back
    untouched and its payloads ARE the estate's.

    That is what makes a base-versus-sibling difference read as exactly the sibling's staging,
    with no third thing to subtract. Byte-identical, not merely equivalent — a base run whose
    query was normalised on the way through would no longer be the run the sibling forked
    from."""
    prepared = elastic.redirect(verb, params, None)

    assert prepared == params


@pytest.mark.parametrize("verb", ["health-check", "doc-get"])
def test_a_verb_that_addresses_no_corpus_is_left_alone(verb):
    """    A verb outside `query`/`alerts`/`esql` has nothing to retarget, and passes through even
    for a staging world.

    The system's stager is consulted for EVERY verb on it, so this is the branch that keeps a
    health check from being refused for not naming an index."""
    params = {"host": "canary-1"}

    assert elastic.redirect(verb, params, "w1") == params


# the dispatch table: the one place the estate names a vendor

def test_the_event_stream_is_the_only_staged_system():
    """    `STAGERS` names `elastic` and nothing else.

    The one place the estate names a vendor, and it lives inside the per-vendor directory so
    the agnostic seam beside it stays vendor-free. The six state systems have no query engine
    to hand the work to, so they are patched after the fact instead — a name appearing here
    without a module that can stage it would be a system silently claimed and never applied."""
    assert set(STAGERS) == {"elastic"}
    assert STAGERS["elastic"] is elastic


def test_a_stager_answers_the_two_calls_the_applier_makes():
    """    The applier reaches a stager through `redirect` alone, so that is the contract a new
    stager has to meet.

    Pinned as a signature check rather than a behaviour one: adding a stager is meant to be one
    entry in the table and never a branch in the seam, which only holds while the table's
    values are interchangeable."""
    assert callable(STAGERS["elastic"].redirect)
    assert isinstance(STAGERS["elastic"].StagingError, type)
