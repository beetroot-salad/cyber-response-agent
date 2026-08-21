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
query body. Both are pinned, as is the refusal — a `query` call with no explicit `index` is
addressing the run's configured default, which this frame cannot see, and guessing wrong would
stage a world into an index nobody reads.

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
from defender.learning.branch.estate.stagers.dispatch import STAGERS

#: The committed elastic catalog: 15 templates, 12 of them ES|QL. Both numbers are asserted
#: below rather than merely derived, because a corpus that shrank to one template would make
#: every parametrized case below pass over less and stay green.
CATALOG = PATHS.defender_dir / "skills" / "gather" / "queries" / "elastic"
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


# ==========================================================================
# the committed corpus: every template retargets, with its pipes intact
# ==========================================================================

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


# ==========================================================================
# the view name: per world, derived from the pattern
# ==========================================================================

@pytest.mark.parametrize(("pattern", "world_id", "expected"), [
    ("logs-system.auth-*", "b", "logs-system.auth-w-b"),
    ("logs-*", "a", "logs-w-a"),
    (".internal.alerts-security.alerts-default-*", "z", ".internal.alerts-security.alerts-default-w-z"),
    ("logs-zeek.connection", "a", "logs-zeek.connection-w-a"),
])
def test_a_view_name_trims_the_pattern_and_carries_the_world(pattern, world_id, expected):
    """    The alias a world's queries read: the pattern's trailing wildcard and separator trimmed,
    then the world id appended.

    Spelled as literals so the rule is legible here rather than only in the code — the sweep
    above uses `view_name` to build its expectation, and this is what keeps that from being
    circular."""
    assert elastic.view_name(pattern, world_id) == expected


def test_two_siblings_never_share_a_view():
    """    Two worlds off one pattern get two different aliases.

    Per world, never shared: siblings reading one view would see each other's staged documents,
    and the pair would be measuring contamination rather than a difference."""
    a = elastic.view_name("logs-system.auth-*", "a")
    b = elastic.view_name("logs-system.auth-*", "b")

    assert a != b


# ==========================================================================
# the ES|QL rewrite: what belongs to the FROM command, and what does not
# ==========================================================================

def test_a_metadata_clause_survives_with_its_following_newline():
    """    `FROM <sources> METADATA <fields>` keeps the METADATA suffix AND the newline after it.

    The suffix belongs to the same command, so it moves with the rewrite. The newline is the
    author's formatting and is measured off the same text in both branches — taking it only on
    the no-METADATA path joined `METADATA _id` to the following `| WHERE`, turning a two-line
    query into one. Pinned as the exact string, because "METADATA is still in there somewhere"
    would pass on the joined query too."""
    body = 'FROM logs-system.auth-* METADATA _id, _index\n| WHERE user.name == "root"\n| LIMIT 5'

    out = elastic.rewrite_from(body, "logs-system.auth-w-b")

    assert out == (
        'FROM logs-system.auth-w-b METADATA _id, _index\n'
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
        == "FROM logs-system.auth-w-b METADATA _id"


def test_only_the_leading_from_moves_even_when_a_pipe_stage_names_one():
    """    Everything after the first pipe is another command and is never touched — including a
    string literal that happens to spell `FROM logs-*`.

    This is a leading-CLAUSE substitution, not query-language surgery. A rewrite implemented as
    a global replace would silently edit a defender's own `EVAL`ed note, and the sibling's
    evidence would then differ from the base run's for a reason that has nothing to do with the
    world."""
    body = 'FROM logs-*\n| EVAL note = "read FROM logs-* earlier"\n| LIMIT 1'

    out = elastic.redirect("esql", {"query": body}, "w1")["query"]

    assert out == 'FROM logs-w-w1\n| EVAL note = "read FROM logs-* earlier"\n| LIMIT 1'


def test_a_multi_source_from_is_not_left_half_staged():
    """    A `FROM a-*, b-*` query must not come back with one source staged and one not.

    Half-staged is the worst of the three outcomes: the world's difference is silently absent
    from part of the evidence, the query still runs, and the sibling reports a measurement over
    a corpus that is partly the base run's. Refusing is a correct answer here — a query that
    cannot be pointed at a world's view is exactly what `StagingError` is for."""
    body = "FROM logs-system.auth-*, logs-nginx.access-*\n| STATS COUNT(*)"

    try:
        out = elastic.redirect("esql", {"query": body}, "b")["query"]
    except elastic.StagingError:
        out = ""  # refusing stages nothing, which is not half-staging

    assert "logs-system.auth-*" not in out


def test_a_lowercased_from_still_retargets():
    """    ES|QL's `FROM` is case-insensitive, and so is the rewrite; the author's own casing
    survives.

    Model-written ad-hoc queries are not spelled to the catalog's house style, and a stager
    that only recognised the uppercase spelling would refuse a valid query — which, at the seam
    where refusing means the sibling cannot run, is the expensive direction to be wrong in."""
    out = elastic.redirect("esql", {"query": "from logs-*\n| LIMIT 1"}, "w1")["query"]

    assert out == "from logs-w-w1\n| LIMIT 1"


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


# ==========================================================================
# the param-indexed path: `query` and `alerts`
# ==========================================================================

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

    assert prepared == {**params, "index": "logs-system.auth-w-w1"}
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


@pytest.mark.parametrize("index", ["", None, 42])
def test_an_index_that_is_not_a_real_pattern_is_refused(index):
    """    An empty, absent or non-string `index` is the same case as a missing one.

    `source_pattern` returns `None` for each, so all three land on the refusal rather than on a
    view name built out of `''` or `'42'`."""
    with pytest.raises(elastic.StagingError, match="explicit index"):
        elastic.redirect("query", {"index": index}, "w1")


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


# ==========================================================================
# the null cases: the base world, and a verb with no corpus
# ==========================================================================

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


# ==========================================================================
# the dispatch table: the one place the estate names a vendor
# ==========================================================================

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
