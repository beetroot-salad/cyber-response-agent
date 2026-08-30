"""#947 — cross-world corpus isolation, and what a refusal may tell the model (§7 FORK-6, NEW-1).

Two decisions the human took at the §7 seam, both of them corrections of what a lane had
settled from a reading rather than from an execution.

**FORK-6 — the model never learns that staged indices exist, AND a call naming another world's
view is refused.** The enforcement point is the serving registry's own serve point, ABOVE
per-world staging, and NOT the stager the fork proposed. Two executed facts force that:

* on a world that DOES stage the event stream, the stager rewrites a sibling-authored
  `FROM wv-c-…` to `wv-a-wv-c-…`, so the cross-world read never happens. The live hole is
  exactly the world that stages NOTHING — a control — where the applier returns the parameters
  untouched and the query-language arm sends the sibling's alias verbatim. Every episode with a
  control world has exactly one such sibling by construction, so a demand written as "the stager
  refuses a foreign name" passes its own test and leaves the hole open.
* the shared outbound HTTP guard CANNOT host the check: it is handed the URL, and the index
  lives in the URL for one arm and inside the request BODY for the other. Executed: the
  param-indexed call normalises to `/wv-a-logs-/_search`, the query-language call to `/_query`.

**NEW-1 — no model-visible text may name a staged index.** Every open channel found at the seam
is fault text: an adapter fault's detail reaches the model verbatim inside the untrusted wrap,
and an executed refusal returned the namespace prefix, the `wv-{world}-{stem}` template and the
world's own id, unasked, in answer to a five-character query. The same text is persisted into
the queries table's failure digest. Implemented as a FILTER over fault detail rather than as
per-site wording, because the cluster's own error text is relayed verbatim and whether a live
cluster names the index there could not be settled from this session.

The two demands here are the FILTER's own contract — what `redact_model_visible` removes and
what it must leave intact. That the two fault handlers the probe named actually CALL it is a
separate question a unit test of a filter cannot answer, and it is pinned in
`test_947_triplet_served.py`, which drives a real run through the replay harness and reads the
model's turn and the run's `executed_queries.jsonl`. A filter that ships and is never wired in
passes everything in this file.

RED against b8a63e66: the query-language arm confines nothing on its source clause and passes a
sibling's `wv-` name through to the transport, recording nothing (PO-C17, executed and refuted);
and both refusals above are the shipped text (47-visibility-probe, executed).
"""
from __future__ import annotations

import pytest

from defender.tests import _triplet_947 as T

TOKEN_A = T.world_token("a")
TOKEN_C = T.world_token("c")
FOREIGN = f"wv-{TOKEN_C}-logs-"


def _serving():
    return T.mod("learning.branch.estate.registry")


def _served_call(world_token, *, touches, verb, params, adapters=None, overlay=None):
    """Drive ONE call through the real serving registry for a world with these touches.

    THE OVERLAY AGREES WITH `touches` BY DEFAULT, because in production one is derived from the
    other (`_family.touches_of`) and the applier narrows its retarget by the overlay's declared
    keys. A world touching `elastic` with an EMPTY overlay is a shape no manifest produces, and
    against it the stager reads the base rather than the world's view — so the positive control
    below would be asserting on the untouched pattern.
    """
    registry = _serving()
    if overlay is None:
        # A REAL declared difference, because `_parse_elastic_entry` normalises an entry that
        # stages nothing to ABSENT — an overlay of empty entries is an overlay that declares no
        # pattern, which is the same empty shape this default exists to avoid.
        overlay = ({"elastic": T.elastic_overlay(inject=[{"_id": "i1"}])}
                   if "elastic" in tuple(touches) else {})
    world = registry.world_for(token=world_token, touches=touches, overlay=overlay)
    # `.out` — the serve point hands back the whole PASSAGE (the asked and prepared params,
    # what staging moved, the decision) because `WorldRegistry._served` needs those for its
    # ledger rows and must not re-derive them. This driver wants the answer.
    return registry.serve_one(world, "elastic", verb, params,
                              adapters=adapters or T.FakeAdapters()).out


# ---------------------------------------------------------------------------------------
# FORK-6 — the refusal, its positive control, and the world that stages nothing
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(("verb", "params"), [
    ("query", {"index": FOREIGN}),
    ("esql", {"query": f"FROM {FOREIGN} | LIMIT 1"}),
])
def test_947_a_call_naming_another_worlds_view_is_refused_at_the_serve_point(verb, params):
    """A call naming another world's staged view is refused at the serving registry's serve
    point, in BOTH query languages, before the adapter body runs — the adapter records no call
    at all, and the refusal is recorded as evidence rather than passing silently."""
    fault = T.sym("scripts.adapters.confinement", "ConfinementFault")
    adapters = T.FakeAdapters()
    assert hasattr(_serving(), "serve_one"), "the serve point has no drivable seam"
    with pytest.raises(fault):
        _served_call(TOKEN_A, touches=("elastic",), verb=verb, params=params,
                     adapters=adapters)
    assert adapters.calls == []


@pytest.mark.parametrize(("verb", "params"), [
    ("query", {"index": FOREIGN}),
    ("esql", {"query": f"FROM {FOREIGN} | LIMIT 1"}),
])
def test_947_a_world_that_stages_nothing_is_covered_by_the_same_refusal(verb, params):
    """The world that stages NOTHING is covered by the same refusal: a control declares no
    system, so the applier returns its parameters untouched and no world label is threaded onto
    its context — and that is exactly the sibling that could otherwise read another world's
    corpus. Both query languages are refused for it too."""
    fault = T.sym("scripts.adapters.confinement", "ConfinementFault")
    adapters = T.FakeAdapters()
    assert hasattr(_serving(), "serve_one"), "the serve point has no drivable seam"
    with pytest.raises(fault):
        _served_call(TOKEN_A, touches=(), verb=verb, params=params, adapters=adapters)
    assert adapters.calls == []


def test_947_a_worlds_own_view_and_an_ordinary_pattern_are_still_served(tmp_path):
    """The positive control for the isolation refusal: this world's OWN view is served, and an
    ordinary configured pattern is served unchanged — so the refusals above are proof of a
    working boundary rather than of a channel that answers nothing."""
    adapters = T.FakeAdapters({("elastic", "query"): {"hits": [{"_id": "d1"}]}})
    own = _served_call(TOKEN_A, touches=("elastic",), verb="query",
                       params={"index": T.EVENTS_PATTERN}, adapters=adapters)
    assert own["hits"] == [{"_id": "d1"}]
    assert adapters.calls, "the world's own read never reached the adapter"
    prepared = adapters.calls[0][2]
    assert prepared["index"] == f"wv-{TOKEN_A}-logs-"
    control = T.FakeAdapters({("elastic", "query"): {"hits": [{"_id": "d1"}]}})
    _served_call(TOKEN_A, touches=(), verb="query", params={"index": T.EVENTS_PATTERN},
                 adapters=control)
    assert control.calls[0][2]["index"] == T.EVENTS_PATTERN


# ---------------------------------------------------------------------------------------
# NEW-1 — no model-visible text names a staged index
# ---------------------------------------------------------------------------------------


def _model_text(detail: str) -> str:
    """The text a fault's detail becomes on the model's side of the tool boundary."""
    return T.mod("learning.branch.redaction").redact_model_visible(detail)


@pytest.mark.parametrize("detail", [
    "corpus pattern 'wv-*' still reaches 'wv-{a}-wv-', the view built from it",
    "index 'wv-{a}-wv-{c}-logs-' falls outside the configured patterns and is not a world "
    "view of '{a}'",
    "Elasticsearch query failed (HTTP 404): no such index [wv-{a}-logs-]",
])
def test_947_no_model_visible_fault_text_names_a_staged_index(detail):
    """No model-visible fault text names a staged index: the namespace prefix, the staged-name
    template and any world's own id are all removed from a fault's detail before it reaches the
    model — the staging refusal, the confinement refusal and the cluster's own relayed reason
    alike, because all three arrive on one channel."""
    rendered = _model_text(detail.format(a=TOKEN_A, c=TOKEN_C))
    for leak in ("wv-", TOKEN_A, TOKEN_C, T.EPISODE_TOKEN):
        assert leak not in rendered, f"{leak!r} survived into model-visible text"


def test_947_an_ordinary_refusal_still_tells_the_model_something_actionable():
    """The positive control for the redaction: an ordinary refusal that names nothing staged is
    passed through intact, so the filter removes staged names rather than emptying the channel
    the model reasons from."""
    plain = "index expression 'logs-*,alerts-*' names a multi-index list — refused whole"
    assert _model_text(plain) == plain
    redacted = _model_text(f"index 'wv-{TOKEN_A}-logs-' falls outside the configured patterns")
    assert redacted.strip()
    assert "falls outside the configured patterns" in redacted


#: Words that only a BRANCHED run could honestly use about itself. A defender reading any of
#: these in its own fault text has learned that its corpus is staged and that there are other
#: arms to be one of — which is the whole of the scheme, and the one thing the design says it
#: must not be able to learn.
_SCHEME_WORDS = ("world", "staged", "staging", "episode", "sibling", "branch", "overlay",
                 "corpus", "view")


@pytest.mark.parametrize("detail", [
    "Elasticsearch query failed (HTTP 404): no such index [wv-{a}-logs-]",
    "index 'wv-{a}-logs-' falls outside the configured patterns",
    "no such file /runs/{a}/alert.json",
])
def test_947_what_the_redaction_leaves_behind_names_nothing_about_the_scheme(detail):
    """WHAT REPLACES a removed name discloses no more than the name did. The filter's markers
    are text the model reads, so a marker reading "a staged view" or "a world id" hands over in
    English exactly what removing the name withheld — that this run's corpus is staged and that
    worlds exist to have ids.

    The sibling demand holds every prompt-facing document to silence about the namespace "so
    the fault channel is the only way the scheme could have been learned". This is that same
    rule applied to the filter that sits ON the fault channel: an index and a run id are things
    every run has, so what stands in for a removed name must be producible by a run with no
    world at all."""
    rendered = _model_text(detail.format(a=TOKEN_A)).casefold()
    for word in _SCHEME_WORDS:
        assert word not in rendered, (
            f"the redaction's own replacement text says {word!r} — the marker discloses the "
            "scheme the removal exists to hide")
    assert rendered != detail.format(a=TOKEN_A).casefold(), (
        "nothing was redacted at all, so the assertion above passed on an unfiltered string")


def test_947_the_environment_description_never_mentions_the_world_view_namespace():
    """Nothing the model reads before it asks anything mentions the world-view namespace: no
    prompt-facing knowledge or skill file names the prefix, the template or a world label, so
    the fault channel is the only way the scheme could have been learned."""
    roots = [T.DEFENDER / "knowledge", T.DEFENDER / "skills", T.DEFENDER / "docs"]
    for root in roots:
        for path in root.rglob("*.md"):
            text = path.read_text(encoding="utf-8", errors="replace")
            assert "wv-" not in text, path
            assert "VIEW_NAMESPACE" not in text, path
