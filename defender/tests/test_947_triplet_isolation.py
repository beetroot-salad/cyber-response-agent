"""#947 — what a refusal may tell the model about a branched episode (§7 NEW-1).

**NEW-1 — no model-visible text may name the episode's scheme.** Every open channel found at the
seam is fault text: an adapter fault's detail reaches the model verbatim inside the untrusted
wrap, and an executed refusal returned the world's own id, unasked, in answer to a
five-character query. The same text is persisted into the queries table's failure digest.
Implemented as a FILTER over fault detail rather than as per-site wording, because the system's
own error text is relayed verbatim.

#1224 retired cluster staging and its world-view names, and with them FORK-6's cross-world view
refusal at the serve point and the filter's staged-name rule: a world is now served by its own
live oracle and reads no corpus a sibling built. What survives is the filter's token rule — no
run or world token reaches the model — and its silence about the scheme.

The demands here are the FILTER's own contract — what `redact_model_visible` removes and what it
must leave intact. That the fault handlers actually CALL it is pinned in
`test_947_triplet_served.py`, which drives a real run through the replay harness and reads the
model's turn and the run's `executed_queries.jsonl`.
"""
from __future__ import annotations

import pytest

from defender.tests import _triplet_947 as T

TOKEN_A = T.world_token("a")
TOKEN_C = T.world_token("c")


# ---------------------------------------------------------------------------------------
# NEW-1 — no model-visible text names a run or world token
# ---------------------------------------------------------------------------------------


def _model_text(detail: str) -> str:
    """The text a fault's detail becomes on the model's side of the tool boundary."""
    return T.mod("learning.branch.redaction").redact_model_visible(detail)


@pytest.mark.parametrize("detail", [
    "the system refused the read for run {a}: rate limited",
    "no record of {c} is visible to {a}",
    "Elasticsearch query failed (HTTP 404): no such index [logs-{a}]",
])
def test_947_no_model_visible_fault_text_names_a_run_or_world_token(detail):
    """No model-visible fault text names a run or world token: the episode's token and any
    world's own token are removed from a fault's detail before it reaches the model — a
    refusal and the system's own relayed reason alike, because both arrive on one channel."""
    rendered = _model_text(detail.format(a=TOKEN_A, c=TOKEN_C))
    for leak in (TOKEN_A, TOKEN_C, T.EPISODE_TOKEN):
        assert leak not in rendered, f"{leak!r} survived into model-visible text"
    assert rendered != detail.format(a=TOKEN_A, c=TOKEN_C), "nothing was redacted at all"


def test_947_an_ordinary_refusal_still_tells_the_model_something_actionable():
    """The positive control for the redaction: an ordinary refusal that names no token is
    passed through intact, so the filter removes tokens rather than emptying the channel
    the model reasons from."""
    plain = "index expression 'logs-*,alerts-*' names a multi-index list — refused whole"
    assert _model_text(plain) == plain
    redacted = _model_text(f"index 'logs-{TOKEN_A}' falls outside the configured patterns")
    assert redacted.strip()
    assert "falls outside the configured patterns" in redacted


#: Words that only a BRANCHED run could honestly use about itself. A defender reading any of
#: these in its own fault text has learned that its corpus is staged and that there are other
#: arms to be one of — which is the whole of the scheme, and the one thing the design says it
#: must not be able to learn.
_SCHEME_WORDS = ("world", "staged", "staging", "episode", "sibling", "branch", "overlay",
                 "corpus", "view")


@pytest.mark.parametrize("detail", [
    "Elasticsearch query failed (HTTP 404): no such index [logs-{a}]",
    "index 'logs-{a}' falls outside the configured patterns",
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
    """Nothing the model reads before it asks anything mentions the retired world-view
    namespace: no prompt-facing knowledge or skill file names its prefix or its constant, so no
    shipped description still tells a run that its corpus might be a world's view."""
    roots = [T.DEFENDER / "knowledge", T.DEFENDER / "skills", T.DEFENDER / "docs"]
    for root in roots:
        for path in root.rglob("*.md"):
            text = path.read_text(encoding="utf-8", errors="replace")
            assert "wv-" not in text, path
            assert "VIEW_NAMESPACE" not in text, path  # lint-stale-ref: ok — asserts the retired name stays out of prompt-facing docs
