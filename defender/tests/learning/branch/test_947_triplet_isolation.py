"""#947 — what a refusal may tell the model about a branched episode (§7 NEW-1)."""
from __future__ import annotations

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T

TOKEN_A = T.fixture_world_id("a")
TOKEN_C = T.fixture_world_id("c")


# NEW-1 — no model-visible text names a run or world token


def _model_text(detail: str) -> str:
    """The text a fault's detail becomes on the model's side of the tool boundary."""
    return T.mod("_redaction").redact_model_visible(
        detail, frozenset((TOKEN_A, TOKEN_C, T.EPISODE_ID)))


@pytest.mark.parametrize("detail", [
    "the system refused the read for run {a}: rate limited",
    "no record of {c} is visible to {a}",
    "Elasticsearch query failed (HTTP 404): no such index [logs-{a}]",
])
def test_947_no_model_visible_fault_text_names_a_run_or_world_token(detail):
    rendered = _model_text(detail.format(a=TOKEN_A, c=TOKEN_C))
    for leak in (TOKEN_A, TOKEN_C, T.EPISODE_ID):
        assert leak not in rendered, f"{leak!r} survived into model-visible text"
    assert rendered != detail.format(a=TOKEN_A, c=TOKEN_C), "nothing was redacted at all"


def test_947_an_ordinary_refusal_still_tells_the_model_something_actionable():
    plain = "index expression 'logs-*,alerts-*' names a multi-index list — refused whole"
    assert _model_text(plain) == plain
    redacted = _model_text(f"index 'logs-{TOKEN_A}' falls outside the configured patterns")
    assert redacted.strip()
    assert "falls outside the configured patterns" in redacted


#: Words that only a BRANCHED run could honestly use about itself. A defender reading any of
_SCHEME_WORDS = ("world", "staged", "staging", "episode", "sibling", "branch", "overlay",
                 "corpus", "view")


@pytest.mark.parametrize("detail", [
    "Elasticsearch query failed (HTTP 404): no such index [logs-{a}]",
    "index 'logs-{a}' falls outside the configured patterns",
    "no such file /runs/{a}/alert.json",
])
def test_947_what_the_redaction_leaves_behind_names_nothing_about_the_scheme(detail):
    """WHAT REPLACES a removed name discloses no more than the name did."""
    rendered = _model_text(detail.format(a=TOKEN_A)).casefold()
    for word in _SCHEME_WORDS:
        assert word not in rendered, (
            f"the redaction's own replacement text says {word!r} — the marker discloses the "
            "scheme the removal exists to hide")
    assert rendered != detail.format(a=TOKEN_A).casefold(), (
        "nothing was redacted at all, so the assertion above passed on an unfiltered string")
