"""Hermetic spec for the judge-doc validators' "non-empty string" gates (#722, same class).

The judge writes this YAML after reading the actor's story and the investigation, both
downstream of attacker-influenced alert/gather text. `validate.py` is the gate that
decides whether a case is processable — and a validated finding is not merely logged:
`persist.py` queues `subject_anchor` / `subject_topic` verbatim into the pending-findings
table, and the lesson curator's prompt renders them as the lesson's anchor. A field that
renders as NOTHING must therefore not pass a check spelled "must be a non-empty string".

`not v.strip()` was that check. strip() keys off `str.isspace()`, True for the
visible-width separators (U+00A0, U+3000, U+2028) and False for the zero-width ones
(U+200B, U+FEFF, U+00AD, U+2060) and NUL — so an anchor of a single zero-width space
passed the gate and became a lesson anchor, while an anchor of one NBSP did not.

The same split ran the other way on the two keyword gates: `outcome` and the report's
`disposition` tolerated an NBSP around the keyword and turned the whole case
unprocessable on a zero-width one. Both now match on what the value renders as.

Driven through the public seam the pipeline itself calls — the `learning.loop`
re-exports — with real docs and a real report.md on disk.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender._text import is_content_less, strip_zero_width
from defender.learning import loop
from defender.learning.core.config import RunUnprocessable

# Renders as nothing, on both sides of isspace(). The zero-width half is what the old
# `.strip()` gate let through.
CONTENT_LESS = [
    ("ascii-spaces", "   "),
    ("U+00A0-no-break-space", " "),
    ("U+3000-ideographic-space", "　"),
    ("U+200B-zero-width-space", "​"),
    ("U+FEFF-byte-order-mark", "﻿"),
    ("U+00AD-soft-hyphen", "­"),
    ("U+2060-word-joiner", "⁠"),
    ("U+0000-nul", "\x00"),
    ("mixed", "​ ﻿\n\x00"),
]
_IDS = [t for t, _ in CONTENT_LESS]


def _judge_doc(**overrides):
    """A valid adversarial judge doc — the shape `tests/learning/test_loop.py` pins."""
    doc = {
        "outcome": "caught",
        "outcome_rationale": "Lead l-001 refuted the projection.",
        "encounter_analysis": "lead-by-lead walkthrough.",
        "defender_findings": [
            {
                "type": "detection-confirmed",
                "subject_anchor": "l-001",
                "subject_topic": "falco container scan",
                "finding": "lead caught the story.",
                "citations": [{"source": "investigation", "quote": "q"}],
            }
        ],
        "confidence": "high.",
    }
    doc.update(overrides)
    return doc


def _actor_observation(**overrides):
    o = {
        "type": "misprediction",
        "subject_anchor": "l-001",
        "subject_topic": "falco container scan",
        "observation": "the story assumed the scan was silent.",
    }
    o.update(overrides)
    return o


def _environment_observation(**overrides):
    o = {
        "alert_rule_ids": ["rule-42"],
        "relevance_criteria": "hosts in the finance tier.",
        "fact": "FINANCE-DB runs the nightly export at 02:00.",
    }
    o.update(overrides)
    return o


def _report(tmp_path: Path, disposition: str) -> Path:
    p = tmp_path / "report.md"
    p.write_text(
        f"---\ndisposition: \"{disposition}\"\n---\n\nThe write-up.\n", encoding="utf-8"
    )
    return p


# ===========================================================================
# the "non-empty string" gates — a field that renders as nothing is empty
# ===========================================================================

@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=_IDS)
@pytest.mark.parametrize("key", ["subject_anchor", "subject_topic"])
def test_a_finding_anchor_that_renders_as_nothing_is_rejected(key, tag, text):
    """The anchor `persist.py` queues and the curator prompt renders as the lesson's
    subject. Before #722 the zero-width spellings passed this gate."""
    doc = _judge_doc()
    doc["defender_findings"][0][key] = text
    with pytest.raises(RunUnprocessable, match=f"finding\\[0\\].{key} must be a non-empty string"):
        loop.validate_judge_doc(doc)


@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=_IDS)
@pytest.mark.parametrize(
    "key", ["type", "subject_anchor", "subject_topic", "observation"]
)
def test_an_actor_observation_field_that_renders_as_nothing_is_rejected(key, tag, text):
    doc = _judge_doc(actor_observations=[_actor_observation(**{key: text})])
    with pytest.raises(RunUnprocessable, match=f"actor_observations\\[0\\].{key}"):
        loop.validate_judge_doc(doc)


@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=_IDS)
@pytest.mark.parametrize("key", ["relevance_criteria", "fact"])
def test_an_environment_observation_field_that_renders_as_nothing_is_rejected(key, tag, text):
    doc = _judge_doc(environment_observations=[_environment_observation(**{key: text})])
    with pytest.raises(RunUnprocessable, match=f"environment_observations\\[0\\].{key}"):
        loop.validate_judge_doc(doc)


@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=_IDS)
def test_a_rule_id_anchor_that_renders_as_nothing_is_rejected(tag, text):
    """`alert_rule_ids` is the fact's retrieval anchor, and only the LIST was checked for
    emptiness — its entries never were. A list holding one zero-width id is as anchorless
    as `[]`, and `persist.py` would store it as the anchor."""
    doc = _judge_doc(environment_observations=[_environment_observation(alert_rule_ids=[text])])
    with pytest.raises(RunUnprocessable, match="alert_rule_ids entries must be non-empty"):
        loop.validate_judge_doc(doc)


@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=_IDS)
def test_one_content_less_rule_id_among_real_ones_is_rejected(tag, text):
    """Not just the all-blank case: a blank id riding along with a real one is rejected
    too, so the anchor list cannot be padded with ids that render as nothing."""
    doc = _judge_doc(
        environment_observations=[_environment_observation(alert_rule_ids=["rule-42", text])]
    )
    with pytest.raises(RunUnprocessable, match="alert_rule_ids entries must be non-empty"):
        loop.validate_judge_doc(doc)


def test_real_rule_id_anchors_still_validate():
    """The controls: real ids pass, and so does an id that merely CARRIES an invisible
    character. A non-string id is rejected by the same gate."""
    assert loop.validate_judge_doc(
        _judge_doc(environment_observations=[
            _environment_observation(alert_rule_ids=["rule-42", "﻿v2-falco-net-tool"])
        ])
    )
    with pytest.raises(RunUnprocessable, match="alert_rule_ids entries must be non-empty"):
        loop.validate_judge_doc(
            _judge_doc(environment_observations=[_environment_observation(alert_rule_ids=[42])])
        )


@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=_IDS)
def test_a_resolution_method_that_renders_as_nothing_is_rejected(tag, text):
    with pytest.raises(RunUnprocessable, match="resolution_method` must be a non-empty string"):
        loop.validate_judge_doc(_judge_doc(resolution_method=text))


@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=_IDS)
def test_the_benign_validator_shares_the_gate(tag, text):
    """`validate_judge_benign_doc` runs the same `_validate_finding`, so the benign lane
    is not a way around the anchor gate."""
    doc = _judge_doc(outcome="survived")
    doc["defender_findings"][0]["type"] = "lead-set"
    doc["defender_findings"][0]["subject_anchor"] = text
    with pytest.raises(RunUnprocessable, match="must be a non-empty string"):
        loop.validate_judge_benign_doc(doc)


def test_real_fields_still_validate_and_are_not_rewritten():
    """The controls: ordinary prose passes, prose that merely CARRIES an invisible
    character passes, and the validator returns the doc untouched — it is a gate, not a
    normalizer, so no queued anchor is silently mangled on the way through."""
    anchor, topic = "﻿l-001", "falco​container scan"
    doc = _judge_doc(resolution_method="closed as benign by the on-call.")
    doc["defender_findings"][0]["subject_anchor"] = anchor
    doc["defender_findings"][0]["subject_topic"] = topic
    doc["actor_observations"] = [_actor_observation()]
    doc["environment_observations"] = [_environment_observation()]
    out = loop.validate_judge_doc(doc)
    assert out["defender_findings"][0]["subject_anchor"] == anchor
    assert out["defender_findings"][0]["subject_topic"] == topic


# ===========================================================================
# the keyword gates — the same split, running the other way
# ===========================================================================

@pytest.mark.parametrize(
    ("tag", "outcome"),
    [
        ("leading-zwsp", "​caught"),
        ("trailing-zwsp", "caught​"),
        ("interior-zwsp", "ca​ught"),
        ("bom-wrapped", "﻿caught﻿"),
        ("soft-hyphen", "caught­"),
        ("nul", "caught\x00"),
        ("leading-nbsp", " caught"),          # already worked — regression guard
        ("keyword-then-rationale", "caught. the lead refuted it."),  # unchanged split
    ],
)
def test_an_outcome_keyword_is_matched_on_what_it_renders_as(tag, outcome):
    """A zero-width character clinging to `caught` used to make the whole judged case
    unprocessable, while an NBSP in the same position was tolerated. Both now resolve to
    the keyword — and the whitespace-based split that cuts the rationale off still runs,
    because strip_zero_width leaves whitespace alone."""
    assert loop.validate_judge_doc(_judge_doc(outcome=outcome))


@pytest.mark.parametrize(
    ("tag", "outcome"),
    [("content-less", "​"), ("not-a-keyword", "acquitted"), ("empty", "")],
)
def test_an_outcome_that_is_not_a_keyword_is_still_rejected(tag, outcome):
    """The guarded negative: matching on what renders does NOT mean accepting anything.
    Only the enum's keywords pass, and a content-less outcome is not one of them."""
    with pytest.raises(RunUnprocessable, match="outcome keyword"):
        loop.validate_judge_doc(_judge_doc(outcome=outcome))


@pytest.mark.parametrize(
    ("tag", "written"),
    [("clean", "benign"), ("trailing-zwsp", "benign​"), ("bom", "﻿benign")],
)
def test_a_report_disposition_is_matched_on_what_it_renders_as(tmp_path, tag, written):
    """report.md's disposition is the headline the loop reads to pick a direction. The
    normalized keyword comes back, so no caller downstream ever sees the invisible
    characters the model wrote around it."""
    assert loop.normalize_disposition(_report(tmp_path, written)) == "benign"


@pytest.mark.parametrize(
    ("tag", "written"), [("not-a-keyword", "spicy"), ("content-less", "​")]
)
def test_a_report_disposition_that_is_not_a_keyword_is_still_rejected(tmp_path, tag, written):
    with pytest.raises(RunUnprocessable, match="disposition="):
        loop.normalize_disposition(_report(tmp_path, written))


# ===========================================================================
# the shared helper's own contract
# ===========================================================================

def test_strip_zero_width_keeps_the_whitespace_callers_split_on():
    """`strip_zero_width` drops what occupies no space and KEEPS whitespace — the
    property the outcome split depends on. Dropping `\\n` (category Cc, like NUL) would
    silently glue a keyword to the rationale beneath it."""
    assert strip_zero_width("caught​﻿\x00") == "caught"
    assert strip_zero_width("caught. why\nbecause") == "caught. why\nbecause"
    assert strip_zero_width(" caught ") == " caught "
    assert strip_zero_width("") == ""
    # what survives is exactly what a reader sees, so the two helpers agree
    assert is_content_less(strip_zero_width("​﻿ \x00"))
    assert not is_content_less(strip_zero_width("​x"))
