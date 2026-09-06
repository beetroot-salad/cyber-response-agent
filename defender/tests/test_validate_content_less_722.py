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


# the "non-empty string" gates — a field that renders as nothing is empty



















# the keyword gates — the same split, running the other way





@pytest.mark.parametrize(("tag", "written"), [("clean", "benign")])
def test_a_report_disposition_is_matched_on_what_it_renders_as(tmp_path, tag, written):
    """report.md's disposition is the headline the loop reads to pick a direction. The
    normalized keyword comes back, so no caller downstream ever sees the invisible
    characters the model wrote around it.

    #923 (§7 round 4) narrows this to the CLEAN spelling — the zero-width/BOM spellings that
    used to belong here now belong in the rejected set below: on READ there is no author left
    to ask, so a value that only becomes a member after something strips it is answered
    exactly as a value that was never a member. `strip_zero_width` no longer runs in
    `_vocab.normalized_disposition` at all."""
    assert loop.normalize_disposition(_report(tmp_path, written)) == "benign"


@pytest.mark.parametrize(
    ("tag", "written"),
    [
        ("not-a-keyword", "spicy"),
        ("content-less", "​"),
        # #923: moved from the "matched on what it renders as" set above — the read side no
        # longer coerces a zero-width- or BOM-laced disposition into the member it resembles.
        ("trailing-zwsp", "benign​"),
        ("bom", "﻿benign"),
    ],
)
def test_a_report_disposition_that_is_not_a_keyword_is_still_rejected(tmp_path, tag, written):
    with pytest.raises(RunUnprocessable, match="disposition="):
        loop.normalize_disposition(_report(tmp_path, written))


# the shared helper's own contract

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
