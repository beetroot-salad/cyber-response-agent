"""#1545: a benign close's confidence. The model states one, the record earns a ceiling, and the
close commits the lower. `high` needs every load-bearing step authorized AND a baseline the
activity matches; `medium` the authorization alone; `low` either no contract at all, or a
searched-and-empty record with one story standing, a matching baseline, and nothing an attacker
would have gained."""

from __future__ import annotations

import pytest

from defender.investigation.close_tool import render_report
from defender.records._artifact_schema import validate_report
from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import (
    benign_confidence_ceiling,
    committed_benign_confidence,
    validate_companion,
)
from defender.skills.invlang.validate._gating import disposition_entry_price
from defender.tests.support.shared.contracts import _tacit983 as scene


def _conclude(*, confidence: str | None = "high", attacker_gain: str | None = None,
              impact: str = "none") -> str:
    rows = [
        "termination.category   adversarial-refuted",
        "disposition            benign",
        f"impact_verdict         {impact}",
    ]
    if confidence is not None:
        rows.append(f"confidence             {confidence}")
    if attacker_gain is not None:
        rows.append(f"attacker_gain          {attacker_gain}")
    rows.append('summary                "the build step\'s own CA rewrite"')
    return (
        "```invlang\n:T conclude\n" + "\n".join(rows) + "\n\n"
        ":T conclude.surviving [hyp_id|final_weight]\nh-001|++\n```\n"
    )


def _exhausted_rows(*, baseline: bool = True) -> str:
    consults = [scene.lookup_miss_row()]
    if baseline:
        consults.append(scene.consultation_row())
    return scene.consult_block(*consults) + scene.authz_block(scene.authz_row(
        verdict="indeterminate", basis="exhausted", grounding="", anchor_id="",
    ))


def _doc(rows: str, **conclude) -> str:
    return scene.document(rows=rows, conclude=_conclude(**conclude))


def _companion(doc: str):
    return parse_dense_companion(doc)[0]


# ------------------------------------------------------------------ the authorized route


def test_authorized_with_a_baseline_earns_high():
    doc = _doc(scene.authorized_rows(baseline=True))
    assert validate_companion(doc, None) == []
    assert benign_confidence_ceiling(_companion(doc)) == "high"
    assert committed_benign_confidence(_companion(doc)) == "high"


def test_authorized_without_a_baseline_caps_at_medium():
    doc = _doc(scene.authorized_rows())
    assert validate_companion(doc, None) == []
    assert benign_confidence_ceiling(_companion(doc)) == "medium"
    assert committed_benign_confidence(_companion(doc)) == "medium", (
        "the model's `high` outranked a record that never checked the session"
    )


def test_the_model_may_claim_less_than_the_record_earns():
    doc = _doc(scene.authorized_rows(baseline=True), confidence="low")
    assert committed_benign_confidence(_companion(doc)) == "low"


def test_a_close_that_states_no_confidence_never_reaches_high():
    doc = _doc(scene.authorized_rows(baseline=True), confidence=None)
    assert validate_companion(doc, None) == []
    assert committed_benign_confidence(_companion(doc)) == "medium"


def test_an_off_vocabulary_confidence_is_refused():
    doc = _doc(scene.authorized_rows(baseline=True), confidence="certain")
    assert [e for e in validate_companion(doc, None) if "confidence" in e]


# ------------------------------------------------------------------ the baseline route


def test_no_record_with_a_baseline_and_no_gain_closes_at_low():
    doc = _doc(_exhausted_rows(), attacker_gain="none")
    assert validate_companion(doc, None) == []
    assert disposition_entry_price("benign", doc).owed == ()
    assert committed_benign_confidence(_companion(doc)) == "low", (
        "a close with no authorization record rose above `low`"
    )


@pytest.mark.parametrize(
    ("rows", "conclude", "names"),
    [
        pytest.param(_exhausted_rows(), {"attacker_gain": "some"}, "attacker_gain none",
                     id="an-attacker-would-have-gained-something"),
        pytest.param(_exhausted_rows(), {}, "attacker_gain none", id="gain-never-stated"),
        pytest.param(_exhausted_rows(baseline=False), {"attacker_gain": "none"},
                     "baseline", id="no-baseline"),
        pytest.param(_exhausted_rows(), {"attacker_gain": "none", "impact": "exceeds"},
                     "impact_verdict", id="impact-exceeded"),
    ],
)
def test_the_baseline_route_refuses_what_it_does_not_pay_for(rows, conclude, names):
    doc = _doc(rows, **conclude)
    owed = disposition_entry_price("benign", doc).owed
    assert any(names in e for e in owed), owed
    assert benign_confidence_ceiling(_companion(doc)) is None


def test_two_stories_standing_is_not_benign():
    doc = scene.document(
        rows=_exhausted_rows(), settled=False, conclude=_conclude(attacker_gain="none"),
    )
    owed = disposition_entry_price("benign", doc).owed
    assert any("exactly one story" in e for e in owed), owed


def test_an_unauthorized_step_is_never_benign():
    rows = scene.consult_block(scene.lookup_hit_row(), scene.consultation_row()) + (
        scene.authz_block(scene.authz_row(verdict="unauthorized"))
    )
    doc = _doc(rows, attacker_gain="none")
    assert benign_confidence_ceiling(_companion(doc)) is None
    assert disposition_entry_price("benign", doc).owed


def test_an_open_contract_is_not_a_searched_one():
    """A contract simply left `retry` is a question not yet asked, not a missing record."""
    rows = scene.consult_block(scene.consultation_row()) + scene.authz_block(scene.authz_row(
        verdict="indeterminate", grounding="", anchor_id="",
    ))
    doc = _doc(rows, attacker_gain="none")
    assert benign_confidence_ceiling(_companion(doc)) is None


# ------------------------------------------------------------------ the report


def test_the_report_carries_the_committed_confidence():
    body = render_report("benign", outcome="stands", cause="c", confidence="medium")
    assert "confidence: medium\n" in body
    assert validate_report(body) is None


@pytest.mark.parametrize(
    ("disposition", "confidence"),
    [("malicious", "high"), ("benign", "certain")],
)
def test_the_report_refuses_a_confidence_off_benign_or_off_vocabulary(disposition, confidence):
    body = render_report(disposition, outcome="stands", cause="c", confidence=confidence)
    reason = validate_report(body)
    assert reason is not None
    assert "confidence" in reason
