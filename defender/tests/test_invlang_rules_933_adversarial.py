"""Mutation-derived edge cases for invlang validator rules #6, #17, #23, #24 and #33."""

from __future__ import annotations

import pytest

from defender.skills.invlang.validate import _SIBLING_FORK_TAG, validate_companion

_PROLOGUE = """\
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|monitoring-agent/internal/known-corp|172.18.0.15|
v-002|compute|monitoring-agent/internal/known-corp|172.18.0.16|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|

"""

_HYP_HEADER = (
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
)


def _doc(body: str) -> str:
    return "```invlang\n" + body + "```\n"


def _errors(body: str) -> list[str]:
    return [str(e) for e in validate_companion(_doc(body), None)]


def _joined(body: str) -> str:
    return "\n".join(_errors(body))


# rule #6: prediction completeness for `++`

_TWO_PREDS = _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
p2|proposed_edge|"no fixed interval separates the failures"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001|elastic|10m

"""


def test_the_coverage_gate_still_bites_when_a_conclude_block_is_present() -> None:
    errors = _errors(_TWO_PREDS + """\
:T resolutions
h-001  null → ++   [l-001 p1 severe ⟂ e-001 :: bursty]

:T conclude
termination.category   exhaustion
disposition            inconclusive
impact_verdict         none
confidence             low
summary                "Confirmed on the burst pattern"

:T conclude.surviving [hyp_id|final_weight]
h-001|++
""")
    assert any("resolution of h-001 to '++' leaves p2 unmatched" in e for e in errors), errors


def test_an_earlier_partial_move_counts_toward_the_double_plus() -> None:
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
p2|proposed_edge|"no fixed interval separates the failures"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001|elastic|10m
l-002|2|interval-histogram|v-001|h-001|elastic|24h

:T resolutions
h-001  null → +    [l-001 p1 moderate ⟂ e-001 :: bursty]
h-001  + → ++      [l-002 p2 severe ⟂ e-001 :: no interval]
""") == []


def test_the_first_confirming_lead_is_the_one_named() -> None:
    """Two `++` rows, one hypothesis. The error names `l-001`, the lead that first made the
    claim — the append-only document's earliest offending write, not its latest."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
p2|proposed_edge|"no fixed interval separates the failures"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001|elastic|10m
l-002|2|auth-history-again|v-001|h-001|elastic|24h

:T resolutions
h-001  null → ++   [l-001 p1 severe ⟂ e-001 :: bursty]
h-001  ++ → ++     [l-002 p1 severe ⟂ e-001 :: bursty again]
""")
    assert len(errors) == 1
    assert errors[0].startswith("lead l-001: resolution of h-001 to '++' leaves p2 unmatched")


def test_a_hypothesis_born_inside_a_lead_is_gated_too() -> None:
    errors = _errors(_PROLOGUE + """\
:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001||elastic|10m
l-002|2|interval-histogram|v-001|h-003|elastic|24h

:H l-001.new_hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-003|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-003.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
p2|proposed_edge|"no fixed interval separates the failures"

:T resolutions
h-003  null → ++   [l-002 p1 severe ⟂ e-001 :: bursty]
""")
    assert len(errors) == 1
    assert "resolution of h-003 to '++' leaves p2 unmatched" in errors[0]


def test_a_siblings_citation_does_not_cover_this_hypothesis() -> None:
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
p2|proposed_edge|"no fixed interval separates the failures"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures repeat on a fixed interval"
p2|proposed_edge|"the interval is stable to the second"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001,h-002|elastic|10m

:T resolutions
h-001  null → ++   [l-001 p1 severe ⟂ e-001 :: bursty]
h-002  null → -    [l-001 p2 moderate ⟂ e-001 :: no stable interval]
""")
    assert len(errors) == 1
    assert "resolution of h-001 to '++' leaves p2 unmatched" in errors[0]


# rule #17: SCREEN structural integrity

_SCREEN_HEADER = ":L findings [id|loop|name|target|mode|tests|system|window|screen_result]\n"


def test_a_matched_screen_with_no_hypothesize_block_is_the_shape_the_rule_wants() -> None:
    assert _errors(_PROLOGUE + _SCREEN_HEADER + """\
l-001|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|match
""") == []


def test_a_result_on_a_non_screen_lead_is_one_defect_not_two() -> None:
    """One defect, one refusal:"""
    errors = _errors(_PROLOGUE + _SCREEN_HEADER + """\
l-001|1|auth-history|v-001|||elastic|10m|no_match
l-002|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|no_match
""")
    assert len(errors) == 1
    assert "on a lead whose mode is ''" in errors[0]


# rule #23: hypothesis fork distinctness

_TWO_PARENTS = _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active
{children}

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures repeat on a fixed interval"

{child_preds}"""


def test_identical_claims_under_different_parents_are_not_a_fork() -> None:
    assert _errors(_TWO_PARENTS.format(
        children=(
            "h-001-a|?burst-source-a|v-001|runs_on|process|??/??/??||null|active\n"
            "h-002-b|?burst-source-b|v-001|runs_on|process|??/??/??||null|active"
        ),
        child_preds=(
            ':H h-001-a.preds [id|subject|claim]\n'
            'p1|proposed_edge|"the source is a single host"\n'
            "\n"
            ':H h-002-b.preds [id|subject|claim]\n'
            'p1|proposed_edge|"the source is a single host"\n'
        ),
    )) == []


def test_identical_claims_under_the_SAME_parent_are_a_fork() -> None:
    """The control for the pair above: move both children under `h-001` and the same two
    sentences become the defect."""
    errors = _errors(_TWO_PARENTS.format(
        children=(
            "h-001-a|?burst-source-a|v-001|runs_on|process|??/??/??||null|active\n"
            "h-001-b|?burst-source-b|v-001|runs_on|process|??/??/??||null|active"
        ),
        child_preds=(
            ':H h-001-a.preds [id|subject|claim]\n'
            'p1|proposed_edge|"the source is a single host"\n'
            "\n"
            ':H h-001-b.preds [id|subject|claim]\n'
            'p1|proposed_edge|"the source is a single host"\n'
        ),
    ))
    assert len(errors) == 1
    assert "hypotheses h-001-a, h-001-b anchor on v-001 and " + _SIBLING_FORK_TAG in errors[0]


def test_two_siblings_repeating_one_attribute_prediction_are_refused() -> None:
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"the binary is unsigned"

:H h-002.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"The binary is   unsigned."
""")
    assert len(errors) == 1
    assert "hypotheses h-001, h-002 anchor on v-001 and " + _SIBLING_FORK_TAG in errors[0]


def test_an_attribute_prediction_keys_on_what_the_value_is_a_value_of() -> None:
    """The mirror of the pair above, and the reason `target` and `attribute` ARE in the key where `.preds`'s `subject` is not."""
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"unsigned"

:H h-002.attr_preds [id|target|attribute|claim]
ap1|attached_vertex|signing|"unsigned"
""") == []


def test_siblings_that_share_one_claim_and_differ_in_another_are_distinct() -> None:
    """The floor is an IDENTICAL claim set, not an overlapping one."""
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"both stories expect the source inside the corporate range"
p2|proposed_edge|"failures arrive in bursts"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"both stories expect the source inside the corporate range"
p2|proposed_edge|"failures repeat on a fixed interval"
""") == []


def test_two_siblings_declaring_no_predictions_are_skipped() -> None:
    joined = _joined(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active
""")
    assert _SIBLING_FORK_TAG not in joined


# rule #24: hypothesis persistence at CONCLUDE

def test_naming_a_hypothesis_in_the_conclude_prose_is_not_a_discharge() -> None:
    """v2.18 excised "cited in the conclude block" from arm (b):"""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures repeat on a fixed interval"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001|elastic|10m

:T conclude
termination.category   exhaustion
termination.rationale  "h-002 was never reached; the interval histogram lead did not return"
disposition            malicious
impact_verdict         none
confidence             low
summary                "h-002 stays open"

:T conclude.surviving [hyp_id|final_weight]
h-001|null

:T conclude.deferred_preds [prediction_ref|rationale]
h-001.p1|"the interval histogram lead did not return"
h-002.p1|"the interval histogram lead did not return"
""")
    assert len(errors) == 1
    assert "hypothesis h-002 is neither refuted nor carried into the close" in errors[0]


# rule #33: attribute-prediction structure

def _with_attr_preds(rows: str) -> str:
    return _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-001.attr_preds [id|target|attribute|claim]
""" + rows


@pytest.mark.parametrize(("case", "apid"), [
    # `a1` — the one shape the original file writes — is the only one a `\\w+` regex misses.
    ("trailing-junk", "ap1x"),
    ("leading-junk", "xap1"),
    ("no-index", "ap"),
    ("wrong-case", "AP1"),
    ("index-only", "1"),
])
def test_every_id_outside_the_ap_namespace_is_refused(case: str, apid: str) -> None:
    errors = _errors(_with_attr_preds(f'{apid}|proposed_parent|signing|"unsigned"\n'))
    assert len(errors) == 1
    assert f"row {apid!r}: an attribute prediction is numbered `ap<n>`" in errors[0]


def test_a_hypothesis_whose_only_predictions_are_attribute_predictions_is_checked() -> None:
    """`.attr_preds` does not require a `.preds` block beside it — the whole point of rule
    #33's namespace is that an observable may be declared under either."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
a1|proposed_parent|signing|"unsigned"
""")
    assert len(errors) == 1
    assert "row 'a1': an attribute prediction is numbered `ap<n>`" in errors[0]


def test_a_defective_row_on_a_lead_declared_hypothesis_is_refused() -> None:
    """`:H l-NNN.new_hypotheses` declares hypotheses the same way the opening block does, and
    `_walkers.all_hypotheses` walks both."""
    errors = _errors(_PROLOGUE + """\
:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001||elastic|10m

:H l-001.new_hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-003|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-003.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-003.attr_preds [id|target|attribute|claim]
a9|proposed_parent|signing|"unsigned"
""")
    assert len(errors) == 1
    assert "`:H h-003.attr_preds` row 'a9'" in errors[0]
