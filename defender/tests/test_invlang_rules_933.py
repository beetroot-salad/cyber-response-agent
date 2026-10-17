"""#933 — the five spec rules that were written down and never armed.

Rules #6 (prediction completeness for `++`), #17 (SCREEN structural integrity), #23
(hypothesis fork distinctness), #24 (hypothesis persistence at CONCLUDE) and #33
(attribute-prediction structure) were active in `docs/investigation-language.md` with no
implementing function. Each block below pairs the violation with a LIVENESS CONTROL — the same
document, one cell different, validating clean — so a check that stopped running fails here
rather than passing vacuously.

The shared prologue is the smallest document the other rules accept: one vertex with a settled
class, one `siem-event` edge for rule #4, and no `conclude`, so nothing but the rule under test
can speak.
"""

from __future__ import annotations

import pytest

from defender.skills.invlang.validate import _SIBLING_FORK_TAG, validate_companion

_PROLOGUE = """\
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|monitoring-agent/internal/known-corp|172.18.0.15|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|

"""

_HYP_HEADER = (
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
)

_ONE_HYPOTHESIS = _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
p2|proposed_edge|"no fixed interval separates the failures"

"""

_LEAD = """\
:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001|elastic|10m

"""


def _doc(body: str) -> str:
    return "```invlang\n" + body + "```\n"


def _errors(body: str) -> list[str]:
    return validate_companion(_doc(body), None)


# rule #6: prediction completeness for `++`

_SIX_FULL = _PROLOGUE + _ONE_HYPOTHESIS + _LEAD + """\
:T resolutions
h-001  null → ++   [l-001 p1,p2 severe ⟂ e-001 :: bursty, no interval]
"""

_SIX_PARTIAL = _SIX_FULL.replace("[l-001 p1,p2 severe", "[l-001 p1 severe")

#: The same hypothesis with its second observable declared as an ATTRIBUTE prediction instead.
#: `matched_prediction_ids` may cite either namespace (rules #33/#34), so an `ap*` left
#: unmatched is the same hole as a `p*` left unmatched — pinning the judgment call that #6's
#: "full prediction set" is `_declared_prediction_ids`'s union and not `p*` alone.
_SIX_WITH_ATTR_PRED = _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_edge|interval|"no fixed interval separates the failures"

""" + _LEAD + """\
:T resolutions
h-001  null → ++   [l-001 p1 severe ⟂ e-001 :: bursty]
"""


def test_a_double_plus_leaving_a_declared_prediction_unmatched_is_refused() -> None:
    errors = _errors(_SIX_PARTIAL)
    assert len(errors) == 1
    assert "resolution of h-001 to '++' leaves p2 unmatched" in errors[0]
    # The repair is spelled as a row that PARSES: bare "h-001 ++ → +" is refused by
    # `_RESOLUTION_LINE_RE` for the missing citation head, so a message offering it as a
    # literal hands the author a second refusal instead of a fix. The LEAD is filled in for
    # the same reason — `<lead>` copied verbatim draws `undeclared lead '<lead>'`, which is
    # the second refusal by another route.
    assert "`h-001  ++ → +   [l-001 <ids> <severity> ⟂ <edges>]`" in errors[0]
    assert "grade it partial coverage" in errors[0]


def test_an_unmatched_attribute_prediction_blocks_a_double_plus_like_a_p_star_would() -> None:
    errors = _errors(_SIX_WITH_ATTR_PRED)
    assert len(errors) == 1
    assert "leaves ap1 unmatched" in errors[0]


# rule #17: SCREEN structural integrity

_SCREEN_HEADER = ":L findings [id|loop|name|target|mode|tests|system|window|screen_result]\n"

_SCREEN_CLEAN = _PROLOGUE + _SCREEN_HEADER + """\
l-001|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|no_match
"""

_SCREEN_ON_A_NON_SCREEN_LEAD = _PROLOGUE + _SCREEN_HEADER + """\
l-001|1|auth-history|v-001|||elastic|10m|no_match
"""

_SCREEN_SEQUENCE_EVERY_LEAD_SCORED = _PROLOGUE + _SCREEN_HEADER + """\
l-001|1|source-screen|v-001|screen||cmdb|n/a|no_match
l-002|1|cadence-screen|v-001|screen||elastic|24h|no_match
"""

_SCREEN_MATCH_WITH_HYPOTHESES = _PROLOGUE + _ONE_HYPOTHESIS + _SCREEN_HEADER + """\
l-001|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|match
"""


def test_a_screen_result_on_a_lead_that_did_not_screen_is_refused() -> None:
    errors = _errors(_SCREEN_ON_A_NON_SCREEN_LEAD)
    assert len(errors) == 1
    assert "lead l-001: `screen_result: no_match` on a lead whose mode is ''" in errors[0]


def test_a_matched_screen_beside_a_hypothesize_block_is_refused() -> None:
    errors = _errors(_SCREEN_MATCH_WITH_HYPOTHESES)
    assert len(errors) == 1
    assert "`screen_result: match` closes the run on the fast path" in errors[0]


# rule #23: hypothesis fork distinctness

_FORK_DISTINCT = _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts, no fixed interval between them"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures repeat on a fixed interval"
"""

_FORK_IDENTICAL = _FORK_DISTINCT.replace(
    'p1|proposed_edge|"failures repeat on a fixed interval"',
    'p1|proposed_edge|"Failures arrive in bursts,   no fixed interval between them"',
)

#: The same claims on hypotheses hung on DIFFERENT vertices. Not siblings, so not a fork.
_SAME_CLAIMS_ON_TWO_ANCHORS = _PROLOGUE.replace(
    "v-001|compute|monitoring-agent/internal/known-corp|172.18.0.15|",
    "v-001|compute|monitoring-agent/internal/known-corp|172.18.0.15|\n"
    "v-002|compute|monitoring-agent/internal/known-corp|172.18.0.16|",
) + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?credential-guessing|v-002|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts, no fixed interval between them"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts, no fixed interval between them"
"""


def test_siblings_declaring_the_same_claims_are_refused() -> None:
    errors = _errors(_FORK_IDENTICAL)
    assert len(errors) == 1
    assert "hypotheses h-001, h-002 anchor on v-001 and " + _SIBLING_FORK_TAG in errors[0]
    # The message names the RULE rather than the colliding claim text: two hypotheses that
    # collide here are identical over their whole signature, so quoting it back adds length
    # and not information, and the repair is a differing prediction rather than an edit to
    # the sentence quoted.
    assert "siblings must differ on at least one predicted observable" in errors[0]


#: Identical claims under DIFFERENT parent classes — the mirror of `_FORK_DISTINCT`, and the
#: half that tells the two candidate rules apart. Keyed on the claim set this is a fork and is
#: refused; keyed on `parent_class` it is two distinct upstreams and passes.
_FORK_IDENTICAL_DISTINCT_CLASSES = _FORK_IDENTICAL.replace(
    "h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??|",
    "h-002|?scheduled-service-retry|v-001|runs_on|process|init-or-entrypoint|",
)


def test_the_axis_is_the_claim_set_and_not_the_parent_class() -> None:
    """The #934 guard, stated so that only the right rule can pass it."""
    assert _errors(_FORK_DISTINCT) == []
    errors = _errors(_FORK_IDENTICAL_DISTINCT_CLASSES)
    assert len(errors) == 1
    assert "hypotheses h-001, h-002 anchor on v-001 and " + _SIBLING_FORK_TAG in errors[0]


# rule #24: hypothesis persistence at CONCLUDE

# #923: `disposition malicious` here, not `inconclusive` — this class is about the surviving
# table, unrelated to `inconclusive`'s own entry price (a `ceiling_test` row this fixture
# never writes).
_TWO_LIVE_HYPOTHESES = _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures repeat on a fixed interval"

""" + _LEAD + """\
:T conclude
termination.category   exhaustion
disposition            malicious
impact_verdict         none
confidence             low
summary                "Neither cadence story was settled"

:T conclude.deferred_preds [prediction_ref|rationale]
h-001.p1|"the interval histogram lead did not return"
h-002.p1|"the interval histogram lead did not return"

"""

_SURVIVING_ONE_OF_TWO = _TWO_LIVE_HYPOTHESES + """\
:T conclude.surviving [hyp_id|final_weight]
h-001|null
"""

_SURVIVING_BOTH = _TWO_LIVE_HYPOTHESES + """\
:T conclude.surviving [hyp_id|final_weight]
h-001|null
h-002|null
"""


def test_a_surviving_table_that_omits_a_live_hypothesis_is_refused() -> None:
    errors = _errors(_SURVIVING_ONE_OF_TWO)
    assert len(errors) == 1
    assert "hypothesis h-002 is neither refuted nor carried into the close" in errors[0]
    assert "omits it" in errors[0]


def test_refuting_the_hypothesis_discharges_it_instead() -> None:
    """The other arm: `--` is a discharge, so a refuted hypothesis needs no surviving row."""
    refuted = _SURVIVING_ONE_OF_TWO.replace(
        ":T conclude\n",
        ":T resolutions\n"
        "h-002  null → --   [l-001 p1 severe ⟂ e-001 :: interval is fixed to the second]\n\n"
        ":T conclude\n",
    )
    assert _errors(refuted) == []


def test_an_empty_surviving_table_still_speaks() -> None:
    """`none` is the format's empty-ARRAY marker, so the table is present and claims nothing
    survived — which two live hypotheses contradict."""
    errors = _errors(_TWO_LIVE_HYPOTHESES + """\
:T conclude.surviving [hyp_id|final_weight]
none|
""")
    assert len(errors) == 2
    assert all("neither refuted nor carried into the close" in e for e in errors)


# rule #33: attribute-prediction structure

def _with_attr_preds(rows: str) -> str:
    return _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-001.attr_preds [id|target|attribute|claim]
""" + rows


@pytest.mark.parametrize(("case", "rows", "fragment"), [
    ("id-outside-the-ap-namespace",
     'a1|proposed_parent|signing|"unsigned"\n',
     "row 'a1': an attribute prediction is numbered `ap<n>`"),
    ("target-outside-the-enum",
     'ap1|v-001|signing|"unsigned"\n',
     "target 'v-001' is not one of proposed_parent, attached_vertex, proposed_edge"),
    ("claim-cell-empty",
     "ap1|proposed_parent|signing|\n",
     "row 'ap1': empty `claim`"),
])
def test_a_defective_attribute_prediction_row_is_refused(
    case: str, rows: str, fragment: str
) -> None:
    errors = _errors(_with_attr_preds(rows))
    assert len(errors) == 1
    assert fragment in errors[0]


# refutation scope: the third `p*` site, which rule #7's family never reached

_REFUT_IN_SCOPE = _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"unsigned"

:H h-001.refuts [id|refutes|claim]
r1|p1,ap1|"the series is cadenced and the binary is signed"
"""

_REFUT_OUT_OF_SCOPE = _REFUT_IN_SCOPE.replace("r1|p1,ap1|", "r1|p1,ap9|")

#: A sibling's `p1` is not this hypothesis's evidence in either direction. The id EXISTS in the
#: document, so a document-wide lookup accepts this and only a hypothesis-scoped one refuses it.
_REFUT_CITES_A_SIBLINGS_PREDICTION = _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-002.preds [id|subject|claim]
p2|proposed_edge|"failures repeat on a fixed interval"

:H h-001.refuts [id|refutes|claim]
r1|p2|"the series is cadenced"
"""

#: A refutation on a hypothesis that declared no predictions yet. Lean, legal, and nothing for
#: the scope rule to resolve against — rule #23 exempts the same shape.
_REFUT_ON_A_PREDICTIONLESS_HYPOTHESIS = _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.refuts [id|refutes|claim]
r1|p1|"the series is cadenced"
"""


def test_a_refutation_naming_an_undeclared_prediction_is_refused() -> None:
    """`:H h-NNN.refuts`'s `refutes` column is the third site naming a `p*`/`ap*`, and it resolved against nothing:"""
    errors = _errors(_REFUT_OUT_OF_SCOPE)
    assert len(errors) == 1
    assert "row 'r1' refutes prediction 'ap9'" in errors[0]
    assert "h-001 does not declare" in errors[0]


def test_a_refutation_may_not_reach_a_siblings_prediction() -> None:
    """Scoped to the declaring hypothesis for the reason `_check_prediction_refs` is. `p2` is
    declared in this document, just not by `h-001`, so a document-wide lookup passes it."""
    errors = _errors(_REFUT_CITES_A_SIBLINGS_PREDICTION)
    assert len(errors) == 1
    assert "row 'r1' refutes prediction 'p2'" in errors[0]


# review follow-ups: the holes the armed rules left open
#
# Every case below was reachable on the first arming pass and is now closed. They live here
# rather than in a file of their own because each is the SAME rule as the block above it, one
# input further out — a rule that stops firing on these is a rule that shipped its first
# version again.


_ONE_CONTRACT = _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|endpoint-policy|"is this auth permitted"|escalate|escalate

"""


def test_a_conclude_block_that_records_nothing_is_refused() -> None:
    """The CLOSURE gates read "is this document closing" off a non-empty `conclude`, and `_project_conclude_scalars` drops an unrecognized key in silence — so a close keyed entirely on keys the projection do"""
    errors = _errors(_PROLOGUE + _ONE_CONTRACT + _LEAD + """\
:T conclude
handoff_notes          "sent to tier 2"
""")
    assert any("`:T conclude` recorded nothing" in e for e in errors)


def test_a_citation_from_a_row_that_moved_nowhere_does_not_cover_a_confirmation() -> None:
    """Rule #6 unioned `matched_prediction_ids` over EVERY resolution, so a `null → null`
    row citing `p2` covered the `++` — while rule #34, the late half of the same pair, does
    not count it. The write gate passed a document its own closure gate refuses."""
    errors = _errors(_PROLOGUE + _ONE_HYPOTHESIS + _LEAD + """\
:T resolutions
h-001  null → null [l-001 p2 mild ⟂ e-001 :: looked, moved nowhere]
h-001  null → ++   [l-001 p1 severe ⟂ e-001 :: bursty]
""")
    assert any("leaves p2 unmatched" in e for e in errors)


def test_a_prediction_numbered_outside_the_p_namespace_is_refused() -> None:
    """Rule #33 armed the id-shape check on `.attr_preds` and left `.preds` unchecked."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
x1|proposed_edge|"failures arrive in bursts"

""" + _LEAD)
    assert any("a prediction is numbered `p<n>`" in e for e in errors)


def test_a_blank_ceiling_test_row_is_not_a_receipt() -> None:
    """`ceiling_test  ""` projects as a one-element list holding the empty string — truthy,
    and a receipt naming no gap. The honest `none` marker projects as absence and IS refused,
    so a bare truthiness test made the blank easier to pass than the honest answer."""
    errors = _errors(_PROLOGUE + _ONE_HYPOTHESIS + _LEAD + """\
:T resolutions
h-001  null → +    [l-001 p1,p2 mild ⟂ e-001 :: bursty, no interval]

:T conclude
disposition            inconclusive
confidence             low
termination.category   severity-ceiling
ceiling_test           ""
summary                "s"

:T conclude.surviving [hyp_id|final_weight]
h-001|+
""")
    assert any("with no `ceiling_test`" in e for e in errors)


def test_a_shared_contract_id_is_discharged_only_by_its_own_anchor_kind() -> None:
    """`_check_authz_contract_ids` permits two declarers of one `ac*` when one is refuted — which is exactly the shape this rule covers and the benign gate does not."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-001.refuts [id|refutes|claim]
r1|p1|"failures are evenly spaced"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|change-mgmt|"was this change approved"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"the scheduler owns the retry"

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"may this identity authenticate here"|escalate|escalate

""" + _LEAD + """\
:R authz [resolved_by|fulfills|verdict|grounding|anchor_id|anchor_kind|authority|as_of|reasoning]
l-001|ac1|authorized|iam-policy-binding|POL-1|iam-policy|full|2026-05-05T03:42:11Z|"bound"

:T resolutions
h-001  null → --   [l-001 r1 severe ⟂ e-001 :: evenly spaced]
h-002  null → +    [l-001 p1 mild ⟂ e-001 :: scheduler owns it]

:T conclude
disposition            inconclusive
confidence             low
summary                "s"

:T conclude.surviving [hyp_id|final_weight]
h-002|+
""")
    assert any("authz contract h-001.ac1 is declared and then abandoned" in e for e in errors)


def test_two_screen_phases_in_different_loops_are_two_sequences() -> None:
    """Two screen phases in different loops, each carrying its own result."""
    assert _errors(_PROLOGUE + """\
:L findings [id|loop|name|target|mode|screen_result|tests|system|window]
l-001|1|known-pattern-screen|v-001|screen|no_match||elastic|10m
l-002|2|second-phase-screen|v-001|screen|no_match||elastic|10m
""") == []


def test_a_leading_decimal_point_is_not_stripped_from_a_claim() -> None:
    """`str.strip` takes a character SET, so the trailing-full-stop strip also ate a leading
    decimal point — fusing two siblings that fork on a tenfold threshold into one signature
    and refusing the fork."""
    from defender.skills.invlang.validate import _normalized_claim

    assert _normalized_claim(".5 sigma above baseline") != _normalized_claim(
        "5 sigma above baseline"
    )
    assert _normalized_claim('  "Alpha holds."  ') == "alpha holds"


# #940 review regressions
#
# Each of these was a hole a rule armed in this change left open, or a legal document one of
# them refused. They sit here rather than in their own file so they share the one prologue —
# the same reason the blocks above do.

#: A `:T conclude` block for tests that need SOME close and don't care which — hypothesis
#: persistence, prediction/contract closure, deferral rationale. #923 gives `inconclusive`
#: its own entry price (a `ceiling_test` row naming a source or capability), unrelated to any
#: of these rules; `malicious` carries no price under any rule and keeps these fixtures
#: exercising only what they name. (Renamed from `_CLOSE_INCONCLUSIVE`, which this no longer
#: is.)
_CLOSE_UNPRICED = """\
:T conclude
disposition            malicious
summary                "s"

:T conclude.surviving [hyp_id|final_weight]
h-001|null

"""

_ONE_PRED = _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

"""


def _moved(after: str) -> str:
    return f":T resolutions\nh-001 null \u2192 {after}    [l-001 p1 mild \u27c2 e-001]\n\n"


@pytest.mark.parametrize("after", ["confirmed", "x", "+++", "CONFIRMED"])
def test_an_off_vocabulary_after_token_settles_no_prediction(after: str) -> None:
    """The `after` cell is an unvalidated a non-whitespace run and nothing checks it against `WEIGHT_BUCKETS`, so a "moved unless null" test made a misspelling the CHEAPEST row in the language:"""
    errors = _errors(_PROLOGUE + _ONE_PRED + _LEAD + _moved(after) + _CLOSE_UNPRICED)
    assert any("h-001.p1" in e and "declared and then abandoned" in e for e in errors), errors


#: A `:R impact` row and the `ip1` it grades, with EVERY cell quoted — legal, and the shape
#: that drew three simultaneous refusals before the read side learned to unquote.
_IMPACT_QUOTED = (
    ":L l-001.impact_preds "
    "[id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]\n"
    'ip1|"confidentiality"|"session bytes within the 30d baseline"'
    "|within|exceeds|indeterminate|exceeds\n\n"
    ":R impact [resolved_by|pred_ref|dim|observed|verdict|grounding|authority|as_of"
    "|reasoning]\n"
    'l-001|"ip1"|"confidentiality"|"180GB"|"exceeds"|"telemetry-baseline"|"partial"'
    '|"2026-05-05T04:00:00Z"|"3 sigma over a 2 sigma threshold"\n\n'
)


_LONE_CONTRACT = _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"may this identity authenticate here"|escalate|escalate

"""


def _authz_row(fulfills: str) -> str:
    return (
        ":R authz [resolved_by|fulfills|verdict|grounding|anchor_id|anchor_kind|authority"
        "|as_of|reasoning]\n"
        f'l-001|{fulfills}|authorized|iam-policy-binding|POL-1|iam-policy|full'
        '|2026-05-05T03:42:11Z|"bound"\n\n'
    )


def test_a_qualified_fulfills_discharges_only_its_own_declarer() -> None:
    """...and no other hypothesis's `ac1`: the qualified form names its declarer, which is the
    whole reason it is worth accepting."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?a|v-001|runs_on|process|??/??/??||null|active
h-002|?b|v-001|runs_on|process|??/??/??||--|refuted

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"may this identity authenticate here"|escalate|escalate

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|change-mgmt|"was this change approved"|escalate|escalate

""" + _LEAD + _authz_row("h-001.ac1") + _CLOSE_UNPRICED)
    assert [e for e in errors if "h-002.ac1" in e], errors
    assert not [e for e in errors if "h-001.ac1" in e], errors


def test_twin_contracts_under_one_anchor_kind_are_discharged_by_nothing() -> None:
    """`_authz_contract_error` states it first:"""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?a|v-001|runs_on|process|??/??/??||null|active
h-002|?b|v-001|runs_on|process|??/??/??||--|refuted

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"may this identity authenticate here"|escalate|escalate

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"a different question under the same anchor"|escalate|escalate

""" + _LEAD + _authz_row("ac1") + _CLOSE_UNPRICED)
    named = [e for e in errors if "is declared and then abandoned" in e]
    assert [e for e in named if "h-001.ac1" in e], errors
    assert [e for e in named if "h-002.ac1" in e], errors
    # The repair has to be one the grammar can express AND one that works. `fulfills=ac1` is
    # already written, and renumbering an append-only `:H` row is not a repair at all — so the
    # message names the QUALIFIED `fulfills=h-NNN.ac1`, which this rule resolves through its
    # `qualified` set and which does discharge a twin (asserted below).
    assert all("fulfills=h-001.ac1" in e for e in named if "h-001.ac1" in e), errors
    assert all("fulfills=h-002.ac1" in e for e in named if "h-002.ac1" in e), errors
    assert all("numbers across the DOCUMENT" in e for e in named), errors


@pytest.mark.parametrize(
    ("rationale", "discharges"),
    [('"telemetry never arrived"', True), ("none", False), ("n/a", False), ('""', False)],
)
def test_the_empty_marker_is_not_a_deferral_rationale(
    rationale: str, discharges: bool
) -> None:
    """`none` / `n/a` is the format's own word for "nothing to say", taught two paragraphs from the deferral tables as the empty-TABLE marker."""
    errors = _errors(
        _PROLOGUE + _ONE_PRED + _LEAD + _CLOSE_UNPRICED
        + f":T conclude.deferred_preds [prediction_ref|rationale]\nh-001.p1|{rationale}\n\n"
    )
    assert (errors == []) is discharges, errors


def test_a_second_conclude_block_of_unrecognized_keys_does_not_refuse_the_close() -> None:
    """`_project_conclude_scalars` refuses to warn on an unrecognized flat key because "the lessons corpus can instruct conclude rows this projection does not carry, and `learning/core/persist.py` dead-letters a run whose investigation.md fails validation"."""
    assert _errors(
        _PROLOGUE + _ONE_PRED + _LEAD + _CLOSE_UNPRICED
        + ":T conclude\nescalation_target      soc-tier2\n\n"
        + ":T conclude.deferred_preds [prediction_ref|rationale]\n"
          'h-001.p1|"telemetry never arrived"\n\n'
    ) == []


# #940 sweep regressions
#
# The second pass over the first pass. Two of these are defects the FIRST round of #940 fixes
# introduced, which is the reason the block exists as its own heading.

_LESSON_CONCLUDE = ":T conclude\nanalyst_note           soc-tier2\n\n"
_REAL_CONCLUDE = (
    ':T conclude\ndisposition            benign\nsummary                "s"\n\n'
    ":T conclude.surviving [hyp_id|final_weight]\nh-001|null\n\n"
)
_DEFER_P1 = (
    ":T conclude.deferred_preds [prediction_ref|rationale]\n"
    'h-001.p1|"telemetry never arrived"\n\n'
)


def _screen_row(mode: str, result: str) -> str:
    return (
        ":L findings [id|loop|name|target|mode|screen_result|tests|system|window]\n"
        f"l-001|1|probe|v-001|{mode}|{result}|h-001|elastic|10m\n\n"
    )


# #943 review regressions
#
# The quoting sweep the `target` fix started, finished across the rest of the row, plus the two
# normalization holes the fork rule was left with. Each case below validated CLEAN (or was
# refused with advice the author had already followed) before this block existed.


def test_a_claim_that_normalizes_to_nothing_is_an_empty_claim() -> None:
    """`_predicted_observables` drops a claim normalizing to `""` from the fork signature on the stated grounds that "rule #33 already refuses the row" — which was true of a BLANK cell and false of `"."`, `"..."` or `"''"`."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"..."

:H h-002.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"..."
""")
    assert len(errors) == 2
    assert all("empty `claim`" in e for e in errors)


def test_a_screen_result_on_a_lead_that_never_screened_does_not_also_close_the_run() -> None:
    """The mode arm and the matched-screen arm were not alternatives: one `match` on a lead
    with no `mode: screen` earned both, and the second told the author to delete a legitimate
    `:H hypothesize.hypotheses` block over a screen that never ran."""
    errors = _errors(_PROLOGUE + _ONE_HYPOTHESIS + """\
:L findings [id|loop|name|target|mode|screen_result|tests|system|window]
l-001|1|auth-history|v-001||match|h-001|elastic|10m
""")
    assert len(errors) == 1
    assert "on a lead whose mode is ''" in errors[0]


def test_a_whitespace_only_attribute_is_the_parse_error_rule_33_says_it_is() -> None:
    """Rule #33 leaves `attribute` to the parser on the stated grounds that `_require` tests truthiness — which held for a bare empty cell and not for a quoted run of spaces, since `_require` saw the cell before anything unquoted it."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|"  "|"unsigned"
""")
    assert len(errors) == 1
    assert "attr_preds row missing id/target/attribute" in errors[0]


# #943 second-review regressions
#
# Nine more inputs the first arming pass let through, in the order the rules are declared
# above. Every one is the SAME rule one input further out, so each carries the control that
# says the rule is still the thing being measured.


def test_a_leading_full_stop_does_not_split_a_fork() -> None:
    """`_normalized_claim` stopped eating a LEADING full stop so `".5σ above baseline"` keeps its decimal point."""
    def fork(second: str) -> str:
        return _PROLOGUE + _HYP_HEADER + f"""\
h-001|?a|v-001|runs_on|process|??/??/??||null|active
h-002|?b|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"{second}"
"""
    assert len(_errors(fork("failures arrive in bursts"))) == 1
    for evasion in (".failures arrive in bursts", ". failures arrive in bursts"):
        errors = _errors(fork(evasion))
        assert len(errors) == 1, evasion
        assert _SIBLING_FORK_TAG in errors[0]


def test_an_off_vocabulary_grade_is_refused_rather_than_ignored() -> None:
    """The `after` cell was an unvalidated a non-whitespace run, and every weight-keyed gate is a membership test — so a misspelled grade skipped the strong-move provenance gate and the `++` coverage gate at once, where the honest `++` is refused for what it leaves open."""
    for token in ("confirmed", "+++"):
        errors = _errors(_SIX_PARTIAL.replace("null → ++", f"null → {token}"))
        assert len(errors) == 1, token
        assert f"after {token!r}, which is not a weight" in errors[0]


def test_a_confirmation_resting_on_a_dead_refutation_is_not_forced_to_lie() -> None:
    """`_check_strong_move_provenance` reads `matched_refutation_ids` as the same half of a strong move's provenance that `matched_prediction_ids` is;"""
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
p2|proposed_edge|"no fixed interval separates the failures"

:H h-001.refuts [id|refutes|claim]
r1|p2|"a fixed interval separates them"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001|elastic|10m
l-002|2|cadence|v-001|h-001|elastic|24h

:T resolutions
h-001  null → +    [l-001 p1 weak ⟂ e-001 :: bursty]
h-001  +    → ++   [l-002 r1 severe ⟂ e-001 :: the interval never appeared]
""") == []


def test_a_matched_screen_sees_a_hypothesis_born_inside_a_lead() -> None:
    """The fast-path arm read only `:H hypothesize.hypotheses`, and a hypothesis born mid-run
    is declared at the other of the two declaring blocks — so moving the block one lead over
    disarmed the arm on the contradiction it owns."""
    errors = _errors(_PROLOGUE + _SCREEN_HEADER + """\
l-001|0|probe-screen|v-001|screen||cmdb|n/a|match

:H l-001.new_hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?a|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
""")
    assert len(errors) == 1
    assert "closes the run on the fast path" in errors[0]


def test_a_prediction_the_annotation_negates_does_not_cover_a_confirmation() -> None:
    """`matched_prediction_ids` means "this lead TESTED the id" and files `¬p2` beside `p1` (`test_invlang_parser.test_resolution_negated_iff_literal_still_attributes`)."""
    errors = _errors(_PROLOGUE + _ONE_HYPOTHESIS + _LEAD + """\
:T resolutions
h-001  null → ++   [l-001 severe ⟂ e-001 :: bursty but the interval was fixed ⟺ p1 ∧ ¬p2]
""")
    assert len(errors) == 1
    assert "leaves p2 unmatched" in errors[0]


_IP1 = (
    ":L l-001.impact_preds "
    "[id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]\n"
    'ip1|confidentiality|"bytes within the 30d baseline"'
    "|within|exceeds|indeterminate|exceeds\n\n"
)


def _impact_rows(*rows: str) -> str:
    head = (
        ":R impact [resolved_by|pred_ref|dim|observed|verdict|grounding|authority|as_of"
        "|reasoning]\n"
    )
    return head + "".join(rows) + "\n"


_GRADE_EXCEEDS = (
    'l-001|ip1|confidentiality|"180GB"|exceeds|telemetry-baseline|partial'
    '|2026-05-05T04:00:00Z|"3 sigma over"\n'
)
_GRADE_WITHIN = (
    'l-001|ip1|confidentiality|"2GB"|within|telemetry-baseline|partial'
    '|2026-05-05T04:00:00Z|"inside baseline"\n'
)


def test_one_impact_predicate_may_not_be_graded_two_ways() -> None:
    """`_check_impact_closure` asks only whether SOME row names the ref, so a predicate could be graded `exceeds` AND `within` and still read as resolved — letting the close pick which of its own answers to """
    errors = _errors(
        _PROLOGUE + _ONE_PRED + _LEAD + _IP1
        + _impact_rows(_GRADE_EXCEEDS, _GRADE_WITHIN)
        + _REAL_CONCLUDE + _DEFER_P1
    )
    assert any("graded exceeds, within" in e for e in errors), errors


# the two append-only wedges
#
# A rule may refuse a row only for something knowable when that row is written. Both cases
# below broke it in the same way: a document that validated CLEAN was turned into a refusal by
# a LATER legal append, naming a committed row that no write can reach back into. Each test
# runs the append sequence in order, because the defect is invisible in the end state alone —
# the final document is the only thing a single-shot test would see, and it looks like an
# ordinary refusal.

_WEDGE_HYP = _HYP_HEADER + """\
h-001|?a|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

"""
_WEDGE_HYP_TWO_PREDS = _WEDGE_HYP.replace(
    'p1|proposed_edge|"failures arrive in bursts"\n',
    'p1|proposed_edge|"failures arrive in bursts"\np2|proposed_edge|"the interval is fixed"\n',
)

_WEDGE_LEAD = (
    ":L findings [id|loop|name|target|mode|tests|system|window]\n"
    "l-001|1|probe|v-001||h-001|elastic|24h\n\n"
)
_WEDGE_CONFIRM = ":T resolutions\nh-001  null → ++   [l-001 p1 severe ⟂ e-001]\n\n"
_WEDGE_APPEND_P2 = (
    ':H h-001.preds [id|subject|claim]\np2|proposed_edge|"the interval is fixed"\n\n'
)


def test_declaring_one_more_prediction_after_a_double_plus_leaves_a_legal_next_write() -> None:
    """Rule #6 compared a growing cited set against a growing DECLARED set."""
    turn_1 = _PROLOGUE + _WEDGE_HYP + _WEDGE_LEAD + _WEDGE_CONFIRM
    assert _errors(turn_1) == []

    turn_2 = turn_1 + _WEDGE_APPEND_P2
    assert [e for e in _errors(turn_2) if "leaves p2 unmatched" in e]

    # THE REPAIR, and the whole point: the run says it is no longer claiming full coverage.
    turn_3 = turn_2 + ":T resolutions\nh-001  ++ → +   [l-001 p1 severe ⟂ e-001]\n\n"
    assert _errors(turn_3) == []


_TWO_LEADS = (
    ":L findings [id|loop|name|target|mode|tests|system|window]\n"
    "l-001|1|first|v-001||h-001|elastic|24h\n"
    "l-002|1|second|v-001||h-001|elastic|24h\n\n"
)


def test_a_null_move_off_a_double_plus_withdraws_it_and_conclude_still_asks() -> None:
    """`++ → null` is a legal weight cell and says the run stopped standing behind the grade."""
    withdrawn = _PROLOGUE + _WEDGE_HYP + _TWO_LEADS + (
        ":T resolutions\nh-001  null → ++     [l-002 p1 severe ⟂ e-001]\n\n"
    ) + _WEDGE_APPEND_P2 + (
        ":T resolutions\nh-001  ++   → null   [l-002 p1 severe ⟂ e-001]\n\n"
    )
    # The WHOLE list, not a filter: a filtered negative survives the rule being deleted.
    assert _errors(withdrawn) == []
    closing = withdrawn + (
        ':T conclude\ndisposition            benign\nsummary                "s"\n\n'
        ":T conclude.surviving [hyp_id|final_weight]\nh-001|null\n\n"
    )
    assert [e for e in _errors(closing) if "h-001.p2" in e and "abandoned" in e]


@pytest.mark.parametrize(("case", "rows", "owner"), [
    # `final_weights` reports `-` here — the l-001 bucket folds first — while the document's
    # last-written row grades `++`. #6 owns it: a `++` moved and nothing took it back.
    ("standing-double-plus-that-the-fold-calls-weaker",
     ":T resolutions\nh-001  null → -    [l-002 p1 severe \u27c2 e-001]\n\n"
     ":T resolutions\nh-001  -    → ++   [l-001 p1 severe \u27c2 e-001]\n\n",
     "leaves p2 unmatched"),
    # And the mirror: `final_weights` reports `++` while the document withdrew it. #34 owns it.
    ("withdrawn-double-plus-that-the-fold-calls-confirmed",
     ":T resolutions\nh-001  null → ++   [l-002 p1 severe \u27c2 e-001]\n\n"
     ":T resolutions\nh-001  ++   → +    [l-001 p1 severe \u27c2 e-001]\n\n",
     "h-001.p2"),
])
def test_exactly_one_rule_owns_the_hypothesis_whichever_way_the_fold_reads_it(
    case: str, rows: str, owner: str,
) -> None:
    """The #6/#34 handoff, pinned against the ordering that broke it."""
    doc = _PROLOGUE + _WEDGE_HYP_TWO_PREDS + _TWO_LEADS + rows + (
        ':T conclude\ndisposition            benign\nsummary                "s"\n\n'
        ":T conclude.surviving [hyp_id|final_weight]\nh-001|++\n\n"
    )
    errors = _errors(doc)
    # EXACTLY ONE. A filter that only asks "did the owner speak" passes when BOTH rules
    # speak, which is the failure this test is named for.
    assert len(errors) == 1, errors
    assert owner in errors[0], errors


def test_a_withdrawal_the_document_takes_back_re_arms_the_gate() -> None:
    """The repair is a WITHDRAWAL, not an exemption — re-confirming puts the claim back."""
    confirmed = _PROLOGUE + _WEDGE_HYP_TWO_PREDS + _TWO_LEADS + (
        ":T resolutions\nh-001  null → ++   [l-001 p1 severe ⟂ e-001]\n\n"
    )
    assert [e for e in _errors(confirmed) if "leaves p2 unmatched" in e]

    withdrawn = confirmed + ":T resolutions\nh-001  ++ → +   [l-002 p1 severe ⟂ e-001]\n\n"
    assert _errors(withdrawn) == []

    reconfirmed = withdrawn + ":T resolutions\nh-001  + → ++   [l-002 p1 severe ⟂ e-001]\n\n"
    assert [e for e in _errors(reconfirmed) if "leaves p2 unmatched" in e], (
        "a re-confirmed `++` is standing again and owes its predictions"
    )


def test_a_downgraded_double_plus_is_asked_for_its_prediction_at_conclude() -> None:
    """The control on the repair above — it withdraws a claim, it does not discard a prediction."""
    closing = (
        _PROLOGUE + _WEDGE_HYP + _WEDGE_LEAD + _WEDGE_CONFIRM + _WEDGE_APPEND_P2
        + ":T resolutions\nh-001  ++ → +   [l-001 p1 severe ⟂ e-001]\n\n"
        + ':T conclude\ndisposition            benign\nsummary                "s"\n\n'
        + ":T conclude.surviving [hyp_id|final_weight]\nh-001|+\n\n"
    )
    assert [e for e in _errors(closing) if "h-001.p2" in e and "abandoned" in e]


