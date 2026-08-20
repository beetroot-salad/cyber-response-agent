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

from defender.skills.invlang.validate import validate_companion

_PROLOGUE = """\
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|monitoring/internal/known-corp|172.18.0.15|

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


# --- rule #6: prediction completeness for `++` --------------------------------------------

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
    assert "grade '+' for partial coverage" in errors[0]


def test_the_same_double_plus_citing_every_prediction_validates_clean() -> None:
    """The liveness control. One id back in the head and the document passes, so the refusal
    above is the coverage gate and not some other rule the fixture trips."""
    assert _errors(_SIX_FULL) == []


def test_an_unmatched_attribute_prediction_blocks_a_double_plus_like_a_p_star_would() -> None:
    errors = _errors(_SIX_WITH_ATTR_PRED)
    assert len(errors) == 1
    assert "leaves ap1 unmatched" in errors[0]


def test_citing_the_attribute_prediction_clears_it() -> None:
    """The control for the arm above: `ap1` in the head and the same document passes."""
    assert _errors(
        _SIX_WITH_ATTR_PRED.replace("[l-001 p1 severe", "[l-001 p1,ap1 severe")
    ) == []


# --- rule #17: SCREEN structural integrity ------------------------------------------------

_SCREEN_HEADER = ":L findings [id|loop|name|target|mode|tests|system|window|screen_result]\n"

_SCREEN_CLEAN = _PROLOGUE + _SCREEN_HEADER + """\
l-001|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|no_match
"""

_SCREEN_ON_A_NON_SCREEN_LEAD = _PROLOGUE + _SCREEN_HEADER + """\
l-001|1|auth-history|v-001|||elastic|10m|no_match
"""

_SCREEN_ON_AN_INTERMEDIATE_LEAD = _PROLOGUE + _SCREEN_HEADER + """\
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


def test_a_screen_result_on_an_intermediate_screen_lead_is_refused() -> None:
    errors = _errors(_SCREEN_ON_AN_INTERMEDIATE_LEAD)
    assert len(errors) == 1
    assert "on an intermediate screen lead" in errors[0]
    assert "l-002 screens after it" in errors[0]


def test_a_matched_screen_beside_a_hypothesize_block_is_refused() -> None:
    errors = _errors(_SCREEN_MATCH_WITH_HYPOTHESES)
    assert len(errors) == 1
    assert "`screen_result: match` closes the run on the fast path" in errors[0]


@pytest.mark.parametrize(("case", "body"), [
    # The plain shape: one screen lead, `mode: screen`, last in the run.
    ("a-lone-screen-lead", _SCREEN_CLEAN),
    # The sequence's FINAL lead may carry the result — only the earlier ones may not.
    ("the-final-lead-of-a-sequence",
     _SCREEN_ON_AN_INTERMEDIATE_LEAD.replace("|n/a|no_match", "|n/a|")),
    # A screen that did NOT match leaves the run free to hypothesize.
    ("no-match-beside-a-hypothesize-block",
     _SCREEN_MATCH_WITH_HYPOTHESES.replace("|n/a|match", "|n/a|no_match")),
])
def test_the_screen_shapes_the_rule_must_accept(case: str, body: str) -> None:
    """The liveness controls, one per arm — each is the refused document with the single cell
    that made it wrong put right."""
    assert _errors(body) == []


# --- rule #23: hypothesis fork distinctness -----------------------------------------------

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
    "v-001|compute|monitoring/internal/known-corp|172.18.0.15|",
    "v-001|compute|monitoring/internal/known-corp|172.18.0.15|\n"
    "v-002|compute|monitoring/internal/known-corp|172.18.0.16|",
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
    assert "sibling hypotheses h-001, h-002 declare the same claims" in errors[0]
    assert "failures arrive in bursts, no fixed interval between them" in errors[0]


def test_one_differing_claim_is_the_whole_price() -> None:
    """The liveness control. The refused document above differs from this one only in the text
    of `h-002`'s single claim."""
    assert _errors(_FORK_DISTINCT) == []


#: Identical claims under DIFFERENT parent classes — the mirror of `_FORK_DISTINCT`, and the
#: half that tells the two candidate rules apart. Keyed on the claim set this is a fork and is
#: refused; keyed on `parent_class` it is two distinct upstreams and passes.
_FORK_IDENTICAL_DISTINCT_CLASSES = _FORK_IDENTICAL.replace(
    "h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??|",
    "h-002|?scheduled-service-retry|v-001|runs_on|process|init-or-entrypoint|",
)


def test_the_axis_is_the_claim_set_and_not_the_parent_class() -> None:
    """The #934 guard, stated so that only the right rule can pass it.

    Two documents a classification-keyed check grades the opposite way round: siblings sharing
    an open `??/??/??` while forking on their claims are legal (#934 made the shared open tuple
    canonical), and siblings holding different classifications while declaring the same claim
    are a fork. Keying on `parent_class` refuses the first and accepts the second, so no such
    check passes both assertions.

    Replaces a substring test on the error text, which could not establish this: neither
    spelling of the rule prints the column name, so `"parent_class" not in errors` was true of
    the reversion it was written to catch.
    """
    assert _errors(_FORK_DISTINCT) == []
    errors = _errors(_FORK_IDENTICAL_DISTINCT_CLASSES)
    assert len(errors) == 1
    assert "sibling hypotheses h-001, h-002 declare the same claims" in errors[0]


def test_the_same_claims_on_different_anchors_are_not_siblings() -> None:
    assert _errors(_SAME_CLAIMS_ON_TWO_ANCHORS) == []


# --- rule #24: hypothesis persistence at CONCLUDE -----------------------------------------

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
disposition            inconclusive
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


def test_a_surviving_table_naming_every_live_hypothesis_validates_clean() -> None:
    """The liveness control — one row added to the refused document."""
    assert _errors(_SURVIVING_BOTH) == []


def test_refuting_the_hypothesis_discharges_it_instead() -> None:
    """The other arm: `--` is a discharge, so a refuted hypothesis needs no surviving row."""
    refuted = _SURVIVING_ONE_OF_TWO.replace(
        ":T conclude\n",
        ":T resolutions\n"
        "h-002  null → --   [l-001 p1 severe ⟂ e-001 :: interval is fixed to the second]\n\n"
        ":T conclude\n",
    )
    assert _errors(refuted) == []


def test_a_close_that_writes_no_surviving_table_is_out_of_scope() -> None:
    """The measured concession, pinned so it is a decision and not a regression.

    `:T conclude.surviving` is omittable by construction and an absent table defers to the
    resolution record, under which both hypotheses survive and nothing was dropped. Reading an
    absent table as an empty one would refuse seven of the eight ```invlang documents in the
    tree, both shipped goldens among them."""
    assert _errors(_TWO_LIVE_HYPOTHESES) == []


def test_an_empty_surviving_table_still_speaks() -> None:
    """`none` is the format's empty-ARRAY marker, so the table is present and claims nothing
    survived — which two live hypotheses contradict."""
    errors = _errors(_TWO_LIVE_HYPOTHESES + """\
:T conclude.surviving [hyp_id|final_weight]
none|
""")
    assert len(errors) == 2
    assert all("neither refuted nor carried into the close" in e for e in errors)


# --- rule #33: attribute-prediction structure ---------------------------------------------

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


def test_a_well_formed_attribute_prediction_validates_clean() -> None:
    """The liveness control. Every defect above is one cell away from this row."""
    assert _errors(_with_attr_preds('ap1|proposed_parent|signing|"unsigned"\n')) == []


def test_the_uniqueness_clause_is_already_owned_by_the_parser() -> None:
    """Rule #33's fourth clause needs no code in `validate.py`, and this records who has it.

    A repeat inside one `.attr_preds` block is a `_warn_repeated_ids` parse error, which is
    already error severity. A repeat ACROSS blocks never reaches the projected record —
    `_extend_by_id` keys accumulation by id — and must not be refused, since re-emitting a
    sub-block with one row added is the documented append shape.
    """
    within_one_block = _errors(_with_attr_preds(
        'ap1|proposed_parent|signing|"unsigned"\n'
        'ap1|proposed_parent|cmdline|"launched from a terminal"\n'
    ))
    assert len(within_one_block) == 1
    assert "'ap1' is declared twice in this block" in within_one_block[0]

    across_two_blocks = _errors(_with_attr_preds(
        'ap1|proposed_parent|signing|"unsigned"\n'
        "\n"
        ":H h-001.attr_preds [id|target|attribute|claim]\n"
        'ap1|proposed_parent|signing|"unsigned"\n'
        'ap2|proposed_parent|cmdline|"launched from a terminal"\n'
    ))
    assert across_two_blocks == []


# --- refutation scope: the third `p*` site, which rule #7's family never reached ----------

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
    """`:H h-NNN.refuts`'s `refutes` column is the third site naming a `p*`/`ap*`, and it
    resolved against nothing: `_check_prediction_refs` walks which ids a MOVE matched, rule
    #5's half walks the `r*` a `--` cited, and neither asks what the refutation itself claims
    to overturn."""
    errors = _errors(_REFUT_OUT_OF_SCOPE)
    assert len(errors) == 1
    assert "row 'r1' refutes prediction 'ap9'" in errors[0]
    assert "h-001 does not declare" in errors[0]


def test_a_refutation_naming_its_own_hypothesis_predictions_is_clean() -> None:
    """The liveness control, across both PREDICT namespaces — the refused document above
    differs only in `ap1` becoming `ap9`."""
    assert _errors(_REFUT_IN_SCOPE) == []


def test_a_refutation_may_not_reach_a_siblings_prediction() -> None:
    """Scoped to the declaring hypothesis for the reason `_check_prediction_refs` is. `p2` is
    declared in this document, just not by `h-001`, so a document-wide lookup passes it."""
    errors = _errors(_REFUT_CITES_A_SIBLINGS_PREDICTION)
    assert len(errors) == 1
    assert "row 'r1' refutes prediction 'p2'" in errors[0]


def test_a_refutation_on_a_hypothesis_with_no_predictions_is_left_alone() -> None:
    """A predictionless hypothesis has nothing to resolve against; refusing here would deny
    the lean shape rule #23 exempts rather than catch a defect this rule owns."""
    assert _errors(_REFUT_ON_A_PREDICTIONLESS_HYPOTHESIS) == []
