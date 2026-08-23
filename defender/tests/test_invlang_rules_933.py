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
    # The repair is spelled as a row that PARSES: bare "h-001 ++ → +" is refused by
    # `_RESOLUTION_LINE_RE` for the missing citation head, so a message offering it as a
    # literal hands the author a second refusal instead of a fix.
    assert "`h-001  ++ → +   [<lead> <ids> <severity> ⟂ <edges>]`" in errors[0]
    assert "grade it partial coverage" in errors[0]


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


@pytest.mark.parametrize(("case", "body"), [
    # The plain shape: one screen lead, `mode: screen`, last in the run.
    ("a-lone-screen-lead", _SCREEN_CLEAN),
    # Every lead of a sequence may carry its own result; see the wedge regression below.
    ("every-lead-of-a-sequence", _SCREEN_SEQUENCE_EVERY_LEAD_SCORED),
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
    assert "hypotheses h-001, h-002 anchor on v-001 and " + _SIBLING_FORK_TAG in errors[0]
    # The message names the RULE rather than the colliding claim text: two hypotheses that
    # collide here are identical over their whole signature, so quoting it back adds length
    # and not information, and the repair is a differing prediction rather than an edit to
    # the sentence quoted.
    assert "siblings must differ on at least one predicted observable" in errors[0]


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
    assert "hypotheses h-001, h-002 anchor on v-001 and " + _SIBLING_FORK_TAG in errors[0]


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


# --- review follow-ups: the holes the armed rules left open --------------------------------
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
    """The CLOSURE gates read "is this document closing" off a non-empty `conclude`, and
    `_project_conclude_scalars` drops an unrecognized key in silence — so a close keyed
    entirely on keys the projection does not carry stood #13/#24/#26/#31/#34 all down with no
    diagnostic. A `:T conclude` that lands nothing is now its own parse refusal."""
    errors = _errors(_PROLOGUE + _ONE_CONTRACT + _LEAD + """\
:T conclude
handoff_notes          "sent to tier 2"
""")
    assert any("`:T conclude` recorded nothing" in e for e in errors)


def test_a_lone_deferral_table_does_not_arm_the_closure_gates() -> None:
    """`:T conclude.deferred_preds` carrying the SKILL-taught `none` marker opens the
    `conclude` bucket, which a truthiness test read as a close in progress — refusing a
    mid-run write for every commitment the run had not reached CONCLUDE on yet."""
    assert _errors(_PROLOGUE + _ONE_CONTRACT + _LEAD + """\
:T conclude.deferred_preds [prediction_ref|rationale]
none
""") == []


def test_a_quoted_deferral_reference_still_defers() -> None:
    """The ref cell is matched verbatim against `h-001.ac1`, so an unquoted read made a
    quoted row defer nothing — while the refusal told the author to add the row they had
    just written."""
    assert _errors(_PROLOGUE + _ONE_CONTRACT + _LEAD + """\
:T resolutions
h-001  null → +    [l-001 p1 mild ⟂ e-001 :: bursty]

:T conclude
disposition            inconclusive
confidence             low
summary                "s"

:T conclude.surviving [hyp_id|final_weight]
h-001|+

:T conclude.deferred_authz [contract_ref|rationale]
"h-001.ac1"|"authority anchor unavailable"
""") == []


def test_quoted_cells_of_a_closed_vocabulary_are_read_unquoted() -> None:
    """`target`, `dim` and `advance_to` are compared against closed sets by rules #33, #29
    and #18. Quoting a whole cell is the format's own habit and their neighbours are already
    unquoted, so a uniformly-quoted row named legal values and was refused for the quotes."""
    assert _errors(_PROLOGUE + _ONE_HYPOTHESIS + """\
:H h-001.attr_preds [id|target|attribute|claim]
ap1|"proposed_parent"|signing|"UNSIGNED"

""" + _LEAD + """\
:L l-001.lead_preds [id|if|read_as|advance_to]
lp1|"cadence matches"|"periodic tooling"|"CONCLUDE"

:L l-001.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]
ip1|"confidentiality"|"bytes within baseline"|within|exceeds|indeterminate|exceeds
""") == []


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
    """Rule #33 armed the id-shape check on `.attr_preds` and left `.preds` unchecked. A
    resolution head reads only `p*`/`ap*`/`r*`, so an id outside the namespace can be cited
    by nothing — and rule #34 then refuses the close with a repair the grammar cannot
    express."""
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
    """`_check_authz_contract_ids` permits two declarers of one `ac*` when one is refuted —
    which is exactly the shape this rule covers and the benign gate does not. A bare-id
    discharge set let the live hypothesis's row settle the refuted one's unrelated question,
    the automatic discharge rule #26 says it does not grant."""
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
    """Two screen phases in different loops, each carrying its own result.

    Written against the intermediate arm's same-loop term, which v2.22 struck along with the
    rest of that arm — so nothing here can refuse this document any more, and the test is kept
    only as a shape the rule must keep accepting. The refusal it used to pin is gone for good;
    see `test_appending_the_next_screen_of_a_sequence_leaves_the_committed_one_alone`."""
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


# --- #940 review regressions ---------------------------------------------------------------
#
# Each of these was a hole a rule armed in this change left open, or a legal document one of
# them refused. They sit here rather than in their own file so they share the one prologue —
# the same reason the blocks above do.

_CLOSE_INCONCLUSIVE = """\
:T conclude
disposition            inconclusive
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
    """The `after` cell is an unvalidated `\\S+` and nothing checks it against
    `WEIGHT_BUCKETS`, so a "moved unless null" test made a misspelling the CHEAPEST row in the
    language: it discharged rule #34, skipped rule #4 (which fires on `STRONG_WEIGHTS`) and
    skipped rule #6 (which fires on `++`), where the honest `null` was refused."""
    errors = _errors(_PROLOGUE + _ONE_PRED + _LEAD + _moved(after) + _CLOSE_INCONCLUSIVE)
    assert any("h-001.p1" in e and "declared and then abandoned" in e for e in errors), errors


@pytest.mark.parametrize("after", ["+", "-"])
def test_a_real_weight_still_settles_the_prediction_it_cites(after: str) -> None:
    """The liveness control: closing the off-vocabulary hole must not close the door on a
    resolution that really moved the hypothesis."""
    assert _errors(_PROLOGUE + _ONE_PRED + _LEAD + _moved(after) + _CLOSE_INCONCLUSIVE) == []

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


@pytest.mark.parametrize("fulfills", ["ac1", "h-001.ac1"])
def test_either_fulfills_spelling_discharges_the_contract(fulfills: str) -> None:
    """Spec rule #7 blesses the qualified `h-{id}.ac{n}`; `skills/invlang/SKILL.md` teaches the
    bare `ac<n>`. Rule #26 indexed the raw cell and looked it up bare, so the spelling the spec
    calls correct refused a close for a contract the run had answered."""
    assert _errors(
        _PROLOGUE + _LONE_CONTRACT + _LEAD + _authz_row(fulfills) + _CLOSE_INCONCLUSIVE
    ) == []


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

""" + _LEAD + _authz_row("h-001.ac1") + _CLOSE_INCONCLUSIVE)
    assert [e for e in errors if "h-002.ac1" in e], errors
    assert not [e for e in errors if "h-001.ac1" in e], errors


def test_twin_contracts_under_one_anchor_kind_are_discharged_by_nothing() -> None:
    """`_authz_contract_error` states it first: a `:R authz` row names only the contract id, so
    when two hypotheses declare one `ac*` under the SAME anchor kind no row can be attributed
    to either. Reading the shared kind as a discharge let one row close two questions — and
    `_check_authz_contract_ids` exempts the collision when one side is refuted, which is
    exactly the shape rule #26 covers and the benign gate does not."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?a|v-001|runs_on|process|??/??/??||null|active
h-002|?b|v-001|runs_on|process|??/??/??||--|refuted

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"may this identity authenticate here"|escalate|escalate

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"a different question under the same anchor"|escalate|escalate

""" + _LEAD + _authz_row("ac1") + _CLOSE_INCONCLUSIVE)
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


def test_the_twin_repair_the_message_names_actually_discharges_both() -> None:
    """The control on the message above. A repair a refusal offers has to clear it — otherwise
    the only exit left is a `:T conclude.deferred_authz` row recording that the run never
    answered a question it did answer."""
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?a|v-001|runs_on|process|??/??/??||null|active
h-002|?b|v-001|runs_on|process|??/??/??||--|refuted

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"may this identity authenticate here"|escalate|escalate

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"a different question under the same anchor"|escalate|escalate

""" + _LEAD + _authz_row("h-001.ac1") + _authz_row("h-002.ac1") + _CLOSE_INCONCLUSIVE) == []


@pytest.mark.parametrize(
    ("rationale", "discharges"),
    [('"telemetry never arrived"', True), ("none", False), ("n/a", False), ('""', False)],
)
def test_the_empty_marker_is_not_a_deferral_rationale(
    rationale: str, discharges: bool
) -> None:
    """`none` / `n/a` is the format's own word for "nothing to say", taught two paragraphs from
    the deferral tables as the empty-TABLE marker. A bare-truthiness test made it a discharge —
    one word clearing the only guard the escape hatch has, while the honest empty cell is
    refused."""
    errors = _errors(
        _PROLOGUE + _ONE_PRED + _LEAD + _CLOSE_INCONCLUSIVE
        + f":T conclude.deferred_preds [prediction_ref|rationale]\nh-001.p1|{rationale}\n\n"
    )
    assert (errors == []) is discharges, errors


@pytest.mark.parametrize(
    "block",
    [
        ":L l-001.lead_preds [id|if|read_as|advance_to]\nnone\n\n",
        ":L l-001.impact_preds "
        "[id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]\nnone\n\n",
    ],
)
def test_a_lone_none_row_is_the_empty_table_marker_on_a_lead_plan_block(block: str) -> None:
    """`_row_cells` pads a lone marker to the block width, so without the filter every sibling
    sub-table applies it landed as a record whose id IS `none` — and rules #18 / #29 emitted
    four and seven refusals apiece, none of which said the author wrote the marker."""
    from defender.skills.invlang.parser import parse_dense_companion

    body = _PROLOGUE + _ONE_PRED + _LEAD + block
    companion, warnings = parse_dense_companion(_doc(body))
    assert warnings == []
    assert "predictions" not in companion["findings"][0]
    assert "impact_predictions" not in companion["findings"][0]
    assert _errors(body) == []


def test_a_matched_screen_followed_by_a_second_screen_lead_is_clean() -> None:
    """A `match` with a later screen lead beside it, and no `hypothesize` block: nothing to
    refuse.

    This pinned the `match` carve-out inside the intermediate arm — a matched screen ENDS the
    run, so refusing its row for a follower that exists only as an append-only `:L findings`
    declaration left no legal repair. v2.22 struck the arm and the carve-out with it, so the
    document is clean for a simpler reason and no mutation of the surviving arms can fail
    this. Kept as a liveness shape, not as coverage."""
    assert _errors(_PROLOGUE + """\
:L findings [id|loop|name|target|mode|screen_result|tests|system|window]
l-001|0|first-phase-screen|v-001|screen|match||elastic|10m
l-002|0|second-phase-screen|v-001|screen|||elastic|10m
""") == []


def test_a_quoted_lead_name_resolves_an_advance_to() -> None:
    """`_lead_pred_row` unquotes `advance_to` and `_lead_header_record` does not unquote
    `name`, so a document quoting its cells uniformly was refused with a message listing the
    destination among the names it said did not match — and the declaring `:L findings` row is
    committed, so the refusal had no repair."""
    assert _errors(_PROLOGUE + _ONE_PRED + """\
:L findings [id|loop|name|target|tests|system|window]
l-001|1|"auth history"|v-001|h-001|elastic|10m
l-002|1|"cadence check"|v-001|h-001|elastic|10m

:L l-001.lead_preds [id|if|read_as|advance_to]
lp1|"failures cluster in the last 10 min"|"anomalous spike"|"cadence check"
""") == []


def test_a_uniformly_quoted_impact_resolution_is_read_as_written() -> None:
    """`_impact_pred_row` unquotes the DECLARING side and `_canonicalize_resolution_row`
    unquotes nothing, so the same quoting on the grading row drew three refusals at once — two
    off-enum and one unresolvable `pred_ref` — for values all spelled correctly."""
    assert _errors(_PROLOGUE + _ONE_PRED + _LEAD + _IMPACT_QUOTED) == []


def test_a_second_conclude_block_of_unrecognized_keys_does_not_refuse_the_close() -> None:
    """`_project_conclude_scalars` refuses to warn on an unrecognized flat key because "the
    lessons corpus can instruct conclude rows this projection does not carry, and
    `learning/core/persist.py` dead-letters a run whose investigation.md fails validation".
    A per-BLOCK "recorded nothing" flag turned exactly that write into the refusal that comment
    forbids, on a document whose close is already fully recorded."""
    assert _errors(
        _PROLOGUE + _ONE_PRED + _LEAD + _CLOSE_INCONCLUSIVE
        + ":T conclude\nescalation_target      soc-tier2\n\n"
        + ":T conclude.deferred_preds [prediction_ref|rationale]\n"
          'h-001.p1|"telemetry never arrived"\n\n'
    ) == []


def test_a_conclude_block_that_really_records_nothing_still_warns() -> None:
    """The liveness control for the test above: a close that projects to `{}` stands every
    CONCLUDE rule down, and has to be loud."""
    assert any(
        "recorded nothing" in e
        for e in _errors(
            _PROLOGUE + _ONE_PRED + _LEAD
            + ":T conclude\nescalation_target      soc-tier2\n\n"
        )
    )


# --- #940 sweep regressions ------------------------------------------------------------------
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


def test_a_lesson_keyed_conclude_block_is_accepted_in_either_order() -> None:
    """The "recorded nothing" verdict is about the DOCUMENT, so it cannot depend on where in
    the document the empty block sits. Decided inline it was scoped to the blocks projected
    BEFORE this one — a PREFIX — so the pair it exists to protect passed in one order and was
    refused in the other, and on a document already holding such a block every later append
    re-derived the refusal against a block nobody may edit."""
    base = _PROLOGUE + _ONE_PRED + _LEAD
    assert _errors(base + _REAL_CONCLUDE + _DEFER_P1 + _LESSON_CONCLUDE) == []
    assert _errors(base + _LESSON_CONCLUDE + _REAL_CONCLUDE + _DEFER_P1) == []


def _screen_row(mode: str, result: str) -> str:
    return (
        ":L findings [id|loop|name|target|mode|screen_result|tests|system|window]\n"
        f"l-001|1|probe|v-001|{mode}|{result}|h-001|elastic|10m\n\n"
    )


def test_rule_17_reads_mode_and_screen_result_the_same_way() -> None:
    """`screen_result` went through the unquoting `_cell` and `mode` stayed raw, so a
    uniformly quoted `:L findings` row was refused for a `mode` it spells correctly — with
    advice ("set `mode: screen`") the author had already followed, on an append-only row that
    cannot be rewritten."""
    assert _errors(_PROLOGUE + _screen_row("screen", "no_match") + _ONE_PRED) == []
    assert _errors(_PROLOGUE + _screen_row('"screen"', '"no_match"') + _ONE_PRED) == []


# --- #943 review regressions -----------------------------------------------------------------
#
# The quoting sweep the `target` fix started, finished across the rest of the row, plus the two
# normalization holes the fork rule was left with. Each case below validated CLEAN (or was
# refused with advice the author had already followed) before this block existed.


def test_every_quotable_cell_of_a_prediction_row_is_read_unquoted() -> None:
    """The parser unquoted `target` and `claim` and left `id` and `attribute` raw, so the two
    rules that COMPARE those cells disagreed with the two that do not.

    Failing closed on `id`: `_check_prediction_id_namespace` and rule #33's id-shape arm refuse
    a uniformly quoted row for a namespace it is already inside, on a `:H` row that is
    immutable — the refusal has no repair. `refutes` is the third: quoted whole, the cell
    splits its own quote characters INTO the ids and every one of them is reported undeclared
    beside a list that contains it.
    """
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
"p1"|"proposed_edge"|"failures arrive in bursts"
"p2"|"proposed_edge"|"no fixed interval separates the failures"

:H h-001.attr_preds [id|target|attribute|claim]
"ap1"|"proposed_parent"|"signing"|"UNSIGNED"

:H h-001.refuts [id|refutes|claim]
"r1"|"p1,p2"|"the series is cadenced"
""") == []


def test_a_quoted_attribute_cell_does_not_rescue_a_duplicate_fork() -> None:
    """Failing OPEN, the other half of the same asymmetry. `attribute` is two thirds of the
    `.attr_preds` fork key with `target`, so quoting it on one sibling gave the pair two
    signatures for one observable and rule #23 stood down."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"UNSIGNED"

:H h-002.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|"signing"|"UNSIGNED"
""")
    assert len(errors) == 1
    assert _SIBLING_FORK_TAG in errors[0]


def test_a_quoted_loop_cell_still_projects_as_the_integer_it_spells() -> None:
    """`_lead_header_record` only `int()`s a loop cell that parses, and the `int()` sits under
    `contextlib.suppress` — so before the unquoting sweep `"1"` survived as a STRING that
    equals no other lead's loop. Observed on the projection rather than through a rule: rule
    #17 no longer reads `loop`, and `_check_loop_close` is the reader that still does."""
    from defender.skills.invlang.parser import parse_dense_companion
    body, _warnings = parse_dense_companion(_doc(_PROLOGUE + """\
:L findings [id|loop|name|target|mode|screen_result|tests|system|window]
l-001|"1"|first|v-001|screen|||elastic|10m
"""))
    assert [lead.get("loop") for lead in body["findings"]] == [1]


def test_a_refutation_that_overturns_nothing_writes_the_empty_array_marker() -> None:
    """`none` is the format's empty-ARRAY spelling, honoured for `:T conclude.surviving` and
    `:T shelved`. Read as a prediction id it made "this refutation overturns nothing" an
    error-severity refusal of an immutable row."""
    assert _errors(_PROLOGUE + _ONE_HYPOTHESIS + """\
:H h-001.refuts [id|refutes|claim]
r1|none|"the series is cadenced"
""") == []


def test_a_claim_that_normalizes_to_nothing_is_an_empty_claim() -> None:
    """`_predicted_observables` drops a claim normalizing to `""` from the fork signature on
    the stated grounds that "rule #33 already refuses the row" — which was true of a BLANK cell
    and false of `"."`, `"..."` or `"''"`. Two siblings could carry one placeholder each and
    pass both rules: #33 because the cell is non-blank, #23 because the signature is empty."""
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


def test_a_quote_outside_the_full_stop_normalizes_like_one_inside_it() -> None:
    """The leading-decimal fix strips quotes ONCE and before the full stop, where the spelling
    it replaced stripped a mixed set until both ends were clean. A quote sitting outside the
    sentence period is only exposed after the stop comes off, so British and American quote
    punctuation of ONE claim keyed as two — and the fork rule stood down."""
    from defender.skills.invlang.validate import _normalized_claim

    assert _normalized_claim("the unit is 'enabled'.") == _normalized_claim(
        "the unit is 'enabled.'"
    )
    # The property the rewrite bought, re-pinned so neither direction can be traded for the
    # other: a LEADING full stop is never sentence punctuation.
    assert _normalized_claim(".5 sigma above baseline") != _normalized_claim(
        "5 sigma above baseline"
    )


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


def test_the_matched_screen_arm_names_the_lead_that_screened() -> None:
    """The liveness control for the arm above — with `mode: screen` on the row, the fast-path
    refusal is exactly what comes back."""
    errors = _errors(_PROLOGUE + _ONE_HYPOTHESIS + """\
:L findings [id|loop|name|target|mode|screen_result|tests|system|window]
l-001|1|probe-screen|v-001|screen|match|h-001|cmdb|n/a
""")
    assert len(errors) == 1
    assert "closes the run on the fast path" in errors[0]


def test_a_whitespace_only_attribute_is_the_parse_error_rule_33_says_it_is() -> None:
    """Rule #33 leaves `attribute` to the parser on the stated grounds that `_require` tests
    truthiness — which held for a bare empty cell and not for a quoted run of spaces, since
    `_require` saw the cell before anything unquoted it. The row then declared an `ap1` that
    rules #6/#34 require settled while naming no attribute, and degraded rule #23's fork key
    to `proposed_parent.=unsigned`."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|"  "|"unsigned"
""")
    assert len(errors) == 1
    assert "attr_preds row missing id/target/attribute" in errors[0]


# --- #943 second-review regressions ----------------------------------------------------------
#
# Nine more inputs the first arming pass let through, in the order the rules are declared
# above. Every one is the SAME rule one input further out, so each carries the control that
# says the rule is still the thing being measured.


def test_a_leading_full_stop_does_not_split_a_fork() -> None:
    """`_normalized_claim` stopped eating a LEADING full stop so `".5σ above baseline"` keeps
    its decimal point. Kept for EVERY leading stop, the correction fails open the other way:
    one typed character makes an observable a sibling already spelled normalize apart, and
    rule #23 retires on a pair that forks on nothing."""
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


def test_a_decimal_point_still_forks_a_pair_that_forks_on_one() -> None:
    """The control for the arm above, and the reason the strip is conditional rather than
    gone: the tenfold-threshold pair the leading-dot fix was written for still validates."""
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?a|v-001|runs_on|process|??/??/??||null|active
h-002|?b|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|".5 sigma above baseline"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"5 sigma above baseline"
""") == []


def test_an_off_vocabulary_grade_is_refused_rather_than_ignored() -> None:
    """The `after` cell was an unvalidated `\\S+`, and every weight-keyed gate is a membership
    test — so a misspelled grade skipped the strong-move provenance gate and the `++` coverage
    gate at once, where the honest `++` is refused for what it leaves open. A typo was
    strictly cheaper than telling the truth."""
    for token in ("confirmed", "+++"):
        errors = _errors(_SIX_PARTIAL.replace("null → ++", f"null → {token}"))
        assert len(errors) == 1, token
        assert f"after {token!r}, which is not a weight" in errors[0]


def test_a_weight_declared_at_birth_is_checked_against_the_same_list() -> None:
    """The `:H` cell is the other write site for a weight, and `_hypothesis_record` stores
    anything that is not `null` verbatim."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?a|v-001|runs_on|process|??/??/??||strongly-confirmed|active
""")
    assert len(errors) == 1
    assert "weight 'strongly-confirmed' is not a weight" in errors[0]


def test_a_confirmation_resting_on_a_dead_refutation_is_not_forced_to_lie() -> None:
    """`_check_strong_move_provenance` reads `matched_refutation_ids` as the same half of a
    strong move's provenance that `matched_prediction_ids` is; rule #6 read only the `p*`
    side, so a `++` whose evidence is a refutation that failed to materialize had exactly one
    spelling that cleared the gate — citing the prediction as MATCHED, which is a claim the
    run did not make."""
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


def test_the_empty_cell_marker_is_not_a_screen_verdict() -> None:
    """`n/a` in an unused trailing column is the shipped convention
    (`defender/examples/example-b-parallel-iam-cmdb.md` writes it in `window`), so reading it
    as a verdict refuses a row that says "nothing here" and offers "drop the cell" as the
    repair for a cell that already means that."""
    assert _errors(_PROLOGUE + _SCREEN_HEADER + """\
l-001|1|source-screen|v-001|screen||cmdb|n/a|no_match
l-002|2|auth-history|v-001|||elastic|10m|n/a
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


def test_a_screen_cell_the_author_capitalized_is_read_as_the_value_it_spells() -> None:
    """Neither `mode` nor `screen_result` is in any `_check_vocab_*` arm, so a case difference
    went uncorrected in both directions: `Screen` was refused for a mode the author spelled
    correctly, and `Match` slipped past the fast-path arm in silence."""
    assert _errors(_PROLOGUE + _SCREEN_HEADER + """\
l-001|1|source-screen|v-001|Screen||cmdb|n/a|no_match
""") == []
    errors = _errors(_PROLOGUE + _ONE_HYPOTHESIS + _SCREEN_HEADER + """\
l-001|0|probe-screen|v-001|screen||cmdb|n/a|Match
""")
    assert len(errors) == 1
    assert "closes the run on the fast path" in errors[0]


def test_a_padded_prediction_id_is_the_p_star_it_spells() -> None:
    """`.preds` and `.refuts` unquoted their `id` and stopped there, while `.attr_preds`
    stripped as well — so `" p1 "` was refused for its padding on an immutable `:H` row while
    `" ap1 "` beside it was accepted, and `"r1 "` parsed clean and then refused the `--` that
    cited it with "does not declare (declares: r1 )"."""
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?a|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
" p1 "|proposed_edge|"failures arrive in bursts"

:H h-001.refuts [id|refutes|claim]
"r1 "|" p1 "|"a fixed interval separates them"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001|elastic|10m

:T resolutions
h-001  null → --   [l-001 r1 severe ⟂ e-001 :: refuted]
""") == []


def test_a_quoted_tests_cell_still_names_the_ids_it_lists() -> None:
    """`:L findings`' `tests` column reached `_split_csv` raw, so a quoted whole cell split
    the quote characters INTO the ids. Both readers gate on id shape and DROP what does not
    match, so the lead's hypothesis attribution and its commitment scoping vanished with no
    diagnostic — the fail-OPEN half of the defect `refutes` was fixed for."""
    errors = _errors(_PROLOGUE + _ONE_HYPOTHESIS + """\
:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|"h-999,p9"|elastic|10m
""")
    assert any("tests undeclared hypothesis 'h-999'" in e for e in errors)


def test_a_quoted_surviving_row_carries_the_hypothesis_into_the_close() -> None:
    """The sibling of the arm above, on the table rule #24 reads. Quoted, the refusal listed
    the id it claimed was missing."""
    assert _errors(_PROLOGUE + _ONE_HYPOTHESIS + _LEAD + """\
:T conclude.surviving [hyp_id|final_weight]
"h-001"|null
""") == []


def test_an_attribute_prediction_target_is_read_case_insensitively() -> None:
    """`_predicted_observables` lowercases `target` into rule #23's fork key while rule #33
    compared it raw — one cell read as the canonical target by one rule and an illegal one by
    the other, in the same pass over the same row."""
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?a|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|Proposed_Parent|signing|"unsigned"
""") == []


def test_a_quoted_anchor_still_puts_two_siblings_in_one_fork_group() -> None:
    """`:H`'s header row was the one projector the quoting sweep skipped, and `attached_to` is
    half of rule #23's sibling-group key — so a uniformly quoted anchor equalled no other
    sibling's and the pair dropped out of the group in silence, refusing nothing."""
    def fork(anchor2: str, weight2: str) -> str:
        return _PROLOGUE + _HYP_HEADER + f"""\
h-001|?a|v-001|runs_on|process|??/??/??||null|active
h-002|?b|{anchor2}|runs_on|process|??/??/??||{weight2}|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
"""
    errors = _errors(fork('"v-001"', "null"))
    assert len(errors) == 1
    assert _SIBLING_FORK_TAG in errors[0]
    # `weight` is the other compared cell on that row: quoted, `"--"` was not REFUTED_WEIGHT,
    # so the hypothesis the run refuted read as live and the retired pair was refused anyway.
    assert _errors(fork("v-001", '"--"')) == []


def test_a_prediction_the_annotation_negates_does_not_cover_a_confirmation() -> None:
    """`matched_prediction_ids` means "this lead TESTED the id" and files `¬p2` beside `p1`
    (`test_invlang_parser.test_resolution_negated_iff_literal_still_attributes`). Rule #6 asks
    whether the prediction CAME IN, and the two answers are opposite on that token — so a `++`
    cleared the coverage gate on an annotation saying one of its predictions did not."""
    errors = _errors(_PROLOGUE + _ONE_HYPOTHESIS + _LEAD + """\
:T resolutions
h-001  null → ++   [l-001 severe ⟂ e-001 :: bursty but the interval was fixed ⟺ p1 ∧ ¬p2]
""")
    assert len(errors) == 1
    assert "leaves p2 unmatched" in errors[0]


def test_an_annotation_naming_one_id_does_not_discard_the_heads_list() -> None:
    """`matched_pred_ids = iff_pred_ids or head_ids` was a REPLACEMENT, so one iff literal in
    the `::` segment — otherwise free prose — wiped the head's own citations and rule #6
    refused a `++` for leaving unmatched a prediction the row visibly cites."""
    assert _errors(_PROLOGUE + _ONE_HYPOTHESIS + _LEAD + """\
:T resolutions
h-001  null → ++   [l-001 p1,p2 severe ⟂ e-001 :: bursts observed ⟺ p1]
""") == []

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
    """`_check_impact_closure` asks only whether SOME row names the ref, so a predicate could
    be graded `exceeds` AND `within` and still read as resolved — letting the close pick which
    of its own answers to be measured against, which is the after-the-fact choice the
    pre-registration axis exists to prevent. The authz axis already refuses the analogous
    disagreement."""
    errors = _errors(
        _PROLOGUE + _ONE_PRED + _LEAD + _IP1
        + _impact_rows(_GRADE_EXCEEDS, _GRADE_WITHIN)
        + _REAL_CONCLUDE + _DEFER_P1
    )
    assert any("graded exceeds, within" in e for e in errors), errors


def test_one_impact_predicate_graded_once_is_clean() -> None:
    """The liveness control: agreement is the rule, not a ban on grading."""
    assert _errors(
        _PROLOGUE + _ONE_PRED + _LEAD + _IP1
        + _impact_rows(_GRADE_EXCEEDS)
        + _REAL_CONCLUDE + _DEFER_P1
    ) == []


# --- the two append-only wedges -------------------------------------------------------------
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
    """Rule #6 compared a growing cited set against a growing DECLARED set.

    Turn 1 commits the `++` covering the one prediction h-001 declared — clean. Turn 2 appends
    a second prediction, which is the documented append shape and cannot be un-written, and the
    committed `++` retroactively stopped covering its own hypothesis. Both repairs the message
    offered were unreachable: citing p2 asserts an untested prediction came in, and the
    downgrade did nothing because the rule keyed on the FIRST `++` a row ever wrote.
    """
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


def test_the_withdrawal_is_read_off_the_row_and_not_off_the_lead_order() -> None:
    """The repair has to work whichever lead the withdrawing row is attributed to.

    Keyed on `_walkers.final_weights` it did not. That walker resolves last-move-wins by
    LEAD-DECLARATION order rather than append order, so a `++` on the later-declared lead beat
    a withdrawal on the earlier one and the advertised repair was a silent no-op — on every
    document with more than one lead, which is every real one. Both attributions below are the
    same document to an author and have to be the same document here.
    """
    base = _PROLOGUE + _WEDGE_HYP + _TWO_LEADS + (
        ":T resolutions\nh-001  null → ++   [l-002 p1 severe ⟂ e-001]\n\n"
    ) + _WEDGE_APPEND_P2
    assert [e for e in _errors(base) if "leaves p2 unmatched" in e]
    for lead in ("l-001", "l-002"):
        withdrawn = base + (
            f":T resolutions\nh-001  ++ → +   [{lead} p1 severe ⟂ e-001]\n\n"
        )
        assert _errors(withdrawn) == [], f"withdrawal attributed to {lead} was not honoured"


def test_a_null_move_off_a_double_plus_withdraws_it_and_conclude_still_asks() -> None:
    """`++ → null` is a legal weight cell and says the run stopped standing behind the grade.

    Read through `final_weights` it was worse than a withdrawal: that walker reads `after` RAW
    where `_confirmed_at` reads it through the closed `_resolution_move`, so the hypothesis was
    neither confirmed-and-standing nor refuted and rule #6 simply switched off — a document
    main refuses. It is a withdrawal like any other, and #34 is what collects afterwards.
    """
    withdrawn = _PROLOGUE + _WEDGE_HYP + _TWO_LEADS + (
        ":T resolutions\nh-001  null → ++     [l-002 p1 severe ⟂ e-001]\n\n"
    ) + _WEDGE_APPEND_P2 + (
        ":T resolutions\nh-001  ++   → null   [l-002 p1 severe ⟂ e-001]\n\n"
    )
    assert not [e for e in _errors(withdrawn) if "leaves p2 unmatched" in e]
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
    """The #6/#34 handoff, pinned against the ordering that broke it.

    Both documents are ones `_walkers.final_weights` reads BACKWARDS, and they fail in opposite
    directions: keyed on the fold, the first was owned by neither rule and the second was
    refused by #6 for a claim the document had already withdrawn. The withdrawal marker is a
    property of ONE ROW, so neither case depends on where that row sits.
    """
    doc = _PROLOGUE + _WEDGE_HYP_TWO_PREDS + _TWO_LEADS + rows + (
        ':T conclude\ndisposition            benign\nsummary                "s"\n\n'
        ":T conclude.surviving [hyp_id|final_weight]\nh-001|++\n\n"
    )
    errors = _errors(doc)
    assert [e for e in errors if owner in e], errors


def test_a_downgraded_double_plus_is_asked_for_its_prediction_at_conclude() -> None:
    """The control on the repair above — it withdraws a claim, it does not discard a
    prediction. Rule #34 excludes what #6 owns so the two cannot both refuse one hypothesis;
    keyed on "ever `++`" it would also exclude a downgraded one, and p2 would be asked about by
    NEITHER rule. `_confirmed_and_standing` is the single predicate that splits them.
    """
    closing = (
        _PROLOGUE + _WEDGE_HYP + _WEDGE_LEAD + _WEDGE_CONFIRM + _WEDGE_APPEND_P2
        + ":T resolutions\nh-001  ++ → +   [l-001 p1 severe ⟂ e-001]\n\n"
        + ':T conclude\ndisposition            benign\nsummary                "s"\n\n'
        + ":T conclude.surviving [hyp_id|final_weight]\nh-001|+\n\n"
    )
    assert [e for e in _errors(closing) if "h-001.p2" in e and "abandoned" in e]


def test_appending_the_next_screen_of_a_sequence_leaves_the_committed_one_alone() -> None:
    """Rule #17's intermediate arm asked the author to know, when writing a screen lead,
    whether another screen would follow it in the same loop.

    Turn 1 commits a screen lead that falls through — clean, and it is the last screen so far.
    Turn 2 appends the next narrowing screen, which is the sequence the rule's own docstring
    describes, and turn 1's committed `:L findings` cell became an error naming a row no write
    can withdraw. The arm is gone; the two arms whose defects ARE knowable at write time stay,
    and the tests above hold them.
    """
    turn_1 = _PROLOGUE + _SCREEN_HEADER + (
        "l-001|0|source-screen|v-001|screen||cmdb|n/a|no_match\n"
    )
    assert _errors(turn_1) == []

    turn_2 = turn_1 + "l-002|0|cadence-screen|v-001|screen||elastic|24h|no_match\n"
    assert _errors(turn_2) == []
