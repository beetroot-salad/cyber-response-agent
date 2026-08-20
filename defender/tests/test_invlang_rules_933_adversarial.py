"""#933 — the arms of rules #6, #17, #23, #24 and #33 that survived mutation.

Companion to `test_invlang_rules_933.py`, kept separate because it was written against the
same five functions from the outside: each block here was derived from a MUTANT of
`validate.py` that the original file's 24 tests let through. Every test below fails on its
mutant and passes on the shipped implementation.

What survived, and therefore what these pin:

* #6 — the `++`-only trigger (a `+` may under-cite), the union across resolutions, the
  citation floor of ZERO, hypotheses born inside a lead, and the per-hypothesis scoping of
  the citation pool.
* #17 — the "next lead also screens" reading of *intermediate*, the `match`-without-
  `hypothesize` shape that is the rule's whole point, and leads past the first.
* #23 — the PARENT half of the sibling key, `ap*` claims in the signature (keyed on
  `target`/`attribute` as well as the value, because the value alone names nothing), partial
  overlap, and the empty-signature skip.
* #24 — the two arms v2.18 excised: naming a hypothesis in the conclude PROSE is not a
  discharge.
* #33 — every id shape but `a1`, every illegal target but `v-001`, the two legal targets the
  original file never wrote, rows past the first, and rows on a lead-declared hypothesis.
"""

from __future__ import annotations

import pytest

from defender.skills.invlang.validate import validate_companion

_PROLOGUE = """\
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|monitoring/internal/known-corp|172.18.0.15|
v-002|compute|monitoring/internal/known-corp|172.18.0.16|

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


# --- rule #6: prediction completeness for `++` --------------------------------------------

_TWO_PREDS = _PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
p2|proposed_edge|"no fixed interval separates the failures"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|auth-history|v-001|h-001|elastic|10m

"""


def test_a_plus_may_leave_a_prediction_unmatched() -> None:
    """`++` is the only grade this rule gates. Partial coverage is exactly what `+` means, so
    a `+` citing one of two predictions is the shape the rule EXISTS to route traffic to —
    refusing it too would leave an author with no legal way to record a half-answered fork."""
    assert _errors(_TWO_PREDS + """\
:T resolutions
h-001  null → +    [l-001 p1 moderate ⟂ e-001 :: bursty; interval not read]
""") == []


def test_the_coverage_gate_still_bites_when_a_conclude_block_is_present() -> None:
    """Rule #6 is described as the EARLY gate and #34 as the late one, which is a statement
    about when it first fires, not about it standing down later. A document that writes the
    `++` and then closes is the same defective `++`."""
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
    """The union is taken across EVERY resolution on the hypothesis, not only the `++` row —
    which is what makes the rule repairable on an append-only document. `p1` settled by a `+`
    in loop 1 is settled when loop 2 cites `p2` and grades `++`."""
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


def test_a_double_plus_citing_nothing_at_all_is_refused_by_the_coverage_gate() -> None:
    """Zero is the boundary of "partial", and the gate has to hold there too: a skip added for
    the no-citation case would hand every under-covered `++` a way through by citing less
    rather than more. `_check_strong_move_provenance` also speaks here; this asserts rule #6's
    own sentence is among what comes back, naming BOTH unmatched ids."""
    joined = _joined(_TWO_PREDS + """\
:T resolutions
h-001  null → ++   [l-001 severe ⟂ e-001 :: confirmed, no ids cited]
""")
    assert "resolution of h-001 to '++' leaves p1, p2 unmatched" in joined


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
    """`_walkers.all_hypotheses` walks `:H l-NNN.new_hypotheses` as well as the opening block,
    and a mid-run hypothesis is exactly the one whose prediction set a later loop is tempted to
    part-answer."""
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
    """The citation pool is per-hypothesis. `p2` is an id in BOTH hypotheses' namespaces, and
    a pool keyed on the document rather than the hypothesis would let `h-002`'s `p2` discharge
    `h-001`'s — the same-level sibling rollup rule #25 exists to block one level up."""
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


# --- rule #17: SCREEN structural integrity ------------------------------------------------

_SCREEN_HEADER = ":L findings [id|loop|name|target|mode|tests|system|window|screen_result]\n"


def test_a_screen_lead_followed_by_a_non_screen_lead_carries_its_result() -> None:
    """"Intermediate" is read as "the NEXT lead also screens" precisely so a screen phase that
    ends can be answered. Dropping that conjunct — any following lead makes the screen
    intermediate — refuses this, which is the ordinary shape: screen, then investigate."""
    assert _errors(_PROLOGUE + _SCREEN_HEADER + """\
l-001|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|no_match
l-002|1|auth-history|v-001|||elastic|10m|
""") == []


def test_a_matched_screen_with_no_hypothesize_block_is_the_shape_the_rule_wants() -> None:
    """Arm C's whole content is `match` AND hypotheses. The original file only ever writes
    `match` beside a `hypothesize` block, so a check that refused every `match` — the fast-path
    close the rule is written to PERMIT — reads identically to it."""
    assert _errors(_PROLOGUE + _SCREEN_HEADER + """\
l-001|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|match
""") == []


def test_a_matched_screen_beside_an_empty_hypothesize_block_is_not_an_investigation() -> None:
    """A `:H hypothesize.hypotheses` header with no rows projects the key with an empty list.
    The block enumerates nothing, so there is no second run to collide with the fast path."""
    joined = _joined(_PROLOGUE + _HYP_HEADER + "\n" + _SCREEN_HEADER + """\
l-001|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|match
""")
    assert "closes the run on the fast path" not in joined


def test_a_result_on_a_non_screen_lead_is_one_defect_not_two() -> None:
    """The mode arm and the intermediate arm are alternatives: a lead that never screened
    cannot also be an intermediate member of a screen sequence. Running both would tell the
    author to set `mode: screen` and to drop the cell for being mid-sequence at once."""
    errors = _errors(_PROLOGUE + _SCREEN_HEADER + """\
l-001|1|auth-history|v-001|||elastic|10m|no_match
l-002|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|no_match
""")
    assert len(errors) == 1
    assert "on a lead whose mode is ''" in errors[0]


def test_the_defect_is_found_on_a_lead_that_is_not_the_first() -> None:
    """Every violating fixture in the original file puts the offending lead at index 0."""
    errors = _errors(_PROLOGUE + _SCREEN_HEADER + """\
l-001|1|monitoring-probe-screen|v-001|screen||cmdb|n/a|no_match
l-002|1|auth-history|v-001|||elastic|10m|no_match
""")
    assert len(errors) == 1
    assert errors[0].startswith("lead l-002: `screen_result: no_match` on a lead whose mode is")


# --- rule #23: hypothesis fork distinctness -----------------------------------------------

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
    """The sibling group is `(parent hypothesis, anchor)`, and the parent is read off the id
    shape. Two children of DIFFERENT parents compete with their own siblings, not with each
    other, so one repeated sentence across two forks is not a pair no lead can split."""
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
    assert "sibling hypotheses h-001-a, h-001-b declare the same claims" in errors[0]


def test_two_siblings_repeating_one_attribute_prediction_are_refused() -> None:
    """`ap*` claims are in the signature — rule #35's signature is the union of both PREDICT
    blocks and #23 implements it. Same `target`, same `attribute`, same predicted value in
    different case and spacing: one observable written twice, and the pair no lead splits."""
    errors = _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"the binary is unsigned"

:H h-002.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"The binary is   unsigned."
""")
    assert len(errors) == 1
    assert "sibling hypotheses h-001, h-002 declare the same claims" in errors[0]


def test_an_attribute_prediction_keys_on_what_the_value_is_a_value_of() -> None:
    """The mirror of the pair above, and the reason `target` and `attribute` ARE in the key
    where `.preds`'s `subject` is not.

    A `.preds` claim is a sentence carrying its own subject, so filing it under two subject
    labels writes one observable twice. An `.attr_preds` claim is a VALUE — `unsigned`,
    `none`, `partial` — and the value alone says nothing about what was measured. These two
    predict the same word about two DIFFERENT objects: one lead reading the proposed parent's
    signing and the anchored vertex's signing can come back and leave exactly one standing,
    which is what makes them a fork rather than a duplicate. Keying on the bare claim fuses
    them and refuses a legal document.
    """
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"unsigned"

:H h-002.attr_preds [id|target|attribute|claim]
ap1|attached_vertex|signing|"unsigned"
""") == []


def test_siblings_that_share_one_claim_and_differ_in_another_are_distinct() -> None:
    """The floor is an IDENTICAL claim set, not an overlapping one. "At least one prediction
    whose claimed value differs" is the whole price, and a shared premise beside a differing
    one is a fork a single lead can still split.

    The shared claim is written to sort FIRST of the three, so a check that compared any single
    representative of the set — the first claim, the smallest, a hash of one element — collides
    here rather than passing by luck of ordering."""
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


def test_a_sibling_declaring_a_strict_superset_is_distinct() -> None:
    """`h-002` declares everything `h-001` does and one thing more. That extra claim is a
    prediction whose value differs — evidence against it leaves `h-001` standing — so the pair
    is splittable and legal. A containment test in place of set equality would refuse it."""
    assert _errors(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"
p2|proposed_edge|"the bursts repeat on a fixed outer period"
""") == []


def test_two_siblings_declaring_no_predictions_are_skipped() -> None:
    """Empty signatures are skipped per rule #35 — a hypothesis with no fork axis has none to
    compare, and leanness and the refutation-link rules own that shape. Without the skip both
    hypotheses key on the empty set and the pair reads as identical."""
    joined = _joined(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active
""")
    assert "declare the same claims" not in joined


def test_a_pair_of_blank_claims_is_an_empty_signature_not_a_shared_one() -> None:
    """A blank `claim` cell is refused by rule #33 and contributes NOTHING to the fork axis.
    Counting it would turn two separately-defective hypotheses into a spurious fork report on
    top of the two real defects."""
    joined = _joined(_PROLOGUE + _HYP_HEADER + """\
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??/??/??||null|active

:H h-001.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|

:H h-002.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|
""")
    assert "declare the same claims" not in joined
    assert joined.count("empty `claim`") == 2


# --- rule #24: hypothesis persistence at CONCLUDE -----------------------------------------

def test_naming_a_hypothesis_in_the_conclude_prose_is_not_a_discharge() -> None:
    """v2.18 excised "cited in the conclude block" from arm (b): `termination.rationale` is
    free text and nothing in the termination pair is a projected hypothesis reference. The
    two discharges are `--` and a `:T conclude.surviving` row, and prose naming the id is
    neither."""
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
disposition            inconclusive
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


# --- rule #33: attribute-prediction structure ---------------------------------------------

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
    """`^ap\\d+$`, anchored at BOTH ends. `matched_prediction_ids` resolves ids by equality, so
    `ap1x` is as uncitable as `a1` — a substring match on either end reads as live code while
    admitting both."""
    errors = _errors(_with_attr_preds(f'{apid}|proposed_parent|signing|"unsigned"\n'))
    assert len(errors) == 1
    assert f"row {apid!r}: an attribute prediction is numbered `ap<n>`" in errors[0]


def test_a_target_that_merely_resembles_a_legal_one_is_refused() -> None:
    """The enum is exact. `proposed` is not `proposed_parent` or `proposed_edge`, and which of
    the two it meant is the whole content of the cell."""
    errors = _errors(_with_attr_preds('ap1|proposed|signing|"unsigned"\n'))
    assert len(errors) == 1
    assert "target 'proposed' is not one of" in errors[0]


def test_all_three_declared_targets_validate_clean() -> None:
    """The original file only ever writes `proposed_parent`, so two thirds of the enum was
    pinned by nothing but the text of the error message. Dropping either of the other two
    from the tuple has to break a document, not only a sentence."""
    assert _errors(_with_attr_preds(
        'ap1|proposed_parent|signing|"unsigned"\n'
        'ap2|attached_vertex|os_release|"the host runs the pinned image"\n'
        'ap3|proposed_edge|interval|"no fixed interval separates the failures"\n'
    )) == []


def test_a_whitespace_only_claim_is_an_empty_claim() -> None:
    """A quoted run of spaces survives the parser intact — `"   "` projects as `"   "`, not as
    the empty string — so the emptiness test has to normalize. A blank-looking cell commits to
    nothing while still counting as a prediction rules #6 and #34 require settled."""
    errors = _errors(_with_attr_preds('ap1|proposed_parent|signing|"   "\n'))
    assert len(errors) == 1
    assert "row 'ap1': empty `claim`" in errors[0]


def test_a_defect_on_the_second_row_of_a_block_is_found() -> None:
    """Every defective fixture in the original file puts the bad row first and alone."""
    errors = _errors(_with_attr_preds(
        'ap1|proposed_parent|signing|"unsigned"\n'
        'ap2|the_parent|cmdline|"launched from a terminal"\n'
    ))
    assert len(errors) == 1
    assert "row 'ap2': target 'the_parent' is not one of" in errors[0]


def test_one_row_can_be_wrong_three_ways_and_says_so_three_times() -> None:
    """The three clauses are independent, and an author fixing the id should not then discover
    the target, and then the claim. One pass, one row, three sentences."""
    errors = _errors(_with_attr_preds("a1|the_parent|signing|\n"))
    assert len(errors) == 3
    assert any("an attribute prediction is numbered `ap<n>`" in e for e in errors)
    assert any("target 'the_parent' is not one of" in e for e in errors)
    assert any("empty `claim`" in e for e in errors)


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
