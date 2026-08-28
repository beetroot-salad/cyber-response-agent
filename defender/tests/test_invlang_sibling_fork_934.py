"""#934 — the fork shape §Sibling-fork uniqueness now asks for stays writable.

The SKILL used to demand a **topological** difference between sibling hypotheses
(`parent_type`/`parent_class`/`attached_to`/`rel`) while its own worked example forked on
the `?name` and the predictions alone. Agents resolved the contradiction by manufacturing a
class tuple: every tuple-class sibling pair in the corpus differed in all three slots, so a
CMDB row placing the source refuted a story about *rate* and the true world — internal AND
brute-force — was never a cell in the model.

The rewrite makes the predicted observable the distinctness axis and leaves the slots the
alert has not settled `??`, which means two live siblings now legitimately share
`parent_class`. Rule #23 ships here as the check that says so — the textual floor over the
declared claims, and NOT the classification-keyed spelling it was specified under, which would
have refused exactly the well-formed fork below and passed the malformed one. It also absorbs
#35 (sibling prediction divergence), the OTHER unimplemented spec rule that stated this same
check on the prediction signature; the two became one the moment #934 moved #23's axis.

Two halves, so two kinds of test: the shape stays writable (the `??` fork, and a benign close
over it), and the rule fires where it should without firing where the document is merely
mid-composition.
"""

from __future__ import annotations

from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import _SIBLING_FORK_TAG, validate_companion

#: Siblings that share every topological column and an OPEN `parent_class`, forking on one
#: predicted observable apiece — the cadence a single lead over the failure series splits.
_OPEN_PARENT_FORK = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/??/??|172.18.0.15|knowledge=partial

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?credential-guessing|v-001|runs_on|process|??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts, no fixed interval between them"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures repeat on a fixed interval"
```
"""

#: The same fork run to a `benign` close: the cadence lead grades h-002 up and h-001 out, the
#: source's own class cell is resolved by the CMDB lead, and the two proposed parents stay
#: `??`. A proposed parent is not an observed vertex, so its open slot must not reach the
#: benign gate — the SKILL says so under §Open questions, and a run that had to name one to
#: close would be back to minting tuples. Graded and closed on purpose rather than left with
#: two live null-weight siblings: the fixture is what a reader copies as the shape, so it has
#: to be a document a real run could emit, not the smallest one this gate happens to pass.
_BENIGN_CLOSE_OVER_OPEN_PARENTS = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/??/??|172.18.0.15|knowledge=partial
v-002|compute|app-server/internal/known-corp|canary-1|os=linux

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?credential-guessing|v-001|runs_on|process|??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts, no fixed interval between them"

:H h-001.refuts [id|refutes|claim]
r1|p1|"failures repeat on a fixed interval"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures repeat on a fixed interval"

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-002|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed

:L findings [id|loop|name|target|tests|system|window]
l-001|1|cmdb-source-lookup|v-001|h-001,h-002|cmdb|n/a
l-002|1|auth-failure-cadence|v-001|h-001,h-002|siem|24h

:R attr_updates [resolved_by|target|key|value]
l-001|v-001|class|monitoring/internal/known-corp
l-001|v-001|attrs.knowledge|full

:T resolutions
h-001  null → --   [l-002 r1 severe ⟂ e-001 :: failures land on a fixed 300s interval]
h-002  null → ++   [l-002 p1 severe ⟂ e-001 :: failures land on a fixed 300s interval]

:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      scheduled-service-retry
summary                "Failure series is the documented monitoring probe's fixed-interval retry"

:T conclude.surviving [hyp_id|final_weight]
h-002|++
```
"""


def test_siblings_sharing_an_open_parent_class_parse_and_validate_clean() -> None:
    body, warnings = parse_dense_companion(_OPEN_PARENT_FORK)
    assert warnings == []
    # Assert on what parsed. A document whose fence stopped being recognized parses to `{}`
    # with no warnings and validates clean, so `warnings == []` alone is a pass this file
    # would earn by testing nothing.
    hyps = body["hypothesize"]["hypotheses"]
    assert [h["id"] for h in hyps] == ["h-001", "h-002"]
    assert {h["proposed_edge"]["parent_vertex"]["classification"] for h in hyps} == {"??"}
    assert validate_companion(_OPEN_PARENT_FORK, None) == []


def _blocked(errors: list[str]) -> list[str]:
    return [e for e in errors if "disposition benign blocked" in e]


def test_an_open_proposed_parent_does_not_block_a_benign_close() -> None:
    assert validate_companion(_BENIGN_CLOSE_OVER_OPEN_PARENTS, None) == []


def test_the_benign_gate_is_live_on_that_document() -> None:
    """The control that keeps the pass above from being vacuous.

    Drop the one `:R attr_updates` row and the SAME document blocks — so the gate does walk
    this shape, and the clean result above is the proposed parents being out of its scope
    rather than the check never running.
    """
    control = _BENIGN_CLOSE_OVER_OPEN_PARENTS.replace(
        "l-001|v-001|class|monitoring/internal/known-corp\n", ""
    )
    blocked = _blocked(validate_companion(control, None))
    assert len(blocked) == 1
    assert "vertex v-001" in blocked[0]


# rule #23 — the textual floor over declared claims

def _fork_errors(doc: str) -> list[str]:
    """Rule #23's diagnostics, picked out of the flat list `validate_companion` returns.

    Filtered on `_SIBLING_FORK_TAG`, the constant the check BUILDS its message from — not on a
    phrase copied out of that message. A filter spelled as a copied phrase is a filter that
    silently matches nothing the day the prose is reworded, and every `== []` assertion below
    would then pass by finding nothing rather than by the rule staying quiet. Importing the
    identity makes that failure mode unreachable: the message and the filter cannot drift
    apart, because there is only one string.

    The `== []` assertions are still only as good as the positive controls beside them —
    `test_siblings_predicting_the_same_observable_are_refused` and
    `test_matching_attribute_predictions_do_not_rescue_a_duplicate` are what establish this
    helper returns non-empty for a document the rule refuses, so a silent deletion of the
    check would go red here rather than green everywhere.
    """
    return [str(e) for e in validate_companion(doc, None) if _SIBLING_FORK_TAG in str(e)]


def _fork_doc(h1_claim: str, h2_claim: str, *, anchor2: str = "v-001", tail: str = "") -> str:
    return (
        "```invlang\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|compute|ip-only/??/??|172.18.0.15|knowledge=partial\n"
        "v-002|compute|server/internal/known-corp|canary-1|os=linux\n"
        "\n"
        ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
        "e-001|attempted_auth|v-001|v-002|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed\n"
        "\n"
        ":H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class"
        "|integrity_waived?|weight|status]\n"
        "h-001|?credential-guessing|v-001|runs_on|process|??||null|active\n"
        f"h-002|?scheduled-service-retry|{anchor2}|runs_on|process|??||null|active\n"
        "\n"
        ":H h-001.preds [id|subject|claim]\n"
        f'p1|proposed_edge|"{h1_claim}"\n'
        "\n"
        ":H h-002.preds [id|subject|claim]\n"
        f'p1|proposed_edge|"{h2_claim}"\n'
        + tail +
        "```\n"
    )


def test_siblings_predicting_the_same_observable_are_refused() -> None:
    """Same claim, different `?name` — the fork no lead can split."""
    errors = _fork_errors(_fork_doc("failures arrive in bursts", "failures arrive in bursts"))
    assert len(errors) == 1
    assert "h-001, h-002" in errors[0]
    assert "v-001" in errors[0]


def test_case_and_spacing_do_not_buy_distinctness() -> None:
    """The floor normalizes before comparing, or a shift key defeats the rule."""
    assert _fork_errors(
        _fork_doc("failures arrive in bursts", "Failures  arrive in   bursts.")
    )


def test_one_differing_claim_is_enough() -> None:
    assert _fork_errors(
        _fork_doc("failures arrive in bursts", "failures repeat on a fixed interval")
    ) == []


def test_siblings_on_different_anchors_are_not_siblings() -> None:
    """The group is `(parent hypothesis, anchor)`. Two stories about two entities predicting
    the same thing are two questions, not one question asked twice."""
    assert _fork_errors(
        _fork_doc("failures arrive in bursts", "failures arrive in bursts", anchor2="v-002")
    ) == []


def test_a_hypothesis_with_no_predictions_yet_is_exempt() -> None:
    """`:H hypothesize.hypotheses` and the `.preds` blocks arrive as separate appends, so a
    group is legally predictionless in between. Refusing that would deny the write on its way
    to satisfying the rule."""
    doc = _fork_doc("failures arrive in bursts", "unused")
    doc = doc[: doc.index(":H h-002.preds")] + "```\n"
    assert _fork_errors(doc) == []


def test_refuting_one_of_the_two_is_the_repair() -> None:
    """`:H` rows are immutable and the document is append-only, so a collision already on disk
    can only be repaired by refuting one side. LIVE-only scoping is what leaves that open —
    under a declared-set reading every later write would be denied for a row nobody may touch.
    """
    tail = (
        "\n"
        ":H h-002.refuts [id|refutes|claim]\n"
        'r1|p1|"failures repeat on a fixed interval"\n'
        "\n"
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|auth-cadence|v-001|h-001,h-002|siem|24h\n"
        "\n"
        ":T resolutions\n"
        "h-002  null → --   [l-001 r1 severe ⟂ e-001 :: the series is bursty, not cadenced]\n"
    )
    doc = _fork_doc("failures arrive in bursts", "failures arrive in bursts", tail=tail)
    assert _fork_errors(doc) == []


#: A fork carried entirely by `.attr_preds`: identical `.preds`, opposite predicted values for
#: one attribute of the anchored vertex.
#:
#: `target` is `attached_vertex`, NOT `v-001`. The cell names WHICH of the hypothesis's three
#: objects carries the attribute (`_ATTR_PRED_TARGETS`) — the proposed parent and proposed edge
#: have no id yet, and the attached vertex is already named by `attached_to` — so a vertex id
#: there is a rule #33 violation. It shipped as `v-001` because #33 had no implementation when
#: this fixture was written; `attached_vertex` is the same prediction about the same object,
#: said in the grammar.
_ATTR_FORK = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/??/??|172.18.0.15|knowledge=partial

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?credential-guessing|v-001|runs_on|process|??||null|active
h-002|?scheduled-service-retry|v-001|runs_on|process|??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-001.attr_preds [id|target|attribute|claim]
ap1|attached_vertex|signing|"UNSIGNED"

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-002.attr_preds [id|target|attribute|claim]
ap1|attached_vertex|signing|"SIGNED"
```
"""


def test_a_fork_carried_only_by_attribute_predictions_is_distinct() -> None:
    """`.attr_preds` declares predicted observables too — the most concrete kind. Reading only
    `.preds` would refuse a pair that forks on the one axis a lead can measure exactly."""
    assert _fork_errors(_ATTR_FORK) == []


def test_matching_attribute_predictions_do_not_rescue_a_duplicate() -> None:
    assert _fork_errors(_ATTR_FORK.replace('"SIGNED"', '"UNSIGNED"'))
