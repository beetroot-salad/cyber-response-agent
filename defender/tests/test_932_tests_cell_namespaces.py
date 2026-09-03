"""The `:L findings` `tests` column stops losing tokens between two regexes (#932 follow-up).

The column is MIXED — a lead names the hypotheses it discriminates and the commitments it was
run for — and both readers used to SELECT their kind with a `fullmatch` inside a comprehension.
A token in neither namespace was therefore skipped by both and validated clean. Three shapes
had that property, and one of them is not even a defect:

* `h_888` / `H-888` — malformed, and the old docstring accepted them as the price of the gate;
* `h-001.ac1` — the QUALIFIED spelling spec rule #7 blesses, written by `.defender-runs/turnN-A`
  l-003 as its entire `tests` cell, which meant that lead's whole column reached no rule at all.

`_classify_tests_token` resolves every token exhaustively and the residue is a finding, not a
silence. Each violation below is paired with a LIVENESS CONTROL so a check that stopped running
fails here rather than passing vacuously.
"""

from __future__ import annotations

from defender.skills.invlang.validate import _classify_tests_token, validate_companion

_PROLOGUE = """\
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|monitoring-agent/internal/known-corp|172.18.0.15|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|

"""

_HYPOTHESES = """\
:H hypothesize.hypotheses \
[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?credential-guessing|v-001|runs_on|process|??/??/??||null|active
h-002|?monitoring-probe|v-001|runs_on|process|??/??/??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_edge|"failures arrive in bursts"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|change-mgmt|"an approved change covers this window"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_edge|"failures are evenly spaced"

"""


def _doc(tests: str) -> str:
    return (
        "```invlang\n"
        + _PROLOGUE
        + _HYPOTHESES
        + ":L findings [id|loop|name|target|tests|system|window]\n"
        + f"l-001|1|cadence-check|v-001|{tests}|elastic|±10m\n"
        + "```\n"
    )


def _errors(tests: str) -> list[str]:
    return [e for e in validate_companion(_doc(tests)) if "`:L findings` tests" in e]


def test_every_legal_shape_is_resolved() -> None:
    """The four namespaces the column can carry, classified without overlap."""
    assert _classify_tests_token("h-001")[1:] == ("h-001", None, False)
    assert _classify_tests_token("h-001-002")[1:] == ("h-001-002", None, False)
    assert _classify_tests_token("ac1")[1:] == (None, "ac1", False)
    assert _classify_tests_token("h-001.ac1")[1:] == ("h-001", "ac1", False)
    # Recognized but unresolvable HERE — a lead-scoped id in a hypothesis-scoped column.
    assert _classify_tests_token("lp1")[1:] == (None, None, True)


def test_the_qualified_spelling_is_accepted_and_actually_checked() -> None:
    """LIVENESS CONTROL and regression in one. `h-001.ac1` is legal — `h-001` declares `ac1` —
    so it must pass; and the same cell with a contract nobody declares must NOT, which is what
    proves the token is being read rather than skipped as it was before."""
    assert _errors("h-001.ac1") == []
    assert len(_errors("h-001.ac9")) == 1
    assert "h-001.ac9" in _errors("h-001.ac9")[0]


def test_a_qualified_token_resolves_against_its_own_hypothesis_only() -> None:
    """`h-002.ac1` is refused even though a SIBLING on the same row declares `ac1`. The bare
    form scopes against the union of the row's hypotheses; the qualified form names its
    declarer, and honouring that is the cross-citation the sibling rules refuse elsewhere."""
    assert _errors("h-001,h-002,ac1") == []
    refused = _errors("h-001,h-002,h-002.ac1")
    assert len(refused) == 1
    assert "h-002 does not declare" in refused[0]


def test_a_malformed_hypothesis_id_stops_passing_as_some_other_kind() -> None:
    """The residue the old shape gate accepted by name. `h_888` matches no namespace, so both
    readers skipped it and the document validated clean."""
    for bad in ("h_888", "H-888", "garbage", "h-001.zz"):
        errors = _errors(bad)
        assert len(errors) == 1, f"{bad} must be reported"
        assert "no id namespace" in errors[0]


def test_a_lead_scoped_id_is_exempt_not_residue() -> None:
    """`lp1` is a real namespace `_check_lead_prediction_structure` owns, and no hypothesis's
    declarations could resolve it. Recognized-but-unresolvable and unrecognized have to be
    different answers, or the residue rule denies a legal document."""
    assert _errors("lp1") == []
    assert _errors("h-001,lp1") == []


def test_an_undeclared_hypothesis_is_still_the_other_rule_s_defect() -> None:
    """The residue rule does not take over `_check_hypothesis_refs`' job: a well-formed id
    that nothing declares is a dangling reference, reported as one, and reported once."""
    errors = _errors("h-009")
    assert len(errors) == 1
    assert "no id namespace" not in errors[0]
