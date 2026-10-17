"""Every site that names an `h-*` resolves to a `:H` row, and the weight table is keyed by
exactly what those rows declare.

#819 closed the `:T resolutions` case — a resolution could no longer move a hypothesis
nothing declared. It was the shallowest of three reference sites and the second of two
depths, and #821 is the rest of both:

  * `:L findings`' `tests` column references a hypothesis the
    same way and neither resolved it. A lead could claim to TEST a hypothesis nobody
    declared — upstream of
    the resolution the rule did catch, so a typo surfaced (if at all) one step late and
    pointing at the wrong row.

  * `_walkers.final_weights` seeded an entry from the resolution row itself, so the
    validator was a gate in front of a walker that still minted the phantom. The gate only
    runs on the write; `queries.py` and the judge's `compare.py` read the walker on
    documents that never passed through it — one carrying a parse warning, or one read back
    after the fact — and counted an id that existed only as a typo as a live hypothesis.

The declaration check is `validate_companion`'s; the key set is the walker's. They are
tested together here because either alone leaves the phantom reachable.

The resolution site's own tests stay in `test_invlang_prediction_refs.py` with the
prediction-citation rule they were written against; `_check_hypothesis_refs` now owns all
four sites, and the error it emits for a resolution keeps its `moves undeclared hypothesis`
body — only the closing clause generalised, from "before anything resolves it" to "before
anything references it", now that three more sites can be the thing referencing it.
"""

from __future__ import annotations


import pytest

from defender.skills.invlang._walkers import (
    all_hypotheses,
    final_weights,
)
from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import validate_companion

_HYP_HEADER = (
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]"
)
_LEAD_HEADER = ":L findings [id|loop|name|target|tests|system|window]"
_EDGE = (
    ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    "e-002|executed|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|\n"
)

#: Scoped to this rule. `examples/` carries unrelated errors that predate it, so the corpus
#: check below stays a check on the rule rather than a freeze of the whole validator's
#: verdict. One substring covers all three sites — `moves`/`tests`/`names` undeclared
#: hypothesis — because they share the message body by construction.
_MARKERS = ("undeclared hypothesis",)
_COMMITMENT_MARKER = "tests commitment"


def _doc(body: str) -> str:
    return "```invlang\n" + body + "\n```"


def _hyp_row(hid: str, name: str = "?adversary-shell") -> str:
    return f"{hid}|{name}|v-001|executed|process|unclassified-process||null|active\n"


def _declaring(*hids: str) -> str:
    return _EDGE + "\n" + _HYP_HEADER + "\n" + "".join(_hyp_row(h) for h in hids)


def _lead(tests: str) -> str:
    return _LEAD_HEADER + "\n" + f"l-001|1|process-ancestry|v-001|{tests}|elastic|±10m\n"


def _errors(text: str) -> list[str]:
    return [e for e in validate_companion(text) if any(m in e for m in _MARKERS)]


def _parsed(body: str):
    companion, warnings = parse_dense_companion(_doc(body))
    assert warnings == [], warnings
    return companion


def test_a_lead_that_tests_an_undeclared_hypothesis_is_rejected():
    """The first of the two sites. h-999 is not declared anywhere, and PLAN is where the
    typo is cheapest to fix — before a lead is dispatched against a commitment that does
    not exist."""
    errors = _errors(_doc(_declaring("h-001") + "\n" + _lead("h-001,h-999")))
    assert len(errors) == 1
    assert "'h-999'" in errors[0]
    assert "h-001" in errors[0], "the error must show what IS declared"


def test_a_phantom_hierarchical_child_is_reported():
    """The id shape the language allocates when a lean hypothesis refines into sub-cases:"""
    errors = _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-001,h-001-777") + "\n"
    ))
    assert len(errors) == 1, errors
    assert "'h-001-777'" in errors[0]


def test_a_lead_may_test_the_hypothesis_it_declared_mid_run():
    """The legitimate fork the rule must not cost, at this site too: `:H l-NNN.new_hypotheses`
    declares h-010 inside the lead that found it, and the same lead may test it."""
    assert _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-001,h-010") + "\n"
        ":H l-001.new_hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        + _hyp_row("h-010", "?mid-run-fork")
    )) == []


def test_a_second_hypothesize_block_declares_a_fork_the_same_way():
    """The other documented spelling — append-only forbids rewriting the loop-1 block, so
    both must count as declarations or a forked run cannot reference its own fork."""
    assert _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-001,h-003") + "\n"
        + _HYP_HEADER + "\n"
        + _hyp_row("h-003", "?late-fork")
    )) == []


def test_a_dropped_declaration_block_stands_the_site_down():
    """The same deference #819 established, keyed to the declaring block."""
    doc = _doc(
        _EDGE + "\n"
        ":H hypothesize.hypotheses [id|name|attached_to|rel]\n"
        "h-001|?adversary-shell|v-001|executed\n"
        "\n"
        + _lead("h-001") + "\n"
    )
    assert _errors(doc) == []
    assert [e for e in validate_companion(doc) if "whole block rejected" in e]


def test_final_weights_does_not_mint_a_hypothesis_no_H_row_declares():
    """The walker half of #821, on a document the validator never saw. Seeding the entry
    from the resolution row is what made an id that exists only as a typo a key in the
    table every consumer reads."""
    companion = _parsed(
        _declaring("h-001") + "\n"
        + _lead("h-001") + "\n"
        ":T resolutions\n"
        "h-404  null → +    [l-001 weak ⟂ e-002 :: unrelated]"
    )
    assert set(final_weights(companion)) == {"h-001"}


def test_the_weight_table_is_keyed_by_exactly_what_the_H_rows_declare():
    """The invariant the two tests above are instances of, and the one the consumers were
    already written as if it held: both look weights up BY a declared id."""
    companion = _parsed(
        _declaring("h-001", "h-002") + "\n"
        + _lead("h-001,h-002") + "\n"
        ":T resolutions\n"
        "h-404  null → +    [l-001 weak ⟂ e-002 :: phantom]"
    )
    assert set(final_weights(companion)) == set(all_hypotheses(companion))


def test_a_conclude_naming_a_hypothesis_nothing_declares_is_rejected():
    """The fourth site, and the one the parser used to throw away:"""
    errors = _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-001") + "\n"
        ":T conclude.surviving [hyp_id|final_weight]\n"
        "h-404|+\n"
    ))
    assert len(errors) == 1
    assert "'h-404'" in errors[0]
    assert "conclude.surviving" in errors[0], "the error must name the site"


@pytest.mark.parametrize("marker", ["none", "n/a", "None"])
def test_an_empty_surviving_table_is_not_read_as_a_hypothesis(marker: str):
    """`none` is how the format writes an EMPTY array, not an id (`docs/dense-investigation-format.md`:"""
    companion = _parsed(
        _declaring("h-001") + "\n"
        + _lead("h-001") + "\n"
        ":T conclude.surviving [hyp_id|final_weight]\n"
        + marker + "\n"
    )
    assert (companion.get("conclude") or {}).get("surviving_hypotheses") == []
    assert _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-001") + "\n"
        ":T conclude.surviving [hyp_id|final_weight]\n"
        + marker + "\n"
    )) == []


def test_the_surviving_key_is_not_advertised_as_a_flat_conclude_row():
    """`_CONCLUDE_SCALARS` is read off `Conclude.__annotations__`, so a field added to carry a SUB-TABLE joins the flat-key set unless it is subtracted like `termination` is."""
    from defender.skills.invlang.parser import _CONCLUDE_KEYS_HINT, _CONCLUDE_SCALARS

    assert "surviving_hypotheses" not in _CONCLUDE_SCALARS
    assert "surviving_hypotheses" not in _CONCLUDE_KEYS_HINT
    companion = _parsed(
        _declaring("h-001") + "\n"
        ":T conclude\n"
        # A recognized key beside the unrecognized one: a `:T conclude` that records NOTHING
        # is warned in its own right, and this test is about the flat-key hint rather than
        # about an empty close.
        "disposition            inconclusive\n"
        "surviving_hypotheses   none\n"
        "\n"
        ":T conclude.surviving [hyp_id|final_weight]\n"
        "h-001|+\n"
    )
    assert (companion.get("conclude") or {}).get("surviving_hypotheses") == [
        {"hypothesis": "h-001", "final_weight": "+"}
    ]


def test_the_surviving_table_is_projected_rather_than_discarded():
    """The parser half. Checking the reference needs the rows to reach the companion at
    all, and `hypothesis` is the key `:T resolutions` records already use for it."""
    companion = _parsed(
        _declaring("h-001") + "\n"
        + _lead("h-001") + "\n"
        ":T conclude.surviving [hyp_id|final_weight]\n"
        "h-001|+\n"
    )
    assert (companion.get("conclude") or {}).get("surviving_hypotheses") == [
        {"hypothesis": "h-001", "final_weight": "+"}
    ]


def test_a_dropped_declaration_defers_for_its_own_ids_only():
    """Per ID, not per DOCUMENT."""
    doc = _doc(
        _declaring("h-001") + "\n"
        ":H l-001.new_hypotheses [id|name|attached_to|rel]\n"
        "h-005|?dropped-with-its-block|v-001|executed\n"
        "\n"
        + _lead("h-001,h-005,h-999")
    )
    errors = _errors(doc)
    assert len(errors) == 1, errors
    assert "'h-999'" in errors[0]
    assert "h-005" not in errors[0], "the dropped id defers to its own parse warning"
    assert [e for e in validate_companion(doc) if "whole block rejected" in e]


def test_the_misspelled_declaration_block_defers_for_the_ids_it_dropped():
    """`:H l-001.new_hypothesis` (singular) is the reachable typo, and it deletes the declarations just as a rejected header does — the parser warns and says so."""
    doc = _doc(
        _declaring("h-001") + "\n"
        + _lead("h-001,h-010") + "\n"
        ":H l-001.new_hypothesis "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        + _hyp_row("h-010", "?mid-run-fork") + "\n"
        "\n"
        ":T resolutions\n"
        "h-010  null → +    [l-001 weak ⟂ e-002 :: the fork holds]"
    )
    assert _errors(doc) == []
    assert [e for e in validate_companion(doc) if "new_hypothesis`" in e]


def test_a_dropped_declaration_does_not_make_the_commitment_rule_double_report():
    """The commitment half needs the same deference. With the `:H` block rejected there is
    nothing to scope a `p*` against, and falling back to "every declared hypothesis" —
    which is none — reported it on top of the parse warning: two errors, one defect."""
    doc = _doc(
        _EDGE + "\n"
        ":H hypothesize.hypotheses [id|name|attached_to|rel]\n"
        "h-001|?dropped-with-its-block|v-001|executed\n"
        "\n"
        + _lead("p1")
    )
    assert _commitment_errors(doc) == []
    assert [e for e in validate_companion(doc) if "whole block rejected" in e]


def test_an_unmappable_dropped_declaration_still_stands_the_rule_down():
    """The honest fallback. A declaration row whose first cell is not id-shaped names no id to defer FOR, so there is no way to tell a reference that block would have satisfied from a genuine phantom — and r"""
    assert _errors(_doc(
        _declaring("h-001") + "\n"
        ":H l-001.new_hypotheses [id|name|attached_to|rel]\n"
        "not-an-id|?mangled|v-001|executed\n"
        "\n"
        + _lead("h-001,h-999")
    )) == []


def _commitment_errors(text: str) -> list[str]:
    return [e for e in validate_companion(text) if _COMMITMENT_MARKER in e]


def _with_preds(tests: str) -> str:
    """h-001 declares p1 + ac1; h-002 declares p2 and nothing else."""
    return _doc(
        _declaring("h-001", "h-002") + "\n"
        ":H h-001.preds [id|subject|claim]\n"
        'p1|proposed_parent|"the parent is interactive"\n'
        "\n"
        ":H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        'ac1|e-002|iam-policy|"provisioned for the destination"|escalate|escalate\n'
        "\n"
        ":H h-002.preds [id|subject|claim]\n"
        'p2|proposed_parent|"the parent is packaged"\n'
        "\n"
        + _lead(tests)
    )


def test_a_commitment_in_tests_that_no_tested_hypothesis_declares_is_rejected():
    """The other half of the mixed column. Only its `h-*` was being resolved, so
    `tests=h-001,p9` named a commitment that does not exist and validated clean — the same
    hole the hypothesis half had, one namespace over."""
    errors = _commitment_errors(_with_preds("h-001,p9"))
    assert len(errors) == 1
    assert "'p9'" in errors[0]


def test_an_undeclared_authorization_contract_in_tests_is_rejected():
    """`ac*` is the namespace no resolution head ever cites, so `tests` is the only place
    it can be checked at all."""
    errors = _commitment_errors(_with_preds("h-001,ac9"))
    assert len(errors) == 1
    assert "'ac9'" in errors[0]


def test_a_siblings_commitment_is_rejected_even_though_it_exists():
    """The scoping that makes the rule worth having:"""
    errors = _commitment_errors(_with_preds("h-001,p2"))
    assert len(errors) == 1
    assert "'p2'" in errors[0]


