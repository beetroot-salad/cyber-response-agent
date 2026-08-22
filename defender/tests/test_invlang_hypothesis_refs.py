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

from pathlib import Path

import pytest

from defender.skills.invlang._walkers import (
    all_hypotheses,
    final_weights,
    live_hypothesis_ids,
)
from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import validate_companion
from defender.tests._invlang_corpus import corpus_docs, corpus_id

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
    """The id shape the language allocates when a lean hypothesis refines into sub-cases:
    `h-001` → `h-001-001` (`docs/investigation-language.md` §Refinement via hierarchical
    IDs), written into the lead's `new_hypotheses` — so `tests` is precisely where children
    are named. A single-segment `h-[A-Za-z0-9]+` gate failed on the second hyphen and skipped
    them, which exempted the one id shape the site was added for."""
    errors = _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-001,h-001-777") + "\n"
    ))
    assert len(errors) == 1, errors
    assert "'h-001-777'" in errors[0]


def test_a_declared_hierarchical_child_costs_the_document_nothing():
    """The other half: the fork is legitimate when the child IS declared, and widening the
    shape must not turn a correct refinement into a refusal."""
    assert _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-001-001") + "\n"
        ":H l-001.new_hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        + _hyp_row("h-001-001", "?refined-child") + "\n"
    )) == []


def test_a_commitment_of_another_kind_in_tests_is_not_read_as_a_hypothesis():
    """`tests` is the COMMITMENTS the lead was run for, and the shipped golden proves that
    is three id kinds: `golden-sshpivot-ab3` tests `ac1` on l-002 and `p2` on l-003. A rule
    reading the column as hypotheses-only denied a correct document — the first draft of
    this one did."""
    assert _errors(_doc(_declaring("h-001") + "\n" + _lead("h-001,ac1,p2"))) == []


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
    """The same deference #819 established, keyed to the declaring block. The `:H` header
    is off-schema so the parser rejects the whole block and h-001 never exists — every
    reference to it then looks phantom, and the parse warning already names the cause. One
    defect, one error."""
    doc = _doc(
        _EDGE + "\n"
        ":H hypothesize.hypotheses [id|name|attached_to|rel]\n"
        "h-001|?adversary-shell|v-001|executed\n"
        "\n"
        + _lead("h-001") + "\n"
    )
    assert _errors(doc) == []
    assert [e for e in validate_companion(doc) if "whole block rejected" in e]


def test_a_warning_that_drops_no_hypothesis_does_not_stand_the_rule_down():
    """An unknown block drops no `:H` row, so h-999 is still phantom for exactly the reason
    the error gives. Gating on "no warnings at all" would hide it behind any unrelated
    parse defect."""
    errors = _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-999") + "\n"
        ":Z bogus.block [a|b]\n"
        "x|y\n"
    ))
    assert len(errors) == 1
    assert "'h-999'" in errors[0]


def test_one_undeclared_id_written_twice_is_one_error():
    """`tests` is a csv the parser splits without deduping, and one id written twice is one
    defect however many times the row names it."""
    assert len(_errors(_doc(_declaring("h-001") + "\n" + _lead("h-999,h-999")))) == 1




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


def test_live_hypothesis_ids_does_not_report_the_phantom():
    """The key set is what `live_hypothesis_ids` filters, so the phantom arrived at the
    judge and at `queries.py` as a live hypothesis — not refuted, because nothing ever
    refutes a hypothesis nobody declared."""
    companion = _parsed(
        _declaring("h-001") + "\n"
        + _lead("h-001") + "\n"
        ":T resolutions\n"
        "h-404  null → ++   [l-001 severe ⟂ e-002 :: phantom]"
    )
    assert live_hypothesis_ids(companion) == ["h-001"]


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


def test_a_declared_hypothesis_still_moves_to_the_weight_its_resolution_set():
    """The regression the narrowing must not cause: dropping unknown ids must not stop the
    walker doing its job, which is to move a declared weight."""
    companion = _parsed(
        _declaring("h-001") + "\n"
        + _lead("h-001") + "\n"
        ":T resolutions\n"
        "h-001  null → +    [l-001 weak ⟂ e-002 :: suggestive]"
    )
    assert final_weights(companion) == {"h-001": "+"}


def test_a_refuted_hypothesis_is_still_dropped_from_live():
    """The other half of that regression — `live_hypothesis_ids` still reads the moved
    weight, not the declared one."""
    companion = _parsed(
        _declaring("h-001", "h-002") + "\n"
        + _lead("h-001,h-002") + "\n"
        ":T resolutions\n"
        "h-001  null → --   [l-001 severe ⟂ e-002 :: refuted outright]"
    )
    assert live_hypothesis_ids(companion) == ["h-002"]




def test_a_conclude_naming_a_hypothesis_nothing_declares_is_rejected():
    """The fourth site, and the one the parser used to throw away: `:T conclude.surviving`
    was matched by a blanket `conclude.*` branch that projected nothing, so the run's
    closing claim about what is still standing could name a phantom and no rule could see
    it — while the rule against exactly that was written three sites over."""
    errors = _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-001") + "\n"
        ":T conclude.surviving [hyp_id|final_weight]\n"
        "h-404|+\n"
    ))
    assert len(errors) == 1
    assert "'h-404'" in errors[0]
    assert "conclude.surviving" in errors[0], "the error must name the site"


def test_a_conclude_naming_declared_hypotheses_costs_nothing():
    assert _errors(_doc(
        _declaring("h-001", "h-002") + "\n"
        + _lead("h-001,h-002") + "\n"
        ":T conclude.surviving [hyp_id|final_weight]\n"
        "h-001|+\n"
        "h-002|--\n"
    )) == []


@pytest.mark.parametrize("marker", ["none", "n/a", "None"])
def test_an_empty_surviving_table_is_not_read_as_a_hypothesis(marker: str):
    """`none` is how the format writes an EMPTY array, not an id
    (`docs/dense-investigation-format.md`: "Empty arrays render as a single `none` row",
    with `surviving_hypotheses` named among them; rule 36 in `investigation-language.md`
    handles "absent or empty" explicitly). A run whose hypotheses were all refuted writes
    exactly this row, and projecting the marker denied it at the write lane."""
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
    """`_CONCLUDE_SCALARS` is read off `Conclude.__annotations__`, so a field added to carry
    a SUB-TABLE joins the flat-key set unless it is subtracted like `termination` is. Left
    in, the parse hint told the author `surviving_hypotheses` was a legal `:T conclude` row
    — and writing one before the sub-table made `setdefault(...).append(...)` raise on a
    `str`, which the write lane renders as "validation errored" and refuses the whole file."""
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
    """Per ID, not per DOCUMENT. `:H l-001.new_hypotheses` is rejected on its header so
    h-005 is deleted and every reference to it must defer — but h-999 is a typo the same
    row makes, unrelated to the dropped block, and standing the whole rule down for the
    file hid it behind a warning that has nothing to do with it."""
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


def test_a_declaration_block_that_dropped_nothing_defers_for_nothing():
    """A rejected header on a `:H` block with NO rows deleted no id. The warning then names
    none, and treating "named nothing" as "could not be mapped" stood the rule down for the
    whole document — hiding every unrelated phantom behind a warning that dropped nothing at
    all, which is the failure the per-ID keying was written to end."""
    doc = _doc(
        _declaring("h-001") + "\n"
        ":H l-001.new_hypotheses [id|name]\n"
        "\n"
        + _lead("h-001,h-999")
    )
    errors = _errors(doc)
    assert len(errors) == 1, errors
    assert "'h-999'" in errors[0]


def test_the_misspelled_declaration_block_defers_for_the_ids_it_dropped():
    """`:H l-001.new_hypothesis` (singular) is the reachable typo, and it deletes the
    declarations just as a rejected header does — the parser warns and says so. Keying the
    deference to the two DECLARING names alone left that one warning followed by one
    undeclared-`h-*` error at EVERY site that references the dropped fork."""
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
    """The honest fallback. A declaration row whose first cell is not id-shaped names no
    id to defer FOR, so there is no way to tell a reference that block would have satisfied
    from a genuine phantom — and reporting them would give two errors for one defect, which
    is the whole reason the deference exists."""
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


def test_a_declared_commitment_costs_the_document_nothing():
    assert _commitment_errors(_with_preds("h-001,p1,ac1")) == []


def test_a_siblings_commitment_is_rejected_even_though_it_exists():
    """The scoping that makes the rule worth having: h-002 declares a p2 and h-001 does
    not, so a row testing only h-001 may not name it. Resolving against every hypothesis in
    the run would accept exactly the cross-citation `_check_prediction_refs` refuses one
    level down."""
    errors = _commitment_errors(_with_preds("h-001,p2"))
    assert len(errors) == 1
    assert "'p2'" in errors[0]


def test_a_row_naming_both_hypotheses_may_name_either_commitment():
    """The shipped golden's shape: `golden-sshpivot-ab3` tests `h-001,h-002,ac1` on l-002
    and `h-001,h-002,p2` on l-003, and the commitment belongs to one of the two."""
    assert _commitment_errors(_with_preds("h-001,h-002,p1,p2,ac1")) == []


def test_an_unprojected_namespace_in_tests_is_left_alone():
    """An `lp*` in the `tests` column resolves against nothing here, and stays exempt now
    that #933 projects `:L l-NNN.lead_preds` — for a structural reason rather than the old
    "nothing declares it". An `lp*` is scoped to a LEAD and this column is scoped to a
    HYPOTHESIS, so no hypothesis's declarations could resolve one; `COMMITMENT_ID_RE`
    `fullmatch`es `p\\d+` and so excludes `lp1` outright. Do not remove the carve-out on the
    strength of the namespace now being projected."""
    assert _commitment_errors(_with_preds("h-001,lp1")) == []


def test_an_undeclared_hypothesis_on_the_row_stands_the_commitment_check_down():
    """One defect, one error: the row's `h-*` is the defect, and its commitments cannot be
    scoped until that is fixed."""
    assert _commitment_errors(_with_preds("h-999,p9")) == []
    assert len(_errors(_with_preds("h-999,p9"))) == 1




@pytest.mark.parametrize("path", corpus_docs(), ids=corpus_id)
def test_the_shipped_corpus_carries_no_hypothesis_reference_defect(path: Path):
    assert _errors(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("path", corpus_docs(), ids=corpus_id)
def test_the_shipped_corpus_carries_no_tested_commitment_defect(path: Path):
    """The golden is the reason this rule is scoped to the tested hypotheses rather than
    to the document: l-002 tests `ac1` and l-003 tests `p2`, both legitimately."""
    assert _commitment_errors(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("path", corpus_docs(), ids=corpus_id)
def test_no_shipped_document_mints_a_phantom_in_its_weight_table(path: Path):
    """The walker rule against the corpus, including `example-b-parallel-iam-cmdb.md` —
    the document whose `:H` block the parser drops. The validator stands down there and
    says so; the walker must still refuse to invent the hypotheses that block would have
    declared."""
    companion, _warnings = parse_dense_companion(path.read_text(encoding="utf-8"))
    assert set(final_weights(companion)) <= set(all_hypotheses(companion))
