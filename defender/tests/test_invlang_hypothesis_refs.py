"""Every site that names an `h-*` resolves to a `:H` row, and the weight table is keyed by
exactly what those rows declare.

#819 closed the `:T resolutions` case — a resolution could no longer move a hypothesis
nothing declared. It was the shallowest of three reference sites and the second of two
depths, and #821 is the rest of both:

  * `:L findings`' `tests` column and `:T shelved`'s `hyp_id` reference a hypothesis the
    same way and neither resolved it. A lead could claim to TEST a hypothesis nobody
    declared, and a `:T shelved` row could retire one that never existed — both upstream of
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
three sites, and the error it emits for a resolution is unchanged.
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
_SHELVED_HEADER = ":T shelved [hyp_id|by_lead|rationale]"
_EDGE = (
    ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    "e-002|executed|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|\n"
)

#: Scoped to the two sites this issue opened. `examples/` carries unrelated errors that
#: predate it, so the corpus check below stays a check on this rule rather than a freeze of
#: the whole validator's verdict.
_MARKERS = ("tests undeclared hypothesis", "shelves undeclared hypothesis")


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


def test_a_shelved_row_retiring_an_undeclared_hypothesis_is_rejected():
    """The second. Shelving is how a hypothesis leaves the run, so a phantom here reads as
    a hypothesis that was raised and dropped — the record says a question was considered
    and closed when it was never asked."""
    errors = _errors(_doc(
        _declaring("h-001") + "\n"
        + _lead("h-001") + "\n"
        + _SHELVED_HEADER + "\n"
        'h-888|l-001|"weak signal"\n'
    ))
    assert len(errors) == 1
    assert "'h-888'" in errors[0]


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


def test_a_dropped_declaration_block_stands_both_sites_down():
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
        + _SHELVED_HEADER + "\n"
        'h-001|l-001|"dropped along with its block"\n'
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




@pytest.mark.parametrize("path", corpus_docs(), ids=corpus_id)
def test_the_shipped_corpus_carries_no_hypothesis_reference_defect(path: Path):
    assert _errors(path.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("path", corpus_docs(), ids=corpus_id)
def test_no_shipped_document_mints_a_phantom_in_its_weight_table(path: Path):
    """The walker rule against the corpus, including `example-b-parallel-iam-cmdb.md` —
    the document whose `:H` block the parser drops. The validator stands down there and
    says so; the walker must still refuse to invent the hypotheses that block would have
    declared."""
    companion, _warnings = parse_dense_companion(path.read_text(encoding="utf-8"))
    assert set(final_weights(companion)) <= set(all_hypotheses(companion))
