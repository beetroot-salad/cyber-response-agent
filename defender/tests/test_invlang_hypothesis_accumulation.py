"""`:H` blocks accumulate; a hypothesis is declared once and never un-declared.

Append-only forbids rewriting the loop-1 `:H hypothesize.hypotheses` block, so a
loop that forks a hypothesis has only one way to record it: a SECOND block. That
block used to REPLACE the projected list — every earlier loop's hypothesis
vanished from the companion, silently, with no parse warning. Everything keyed
off `_walkers.all_hypotheses` inherited the hole: the predictions a later
resolution resolves against, the weights `final_weights` reports, and the authz
contracts `disposition: benign` is gated on.

The lead-scoped spelling (`:H l-NNN.new_hypotheses`) had the mirror defect. Its
records never entered the projector's sub-block index, so the `:H h-NNN.preds`
declaring their predictions was rejected as "unknown hypothesis" — a mid-run
hypothesis could not carry a prediction at all (#816).
"""

from __future__ import annotations

from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import validate_companion

_HYP_HEADER = (
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]"
)
_LEAD_HEADER = ":L findings [id|loop|name|target|tests|system|window]"
_EDGE = (
    ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    "e-001|executed|v-001|v-001|2026-05-05T03:42:11Z|siem-event:siem|\n"
)


def _doc(body: str) -> str:
    return "```invlang\n" + body + "\n```"


def _hyp_row(hid: str, name: str) -> str:
    return f"{hid}|?{name}|v-001|executed|process|unclassified-process||null|active\n"


def _loop_one() -> str:
    return _EDGE + "\n" + _HYP_HEADER + "\n" + _hyp_row("h-001", "adversary-shell")




def test_a_second_hypothesize_block_adds_rather_than_replaces():
    """The whole bug in one assertion: loop 2 forks h-003, and h-001 must survive."""
    body, warnings = parse_dense_companion(_doc(
        _loop_one() + "\n"
        + _HYP_HEADER + "\n" + _hyp_row("h-003", "packaged-daemon")
    ))
    assert warnings == []
    assert [h["id"] for h in body["hypothesize"]["hypotheses"]] == ["h-001", "h-003"]


def test_a_later_block_cannot_un_declare_an_earlier_hypothesis_prediction():
    """`:H h-001.preds` is projected before loop 2's block is even read. Replacing
    the list took the predictions with it, so a loop-2 resolution citing p1 found
    a hypothesis that declared nothing."""
    body, warnings = parse_dense_companion(_doc(
        _loop_one()
        + ":H h-001.preds [id|subject|claim]\n"
        'p1|proposed_parent|"parent is an interactive shell"\n'
        "\n"
        + _HYP_HEADER + "\n" + _hyp_row("h-003", "packaged-daemon")
    ))
    assert warnings == []
    h001 = next(h for h in body["hypothesize"]["hypotheses"] if h["id"] == "h-001")
    assert [p["id"] for p in h001["predictions"]] == ["p1"]


def test_first_declaration_wins_when_a_second_block_repeats_an_id():
    """Re-declaring a row to carry an updated field is not a merge — that needs a
    status vocabulary and an append-only amendment first. Pinned so the choice is
    visible: the sub-block index keeps the ORIGINAL record, matching
    `_walkers.all_hypotheses`, rather than silently rebinding to the late one."""
    body, warnings = parse_dense_companion(_doc(
        _loop_one() + "\n"
        + _HYP_HEADER + "\n" + _hyp_row("h-001", "renamed-late") + "\n"
        + ":H h-001.preds [id|subject|claim]\n"
        'p1|proposed_parent|"claim"\n'
    ))
    assert warnings == []
    hyps = body["hypothesize"]["hypotheses"]
    assert [h["name"] for h in hyps] == ["?adversary-shell", "?renamed-late"]
    assert [p["id"] for p in hyps[0]["predictions"]] == ["p1"]
    assert "predictions" not in hyps[1]


def test_a_benign_disposition_still_sees_an_earlier_loops_authz_contract():
    """The safety consequence, and the reason this is a parser bug worth its own
    change. `disposition: benign` requires every authz contract on a live
    hypothesis to be resolved `authorized`. While a later `:H` block deleted
    h-001, its unfulfilled contract went with it — and the benign gate passed on
    an alert whose mechanism was never proven permitted."""
    doc = _doc(
        _loop_one()
        + ":H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        'ac1|e-001|iam-policy|"the account may run this"|escalate|escalate\n'
        "\n"
        + _HYP_HEADER + "\n" + _hyp_row("h-003", "packaged-daemon") + "\n"
        + ":T conclude\ndisposition            benign\n"
    )
    errors = [e for e in validate_companion(doc) if "authz contract ac1" in e]
    assert len(errors) == 1, errors
    assert "h-001" in errors[0]




def test_a_lead_born_hypothesis_can_declare_a_prediction():
    """`:H l-NNN.new_hypotheses` + `:H h-NNN.preds` is the documented way to fork
    mid-run. The sub-block used to be rejected outright."""
    body, warnings = parse_dense_companion(_doc(
        _EDGE + "\n"
        + _LEAD_HEADER + "\n"
        "l-001|1|process-ancestry|v-001|h-001|elastic|±10m\n"
        "\n"
        ":H l-001.new_hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        + _hyp_row("h-010", "mid-run-fork")
        + "\n"
        ":H h-010.preds [id|subject|claim]\n"
        'p1|proposed_parent|"the fork predicts this"\n'
    ))
    assert warnings == [], [w.format() for w in warnings]
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    fork = lead["new_hypotheses"][0]
    assert fork["id"] == "h-010"
    assert [p["id"] for p in fork["predictions"]] == ["p1"]


def test_two_new_hypotheses_blocks_on_one_lead_accumulate():
    body, warnings = parse_dense_companion(_doc(
        _EDGE + "\n"
        + _LEAD_HEADER + "\n"
        "l-001|1|process-ancestry|v-001|h-001|elastic|±10m\n"
        "\n"
        ":H l-001.new_hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        + _hyp_row("h-010", "first-fork")
        + "\n"
        ":H l-001.new_hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        + _hyp_row("h-011", "second-fork")
    ))
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert [h["id"] for h in lead["new_hypotheses"]] == ["h-010", "h-011"]


def test_a_subblock_for_a_genuinely_unknown_hypothesis_still_warns():
    """The registration widens what counts as declared; it must not silence the
    warning for an id nothing declares anywhere."""
    _body, warnings = parse_dense_companion(_doc(
        _loop_one() + "\n"
        ":H h-999.preds [id|subject|claim]\n"
        'p1|proposed_parent|"orphan"\n'
    ))
    assert len(warnings) == 1
    assert "unknown hypothesis 'h-999'" in warnings[0].reason
