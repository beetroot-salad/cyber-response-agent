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

from defender.skills.invlang._walkers import all_hypotheses
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


def test_re_emitting_the_table_neither_replaces_nor_duplicates():
    """Accumulation is BY ID, not blind.

    Re-emitting the whole table with one new row appended is the natural reading
    of a table block, and it was correct under the old replace semantics. Blind
    `extend` would turn it into duplicate rows — and `runtime/review/projector.py`
    maps the raw list straight to the review lenses without the dedup
    `_walkers.all_hypotheses` applies, so every lens would see h-001 twice.

    First declaration wins, so a re-declared row carrying an updated field is
    dropped rather than merged. That still needs a status vocabulary and an
    append-only amendment (#798 non-goals); what it must not do is silently
    corrupt the list."""
    body, warnings = parse_dense_companion(_doc(
        _loop_one() + "\n"
        + _HYP_HEADER + "\n"
        + _hyp_row("h-001", "renamed-late")
        + _hyp_row("h-003", "genuinely-new") + "\n"
        + ":H h-001.preds [id|subject|claim]\n"
        'p1|proposed_parent|"claim"\n'
    ))
    assert warnings == []
    hyps = body["hypothesize"]["hypotheses"]
    assert [h["name"] for h in hyps] == ["?adversary-shell", "?genuinely-new"]
    assert [p["id"] for p in hyps[0]["predictions"]] == ["p1"]


def test_a_re_emitted_sub_block_does_not_duplicate_its_rows_either():
    body, warnings = parse_dense_companion(_doc(
        _loop_one()
        + ":H h-001.preds [id|subject|claim]\n"
        'p1|proposed_parent|"first"\n'
        "\n"
        ":H h-001.preds [id|subject|claim]\n"
        'p1|proposed_parent|"re-emitted"\n'
        'p2|proposed_parent|"genuinely new"\n'
    ))
    assert warnings == []
    preds = body["hypothesize"]["hypotheses"][0]["predictions"]
    assert [(p["id"], p["claim"]) for p in preds] == [
        ("p1", "first"), ("p2", "genuinely new")
    ]


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




def test_a_second_preds_block_adds_a_prediction_rather_than_replacing():
    """The sub-block has the same append-only shape as the table above it: a loop
    that adds a prediction to a live hypothesis can only write a SECOND `:H
    h-001.preds`, and assignment took the first block's predictions with it."""
    body, warnings = parse_dense_companion(_doc(
        _loop_one()
        + ":H h-001.preds [id|subject|claim]\n"
        'p1|proposed_parent|"parent is an interactive shell"\n'
        "\n"
        ":H h-001.preds [id|subject|claim]\n"
        'p2|proposed_parent|"parent was launched from a terminal"\n'
    ))
    assert warnings == []
    h001 = body["hypothesize"]["hypotheses"][0]
    assert [p["id"] for p in h001["predictions"]] == ["p1", "p2"]


def test_a_second_authz_block_cannot_drop_an_earlier_contract():
    """The safety edge of the same defect. `ac1` is fulfilled by nothing; `ac2`
    is authorized. While the second block REPLACED the contract list, ac1
    vanished and the benign gate saw only the satisfied contract."""
    doc = _doc(
        _loop_one()
        + ":H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        'ac1|e-001|iam-policy|"the account may run this"|escalate|escalate\n'
        "\n"
        ":H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        'ac2|e-001|iam-policy|"the account may reach this host"|escalate|escalate\n'
        "\n"
        ":R authz [resolved_by|fulfills_contract|anchor_kind|verdict]\n"
        "l-001|ac2|iam-policy|authorized\n"
        "\n"
        + _LEAD_HEADER + "\n"
        "l-001|1|authz-check|v-001|h-001|elastic|±10m\n"
        "\n"
        ":T conclude\ndisposition            benign\n"
    )
    blocked = [e for e in validate_companion(doc) if "authz contract" in e]
    assert len(blocked) == 1, blocked
    assert "ac1" in blocked[0]


def test_a_second_refuts_block_adds_a_refutation_rather_than_replacing():
    body, _warnings = parse_dense_companion(_doc(
        _loop_one()
        + ":H h-001.refuts [id|refutes|claim]\n"
        'r1||"no shell ancestor"\n'
        "\n"
        ":H h-001.refuts [id|refutes|claim]\n"
        'r2||"packaged installer path"\n'
    ))
    h001 = body["hypothesize"]["hypotheses"][0]
    assert [r["id"] for r in h001["refutation_shape"]] == ["r1", "r2"]


def test_declaring_one_id_at_both_sites_is_rejected_and_the_table_still_outranks():
    """Two sites declaring one id is not recoverable, so it is warned — and the
    warning blocks the write, since `validate_companion` turns any parse warning
    into an error.

    Precedence alone cannot fix it. `_walkers.all_hypotheses` reads the `:H
    hypothesize.hypotheses` table before any lead's `new_hypotheses`, so the
    projector realigns to the table whatever the document order — but a
    `:H h-010.authz` that appeared BEFORE the table row has already attached to
    the lead record, and no rebinding moves it. Left silent, that landed a
    contract on a record no consumer reads and `disposition: benign` passed on
    it. Both halves are asserted: the document is refused, and what the readers
    see is the table's record."""
    doc = _doc(
        _EDGE + "\n"
        + _LEAD_HEADER + "\n"
        "l-001|1|process-ancestry|v-001|h-010|elastic|±10m\n"
        "\n"
        ":H l-001.new_hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        + _hyp_row("h-010", "mid-run-fork")
        + "\n"
        + _HYP_HEADER + "\n" + _hyp_row("h-010", "mid-run-fork") + "\n"
        + ":H h-010.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        'ac1|e-001|iam-policy|"the account may run this"|escalate|escalate\n'
        "\n"
        ":T conclude\ndisposition            benign\n"
    )
    body, warnings = parse_dense_companion(doc)
    assert len(warnings) == 1
    assert "declared both by" in warnings[0].reason
    assert all_hypotheses(body)["h-010"].get("authorization_contract")
    blocked = [e for e in validate_companion(doc) if "authz contract ac1" in e]
    assert len(blocked) == 1, blocked


def test_a_lead_declaring_hypotheses_off_a_stale_header_is_rejected_whole():
    """The prologue site rejects an off-schema `:H` header outright. The lead site
    skipped the check — and a lead-born record now reaches every consumer of
    `_walkers.all_hypotheses`, so an off-schema row would have ridden in."""
    body, warnings = parse_dense_companion(_doc(
        _EDGE + "\n"
        + _LEAD_HEADER + "\n"
        "l-001|1|process-ancestry|v-001|h-010|elastic|±10m\n"
        "\n"
        ":H l-001.new_hypotheses [id|name|attached_to|rel]\n"
        "h-010|?stale|v-001|executed\n"
    ))
    assert len(warnings) == 1
    assert "whole block rejected" in warnings[0].reason
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert "new_hypotheses" not in lead


def test_a_second_observations_block_adds_to_a_lead_rather_than_replacing():
    """Not `:H`, same defect: the two observation sub-blocks assigned, so a lead
    whose results arrive in two blocks kept only the last — and append-only
    leaves no way to write them as one."""
    body, warnings = parse_dense_companion(_doc(
        _LEAD_HEADER + "\n"
        "l-001|1|process-ancestry|v-001|h-001|elastic|±10m\n"
        "\n"
        ":V l-001.observations.vertices [id|type|class|ident|attrs?]\n"
        "v-100|compute|server/internal/known-corp|host-a|\n"
        "\n"
        ":V l-001.observations.vertices [id|type|class|ident|attrs?]\n"
        "v-101|compute|server/internal/known-corp|host-b|\n"
    ))
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    observed = lead["outcome"]["observations"]["vertices"]
    assert [v["id"] for v in observed] == ["v-100", "v-101"]


def test_a_second_prologue_vertices_block_adds_rather_than_replacing():
    body, warnings = parse_dense_companion(_doc(
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|compute|server/internal/known-corp|host-a|\n"
        "\n"
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-002|compute|server/internal/known-corp|host-b|\n"
    ))
    assert warnings == []
    assert [v["id"] for v in body["prologue"]["vertices"]] == ["v-001", "v-002"]
