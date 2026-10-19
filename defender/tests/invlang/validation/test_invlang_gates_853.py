from __future__ import annotations

from defender.skills.invlang.parser import (
    _split_cells,
    _split_subcells,
    _unquote,
    parse_dense_companion,
)
from defender.skills.invlang.validate import validate_companion

# document fixtures

_CONCLUDE_BENIGN = """
:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      routine-admin-login
summary                "Login matched established bastion usage"
"""


def _doc(*sections: str) -> str:
    return "```invlang\n" + "\n".join(s.strip("\n") + "\n" for s in sections) + "```\n"


def _benign_doc(vertex_row: str) -> str:
    return _doc(
        ":V prologue.vertices [id|type|class|ident|attrs?]\n" + vertex_row,
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|cmdb-lookup|v-001||cmdb|n/a",
        _CONCLUDE_BENIGN,
    )


def _blocked(errors: list[str]) -> list[str]:
    return [e for e in errors if "disposition benign blocked" in e]


# F-14 — the escaped quote never reaches the quote toggle

def test_backslash_quote_in_a_middle_cell_does_not_merge_the_rest_of_the_row():
    assert _split_cells(r"a|b\"c|d") == ["a", r"b\"c", "d"]
    # ...and the row keeps its cell count however many escaped quotes it carries.
    assert _split_cells(r'a|b\"c|d\"e|f') == ["a", r"b\"c", r"d\"e", "f"]


def test_escaped_delimiter_and_quoted_cells_are_unchanged():
    """The controls the one-line change had to leave byte-identical."""
    assert _split_cells(r"a|b\|c|d") == ["a", "b|c", "d"]
    row = 'v-002|process|process:bash|bash[pid=42]|flags="EXE_WRITABLE|EXE_LOWER_LAYER"'
    assert _split_cells(row)[4] == 'flags="EXE_WRITABLE|EXE_LOWER_LAYER"'
    assert _split_subcells('a=1;b="x;y"') == ["a=1", 'b="x;y"']
    assert _unquote(r'"he said \"hi\""') == 'he said "hi"'


def test_a_laced_ident_cell_no_longer_hides_an_open_attribute_from_the_benign_gate():
    """The stealth shape the defect bought: `attrs.signing=??` is still ON THE PAGE, and used
    to be invisible to the gate because the ident cell's `\\"` ate the delimiter before it."""
    laced = _benign_doc(
        r'v-001|compute|bastion/internal/known-corp|host\"01|signing=??'
    )
    companion, warnings = parse_dense_companion(laced)
    assert warnings == []
    vertex = companion["prologue"]["vertices"][0]
    assert vertex["identifier"] == r"host\"01"
    assert vertex["attributes"] == {"signing": "??"}
    assert _blocked(validate_companion(laced))


def test_a_quote_opening_mid_token_is_refused_rather_than_merging_cells():
    """F-14's residual half, and the one the `\"` fix did NOT close:"""
    merged = _benign_doc(
        'v-001|compute|bastion"/internal/known-corp|bastion"-01.corp|signing=??'
    )
    _companion, warnings = parse_dense_companion(merged)
    assert len(warnings) == 1
    assert warnings[0].reason.startswith(
        'cell \'bastion"/internal/known-corp|bastion"-01.corp\' opens a `"` inside a token'
    )
    assert validate_companion(merged)


def test_a_row_short_of_a_required_column_is_refused_not_padded():
    truncated = _benign_doc("v-001|compute|bastion/internal/known-corp")
    _companion, warnings = parse_dense_companion(truncated)
    assert [w.reason for w in warnings] == [
        "row has 3 cells but the header requires 4 for [id|type|class|ident|attrs] — "
        "only a `?` column may be omitted (an unbalanced `\"` inside a cell merges the "
        'cells after it: quote the whole cell, or escape the quote as `\\"`)'
    ]
    assert validate_companion(truncated)


def test_a_quoted_cell_and_a_quoted_subcell_value_are_still_legal():
    """The controls the placement rule is bounded by — every quoting shape the corpus uses:
    a wholly-quoted cell carrying a `|`, and a quoted value inside a `k=v` subcell."""
    doc = _doc(
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        'v-001|process|process:bash|bash[pid=42]|flags="EXE_WRITABLE|EXE_LOWER";user=root',
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|cmdb-lookup|v-001||cmdb|n/a",
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        'l-001|e-001|ac1|authorized|change-mgmt|"CHG-4471 covers the window"',
    )
    companion, warnings = parse_dense_companion(doc)
    assert warnings == []
    assert companion["prologue"]["vertices"][0]["attributes"] == {
        "flags": "EXE_WRITABLE|EXE_LOWER",
        "user": "root",
    }


# F-15 — every documented spelling of an unresolved slot blocks benign

def test_per_slot_candidate_set_blocks_benign():
    """SKILL.md §Open questions: "Per-slot enumeration is fine when only one axis is open" —
    so the gate has to read the slot, not the whole cell."""
    doc = _benign_doc("v-001|compute|monitoring-agent/{internal, dmz}/known-corp|10.42.7.183|")
    assert _blocked(validate_companion(doc))


def test_attribute_candidate_set_blocks_benign_and_names_the_value():
    doc = _benign_doc(
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|signing={signed, unsigned}"
    )
    errors = _blocked(validate_companion(doc))
    assert len(errors) == 1
    assert "'signing'" in errors[0]


def test_an_unterminated_candidate_set_blocks_benign():
    truncated = _benign_doc(
        "v-001|compute|{monitoring-agent/internal/known-corp, ip-only/internet/novel|10.42.7.183|"
    )
    mid_tuple = _benign_doc(
        "v-001|compute|monitoring-agent/{internal, dmz/known-corp|10.42.7.183|"
    )
    assert _blocked(validate_companion(truncated))
    assert _blocked(validate_companion(mid_tuple))


def test_a_candidate_set_resolved_by_attr_updates_closes_benign():
    """The documented three-state progression `?? -> {a, b, c} -> concrete` still terminates:
    the gate reads EFFECTIVE state, so the refinement row is what clears it."""
    doc = _doc(
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|compute|monitoring-agent/{internal, dmz}/known-corp|10.42.7.183|",
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|cmdb-lookup|v-001||cmdb|n/a",
        ":R attr_updates [resolved_by|target|key|value]\n"
        "l-001|v-001|class|monitoring-agent/internal/known-corp",
        _CONCLUDE_BENIGN,
    )
    assert validate_companion(doc) == []


# F-16 — an `ac*` id binds to exactly one hypothesis

_TWO_LIVE_HYPS = (
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
    "h-001|?gpo-edit-via-it-admin-svc|v-001|modified|identity|service-account/known-corp||null|active\n"
    "h-002|?scheduled-task-edit|v-001|created|identity|service-account/known-corp||null|active"
)


def _authz_doc(
    first_id: str, second_id: str, *resolution_rows: str, refute: str = ""
) -> str:
    moved = (
        ":T resolutions\n"
        f"{refute}  null → --    [l-001 p1 severe ⟂ e-001 :: no change window covers it]"
        if refute
        else ""
    )
    return _doc(
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|",
        ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
        "e-001|modified|v-001|v-001|2026-05-07T14:25:22.570Z|siem-event:wazuh|",
        _TWO_LIVE_HYPS,
        ":H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        f"{first_id}|e-001|change-mgmt|\"approved change ticket exists\"|escalate|escalate",
        ":H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        f"{second_id}|e-001|change-mgmt|\"approved change ticket exists\"|escalate|escalate",
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|change-lookup|v-001|h-001,h-002|change-mgmt|n/a",
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        + "\n".join(resolution_rows),
        moved,
        _CONCLUDE_BENIGN,
    )


def test_two_hypotheses_declaring_the_same_contract_id_are_denied():
    """The collision is refused at the DECLARING site — a `:R authz` row carries no hypothesis
    column, so an ambiguous id cannot be scoped after the fact."""
    doc = _authz_doc(
        "ac1", "ac1", "l-001|e-001|ac1|authorized|change-mgmt|\"CHG-4471 covers the window\""
    )
    errors = validate_companion(doc)
    assert any(
        "authz contract 'ac1' is declared by more than one live hypothesis" in e
        for e in errors
    ), errors
    assert any("h-001" in e and "h-002" in e for e in errors)


def test_a_collision_with_one_side_refuted_is_not_denied():
    """LIVE, not declared — and the scope is what keeps the rule repairable."""
    doc = _authz_doc(
        "ac1",
        "ac1",
        'l-001|e-001|ac1|authorized|change-mgmt|"CHG-4471 covers the window"',
        refute="h-002",
    )
    errors = validate_companion(doc)
    assert not [e for e in errors if "declared by more than one live hypothesis" in e]
    assert [e for e in errors if "shares BOTH its id and its anchor kind" in e], errors


def test_one_authz_row_no_longer_discharges_a_siblings_contract():
    doc = _authz_doc(
        "ac1", "ac2", "l-001|e-001|ac1|authorized|change-mgmt|\"CHG-4471 covers the window\""
    )
    blocked = _blocked(validate_companion(doc))
    assert len(blocked) == 1
    assert "ac2" in blocked[0]
    assert "h-002" in blocked[0]


def test_one_hypothesis_repeating_a_contract_id_in_one_block_is_denied():
    doc = _doc(
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|",
        ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
        "e-001|modified|v-001|v-001|2026-05-07T14:25:22.570Z|siem-event:wazuh|",
        ":H hypothesize.hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        "h-001|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active",
        ":H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        'ac1|e-001|change-mgmt|"approved change ticket exists"|escalate|escalate\n'
        'ac1|e-001|iam-policy|"the account may modify the GPO"|escalate|escalate',
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|change-lookup|v-001|h-001|change-mgmt|n/a",
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        'l-001|e-001|ac1|authorized|change-mgmt|"CHG-4471 covers the window"',
        _CONCLUDE_BENIGN,
    )
    _companion, warnings = parse_dense_companion(doc)
    assert [w.reason for w in warnings] == [
        "'ac1' is declared twice in this block; only the FIRST row is kept and the later "
        "one is discarded with everything it declares. Give each row its own id, or send "
        "the added rows as a second block."
    ]
    assert validate_companion(doc)


# F-27 — a hierarchical child declares its own sub-blocks

_CHILD_DOC = _doc(
    ":V prologue.vertices [id|type|class|ident|attrs?]\n"
    "v-001|compute|bastion/internal/known-corp|bastion-01.corp|",
    ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    "e-001|authenticated_as|v-001|v-001|2026-05-07T14:25:22.570Z|siem-event:wazuh|",
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
    "h-001-001|?bastion-relay-refined|v-001|authenticated_as|identity|operator||null|active",
    ":H h-001-001.preds [id|subject|claim]\n"
    "p1|proposed_parent|\"the relay session traces to a documented operator\"",
    ":L findings [id|loop|name|target|tests|system|window]\n"
    "l-001|1|identity-lookup|v-001|h-001-001|identity|n/a",
    ":T resolutions\n"
    "h-001-001  null → ++    [l-001 p1 severe ⟂ e-001 :: operator session documented]",
)


def test_a_hierarchical_child_can_declare_the_predictions_the_validator_demands():
    """`_HYP_PREFIX_RE` is built from `HYPOTHESIS_ID_RE` now, so the declaring side accepts every id the four reference sites already accepted."""
    companion, warnings = parse_dense_companion(_CHILD_DOC)
    assert warnings == []
    hyp = companion["hypothesize"]["hypotheses"][0]
    assert [p["id"] for p in hyp["predictions"]] == ["p1"]
    assert validate_companion(_CHILD_DOC) == []
