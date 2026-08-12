"""#853 — four parser/validator gaps that let a block close over an unresolved classification.

One suite because the four defects sit in one skill and two of them defeat the same gate from
opposite directions:

  F-14  `_split_quoted` let the `"` of a `\\"` reach the quote toggle, so a row carrying an odd
        number of them before its last cell silently MERGED the remaining cells and `_row_cells`
        padded the record with empty strings — no RowError, no warning. The committed document
        still displays `signing=??` to a human while the benign gate reads nothing.
  F-15  `_has_open_slot` implemented only the whole-cell `{a, b}` form of the documented rule,
        so the per-slot and type-prefixed spellings SKILL.md itself blesses closed benign over
        an unresolved class.
  F-16  `_check_benign_authz` resolves verdicts by bare contract id across the whole document
        while `ac*` ids were hypothesis-local everywhere else, so one `:R authz` row discharged
        every hypothesis's same-numbered contract.
  F-27  `_HYP_PREFIX_RE` restated a narrower hypothesis id than `HYPOTHESIS_ID_RE`, so a
        hierarchical child could never declare the predictions the validator then demands.

Every fixture below is a WHOLE document run through the real `parse_dense_companion` /
`validate_companion`, because three of the four defects are only observable in what the gate
concludes, not in what the unit returns. Each negative case is paired with the control that
keeps the fix from being "deny everything": a laced-but-legal `\\|`, a concrete class, an
attribute whose value merely CONTAINS braces, and distinct `ac*` ids that still discharge.
"""

from __future__ import annotations

from defender.skills.invlang.parser import (
    _split_cells,
    _split_subcells,
    _unquote,
    parse_dense_companion,
)
from defender.skills.invlang.validate import validate_companion

# --------------------------------------------------------------------------- #
# document fixtures
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# F-14 — the escaped quote never reaches the quote toggle
# --------------------------------------------------------------------------- #

def test_backslash_quote_in_a_middle_cell_does_not_merge_the_rest_of_the_row():
    """The defect in one call: an ODD `\\"` before the last cell used to swallow every
    remaining delimiter. The pair is consumed verbatim now, exactly as `_has_unbalanced_quote`
    has always read it."""
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
    """F-14's residual half, and the one the `\\"` fix did NOT close: an EVEN number of plain
    `"` merges cells with row parity intact, so `_has_unbalanced_quote` stays silent. Nor can
    a cell count see it — the merge eats one delimiter and the optional trailing `attrs?`
    absorbs the shift, so `signing=??` lands in `ident`, which by #836/N9 gates nothing. What
    is actually malformed is the quote's POSITION, and that is what the row is refused for."""
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
    """The pad was the silent half of F-14: a record short of what its own header requires
    became a record with empty strings in it, and no diagnostic. The `?` flags say which
    columns may be omitted; anything before the last required one is a refusal."""
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


def test_an_empty_table_still_writes_itself_as_one_none_row():
    """`none` under a two-column header is a COMPLETE row saying the table is empty, not a
    truncated one — the shape `:T conclude.surviving` uses when every hypothesis was
    refuted. The required-cell check has to know the marker or it refuses that document."""
    doc = _doc(
        ":V prologue.vertices [id|type|class|ident|attrs?]\n"
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|",
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|cmdb-lookup|v-001||cmdb|n/a",
        ":T conclude.surviving [hyp_id|final_weight]\nnone",
    )
    _companion, warnings = parse_dense_companion(doc)
    assert warnings == []
    assert validate_companion(doc) == []


def test_an_omitted_trailing_optional_column_is_still_padded():
    """The control the `?` flags exist for: `attrs?` is optional, so a row that stops after
    `ident` — with no trailing `|` — is a complete row and still parses."""
    doc = _benign_doc("v-001|compute|bastion/internal/known-corp|bastion-01.corp")
    companion, warnings = parse_dense_companion(doc)
    assert warnings == []
    assert companion["prologue"]["vertices"][0]["identifier"] == "bastion-01.corp"
    assert validate_companion(doc) == []


# --------------------------------------------------------------------------- #
# F-15 — every documented spelling of an unresolved slot blocks benign
# --------------------------------------------------------------------------- #

def test_per_slot_candidate_set_blocks_benign():
    """SKILL.md §Open questions: "Per-slot enumeration is fine when only one axis is open" —
    so the gate has to read the slot, not the whole cell."""
    doc = _benign_doc("v-001|compute|monitoring-agent/{internal, dmz}/known-corp|10.42.7.183|")
    assert _blocked(validate_companion(doc))


def test_whole_triple_and_type_prefixed_candidate_sets_block_benign():
    whole = _benign_doc(
        "v-001|compute|{monitoring-agent/internal/known-corp, ip-only/internet/novel}|10.42.7.183|"
    )
    prefixed = _benign_doc(
        "v-001|compute|compute:{monitoring-agent/internal/known-corp, ip-only/internet/novel}|10.42.7.183|"
    )
    assert _blocked(validate_companion(whole))
    assert _blocked(validate_companion(prefixed))


def test_single_member_candidate_set_blocks_benign():
    """No comma required: `{internal}` has still not picked, and demanding the comma made the
    NARROWEST open state the one spelling that passed."""
    doc = _benign_doc("v-001|compute|monitoring-agent/{internal}/known-corp|10.42.7.183|")
    assert _blocked(validate_companion(doc))


def test_attribute_candidate_set_blocks_benign_and_names_the_value():
    doc = _benign_doc(
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|signing={signed, unsigned}"
    )
    errors = _blocked(validate_companion(doc))
    assert len(errors) == 1
    assert "'signing'" in errors[0]


def test_an_unterminated_candidate_set_blocks_benign():
    """A dropped `}` must not read as concrete. The brace-aware split folds every slot after
    the unclosed `{` into one cell that is neither `??` nor a closed `{...}`, so without this
    a one-character typo closed benign over the class it was still enumerating."""
    truncated = _benign_doc(
        "v-001|compute|{monitoring-agent/internal/known-corp, ip-only/internet/novel|10.42.7.183|"
    )
    mid_tuple = _benign_doc(
        "v-001|compute|monitoring-agent/{internal, dmz/known-corp|10.42.7.183|"
    )
    assert _blocked(validate_companion(truncated))
    assert _blocked(validate_companion(mid_tuple))


def test_a_resolved_document_and_an_attribute_that_merely_contains_braces_still_close():
    """The whole-value anchor, as a control: a legitimate `attrs.cmdline` carrying `{...}`
    inside a longer string is a fact, not an open question, and must not block."""
    doc = _benign_doc(
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|cmdline=deploy-{blue}-svc"
    )
    assert validate_companion(doc) == []


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


# --------------------------------------------------------------------------- #
# F-16 — an `ac*` id binds to exactly one hypothesis
# --------------------------------------------------------------------------- #

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
    """LIVE, not declared — and the scope is what keeps the rule repairable. `investigation.md`
    is append-only and `:H` rows are immutable, so a collision already on disk can never be
    edited away; under a declared-set reading every later write to that document would be
    denied for a row the author is not allowed to touch. Refuting one side is the in-grammar
    move that ends the ambiguity, and it costs nothing: `_check_benign_authz` reads the same
    live set, so a contract on a refuted hypothesis discharges nothing either way."""
    doc = _authz_doc(
        "ac1",
        "ac1",
        'l-001|e-001|ac1|authorized|change-mgmt|"CHG-4471 covers the window"',
        refute="h-002",
    )
    assert not [e for e in validate_companion(doc) if "authz contract" in e]


def test_one_authz_row_no_longer_discharges_a_siblings_contract():
    """The control on the fix's other half: with the ids made distinct — the repair the new
    error asks for — h-002's contract is unresolved and benign is blocked. This is the outcome
    the collision was silently buying, so it has to hold under the same document shape."""
    doc = _authz_doc(
        "ac1", "ac2", "l-001|e-001|ac1|authorized|change-mgmt|\"CHG-4471 covers the window\""
    )
    blocked = _blocked(validate_companion(doc))
    assert len(blocked) == 1
    assert "ac2" in blocked[0]
    assert "h-002" in blocked[0]


def test_one_hypothesis_repeating_a_contract_id_in_one_block_is_denied():
    """The collision's other half, one level down: `_extend_by_id` keeps the FIRST row per id,
    so a second `ac1` carrying a different predicate was discarded in silence and the benign
    gate never had to satisfy it. The projector names the dropped row now."""
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


def test_distinct_contract_ids_each_discharged_still_close_benign():
    doc = _authz_doc(
        "ac1",
        "ac2",
        "l-001|e-001|ac1|authorized|change-mgmt|\"CHG-4471 covers the window\"",
        "l-001|e-001|ac2|authorized|change-mgmt|\"CHG-4471 covers the window\"",
    )
    assert validate_companion(doc) == []


# --------------------------------------------------------------------------- #
# F-27 — a hierarchical child declares its own sub-blocks
# --------------------------------------------------------------------------- #

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
    """`_HYP_PREFIX_RE` is built from `HYPOTHESIS_ID_RE` now, so the declaring side accepts
    every id the four reference sites already accepted. Before, the sub-block fell through to
    the generic unknown-block warning and the whole write was denied — leaving a committed
    child with no way to declare a prediction, and so no way to ever be moved `++`."""
    companion, warnings = parse_dense_companion(_CHILD_DOC)
    assert warnings == []
    hyp = companion["hypothesize"]["hypotheses"][0]
    assert [p["id"] for p in hyp["predictions"]] == ["p1"]
    assert validate_companion(_CHILD_DOC) == []


def test_a_sub_block_on_an_undeclared_child_still_warns_about_the_hypothesis():
    """The widened prefix must not swallow a typo: an unknown child now lands on the
    sub-block's own "references unknown hypothesis" warning, which names the real cause."""
    typo = _CHILD_DOC.replace(":H h-001-001.preds", ":H h-001-002.preds")
    _companion, warnings = parse_dense_companion(typo)
    assert [w.reason for w in warnings] == [
        "sub-block references unknown hypothesis 'h-001-002'"
    ]
