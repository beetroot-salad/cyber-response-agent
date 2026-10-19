from __future__ import annotations

from defender.skills.invlang.parser import (
    deferred_hypothesis_ids,
    parse_dense_companion,
)
from defender.skills.invlang.validate import (
    effective_vertex_state,
    validate_companion,
)

# document fixtures — the #853 suite's shapes, so a reader who knows one knows both

_CONCLUDE_BENIGN = """
:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      routine-admin-login
summary                "Login matched established bastion usage"
"""

_FINDINGS = (
    ":L findings [id|loop|name|target|tests|system|window]\n"
    "l-001|1|cmdb-lookup|v-001||cmdb|n/a"
)


def _doc(*sections: str) -> str:
    return "```invlang\n" + "\n".join(s.strip("\n") + "\n" for s in sections) + "```\n"


def _benign_doc(*sections: str) -> str:
    return _doc(*sections, _FINDINGS, _CONCLUDE_BENIGN)


def _vertices(*rows: str) -> str:
    return ":V prologue.vertices [id|type|class|ident|attrs?]\n" + "\n".join(rows)


def _blocked(errors: list[str]) -> list[str]:
    return [e for e in errors if "disposition benign blocked" in e]


def _parse_errors(errors: list[str]) -> list[str]:
    return [e for e in errors if e.startswith("parse error:")]


_CLEAN_VERTEX = "v-001|compute|bastion/internal/known-corp|bastion-01.corp|"


# F-2 — a header the regex rejects no longer vaporizes its block

_REJECTED_HEADERS = (
    ":T conclude   # loop 2 wrap-up",
    ":T conclude (loop 3)",
)


def _conclude_fence(header: str) -> str:
    return _doc(header + "\n" + _CONCLUDE_BENIGN.strip("\n").split("\n", 1)[1])


def test_a_trailing_comment_on_a_header_no_longer_deletes_the_whole_block():
    """The defect in one document:"""
    for header in _REJECTED_HEADERS:
        doc = _conclude_fence(header)
        companion, warnings = parse_dense_companion(doc)
        assert companion == {}, header
        assert len(warnings) == 1, header
        assert warnings[0].row == header
        assert "not a block header and no block is open" in warnings[0].reason
        assert "NOTHING after it" in warnings[0].reason
        # ...and the write is refused, where it used to be accepted.
        assert _parse_errors(validate_companion(doc)), header


def test_a_rejected_prologue_header_is_refused_rather_than_returning_nothing():
    doc = _doc(_vertices(_CLEAN_VERTEX).replace(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        ":V prologue.vertices [id|type|class|ident|attrs?]   # loop 2",
    ))
    companion, warnings = parse_dense_companion(doc)
    assert companion == {}
    assert len(warnings) == 1
    assert _parse_errors(validate_companion(doc))


def test_a_header_rejected_after_a_good_block_still_earns_its_own_warning():
    """The rejected header is not always first."""
    doc = _benign_doc(
        _vertices(_CLEAN_VERTEX) + "\n:V prologue.vertices [id|type]   # second block"
    )
    companion, warnings = parse_dense_companion(doc)
    assert [v["id"] for v in companion["prologue"]["vertices"]] == ["v-001"]
    assert warnings
    assert validate_companion(doc)


def test_a_story_section_does_not_swallow_the_rejected_header_under_it():
    """The gap the story arm left open, which is F-2 whole:"""
    doc = _doc(
        "### story h-001\nThe operator logged in from the bastion, as they do every morning.",
        _REJECTED_HEADERS[0] + "\n"
        + _CONCLUDE_BENIGN.strip("\n").split("\n", 1)[1],
    )
    companion, warnings = parse_dense_companion(doc)
    assert companion == {}
    assert len(warnings) == 1
    assert warnings[0].row == _REJECTED_HEADERS[0]
    assert _parse_errors(validate_companion(doc))


# F-3 — a refuted hypothesis's row discharges nothing of a live one's

_TWO_HYPS = (
    ":H hypothesize.hypotheses "
    "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
    "h-001|?gpo-edit-via-it-admin-svc|v-001|modified|identity|service-account/known-corp"
    "||null|active\n"
    "h-002|?scheduled-task-edit|v-001|created|identity|service-account/known-corp"
    "||null|active"
)


def _shared_id_doc(second_id: str) -> str:
    """h-001 (live) asks a change-management question; h-002, refuted, asked an iam-policy
    one. The single `:R authz` row answers h-002's."""
    return _doc(
        _vertices(_CLEAN_VERTEX),
        ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
        "e-001|modified|v-001|v-001|2026-05-07T14:25:22.570Z|siem-event:wazuh|",
        _TWO_HYPS,
        ":H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        'ac1|e-001|change-mgmt|"approved change ticket exists"|escalate|escalate',
        ":H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]\n"
        f'{second_id}|e-001|iam-policy|"the account may modify the GPO"|escalate|escalate',
        ":H h-002.preds [id|subject|claim]\n"
        'p1|proposed_parent|"a change window covers the edit"',
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|change-lookup|v-001|h-001,h-002|change-mgmt|n/a",
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        f'l-001|e-001|{second_id}|authorized|iam-policy|"the role grants GPO write"',
        ":T resolutions\n"
        "h-002  null → --    [l-001 p1 severe ⟂ e-001 :: no change window covers it]",
        _CONCLUDE_BENIGN,
    )


def test_a_refuted_declarers_authz_row_no_longer_discharges_a_live_contract():
    blocked = _blocked(validate_companion(_shared_id_doc("ac1")))
    assert len(blocked) == 1
    assert "ac1" in blocked[0]
    assert "h-001" in blocked[0]
    assert "also declared by h-002" in blocked[0]
    assert "change-mgmt" in blocked[0]


def test_the_shared_id_is_repairable_by_the_append_the_error_names():
    """What the "ignore an ambiguous row entirely" reading would have cost:"""
    doc = _shared_id_doc("ac1").replace(
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n",
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        'l-001|e-001|ac1|authorized|change-mgmt|"CHG-4471 covers the window"\n',
    )
    assert validate_companion(doc) == []


def test_a_contract_with_no_anchor_kind_never_reaches_the_scoping_at_all():
    """What makes `anchor_kind` a usable discriminator rather than one more cell that might say nothing:"""
    doc = _shared_id_doc("ac1").replace(
        'ac1|e-001|change-mgmt|"approved change ticket exists"',
        'ac1|e-001||"approved change ticket exists"',
    )
    companion, warnings = parse_dense_companion(doc)
    assert [w.reason for w in warnings] == ["authz row missing id/anchor_kind"]
    assert companion["hypothesize"]["hypotheses"][0].get("authorization_contract") is None
    assert _parse_errors(validate_companion(doc))


def test_a_shared_id_AND_a_shared_anchor_kind_discharges_nothing():
    """The case with no honest reading left:"""
    doc = _shared_id_doc("ac1").replace("iam-policy", "change-mgmt")
    blocked = _blocked(validate_companion(doc))
    assert len(blocked) == 1
    assert "shares BOTH its id and its anchor kind" in blocked[0]
    assert "h-002" in blocked[0]


# F-12 — an id repeated inside ONE block is named, not deleted in silence

_REPEAT_REASON = (
    "'v-001' is declared twice in this block; only the FIRST row is kept and the later one "
    "is discarded with everything it declares. Give each row its own id, or send the added "
    "rows as a second block."
)

#: The ordinal typo, and the row it deletes — the one carrying the open slot.
_TYPO_ROW = "v-001|process|process:bash|bash[pid=42]|integrity=??"


def test_a_repeated_vertex_id_in_one_block_warns_instead_of_deleting_the_open_slot():
    """The document ACCEPTED `disposition benign` before this: the second row was dropped by
    `_extend_by_id` before the companion existed, and with it the only `??` on the page."""
    doc = _benign_doc(_vertices(_CLEAN_VERTEX, _TYPO_ROW))
    companion, warnings = parse_dense_companion(doc)
    assert [w.reason for w in warnings] == [_REPEAT_REASON]
    assert len(companion["prologue"]["vertices"]) == 1
    assert validate_companion(doc)


def test_the_two_hypothesis_declaration_sites_warn_on_the_same_shape():
    """The other two `_extend_by_id` sites, and the sharpest case of the same drop:"""
    rows = (
        "h-001|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active\n"
        "h-001|?scheduled-task|v-001|created|identity|service-account/known-corp||null|active"
    )
    hypothesize = _benign_doc(
        _vertices(_CLEAN_VERTEX),
        ":H hypothesize.hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        + rows,
    )
    lead_born = _benign_doc(
        _vertices(_CLEAN_VERTEX),
        ":H l-001.new_hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        + rows,
    )
    for doc in (hypothesize, lead_born):
        reasons = [w.reason for w in parse_dense_companion(doc)[1]]
        assert reasons == [_REPEAT_REASON.replace("'v-001'", "'h-001'")], doc
        assert validate_companion(doc), doc


def test_the_same_id_across_two_blocks_is_still_the_silent_legal_re_emission():
    doc = _benign_doc(_vertices(_CLEAN_VERTEX), _vertices(_CLEAN_VERTEX))
    assert parse_dense_companion(doc)[1] == []
    assert validate_companion(doc) == []


# F-6 — a blank refinement value resolves nothing

_OPEN_VERTEX = "v-001|compute|??/??/??|10.42.7.183|knowledge=??"


def _refined(*rows: str) -> str:
    return _benign_doc(
        _vertices(_OPEN_VERTEX),
        ":R attr_updates [resolved_by|target|key|value]\n" + "\n".join(rows),
    )


def test_a_blank_refinement_value_is_refused_and_clears_nothing():
    doc = _refined("l-001|v-001|class|", "l-001|v-001|attrs.knowledge|")
    errors = validate_companion(doc)
    empty = [e for e in errors if "the `value` cell" in e]
    assert len(empty) == 2
    assert all("settles nothing" in e for e in empty)
    assert len(_blocked(errors)) == 2


def test_a_blank_value_cannot_erase_a_value_the_document_settled():
    """The other direction of the same guard, and the one only the fold can show:"""
    doc = _benign_doc(
        _vertices(
            "v-001|compute|bastion/internal/known-corp|bastion-01.corp|knowledge=documented"
        ),
        ":R attr_updates [resolved_by|target|key|value]\n"
        "l-001|v-001|class|\n"
        "l-001|v-001|attrs.knowledge|",
    )
    companion, _warnings = parse_dense_companion(doc)
    state = effective_vertex_state(companion)["v-001"]
    assert state["classification"] == "bastion/internal/known-corp"
    assert state["attributes"]["knowledge"] == "documented"


def test_a_bad_key_with_a_blank_value_still_earns_only_the_key_warning():
    doc = _refined("l-001|v-001|knowledge|")
    assert [e for e in validate_companion(doc) if "the `value` cell" in e] == []


# F-26 — an unterminated candidate set in an ATTRIBUTE value blocks benign

def test_an_unterminated_candidate_set_in_an_attribute_blocks_benign():
    """The attribute-arm twin of #853's `test_an_unterminated_candidate_set_blocks_benign`,
    which covers only the class cell. One character, and the value read as a settled fact."""
    doc = _benign_doc(_vertices(
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|role={internal, dmz"
    ))
    blocked = _blocked(validate_companion(doc))
    assert len(blocked) == 1
    assert "'role'" in blocked[0]


# F-27 — a stray `:H l-NNN.<sub>` block stands nothing down

def _stray_doc(*extra: str) -> str:
    return _doc(
        _vertices(_CLEAN_VERTEX),
        ":H hypothesize.hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        "h-001|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active",
        ":L findings [id|loop|name|target|tests|system|window]\n"
        "l-001|1|cmdb-lookup|v-001|h-999|cmdb|n/a",
        *extra,
    )


def test_a_stray_lead_sub_block_no_longer_hides_a_phantom_hypothesis():
    """The stray block's own warning is error severity either way, so no write was ever at stake — the cost was diagnostic completeness."""
    stray = ":H l-001.preds [id|subject|claim]\np9|v-001|\"the host is a bastion\""
    errors = validate_companion(_stray_doc(stray))
    assert any("unknown lead sub-block" in e for e in errors), errors
    assert any("h-999" in e for e in errors), errors


def test_the_singular_new_hypothesis_typo_still_defers_for_its_own_ids():
    typo = (
        ":H l-001.new_hypothesis "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        "h-999|?forked-story|v-001|modified|identity|service-account/known-corp||null|active"
    )
    _companion, warnings = parse_dense_companion(_stray_doc(typo))
    assert deferred_hypothesis_ids(warnings) == frozenset({"h-999"})
    assert not [e for e in validate_companion(_stray_doc(typo)) if "h-999" in e]


# the silent-drop gate's own findings — baselined by #886, fixed here

def _conclude_table(block: str) -> str:
    return _benign_doc(_vertices(_CLEAN_VERTEX), block)


def test_a_surviving_row_with_no_hypothesis_id_is_named_not_dropped():
    """One guard carried two cases — the documented `none` empty-TABLE marker, and a row whose `hyp_id` cell is simply empty."""
    doc = _conclude_table(":T conclude.surviving [hyp_id|final_weight]\n|++")
    companion, warnings = parse_dense_companion(doc)
    assert len(warnings) == 1
    assert warnings[0].reason.startswith("surviving row has no hypothesis id")
    assert companion["conclude"]["surviving_hypotheses"] == []
    assert _parse_errors(validate_companion(doc))


def test_an_empty_table_written_as_the_none_marker_stays_silent():
    for block in (
        ":T conclude.surviving [hyp_id|final_weight]\nnone",
        ":T conclude.surviving [hyp_id|final_weight]\nn/a",
    ):
        doc = _conclude_table(block)
        assert parse_dense_companion(doc)[1] == [], block
        assert validate_companion(doc) == [], block


def test_a_hypothesis_row_with_an_empty_id_is_refused_once_not_twice():
    """The third baselined finding, and the one that is NOT a drop."""
    doc = _benign_doc(
        _vertices(_CLEAN_VERTEX),
        ":H hypothesize.hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        "|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active",
    )
    companion, warnings = parse_dense_companion(doc)
    assert [w.reason for w in warnings] == ["hypothesis missing id/name"]
    assert companion.get("hypothesize", {}).get("hypotheses", []) == []
