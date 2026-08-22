"""#876 — six more parser/validator gaps, five of which end at the same benign write gate.

The direct successor to #853 and against the same gate, so this suite is shaped like its
sibling: every fixture is a WHOLE document run through the real `parse_dense_companion` /
`validate_companion`, because the defects are observable in what the gate CONCLUDES, not in
what any unit returns. Each negative case is paired with the control that keeps the fix from
being "deny everything".

  F-2   `HEADER_RE` anchors `\\s*$` after the optional `[cols]`, so a trailing `# comment`
        made the header a non-header — and `_tokenize_fence` then discarded it together with
        every row beneath it, silently. A `:T conclude   # loop 2 wrap-up` fence parsed to an
        EMPTY companion with no warnings, so the benign gate never ran at all.
  F-3   `_check_authz_contract_ids` exempts a contract-id collision whose other side is
        refuted, on the true premise that a refuted contract discharges nothing. The premise
        is false of the ROW: `_check_benign_authz` resolves by bare id, so the refuted
        declarer's `:R authz` row discharged the LIVE declarer's same-numbered contract. A
        shared id is scoped by ANCHOR KIND now — the column that says which question a row
        answers — which closes the gap and still leaves the author an append that repairs it.
  F-12  Four `_extend_by_id` graph-row sites had no repeated-id check, and `_extend_by_id`
        keeps the FIRST record per id — so a second row repeating `v-001` by an ordinal typo
        was deleted before the companion existed, with the open slot it carried.
  F-6   `_apply_attr_updates` assigned a refinement value unconditionally, and `""` is read
        as neither open nor unresolved — so a present-but-blank value cell did not downgrade
        the slot, it RESOLVED it.
  F-26  `is_unresolved` required `{` AND `}`, so an unterminated candidate set in an
        ATTRIBUTE value read as a settled fact. The class arm has carried a count guard for
        the same one-character typo since #853/F-15.
  F-27  The catch-all `:H l-NNN.<sub>` warning filled `dropped_ids` with every row's first
        cell, asserting they are hypothesis ids. For any sub-name but the singular
        `new_hypothesis` typo they are not, and `deferred_hypothesis_ids` then stood the
        undeclared-hypothesis rule down for the whole document — costing a round trip, not a
        write.

The last section is not one of the six. `lint_silent_row_drop` (#886) shipped with three
parser drops baselined as true positives it was forbidden to fix, annotated "filed as #876"
— which #876's six findings never carried. They are fixed here, so the gate's baseline holds
nothing but false positives; one of the three turned out not to be a drop at all.
"""

from __future__ import annotations

from defender.skills.invlang.parser import (
    deferred_hypothesis_ids,
    parse_dense_companion,
)
from defender.skills.invlang.validate import (
    effective_vertex_state,
    validate_companion,
)

# --------------------------------------------------------------------------- #
# document fixtures — the #853 suite's shapes, so a reader who knows one knows both
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


# --------------------------------------------------------------------------- #
# F-2 — a header the regex rejects no longer vaporizes its block
# --------------------------------------------------------------------------- #

#: The two spellings that reach the tokenizer's silent path in the ordinary authoring loop.
#: `append_block` sends ONE block per fence (`runtime/tools.py`), so the rejected header is
#: the FIRST in its fence, which is exactly the case where no block is open to absorb it.
_REJECTED_HEADERS = (
    ":T conclude   # loop 2 wrap-up",
    ":T conclude (loop 3)",
)


def _conclude_fence(header: str) -> str:
    return _doc(header + "\n" + _CONCLUDE_BENIGN.strip("\n").split("\n", 1)[1])


def test_a_trailing_comment_on_a_header_no_longer_deletes_the_whole_block():
    """The defect in one document: byte-identical conclude rows, one character of habit from
    every other fenced language, and the block was gone with `warnings == []`. The benign
    disposition then never reached `_check_disposition_gating` — it dispatches on
    `companion["conclude"]`, and there was no conclude to dispatch on."""
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


def test_the_dropped_rows_are_counted_in_the_one_warning_the_header_earns():
    """ONE warning per run of orphan lines, not one per line: the rejected header is the
    whole repair, and a seven-row `:T conclude` would otherwise cost eight errors for one
    trailing comment. What followed it is still named, as a count."""
    doc = _conclude_fence(_REJECTED_HEADERS[0])
    _companion, warnings = parse_dense_companion(doc)
    assert len(warnings) == 1
    assert "the 6 line(s) under it" in warnings[0].reason


def test_a_rejected_prologue_header_is_refused_rather_than_returning_nothing():
    """The other half of the same silence, on a fresh document: the whole prologue gone, with
    zero diagnostics. `parse_dense_companion` used to return early on the empty block list —
    which is the path a fence whose FIRST header was rejected always takes."""
    doc = _doc(_vertices(_CLEAN_VERTEX).replace(
        ":V prologue.vertices [id|type|class|ident|attrs?]",
        ":V prologue.vertices [id|type|class|ident|attrs?]   # loop 2",
    ))
    companion, warnings = parse_dense_companion(doc)
    assert companion == {}
    assert len(warnings) == 1
    assert _parse_errors(validate_companion(doc))


def test_a_header_rejected_after_a_good_block_still_earns_its_own_warning():
    """The rejected header is not always first. With a block still open the line lands as a
    ROW of that block and draws a cell-count error — loud, and already refused before this
    fix — so the assertion here is that the document is still refused and the good block is
    still projected, not that the warning changed shape."""
    doc = _benign_doc(
        _vertices(_CLEAN_VERTEX) + "\n:V prologue.vertices [id|type]   # second block"
    )
    companion, warnings = parse_dense_companion(doc)
    assert [v["id"] for v in companion["prologue"]["vertices"]] == ["v-001"]
    assert warnings
    assert validate_companion(doc)


def test_a_clean_header_and_a_story_section_are_unchanged():
    """The controls the fix is bounded by: the same document with the comment removed closes
    benign, and a `### story h-NNN` section's PROSE is narrative by construction — there is
    no row there to land and nothing to warn about."""
    clean = _benign_doc(_vertices(_CLEAN_VERTEX))
    assert parse_dense_companion(clean)[1] == []
    assert validate_companion(clean) == []

    storied = _benign_doc(
        _vertices(_CLEAN_VERTEX),
        "### story h-001\nThe operator logged in from the bastion, as they do every morning.",
    )
    assert parse_dense_companion(storied)[1] == []
    assert validate_companion(storied) == []


def test_a_story_section_does_not_swallow_the_rejected_header_under_it():
    """The gap the story arm left open, which is F-2 whole: `in_story` ended only at an
    ACCEPTED header, so a `### story h-NNN` section standing above a rejected one swallowed
    the header AND every row beneath it — an EMPTY companion, `warnings == []`, and the benign
    gate never dispatched. A header ATTEMPT ends the story now."""
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


def test_each_rejected_header_earns_its_own_warning():
    """One warning covers the ROWS a rejected header takes down, not the next header the
    author also has to fix: repairing the first opens a block, and a second rejected header
    would then land in it as a bad row, for a second round trip over a defect the document had
    already stated."""
    doc = _doc(
        _REJECTED_HEADERS[0] + "\ndisposition|benign",
        ":V prologue.vertices [id|type|class|ident|attrs?]   # loop 3\n" + _CLEAN_VERTEX,
    )
    warnings = parse_dense_companion(doc)[1]
    assert [w.row for w in warnings] == [
        _REJECTED_HEADERS[0],
        ":V prologue.vertices [id|type|class|ident|attrs?]   # loop 3",
    ]


# --------------------------------------------------------------------------- #
# F-3 — a refuted hypothesis's row discharges nothing of a live one's
# --------------------------------------------------------------------------- #

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
    """The collision error's own remedy text says "or refute one of them, if the evidence
    says so" — and taking it used to convert a refusal into a DISCHARGE. h-001's
    change-management question was never asked, and an iam-policy answer closed it."""
    blocked = _blocked(validate_companion(_shared_id_doc("ac1")))
    assert len(blocked) == 1
    assert "ac1" in blocked[0]
    assert "h-001" in blocked[0]
    assert "also declared by h-002" in blocked[0]
    assert "change-mgmt" in blocked[0]


def test_the_shared_id_is_repairable_by_the_append_the_error_names():
    """What the "ignore an ambiguous row entirely" reading would have cost: `:H` rows are
    immutable, so a live contract holding a shared `ac1` can never be renumbered, and benign
    would be unreachable for the rest of that document's life. Writing the row that carries
    THIS contract's anchor kind is an ordinary append, and it discharges it."""
    doc = _shared_id_doc("ac1").replace(
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n",
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        'l-001|e-001|ac1|authorized|change-mgmt|"CHG-4471 covers the window"\n',
    )
    assert validate_companion(doc) == []


def test_a_contract_with_no_anchor_kind_never_reaches_the_scoping_at_all():
    """What makes `anchor_kind` a usable discriminator rather than one more cell that might say
    nothing: `_hyp_sub_authz_row` requires it, so a contract without one is a parse error and
    never reaches the companion. There is no "both sides blank" case for the scoping to answer.
    """
    doc = _shared_id_doc("ac1").replace(
        'ac1|e-001|change-mgmt|"approved change ticket exists"',
        'ac1|e-001||"approved change ticket exists"',
    )
    companion, warnings = parse_dense_companion(doc)
    assert [w.reason for w in warnings] == ["authz row missing id/anchor_kind"]
    assert companion["hypothesize"]["hypotheses"][0].get("authorization_contract") is None
    assert _parse_errors(validate_companion(doc))


def test_a_shared_id_AND_a_shared_anchor_kind_discharges_nothing():
    """The case with no honest reading left: two declarers asking the SAME question under the
    same id. No row can be attributed, so none discharges — and unlike the differing-anchor
    case there is no append that repairs it, which is why the both-live spelling is refused
    at the declaring site before it can ever get here."""
    doc = _shared_id_doc("ac1").replace("iam-policy", "change-mgmt")
    blocked = _blocked(validate_companion(doc))
    assert len(blocked) == 1
    assert "shares BOTH its id and its anchor kind" in blocked[0]
    assert "h-002" in blocked[0]


def test_the_repair_the_error_asks_for_still_closes():
    """The control on the fix: with h-002's contract given an id of its own — the repair the
    new error names — nothing is ambiguous, and h-001's contract is simply unfulfilled. The
    error is the ordinary one, so the fix has not turned a distinct-id document into a
    permanently refused one."""
    blocked = _blocked(validate_companion(_shared_id_doc("ac2")))
    assert len(blocked) == 1
    assert "no fulfilling :R authz row" in blocked[0]
    assert "ac1" in blocked[0]
    assert "h-001" in blocked[0]


def test_a_live_contract_with_an_unambiguous_row_still_discharges():
    """The other control, and the one that keeps the fix from being "deny every authz": with
    the ids distinct, h-001's contract is discharged by its id alone — the anchor-kind scoping
    applies only where an id is shared, so a document that left the cell empty is unaffected.
    """
    doc = _shared_id_doc("ac2").replace(
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n",
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        'l-001|e-001|ac1|authorized|change-mgmt|"CHG-4471 covers the window"\n',
    )
    assert validate_companion(doc) == []


# --------------------------------------------------------------------------- #
# F-12 — an id repeated inside ONE block is named, not deleted in silence
# --------------------------------------------------------------------------- #

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


def test_the_corrected_ordinal_is_what_the_deleted_row_was_hiding():
    """The same document with the typo repaired: the row lands, and the gate refuses the
    close on the open slot it carries. This is the outcome the silent drop was buying."""
    doc = _benign_doc(_vertices(_CLEAN_VERTEX, _TYPO_ROW.replace("v-001", "v-002", 1)))
    assert parse_dense_companion(doc)[1] == []
    blocked = _blocked(validate_companion(doc))
    assert len(blocked) == 1
    assert "v-002" in blocked[0]
    assert "'integrity'" in blocked[0]


def test_the_other_three_graph_row_sites_warn_on_the_same_shape():
    """`:E prologue.edges` and both lead observation blocks, which `runtime/review/projector`
    also maps straight to the review lenses with none of the walkers' dedup."""
    edge = ":E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n"
    both = (
        "e-001|modified|v-001|v-001|2026-05-07T14:25:22.570Z|siem-event:wazuh|\n"
        "e-001|authenticated_as|v-001|v-001|2026-05-07T14:26:00.000Z|siem-event:wazuh|"
    )
    prologue_edges = _benign_doc(_vertices(_CLEAN_VERTEX), edge + both)
    obs_vertices = _benign_doc(
        _vertices(_CLEAN_VERTEX),
        ":V l-001.observations.vertices [id|type|class|ident|attrs?]\n"
        + _CLEAN_VERTEX + "\n" + _TYPO_ROW,
    )
    obs_edges = _benign_doc(
        _vertices(_CLEAN_VERTEX),
        ":E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]\n" + both,
    )
    for doc, rid in (
        (prologue_edges, "e-001"), (obs_vertices, "v-001"), (obs_edges, "e-001"),
    ):
        reasons = [w.reason for w in parse_dense_companion(doc)[1]]
        assert reasons == [_REPEAT_REASON.replace("'v-001'", f"{rid!r}")], rid
        assert validate_companion(doc), rid


def test_the_two_hypothesis_declaration_sites_warn_on_the_same_shape():
    """The other two `_extend_by_id` sites, and the sharpest case of the same drop: a repeated
    `h-001` deletes a whole hypothesis — story, anchor, status — and every `:H h-001.authz`
    contract in the document then attaches to the SURVIVING row, so the benign gate discharges
    a contract the deleted hypothesis never got to state. `_register_hypotheses` cannot catch
    it: it is written against the cross-BLOCK re-emission, where the first declaration standing
    silently is the sanctioned append-only shape."""
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
    """The control the helper is bounded by, and the reason it compares only the rows of the
    block in hand: append-only makes a SECOND `:V prologue.vertices` the sanctioned way to
    add a vertex, and re-sending a committed row there is a re-emission, not a repeat."""
    doc = _benign_doc(_vertices(_CLEAN_VERTEX), _vertices(_CLEAN_VERTEX))
    assert parse_dense_companion(doc)[1] == []
    assert validate_companion(doc) == []


# --------------------------------------------------------------------------- #
# F-6 — a blank refinement value resolves nothing
# --------------------------------------------------------------------------- #

_OPEN_VERTEX = "v-001|compute|??/??/??|10.42.7.183|knowledge=??"


def _refined(*rows: str) -> str:
    return _benign_doc(
        _vertices(_OPEN_VERTEX),
        ":R attr_updates [resolved_by|target|key|value]\n" + "\n".join(rows),
    )


def test_a_blank_refinement_value_is_refused_and_clears_nothing():
    """Two present-but-empty value cells used to make both benign errors vanish and the
    document accept. The row is refused now, and the guard on the fold means the open slots
    are still open even on a document that never went through the gate."""
    doc = _refined("l-001|v-001|class|", "l-001|v-001|attrs.knowledge|")
    errors = validate_companion(doc)
    empty = [e for e in errors if "the `value` cell" in e]
    assert len(empty) == 2
    assert all("settles nothing" in e for e in empty)
    assert len(_blocked(errors)) == 2


def test_a_whitespace_only_refinement_value_reads_the_same_way():
    doc = _refined("l-001|v-001|attrs.knowledge|   ")
    assert [e for e in validate_companion(doc) if "the `value` cell" in e]
    assert _blocked(validate_companion(doc))


def test_a_blank_value_cannot_erase_a_value_the_document_settled():
    """The other direction of the same guard, and the one only the fold can show: erasing a
    RESOLVED class or attribute to `""` moves no gate — `has_open_slot("")` is False — so
    the damage is silent and lands on every reader of the effective state, the review lenses
    included. The row is refused either way; this is what the guard keeps true for a document
    that never went through the gate."""
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


def test_a_real_refinement_still_closes_benign():
    """The positive control the fix had to keep green — the documented `?? -> {a, b, c} ->
    concrete` progression still terminates."""
    doc = _refined(
        "l-001|v-001|class|monitoring-agent/internal/known-corp",
        "l-001|v-001|attrs.knowledge|documented",
    )
    assert validate_companion(doc) == []


def test_a_bad_key_with_a_blank_value_still_earns_only_the_key_warning():
    """The bad-KEY family stays warn severity because that row is INERT — it changes no
    effective state, so its empty value changes nothing either. Only a row that would have
    been applied earns the refusal."""
    doc = _refined("l-001|v-001|knowledge|")
    assert [e for e in validate_companion(doc) if "the `value` cell" in e] == []


# --------------------------------------------------------------------------- #
# F-26 — an unterminated candidate set in an ATTRIBUTE value blocks benign
# --------------------------------------------------------------------------- #

def test_an_unterminated_candidate_set_in_an_attribute_blocks_benign():
    """The attribute-arm twin of #853's `test_an_unterminated_candidate_set_blocks_benign`,
    which covers only the class cell. One character, and the value read as a settled fact."""
    doc = _benign_doc(_vertices(
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|role={internal, dmz"
    ))
    blocked = _blocked(validate_companion(doc))
    assert len(blocked) == 1
    assert "'role'" in blocked[0]


def test_the_three_neighbours_of_that_typo_are_unchanged():
    """The closed set, the `??`, and the identical dropped brace in the CLASS cell — all
    three were already refused, which is what made the attribute arm the gap."""
    closed = _benign_doc(_vertices(
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|role={internal, dmz}"
    ))
    unknown = _benign_doc(_vertices(
        "v-001|compute|bastion/internal/known-corp|bastion-01.corp|role=??"
    ))
    in_class = _benign_doc(_vertices(
        "v-001|compute|bastion/{internal, dmz|bastion-01.corp|"
    ))
    for doc in (closed, unknown, in_class):
        assert _blocked(validate_companion(doc))


def test_a_value_that_merely_contains_a_brace_still_closes():
    """Not a brace COUNT — the whole-value anchor is what keeps the fix narrow. A shell
    command carrying an unclosed `{` does not START with one, and an `attrs.cmdline` with a
    balanced `{...}` inside a longer string is a fact, not an open question."""
    for value in ("cmdline=bash -c 'for i in {1..5'", "cmdline=deploy-{blue}-svc"):
        doc = _benign_doc(_vertices(
            f"v-001|compute|bastion/internal/known-corp|bastion-01.corp|{value}"
        ))
        assert validate_companion(doc) == [], value


# --------------------------------------------------------------------------- #
# F-27 — a stray `:H l-NNN.<sub>` block stands nothing down
# --------------------------------------------------------------------------- #

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
    """The stray block's own warning is error severity either way, so no write was ever at
    stake — the cost was diagnostic completeness. The author repaired the stray block,
    re-sent, and only then learned about the phantom `h-999`: one extra round trip on a
    document that had already told the validator everything it needed."""
    stray = ":H l-001.preds [id|subject|claim]\np9|v-001|\"the host is a bastion\""
    errors = validate_companion(_stray_doc(stray))
    assert any("unknown lead sub-block" in e for e in errors), errors
    assert any("h-999" in e for e in errors), errors


def test_the_stray_block_defers_for_no_id_at_all():
    """The mechanism under it: `deferred_hypothesis_ids` returns `None` — "stand down
    everywhere" — when a dropped declaration cannot be mapped to an id, and an unfiltered
    `p9` was exactly such an id. Filtered, the warning names nothing and is SKIPPED, which
    is the honest answer for a block that deleted no declaration."""
    stray = ":H l-001.preds [id|subject|claim]\np9|v-001|\"the host is a bastion\""
    _companion, warnings = parse_dense_companion(_stray_doc(stray))
    assert deferred_hypothesis_ids(warnings) == frozenset()


def test_the_singular_new_hypothesis_typo_still_defers_for_its_own_ids():
    """The case the branch was written for, and the case the filter must not break: the
    typo's dropped rows ARE hypothesis declarations, and their ids are the only channel by
    which the rule can know to stay quiet about them."""
    typo = (
        ":H l-001.new_hypothesis "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        "h-999|?forked-story|v-001|modified|identity|service-account/known-corp||null|active"
    )
    _companion, warnings = parse_dense_companion(_stray_doc(typo))
    assert deferred_hypothesis_ids(warnings) == frozenset({"h-999"})
    assert not [e for e in validate_companion(_stray_doc(typo)) if "h-999" in e]


# --------------------------------------------------------------------------- #
# the silent-drop gate's own findings — baselined by #886, fixed here
# --------------------------------------------------------------------------- #

def _conclude_table(block: str) -> str:
    return _benign_doc(_vertices(_CLEAN_VERTEX), block)


def test_a_surviving_row_with_no_hypothesis_id_is_named_not_dropped():
    """One guard carried two cases — the documented `none` empty-TABLE marker, and a row
    whose `hyp_id` cell is simply empty. The second is a drop: the row vanished from
    `conclude.surviving_hypotheses` with nothing raised, and the close then reasoned over a
    shortened survivor set no reader could tell from an honestly shorter one."""
    doc = _conclude_table(":T conclude.surviving [hyp_id|final_weight]\n|++")
    companion, warnings = parse_dense_companion(doc)
    assert len(warnings) == 1
    assert warnings[0].reason.startswith("surviving row has no hypothesis id")
    assert companion["conclude"]["surviving_hypotheses"] == []
    assert _parse_errors(validate_companion(doc))


def test_an_empty_table_written_as_the_none_marker_stays_silent():
    """The control that makes the guard above honest. `_row_cells` pads a lone `none` row to
    the block's width, so the marker arrives as a real record with `hyp_id="none"` — a run
    that carried nothing into the close must not be told it wrote a bad row."""
    for block in (
        ":T conclude.surviving [hyp_id|final_weight]\nnone",
        ":T conclude.surviving [hyp_id|final_weight]\nn/a",
    ):
        doc = _conclude_table(block)
        assert parse_dense_companion(doc)[1] == [], block
        assert validate_companion(doc) == [], block


def test_a_hypothesis_row_with_an_empty_id_is_refused_once_not_twice():
    """The third baselined finding, and the one that is NOT a drop. `_hypothesis_record`
    `_require`s `id` and `name`, so the row raises `RowError` and is warned before any record
    exists — nothing that reaches `_register_hypotheses`' `isinstance` guard can fail it. A
    warning there would be a second diagnostic for a defect already named."""
    doc = _benign_doc(
        _vertices(_CLEAN_VERTEX),
        ":H hypothesize.hypotheses "
        "[id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]\n"
        "|?gpo-edit|v-001|modified|identity|service-account/known-corp||null|active",
    )
    companion, warnings = parse_dense_companion(doc)
    assert [w.reason for w in warnings] == ["hypothesis missing id/name"]
    assert companion.get("hypothesize", {}).get("hypotheses", []) == []
