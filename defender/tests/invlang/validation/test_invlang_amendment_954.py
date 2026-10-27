"""invlang amendments: a repeated lead id in one `:L findings` block is first-wins with a diagnostic and a refused write; `_check_attr_update_keys` repair suggestions re-split to the declared width or are withheld."""
from __future__ import annotations

import pytest

from defender.tests.support.invlang.validation._invlang_amendment_954 import (
    CONCLUDE_BENIGN,
    CONCLUDE_FALSE_POSITIVE,
    OPTIONAL_ATTR_HEADER,
    REPEAT_PHRASE,
    STRAND_FINDINGS_HEADER,
    UNDECLARED_LEAD_PHRASE,
    VERTICES,
    VERTICES_FREEFORM_CLASS,
    VERTICES_WITH_AN_ESCAPED_PIPE_ID,
    VERTICES_WITH_A_QUOTED_PIPE_ID,
    attr_block,
    attr_doc,
    cells,
    close_block,
    diagnostics,
    entry_price,
    findings_block,
    key_warning,
    leads,
    main_deps,
    repeat_diagnostics,
    seed_investigation,
    warnings_of,
)

# F-46 rows. Two rows for one lead, disagreeing on every non-empty cell they share, so no
# assertion below can be satisfied by an implementation that merges instead of choosing.

#: The row a first-wins fold must keep, whole.
FIRST_ROW = "l-001|1|alpha|v-001||cmdb|24h"
#: The row it must discard, with everything that row declares.
LATER_ROW = "l-001|2|beta|v-002||edr|48h"
#: A third row for the same id — F-C's count case.
THIRD_ROW = "l-001|3|gamma|v-002||edr|72h"
#: A DIFFERENT lead in the same block. The complementary condition for every negative here.
OTHER_ROW = "l-002|1|delta|v-002||edr|48h"

#: EXECUTED at base: one bucket, every non-empty field the LATER row's, `warnings == []`.
REPEAT_DOC = VERTICES + findings_block(FIRST_ROW, LATER_ROW)
#: The same document with the later row never written — what O3 says the repeat must read as.
FIRST_ONLY_DOC = VERTICES + findings_block(FIRST_ROW)
#: ...and with the first row never written, so a test can tell the two readings apart.
LATER_ONLY_DOC = VERTICES + findings_block(LATER_ROW)
#: EXECUTED at base: two buckets, no warning. D5's complementary condition.
TWO_IDS_DOC = VERTICES + findings_block(FIRST_ROW, OTHER_ROW)


def _flagged(text):
    """The repair window as `fix_row` addresses it — one `locus.row_text` per warn
    diagnostic."""
    from defender.skills.invlang.validate import warn_diagnostics

    return [d.locus.row_text for d in warn_diagnostics(text) if d.locus is not None]


def _append(deps, text):
    from defender.investigation.tools import _tool_append_block

    return _tool_append_block(deps, text)


def _fix(deps, old_row, new_row):
    from defender.investigation.tools import _tool_fix_row

    return _tool_fix_row(deps, old_row, new_row)


def _inv(run):
    return (run / "investigation.md").read_text(encoding="utf-8")


# F-46 — the repeated lead id

def test_repeated_lead_id_returns_a_first_wins_bucket_and_an_error_diagnostic():
    """`parse_dense_companion` over a `:L findings` block listing one lead id twice returns ONE ParseWarning per EXTRA row in slot 2 and, in slot 1, exactly one `lead_bucket` for that id holding the FIRST row's values in identity, outcome and query_details alike;"""
    warnings = warnings_of(REPEAT_DOC)
    repeats = [w for w in warnings if REPEAT_PHRASE in w.reason]
    assert len(repeats) == 1, f"one warning per extra row, got {[w.reason for w in warnings]}"
    assert repeats[0].row_index == -1
    assert repeats[0].row == ""

    buckets = leads(REPEAT_DOC)
    assert len(buckets) == 1, "the repeat is ONE lead, not two"
    lead = buckets[0]
    assert lead["id"] == "l-001"
    assert lead["name"] == "alpha", "the FIRST row's name, whole"
    assert lead["target"] == "v-001"
    assert lead["loop"] == 1, "`loop` is coerced through int() — never the string '1'"
    assert lead["query_details"] == {"system": "cmdb", "time_window": "24h"}
    assert "window" not in lead
    assert "fail_reason" not in lead
    assert lead == leads(FIRST_ONLY_DOC)[0], "the repeat reads as the first row alone"

    diags = repeat_diagnostics(REPEAT_DOC)
    assert len(diags) == 1
    assert diags[0].severity == "error"
    assert diags[0].locus is not None
    assert diags[0].locus.row_text == ""
    assert diags[0].locus.row_index == -1


def test_repeated_lead_id_in_one_block_is_named_in_a_parse_diagnostic():
    """A `:L findings` block listing one lead id twice gains a `parse_warnings` diagnostic that NAMES that id, and `lead_bucket` keeps the id it names (O1, D1)."""
    diags = repeat_diagnostics(REPEAT_DOC)
    assert len(diags) == 1
    assert "'l-001'" in diags[0].message, diags[0].message
    assert [b["id"] for b in leads(REPEAT_DOC)] == ["l-001"]


def test_repeated_lead_id_refuses_the_write_and_commits_nothing(tmp_path):
    """`append_block` proposing a `:L findings` block that lists one lead id twice is refused through the real write gate — `validate_investigation` over the full proposed text, via `decide_write` — and `investigation_md` is left exactly as it stood (O2, D2)."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, VERTICES)

    with pytest.raises(ModelRetry) as exc:
        _append(deps, findings_block(FIRST_ROW, LATER_ROW))

    assert "failed invlang validation" in str(exc.value)
    assert REPEAT_PHRASE in str(exc.value)
    assert "No changes were made" in str(exc.value)
    assert _inv(run) == VERTICES, "a refused append must commit nothing"

    # The control: the same block with the repeat removed lands.
    _append(deps, findings_block(FIRST_ROW))
    assert FIRST_ROW in _inv(run)


def test_relisting_a_lead_overwrites_a_conflicting_non_empty_cell():
    """A lead re-listed in a SECOND `:L findings` block still merges into its existing `lead_bucket`, the later block winning on a conflicting NON-EMPTY cell, with no diagnostic (O4, D4b)."""
    doc = (
        VERTICES
        + findings_block("l-001|1|alpha|v-001||cmdb|24h|timeout")
        + findings_block("l-001|2|beta|v-002||edr|48h|network-error")
    )
    assert repeat_diagnostics(doc) == [], "a CROSS-block re-listing is the legal amendment"

    lead = leads(doc)[0]
    assert lead["name"] == "beta"
    assert lead["target"] == "v-002"
    assert lead["loop"] == 2
    assert lead["query_details"]["system"] == "edr"
    assert lead["query_details"]["time_window"] == "48h"
    assert lead["outcome"]["failure_reason"] == "network-error"


def test_a_block_without_a_repeated_id_gains_no_diagnostic():
    """A `:L findings` block whose ids are all distinct gains NO repeated-id diagnostic on any surface the finding could reach — `parse_warnings`, `diagnose`, or the write gate's refusal text — and both leads project (O5, D5)."""
    from defender.records._artifact_schema import validate_investigation

    assert [w.reason for w in warnings_of(TWO_IDS_DOC) if REPEAT_PHRASE in w.reason] == []
    assert repeat_diagnostics(TWO_IDS_DOC) == []
    assert validate_investigation(TWO_IDS_DOC, None) is None
    assert [b["id"] for b in leads(TWO_IDS_DOC)] == ["l-001", "l-002"], (
        "the channel is non-empty: both leads are really there to be flagged"
    )

    # The complementary condition, on the same address: the mechanism DOES fire.
    assert len(repeat_diagnostics(REPEAT_DOC)) == 1


def test_the_surviving_lead_stays_declared_for_every_reader_that_names_it():
    """The lead that survives a within-block repeat is still DECLARED at BOTH readers that decide a lead id's declaredness — `check_lead_refs`, which raises "undeclared lead", and the false-positive entry pr"""
    refined = REPEAT_DOC + attr_block("l-001|v-001|class|file-server/internal/known-corp")
    diags = diagnostics(refined)
    assert [d.message for d in diags if UNDECLARED_LEAD_PHRASE in d.message] == []
    assert len([d for d in diags if REPEAT_PHRASE in d.message]) == 1

    # The second declaredness reader, on a document that closes false-positive: the survivor
    # resolves and its own target check passes, so nothing is owed.
    both_in_prologue = VERTICES + findings_block(
        "l-001|1|alpha|v-001||cmdb|24h",
        "l-001|2|beta|v-001||edr|48h",
    ) + attr_block("l-001|v-001|class|file-server/internal/known-corp") + CONCLUDE_FALSE_POSITIVE
    assert entry_price("false-positive", both_in_prologue) == ()

    # ...and it CAN say the id is undeclared, so the assertion above is not vacuous.
    undeclared = VERTICES + findings_block(
        "l-002|1|alpha|v-001||cmdb|24h"
    ) + CONCLUDE_FALSE_POSITIVE
    assert any("not a lead" in owed for owed in entry_price("false-positive", undeclared))

    # F-K's own case: first-wins STRANDS the later row's `mode`, so the screen-structure gate
    # raises a secondary finding against a row the author wrote correctly. That is accepted.
    stranded = VERTICES + findings_block(
        "l-001|1|alpha|v-001||cmdb|24h|||no_match",
        "l-001|2|beta|v-001||edr|48h||screen|",
    ) + attr_block("l-001|v-001|class|file-server/internal/known-corp")
    stranded_diags = diagnostics(stranded)
    assert [d.message for d in stranded_diags if UNDECLARED_LEAD_PHRASE in d.message] == []
    assert len([d for d in stranded_diags if REPEAT_PHRASE in d.message]) == 1


def test_id_comparison_is_byte_exact_across_quoting_padding_and_case():
    """"Same lead id" means the same cell BYTES:"""
    for spelling in ('"l-001"', '"  l-001  "', "L-001"):
        doc = VERTICES + findings_block(FIRST_ROW, f"{spelling}|2|beta|v-002||edr|48h")
        assert repeat_diagnostics(doc) == [], f"{spelling} is not the same bytes as l-001"
        assert [b["id"] for b in leads(doc)] == ["l-001", spelling]

    # The complementary condition: the same bytes twice DO collide.
    assert len(repeat_diagnostics(REPEAT_DOC)) == 1


def test_a_blank_cell_in_an_amending_row_does_not_erase_the_earlier_value():
    """A blank cell in a row that amends a lead from a SECOND block does not erase the value an earlier block landed — but `name` and `target` are taken UNCONDITIONALLY, so a blank `target` does overwrite with `""` (F-J, D27)."""
    doc = (
        VERTICES
        + findings_block(
            "l-001|1|alpha|v-001||cmdb|24h|timeout|screen|no_match|yes|open",
            header=STRAND_FINDINGS_HEADER,
        )
        + findings_block("l-001||beta|||||||||", header=STRAND_FINDINGS_HEADER)
    )
    lead = leads(doc)[0]
    # C1's five, every one: blank in the amending row, and every one survives.
    assert lead["loop"] == 1, "a blank `loop` cell does not erase the earlier loop"
    assert lead["mode"] == "screen"
    assert lead["trust_root_reached"] == "yes"
    assert lead["screen_result"] == "no_match"
    assert lead["status"] == "open"
    # ...and the three C1 does not name that behave the same way for a different reason —
    # `query_details` and `outcome` are merged sub-dicts, so an absent key writes nothing.
    assert lead["query_details"]["system"] == "cmdb"
    assert lead["query_details"]["time_window"] == "24h"
    assert lead["outcome"]["failure_reason"] == "timeout"
    # The two the amending row takes UNCONDITIONALLY.
    assert lead["name"] == "beta"
    assert lead["target"] == "", "`target` is taken unconditionally — C1 does not cover it"
    assert repeat_diagnostics(doc) == [], "a CROSS-block re-listing is the legal amendment"


# F-47 — the repair suggestion

#: The escaped-pipe trigger, RIGHT of the key cell. EXECUTED at base: both candidates split to
#: FIVE cells under a four-column header, which is the second refusal F-47 describes.
ESCAPED_PIPE_ROW = r"l-001|v-001|bogus|curl\|bash"
#: EXECUTED at base: `_swap_cell` normalises the padding away and the result keeps the declared
#: width — so a width guard alone cannot see this one.
PADDED_ROW = "l-001| v-001 |bogus|hello"
#: An escaped pipe INSIDE the key cell, on a row that still splits to four. EXECUTED at base:
#: `…|class|hello` splits to 4 and `…|attrs.a|b|hello` to 5 — exactly one candidate fails.
ASYMMETRIC_ROW = r"l-001|v-001|a\|b|hello"
ESCAPED_PIPE_LEFT_ROW = r"l-001|bastion\|01|owner|svc.config-mgmt"
MID_TOKEN_QUOTE_ROW = 'l-001|v-001|"class"|hello'


def test_suggestion_splits_back_to_the_declared_column_count():
    """Every candidate `check_attr_update_keys` writes into `fix` re-splits to exactly the column count `attr_updates_block` declares, for both repair routes `attr_update_keys` offers — `class` and `attrs.<key>` — with the author's escaped pipe intact (O6, D6)."""
    doc = attr_doc(ESCAPED_PIPE_ROW, prologue=VERTICES_FREEFORM_CLASS)
    d = key_warning(doc)
    assert d.fix, "both candidates survive this row; withholding here loses a working repair"
    for candidate in d.fix:
        assert len(cells(candidate)) == 4, f"{candidate!r} re-splits to {len(cells(candidate))}"
        assert r"curl\|bash" in candidate, "the value cell is the author's bytes"
    assert d.fix[0] == r"l-001|v-001|class|curl\|bash"
    assert d.fix[1] == r"l-001|v-001|attrs.bogus|curl\|bash"


def test_withheld_suggestion_is_an_empty_fix_tuple_on_a_still_flagged_row():
    """When a candidate cannot satisfy O6 the whole suggestion is withheld:"""
    from defender.records._artifact_schema import render_diagnostic

    doc = attr_doc(ASYMMETRIC_ROW)
    d = key_warning(doc)
    assert d.fix == ()
    assert d.severity == "warning"
    assert d.locus is not None
    assert d.locus.row_text == ASYMMETRIC_ROW
    assert "withheld" in d.message.lower(), (
        "the renderer cannot signal suppression, so the message must"
    )
    assert "use:" not in render_diagnostic(d)

    # A withheld fix does not change which rows stay flagged in the same block.
    both = attr_doc(ASYMMETRIC_ROW, PADDED_ROW)
    assert _flagged(both) == [ASYMMETRIC_ROW, PADDED_ROW]


def test_suggestion_differs_from_the_authors_row_in_the_key_cell_only():
    """A candidate is byte-identical to `locus.row_text` in every cell the author wrote, and differs only in the key cell (O8, D8)."""
    padded = key_warning(attr_doc(PADDED_ROW, prologue=VERTICES_FREEFORM_CLASS))
    assert padded.locus.row_text == PADDED_ROW
    assert padded.fix[0] == "l-001| v-001 |class|hello"
    assert padded.fix[1] == "l-001| v-001 |attrs.bogus|hello"

    row = 'l-001| "v-001|v-002" | bogus |hello'
    quoted = key_warning(
        attr_doc(row, prologue=VERTICES_WITH_A_QUOTED_PIPE_ID)
    )
    assert quoted.locus.row_text == row
    assert quoted.fix[0] == 'l-001| "v-001|v-002" |class|hello'
    assert quoted.fix[1] == 'l-001| "v-001|v-002" |attrs.bogus|hello'
    for candidate in quoted.fix:
        assert len(cells(candidate)) == 4

    escaped = key_warning(
        attr_doc(ESCAPED_PIPE_LEFT_ROW, prologue=VERTICES_WITH_AN_ESCAPED_PIPE_ID)
    )
    assert escaped.locus.row_text == ESCAPED_PIPE_LEFT_ROW
    assert escaped.fix[0] == r"l-001|bastion\|01|class|svc.config-mgmt"
    assert escaped.fix[1] == r"l-001|bastion\|01|attrs.owner|svc.config-mgmt"
    for candidate in escaped.fix:
        assert len(cells(candidate)) == 4, (
            f"{candidate!r} re-splits to {len(cells(candidate))} — the escape was dropped"
        )


def test_quoted_pipe_cells_round_trip_unchanged():
    """A cell quoting its pipe — the whole-cell form and the `k=v` form the design names — still splits to the declared width and still appears byte-identical in both candidates (O9, D9)."""
    for value in ('"curl|bash"', 'cmd="curl|bash"'):
        row = f"l-001|v-001|bogus|{value}"
        d = key_warning(attr_doc(row, prologue=VERTICES_FREEFORM_CLASS))
        assert d.locus.row_text == row
        assert d.fix == (f"l-001|v-001|class|{value}", f"l-001|v-001|attrs.bogus|{value}")
        for candidate in d.fix:
            assert len(cells(candidate)) == 4


def test_the_backslash_pipe_escape_is_still_accepted_by_the_splitter():
    """`split_cells` still reads `|` as one escaped delimiter inside a cell, and a row carrying one still parses to the declared width with no parse warning (D10)."""
    assert cells(r"a|b\|c") == ["a", "b|c"]

    doc = attr_doc(ESCAPED_PIPE_ROW)
    assert warnings_of(doc) == [], "the escaped row is not a parse fault"
    assert cells(ESCAPED_PIPE_ROW) == ["l-001", "v-001", "bogus", "curl|bash"]


def test_a_quoted_legal_keyword_is_repaired_by_unquoting_it():
    """A key cell spelling a quoted legal keyword is still an ILLEGAL key, and the repair offered for it is now the unquoted keyword (#963, superseding the observable #954 pinned here)."""
    doc = attr_doc(MID_TOKEN_QUOTE_ROW, prologue=VERTICES_FREEFORM_CLASS)
    d = key_warning(doc)
    assert "'\"class\"'" in d.message, "the quoted keyword is still an illegal key"
    assert d.fix == ("l-001|v-001|class|hello",)
    assert not any('attrs."class"' in c for c in d.fix), (
        "the candidate that splices a refused key behind `attrs.` is gone, not withheld"
    )
    assert d.locus is not None
    assert d.locus.row_text == MID_TOKEN_QUOTE_ROW
    assert d.severity == "warning"


def test_an_empty_key_is_not_repaired_into_an_empty_attribute_name():
    """`attrs.` is legal-SHAPED and names nothing — the `attrs.<name>` test is a prefix check, so it accepts the bare prefix and would land an attribute whose name is the empty string."""
    d = key_warning(
        attr_doc('l-001|v-001|""|hello', prologue=VERTICES_FREEFORM_CLASS)
    )
    assert d.fix == ("l-001|v-001|class|hello",)
    assert not any(c.endswith("attrs.|hello") for c in d.fix)


def test_the_offered_unquoting_repair_actually_pastes(tmp_path):
    """The repair #963 offers is one `fix_row` accepts and one that clears the flag — the loop the withheld suggestion could not close."""
    doc = attr_doc(MID_TOKEN_QUOTE_ROW, prologue=VERTICES_FREEFORM_CLASS)
    d = key_warning(doc)
    deps, run = main_deps(tmp_path)
    seed_investigation(run, doc)

    _fix(deps, MID_TOKEN_QUOTE_ROW, d.fix[0])

    after = _inv(run)
    assert d.fix[0] in after
    assert _flagged(after) == []


def test_an_invisible_character_the_strip_does_not_remove_reaches_model_context_raw():
    """A character the tokenizer's strip does not remove survives into `raw_row` / `locus.row_text` byte for byte, and `render_diagnostic` splices that text into `model_context` unchanged (D18)."""
    from defender.records._artifact_schema import render_diagnostic

    row = "l-001|v-001|bo​gus|hello"
    doc = attr_doc(row)
    d = key_warning(doc)
    assert d.locus.row_text == row
    assert "​" in d.locus.row_text
    assert _flagged(doc) == [row], "the window addresses the row by its exact bytes"
    assert f"row: {row}" in render_diagnostic(d)


def test_a_legal_short_row_is_rebuilt_byte_identically_then_padded_to_the_declared_width(
    tmp_path,
):
    """Under a header marking its trailing column optional, a legal short row's candidates are rebuilt from the author's raw text and then PADDED to the declared width — byte-identical in every cell the author wrote, full width on paste (F-F, D28)."""
    plain = key_warning(attr_doc("l-001|v-001|bogus", header=OPTIONAL_ATTR_HEADER))
    assert plain.locus.row_text == "l-001|v-001|bogus"
    assert plain.fix == ("l-001|v-001|class|", "l-001|v-001|attrs.bogus|")
    for candidate in plain.fix:
        assert len(cells(candidate)) == 4

    padded = key_warning(attr_doc("l-001|  v-001  |bogus", header=OPTIONAL_ATTR_HEADER))
    assert padded.fix == ("l-001|  v-001  |class|", "l-001|  v-001  |attrs.bogus|")
    for candidate in padded.fix:
        assert len(cells(candidate)) == 4

    # The paste half, which no demand drove: the width guard passes and the sibling
    # empty-`value` family then refuses, so the candidate is a template and not a repair.
    from pydantic_ai.exceptions import ModelRetry

    doc = attr_doc("l-001|v-001|bogus", header=OPTIONAL_ATTR_HEADER)
    deps, run = main_deps(tmp_path)
    seed_investigation(run, doc)
    with pytest.raises(ModelRetry) as exc:
        _fix(deps, "l-001|v-001|bogus", plain.fix[0])
    assert "the `value` cell for key 'class' is empty" in str(exc.value)
    assert _inv(run) == doc, "a refused paste must commit nothing"

    # ...and the same candidate with the value filled in DOES land, so the refusal above is
    # about the empty cell and not about the padding.
    _fix(deps, "l-001|v-001|bogus", "l-001|v-001|class|bastion/internal/known-corp")
    assert _flagged(_inv(run)) == [], "the filled-in repair closed the window"


def test_paste_gate_enforces_the_same_declared_width_equality_as_the_offer_gate(tmp_path):
    """`suggestion_row` meets the same `declared-width-equality` constraint on the paste via that it meets on the offer via:"""
    from pydantic_ai.exceptions import ModelRetry

    doc = attr_doc(ESCAPED_PIPE_ROW, prologue=VERTICES_FREEFORM_CLASS)
    candidate = key_warning(doc).fix[0]

    deps, run = main_deps(tmp_path)
    seed_investigation(run, doc)
    assert _flagged(doc) == [ESCAPED_PIPE_ROW]

    _fix(deps, ESCAPED_PIPE_ROW, candidate)
    assert candidate in _inv(run)
    assert _flagged(_inv(run)) == [], "the repair closed the window"

    # The other end of the parity: today's rejoin, which loses the escape, is refused for its
    # width — the second refusal, named.
    deps2, run2 = main_deps(tmp_path / "second")
    seed_investigation(run2, doc)
    with pytest.raises(ModelRetry) as exc:
        _fix(deps2, ESCAPED_PIPE_ROW, "l-001|v-001|class|curl|bash")
    assert "5 cells" in str(exc.value)
    assert "declares 4" in str(exc.value)
    assert _inv(run2) == doc

    # Idempotency: the same repair a second time finds an empty window.
    with pytest.raises(ModelRetry) as again:
        _fix(deps, ESCAPED_PIPE_ROW, candidate)
    assert "Nothing is currently flagged" in str(again.value)

    # The padding round trip (brief F9): the on-disk line carries TRAILING padding, the window
    # addresses it without, and a candidate carrying only LEADING padding still lands.
    on_disk = "l-001|v-001|bogus|  hello  "
    padded_doc = attr_doc(on_disk, prologue=VERTICES_FREEFORM_CLASS)
    addressed = key_warning(padded_doc).locus.row_text
    assert addressed == "l-001|v-001|bogus|  hello", "the tokenizer already rstripped the line"
    assert on_disk in padded_doc, "...while the on-disk bytes still carry the trailing padding"

    deps3, run3 = main_deps(tmp_path / "padded")
    seed_investigation(run3, padded_doc)
    _fix(deps3, addressed, "l-001|v-001|class|  hello")
    assert "l-001|v-001|class|  hello" in _inv(run3)
    assert _flagged(_inv(run3)) == [], "the padded repair closed the window"


def test_the_paste_gate_returns_a_reason_where_the_row_reader_would_raise(tmp_path):
    """The parser's row reader is WRAPPED, not substituted:"""
    from defender.records._artifact_schema import validate_investigation
    from pydantic_ai.exceptions import ModelRetry

    doc = attr_doc(MID_TOKEN_QUOTE_ROW)
    assert validate_investigation(doc, None) is None, (
        "a warn-only document still accepts; an escaping row error would fail it closed"
    )

    deps, run = main_deps(tmp_path)
    seed_investigation(run, doc)
    with pytest.raises(ModelRetry) as exc:
        _fix(deps, MID_TOKEN_QUOTE_ROW, 'l-001|v-001|attrs."class"|hello')
    assert "No changes were made" in str(exc.value)
    assert _inv(run) == doc


def test_a_withheld_fix_row_keeps_its_locus_and_stays_deletable(tmp_path):
    """A row whose repairs were all withheld keeps its `locus`, so it stays in the repair window — and `fix_row(old_row, "")` still reaches it (F-M half two, D31)."""
    from defender.records._artifact_schema import validate_investigation

    doc = attr_doc(MID_TOKEN_QUOTE_ROW)
    assert _flagged(doc) == [MID_TOKEN_QUOTE_ROW]

    deps, run = main_deps(tmp_path)
    seed_investigation(run, doc)
    _fix(deps, MID_TOKEN_QUOTE_ROW, "")

    after = _inv(run)
    assert MID_TOKEN_QUOTE_ROW not in after
    assert _flagged(after) == []
    assert validate_investigation(after, None) is None


PADDING_ATTR_HEADER = "[resolved_by|target|key|value|note?]"

PAD_EATS_DELIMITER_ROW = "l-001|v-001|bogus|c:\\path\\"

BYTES_MOVE_ROW = r"l-001|v-001|a\|a\ |hello"


def test_a_rebuilt_row_that_loses_a_delimiter_is_withheld():
    """A candidate whose rejoin turns an author's trailing backslash into an escaped `|` is WITHHELD, because it no longer splits to the block's declared width."""
    for header, row in (
        (PADDING_ATTR_HEADER, PAD_EATS_DELIMITER_ROW),
        (OPTIONAL_ATTR_HEADER, "l-001|v-001|bogus\\"),
    ):
        d = key_warning(attr_doc(row, header=header))
        assert d.fix == (), f"{row!r} under {header}"
        assert d.severity == "warning"
        assert d.locus is not None
        assert d.locus.row_text == row
        assert "withheld" in d.message.lower()


def test_a_candidate_carrying_a_fence_delimiter_is_withheld():
    """A row whose cells carry ``` gets no candidate, because no rewrite of it can be pasted."""
    from defender.investigation.tools import _new_row_shape_reason

    row = "l-001|v-001|bogus|see ```x``` here"
    d = key_warning(attr_doc(row))
    assert d.fix == ()
    assert "fence delimiter" in d.message
    assert d.locus is not None
    assert d.locus.row_text == row

    # The channel: the paste gate really does refuse this shape, so the withholding above is
    # parity with it and not a new rule.
    assert _new_row_shape_reason("l-001|v-001|class|see ```x``` here", 4) is not None


# O3's payoff over the class of readers that parse without validating

FOLD_FIRST = "l-001|1|alpha|v-001||cmdb|24h|timeout"
FOLD_LATER = "l-001|2|beta|v-002||edr|48h"
FOLD_OTHER = "l-002|2|delta|v-002||edr|48h"
FOLD_REPEAT_DOC = (
    VERTICES + findings_block(FOLD_FIRST, FOLD_LATER, FOLD_OTHER) + close_block(1)
)
FOLD_FIRST_ONLY_DOC = VERTICES + findings_block(FOLD_FIRST, FOLD_OTHER) + close_block(1)
FOLD_LATER_ONLY_DOC = VERTICES + findings_block(FOLD_LATER, FOLD_OTHER) + close_block(1)


def test_a_precedent_case_carrying_the_repeated_id_warning_is_not_loaded_as_clean(tmp_path):
    """`corpus_load_one` — the ONE fused-bucket reader that keeps its warnings rather than discarding them — reports a stored case carrying a within-block repeat as PARTIAL, and its lead is the first row's (D22)."""
    from defender.skills.invlang.corpus import load_corpus
    from defender.tests.support.storage._alert_plant import plant_alert

    case = tmp_path / "case-1"
    case.mkdir()
    plant_alert(case)
    (case / "investigation.md").write_text(REPEAT_DOC + CONCLUDE_BENIGN, encoding="utf-8")

    companions, report = load_corpus(tmp_path)
    assert report.loaded == 1
    assert report.total_warnings >= 1, "a repeat must not load as a clean precedent"
    assert any(
        REPEAT_PHRASE in w.reason for _path, ws in report.partial for w in ws
    ), "the kept warning is the repeated-id one"
    assert companions[0].leads[0]["name"] == "alpha"


FP_FIRST_ROW = "l-001|1|alpha|v-001||cmdb|24h"
FP_LATER_ROW = "l-001|2|beta|v-999||edr|48h"
FP_RESULT = attr_block("l-001|v-001|attrs.owner|svc-deploy")


def _fp_doc(*rows):
    return VERTICES + findings_block(*rows) + FP_RESULT + CONCLUDE_FALSE_POSITIVE


SEEDING_BLOCK = attr_block("l-001|v-001|attrs.owner|svc-deploy")
SEEDED_UPDATES = [{"target": "v-001", "updates": {"attrs.owner": "svc-deploy"}}]


def test_a_lead_bucket_an_earlier_refinement_block_seeded_survives_the_fold():
    """When a `:R attr_updates` row has already opened a lead's bucket, the first-wins fold over a later repeating `:L findings` block MERGES INTO that bucket — the seeded resolution content survives — and the identity it lands is the FIRST row's (D39)."""
    repeat = VERTICES + SEEDING_BLOCK + findings_block(FIRST_ROW, LATER_ROW)
    first_only = VERTICES + SEEDING_BLOCK + findings_block(FIRST_ROW)

    lead = leads(repeat)[0]
    assert lead["outcome"]["attribute_updates"] == SEEDED_UPDATES, (
        "the fold must merge INTO the seeded bucket, never replace it"
    )
    assert lead["name"] == "alpha", "the FIRST row's identity, over a pre-seeded bucket"
    assert lead["target"] == "v-001"
    assert lead["loop"] == 1
    assert lead["query_details"] == {"system": "cmdb", "time_window": "24h"}
    assert lead == leads(first_only)[0], (
        "a pre-seeded bucket reads the repeat as the first row alone, whole"
    )

    # The control the premise names: the seeding block alone really does open the bucket, so
    # the survival assertion above is about the fold and not about an empty dict.
    seeded_only = leads(VERTICES + SEEDING_BLOCK)[0]
    assert seeded_only["outcome"]["attribute_updates"] == SEEDED_UPDATES
    assert "name" not in seeded_only, "nothing has declared the lead yet"

    # ...and the repeat is still named, on a document whose ordering is the reverse of every
    # other fixture in this file.
    assert len(repeat_diagnostics(repeat)) == 1


# F-L — the uniform formation gate

LEGACY_DOC = VERTICES + findings_block(
    "l-001|1|alpha|v-001||cmdb|24h|timeout",
    "l-001|1|beta|v-002||edr|48h",
)
#: The same document with the repeat removed — the control that proves each refusal below is
#: about the repeat and not about the block being appended.
REPAIRED_DOC = VERTICES + findings_block("l-001|1|alpha|v-001||cmdb|24h|timeout")
#: A legal refinement block to append onto either.
NEXT_BLOCK = attr_block("l-001|v-001|class|file-server/internal/known-corp")


def test_a_close_block_write_is_refused_exactly_as_an_ordinary_block_append(tmp_path):
    """A document carrying a within-block repeat is refused when the run appends a `:T close` BLOCK exactly as it is refused when the run appends any other block — the same `validate_investigation` over the """
    from pydantic_ai.exceptions import ModelRetry

    for label, block in (("close", close_block(1)), ("append", NEXT_BLOCK)):
        deps, run = main_deps(tmp_path / label)
        seed_investigation(run, LEGACY_DOC)
        with pytest.raises(ModelRetry) as exc:
            _append(deps, block)
        assert REPEAT_PHRASE in str(exc.value), label
        assert "failed invlang validation" in str(exc.value), label
        assert _inv(run) == LEGACY_DOC, label

    for label, block in (("close-ok", close_block(1)), ("append-ok", NEXT_BLOCK)):
        deps, run = main_deps(tmp_path / label)
        seed_investigation(run, REPAIRED_DOC)
        _append(deps, block)
        assert _inv(run) != REPAIRED_DOC, label


def test_a_legacy_document_holding_a_repeat_is_refused_at_every_write_verb(tmp_path):
    """A document written BEFORE this ships, already holding a within-block repeat, is refused at every verb that WRITES invlang bytes, with no grandfathering and no suppression condition (F-L, D34)."""
    from pydantic_ai.exceptions import ModelRetry

    deps, run = main_deps(tmp_path)
    seed_investigation(run, LEGACY_DOC)
    with pytest.raises(ModelRetry) as append_exc:
        _append(deps, NEXT_BLOCK)
    assert REPEAT_PHRASE in str(append_exc.value)
    assert _inv(run) == LEGACY_DOC

    # The repeat is not in the repair window: error severity, and no locus to address.
    assert _flagged(LEGACY_DOC) == []
    with pytest.raises(ModelRetry) as window_exc:
        _fix(deps, "l-001|1|beta|v-002||edr|48h", "")
    assert "Nothing is currently flagged" in str(window_exc.value)

    # ...and repairing a co-resident flagged row cannot get the document out either.
    warn_row = "l-001|v-001|owner|svc.config-mgmt"
    deps2, run2 = main_deps(tmp_path / "co-resident")
    seed_investigation(run2, LEGACY_DOC + attr_block(warn_row))
    assert _flagged(LEGACY_DOC + attr_block(warn_row)) == [warn_row]
    repair_row = "l-001|v-001|class|file-server/internal/known-corp"
    with pytest.raises(ModelRetry) as repair_exc:
        _fix(deps2, warn_row, repair_row)
    assert REPEAT_PHRASE in str(repair_exc.value)

    # The control: the same repair on a document without the repeat lands.
    deps3, run3 = main_deps(tmp_path / "clean")
    seed_investigation(run3, REPAIRED_DOC + attr_block(warn_row))
    _fix(deps3, warn_row, repair_row)
    assert repair_row in _inv(run3)
