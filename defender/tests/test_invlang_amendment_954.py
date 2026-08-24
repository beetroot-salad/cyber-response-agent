"""#954 — two invlang defects, and the amendment that closes them.

F-46: a `:L findings` block that lists one lead id TWICE folds both rows into one bucket,
silently, field by field, last row winning. The fix warns (the existing repeated-id check)
and keeps the FIRST row, skipping later rows for an id this block already landed.

F-47: the repair suggestion `_check_attr_update_keys` offers is rebuilt from PARSED cells and
rejoined with a bare `"|".join`, so an escaped or padded cell comes back a different shape and
the model's paste earns a SECOND refusal. The fix rebuilds from the row's raw text and
withholds any candidate that does not re-split to the declared width.

RED AGAINST BASE `505b8d1c` IS THE EXPECTED STATE OF THIS FILE. 26 of the 36 collected items
are red; the demands whose observable the fix creates fail here until the implementation
lands. The 10 GREEN ones are the regression set — D4b, D9, D10, D16, D18, D27, D29, D30,
D31, D32 — and they pass at base and must keep passing. (This list stood at "D4b, D9, D10,
D16, D28's first half, D30, D32" for two rounds and was simply wrong: D18, D27, D29 and D31
are green regressions nobody was told to keep, and D28's test as a whole is red. Measured,
not remembered.)

WHOSE DOCUMENTS O3 IS ABOUT, stated because §7 asked for it in writing and the phase-D notes
below it still argue from the population it retired. F-L's FORMATION gate is UNIFORM ACROSS
THE VERBS THE AGENT WRITES INVLANG BYTES THROUGH — `append_block` and `fix_row`, both over
`decide_write` — so no document the run loop authors THROUGH THOSE VERBS can acquire a
within-block repeat after this ships, and the historical population is measured at zero (PO-J3,
re-run at §7: 24 live run documents, 155 lead rows, no in-block repeat). The three qualifying
words are not decoration: the harness writer below runs inside the run loop too, and the
sentence without them is the universal this run has now narrowed twice.

THE UNIVERSAL IS OVER VERBS, NOT OVER WRITERS, and the one exception is censused and filed
rather than gated. This module used to say "no document can ACQUIRE a within-block repeat
after this ships", which is one writer too wide: `defender/runtime/lead_zero.py:955-978`
(`_declare_l_finding`, called at :605 and :1011) appends a `:L findings` block into
`investigation.md` through `write_guarded` before MAIN's first turn, reaching neither
`append_block` nor `decide_write` nor `validate_investigation`. It cannot form THIS defect —
one fence, exactly one row per call, and the next `append_block` re-validates the whole file
— so by the human's decision it is filed as **#964** and is NOT gated here and NOT given a
demand. Do not add one; do not read its absence as an oversight.

So O3's first-wins rule governs documents authored OUTSIDE the gated verbs: fixtures,
examples, the precedent corpus, hand-edited files, a run in flight at the instant of deploy,
and the harness-authored lead-0 block above. D22 (`corpus_load_one`) is the one demand
squarely inside that surviving population. D19, D20, D21 and D33 keep their live-runtime
justifications because the harm they name is what the reader would DO with a fused bucket,
and the close verb is not gated either (see D14's docstring; filed as #961) — but the
document reaching them is one of the shapes above, not one a gated verb wrote.

The human decisions this module applies. The four forks below were resolved in
`.spec-flow/frontiers/70-resolutions.md`; TWO LATER DECISIONS ARE NOT IN THAT FILE, which ends
at the first phase-F round and still carries F-L's un-narrowed "refusal at every verb" wording
— narrowing the formation universal to the verbs the agent writes invlang bytes through, and
filing the harness writer as #964 rather than gating it, were taken at the phase-F and prose
rounds and are recorded in `80-author-digest.md` and in the artifact's own `handoff`. Said here
at the amendment round because this line pointed at one file for all of them; whether §7's file
is backfilled or this pointer is re-aimed is a live decision for the human, not one taken here:

  F-L  NO grandfathering and NO suppression condition. A uniform FORMATION gate: the same
       gate at every verb the agent writes invlang bytes through. The four F-L premises assert
       that uniform outcome over THREE WRITES through TWO VERBS — an ordinary `append_block`,
       an `append_block` whose payload is a `:T close` fence, and a `fix_row` repair — and no
       demand is minted for a legacy exemption. The `close_investigation` VERB is not among
       them and is not gated by anything here (#961); nor is the harness writer (#964).
  F-F  a legal short row's suggestion is REBUILT FROM RAW TEXT, then padded to the declared
       width. O8 is reworded to "byte-identical in every cell the author wrote". Byte-identity
       is not automatic: reusing `_split_quoted` silently strips whitespace from untouched
       cells, so the rebuild needs a no-strip boundary scanner.
  F-M  half one: re-split the candidate through the parser's OWN row reader (`_row_cells`),
       treating its refusal as "withhold" — WRAPPED, not substituted, because that reader
       RAISES where today's gates return a reason and PADS a short row in silence.
       half two: a withheld-fix row keeps its locus and deletion stays reachable.
  F-K  secondary findings are accepted; D12 narrows to "no undeclared-lead error is raised
       against the surviving lead". The broader "the repeated-id diagnostic is the only
       finding" is unachievable and would fail a correct implementation.

Two correction groups from `45-dispositions.md` are applied rather than carried:

  F-N  three phase-C answers pinned `_swap_cell`'s padding-stripped output — the very output
       O8 exists to forbid. Inverted here, and re-corrected by J7: `locus.row_text` is the
       line already stripped, so TRAILING padding is outside the contract (D15).
  F-O  two answers addressed bucket keys the projection never writes. `loop` is an `int`,
       `window` lands at `query_details["time_window"]` and `fail_reason` at
       `outcome["failure_reason"]` (J5).
"""
from __future__ import annotations

import pytest

from defender.tests._invlang_amendment_954 import (
    CONCLUDE_BENIGN,
    CONCLUDE_FALSE_POSITIVE,
    OPTIONAL_ATTR_HEADER,
    REPEAT_PHRASE,
    STRAND_FINDINGS_HEADER,
    UNDECLARED_LEAD_PHRASE,
    VERTICES,
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

# --------------------------------------------------------------------------- #
# F-46 rows. Two rows for one lead, disagreeing on every non-empty cell they share, so no
# assertion below can be satisfied by an implementation that merges instead of choosing.
# --------------------------------------------------------------------------- #

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
    from defender.runtime.tools import _tool_append_block

    return _tool_append_block(deps, text)


def _fix(deps, old_row, new_row):
    from defender.runtime.tools import _tool_fix_row

    return _tool_fix_row(deps, old_row, new_row)


def _inv(run):
    return (run / "investigation.md").read_text(encoding="utf-8")


# =========================================================================== #
# F-46 — the repeated lead id
# =========================================================================== #

def test_repeated_lead_id_returns_a_first_wins_bucket_and_an_error_diagnostic():
    """`parse_dense_companion` over a `:L findings` block listing one lead id twice returns
    ONE ParseWarning per EXTRA row in slot 2 and, in slot 1, exactly one `lead_bucket` for
    that id holding the FIRST row's values in identity, outcome and query_details alike;
    `diagnose` lifts each warning to a Diagnostic at the dataclass default `severity` error,
    whose `locus` carries `row_text == ""` and `row_index == -1`.

    Surface A of the return-value contract (D0a). The locus pin is fork F-C's recommendation
    (a) — reuse the existing helper verbatim — pinned so the choice is RECORDED rather than
    inherited; safe only because this family is error severity, since `_addressable` drops a
    locus-less warn diagnostic entirely.

    The bucket assertions are on the keys `_lead_header_record` actually writes (J5): `loop`
    is coerced through `int()`, `window` lands at `query_details["time_window"]` and
    `fail_reason` at `outcome["failure_reason"]`. `lead["window"]` is a key nothing sets.
    """
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
    """A `:L findings` block listing one lead id twice gains a `parse_warnings` diagnostic
    that NAMES that id, and `lead_bucket` keeps the id it names (O1, D1).

    The assertion is on the id appearing in the message prose — the existing check
    interpolates `{rid!r}` — not on an exact sentence. This is D5's positive control: it is
    what proves the diagnostic channel can see the difference the negative asserts is absent.
    """
    diags = repeat_diagnostics(REPEAT_DOC)
    assert len(diags) == 1
    assert "'l-001'" in diags[0].message, diags[0].message
    assert [b["id"] for b in leads(REPEAT_DOC)] == ["l-001"]


def test_repeated_lead_id_refuses_the_write_and_commits_nothing(tmp_path):
    """`append_block` proposing a `:L findings` block that lists one lead id twice is refused
    through the real write gate — `validate_investigation` over the full proposed text, via
    `decide_write` — and `investigation_md` is left exactly as it stood (O2, D2).

    Driven through the verb rather than through `diagnose` alone: that surface's own contract
    is that WARN findings are not returned through it at all, so a non-None return is the
    observable that the F-46 family landed on the REFUSING side of the severity partition.
    """
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


def test_non_validating_reader_sees_the_first_rows_values():
    """A reader that parses without validating sees the FIRST row's values, not a blend
    (O3, D3): `compaction_detect_loop` takes `max(loop)` over `lead_bucket`, so over a repeat
    whose rows disagree on `loop` it answers the first row's number.

    Re-anchored from `narration_crosscheck_from_run`, which reduces the companion to a SET of
    lead ids and cannot observe first-wins at all (C9). The two single-row documents are the
    observation channel's own control: they show this reader CAN tell 1 from 2.
    """
    from defender.runtime.compaction import detect_loop

    assert detect_loop(FIRST_ONLY_DOC) == 1
    assert detect_loop(LATER_ONLY_DOC) == 2
    assert detect_loop(REPEAT_DOC) == 1, "the later row was discarded, so its loop is not read"


def test_relisting_a_lead_overwrites_a_conflicting_non_empty_cell():
    """A lead re-listed in a SECOND `:L findings` block still merges into its existing
    `lead_bucket`, the later block winning on a conflicting NON-EMPTY cell, with no diagnostic
    (O4, D4b).

    Raised because the existing characterization anchor does not pin last-wins: its two rows
    differ only empty -> `timeout`, so a "merge but never overwrite a non-empty value"
    implementation ships green against it (C12). Here the two blocks disagree on every shared
    column. The addresses are the ones the projection writes (J5).
    """
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
    """A `:L findings` block whose ids are all distinct gains NO repeated-id diagnostic on any
    surface the finding could reach — `parse_warnings`, `diagnose`, or the write gate's
    refusal text — and both leads project (O5, D5).

    A negative: its required positive control on the same address under the complementary
    condition is `test_repeated_lead_id_in_one_block_is_named_in_a_parse_diagnostic`, and the
    last block below re-states it inline, because `assert not diagnostics` is also green over
    a document nothing parsed.
    """
    from defender._artifact_schema import validate_investigation

    assert [w.reason for w in warnings_of(TWO_IDS_DOC) if REPEAT_PHRASE in w.reason] == []
    assert repeat_diagnostics(TWO_IDS_DOC) == []
    assert validate_investigation(TWO_IDS_DOC, None) is None
    assert [b["id"] for b in leads(TWO_IDS_DOC)] == ["l-001", "l-002"], (
        "the channel is non-empty: both leads are really there to be flagged"
    )

    # The complementary condition, on the same address: the mechanism DOES fire.
    assert len(repeat_diagnostics(REPEAT_DOC)) == 1


def test_the_surviving_lead_stays_declared_for_every_reader_that_names_it():
    """The lead that survives a within-block repeat is still DECLARED at BOTH readers that
    decide a lead id's declaredness — `check_lead_refs`, which raises "undeclared lead", and
    the false-positive entry price, whose `entity_check` gate resolves the named id against
    `:L findings` — even when the document also trips a secondary gate (D12).

    "EVERY reader that names it" is a census, not a hope (N6): `undeclared lead` is emitted at
    exactly one site (validate.py:142), and exactly one other production reader asks whether an
    id is a declared lead at all (`_check_false_positive_gating`, validate.py:2429). The third
    site that touches lead-id membership reduces the companion to a SET of ids
    (`_lead_ids_from_companion`, C9) and is the seam D36 waives. Driving one reader and naming
    the obligation "every" was this test's own gap at the first pass; both are driven now.

    READ THE NAME AS THE CLOSED CLASS, not as an open quantifier: "every reader that names it"
    means BOTH readers that decide declaredness, the two-member class N6 enumerated — a cold
    reader counted the body's two against the name's "every" and was right to. The one
    excluded site is excluded because it CANNOT observe the property (it reduces to a set of
    ids), and that exclusion is a cited waiver carrying its own demand id (D36), not a silence.

    NARROWED per F-K: the obligation is "no undeclared-lead error against the surviving
    lead", NOT "the repeated-id diagnostic is the only finding" — on a document that also
    trips the screen-structure gate the broader assertion is false while the implementation is
    correct, and the human accepted that an author may see secondary findings and must
    identify the real one.

    It discriminates: an implementation that DROPS both colliding rows passes D1, D2 and D5
    while making every later block naming that lead report "undeclared lead" — and makes the
    false-positive gate answer "`entity_check` names 'l-001', which is not a lead".
    """
    refined = REPEAT_DOC + attr_block("l-001|v-001|class|svc.config-mgmt")
    diags = diagnostics(refined)
    assert [d.message for d in diags if UNDECLARED_LEAD_PHRASE in d.message] == []
    assert len([d for d in diags if REPEAT_PHRASE in d.message]) == 1

    # The second declaredness reader, on a document that closes false-positive: the survivor
    # resolves and its own target check passes, so nothing is owed.
    both_in_prologue = VERTICES + findings_block(
        "l-001|1|alpha|v-001||cmdb|24h",
        "l-001|2|beta|v-001||edr|48h",
    ) + attr_block("l-001|v-001|class|svc.config-mgmt") + CONCLUDE_FALSE_POSITIVE
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
    ) + attr_block("l-001|v-001|class|svc.config-mgmt")
    stranded_diags = diagnostics(stranded)
    assert [d.message for d in stranded_diags if UNDECLARED_LEAD_PHRASE in d.message] == []
    assert len([d for d in stranded_diags if REPEAT_PHRASE in d.message]) == 1


def test_three_rows_sharing_an_id_produce_one_diagnostic_per_extra_row():
    """Three rows sharing a lead id produce TWO diagnostics — one per EXTRA row, not one per
    id — and the bucket is still the first row's (F-C, D23).

    Both conventions are defensible readings of O1 and the existing helper picks
    one-per-extra-row; the count is pinned here so the choice is recorded rather than
    inherited. The two messages are byte-identical, which is what "one per extra row" means
    for a reader.
    """
    doc = VERTICES + findings_block(FIRST_ROW, LATER_ROW, THIRD_ROW)
    diags = repeat_diagnostics(doc)
    assert len(diags) == 2
    assert diags[0].message == diags[1].message
    assert leads(doc)[0]["name"] == "alpha"


def test_id_comparison_is_byte_exact_across_quoting_padding_and_case():
    """"Same lead id" means the same cell BYTES: a quoted spelling, a quote-wrapped padded
    spelling and a case variant each declare a SECOND lead rather than colliding with the
    first, and no repeated-id diagnostic is raised (F-A, D24).

    Taken because it is what the prescribed mechanism produces — `_row_dict` does not unquote
    (C16) and `_split_quoted`'s strip trims nothing inside a quote (IS-PO2) — and diverging
    silently is the worse outcome. The recorded trap: under byte comparison a quoted id is not
    merely un-flagged, it declares a lead named `'"l-001"'`, so a `:R` row attributing itself
    to the bare id can then earn an undeclared-lead error against a correct row.
    """
    for spelling in ('"l-001"', '"  l-001  "', "L-001"):
        doc = VERTICES + findings_block(FIRST_ROW, f"{spelling}|2|beta|v-002||edr|48h")
        assert repeat_diagnostics(doc) == [], f"{spelling} is not the same bytes as l-001"
        assert [b["id"] for b in leads(doc)] == ["l-001", spelling]

    # The complementary condition: the same bytes twice DO collide.
    assert len(repeat_diagnostics(REPEAT_DOC)) == 1


def test_the_id_check_skips_a_row_the_projection_drops_for_a_missing_name():
    """A `:L findings` block whose first row for an id carries an `id` but no `name` gains NO
    repeated-id diagnostic: the check compares only the rows that LAND, so the well-formed row
    is the block's sole declaration (F-B, D25).

    The two gates disagree about what a row is — `warn_repeated_ids` skips only rows with no
    readable id, `project_findings_block` additionally drops rows with no name — and this is
    the one place where "call the existing check" and "skip rows whose id this block has
    already landed" cannot both be honoured literally. A false error-severity refusal on a
    document containing exactly one valid declaration is worse than the defect being fixed.

    Reading (a) is also ill-typed as the fork worded it: `block_rows` holds raw row STRINGS,
    for which `r.get("id")` is never reached (J1).
    """
    doc = VERTICES + findings_block("l-001|1||v-001||cmdb|24h", FIRST_ROW)

    assert repeat_diagnostics(doc) == []
    assert any("missing id/name" in w.reason for w in warnings_of(doc)), (
        "the pre-existing gate still drops the nameless row, loudly"
    )
    assert leads(doc)[0]["name"] == "alpha"

    # Two rows with no readable id at all cannot collide either — there is nothing to compare,
    # and the caller still lands neither.
    idless = VERTICES + findings_block("|1|alpha|v-001||cmdb|24h", "|2|beta|v-002||edr|48h")
    assert repeat_diagnostics(idless) == []

    # The complementary condition: with both rows named, the check fires.
    assert len(repeat_diagnostics(VERTICES + findings_block(FIRST_ROW, LATER_ROW))) == 1


def test_first_wins_does_not_change_the_published_bucket_order():
    """`lead_bucket`s are published in FIRST-MENTION order, and keeping the first row does not
    reorder them (D26).

    The bucket already exists when the second row arrives, so a first-wins fold implemented as
    an early `continue` is order-preserving — but one implemented as delete-then-reinsert is
    not, and `validate.py`'s screen-structure message and the review projector both read this
    order.
    """
    doc = VERTICES + findings_block(FIRST_ROW, OTHER_ROW, LATER_ROW)
    assert [b["id"] for b in leads(doc)] == ["l-001", "l-002"]
    assert len(repeat_diagnostics(doc)) == 1


def test_a_blank_cell_in_an_amending_row_does_not_erase_the_earlier_value():
    """A blank cell in a row that amends a lead from a SECOND block does not erase the value
    an earlier block landed — but `name` and `target` are taken UNCONDITIONALLY, so a blank
    `target` does overwrite with `""` (F-J, D27).

    C1's verified non-empty-only list is exactly `loop` / `mode` / `trust_root_reached` /
    `screen_result` / `status`; the converged phase-C answer generalises past what C1 covers
    and this test must not. ALL FIVE ARE EXERCISED HERE, not merely named — the first pass
    cited the list in prose and asserted only `loop`, which is a claim living outside asserted
    code. The header spells the fourth column `trust_root` (`STRAND_FINDINGS_HEADER`); the
    bucket key is `trust_root_reached`, and a header declaring the bucket key projects nothing.

    The addresses are corrected too: the value the answer asserted at `lead["window"]` lands at
    `query_details["time_window"]`, and `lead["fail_reason"]` at `outcome["failure_reason"]`
    (J5). `query_details["system"]` is asserted beside `time_window` for the same reason the
    five are: its sibling `target` is exercised in this scenario and it was not, so an
    implementer had no executable pin for whether a blank `system` cell erases the earlier one.
    """
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


# =========================================================================== #
# F-47 — the repair suggestion
# =========================================================================== #

#: The escaped-pipe trigger, RIGHT of the key cell. EXECUTED at base: both candidates split to
#: FIVE cells under a four-column header, which is the second refusal F-47 describes.
ESCAPED_PIPE_ROW = r"l-001|v-001|bogus|curl\|bash"
#: EXECUTED at base: `_swap_cell` normalises the padding away and the result keeps the declared
#: width — so a width guard alone cannot see this one.
PADDED_ROW = "l-001| v-001 |bogus|hello"
#: An escaped pipe INSIDE the key cell, on a row that still splits to four. EXECUTED at base:
#: `…|class|hello` splits to 4 and `…|attrs.a|b|hello` to 5 — exactly one candidate fails.
ASYMMETRIC_ROW = r"l-001|v-001|a\|b|hello"
#: An escaped pipe LEFT of the key cell — the one cell position where the shipped mechanism
#: already corrupts the author's bytes. EXECUTED at base (J16): `locus.row_text` keeps the
#: escape, both candidates come back `l-001|bastion|01|…` at FIVE cells under a four-column
#: header. Needs `VERTICES_WITH_AN_ESCAPED_PIPE_ID`: `_row_dict` unescapes, so the refinement
#: target reads as `bastion|01` and that vertex has to be declared or the warn assertion rides
#: an error-severity refinement-target diagnostic.
ESCAPED_PIPE_LEFT_ROW = r"l-001|bastion\|01|owner|svc.config-mgmt"
#: A quote that opens mid-token once the `attrs.` prefix is spliced in front of it. EXECUTED at
#: base: `attrs."class"` splits to 4, passes the width-only guard, is offered, pastes — and
#: makes the NEXT parse of that row an error.
MID_TOKEN_QUOTE_ROW = 'l-001|v-001|"class"|hello'


def test_suggestion_splits_back_to_the_declared_column_count():
    """Every candidate `check_attr_update_keys` writes into `fix` re-splits to exactly the
    column count `attr_updates_block` declares, for both repair routes `attr_update_keys`
    offers — `class` and `attrs.<key>` — with the author's escaped pipe intact (O6, D6).

    The re-split runs through the SAME splitter the parser uses, never `f.count("|")`: that
    reasoning is what produced the defect. Probed at base (C15): today's rejoin unescapes the
    `\\|` and both candidates split to five cells against a declared four.

    This trigger is unattested in the corpus (C18), so D6 does not stand alone — D7 carries
    the weight.
    """
    doc = attr_doc(ESCAPED_PIPE_ROW)
    d = key_warning(doc)
    assert d.fix, "both candidates survive this row; withholding here loses a working repair"
    for candidate in d.fix:
        assert len(cells(candidate)) == 4, f"{candidate!r} re-splits to {len(cells(candidate))}"
        assert r"curl\|bash" in candidate, "the value cell is the author's bytes"
    assert d.fix[0] == r"l-001|v-001|class|curl\|bash"
    assert d.fix[1] == r"l-001|v-001|attrs.bogus|curl\|bash"


def test_withheld_suggestion_is_an_empty_fix_tuple_on_a_still_flagged_row():
    """When a candidate cannot satisfy O6 the whole suggestion is withheld: `fix` is the empty
    tuple, the Diagnostic is still emitted at warn `severity` with its `locus` intact, the
    message SAYS the suggestion was withheld, and `render_diagnostic` writes no `use:` line
    into `model_context` (O7 and surface B of the return contract, D0b + D7).

    `fix` is `tuple[str, ...] = field(default_factory=tuple)` (C20), so "withheld" is `()` and
    a test asserting `is None` asserts a shape the type forbids.

    ALL-OR-NOTHING, per fork F-E: the reachable asymmetry is an escaped pipe inside the key
    cell (J8 — the odd-trailing-backslash trigger the fork also named is a shape error before
    the key check runs), where `class` survives and `attrs.a|b` does not. Per-candidate
    withholding would hand the author one complete-looking suggestion with no signal that the
    `attrs.` route existed — and made (a)-plus, since `render_diagnostic` cannot signal
    suppression, the withheld case has to say so in the MESSAGE.

    Withholding must not un-flag the row: `locus is not None` or `_addressable` drops the whole
    diagnostic and the row is never flagged at all.
    """
    from defender._artifact_schema import render_diagnostic

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
    """A candidate is byte-identical to `locus.row_text` in every cell the author wrote, and
    differs only in the key cell (O8, D8).

    AMENDED at phase D. Inter-cell padding alone does not discriminate the mechanism the
    design needs: a naive `row.split("|")` rebuild satisfies it and still MISINDEXES the key
    cell the moment a pipe-bearing cell stands to its LEFT (J6). Three members are bound — the
    padding case because it is the attested-shaped half, the combined quoted-pipe-plus-padding
    case because it discriminates a naive split, and the ESCAPED-pipe-left-of-key case because
    it is the one cell position where today's mechanism already corrupts the author's bytes.

    That third row is a live corruption the re-ground probe surfaced and no demand carried
    (J16, executed): `_swap_cell` builds its candidates from `_row_dict`'s UNESCAPED cells and
    `"|".join`s them back, so `bastion\\|01` in `target` comes back as a bare `bastion|01` and
    both offered candidates split to FIVE under a four-column header. J6's quoted-left case
    does NOT cover it — quoting survives the fold and the backslash does not (C16), so the
    quoted row discriminates misindexing while this one discriminates escape loss. D6 exercises
    the escape in the value cell, to the RIGHT.

    Byte-identity is asserted against `locus.row_text`, which is the line already stripped
    (J7), not the on-disk line. And it is a NEW property, not a preserved one: `_split_quoted`
    strips every cell it emits, so today's rejoin normalises the padding away (C17) — writing
    this as a regression over base behaviour would be wrong.
    """
    padded = key_warning(attr_doc(PADDED_ROW))
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
    """A cell quoting its pipe — the whole-cell form and the `k=v` form the design names —
    still splits to the declared width and still appears byte-identical in both candidates
    (O9, D9).

    A regression: the quoted form survives today only because `_row_dict` does not unquote
    (C16). That is incidental, not a guard, which is why it is pinned rather than assumed —
    a raw-text rebuild must not "helpfully" normalise it.
    """
    for value in ('"curl|bash"', 'cmd="curl|bash"'):
        row = f"l-001|v-001|bogus|{value}"
        d = key_warning(attr_doc(row))
        assert d.locus.row_text == row
        assert d.fix == (f"l-001|v-001|class|{value}", f"l-001|v-001|attrs.bogus|{value}")
        for candidate in d.fix:
            assert len(cells(candidate)) == 4


def test_the_backslash_pipe_escape_is_still_accepted_by_the_splitter():
    """`split_cells` still reads `\\|` as one escaped delimiter inside a cell, and a row
    carrying one still parses to the declared width with no parse warning (D10).

    Raised from the design's own normative sentence: "The escape stays accepted. Removing it
    is a tokenizer change with a far wider blast radius than the defect justifies." Nothing
    else in O1-O9 forbids the tokenizer-side fix, and a rebuild that repaired F-47 by dropping
    the escape would pass every other demand here.
    """
    assert cells(r"a|b\|c") == ["a", "b|c"]

    doc = attr_doc(ESCAPED_PIPE_ROW)
    assert warnings_of(doc) == [], "the escaped row is not a parse fault"
    assert cells(ESCAPED_PIPE_ROW) == ["l-001", "v-001", "bogus", "curl|bash"]


def test_suggestion_preserves_leading_but_not_trailing_padding_in_the_value_cell():
    """A value cell written with padding keeps its LEADING padding in every candidate; its
    trailing padding is already gone before the mechanism sees the row (D15).

    Settled premise, corrected twice. Phase C pinned `_swap_cell`'s stripped output — the
    output O8 exists to forbid — and the dispositions' correction over-stated the target: the
    tokenizer strips each line, so `locus.row_text` for `…|bogus|  hello  ` is
    `…|bogus|  hello` (J7) and no rebuild can preserve trailing padding.
    """
    d = key_warning(attr_doc("l-001|v-001|bogus|  hello  "))
    assert d.locus.row_text == "l-001|v-001|bogus|  hello"
    assert d.fix[0] == "l-001|v-001|class|  hello"
    assert d.fix[1] == "l-001|v-001|attrs.bogus|  hello"


def test_even_length_trailing_backslash_run_re_splits_to_the_declared_width():
    """A key cell ending in an EVEN-length run of backslashes pairs up completely, leaving the
    joining `|` intact: the row splits to the declared width and both candidates re-split to
    it (D16).

    Closes fork F-I by executed probe (PO-J1 / J9) rather than by a human decision — the
    values asserted here are the ones the probe observed. The odd-length sibling is NOT
    reachable: the escape eats the delimiter, the row splits to three under a four-column
    header, and it is refused as a shape error before the key check runs at all (J8).
    """
    d = key_warning(attr_doc(r"l-001|v-001|bogus\\|hello"))
    assert d.fix == (r"l-001|v-001|class|hello", r"l-001|v-001|attrs.bogus\\|hello")
    for candidate in d.fix:
        assert len(cells(candidate)) == 4


def test_a_quote_opening_mid_token_is_withheld_not_offered():
    """A candidate that would open a `"` inside a token is WITHHELD: the guard re-splits
    through the parser's own row reader rather than the bare cell splitter, and treats its
    refusal as "withhold" — so `fix` is `()` while the row stays flagged (F-M half one +
    F-H, D17).

    The width-only guard cannot see this class. EXECUTED at base (J11): for a key cell spelling
    a quoted legal keyword, the offered `attrs."class"` splits to four cells, passes both the
    offer guard and the paste gate, lands on disk — and the next parse of that row raises,
    which `diagnose` lifts to error severity. That is a live, currently-shipping wedge.

    F-H's own observable is pinned alongside: a quoted legal keyword IS an illegal refinement
    key today (`_row_dict` never unquotes, C16), it stays one, and the repair that would have
    spliced it behind `attrs.` is not offered.
    """
    doc = attr_doc(MID_TOKEN_QUOTE_ROW)
    d = key_warning(doc)
    assert "'\"class\"'" in d.message, "the quoted keyword is still an illegal key"
    assert d.fix == ()
    assert d.locus is not None
    assert d.locus.row_text == MID_TOKEN_QUOTE_ROW
    assert d.severity == "warning"


def test_an_invisible_character_the_strip_does_not_remove_reaches_model_context_raw():
    """A character the tokenizer's strip does not remove survives into `raw_row` /
    `locus.row_text` byte for byte, and `render_diagnostic` splices that text into
    `model_context` unchanged (D18).

    Two halves, both pinned. The first is the repair window's own round trip: `fix_row`
    addresses a row by the text the warning printed, so a character that survives the strip
    has to survive it on BOTH sides or the model's copy-paste cannot close. The second is this
    spec's R6 finding — the frame line `row: {d.locus.row_text}` is a model-chosen value
    reaching a model-facing sink with no sanitizer between them.

    THE FIRST HALF IS THE DEMAND; THE SECOND IS A CHARACTERIZATION, and the difference is
    recorded rather than left to a reader to notice. The repair window's round trip has to
    hold or the model's copy-paste cannot close, so `locus.row_text == row` and `_flagged`
    addressing it by those exact bytes are asserted as required behaviour. Whether the RENDERED
    text should escape the character instead is a question §7 never took: it is carried in the
    artifact's `handoff.deferred` as an open decision, and the assertion below records today's
    answer so that a change is visible rather than silent. An implementer who escapes it is
    changing a recorded observation, not breaking a contract — say so in the PR and move this
    assertion, do not delete it.
    """
    from defender._artifact_schema import render_diagnostic

    row = "l-001|v-001|bo​gus|hello"
    doc = attr_doc(row)
    d = key_warning(doc)
    assert d.locus.row_text == row
    assert "​" in d.locus.row_text
    assert _flagged(doc) == [row], "the window addresses the row by its exact bytes"
    assert f"row: {row}" in render_diagnostic(d)


def test_a_legal_short_row_is_rebuilt_byte_identically_then_padded_to_the_declared_width():
    """Under a header marking its trailing column optional, a legal short row's candidates are
    rebuilt from the author's raw text and then PADDED to the declared width — byte-identical
    in every cell the author wrote, full width on paste (F-F, D28).

    The human's decision, and the one option that keeps a repair that works today. EXECUTED at
    base (PO-J2 / J10): the current parsed-cell mechanism already pads a legal short row to
    full width and that paste is accepted, so withholding instead would take away a working
    repair — which had to be a recorded decision, not an accident of guard ordering.

    The second half is the resolution's probe-grounded caveat: byte-identity is NOT automatic.
    A rebuild that reuses `_split_quoted` — the natural choice, and the primitive `_split_cells`
    and `_row_cells` are both built on — reaches full width, re-splits cleanly, even preserves
    an escaped pipe, and still silently strips leading/trailing whitespace from every cell it
    did not intend to touch. Only a no-strip boundary scanner passes the padded row.
    """
    plain = key_warning(attr_doc("l-001|v-001|bogus", header=OPTIONAL_ATTR_HEADER))
    assert plain.locus.row_text == "l-001|v-001|bogus"
    assert plain.fix == ("l-001|v-001|class|", "l-001|v-001|attrs.bogus|")
    for candidate in plain.fix:
        assert len(cells(candidate)) == 4

    padded = key_warning(attr_doc("l-001|  v-001  |bogus", header=OPTIONAL_ATTR_HEADER))
    assert padded.fix == ("l-001|  v-001  |class|", "l-001|  v-001  |attrs.bogus|")
    for candidate in padded.fix:
        assert len(cells(candidate)) == 4


def test_paste_gate_enforces_the_same_declared_width_equality_as_the_offer_gate(tmp_path):
    """`suggestion_row` meets the same `declared-width-equality` constraint on the paste via
    that it meets on the offer via: a candidate the offer gate emits is accepted by
    `new_row_shape_reason` and lands, and one that misses the declared width is refused with
    the count named (D13).

    R3's parity obligation. It is the round trip F-47 exists to close: at base the offered
    candidate for this row splits to five cells and the paste earns the SECOND refusal, so
    driving the offer's own output back through `fix_row` is the only assertion that observes
    both ends of the contract at once.

    The last two blocks are the settled idempotency premise — pasting the same repair twice
    earns the window's "nothing is flagged" refusal rather than a second write — and the
    PADDING round trip the design's safety argument rests on and no demand pinned.

    That padding half is brief F9, recorded there as `no-consequence` "because it is the
    property that makes the raw-text mechanism safe" and then never observed. D15's post-change
    expectation is a candidate carrying LEADING padding, and F9 is the only reason such a
    candidate can be pasted at all: `fix_row` matches `old_row` against the STRIPPED row text
    and rewrites the whole on-disk line, trailing padding and all. EXECUTED at base (J17) — a
    row written `…|bogus|  hello  ` is addressed as `…|bogus|  hello`, the padded candidate
    lands, and the window closes. Green at base; it exists to stay green under a rebuild that
    changes what `fix` carries.
    """
    from pydantic_ai.exceptions import ModelRetry

    doc = attr_doc(ESCAPED_PIPE_ROW)
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
    padded_doc = attr_doc(on_disk)
    addressed = key_warning(padded_doc).locus.row_text
    assert addressed == "l-001|v-001|bogus|  hello", "the tokenizer already rstripped the line"
    assert on_disk in padded_doc, "...while the on-disk bytes still carry the trailing padding"

    deps3, run3 = main_deps(tmp_path / "padded")
    seed_investigation(run3, padded_doc)
    _fix(deps3, addressed, "l-001|v-001|class|  hello")
    assert "l-001|v-001|class|  hello" in _inv(run3)
    assert _flagged(_inv(run3)) == [], "the padded repair closed the window"


def test_the_paste_gate_returns_a_reason_where_the_row_reader_would_raise(tmp_path):
    """The parser's row reader is WRAPPED, not substituted: a candidate it refuses comes back
    as a graceful refusal — a reason the model can act on — and never as an exception out of
    the gate (F-M half one's caveat, D29).

    That reader RAISES where both of today's gates return a value: `_new_row_shape_reason`
    returns an explanatory string and `_check_attr_update_keys` returns diagnostics. Swapping
    the splitter in place without catching the row error turns a graceful "it has N cells but
    the block declares M" into an unhandled exception, and turns a warn-only document into
    `validate_investigation`'s fail-closed "validation errored" text.

    Both surfaces are driven: the validator still ACCEPTS the warn-only document whose row
    would make the reader raise, and the repair verb still refuses a bad paste with a reason
    while leaving the file untouched.
    """
    from defender._artifact_schema import validate_investigation
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


def test_a_short_candidate_is_still_refused_where_the_row_reader_would_pad(tmp_path):
    """A candidate SHORTER than the declared width is still refused on paste, under a header
    whose trailing column is optional — the width the paste gate enforces is the header's full
    column count (F-M half one's second caveat, D30).

    The row reader pads a row between `required_cells` and the declared width with empty
    strings and returns normally: no exception, no signal. A guard that substituted it for the
    bare count check would absorb that truncation silently and accept a paste today's gate
    refuses — the same regression in mirror image.
    """
    from pydantic_ai.exceptions import ModelRetry

    doc = attr_doc("l-001|v-001|bogus|hello", header=OPTIONAL_ATTR_HEADER)
    deps, run = main_deps(tmp_path)
    seed_investigation(run, doc)

    with pytest.raises(ModelRetry) as exc:
        _fix(deps, "l-001|v-001|bogus|hello", "l-001|v-001|class")
    assert "3 cells" in str(exc.value)
    assert "declares 4" in str(exc.value)
    assert _inv(run) == doc


def test_a_withheld_fix_row_keeps_its_locus_and_stays_deletable(tmp_path):
    """A row whose repairs were all withheld keeps its `locus`, so it stays in the repair
    window — and `fix_row(old_row, "")` still reaches it (F-M half two, D31).

    F-47's framing is that when a fix is withheld "the only exit left is deleting the row".
    That escape was asserted by the design and pinned by no demand until §7 pinned it HERE,
    which is what this test is (half two resolved to (a) — accept the collision case as a known
    limit, but pin the escape rather than assume it). Why it needs pinning at all: a locus-less
    diagnostic is
    dropped by `_addressable` entirely, and a row that is neither repairable nor deletable
    gates every subsequent write. The collision case the fork also names — a flagged row whose
    text also stands as a whole line the window did not flag — is a pre-existing, unattested
    limit accepted as such.
    """
    from defender._artifact_schema import validate_investigation

    doc = attr_doc(MID_TOKEN_QUOTE_ROW)
    assert _flagged(doc) == [MID_TOKEN_QUOTE_ROW]

    deps, run = main_deps(tmp_path)
    seed_investigation(run, doc)
    _fix(deps, MID_TOKEN_QUOTE_ROW, "")

    after = _inv(run)
    assert MID_TOKEN_QUOTE_ROW not in after
    assert _flagged(after) == []
    assert validate_investigation(after, None) is None


def test_a_row_with_an_illegal_key_and_an_empty_value_is_flagged_once_and_still_offered_a_key_fix():
    """A row breaking two rules — an illegal key AND an empty value — draws exactly ONE
    diagnostic, the warn-severity illegal-key one, and it is still offered its candidates
    (F-G, D32).

    The two checks are an if/else on key legality, so an illegal key never reaches the
    empty-value branch. The design's "never offers a fix that earns a second refusal" is
    scoped here to the SHAPE refusal `new_row_shape_reason` guards, not to every check in the
    validator: applying either candidate leaves the value still empty and the sibling check
    then refuses it on the next pass. Offering the key fix is strictly helpful — the author
    needs both edits anyway, and the key one is the one they cannot guess. Pinned so the
    scoping is not silently re-opened.
    """
    doc = attr_doc("l-001|v-001|bogus|")
    diags = diagnostics(doc)
    assert len(diags) == 1, [d.message for d in diags]
    assert diags[0].severity == "warning"
    assert diags[0].fix == ("l-001|v-001|class|", "l-001|v-001|attrs.bogus|")
    assert "empty" not in diags[0].message


# =========================================================================== #
# O3's payoff over the class of readers that parse without validating
# =========================================================================== #

#: A three-row document whose fold boundary DIFFERS under the two readings: with the later row
#: discarded the lead sits in the closed loop 1 and the fold advances; with it kept the lead
#: moves to loop 2 and loop 1 has no lead at all. EXECUTED at base: `fold_boundary` is 0.
FOLD_FIRST = "l-001|1|alpha|v-001||cmdb|24h|timeout"
FOLD_LATER = "l-001|2|beta|v-002||edr|48h"
FOLD_OTHER = "l-002|2|delta|v-002||edr|48h"
FOLD_REPEAT_DOC = (
    VERTICES + findings_block(FOLD_FIRST, FOLD_LATER, FOLD_OTHER) + close_block(1)
)
FOLD_FIRST_ONLY_DOC = VERTICES + findings_block(FOLD_FIRST, FOLD_OTHER) + close_block(1)
FOLD_LATER_ONLY_DOC = VERTICES + findings_block(FOLD_LATER, FOLD_OTHER) + close_block(1)


def test_the_review_gates_entire_input_sees_the_first_wins_bucket_not_a_blend():
    """`review_projector` — the review gate's ENTIRE input on every confident close — renders
    the first row's lead, not the later row's (D19).

    R7's obligation, and O3's own scope per the design's grounding correction: this is one of
    the three sites the design text itself names as observably different under first-wins
    versus last-wins, and no demand observed it until this one was minted at phase E (its two
    siblings are D20 and D21). The lens is handed a JSON rendering of the
    pruned companion, so the discarded row's values must not appear in it at all.
    """
    from defender.runtime.review.projector import parse_investigation, support_projection

    rendered = support_projection(parse_investigation(REPEAT_DOC), "SALT").text
    assert "alpha" in rendered
    assert "beta" not in rendered, "the lens must not be shown the row the fold discarded"
    assert "v-002" not in rendered

    # The control: the projection really does carry whichever row survives.
    assert "beta" in support_projection(parse_investigation(LATER_ONLY_DOC), "SALT").text


def test_the_compaction_fold_sees_the_first_wins_bucket_not_a_blend():
    """`compaction_fold_boundary` — the fold that buckets leads by `loop` — reads the repeat
    as the first row alone, so a lead the author committed in a closed loop still counts
    toward the boundary (D20).

    The second of O3's three named observably-different sites, and distinct from
    `compaction_detect_loop`: this one buckets, where that one takes a maximum. Under the
    blend the lead moves to loop 2, loop 1 holds no committed finding, and the fold never
    advances — a run that keeps re-sending settled loops to the model.
    """
    from defender.runtime.compaction import fold_boundary

    assert fold_boundary(FOLD_FIRST_ONLY_DOC) == 1
    assert fold_boundary(FOLD_LATER_ONLY_DOC) == 0
    assert fold_boundary(FOLD_REPEAT_DOC) == 1


def test_the_judge_comparison_sees_the_first_wins_bucket_not_a_blend(tmp_path):
    """`judge_compare`'s companion read — the third of O3's named sites — returns the first
    row's lead bucket for a document carrying a within-block repeat (D21).

    The judge parses the run's committed `investigation_md` without validating and swallows
    every exception, so a fused lead reaches the classification silently; there is no channel
    by which the run could learn it was judged on a row the author overwrote.
    """
    from defender.learning.pipeline.judge.compare import parse_investigation_companion

    run = tmp_path / "run"
    run.mkdir()
    (run / "investigation.md").write_text(REPEAT_DOC, encoding="utf-8")

    lead = parse_investigation_companion(run)["findings"][0]
    assert lead["name"] == "alpha"
    assert lead["loop"] == 1
    assert lead["query_details"]["system"] == "cmdb"


def test_a_precedent_case_carrying_the_repeated_id_warning_is_not_loaded_as_clean(tmp_path):
    """`corpus_load_one` — the ONE fused-bucket reader that keeps its warnings rather than
    discarding them — reports a stored case carrying a within-block repeat as PARTIAL, and its
    lead is the first row's (D22).

    R7's obligation over C11's census. The other ten non-validating readers drop their
    warnings; this one carries them into a `LoadReport`, which is what makes "not loaded as
    clean" observable at all. Without the diagnostic the case is indistinguishable from a
    sound precedent, and the corpus is what a later run reasons from.
    """
    from defender.skills.invlang.corpus import load_corpus

    case = tmp_path / "case-1"
    case.mkdir()
    (case / "investigation.md").write_text(REPEAT_DOC + CONCLUDE_BENIGN, encoding="utf-8")

    companions, report = load_corpus(tmp_path)
    assert report.loaded == 1
    assert report.total_warnings >= 1, "a repeat must not load as a clean precedent"
    assert any(
        REPEAT_PHRASE in w.reason for _path, ws in report.partial for w in ws
    ), "the kept warning is the repeated-id one"
    assert companions[0].leads[0]["name"] == "alpha"


#: The false-positive entry price's discriminating trio. The rows disagree on `target`, and only
#: the FIRST row's target is a vertex the prologue carries — so `_check_false_positive_gating`'s
#: "targets X, which the prologue does not carry" arm fires under last-wins and is silent under
#: first-wins. The refinement block gives the lead a committed result, so the gate's
#: `_lead_returned_a_result` arm is quiet and the `target` arm is the only thing observed.
FP_FIRST_ROW = "l-001|1|alpha|v-001||cmdb|24h"
FP_LATER_ROW = "l-001|2|beta|v-999||edr|48h"
FP_RESULT = attr_block("l-001|v-001|attrs.owner|svc-deploy")


def _fp_doc(*rows):
    return VERTICES + findings_block(*rows) + FP_RESULT + CONCLUDE_FALSE_POSITIVE


def test_the_false_positive_entry_price_sees_the_first_wins_bucket_not_a_blend():
    """`disposition_entry_price` — the close's second, non-validating read of the companion —
    prices a `false-positive` document carrying a within-block repeat off the FIRST row's
    `target`, so a repeat whose later row names an entity the prologue never carried owes
    NOTHING, exactly as the same document with the later row never written (D33).

    REWRITTEN. The first pass asserted `observe(repeat) == observe(first_only)` over three
    readers, guarded only by "the channel is non-empty" — and execution showed
    `observe(first_only) == observe(later_only)` at all three, so the equality was true under
    first-wins, last-wins and today's blend alike. A test that cannot fail for its stated
    reason reads as coverage; the two readers where no fixture discriminates are withdrawn to
    cited waivers (D37, D38) and this one is rebuilt around a channel that does.

    The control is D3's, not the first pass's: `later_only` is asserted to owe the target error
    BEFORE the repeat is asserted to owe nothing, which is what proves this reader can tell the
    two rows apart at all. §7 refused this site's waiver because the gate leaf could not cite
    its line number; the citation exists (validate.py:2608, N2 and C11), and the re-decision is
    on an executed probe of observability (J18) rather than on membership in C11's class — the
    thing §7 declined to assume must not be assumed downstream to justify a weaker test.

    The harm is the close's own: a fused lead makes a legal false-positive close refuse against
    a row the author wrote correctly, and — with the rows the other way round — lets one pass
    on an entity the alert never named.
    """
    later_owed = entry_price("false-positive", _fp_doc(FP_LATER_ROW))
    assert len(later_owed) == 1, later_owed
    assert "v-999" in later_owed[0], "the channel really does read the lead's own target"

    assert entry_price("false-positive", _fp_doc(FP_FIRST_ROW)) == ()
    assert entry_price("false-positive", _fp_doc(FP_FIRST_ROW, FP_LATER_ROW)) == (), (
        "the later row was discarded, so its target is not what the price is read against"
    )


#: The `:R attr_updates` block that OPENS the lead's bucket, standing BEFORE the repeating
#: `:L findings` block. Every other fixture in this file puts the refinement block after the
#: findings block — the ordering 20-demands' D12 note fixed at extraction and every later
#: fixture inherited — so this is the only document here that can observe what the fold does to
#: a bucket that already holds content.
SEEDING_BLOCK = attr_block("l-001|v-001|attrs.owner|svc-deploy")
SEEDED_UPDATES = [{"target": "v-001", "updates": {"attrs.owner": "svc-deploy"}}]


def test_a_lead_bucket_an_earlier_refinement_block_seeded_survives_the_fold():
    """When a `:R attr_updates` row has already opened a lead's bucket, the first-wins fold
    over a later repeating `:L findings` block MERGES INTO that bucket — the seeded resolution
    content survives — and the identity it lands is the FIRST row's (D39).

    A settled premise (`test_f46_a_lead_is_referenced_before_a_block_that_declares_it_twice`)
    that reached no demand, no §7 record and no `drops` entry while every count stayed perfect.
    Its mechanism is written into the code it constrains: `_lead_header_record`'s own docstring
    says the outcome fields are returned SEPARATELY "so the caller cannot merge them with a
    plain `dict.update`, which would overwrite the lead's whole outcome and discard resolution
    buckets an earlier `:R` block already projected onto it", and `lead_bucket`'s `setdefault`
    hands back the same dict object on every call.

    It discriminates where nothing else here can. A first-wins fold implemented as
    `proj.findings[rid] = identity` rather than an in-place update passes D0a (whose
    differential compares two documents with no interposed `:R` block), passes D26 (the key
    already exists, so publication order is untouched) — and silently destroys a seeded
    `outcome`/`resolutions` bucket, which is the same class of in-block content loss F-46 was
    filed for. Both halves are asserted together because either alone is satisfiable by the
    wrong implementation.

    Green half at base, red half at base: the seeded `attribute_updates` already survive
    today's blend, and today's blend takes the LATER row's identity (J19, executed).
    """
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


# =========================================================================== #
# F-L — the uniform formation gate
# =========================================================================== #

#: A document whose committed `:L findings` block ALREADY holds a within-block repeat, and
#: whose surviving lead is committed in loop 1 under BOTH readings — so a `:T close` for that
#: loop is legal either way and the only thing that can refuse it is the repeat itself.
LEGACY_DOC = VERTICES + findings_block(
    "l-001|1|alpha|v-001||cmdb|24h|timeout",
    "l-001|1|beta|v-002||edr|48h",
)
#: The same document with the repeat removed — the control that proves each refusal below is
#: about the repeat and not about the block being appended.
REPAIRED_DOC = VERTICES + findings_block("l-001|1|alpha|v-001||cmdb|24h|timeout")
#: A legal refinement block to append onto either.
NEXT_BLOCK = attr_block("l-001|v-001|class|svc.config-mgmt")


def test_a_close_block_write_is_refused_exactly_as_an_ordinary_block_append(tmp_path):
    """A document carrying a within-block repeat is refused when the run appends a `:T close`
    BLOCK exactly as it is refused when the run appends any other block — the same
    `validate_investigation` over the full proposed text, reached over the same `decide_write`
    via, naming the same repeated id (D14).

    RENAMED AND RE-ADDRESSED. This is a parity between two BLOCK WRITES, not evidence about
    the `close_investigation` VERB, and the earlier name said otherwise while the suite
    contained no call to that verb at all. Executed twice at base — once here (J14), once
    independently at phase F — `close_investigation` validates `report.md` and nothing else: a
    document carrying an outright error-severity invlang finding CLOSES, returns
    `outcome == "stands"` and commits a report, leaving `investigation.md` byte-identical and
    unvalidated. The artifact's `close_investigation -> validate_investigation` edge and its
    `close_path` access cell are deleted rather than left standing, because an implementer
    reading them top-down would build a gate the run proved absent.

    That gap is NOT closed here, by the human's decision: it admits *any* error-severity
    finding to a committed report, not merely this fusion, and it was never enumerated by this
    spec — so it is filed as **#961** and no demand in this file gates the close verb.
    What the human's uniform FORMATION gate means is that no verb can WRITE a malformed
    document, which is exactly the parity below.

    EXECUTED at base (J3): a committed document already carrying the repeat makes the gate
    refuse every proposal that RETAINS it and accept one that removes it — the refusal is a
    property of the proposed text, not of the baseline, which is why no legacy exemption
    exists to test for.

    The control block is the point: over the repaired document BOTH writes land, so the
    refusals above are about the repeat and not about the blocks.
    """
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
    """A document written BEFORE this ships, already holding a within-block repeat, is refused
    at every verb that WRITES invlang bytes, with no grandfathering and no suppression
    condition (F-L, D34).

    WHAT THIS BODY DRIVES, said at exactly that width because the earlier wording claimed a
    third write it never made: an ordinary `append_block`, `fix_row` against the repeat itself
    (refused by the empty repair window), and `fix_row` against a CO-RESIDENT flagged row
    (refused by the write gate) — TWO verbs, three writes, plus the control. The `:T close`
    BLOCK append is a fourth write through the same `append_block` verb and its parity is
    `test_a_close_block_write_is_refused_exactly_as_an_ordinary_block_append`, next door; read
    the two together for the block-shape coverage, not this one alone.

    "EVERY VERB" IS FORMATION, AND IS SAID THAT WAY DELIBERATELY. The `close_investigation`
    verb itself does not validate the document (J14, executed twice) and is not gated by
    anything in this file; it writes no invlang bytes, so it forms nothing malformed, and the
    consumption gap it leaves is filed as #961 rather than folded in. One non-verb writer of
    `investigation.md` is likewise a deliberate, filed exclusion and not an oversight:
    `lead_zero._declare_l_finding` seeds a one-row `:L findings` block before MAIN's first
    turn without meeting any gate, cannot form a within-block repeat, and is #964.

    The human rejected all three options offered and chose a uniform formation gate: a run
    should not be able to hold a malformed document in the first place, because the write-time
    gate rejects it. The residual is recorded and knowingly accepted — documents written under
    a gate that did not judge this are precisely the population a uniform gate never judged,
    measured at zero across 24 live documents and 155 lead rows, with a run in flight at the
    instant of deploy the exposure no scan can close.

    Two different gates refuse the repair, and the order matters (J4): the repeat is
    error-severity and carries no locus, so it is never in the repair window at all — the verb
    refuses before the write gate is reached — and a repair of a CO-RESIDENT flagged row is
    then refused by the write gate, because the proposed text still carries the repeat.
    """
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
    with pytest.raises(ModelRetry) as repair_exc:
        _fix(deps2, warn_row, "l-001|v-001|class|svc.config-mgmt")
    assert REPEAT_PHRASE in str(repair_exc.value)

    # The control: the same repair on a document without the repeat lands.
    deps3, run3 = main_deps(tmp_path / "clean")
    seed_investigation(run3, REPAIRED_DOC + attr_block(warn_row))
    _fix(deps3, warn_row, "l-001|v-001|class|svc.config-mgmt")
    assert "l-001|v-001|class|svc.config-mgmt" in _inv(run3)


def test_a_legacy_repeat_is_refused_at_the_learning_intake(tmp_path):
    """A closed run whose committed document holds a within-block repeat is refused at the
    learning intake's own gate — the error-partition copy path — and nothing is staged (D35).

    The fourth F-L premise. The intake validates the investigation on the copy path with the
    same error-severity partition the write gate uses, so the uniform outcome reaches past the
    verbs the runtime drives.

    WHAT IS OBSERVED IS THE REFUSAL AND THE ABSENCE, not the routing. The demand's own prose
    used to add "the run lands in the failed queue for a human" — one grain above what this
    test drives, which is `_copy_shared_inputs` raising `RunUnprocessable` and staging nothing.
    Where an unprocessable run then goes is the drain's business and no claim in this graph
    covers it, so the sentence is narrowed rather than asserted: the observable is that the
    defective document does not reach the loop, and the control is that a repeat-free run does.
    """
    from defender.learning.core.config import RunUnprocessable
    from defender.learning.core.persist import _copy_shared_inputs

    run = tmp_path / "run"
    run.mkdir()
    (run / "alert.json").write_text('{"rule": {"id": "R-1"}}', encoding="utf-8")
    (run / "report.md").write_text(
        "---\ndisposition: benign\n---\n\nbody\n", encoding="utf-8"
    )
    (run / "investigation.md").write_text(LEGACY_DOC, encoding="utf-8")
    staged = tmp_path / "staged"

    with pytest.raises(RunUnprocessable) as exc:
        _copy_shared_inputs(run, staged)
    assert "invlang validation" in str(exc.value)
    assert not (staged / "investigation.md").exists()

    # The control: the same run with the repeat removed stages cleanly.
    (run / "investigation.md").write_text(REPAIRED_DOC, encoding="utf-8")
    staged2 = tmp_path / "staged2"
    _copy_shared_inputs(run, staged2)
    assert (staged2 / "investigation.md").exists()
