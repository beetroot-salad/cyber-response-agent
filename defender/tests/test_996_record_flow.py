"""#996 — `record`, the clerk round loop, and the receipt MAIN reads.

Every demand here is driven through the whole `run_investigation` loop with an injected clerk,
because the receipt, the round loop, the trace and the document do not exist at any lower
altitude — and the receipt is a string the MODEL is sent, so the honest place to read it is the
message history the fake main model records, not a return value.

RED against `7fa49f04`: `run_investigation` does not accept a clerk, `record` is not registered
for MAIN, and `defender/runtime/clerk.py` does not exist. That is the expected state of a spec.

Two conventions this file keeps, both from `70-resolutions.md`:

  * Where the design fixes an outcome line verbatim (v2:73) the test asserts the line. Where a
    resolution ADDS an outcome the design never worded — AR-7's diagnostic-less refusal — the
    test asserts "exactly one outcome line, none of the six fixed ones, naming the refusal",
    rather than inventing a string an implementer would then have to guess.
  * Every fault a clerk fake injects cites the resolution or probe that observed it. No fault
    here is imagined; `_clerk_996.Fault` carries the citations.

PLACED TOP-LEVEL RATHER THAN UNDER `tests/e2e/`, and marked `e2e` so the marker
selection is unchanged: `check_binds` scans ONE directory non-recursively (`_suite.suite_files`
globs `*.py`), and this graph names `defender/tests` — a demand whose test sat one level down
would be reported as a dangling pointer and its prose would never be scanned. The same reason
the #836, #869, #870 and #954 graphs all record "top-level files only".
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402

from defender._artifact_schema import INVESTIGATION_FILE_MAX  # noqa: E402
from defender.agents import MAIN_DEF  # noqa: E402
from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.runtime.tools import AgentDeps, register_tools  # noqa: E402
from defender.tests import _clerk_996 as C  # noqa: E402
from defender.tests.e2e._replay_harness import Turn  # noqa: E402

pytestmark = pytest.mark.e2e


# ---------------------------------------------------------------------------------------
# the receipt (D9, F0a/F0b/F5; AF-2)
# ---------------------------------------------------------------------------------------


def test_996_record_receipt_sections_in_order(tmp_path: Path) -> None:
    """One `record` call returns ONE tool-result string whose sections appear in the design's
    order: `_tool_append_block`'s own return (1), then EXACTLY ONE outcome line (2), then
    `GAPS:` verbatim (4).

    The ORDER is the assertion, not mere presence: MAIN reads this string top-down and a
    receipt whose outcome precedes the bytes it is about reads as an outcome for the wrong
    call.

    SPLIT FROM SECTION (3) BECAUSE THE FOUR CANNOT CO-EXIST ON ONE FIXTURE, and pretending
    otherwise is how the earlier form of this test came to assert something no implementation
    could satisfy. Section (3) renders "whenever the window is open at return"
    (v2:73) — and the design's own step 0 returns BEFORE appending the prose while a row is
    still flagged (v2:83, and `..._a_still_open_window_returns_before_the_prose_is_appended`),
    so the state that makes (3) render is precisely the state that forbids (1) and (2). The
    sibling below drives that state and owns (3)'s position and its render-once rule. Here the
    window is SHUT at return, which is what lets (1), (2) and (4) all render — and `FLAGGED:`
    is asserted ABSENT, which is not a whole-turn absence scan but the section's own stated
    condition read on the arm where it is false."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS, gaps=("who owns svc.config-mgmt?",)))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    assert len(C.outcome_lines(receipt)) == 1, (
        f"section (2) is EXACTLY ONE outcome line; got {C.outcome_lines(receipt)}"
    )
    appended = receipt.find("bytes to investigation.md")
    outcome = receipt.find(C.outcome_lines(receipt)[0])
    gaps = receipt.find("GAPS:")
    assert appended != -1, "section (1) — `_tool_append_block`'s own return — is missing"
    assert gaps != -1, "the clerk returned a gap and section (4) did not render"
    assert "FLAGGED:" not in receipt, (
        f"the clerk's rows landed clean and the window is shut at return, so section (3)'s own "
        f"stated condition is false and it must not render: {receipt!r}"
    )
    assert appended < outcome < gaps, (
        f"the receipt's sections are out of order: appended@{appended} outcome@{outcome} "
        f"gaps@{gaps}"
    )


def test_996_the_flagged_section_renders_once_and_after_the_repair_line(
    tmp_path: Path,
) -> None:
    """Section (3) — `FLAGGED:` — renders ONCE per receipt and AFTER section (0)'s repair line.

    The reading fork F-RECEIPT-FLAGGED closed on (AF-2): a second rendering shows MAIN the same
    diagnostics twice in one receipt, which is the failure an implementation renders when it
    emits the flagged block once inside step 0's own report and again from the "window open at
    return" rule. Both rules fire on THIS fixture — step 0 ran and the window is open at return
    — so it is the one shape where the double render is reachable, and counting is therefore a
    real discrimination rather than a tautology.

    The fixture is step 0's own return arm: a warn window already open and a clerk that declines
    to repair (the empty `fix_row` list), which v2:83 returns from before the prose is appended.
    Sections (1) and (2) therefore do NOT render here, and that is asserted too — an
    implementation that appended MAIN's prose anyway would show a `bytes to investigation.md`
    line for bytes the gate must have refused."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    clerk = C.ScriptedClerk(C.repair_reply())   # the clerk declines the repair
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    assert receipt.count("FLAGGED:") == 1, (
        f"`FLAGGED:` rendered {receipt.count('FLAGGED:')} times in one receipt; AF-2 closed "
        f"F-RECEIPT-FLAGGED on exactly one rendering: {receipt!r}"
    )
    lines = C.outcome_lines(receipt)
    assert len(lines) == 1, (
        f"section (0)'s repair report is the receipt's ONE `record:` line here — nothing was "
        f"appended and nothing was committed, so no section (2) outcome can render: {lines}"
    )
    assert "still flagged" in lines[0], (
        f"section (0) does not report the repair round's outcome: {lines[0]!r}"
    )
    assert receipt.find(lines[0]) < receipt.find("FLAGGED:"), (
        f"`FLAGGED:` precedes the repair line it belongs to: {receipt!r}"
    )
    assert "bytes to investigation.md" not in receipt, (
        f"the window was open at return, so nothing could be appended — yet section (1) "
        f"rendered: {receipt!r}"
    )


def test_996_the_receipts_first_section_names_no_verb_main_lacks(tmp_path: Path) -> None:
    """Section (1) is `_tool_append_block`'s return VERBATIM-MODULO-D15: whatever it carries,
    it never hands MAIN an instruction to call a verb MAIN no longer holds.

    `_tool_append_block`'s warn return ends with "repair each flagged row with `fix_row(...)`"
    DELIBERATELY (F4) — and D14 takes `fix_row` off MAIN's roster, so relaying it byte-for-byte
    trips one of O1's own stated failing conditions. Mechanism 6 owns the append return's text
    too, and D11 already parameterizes the verb name for exactly this reason.

    PO-9 refutes the OTHER half of D9's stated rationale for "verbatim" and it must not be
    restored: `_document.py`'s fast-path guard returns early before frontier derivation runs
    whenever the appended text lands no fence, so the #919 lessons recall D9 cites is
    STRUCTURALLY unreachable on MAIN's prose-only step-1 append — confirmed by two executed
    appends. Section (1) is re-justified on the byte count alone; nothing may add a code path
    that makes a prose-only append carry a recall in order to make D9's sentence true again.

    THAT PROHIBITION IS ASSERTED HERE RATHER THAN ONLY STATED. A correction carried in prose is
    a correction the next implementer restores: the recall block's absence is a probed fact
    whose whole consequence — section (1)'s re-justification — rests on it, and until this
    assertion existed nothing in the suite moved if a code path put the block back. PO-9's own
    third run is the ready-made positive control and it is driven below, because a negative
    scan for a block this receipt might never carry under ANY input discriminates nothing:
    MAIN prose smuggling a COMPLETE invlang fence moves the frontier, and the same section (1)
    does carry the recall then.
    """
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.WARN_ROWS), C.repair_reply())
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    assert "bytes to investigation.md" in receipt, "section (1) never rendered"
    for lost in ("fix_row(", "append_block"):
        assert lost not in receipt, (
            f"the receipt names {lost!r}, a verb D14 removed from MAIN's roster — O1's own "
            f"failing condition, reached through section (1)'s verbatim rule"
        )
    assert C.LESSONS_RECALL_LEAD not in receipt, (
        "a PROSE-ONLY append carried the #919 lessons recall, so a code path was added that "
        "makes D9's refuted sentence true again — DC-1 forbids exactly this"
    )

    # PO-9's third executed run, as the control: the same seam, fence-carrying input.
    smuggled = C.new_run_dir(tmp_path, name="smuggled")
    _, control, _ = C.record_run(
        tmp_path, run_dir=smuggled, prose=[C.QUOTED_FENCE_PROSE],
        clerk=C.ScriptedClerk(C.clerk_reply("")),
    )
    assert C.LESSONS_RECALL_LEAD in control.receipt, (
        "MAIN prose smuggling a complete invlang fence moved the frontier and section (1) "
        "still carried no recall — the negative above cannot tell a restored code path from "
        "a receipt that never relays the block under any input"
    )


def test_996_a_rows_held_receipt_names_every_owed_fact(tmp_path: Path) -> None:
    """When the loop stops on the judgment partition, the receipt's held section names EVERY
    owed fact — one line per unresolved obligation, the same lines the close's own refusal
    renders.

    The fixture owes two: both declared vertices carry an unresolved class, and
    `_check_disposition_gating` prices each separately. A receipt that names one of the two is
    a receipt MAIN answers half of, records again, and is held on again."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.OPEN_SLOT_PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.JUDGMENT_ONLY_ROWS))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    assert C.OUTCOME_HELD in receipt, C.outcome_lines(receipt)
    for vertex in ("v-001", "v-002"):
        assert vertex in receipt, (
            f"the held receipt does not name the fact owed for {vertex}; MAIN cannot answer an "
            f"obligation it was not told about"
        )


def test_996_every_clerk_gap_appears_in_the_receipt(tmp_path: Path) -> None:
    """Every GAP the clerk returned appears in the receipt, verbatim — O2's own failing
    condition is "a GAP the clerk returned absent from the receipt".

    A MALFORMED gaps section is rendered verbatim and UNVALIDATED ([26]): the receipt is the
    only channel by which MAIN learns what the clerk could not settle, and a renderer that
    silently drops a bullet it could not parse fails O2 for the shape that needed it most."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    gaps = ("who owns svc.config-mgmt?", "*** unbalanced [markup", "")
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS, gaps=gaps))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    assert "GAPS:" in receipt
    for gap in gaps[:2]:
        assert gap in receipt, f"the clerk's gap {gap!r} never reached MAIN"


def test_996_clerk_text_relayed_to_main_is_length_capped(tmp_path: Path) -> None:
    """The clerk's own prose reaches MAIN's context through the receipt UNFILTERED, and that is
    accepted — the same text originated in MAIN's own context — but it is BOUNDED.

    S2 as written overclaims: it says what the clerk can do with steered text is bounded by S3
    and S6, but S3 bounds where bytes may LAND and S6 bounds the conclude guard; neither
    constrains the CONTENT of a GAPS bullet, which reaches MAIN verbatim. The amendment states
    the actual boundary and adds a LENGTH cap plus control/markup stripping. A content filter
    over model prose is not testable and is deliberately NOT adopted, so this asserts only what
    can be observed: the relayed text is shorter than what the clerk sent, and no control byte
    survives into MAIN's context."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    bullet = C.huge_gap()
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS, gaps=(bullet,)))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    assert len(receipt) < len(bullet), (
        f"the receipt is {len(receipt)} chars for a {len(bullet)}-char clerk bullet — the "
        f"clerk's output reaches MAIN's context unbounded"
    )
    for ctrl in ("\x00", "\x1b"):
        assert ctrl not in receipt, "a control byte from the clerk's prose reached MAIN"


# ---------------------------------------------------------------------------------------
# flow 1 — the prose lands first, and its own refusal is MAIN's
# ---------------------------------------------------------------------------------------


def test_996_record_lands_main_prose_before_calling_the_clerk(tmp_path: Path) -> None:
    """`record` appends MAIN's prose through `_tool_append_block` BEFORE the clerk is called,
    and the clerk is shown the document that already carries it.

    Driven with a clerk that faults on its very first call, so the only way the prose can be on
    disk afterwards is if step 1 ran before step 3. Both halves are asserted: the prose is in
    the document, and it is in the document view the clerk was handed — a `record` that
    compiled first and appended after would show the clerk a document without it."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(fault=C.Fault(raise_after=0))
    _, _, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    doc = C.document(run_dir)
    assert C.PROSE in doc, "MAIN's prose never landed — step 1 did not run before step 3"
    assert clerk.prompts, "the clerk was never called at all"
    assert C.PROSE in clerk.prompts[0], (
        "the clerk was shown a document that does not carry MAIN's prose, so the prose was "
        "appended after the call rather than before it"
    )


def test_996_a_refusal_on_mains_own_bytes_reaches_main_unchanged(tmp_path: Path) -> None:
    """A write-gate refusal on MAIN's OWN bytes reaches MAIN as today — it is MAIN's text, so
    MAIN is the author who can repair it, and O1's boundary is not crossed.

    MAIN quotes attacker-shaped evidence back into its prose: a complete, well-formed invlang
    fence refining a vertex nothing declares. `_tool_append_block` refuses the whole document,
    nothing lands, and the refusal reaches MAIN through the same `ModelRetry` channel it uses
    today. The clerk is never reached at all — step 1 refused, so there is nothing to compile.
    """
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    quoting = "Quoting the offending block back:\n\n" + C.UNDECLARED_TARGET_ROWS
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk, prose=[quoting])

    assert main.retries, "MAIN was handed no refusal for bytes it wrote itself"
    assert "v-404" in main.retries[-1], main.retries
    assert "v-404" not in C.document(run_dir), "the refused bytes landed anyway"
    assert clerk.calls == 0, (
        "the clerk was called for a prose append that was refused — there is nothing to compile"
    )


def test_996_flagged_write_refusal_through_record_names_record(tmp_path: Path) -> None:
    """The flagged-write refusal MAIN receives names `record`, the verb MAIN actually holds.

    D11 makes `flagged_write_refusal`'s verb name the CALLER's. Reached through the whole loop
    rather than by calling the helper: the name that matters is the one on the string the model
    is sent, and a helper called with the right argument from a call site that hands MAIN a
    different string would pass a unit check and fail the model."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    clerk = C.ScriptedClerk(C.repair_reply())
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    seen = "\n".join([*main.receipts, *main.retries])
    assert seen, "MAIN was handed nothing at all"
    assert "`record`" in seen or "record is blocked" in seen, seen[:400]
    assert "`append_block` is blocked" not in seen, (
        "MAIN was told `append_block` is blocked — a verb it does not hold"
    )


def test_996_direct_append_block_callers_still_see_append_block(tmp_path: Path) -> None:
    """The internal writer keeps its own name for its DIRECT callers: `flagged_write_refusal`
    called for `append_block` still says `append_block`.

    D11 parameterizes the verb name; it does not rename the writer. The two roles that grant
    the document verbs directly, and the #836 suite that drives `_tool_append_block` as itself,
    must keep reading their own name — a rename that reached them would tell a caller to use a
    verb it never had."""
    from defender.runtime.tools._document import flagged_write_refusal
    from defender.skills.invlang.validate import warn_diagnostics

    diags = tuple(warn_diagnostics(C.PROLOGUE + C.WARN_ROWS))
    assert diags, "the fixture no longer opens a warn window"
    text = flagged_write_refusal("append_block", diags)
    assert "`append_block` is blocked" in text, text[:200]


# ---------------------------------------------------------------------------------------
# flow 2 — the clerk's prompt (D5, S2)
# ---------------------------------------------------------------------------------------


def test_996_clerk_prompt_carries_only_main_authored_text(tmp_path: Path) -> None:
    """The clerk turn's slots are all bound and all MAIN-authored: the grammar and catalog, the
    document so far, `pending`, this prose, and the previous call's gaps.

    Asserted against the CAPTURED INBOUND PROMPT, never against the fake's canned reply — a
    fake that only answers leaves the whole outbound channel unpinned. Every slot is asserted
    by its VALUE (the grammar's own heading, the seeded document's bytes, MAIN's prose) so the
    turn's layout stays the implementer's; only the empty-`pending` rendering is pinned on a
    label, and for its own reason."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    turn = clerk.only()
    assert ":V prologue.vertices" in turn, "the invlang grammar/catalog slot is unbound"
    assert "v-001|compute|bastion" in turn, "the document-so-far slot is unbound"
    assert C.PROSE in turn, "MAIN's prose — the thing being compiled — is not in the turn"


def test_996_no_gather_summary_or_raw_reaches_the_clerk(tmp_path: Path) -> None:
    """NEGATIVE (S2, D5): no gather summary and no raw payload byte reaches the clerk, on any
    of the clerk's inbound surfaces.

    POSITIVE CONTROL, on the same address under the complementary condition: the marker bytes
    ARE present in the run dir the clerk's own builder reads its document from, and they ARE in
    MAIN's context — so the absence is a scope the builder holds, not an empty run. Without the
    control the assertion is green on a run where gather never happened.

    S2 is a FRAMING property, not a content one: MAIN's prose may quote attacker-controlled log
    content, and that is MAIN's boundary to hold, as today."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    marker = "SUMMARY-MARKER-996-do-not-relay"
    summaries = run_dir / "gather_summaries"
    summaries.mkdir(parents=True, exist_ok=True)
    (summaries / "l-001.md").write_text(marker + "\n", encoding="utf-8")
    (run_dir / "gather_raw" / "l-001").mkdir(parents=True, exist_ok=True)
    (run_dir / "gather_raw" / "l-001" / "0.json").write_text(
        '{"hit": "RAW-MARKER-996"}\n', encoding="utf-8")

    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert marker in (summaries / "l-001.md").read_text(encoding="utf-8"), (
        "the positive control is missing: the marker bytes are not in the run dir at all, so "
        "the negative below would pass on an empty run"
    )
    turn = clerk.only()
    assert marker not in turn, "a gather SUMMARY reached the clerk's prompt"
    assert "RAW-MARKER-996" not in turn, "a gather RAW payload byte reached the clerk's prompt"


def test_996_an_empty_pending_renders_no_placeholder_in_the_clerk_turn(tmp_path: Path) -> None:
    """`pending`'s falsy default renders EMPTY, not as a placeholder.

    Driven on the FIRST clerk turn of a run, where nothing has been pended: the turn carries a
    `pending` slot and that slot's body is blank. An `x or DEFAULT`-shaped read leaves "none" /
    "(empty)" / "[]" there, and a clerk that reads a placeholder as a pended entry re-emits
    rows for prose nobody sent — which is why the falsy default is individually exercised
    rather than inferred from the non-empty case."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    body = C.pending_section(clerk.only())
    assert body is not None, (
        "the clerk turn carries no `pending:` slot at all — the empty state is unobservable, "
        "and so is the difference between empty and coerced"
    )
    assert body.strip() == "", f"the empty pending slot rendered {body.strip()!r}"
    lowered = body.lower()
    for placeholder in C.PLACEHOLDERS:
        assert placeholder not in lowered, (
            f"the empty pending slot rendered the placeholder {placeholder!r}"
        )


def test_996_the_previous_calls_gaps_are_handed_to_the_next_clerk_call(tmp_path: Path) -> None:
    """`last_gaps` is re-served: the gaps one `record` returned are in the NEXT call's turn.

    The clerk asked MAIN a question through the receipt; the next turn is where MAIN's answer
    can be matched against it. A caller that clears the gaps on return asks the same question
    every round."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    gap = "which lead grounds the owner claim?"
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.CLEAN_ROWS, gaps=(gap,)),
        C.clerk_reply(""),
    )
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                 prose=[C.PROSE, C.SECOND_PROSE])

    assert clerk.calls >= 2, f"the second `record` never reached the clerk ({clerk.calls} calls)"
    assert gap in clerk.prompts[1], (
        "the previous call's gaps were not handed to the next clerk call"
    )


# ---------------------------------------------------------------------------------------
# flow 3 — the round loop, D7 and S6
# ---------------------------------------------------------------------------------------


def test_996_clerk_loop_stops_at_six_rounds(tmp_path: Path) -> None:
    """The round loop's budget is SIX: a clerk that never clears the structural refusal is
    called at most six times for one `record`, and the seventh call never happens.

    The bound is what keeps a compiling failure from becoming an unbounded spend on the model
    that is failing, and it is the same number HD-4 caps `pending` at."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.UNDECLARED_TARGET_ROWS))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls == 6, (
        f"the round loop made {clerk.calls} clerk calls for one `record`; the budget is 6"
    )


def test_996_repair_rounds_and_round_loop_rounds_share_one_budget(tmp_path: Path) -> None:
    """The budget of six is ONE POOL per `record` call: repair rounds and round-loop rounds
    draw from it together, so a call that spends three repairing has three left to compile
    with — never six more.

    The settled reading is "one shared pool of six clerk invocations per `record` call, repair
    rounds included", and it took a judge settlement against a unanimous hedge to fix it there.
    The design says the same twice: flow 0's repair rounds run on the "same budget" as the
    round loop, and the scale dive bounds a call at six rounds INCLUDING repair rounds.

    THE SIBLING TEST ABOVE CANNOT SEE THE DIFFERENCE and neither can any repair test: the
    round-loop test drives zero repair rounds, and every repair test asserts content or
    ordering and counts no calls. An implementation carrying two independent budgets of six
    passes all of them while doubling the worst-case clerk spend the cap exists to bound — and
    it desynchronises the pending cap, which was chosen as "the repair-round budget's own
    number" and would then name an ambiguous constant.

    The one scenario that crosses both halves in a single call: a window already open, a clerk
    that declines the repair twice and repairs on the third round, after which the prose lands
    and the round loop meets a structural refusal it never clears. One pool spends 3 on repair
    and has 3 left, and the sixth call is a round-loop retry carrying the refusal; two pools
    spend 3 and then 6, and the call ends after nine.
    """
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    clerk = C.ScriptedClerk(
        C.repair_reply(),                         # round 1: declined, the window stays open
        C.repair_reply(),                         # round 2: declined again
        C.repair_reply(C.REPAIR_PAIR),            # round 3: the window shuts
        C.clerk_reply(C.UNDECLARED_TARGET_ROWS),  # rounds 4+: structurally refused, repeats
    )
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    doc = C.document(run_dir)
    assert "attrs.owner" in doc, (
        "the repair never landed, so the window never shut and the round loop was never "
        "entered — this scenario measured the repair budget alone and cannot see a second pool"
    )
    assert C.PROSE in doc, (
        "MAIN's prose never landed, so the call never reached the round loop"
    )
    assert clerk.calls == 6, (
        f"one `record` call made {clerk.calls} clerk calls; the budget is SIX for the whole "
        f"call, repair rounds included — 9 is two independent pools of six, which every other "
        f"test in this suite accepts"
    )
    assert "v-404" in clerk.prompts[-1], (
        "the last of the six calls is not a round-loop retry carrying the structural refusal, "
        "so the three repair rounds did not draw the loop's own budget down with them"
    )


def test_996_a_structural_refusal_retries_within_budget(tmp_path: Path) -> None:
    """A refusal the clerk can clear from the grammar and the document alone is RETRIED, and
    the retry carries the refusal.

    The fixture's refusal is a refinement whose target vertex nothing declares — clearable with
    no fact from MAIN, which is D7's own test for the structural partition. Both halves are
    asserted: a second call happened, and the refusal text reached it. A loop that retries
    without handing the refusal back asks the model to guess what it got wrong."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.UNDECLARED_TARGET_ROWS),
        C.clerk_reply(C.CLEAN_ROWS),
    )
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls == 2, f"a structural refusal did not retry ({clerk.calls} calls)"
    assert "v-404" in clerk.prompts[1], "the retry did not carry the refusal"
    assert C.OUTCOME_COMMITTED in main.receipt or C.OUTCOME_COMMITTED_ANON in main.receipt, (
        C.outcome_lines(main.receipt)
    )


def test_996_a_vocab_class_cell_refusal_is_classified_structural(tmp_path: Path) -> None:
    """A `class`-tuple cell holding a value from a sibling enum is STRUCTURAL: the loop retries
    it, and does not stop and hold the block.

    The check is `_check_vocab_class_cells`, a real structural gate at this very base — it is
    `7fa49f04`'s own work — and `design-996-v2.md` never mentions it, while the judgment
    partition's mechanism enumerates the tail without it. The situation is the single most
    likely clerk error (a container value in a compute-role slot) and its classification is
    what decides retry-versus-stop, so it is pinned by driving the loop rather than by an
    enumeration already shown incomplete twice.
    """
    run_dir = C.new_run_dir(tmp_path)
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.VOCAB_CLASS_CELL_DOC),
        C.clerk_reply(C.PROLOGUE),
    )
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls >= 2, (
        f"the class-cell refusal stopped the loop after {clerk.calls} call(s) — it was "
        f"classified as judgment, so the clerk never got to re-emit a cell it could fix alone"
    )
    assert C.OUTCOME_HELD not in main.receipt, C.outcome_lines(main.receipt)


def test_996_a_judgment_only_refusal_stops_the_clerk_loop(tmp_path: Path) -> None:
    """A refusal only MAIN can clear STOPS the loop after that round — one clerk call, not six.

    The fixture's refusal is the disposition price: a `benign` conclude landed onto a record
    whose vertices carry an unresolved class. No fact in the grammar or the document settles
    it, so every further round would burn a call on a refusal the clerk cannot answer — which
    is the whole of what D7 exists to stop."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.OPEN_SLOT_PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.JUDGMENT_ONLY_ROWS))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls == 1, (
        f"a judgment-only refusal drove {clerk.calls} clerk calls; the loop must stop after "
        f"the round that produced it"
    )
    assert C.OUTCOME_HELD in main.receipt, C.outcome_lines(main.receipt)


def test_996_a_held_block_lands_no_row(tmp_path: Path) -> None:
    """NEGATIVE: when the loop stops on the judgment partition, NO row from the block is in the
    document — not the offending row and not the rest of the block.

    POSITIVE CONTROL on the same address under the complementary condition: the same clerk
    block, over a document whose slots are resolved, DOES land every row. Without it "no row
    landed" is also true of a run where the clerk was never called."""
    held_dir = C.new_run_dir(tmp_path, name="held")
    C.seed(held_dir, C.OPEN_SLOT_PROLOGUE)
    C.record_run(tmp_path, run_dir=held_dir,
                 clerk=C.ScriptedClerk(C.clerk_reply(C.JUDGMENT_ONLY_ROWS)))
    assert "disposition" not in C.document(held_dir), (
        "a row from the held block reached the document"
    )
    assert C.document(held_dir).strip() != "", "the document is empty — the control is vacuous"

    landed_dir = C.new_run_dir(tmp_path, name="landed")
    C.seed(landed_dir, C.PROLOGUE)
    C.record_run(tmp_path, run_dir=landed_dir,
                 clerk=C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS)))
    assert "attrs.owner" in C.document(landed_dir), (
        "the positive control did not land either, so the negative above proves nothing"
    )


def test_996_the_next_record_hands_back_the_held_block_and_prose(tmp_path: Path) -> None:
    """The next `record` hands the clerk the held block AND the prose it was compiled from,
    alongside MAIN's new prose.

    O11's failing condition is exactly "the next `record`'s clerk prompt lacks the held block".
    The held pair is what lets the clerk re-emit the same rows with the answers MAIN's new
    prose now gives, instead of recompiling from scratch and losing the correct rows."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.OPEN_SLOT_PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.JUDGMENT_ONLY_ROWS), C.clerk_reply(""))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                 prose=[C.PROSE, C.SECOND_PROSE])

    assert clerk.calls >= 2, f"the second `record` never reached the clerk ({clerk.calls})"
    turn = clerk.prompts[-1]
    assert "termination.category" in turn, "the held block was not re-handed"
    assert C.PROSE in turn, "the prose the held block was compiled from was not re-handed"
    assert C.SECOND_PROSE in turn, "MAIN's new prose is not in the turn"


def test_996_a_mixed_refusal_converges_to_a_judgment_stop_per_round(tmp_path: Path) -> None:
    """A refusal carrying BOTH partitions is re-evaluated per round, so it converges to a D7
    stop once its structural half clears — it does not burn the whole budget.

    The fixture refuses on three lines at once: one undeclared refinement target (structural)
    and two disposition-gating lines (judgment). Round 1 retries on the structural half; round
    2's block clears it and leaves only judgment, and the loop stops there. Adopted from copy1
    AND MADE EXPLICIT, because the contrary retry-dominant reading is equally available from
    D7 as written — and leaving it implicit is how a mixed refusal silently burns all six
    rounds on a fact the clerk was never going to have."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.OPEN_SLOT_PROLOGUE)
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.MIXED_ROWS),
        C.clerk_reply(C.JUDGMENT_ONLY_ROWS),
    )
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls == 2, (
        f"a mixed refusal drove {clerk.calls} clerk calls; it must retry while a structural "
        f"line remains and stop the round after only judgment lines are left"
    )
    assert C.OUTCOME_HELD in main.receipt, C.outcome_lines(main.receipt)


def test_996_a_refusal_with_no_diagnostic_surfaces_and_holds_the_block(tmp_path: Path) -> None:
    """A refusal carrying NO diagnostic in either partition is surfaced to MAIN as a `record`
    failure line, and the block is HELD — by definition it is not something the clerk can fix.

    Reached on ORDINARY input, which is what makes the missing arm material rather than
    hypothetical: MAIN's prose fits under the byte cap but leaves the clerk's rows no headroom,
    and the byte-cap check sits outside the diagnostic machinery entirely — EXECUTED at this
    base, `diagnose` returns zero diagnostics for exactly that refusal.

    The design words six outcome lines and this is a SEVENTH the resolutions add, so the
    assertion is on what the resolution requires — exactly one outcome line, none of the six,
    naming the refusal — rather than on a string nobody has chosen.

    The reply carries a `GAPS:` section because the clerk's contract says every reply does, and
    the round loop now holds it to that: a reply with neither a fence nor that marker is a
    model that lost the format and is pended rather than written. `oversize_rows` has to stay
    UNFENCED for its own reason (fenced filler earns parse diagnostics, and this fixture's
    whole property is a refusal that carries none), so the marker is what keeps it a
    well-formed reply — which is also what a real clerk emits."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(
        C.oversize_rows(C.PROLOGUE), gaps=("the prose left the rows no headroom",)))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    lines = C.outcome_lines(receipt)
    assert len(lines) == 1, f"section (2) is EXACTLY ONE outcome line; got {lines}"
    assert not any(lines[0].startswith(fixed) for fixed in C.FIXED_OUTCOMES), (
        f"a diagnostic-less refusal was reported as one of the six worded outcomes: {lines[0]!r}"
    )
    assert str(INVESTIGATION_FILE_MAX) in receipt or "limit" in receipt, (
        "the receipt does not tell MAIN what the refusal was; a failure line MAIN cannot act "
        f"on is not a surfaced refusal: {receipt[:400]!r}"
    )
    assert len(C.document(run_dir)) <= INVESTIGATION_FILE_MAX, "the oversize block landed"


# ---------------------------------------------------------------------------------------
# S6 — the conclude guard (HD-3)
# ---------------------------------------------------------------------------------------


def test_996_a_conclude_block_is_dropped_unless_the_phase_header_is_report(
    tmp_path: Path,
) -> None:
    """NEGATIVE (S6): a `:T conclude` block is dropped when the phase in force is not
    `## REPORT` — whoever wrote it.

    POSITIVE CONTROL on the same address under the complementary condition: the identical
    clerk block, under a document whose current phase IS `## REPORT`, LANDS. Without it the
    guard is indistinguishable from a clerk whose rows never committed at all."""
    dropped = C.new_run_dir(tmp_path, name="analyze")
    C.seed(dropped, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    C.record_run(tmp_path, run_dir=dropped,
                 clerk=C.ScriptedClerk(C.clerk_reply(C.CONCLUDE_ROWS)))
    assert "disposition" not in C.document(dropped), (
        "a `:T conclude` block landed under `## ANALYZE`"
    )

    landed = C.new_run_dir(tmp_path, name="report")
    C.seed(landed, C.phase_document("## REPORT", C.PROLOGUE))
    C.record_run(tmp_path, run_dir=landed,
                 clerk=C.ScriptedClerk(C.clerk_reply(C.CONCLUDE_ROWS)))
    assert "disposition" in C.document(landed), (
        "the identical block did not land under `## REPORT` either, so the drop above proves "
        "nothing about the guard"
    )


def test_996_a_dropped_conclude_block_is_named_in_the_receipt(tmp_path: Path) -> None:
    """The drop is NOTED: the receipt tells MAIN a conclude block was dropped and why.

    A silent drop is the failure O2 names — MAIN recorded prose whose compiled form did not
    land and was never told. The note is what turns the accepted cost of the positional rule
    (a pended prose written under `## REPORT` and recompiled after the phase moved on has its
    conclude dropped) into something MAIN can act on."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir,
                              clerk=C.ScriptedClerk(C.clerk_reply(C.CONCLUDE_ROWS)))

    receipt = main.receipt
    assert "conclude" in receipt.lower(), (
        f"the receipt does not mention the dropped conclude block at all: {receipt[:400]!r}"
    )
    assert "REPORT" in receipt, (
        "the drop note does not name the header the block would have needed"
    )


def test_996_the_conclude_guard_reads_the_phase_where_the_block_lands(tmp_path: Path) -> None:
    """S6's input is POSITIONAL: the phase in force at the point the block would land — the
    document's own current phase header — never the calling prose's header and never the
    author's identity.

    That one sentence closes all three undefined channels the guard had. Driven on the
    sharpest of them: MAIN's prose carries `## REPORT` as its own heading while the document's
    phase in force is `## ANALYZE`. Reading the prose's header would land the conclude; reading
    the landing phase drops it. The accepted cost is stated with the decision and is the same
    fact from the other side — a pended prose written under `## REPORT` and recompiled after
    the phase moved on has its conclude dropped, and the receipt says so."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    C.record_run(tmp_path, run_dir=run_dir, prose=[C.REPORT_PROSE],
                 clerk=C.ScriptedClerk(C.clerk_reply(C.CONCLUDE_ROWS)))

    doc = C.document(run_dir)
    assert "## REPORT" in doc, "MAIN's prose did not land, so the guard's input is untested"
    assert "disposition" not in doc, (
        "the conclude block landed on a document whose phase in force was `## ANALYZE` — the "
        "guard read the calling prose's own header instead of the landing phase"
    )


def test_996_a_conclude_fence_in_mains_own_append_is_screened_too(tmp_path: Path) -> None:
    """The screen is over the PROPOSED DOCUMENT, not over the clerk: a `:T conclude` fence
    arriving through MAIN's own step-1 append passes through the same rule.

    This is a security finding rather than an ambiguity. S6 as stated covers "a `:T conclude`
    block the CLERK emits", so a conclude fence MAIN writes into its own prose never met the
    guard at all — while the close gate reads the PARSED companion regardless of who wrote the
    bytes. PO-10 bounds the exposure without closing it: the three gates parse rather than
    substring-match, so the attack needs a syntactically valid row — which MAIN's own append
    can land. MAIN loses the ability to hand-write a conclude fence in prose, which is intended:
    D14/O1 already hold that MAIN does not own the grammar."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    smuggled = "Recording the finding:\n\n" + C.CONCLUDE_ROWS
    C.record_run(tmp_path, run_dir=run_dir, prose=[smuggled],
                 clerk=C.ScriptedClerk(C.clerk_reply("")))

    assert "disposition" not in C.document(run_dir), (
        "a `:T conclude` fence MAIN wrote into its own prose reached the document unscreened, "
        "so the close gate can be satisfied by bytes S6 never saw"
    )


def test_996_a_dropped_conclude_block_is_held_on_pending(tmp_path: Path) -> None:
    """An S6-dropped block is HELD on `pending`, like a D7 stop — not discarded with only a
    receipt note.

    Both are MAIN's compiled intent that did not land, and the whole point of `pending` is that
    such intent is re-handed rather than lost. Observed where `pending` is observable: the next
    `record`'s clerk turn carries the dropped block and the prose it came from. It costs one
    entry against the cap of six, like any other pended entry."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    clerk = C.ScriptedClerk(C.clerk_reply(C.CONCLUDE_ROWS), C.clerk_reply(""))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                 prose=[C.PROSE, C.SECOND_PROSE])

    assert clerk.calls >= 2, f"the second `record` never reached the clerk ({clerk.calls})"
    assert "termination.category" in clerk.prompts[-1], (
        "the dropped conclude block was discarded rather than held on `pending`"
    )


# ---------------------------------------------------------------------------------------
# flow 0 — the repair round (D2, D14; cluster R)
# ---------------------------------------------------------------------------------------


def test_996_a_warn_accepted_block_is_repaired_inside_record(tmp_path: Path) -> None:
    """A block the gate accepts WITH a warning is repaired inside the same `record` call: the
    clerk answers repair pairs, they are applied through the real repair verb with MAIN's own
    deps, and the window is shut when `record` returns.

    MAIN never sees the flagged row's syntax and never calls a repair verb — it holds none."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.WARN_ROWS),
        C.repair_reply(C.REPAIR_PAIR),
    )
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    doc = C.document(run_dir)
    assert "attrs.owner" in doc, "the repair never landed"
    assert "|owner|" not in doc, "the flagged row is still in the document"
    assert "FLAGGED:" not in main.receipt, (
        "the receipt reports an open window after a repair that shut it"
    )


def test_996_an_open_window_runs_a_repair_round_before_the_prose_lands(
    tmp_path: Path,
) -> None:
    """With a window already open, `record` runs the repair round FIRST — before MAIN's prose
    is appended.

    The order is forced rather than chosen: the write gate refuses every append while a row is
    flagged, so a `record` that appended first would be refused for a row MAIN did not write —
    verbatim one of O1's failing conditions.

    THE DOCUMENT IS OBSERVED ON DISK, NOT SCANNED FOR IN THE PROMPT. D14 puts MAIN's text IN the
    repair prompt ("the clerk gets the flagged rows, their diagnostics and MAIN's text"), so
    `PROSE not in <the whole turn>` asserts the design's own negation — satisfiable only by an
    implementation that drops MAIN's text from the repair round, which nothing else in the suite
    would object to. What the ordering claim actually means is that `investigation.md` does not
    yet hold the prose when the repair round is dispatched, and that is read off the file at the
    moment of the call. D14's own half is asserted alongside it, positively: nothing else pins
    that MAIN's text reaches the repair turn at all."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)

    class _WatchingClerk(C.ScriptedClerk):
        """`ScriptedClerk` plus the document as it stood when each turn was dispatched. Still
        pure injection through the same seam — it observes, it never decides."""

        def __init__(self, watched: Path, *replies: str) -> None:
            super().__init__(*replies)
            self._watched = watched
            self.documents: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.documents.append(C.document(self._watched))
            return await super().__call__(request)

    clerk = _WatchingClerk(
        run_dir, C.repair_reply(C.REPAIR_PAIR), C.clerk_reply(C.CLEAN_ROWS),
    )
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.prompts, (
        "no clerk call was made at all: step 0's repair round did not run, so MAIN's prose met "
        "the write gate with a row still flagged"
    )
    first = clerk.prompts[0]
    assert C.WARN_ROW in first, "the repair round was not handed the flagged row"
    assert "refinement key" in first or "not a valid refinement key" in first, (
        "the repair round was not handed the row's diagnostic, so the clerk is guessing"
    )
    assert C.PROSE in first, (
        "the repair round was not handed MAIN's text — D14 gives the clerk the flagged rows, "
        "their diagnostics AND MAIN's text, and a repair written without it is a repair written "
        "against a document whose author's intent the clerk cannot see"
    )
    assert clerk.documents, "the watching clerk recorded no document at all"
    assert C.PROSE not in clerk.documents[0], (
        "MAIN's prose had already landed in `investigation.md` when the repair round was "
        "dispatched — but the gate refuses every append while a row is flagged"
    )


def test_996_a_still_open_window_returns_before_the_prose_is_appended(
    tmp_path: Path,
) -> None:
    """A repair round that does NOT shut the window returns immediately: the prose is not
    appended, and the receipt names the rows still flagged.

    O3's failing condition is a `record` that returns with the window open and no receipt
    naming the flagged diagnostics — MAIN would then record again into a gate that refuses it,
    with nothing to act on."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    clerk = C.ScriptedClerk(C.repair_reply())
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert C.PROSE not in C.document(run_dir), (
        "MAIN's prose was appended while a row was still flagged"
    )
    receipt = main.receipt
    assert "FLAGGED:" in receipt, "the receipt does not name the rows still flagged"
    assert "still flagged" in receipt, (
        f"section (0) does not report the repair round's outcome: {receipt[:300]!r}"
    )


def test_996_main_sees_a_repair_outcome_not_the_raw_gate_refusal(tmp_path: Path) -> None:
    """While any row is flagged, MAIN sees a REPAIR outcome and never the writer's own refusal
    text for a row it did not write.

    O1 says MAIN never absorbs a write-gate refusal for a row it did not write; flow 1.1 says a
    refusal on MAIN's next prose append reaches MAIN as today. Because the append validates the
    WHOLE document, a clerk-authored row that later reads as a flagged row would refuse MAIN's
    own unrelated next prose — and the two sentences would contradict. The narrowing that makes
    both true in every reachable state: step 0 runs first, so what MAIN receives is the repair
    round's outcome; once repair is exhausted MAIN receives the reworded diagnostic (the fact
    and its locus), not the writer's refusal.

    The cost is stated: an error-severity diagnostic outside the repair verb's scope is outside
    what any repair round can clear, and the honest receipt says so."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    clerk = C.ScriptedClerk(C.repair_reply())
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert main.receipts, "MAIN received no receipt at all — the refusal escaped as a retry"
    assert not main.retries, (
        f"MAIN absorbed a raw gate refusal for a row the clerk wrote: {main.retries!r}"
    )
    assert "The row LANDED and is committed" not in main.receipt, (
        "the writer's own refusal text was relayed to MAIN verbatim"
    )


def test_996_a_fix_row_refusal_ends_the_round_with_a_named_reason(tmp_path: Path) -> None:
    """A repair call the verb REFUSES ends the repair round immediately, with a receipt line
    naming why — it is not re-attempted until the budget is gone.

    "Still flagged" and "the repair call itself was refused" are different states and only the
    first is worth another round. The fixture drives the second: the clerk answers with an
    `old_row` that is not in the flagged set at all, which the repair verb refuses outright.
    Re-attempting it spends the whole budget on a call that cannot succeed."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    clerk = C.ScriptedClerk(
        C.repair_reply(("l-001|v-999|owner|nobody", "l-001|v-001|attrs.owner|x")),
    )
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls == 1, (
        f"a refused repair call was re-attempted {clerk.calls} times; a refusal ends the round"
    )
    receipt = main.receipt
    assert "v-999" in receipt or "not flagged" in receipt or "refused" in receipt, (
        f"the receipt does not name why the repair call was refused: {receipt[:400]!r}"
    )


def test_996_an_unrepairable_row_names_the_forced_close_escape(tmp_path: Path) -> None:
    """When the flagged set holds a row the repair verb cannot address at all, `record` says so
    and names the run's only remaining path — the forced close.

    The repair path is `:R attr_updates`-only by construction, so a warn diagnostic anywhere
    else is unrepairable however many rounds are spent on it. The deadlock is NOT fixed here
    and is attacker-triggerable — MAIN's prose quoting attacker-supplied alert content that
    reproduces a flagged row's text verbatim makes the repair verb refuse on ambiguity, and
    MAIN holds no repair verb to break it. What this buys is that MAIN is TOLD rather than
    looping until the framework force-closes.

    The fixture is the reachable shape rather than an imagined one: a committed `:V` row that a
    rule shipped after its bytes landed now refuses. The whole-document validation refuses
    every later write for it, the warn window is empty so no repair round runs, and the repair
    verb's `:R attr_updates` scope puts the row out of reach — append-only does the rest."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.VOCAB_CLASS_CELL_DOC)
    clerk = C.ScriptedClerk(C.clerk_reply(""))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    told = "\n".join([*main.receipts, *main.retries])
    assert told, "MAIN was handed nothing at all"
    assert "close" in told.lower(), (
        f"MAIN was never told the forced close is the only remaining path, so its only signal "
        f"is a repeating refusal: {told[:400]!r}"
    )
    assert "compute.role" in told, (
        "the fact and its locus were not named, so MAIN cannot say in prose what the row "
        "should have stated"
    )


# ---------------------------------------------------------------------------------------
# flow 4/5 — provider faults, `pending`, and the give-up
# ---------------------------------------------------------------------------------------


def test_996_a_provider_fault_keeps_the_prose_and_does_not_end_the_run(
    tmp_path: Path,
) -> None:
    """A transport fault inside a clerk call never loses MAIN's prose and never ends the run:
    the prose is pended, the receipt says so, and MAIN's loop continues.

    O6's failing condition is exactly "the scripted clerk raises and the run dies or the
    pending prose is never compiled". The fault class is the one the OpenAI-compatible provider
    surfaces on a dropped connection, not an invented exception."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(fault=C.Fault(raise_after=0))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                              prose=[C.PROSE, C.SECOND_PROSE])

    assert C.PROSE in C.document(run_dir), "MAIN's prose was lost with the faulting call"
    assert C.OUTCOME_PENDING in main.receipts[0], C.outcome_lines(main.receipts[0])
    assert main.calls >= 3, (
        f"the run ended at the fault ({main.calls} model requests) instead of continuing"
    )


def test_996_a_fault_at_either_clerk_call_site_pends_the_prose(tmp_path: Path) -> None:
    """ONE rule at EITHER call site: anything that is not a parsed response and not a
    `ModelRetry` pends the prose, writes its trace row and returns the pending receipt — step
    0's repair call and step 3's round loop alike.

    Driven at the repair call site, the one the design's flow 4 never mentions, and with the
    fault shape the design also never mentions: a reply that is not a parsed response at all
    (the model answered in prose). A completed-but-lost response and a validator raise during
    the D7 classification are the same rule — the validator is just another dependency.

    The first provider fault is TERMINAL for that `record` call's loop, which is the only
    reading under which "the next `record` re-hands the pending prose" parses at all."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    clerk = C.ScriptedClerk(fault=C.Fault(malformed="I could not work out what you wanted."))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls == 1, (
        f"the repair call site retried a non-parsed response {clerk.calls} times; the first "
        f"fault is terminal for that `record` call's loop"
    )
    assert C.OUTCOME_PENDING in main.receipt, C.outcome_lines(main.receipt)
    assert C.trace_rows(run_dir), "the faulting call wrote no trace row"


def test_996_a_clerk_call_that_never_returns_pends_like_a_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clerk call that never returns is bounded by a per-call deadline, and its expiry is a
    fault like any other: the prose is pended and the pending receipt is returned.

    `record` is sequential and is MAIN's only document verb, so a hung clerk call stops the
    whole investigation with no receipt, no trace row and no observable — which is why the
    deadline is part of the contract rather than an operational concern.

    THE DEADLINE'S VALUE IS AN OPEN PARAMETER, carried from the §7 seam and flagged in
    `80-author-digest.md`: the reading (a deadline exists, and its expiry is a fault) is
    decided; the number is not. The precedent that governs it is the one the per-run clerk
    ceiling took — derive it from a constant the run already has rather than mint a
    free-standing one. So this test pins the SEAM and the OBSERVABLE and not the number: the
    deadline is readable and steerable through the environment, exactly as the review stages'
    own `stage_timeout` is, and a call held past it comes back as a pending receipt.

    The whole run is wall-clock bounded, because a demand about a call being bounded cannot be
    discharged by a test that hangs when it is not."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    monkeypatch.setenv(C.TIMEOUT_ENV, "2")
    deadline = C.sym("runtime.clerk", "clerk_deadline_seconds")
    assert deadline() == 2, (
        "the clerk call's deadline is not readable or not steerable, so a hung call has no "
        "bound anyone can observe or an operator can shorten"
    )
    clerk = C.ScriptedClerk(fault=C.Fault(hang_after=0))
    with C.bounded(60, "the hung clerk call never came back"):
        _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert C.OUTCOME_PENDING in main.receipt, C.outcome_lines(main.receipt)
    assert C.PROSE in C.document(run_dir), "the hung call lost MAIN's prose"


def test_996_the_next_record_recompiles_the_pending_prose(tmp_path: Path) -> None:
    """The pending prose is re-handed on the NEXT `record` and compiled there — `pending` is
    re-served IN FULL, alongside the new prose.

    On the re-hand the clerk is told explicitly that the pended prose MAY ALREADY BE COMPILED
    in the document it is being shown. The sharp case is a call that had already committed rows
    moments before the transport failed: the fault pends the prose with no awareness of what
    the document contains, and the re-hand would otherwise treat every pended entry as
    uncompiled by definition. That is a PROMPT guarantee, not a runtime one — tracking
    committed row ids per pended prose is a second mechanism and is not adopted — so what is
    asserted here is the re-hand itself."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)

    # First call faults; the second is answered, so the recompile is observable.
    class _Switching:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.prompts.append(str(request))
            if len(self.prompts) == 1:
                raise ConnectionError("scripted clerk transport fault")
            return C.clerk_reply(C.CLEAN_ROWS)

    switching = _Switching()
    C.record_run(tmp_path, run_dir=run_dir, clerk=switching,
                 prose=[C.PROSE, C.SECOND_PROSE])

    assert len(switching.prompts) >= 2, "the pending prose was never re-handed"
    assert C.PROSE in switching.prompts[-1], "the pended prose is absent from the next turn"
    assert C.SECOND_PROSE in switching.prompts[-1], "MAIN's new prose is absent from the turn"
    assert "attrs.owner" in C.document(run_dir), "the re-handed prose was never compiled"


def test_996_pending_holds_at_most_six_entries(tmp_path: Path) -> None:
    """`pending` is CAPPED at six — the repair-round budget's own number — and on overflow the
    OLDEST entry is dropped.

    An uncapped queue is a feedback loop, not just growth: a context-window rejection is itself
    a provider fault, so the failure grows the very prompt that caused it, and every later
    clerk turn re-serves the whole queue. Observed where the queue is observable — the clerk
    turn that re-serves it — after eight faulting `record` calls.

    READ OFF THE `pending:` SLOT, NEVER OFF THE WHOLE TURN. Every one of the eight proses is
    appended to the document by its own call's step 1 before that call's clerk faults (flow 1's
    order), and the turn carries the document so far (v2:85) — so a scan of the whole turn finds
    all seven earlier proses at cap 6 and at cap 1000 alike and discriminates NOTHING. The slot
    is where the queue is, and `PENDING_LABEL` is the one label this suite pins for exactly this
    reason. HD-4 fixed the cap at six and this is the only test that pins its upper edge; its
    sibling below pins the eviction's receipt line."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)

    class _AlwaysFaults:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.prompts.append(str(request))
            raise ConnectionError("scripted clerk transport fault")

    clerk = _AlwaysFaults()
    proses = [f"Reading {i}: the bastion host answered." for i in range(8)]
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk, prose=proses)

    assert len(clerk.prompts) >= 8, f"only {len(clerk.prompts)} clerk calls were made"
    last = clerk.prompts[-1]
    queued = C.pending_section(last)
    assert queued is not None, (
        "the last clerk turn carries no `pending:` slot at all, so the queue's depth is "
        "unobservable and no cap can be pinned"
    )
    served = [p for p in proses[:-1] if p in queued]
    assert len(served) <= 6, (
        f"the last clerk turn's `pending` slot re-served {len(served)} pended entries; the cap "
        f"is 6"
    )
    assert proses[0] not in queued, (
        "the OLDEST pended entry survived the overflow — the cap drops the oldest"
    )


def test_996_the_dropped_pending_entry_is_named_in_the_receipt(tmp_path: Path) -> None:
    """The cap's eviction carries a receipt line NAMING what was dropped.

    Load-bearing rather than decorative: a dropped entry is prose that was never compiled and
    never will be, which is exactly what O2 requires be visible. Without the line, capping the
    queue converts an unbounded prompt into a silent loss of MAIN's work."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)

    class _AlwaysFaults:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.prompts.append(str(request))
            raise ConnectionError("scripted clerk transport fault")

    proses = [f"Reading {i}: the bastion host answered." for i in range(8)]
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=_AlwaysFaults(), prose=proses)

    late = "\n".join(main.receipts[6:])
    assert "drop" in late.lower(), (
        f"no receipt names the dropped pending entry: {late[:400]!r}"
    )
    assert proses[0][:20] in late, (
        "the drop line does not name WHICH prose was dropped, so MAIN cannot tell what was lost"
    )


def test_996_a_resume_loses_pending_and_last_gaps_and_nothing_else(tmp_path: Path) -> None:
    """The resume loss is EXACTLY the one HD-2 examined: `pending` and `last_gaps` are scoped to
    a single process lifetime and are gone after a re-entry, while everything the decision keeps
    — the bytes already appended, the trace already written, and the call counter's own
    uniqueness — comes through it intact.

    BOTH HALVES ARE THE DEMAND, and a test asserting either alone is worse than none. HD-2(a)
    records the loss as an EXAMINED non-obligation rather than an oversight, and names
    persisting the queue as the REJECTED arm — a second durable mechanism beside the document,
    whose own recovery contract nobody has written — so an implementer must not quietly make it
    durable. HD-2(b) is the single exception and it pulls the other way: the counter is re-keyed
    so it cannot collide after a resume. Between the two sits everything a resume could lose by
    accident, and a test that pinned only the loss would pass a re-entry that dropped MAIN's
    landed prose and the clerk trace along with the queue.

    THE RE-ENTRY IS THE REACHABLE SHAPE, the same one the trace-identity demand drives and the
    one executed at this base: a second pass over one run dir, whose logger reopens the wire log
    in append mode. The first pass records TWICE — a call whose clerk answers with a GAP, so
    `last_gaps` is genuinely populated, then a call whose clerk faults on the transport class
    the provider raises on a dropped connection, so its prose is sitting on `pending` when that
    process ends. Both halves of the loss are therefore OBSERVED and not merely named: a first
    pass whose only call faults produces no gaps at all, and a test driven that way would bind
    `last_gaps` while asserting nothing about it.

    THE TWO HALVES ARE OBSERVED THROUGH DIFFERENT CHANNELS, deliberately. `pending`'s emptiness
    is read off the `pending:` SLOT (`PENDING_LABEL` — the one label this suite pins, because an
    empty queue's rendering is itself a demand), while `last_gaps` is read by VALUE, the same way
    its positive sibling `..._the_previous_calls_gaps_are_handed_to_the_next_clerk_call` reads
    it. A whole-turn absence scan is honest for the GAP and dishonest for the prose: the turn
    binds "the document so far" (design v2:85) and the faulting call had ALREADY appended its
    prose — flow 1's own order — so `lost` is in the turn through the document on any correct
    implementation, while the gap text is clerk-authored, never lands in the document, and is
    not MAIN's prose on either pass.
    """
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    lost = "Before the restart: the bastion host answered from the corporate range."
    gap = "UNSETTLED-BEFORE-THE-RESTART: who owns svc.config-mgmt?"

    _, first, _ = C.record_run(
        tmp_path, run_dir=run_dir, run_id=f"{C.RUN_ID}-pre", prose=[C.PROSE, lost],
        clerk=C.ScriptedClerk(
            C.clerk_reply(C.CLEAN_ROWS, gaps=(gap,)),
            fault=C.Fault(raise_after=1),
        ),
    )
    assert gap in first.receipts[0], (
        f"the first pass's clerk returned a gap and the receipt never carried it, so "
        f"`last_gaps` was never populated and the loss below is vacuous: "
        f"{first.receipts[0][:400]!r}"
    )
    assert C.OUTCOME_PENDING in first.receipt, (
        f"the first pass did not pend its prose, so the re-entry below has nothing to lose and "
        f"the whole scenario is vacuous: {C.outcome_lines(first.receipt)}"
    )

    resumed = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    C.record_run(
        tmp_path, run_dir=run_dir, run_id=f"{C.RUN_ID}-post", prose=[C.SECOND_PROSE],
        clerk=resumed,
    )

    turn = resumed.prompts[0]
    assert gap not in turn, (
        "the previous process's GAPS were re-served after the re-entry — `last_gaps` was made "
        "durable across a resume, and HD-2(a) scopes it to one process lifetime exactly as it "
        "scopes `pending`"
    )
    body = C.pending_section(turn)
    assert body is not None, (
        "the resumed run's first clerk turn carries no `pending:` slot at all, so whether the "
        "queue survived the re-entry is unobservable"
    )
    assert body.strip() == "", (
        f"the resumed run's first clerk turn carries a non-empty `pending` slot: {body!r}"
    )

    assert lost in C.document(run_dir), (
        "the prose the faulting call had already appended is gone from the document — what "
        "HD-2 scopes to one process is the QUEUE, never bytes that already landed"
    )
    rows = C.trace_rows(run_dir)
    assert len(rows) >= 3, (
        f"the first pass's two trace rows did not both survive the re-entry ({len(rows)} row(s) "
        f"for three `record` calls); the trace is the only provenance binding a landed row to "
        f"the call that compiled it, and losing it loses more than was decided"
    )
    keys = [str(row.get("n")) for row in rows]
    assert len(set(keys)) == len(keys), (
        f"a trace row identity repeats across the re-entry — the counter is HD-2's ONE excepted "
        f"piece of state, re-keyed so it cannot collide after a resume: {keys}"
    )


def test_996_a_giveup_receipt_carries_the_last_block_and_the_last_refusal(
    tmp_path: Path,
) -> None:
    """On round exhaustion the receipt carries the clerk's LAST BLOCK as well as the last
    refusal — a give-up is a repair, not a report.

    O7's failing condition is a give-up receipt with only the refusal: MAIN can say in prose
    what the rows should have stated, but only if it is shown what the clerk produced and why
    it was rejected."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.UNDECLARED_TARGET_ROWS))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    assert C.OUTCOME_GIVEUP in receipt, C.outcome_lines(receipt)
    assert "v-404" in receipt, "the last refusal is not in the give-up receipt"
    assert "attr_updates" in receipt, "the clerk's last block is not in the give-up receipt"


def test_996_a_giveup_does_not_push_onto_pending(tmp_path: Path) -> None:
    """A give-up leaves `pending` untouched — the prose it exhausted its rounds on is NOT
    queued for the next call.

    A give-up is not a fault: the clerk answered every round and the block was refused each
    time, so re-handing the same prose would spend another six rounds on it. Observed where
    `pending` is observable, with a genuine pended entry present as the control: a faulting
    call first pends its prose, a give-up follows, and the third call's turn re-serves the
    first prose and NOT the second."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    faulted = "The first reading, lost to a transport fault."
    given_up = "The second reading, refused every round."

    class _FaultThenRefuse:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.prompts.append(str(request))
            if len(self.prompts) == 1:
                raise ConnectionError("scripted clerk transport fault")
            return C.clerk_reply(C.UNDECLARED_TARGET_ROWS)

    clerk = _FaultThenRefuse()
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                 prose=[faulted, given_up, C.SECOND_PROSE])

    last = clerk.prompts[-1]
    assert faulted in last, (
        "the faulted prose is not re-served, so this scenario cannot tell an untouched "
        "`pending` from an empty one"
    )
    assert last.count(given_up) <= 1, (
        "the given-up prose was pushed onto `pending` and re-served alongside the new prose"
    )


# ---------------------------------------------------------------------------------------
# the verb itself (D14, O10)
# ---------------------------------------------------------------------------------------


def test_996_record_returns_only_after_the_clerk_settled(tmp_path: Path) -> None:
    """The clerk call is SYNCHRONOUS inside `record`: the receipt MAIN reads already reflects
    what the clerk did, and the compiled rows are on disk before the tool returns.

    Stated as an explicit non-obligation in the design ("no asynchronous auditor"), which is
    what makes it a demand rather than an implementation detail: an auditor that answered after
    the return would hand MAIN a receipt about a compile that had not happened, and MAIN's next
    turn would read a document mid-write."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls == 1, f"the clerk was called {clerk.calls} times for one `record`"
    receipt = main.receipts[0]
    assert C.OUTCOME_COMMITTED in receipt or C.OUTCOME_COMMITTED_ANON in receipt, (
        C.outcome_lines(receipt)
    )
    assert "attrs.owner" in C.document(run_dir), (
        "the clerk's rows were not on disk when the receipt reported them committed"
    )


def test_996_record_is_registered_sequential(tmp_path: Path) -> None:
    """`record` is registered `sequential=True`, and two calls in one model response both land.

    Two `ToolCallPart`s in ONE model response otherwise run as concurrent tasks, and against
    the real write primitive that is a genuine lost update: both calls read the same pre-image,
    one document reaches disk and both receipts report success. The flag is asserted on the
    registered roster AND the property is driven, because the flag alone is a shape and the
    lost update is the content."""
    agent = Agent("test", deps_type=AgentDeps)
    register_tools(agent, MAIN_DEF.tools)
    tools = dict(agent._function_toolset.tools)
    assert "record" in tools, "`record` is not registered for MAIN at all"
    assert getattr(tools["record"], "sequential", False), (
        "`record` is registered without sequential=True — two calls in one model response "
        "would run concurrently and one document write would be lost"
    )

    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    both = Turn(tool_calls=[("record", {"text": C.PROSE}),
                            ("record", {"text": C.SECOND_PROSE})])
    main = C.MainWithReceipts([both, Turn(text="Holding here.")])
    C.record_run(tmp_path, run_dir=run_dir, main=main,
                 clerk=C.ScriptedClerk(C.clerk_reply("")))

    doc = C.document(run_dir)
    assert C.PROSE in doc, (
        "the first of two `record` calls in a single model response was lost"
    )
    assert C.SECOND_PROSE in doc, (
        "the second of two `record` calls in a single model response was lost"
    )


def test_996_an_empty_record_appends_zero_bytes_and_does_not_refuse(
    tmp_path: Path,
) -> None:
    """`record("")` does NOT refuse: zero bytes are appended, the file is created, and the
    ordinary receipt lead is returned.

    PROBED at this base on the writer underneath: an empty append creates the document at 0
    bytes and returns "appended 0 bytes to investigation.md (0 total)" with no `ModelRetry`.
    The compile half is the `record: nothing to commit` outcome — neither fences nor GAPS came
    back — with no retry, because there was nothing to compile and nothing went wrong."""
    run_dir = C.new_run_dir(tmp_path)
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, prose=[""],
                              clerk=C.ScriptedClerk(C.clerk_reply("")))

    assert not main.retries, f"an empty `record` was refused: {main.retries!r}"
    receipt = main.receipt
    assert "appended 0 bytes" in receipt, receipt[:300]
    assert C.OUTCOME_NOTHING in receipt, C.outcome_lines(receipt)


def test_996_a_same_block_id_collision_refuses_the_whole_append(tmp_path: Path) -> None:
    """A same-block `:V` id collision refuses the WHOLE append: nothing lands on disk, not even
    the first of the two rows.

    PROBED at this base: the collision is diagnosed at ERROR severity and the append raises
    with "No changes were made" — not warn-and-land. It is the clerk's most likely structural
    slip that the round loop must retry rather than commit half of, so the assertion is that
    the document is untouched, not merely that a diagnostic exists.

    Driven with its own prose rather than `C.PROSE` (`record_run`'s default): `C.PROSE` itself
    contains "jsmith" ("The bastion host authenticated jsmith..."), the exact identifier
    `C.ID_COLLISION_ROWS`'s second, colliding row also carries — asserting BOTH "MAIN's prose
    landed" and "jsmith is absent" against the same default prose could never be satisfied by
    any implementation. A prose that never mentions the collision's identifiers keeps both
    checks independent: one about MAIN's OWN bytes, one about the refused block's."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, "## ANALYZE (loop 1)\n\n")
    clerk = C.ScriptedClerk(C.clerk_reply(C.ID_COLLISION_ROWS))
    prose = "The bastion host logged a configuration change at 15:27Z."
    C.record_run(tmp_path, run_dir=run_dir, prose=[prose], clerk=clerk)

    doc = C.document(run_dir)
    assert prose in doc, "MAIN's own prose did not land either — step 1 was refused"
    assert "v-001" not in doc, (
        "the colliding block's FIRST row landed; the whole append must be refused and nothing "
        "may reach disk"
    )
    assert "jsmith" not in doc


def test_996_record_is_still_available_past_the_tool_call_cap(tmp_path: Path) -> None:
    """Past `max_tool_calls`, `record` is METERED but never REFUSED — MAIN can always write
    down what it has already found.

    Driven at a cap of one, so the second `record` is past it: the budget hook accounts the
    call and the verb still answers. The refusal that would fire here for a `core`-tier tool is
    what O10 exists to keep off MAIN's only document verb; a run that hits the cap and can no
    longer record loses everything it found after it."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, limits=limits,
                              clerk=C.ScriptedClerk(C.clerk_reply("")),
                              prose=[C.PROSE, C.SECOND_PROSE])

    assert len(main.receipts) >= 2, (
        f"only {len(main.receipts)} `record` receipt(s) past the cap — the verb was refused"
    )
    assert C.SECOND_PROSE in C.document(run_dir), (
        "the second `record` past the cap did not reach the document"
    )


def test_996_clerk_calls_are_bounded_by_the_runs_tool_call_cap(tmp_path: Path) -> None:
    """Clerk calls are bounded per run, and the bound is DERIVED from the run's existing
    tool-call cap — one clerk call per analyst tool call — rather than stated as a second
    constant.

    The exemption that makes MAIN always able to record is the same exemption that removes the
    only ceiling on clerk spend, so the ceiling has to be restated somewhere; derived, it
    retunes automatically when the cap moves. The discriminator is that it MOVES: driven under
    two different caps, the number of clerk calls the run admits differs, which a free-standing
    constant could not do.

    Worth carrying into the code comment: this bounds the WORST CASE only. Repair rounds
    multiply clerk calls WITHIN one `record` invocation, so the ceiling is not a per-run call
    count anyone can read off the tool-call cap directly. And reaching it degrades to `record`
    WITHOUT a clerk call, never to a refusal — refusing `record` is precisely what O10 exists
    to prevent."""
    proses = [f"Reading {i}: the bastion host answered." for i in range(5)]

    tight_dir = C.new_run_dir(tmp_path, name="tight")
    C.seed(tight_dir, C.PROLOGUE)
    tight = C.ScriptedClerk(C.clerk_reply(""))
    _, tight_main, _ = C.record_run(
        tmp_path, run_dir=tight_dir, clerk=tight, prose=proses,
        limits={**DEFAULT_LIMITS, "max_tool_calls": 1})

    loose_dir = C.new_run_dir(tmp_path, name="loose")
    C.seed(loose_dir, C.PROLOGUE)
    loose = C.ScriptedClerk(C.clerk_reply(""))
    C.record_run(tmp_path, run_dir=loose_dir, clerk=loose, prose=proses,
                 limits={**DEFAULT_LIMITS, "max_tool_calls": 50})

    assert loose.calls > tight.calls, (
        f"the clerk-call ceiling did not move with the run's tool-call cap "
        f"({tight.calls} vs {loose.calls}) — it is a free-standing constant"
    )
    assert len(tight_main.receipts) == len(proses), (
        "reaching the ceiling REFUSED a `record` instead of degrading to `record` without a "
        "clerk call"
    )


# ---------------------------------------------------------------------------------------
# S3 — where clerk bytes may land
# ---------------------------------------------------------------------------------------


def test_996_clerk_bytes_reach_the_run_dir_only_through_gated_verbs(
    tmp_path: Path,
) -> None:
    """NEGATIVE (S3): no byte the clerk produced reaches the run dir except through the gated
    document verbs and the clerk's own trace.

    The clerk's reply carries a marker in a place no verb can land — a GAPS bullet — and the
    whole run dir is walked for it. The only files admitted to carry it are `investigation.md`
    (through the gated append, and only where the rows landed) and `wire_logs/`, which is the
    clerk's own accounted provenance.

    POSITIVE CONTROL on the same address: the clerk's ROWS, which go through the gated verb, DO
    reach `investigation.md`. Without it a run where the clerk never answered would pass."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    marker = "CLERK-SIDE-CHANNEL-996"
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS, gaps=(marker,)))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert "attrs.owner" in C.document(run_dir), (
        "the positive control did not land, so the census below proves nothing"
    )
    stray = []
    for path in sorted(Path(run_dir).rglob("*")):
        if not path.is_file() or "wire_logs" in path.parts:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if marker in body:
            stray.append(str(path.relative_to(run_dir)))
    assert stray == [], f"clerk-authored bytes reached the run dir outside a gated verb: {stray}"


def test_996_lead_zero_and_seed_rows_are_outside_the_record_scope(
    tmp_path: Path,
) -> None:
    """NEGATIVE: rows the HOST wrote into `investigation.md` — lead-0's declaring block and a
    resumed run's seeded prefix — are outside `record`'s traceability scope, and `record` does
    not adopt them.

    O2 is scoped to rows landed through `record` (D13). A host-authored block predates MAIN's
    first turn and answers to no prose, so a `record` that counted it as its own would report a
    compile that never happened. POSITIVE CONTROL on the same address: the rows the clerk DID
    land in this run ARE reported in the receipt and the trace."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    rows = C.trace_rows(run_dir)
    assert rows, "no clerk trace row was written, so the scope is unobservable"
    ids = [i for row in rows for i in (row.get("ids") or [])]
    assert "l-001" not in ids, (
        "the host-authored lead-0 block's row was reported as landed through `record`"
    )
    assert "attrs.owner" in C.document(run_dir), (
        "the positive control did not land, so the negative above is vacuous"
    )
    assert main.receipts, "MAIN received no receipt"


# ---------------------------------------------------------------------------------------
# the faults the round loop and the receipt used to swallow (#1004 review)
# ---------------------------------------------------------------------------------------


def test_996_a_post_accept_repair_fault_is_named_rather_than_thrown(tmp_path: Path) -> None:
    """A clerk fault inside the POST-ACCEPT repair round reaches MAIN as a receipt, never as a
    raised exception.

    The two repair sites are the same call — `_repair_loop` raises a transport fault or an
    unparseable reply from either — and step 0's site catches both. This one did not, so a
    clerk that answered the round and then dropped its connection on the repair took the whole
    agent run down, with no trace row for a call whose rows had already landed. The rows ARE
    committed here, so the prose is not pended: the fault is named and the window stays open,
    which section (3) reports."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    # round 1 warn-accepts, opening the window; the repair round that follows faults.
    clerk = C.ScriptedClerk(C.clerk_reply(C.WARN_ROWS), fault=C.Fault(raise_after=1))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls >= 2, (
        f"the post-accept repair round never ran ({clerk.calls} clerk call(s)), so this "
        "scenario never reached the site under test"
    )
    receipt = main.receipt
    assert "ConnectionError" in receipt, (
        f"the repair round's fault is not named in the receipt at all: {receipt!r}"
    )
    assert C.WARN_ROW in C.document(run_dir), (
        "the rows the round had already committed are not on the document"
    )
    assert C.trace_rows(run_dir), "the faulting call wrote no trace row"


def test_996_a_call_whose_budget_went_to_repair_pends_rather_than_claiming_six_rounds(
    tmp_path: Path,
) -> None:
    """Repair rounds and round-loop rounds draw on ONE budget, so a repair pass that closes the
    window on the LAST of the six leaves the round loop with nothing to spend.

    That call appends MAIN's prose and shows it to no clerk at all. Reported as a give-up it
    claimed six clerk rounds none of which ran, and — because a give-up deliberately does not
    queue (`..._a_giveup_does_not_push_onto_pending`) — the prose sat on disk uncompiled, past
    a close gate that only looks at `pending`. Nothing was attempted, so this is a FAULT: the
    prose is queued and the next `record` re-serves it, which is where the queue is
    observable."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    # Five declined repair rounds, then one that lands the legal repair on the last of the six.
    clerk = C.ScriptedClerk(
        *[C.repair_reply()] * 5, C.repair_reply(C.REPAIR_PAIR), C.clerk_reply(""),
    )
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                              prose=[C.PROSE, C.SECOND_PROSE])

    first = main.receipts[0]
    assert C.OUTCOME_GIVEUP not in first, (
        f"a call that ran ZERO clerk rounds reported a give-up: {C.outcome_lines(first)}"
    )
    assert C.PROSE in C.document(run_dir), "MAIN's prose never landed, so nothing was at risk"
    assert len(clerk.prompts) >= 7, (
        f"the second `record` never reached the clerk ({len(clerk.prompts)} call(s))"
    )
    queued = C.pending_section(clerk.prompts[-1])
    assert queued is not None, "the second call's turn carries no `pending:` slot at all"
    assert C.PROSE in queued, (
        "the prose that reached no clerk round was not queued — it is on disk, uncompiled, "
        "and the close gate reads `pending`, so nothing will ever compile it"
    )


def test_996_the_giveup_line_names_the_rounds_actually_spent(tmp_path: Path) -> None:
    """A give-up names the rounds THIS call spent, never the budget constant.

    The two halves share one pool, so a call whose repair rounds took part of it gives up after
    fewer than six — and a receipt that says six over four is the one number MAIN has for how
    much of the budget its next prose can still buy."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    # One declined repair round, then the repair; four round-loop rounds are then all that is
    # left, and every one of them is refused structurally.
    clerk = C.ScriptedClerk(
        C.repair_reply(), C.repair_reply(C.REPAIR_PAIR),
        C.clerk_reply(C.UNDECLARED_TARGET_ROWS),
    )
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    assert C.OUTCOME_GIVEUP in receipt, C.outcome_lines(receipt)
    assert f"{C.OUTCOME_GIVEUP}4 clerk rounds" in receipt, (
        "the give-up line does not name the four rounds this call actually spent: "
        f"{C.outcome_lines(receipt)}"
    )


def test_996_the_clerk_ceiling_is_not_reported_as_an_accept(tmp_path: Path) -> None:
    """Past the run's clerk ceiling, `record` commits NOTHING — and says so, in the receipt and
    in the trace row alike.

    O10's arm is METERED, not refused: MAIN's prose still lands. What it must not do is report
    the call as an accept — a `committed: true` trace row beside a receipt reading "nothing to
    commit" is the one pairing that makes the trace unusable as the port's own evidence."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, limits=limits,
                              clerk=C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS)),
                              prose=[C.PROSE, C.SECOND_PROSE])

    metered = main.receipts[-1]
    for accept in (C.OUTCOME_COMMITTED, C.OUTCOME_COMMITTED_ANON):
        assert accept not in metered, (
            f"the metered call reported an accept: {C.outcome_lines(metered)}"
        )
    assert "ceiling" in metered.lower(), (
        f"the metered call's receipt does not say why nothing was compiled: {metered!r}"
    )
    rows = C.trace_rows(run_dir)
    assert rows, "no trace rows at all"
    assert rows[-1]["committed"] is False, (
        "the metered call's trace row says it committed rows; it made no clerk call at all"
    )


def test_996_a_conclude_fence_screened_out_of_mains_prose_is_named(tmp_path: Path) -> None:
    """The screen over MAIN'S OWN prose reports what it removed, exactly as the clerk-side drop
    does.

    Both sides run one rule, so both owe MAIN the same note. Without it the receipt for prose
    that was ONLY a conclude fence reads "appended 0 bytes" and nothing else: the model is told
    its record landed, with no way to learn that the block it wrote is not in the document and
    has to be restated under `## REPORT`."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    smuggled = "Recording the finding:\n\n" + C.CONCLUDE_ROWS
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, prose=[smuggled],
                              clerk=C.ScriptedClerk(C.clerk_reply("")))

    assert "disposition" not in C.document(run_dir), "the screen did not run at all"
    receipt = main.receipt
    assert "conclude" in receipt.lower(), (
        f"MAIN's own prose lost a `:T conclude` fence and the receipt never said so: "
        f"{receipt!r}"
    )
    assert "REPORT" in receipt, (
        "the note does not name the header the block would have needed"
    )


def test_996_an_early_conclude_in_one_fence_does_not_discard_the_others(
    tmp_path: Path,
) -> None:
    """S6 excises the offending FENCE, not the whole reply.

    The screen applied to MAIN's prose has always been surgical; the clerk-side test was a
    substring scan over the joined reply, so a round that grounded real rows in one fence and
    concluded early in another committed nothing — burning a `record` call and a clerk round
    over rows the identical rule keeps on the other side of it. The dropped block is still held
    on `pending` for the phase that can take it."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.CLEAN_ROWS + C.CONCLUDE_ROWS), C.clerk_reply(""),
    )
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                              prose=[C.PROSE, C.SECOND_PROSE])

    doc = C.document(run_dir)
    assert "attrs.owner" in doc, (
        "the grounded rows were discarded along with the premature conclude block"
    )
    assert "disposition" not in doc, "the premature conclude block landed under `## ANALYZE`"
    receipt = main.receipts[0]
    assert "conclude" in receipt.lower(), f"the drop is not named: {receipt!r}"
    # READ OFF THE `pending:` SLOT, never off the whole turn: the grammar and catalog the turn
    # also carries name `termination.category` themselves, so a whole-turn scan is green
    # whatever the queue holds.
    queued = C.pending_section(clerk.prompts[-1])
    assert queued is not None, "the second call's turn carries no `pending:` slot at all"
    assert "termination.category" in queued, (
        "the dropped conclude block was discarded rather than held on `pending`"
    )


def test_996_a_judgment_stop_names_the_caps_eviction_too(tmp_path: Path) -> None:
    """The cap's eviction is named on EVERY path that can cause it, not only on a provider
    fault.

    `push_pending` returns what it evicted and three of its four call sites dropped that
    return, so a D7 stop, an AR-7 hold and an S6 drop each evicted the oldest uncompiled prose
    in silence — which is HD-4's own failing condition reached from the majority of its
    triggers. Driven on the judgment stop, with the queue already at the cap."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.OPEN_SLOT_PROLOGUE)
    faulting = [f"Reading {i}: the bastion host answered." for i in range(6)]

    class _FaultsThenStops:
        """Six transport faults fill the queue to the cap; the seventh call answers with the
        judgment-priced block that stops the loop and pushes a seventh entry."""

        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.prompts.append(str(request))
            if len(self.prompts) <= len(faulting):
                raise ConnectionError("scripted clerk transport fault")
            return C.clerk_reply(C.JUDGMENT_ONLY_ROWS)

    clerk = _FaultsThenStops()
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                              prose=[*faulting, C.PROSE])

    receipt = main.receipts[-1]
    assert C.OUTCOME_HELD in receipt, (
        f"the last call did not reach the judgment stop: {C.outcome_lines(receipt)}"
    )
    assert "dropped the oldest pending entry" in receipt, (
        f"the judgment stop evicted the oldest queued prose in silence: {receipt!r}"
    )
    assert faulting[0][:40] in receipt, (
        "the eviction line does not name WHICH prose was lost"
    )


def test_996_clearing_the_queue_names_prose_that_never_reached_the_document(
    tmp_path: Path,
) -> None:
    """A clean accept clears the whole queue — and names the entries whose prose is not on the
    document.

    Every pend but one happens after step 1 has written the prose, so those bytes survive in
    `investigation.md` whatever the clerk does with them. The step-0 repair fault pends prose
    the flagged-row gate would not let land at all, and clearing THAT entry silently is the one
    disposal after which the prose exists nowhere: not in the document, not in the queue, and
    not in the close gate."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    lost = "The first reading, taken while a row was still flagged."

    class _FaultThenRepairThenCompile:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.prompts.append(str(request))
            if len(self.prompts) == 1:
                raise ConnectionError("scripted clerk transport fault")
            if len(self.prompts) == 2:
                return C.repair_reply(C.REPAIR_PAIR)
            return C.clerk_reply(C.CLEAN_ROWS)

    _, main, _ = C.record_run(tmp_path, run_dir=run_dir,
                              clerk=_FaultThenRepairThenCompile(),
                              prose=[lost, C.SECOND_PROSE])

    assert lost not in C.document(run_dir), (
        "the first prose reached the document after all, so this scenario tests nothing"
    )
    receipt = main.receipts[-1]
    assert "never reached investigation.md" in receipt, (
        f"the clear disposed of prose that exists nowhere, in silence: {receipt!r}"
    )
    assert lost[:40] in receipt, "the line does not name WHICH prose was cleared"


def test_996_no_record_receipt_names_a_verb_main_cannot_call(tmp_path: Path) -> None:
    """D15, on the ACCEPT path: nothing `record` hands back names `fix_row` or `append_block`.

    Receipt section (0) is `_tool_append_block`'s own return, passed through verbatim — and on
    a warn-accept that return carried the writer's own repair instruction, telling MAIN to call
    two verbs D14 took off its roster before its next `append_block`. Three model-facing
    strings on one arm, none of them reachable. The instruction that replaces it names the
    repair round that runs inside `record` itself.

    Driven on MAIN'S OWN step-1 append, which is the only way that return can warn: step 0
    returns before appending whenever a row is ALREADY flagged, so the warn has to arrive with
    the bytes of this call. Prose carrying a fence is the ordinary shape here rather than an
    exotic one — the replay harness sends whole golden invlang documents through `record`, and
    MAIN quoting evidence back at itself does the same thing."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(""))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk, prose=[C.WARN_ROWS])

    receipt = main.receipt
    assert "FLAGGED" in receipt or "flagged" in receipt, (
        f"the warn window never opened, so the instruction under test never rendered: "
        f"{receipt!r}"
    )
    for lost in ("fix_row", "append_block"):
        assert lost not in receipt, (
            f"the receipt tells MAIN to call `{lost}`, a verb D14 retired from its roster: "
            f"{receipt!r}"
        )
    assert "`record`" in receipt, (
        "the receipt names no verb MAIN can actually call in place of the retired ones"
    )


def test_996_the_flagged_section_carries_the_closed_spelling_it_offers(
    tmp_path: Path,
) -> None:
    """Section (3) carries each diagnostic's `use:` corrections, not just its message.

    The section used to be built by filtering the refusal's rendered text down to the lines
    starting `- ` or `row:`, which kept the complaint and dropped every `use:` line under it —
    the closed spellings the flagged row needs. The renderer is what owns those three lines, so
    this goes through it."""
    from defender._artifact_schema import render_diagnostic

    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir,
                              clerk=C.ScriptedClerk(C.repair_reply()))

    from defender.skills.invlang.validate import warn_diagnostics

    flagged = warn_diagnostics(C.document(run_dir))
    offered = [d for d in flagged if d.fix]
    assert offered, (
        "the fixture's flagged row carries no `use:` correction, so this test cannot see the "
        "filter it exists to catch"
    )
    receipt = main.receipt
    for d in offered:
        for line in render_diagnostic(d).splitlines():
            assert line.strip() in receipt, (
                f"section (3) dropped a rendered line the flagged row needs: {line!r}"
            )


# ---------------------------------------------------------------------------------------
# the second review pass: framing, spend accounting, and the held block the clear ate
# ---------------------------------------------------------------------------------------


def test_996_the_clerks_inputs_reach_it_inside_untrusted_frames(tmp_path: Path) -> None:
    """The document, MAIN's prose and each pending entry are FRAMED in the clerk's turn.

    MAIN quotes what gather retrieved into its prose and the prose lands in the document, so
    an instruction planted in a payload reaches this role as ordinary turn content unless it
    is framed as the data it is. Every other boundary in the tree where model- or
    payload-influenced text reaches a model does this — the gather summary, the bash and file
    reads, the raw alert — and the clerk holds no grant but WRITES the rows every downstream
    gate reads.

    Asserted on the frame CONTAINING the body, not on a tag appearing somewhere in the turn:
    a delimiter that does not enclose the untrusted bytes is not a frame."""
    import re

    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(""))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk, prose=[C.PROSE])

    turn = clerk.only()
    frames = re.findall(r"<run-([0-9a-f]{16})-untrusted>\n(.*?)\n</run-\1-untrusted>",
                        turn, re.S)
    assert frames, f"the clerk's turn carries no untrusted frame at all: {turn[:400]!r}"
    bodies = [body for _salt, body in frames]
    assert any(C.PROSE in body for body in bodies), (
        "MAIN's prose is in the turn but outside every frame"
    )
    assert any("prologue.vertices" in body for body in bodies), (
        "the document excerpt is in the turn but outside every frame"
    )


def test_996_an_empty_pending_slot_stays_empty_under_framing(tmp_path: Path) -> None:
    """Framing the queue does NOT put a delimiter where its empty rendering has to be.

    The frames go one per ENTRY, not one around the slot, precisely so the falsy default still
    renders blank — a clerk that reads anything there as a pended entry re-emits rows for prose
    nobody sent. Driven beside the sibling above so the two cannot be satisfied separately."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(C.clerk_reply(C.CLEAN_ROWS))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    body = C.pending_section(clerk.only())
    assert body is not None, "the clerk turn carries no `pending:` slot at all"
    assert body.strip() == "", f"the empty pending slot rendered {body.strip()!r}"


def test_996_the_clerks_own_text_reaches_main_framed(tmp_path: Path) -> None:
    """The clerk's block and its GAPS bullets are FRAMED on the way into MAIN's context.

    Both are the clerk's own output, relayed verbatim and unvalidated — the same shape as a
    gather summary, which is framed for exactly this reason. The give-up arm is the one that
    hands MAIN the whole block, so it is where this is driven; the GAPS bullets ride the same
    receipt."""
    import re

    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.UNDECLARED_TARGET_ROWS, gaps=("who owns svc.config-mgmt?",)))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    receipt = main.receipt
    assert C.OUTCOME_GIVEUP in receipt, C.outcome_lines(receipt)
    frames = re.findall(r"<run-([0-9a-f]{16})-untrusted>\n(.*?)\n</run-\1-untrusted>",
                        receipt, re.S)
    bodies = [body for _salt, body in frames]
    assert any("attr_updates" in body for body in bodies), (
        f"the clerk's own block reached MAIN outside every frame: {receipt!r}"
    )
    assert any("svc.config-mgmt" in body for body in bodies), (
        "the clerk's GAPS bullets reached MAIN outside every frame"
    )


def test_996_a_faulted_call_records_the_rounds_it_spent(tmp_path: Path) -> None:
    """A `record` that spent clerk calls and then faulted records THOSE calls in its trace row.

    Every fault arm returns through `pend()` before the loops finish, and the round counters
    used to be assigned after them — so a call that burned three of the six shared calls and
    then lost its connection wrote `rounds: 0, repair_rounds: 0`. Per-call spend is the whole
    reason the trace exists, and it was wrong on exactly the calls that spent budget and landed
    nothing.

    Driven on the round loop, where a structural refusal retries: two rounds are refused and
    the third faults."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.UNDECLARED_TARGET_ROWS), fault=C.Fault(raise_after=2))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls == 3, f"the scenario made {clerk.calls} clerk calls, not 3"
    rows = C.trace_rows(run_dir)
    assert rows, "the faulting call wrote no trace row"
    assert rows[-1]["rounds"] == 3, (
        f"the faulted call's trace row says it spent {rows[-1]['rounds']} rounds; it spent 3 "
        "of the six shared clerk calls"
    )


def test_996_the_retry_prompt_carries_the_whole_refusal(tmp_path: Path) -> None:
    """The clerk's retry turn gets the FULL refusal, not the trace row's clipped copy.

    `trace["refusals"]` is truncated for the row's own sake; feeding that back handed the clerk
    a refusal cut off mid-diagnostic, so it fixed what it could see, was refused on the rest,
    and the shared budget went on a give-up neither party could act on.

    The fixture's refusal has to be longer than the clip for this to discriminate, so the
    document carries several undeclared targets and the assertion is on the refusal's own TAIL
    reaching the turn."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    many = "```invlang\n:R attr_updates [resolved_by|target|key|value]\n" + "".join(
        f"l-001|v-{n}|attrs.owner|svc.config-mgmt\n" for n in range(400, 412)
    ) + "```\n"
    clerk = C.ScriptedClerk(C.clerk_reply(many))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    assert clerk.calls >= 2, "the refusal never reached a retry turn"
    refused = [p for p in clerk.prompts if "refused your last attempt" in p]
    assert refused, "no retry turn carried the refusal section at all"
    served = refused[-1].split("refused your last attempt", 1)[1]
    assert "v-411" in served, (
        "the retry turn carries a refusal clipped before its last diagnostic — the clerk "
        "cannot fix what it was not shown"
    )


def test_996_a_held_conclude_block_survives_a_clean_accept(tmp_path: Path) -> None:
    """An S6-held conclude block is NOT swept away by the next clean accept.

    Every other entry in the queue is prose the clerk could have folded into the rows it just
    committed, which is what makes the blanket clear safe. A conclude block held because the
    phase forbids it could not be: the same screen that held it would drop it again this round.
    Cleared anyway, MAIN's compiled conclusion vanished with no receipt line AND the close gate
    — which reads only whether the queue is empty — was satisfied.

    Read off the `pending:` SLOT, never the whole turn: the grammar and catalog the turn also
    carries name `termination.category` themselves."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    # call 1 compiles a conclude block under ANALYZE (held); call 2 lands ordinary rows
    # cleanly; call 3 is where the queue is observable.
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.CONCLUDE_ROWS), C.clerk_reply(C.CLEAN_ROWS), C.clerk_reply(""))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                 prose=[C.PROSE, C.SECOND_PROSE, "A third reading."])

    assert clerk.calls >= 3, f"only {clerk.calls} clerk calls — the third never ran"
    queued = C.pending_section(clerk.prompts[-1])
    assert queued is not None, "the third turn carries no `pending:` slot at all"
    assert "termination.category" in queued, (
        "the clean accept swept away the held conclude block — MAIN's compiled conclusion is "
        "gone and the close gate now reads an empty queue"
    )


def test_996_a_held_conclude_block_clears_once_the_phase_can_take_it(tmp_path: Path) -> None:
    """POSITIVE CONTROL for the sibling above, and the reason retention cannot wedge the run:
    once the phase IS `## REPORT` the held block lands and the queue drains.

    Retaining an entry no accept can clear would refuse every model close for the rest of the
    run. It drains because the block becomes legal, not because anything special-cases it.

    FOUR CALLS, because HD-3's rule is positional: the phase in force is read from the document
    as it stood when the call BEGAN, so the `## REPORT` header MAIN records on call 2 is not
    the phase in force until call 3. Call 1 compiles the block under ANALYZE (held), call 2
    accepts ordinary rows and records the header, call 3 is the first call at which the block
    can land, and call 4 is where the drained queue is observable."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.CONCLUDE_ROWS), C.clerk_reply(C.CLEAN_ROWS),
        C.clerk_reply(C.CONCLUDE_ROWS), C.clerk_reply(""))
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                 prose=[C.PROSE, C.REPORT_PROSE, "The report stands.", "A fourth reading."])

    assert "disposition" in C.document(run_dir), (
        "the held block never landed under `## REPORT`, so nothing here shows it can drain"
    )
    queued = C.pending_section(clerk.prompts[-1])
    assert queued is not None, "the last turn carries no `pending:` slot at all"
    assert "termination.category" not in queued, (
        "the block landed and the entry stayed queued — every later model close is refused "
        "for a queue nothing can drain"
    )


def test_996_a_screened_pended_prose_is_not_reported_as_never_landed(tmp_path: Path) -> None:
    """The "this prose never reached the document" line fires on prose that never reached the
    document, and not on prose S6 trimmed on its way there.

    The queue holds what step 1 actually WROTE, which is the screened bytes — MAIN's raw text
    minus any conclude fence the phase forbade. Comparing the raw text against the document
    instead makes the test false for every entry that lost a fence: MAIN is told its prose was
    lost, and spends a whole `record` call restating material already on disk.

    The genuine loss is still reported — its own scenario is
    `..._names_prose_that_never_reached_the_document`, and this is the arm that must stay
    quiet."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    trimmed = "The bastion host answered at 15:27Z.\n\n" + C.CONCLUDE_ROWS

    class _FaultThenCompile:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.prompts.append(str(request))
            if len(self.prompts) == 1:
                raise ConnectionError("scripted clerk transport fault")
            return C.clerk_reply(C.CLEAN_ROWS)

    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=_FaultThenCompile(),
                              prose=[trimmed, C.SECOND_PROSE])

    doc = C.document(run_dir)
    assert "The bastion host answered at 15:27Z." in doc, (
        "the screened prose never landed, so this scenario tests nothing"
    )
    assert "disposition" not in doc, "the conclude fence was not screened out at all"
    assert "never reached investigation.md" not in main.receipts[-1], (
        "prose that DID land was reported to MAIN as lost, because the queue held the raw "
        f"text and the document holds the screened bytes: {main.receipts[-1]!r}"
    )


def test_996_the_conclude_guard_is_not_keyed_on_one_spelling_of_its_header(
    tmp_path: Path,
) -> None:
    """S6 screens a `:T conclude` header however the tokenizer would accept it — not only the
    one-space spelling.

    The tokenizer's header rule takes the tag, then a WHITESPACE RUN, then the name, so
    `:T\tconclude` and `:T  conclude` both parse and both land in `companion["conclude"]`. The
    guard tested for the literal substring, so neither reached it — and the close gate reads
    the parsed companion and never the bytes, which is what makes a screen keyed on the
    ordinary spelling a bypass rather than a rough edge. Driven through MAIN's own prose, the
    path that needs no clerk cooperation at all.

    The one-space arm is the positive control: the same document with the ordinary spelling is
    screened too, so the assertion below is about the SPELLING and not about a screen that
    stopped running."""
    for name, header in (("tab", ":T\tconclude"), ("spaces", ":T  conclude")):
        run_dir = C.new_run_dir(tmp_path, name=f"smuggle-{name}")
        C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
        smuggled = C.CONCLUDE_ROWS.replace(":T conclude", header)
        assert header in smuggled, "the fixture did not actually change the header spelling"
        C.record_run(tmp_path, run_dir=run_dir, prose=[smuggled],
                     clerk=C.ScriptedClerk(C.clerk_reply("")))
        assert "disposition" not in C.document(run_dir), (
            f"a `{header}` block reached the document under `## ANALYZE` — the close gate "
            "reads the parsed companion, which accepts this spelling"
        )

    ordinary = C.new_run_dir(tmp_path, name="smuggle-ordinary")
    C.seed(ordinary, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    C.record_run(tmp_path, run_dir=ordinary, prose=[C.CONCLUDE_ROWS],
                 clerk=C.ScriptedClerk(C.clerk_reply("")))
    assert "disposition" not in C.document(ordinary), (
        "the ordinary spelling is not screened either, so the two arms above prove nothing "
        "about the header grammar"
    )


def test_996_a_held_conclusion_dropped_at_report_is_named(tmp_path: Path) -> None:
    """When the phase reaches REPORT and the held conclusion is cleared without having landed,
    MAIN is TOLD.

    Retention keeps the block only while the phase forbids it, so at `## REPORT` the entry
    becomes ordinary backlog and the next clean accept takes it — which is right, REPORT is
    where it could have landed. What is not right is doing that in silence: the "never reached
    the document" line cannot name it (its prose IS on disk, written by the call that compiled
    it), and whether the clerk re-emitted a block its own prompt calls possibly-already-
    compiled is precisely what nothing here can assume. The notice fires on the condition that
    makes the loss real — the document ends the round with no conclusion in it at all.

    FOUR CALLS, for HD-3's positional rule: the `## REPORT` header MAIN records on call 2 is
    not the phase in force until call 3."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    other_rows = C.attr_block("l-001|v-002|attrs.dept|finance")
    clerk = C.ScriptedClerk(
        C.clerk_reply(C.CONCLUDE_ROWS), C.clerk_reply(C.CLEAN_ROWS),
        C.clerk_reply(other_rows), C.clerk_reply(""))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                              prose=[C.PROSE, C.REPORT_PROSE, "The report stands.",
                                     "A fourth reading."])

    assert "disposition" not in C.document(run_dir), (
        "the conclusion landed after all, so there is no loss here to report"
    )
    named = [r for r in main.receipts if "was dropped from the queue" in r]
    assert named, (
        "the held conclusion was cleared at `## REPORT` with nothing in the document and no "
        f"receipt line said so: {main.receipts!r}"
    )


# ---------------------------------------------------------------------------------------
# the fourth review pass: the guards' inputs, and the arms that dropped prose
# ---------------------------------------------------------------------------------------


def test_996_a_phase_header_inside_a_fence_is_not_the_phase_in_force(
    tmp_path: Path,
) -> None:
    """A `## REPORT` line inside a FENCE is quoted text, not the document moving to REPORT.

    MAIN quotes what gather retrieved into its prose, fenced, and that lands in the document —
    so a payload line reading `## REPORT` set the phase in force for every later call and
    switched S6's conclude guard off, which is the guard's whole job. `_corpus._FENCE_RE` owns
    this reading in the tree (`leads.pitfalls_curator` states the rule and walks the same way,
    against the same escape).

    POSITIVE CONTROL on the same address: the identical header OUTSIDE a fence does move the
    phase, so the assertion is about the fence and not about a guard that stopped running."""
    quoted = C.new_run_dir(tmp_path, name="quoted")
    C.seed(quoted, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    C.record_run(tmp_path, run_dir=quoted, clerk=C.ScriptedClerk(C.clerk_reply("")),
                 prose=["gather answered:\n\n```\nweb-01 log\n## REPORT\n```\n"])
    C.record_run(tmp_path, run_dir=quoted, clerk=C.ScriptedClerk(C.clerk_reply(C.CONCLUDE_ROWS)),
                 prose=["Recording the finding."])
    assert "disposition" not in C.document(quoted), (
        "a `## REPORT` line inside a fence was read as the phase in force, so the conclude "
        "guard let a premature conclusion reach the document"
    )

    plain = C.new_run_dir(tmp_path, name="plain")
    C.seed(plain, C.phase_document("## ANALYZE (loop 1)", C.PROLOGUE))
    C.record_run(tmp_path, run_dir=plain, clerk=C.ScriptedClerk(C.clerk_reply("")),
                 prose=["## REPORT\n\nThe activity is routine."])
    C.record_run(tmp_path, run_dir=plain, clerk=C.ScriptedClerk(C.clerk_reply(C.CONCLUDE_ROWS)),
                 prose=["Recording the finding."])
    assert "disposition" in C.document(plain), (
        "an unfenced `## REPORT` header did not move the phase either, so the fenced arm "
        "above proves nothing about fences"
    )


def test_996_a_gaps_marker_inside_a_row_does_not_truncate_the_block(tmp_path: Path) -> None:
    """The reply is split at a `GAPS:` line OUTSIDE the fences, never at the first occurrence
    anywhere in the text.

    The clerk compiles cells out of prose MAIN quoted from gather, so the string can
    legitimately sit inside a row. Cut there, the block is truncated mid-line, a partial
    unterminated fence goes to the write gate, and the rest of that row is reparsed as a gap
    bullet — with the receipt reporting whatever survived as committed."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    rows = C.attr_block("l-001|v-001|attrs.owner|svc GAPS: config-mgmt")
    clerk = C.ScriptedClerk(C.clerk_reply(rows, gaps=("who owns it?",)))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk)

    doc = C.document(run_dir)
    assert "svc GAPS: config-mgmt" in doc, (
        f"the row was truncated at a `GAPS:` inside its own cell: {doc[-400:]!r}"
    )
    assert doc.count("```") % 2 == 0, "an unterminated fence reached the document"
    assert "who owns it?" in main.receipt, "the real GAPS section was not split off"


def test_996_a_clerk_reply_with_neither_rows_nor_gaps_is_not_written(tmp_path: Path) -> None:
    """A reply carrying no invlang fence AND no `GAPS:` marker is the malformed shape — pended,
    never written.

    Free prose outside a fence is not invlang content, so a clerk answering "I could not
    compile this because…" had that sentence appended to `investigation.md` verbatim, the
    document still validated, and the receipt reported it as committed rows. An EMPTY reply
    stays the legitimate nothing-to-commit case, which the sibling assertion holds."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    lost = "I could not compile this because the prose names no vertex."
    clerk = C.ScriptedClerk(lost, C.clerk_reply(""))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk,
                              prose=[C.PROSE, C.SECOND_PROSE])

    assert lost not in C.document(run_dir), (
        f"the clerk's prose was written into the document as rows: {C.document(run_dir)!r}"
    )
    assert C.OUTCOME_PENDING in main.receipts[0], C.outcome_lines(main.receipts[0])
    assert C.OUTCOME_PENDING not in main.receipts[-1], (
        "an EMPTY reply was treated as malformed too — that is the legitimate "
        "nothing-to-commit case"
    )


def test_996_a_reference_leading_row_is_not_reported_as_a_committed_id(
    tmp_path: Path,
) -> None:
    """A row whose leading cell REFERENCES an id declared earlier is not reported as an id this
    call committed.

    The rule is read off the block header's own first column (`resolved_by`), so every `:R`
    family that leads with it is covered rather than the one that was named; `:T resolutions`,
    which declares no column list, is the one exception and is listed as one. The receipt used
    to read `record: committed rows for h-001` on a call that declared nothing new, and the
    same value went into the trace's `ids`, which is what the observability lane reads."""
    extract = C.sym("runtime.tools._clerk", "_extract_ids")

    assert extract(":T resolutions\nh-001  null -> ++  [l-001 p1]\n") == [], (
        "a `:T resolutions` row's leading hypothesis reference was reported as a declaration"
    )
    assert extract(
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        "l-001|e-001|ac1|holds|cmdb|because\n"
    ) == [], "a `resolved_by`-leading `:R authz` row was read as declaring `l-001`"
    assert extract(
        ":V prologue.vertices [id|type|class|ident|attrs?]\nv-001|compute|a/b/c|host|\n"
    ) == ["v-001"], "a genuine declaration stopped being reported"


def test_996_a_reference_block_does_not_swallow_the_next_fence(tmp_path: Path) -> None:
    """The reference-leading flag ends at the FENCE, not only at the next block header.

    A continuation fence that opens without repeating a header is a shape the tokenizer
    documents; every row in one following a `resolved_by` block was being skipped as if still
    inside it, so the receipt named none of the ids that fence actually committed."""
    extract = C.sym("runtime.tools._clerk", "_extract_ids")
    two_fences = (
        "```invlang\n:R attr_updates [resolved_by|target|key|value]\n"
        "l-001|v-001|attrs.owner|svc\n```\n"
        "```invlang\nv-009|compute|a/b/c|host|\n```\n"
    )
    assert extract(two_fences) == ["v-009"], (
        "the following fence's rows were skipped as if the reference block were still open"
    )


def test_996_a_refused_repair_round_pends_the_prose_like_a_fault(tmp_path: Path) -> None:
    """A step-0 repair loop that cannot close the window PENDS MAIN's prose, exactly as the two
    fault arms beside it do.

    This arm returns before step 1 — the flagged-row gate would refuse the write anyway — so
    the prose reached neither the document nor the queue, and the close gate's own account of
    what is still uncompiled was short by it. A transport fault preserved the prose and a
    refused repair lost it, over a difference neither party can act on.

    READ OFF THE `pending:` SLOT of a later ROUND turn, never off the prompts as a whole: the
    repair prompt of the very call under test inlines that same prose (it is the prose the
    window opened on), so a whole-prompt scan is green whatever the queue holds. Which means
    the window has to CLOSE on a later call for a round turn to exist at all — hence the two
    calls: six declined repair rounds, then a repair that lands."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE + C.WARN_ROWS)

    class _DeclineSixThenRepair:
        """Call 1 spends its whole budget declining; call 2's repair lands and its round turn
        is where the queue becomes observable."""

        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def __call__(self, request):  # noqa: ANN001 — mirrors the seam's own shape
            self.prompts.append(str(request))
            if len(self.prompts) <= 6:
                return C.repair_reply()
            if len(self.prompts) == 7:
                return C.repair_reply(C.REPAIR_PAIR)
            return C.clerk_reply("")

    clerk = _DeclineSixThenRepair()
    C.record_run(tmp_path, run_dir=run_dir, clerk=clerk, prose=[C.PROSE, C.SECOND_PROSE])

    assert C.PROSE not in C.document(run_dir), (
        "the first call's prose landed after all, so there was nothing here to queue"
    )
    assert len(clerk.prompts) >= 8, (
        f"the second call never reached a round turn ({len(clerk.prompts)} clerk calls)"
    )
    queued = C.pending_section(clerk.prompts[-1])
    assert queued is not None, "the round turn carries no `pending:` slot at all"
    assert C.PROSE in queued, (
        "the prose of a call whose repair round was refused exists nowhere — not on the "
        "document, not in the queue, and not in the close gate's account of what is owed"
    )


# ---------------------------------------------------------------------------------------
# the fifth review pass: the edges the fourth pass's own fixes opened
# ---------------------------------------------------------------------------------------


def test_996_an_indented_gaps_marker_yields_no_phantom_gap(tmp_path: Path) -> None:
    """An indented `GAPS:` line is split at the MARKER, not at the start of its line.

    The offset the split advances from and the offset the search returned have to be the same
    one. They were not: the search matched from the line start (models indent freely) and the
    split advanced by the length of the word, cutting two characters into it and leaving
    `"S: none"` behind as a gap. That is relayed to MAIN in the receipt, stored as the call's
    unanswered questions, and re-served in every later round prompt — a question no prose can
    ever answer because nobody asked it."""
    split = C.sym("runtime.tools._clerk", "_split_clerk_reply")
    rows = "```invlang\n:V prologue.vertices [id]\nv-1\n```"

    body, gaps = split(rows + "\n  GAPS: none\n")
    assert gaps == [], f"an indented `GAPS: none` produced a phantom gap: {gaps!r}"
    assert body.strip() == rows, "the rows were cut short by the indented marker"

    body2, gaps2 = split(rows + "\n   GAPS:\n   - who owns it?\n")
    assert gaps2 == ["who owns it?"], f"an indented bullet list mis-split: {gaps2!r}"
    assert body2.strip() == rows


def test_996_one_stray_fence_marker_does_not_freeze_the_phase(tmp_path: Path) -> None:
    """An UNPAIRED fence marker opens no region, so a stray one cannot hide every later
    heading.

    Excluding headings inside fences is what stops a quoted payload from setting the phase —
    but a walk that toggles on every marker turns one odd ``` line, which every gate in the
    tree treats as prose, into a permanent freeze: the phase in force never advances again, S6
    excises every conclusion the clerk compiles, the close gate refuses every model close, and
    the run can only force-close `unresolved`. That is a worse failure than the bypass, and it
    is silent.

    The CLOSED-fence arm is the control: a payload inside a properly paired fence still does
    not move the phase, which is the property the walk exists for."""
    phase = C.sym("runtime.tools._clerk", "_current_phase")

    stray = "## ANALYZE (loop 1)\n\nquoted:\n\n```\npayload\n```\n```\n\n## REPORT\n\nprose\n"
    assert phase(stray) == "REPORT", (
        "one unpaired ``` line hid every later heading — the phase in force is frozen for the "
        "rest of the run"
    )

    quoted = "## ANALYZE (loop 1)\n\nquoted:\n\n```\npayload\n## REPORT\n```\n\nprose\n"
    assert phase(quoted) == "ANALYZE", (
        "a heading inside a CLOSED fence moved the phase, so the exclusion this test is "
        "bounding does not happen at all"
    )


def test_996_a_deferral_table_is_not_screened_as_a_conclusion(tmp_path: Path) -> None:
    """S6 screens `:T conclude`, not every block whose name begins with it.

    `:T conclude.deferred_authz` and `:T conclude.deferred_preds` are the deferral tables the
    grammar tells its reader to send FIRST, before the conclusion — so a header match that
    stopped at a word boundary excised them under every phase but REPORT, held them on the
    queue as conclusions, and told MAIN a `:T conclude` block had been dropped for something
    that is not one.

    The conclusion itself is the control: it is still screened under the same phase."""
    screen = C.sym("runtime.tools._clerk", "_screen_conclude_fences")

    deferral = (
        "```invlang\n:T conclude.deferred_preds [prediction_ref|rationale]\n"
        "h-001.p1|the measurement never landed\n```\n"
    )
    kept, removed = screen(deferral, "ANALYZE")
    assert removed == "", f"a deferral table was screened as a conclusion: {removed!r}"
    assert kept == deferral, "the deferral table was altered on its way through"

    _kept2, removed2 = screen(C.CONCLUDE_ROWS, "ANALYZE")
    assert removed2, "the conclusion itself is no longer screened, so this proves nothing"


def test_996_a_fault_after_the_prose_landed_still_reports_the_write(tmp_path: Path) -> None:
    """A clerk fault AFTER step 1 wrote the prose still hands MAIN section (0) and the flagged
    notice.

    The pending line alone leaves MAIN unable to tell whether its bytes reached the document —
    and silent about a row that warn-accepted on that same write, which now blocks every later
    write AND the close. Every other exit reports those; a provider fault is not a reason to
    stop reporting them."""
    run_dir = C.new_run_dir(tmp_path)
    C.seed(run_dir, C.PROLOGUE)
    # MAIN's own prose carries the warn row, so step 1 warn-accepts and the window opens; the
    # clerk call that follows faults.
    clerk = C.ScriptedClerk(C.clerk_reply(""), fault=C.Fault(raise_after=0))
    _, main, _ = C.record_run(tmp_path, run_dir=run_dir, clerk=clerk, prose=[C.WARN_ROWS])

    receipt = main.receipt
    assert C.OUTCOME_PENDING in receipt, C.outcome_lines(receipt)
    assert "bytes to investigation.md" in receipt, (
        f"the faulted call never told MAIN its prose landed: {receipt!r}"
    )
    assert "FLAGGED" in receipt, (
        "the faulted call never told MAIN a flagged row now blocks every later write and the "
        f"close: {receipt!r}"
    )
