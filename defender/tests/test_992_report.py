"""#992 — what the committed report carries (O4, M4, the vocabularies, the caps, and the
ticket egress).

Every test here is one demand of `spec-flow/specs/spec_graph_992.yaml`, named by that demand's
`discharged_by`. RED against 67d29090 is the expected state: the reviewed `_CloseFields` site
has no `ceiling_test`, `REPORT_CAUSES` has six members, and the `ceiling_test` note is
unbounded at the entry-price gate (a6: a 9000-character note passes the gate and strands the
run at the commit).

Two §7 decisions against the judge land here. FK-10: `REPORT_CAUSES` gains a SEVENTH member
and the ticket's closing comment carries it verbatim on a ceiling-held close. R6: the
accumulated rendered `ceiling_test` notes are BOUNDED at the entry-price gate, at both
boundaries, refused before any stage — the value is the implementer's (the spine assumed
2048 B, the sibling `_MAX_RUNTIME_EVIDENCE_BODY_BYTES`), so the test walks a size ladder and
asserts the first refusal is the price gate's at every rung, never the commit's.
"""
from __future__ import annotations

from dataclasses import fields

from defender._artifact_schema import REPORT_FRONTMATTER_MAX, validate_artifact
from defender.runtime.challenge_gate import GateVerdict
from defender.runtime.close_tool import (
    CAUSE_REVIEW_INCOMPLETE,
    CLOSE_RETURNS,
    FAILURE_KINDS,
    REPORT_CAUSES,
    STANDS,
    CloseResult,
)
from defender.scripts.case_history import case_ticket
from defender.skills.invlang.validate import validate_companion
from defender.skills.invlang.validate._gating import _MAX_CEILING_FRONTMATTER_BYTES, ceiling_test_block
from defender.tests import _spec923, _tacit983
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)
from defender.tests._spec992 import (
    CEILING_EXAMINED,
    CONFIDENT,
    GAP,
    NOTE_LADDER,
    UNRESOLVED,
    SHIPPED_CAUSES,
    V2SSHD_RECEIPTS,
    bounds,
    ceiling_companion,
    close_with,
    deps_over,
    frontmatter,
    gap,
    holds,
    note_text,
    noted_companion,
    priced_block,
    raises,
    receipt_note_lines,
    receipts_at_block_cap,
    record_files,
    recording,
    refusal,
    report_parts,
    sparse_companion,
    trace_files,
    wide_companion,
)

_ONE_TURN = "extra_turns"


def _override_arms() -> list[tuple[str, object, dict]]:
    """Every arm on which an `inconclusive` is OVERRIDDEN to `unresolved` after review — the
    same four arms that override a confident close (one rule; test_992_routing's docstring):
    `(name, stages, close kwargs)` for the last attempt; a repeat and a spent pool need a
    challenged attempt first."""
    return [
        ("null-ask", recording(gap(None)), {}),
        ("repeat", recording(gap("l-004")), {"after": [recording(gap("l-004"))]}),
        ("spent-pool", recording(gap("l-005")), {"after": [recording(gap("l-004"))], _ONE_TURN: 1}),
        ("machinery-failure", recording(faults={"composer": raises(RuntimeError("down"))}), {}),
    ]


def _drive(deps, name: str, stages, kw: dict):
    limits = bounds(extra_turns=kw[_ONE_TURN]) if _ONE_TURN in kw else None
    for earlier in kw.get("after", []):
        assert close_with(deps, GAP, earlier, bounds=limits).outcome == "challenged", name
    return close_with(deps, GAP, stages, bounds=limits)


def test_reviewed_inconclusive_carries_receipts(tmp_path):
    """An `inconclusive` that STANDS after review — the held ceiling, the one arm that stands —
    carries into report.md the `ceiling_test:` frontmatter block with the exact receipts the
    entry price gate priced (`state`/`ref`/`cap`), one `ceiling_test (...)` note line per
    receipt in the body, and the `runtime_evidence` block beside it; an `inconclusive` the
    review OVERRIDES — null ask, repeat, spent pool, machinery failure — commits `unresolved`
    and, like every `unresolved`, carries no block and no note line (the receipts stay in
    investigation.md); receipts land identically when the ablation lens was skipped, and two
    rows citing one ref with different states are not collapsed — the lead-anchored
    consistency check refuses the inconsistent one at the price gate (rg4).

    The close reads the file ONCE and the block carries the rows that one parse produced; a
    companion that read cannot decode never reaches the review at all (a row of
    test_992_routing's machinery-failure arms)."""
    golden = ceiling_companion()
    deps, run_dir = deps_over(tmp_path / "holds", golden)
    assert close_with(deps, GAP, recording(holds())).outcome == STANDS
    head, body = report_parts(run_dir)
    assert head.endswith(priced_block(golden)), head
    assert priced_block(golden).startswith("ceiling_test:\n")
    notes = receipt_note_lines(body)
    assert len(notes) == len(V2SSHD_RECEIPTS), notes
    for (state, ref), line in zip(V2SSHD_RECEIPTS, notes, strict=True):
        assert line.startswith(f"ceiling_test ({state}, {ref}): "), line

    for name, stages, kw in _override_arms():
        deps, run_dir = deps_over(tmp_path / name, golden)
        result = _drive(deps, name, stages, kw)
        assert result.outcome == "forced-inconclusive", (name, result)
        assert frontmatter(run_dir)["disposition"] == UNRESOLVED, name
        head, body = report_parts(run_dir)
        assert "ceiling_test" not in head, (name, head)
        assert receipt_note_lines(body) == [], (name, body)
        assert "ceiling_test" in (run_dir / "investigation.md").read_text(encoding="utf-8")

    # The baseline block rides beside the receipts on the reviewed path too.
    with_baseline = _tacit983.inconclusive_document(
        rows=_tacit983.consult_block(_tacit983.consultation_row()),
    )
    deps, run_dir = deps_over(tmp_path / "baseline", with_baseline)
    assert close_with(deps, GAP, recording(holds())).outcome == STANDS
    head, body = report_parts(run_dir)
    assert head.endswith(priced_block(with_baseline))
    assert "runtime-evidence" in body
    assert receipt_note_lines(body)

    # Identical whether the ablation lens ran (the golden) or was skipped (the sparse one).
    sparse = sparse_companion()
    deps, run_dir = deps_over(tmp_path / "sparse", sparse)
    skipped = recording(holds())
    assert close_with(deps, GAP, skipped).outcome == STANDS
    assert skipped.calls == ["support", "composer"]
    assert report_parts(run_dir)[0].endswith(priced_block(sparse))

    # Two rows citing one ref with different states: the inconsistent one is refused at the
    # price gate, before any stage.
    conflicting = _spec923.paid(
        "state=query-failed ref=l-002 note=matches its fail_reason",
        "state=query-empty ref=l-002 note=contradicts its fail_reason",
    )
    stages = recording(holds())
    deps, run_dir = deps_over(tmp_path / "conflict", conflicting)
    text = refusal(deps, GAP, stages)
    assert "query-empty" in text
    assert "l-002" in text
    assert stages.calls == []


def test_confident_and_forced_commits_carry_no_ceiling_test(tmp_path):
    """A reviewed confident close and a gate-forced `unresolved` commit no `ceiling_test:` block
    and no receipt note lines — the receipts are keyed on the verdict's disposition being
    `inconclusive`; a confident close over a document whose conclude block says `inconclusive`
    commits no block either, while the receipts stay visible to the composer inside the
    companion (C3); positive control: the reviewed `inconclusive` over the same companion
    spends the review and carries the block."""
    golden = ceiling_companion()

    confident = recording(holds())
    deps, run_dir = deps_over(tmp_path / "confident", golden)
    assert close_with(deps, CONFIDENT, confident).outcome == STANDS
    head, body = report_parts(run_dir)
    assert "ceiling_test" not in head
    assert receipt_note_lines(body) == []
    assert "l-004" in confident.prompt("composer")
    assert "query-empty" in confident.prompt("composer")

    deps, run_dir = deps_over(tmp_path / "forced", golden)
    forced = close_with(deps, CONFIDENT, recording(gap(None)))
    assert forced.outcome == "forced-inconclusive"
    assert frontmatter(run_dir)["disposition"] == "unresolved"
    head, body = report_parts(run_dir)
    assert "ceiling_test" not in head
    assert receipt_note_lines(body) == []

    control = recording(holds())
    deps, run_dir = deps_over(tmp_path / "control", golden)
    assert close_with(deps, GAP, control).outcome == STANDS
    assert control.calls, "the control did not spend the review"
    head, body = report_parts(run_dir)
    assert head.endswith(priced_block(golden))
    assert len(receipt_note_lines(body)) == 2


def _near_cap_rows() -> tuple[str, ...]:
    """As many distinct paying receipts as fit under `_MAX_CEILING_FRONTMATTER_BYTES`."""
    from defender.runtime.review.projector import parse_investigation
    from defender.skills.invlang.validate import conclude_ceiling_test_rows

    rows: list[str] = []
    while True:
        candidate = rows + [
            f"state=nothing-to-try cap=fake-system-{len(rows):03d}.fake-verb note=capability {len(rows):03d}"
        ]
        block = ceiling_test_block(conclude_ceiling_test_rows(parse_investigation(_spec923.paid(*candidate))))
        if len(block.encode("utf-8")) > _MAX_CEILING_FRONTMATTER_BYTES:
            break
        rows = candidate
    assert rows, "not even one receipt fits under the block cap"
    return tuple(rows)


def test_reviewed_inconclusive_report_frontmatter_stays_under_its_cap_with_the_longest_cause(tmp_path):
    """A reviewed `inconclusive` that stands — under the seventh cause, the longest sentence in
    REPORT_CAUSES — with a `ceiling_test` block at `_MAX_CEILING_FRONTMATTER_BYTES` commits
    inside the 512-byte frontmatter cap; the arithmetic is still checked over EVERY member with
    the longest `failure_kind` beside a block at the cap, so no arm the vocabulary could grow
    into overflows; `validate_report` refuses an overflow; and the seventh cause exists (d23,
    §7 FK-10). (The override arms commit `unresolved`, which carries no block — they are the
    arithmetic's rows, not a reachable overflow.)"""
    rows = _near_cap_rows()
    at_cap = _spec923.paid(*rows)
    block = priced_block(at_cap)
    assert _MAX_CEILING_FRONTMATTER_BYTES - 64 < len(block.encode("utf-8")) <= _MAX_CEILING_FRONTMATTER_BYTES

    deps, run_dir = deps_over(tmp_path / "seventh-cause", at_cap)
    assert close_with(deps, GAP, recording(holds())).outcome == STANDS
    fm = frontmatter(run_dir)
    assert fm["cause"] == CEILING_EXAMINED, fm
    assert "failure_kind" not in fm, fm
    head, _body = report_parts(run_dir)
    assert head.endswith(block)
    assert len(head.encode("utf-8")) <= REPORT_FRONTMATTER_MAX, len(head.encode("utf-8"))

    # The arithmetic over the REAL tuple: every member, with the longest kind, plus a block at
    # the cap, fits — and the seventh is a member.
    assert CEILING_EXAMINED in REPORT_CAUSES
    longest_kind = max(FAILURE_KINDS, key=len)
    for cause in REPORT_CAUSES:
        head = (
            f"disposition: {GAP}\noutcome: {STANDS}\ncause: {cause}\n"
            f"failure_kind: {longest_kind}\n"
        )
        assert len(head.encode("utf-8")) + _MAX_CEILING_FRONTMATTER_BYTES <= REPORT_FRONTMATTER_MAX, cause

    # The cap is real: an overflowing frontmatter is refused by the report schema.
    overflow = "---\n" + f"disposition: {GAP}\noutcome: {STANDS}\ncause: {CEILING_EXAMINED}\n" + (
        "ceiling_test:\n" + "".join(f"- state: nothing-to-try\n  cap: fake-system-{i:03d}.fake-verb\n" for i in range(12))
    ) + "---\nDisposition recorded by the close gate. outcome=stands.\n"
    assert validate_artifact("report.md", overflow, None) is not None


def test_reviewed_inconclusive_ceiling_note_overflow_is_refused(tmp_path):
    """The accumulated rendered `ceiling_test` note lines are BOUNDED at the entry-price gate —
    collected at BOTH boundaries, the investigation.md write gate and the close — with the same
    refusal shape the gate already uses for the over-cap receipt block: an over-cap note is
    refused BEFORE any stage runs (no trace row, no record, no report) and never reaches the
    commit, so at no note size does the close refuse at `validate_report`'s whole-file cap; a
    note under the bound commits on the reviewed path with the note rendered in full; the
    block-cap maximum of distinct receipts each carrying the largest single note the ladder
    commits is either refused at the price gate or commits — never refused at the commit, so
    the file cap is unreachable by notes alone whether the bound is accumulated or per-note
    (F-3); and a literal `</report>` in a note is still refused at the price gate (§7 R6: the
    bound's value is the implementer's, asserted at whatever bound the code declares)."""
    first_refusal_at: int | None = None
    largest_committing: int | None = None
    for size in NOTE_LADDER:
        companion = noted_companion(size)
        stages = recording(holds())
        deps, run_dir = deps_over(tmp_path / f"note-{size}", companion)
        at_write_gate = validate_companion(companion, None)
        try:
            result = close_with(deps, GAP, stages)
        except Exception as e:  # noqa: BLE001 — the refusal's TEXT is the observable
            text = str(e)
            assert "report.md is" not in text, f"a {size}-character note reached the COMMIT and was refused there: {text!r}"
            assert "over the 8192-byte limit" not in text, f"a {size}-character note reached the COMMIT and was refused there: {text!r}"
            assert "close blocked" in text, (size, text)
            assert "ceiling_test" in text, (size, text)
            assert stages.calls == [], f"the refused close spent {stages.calls}"
            assert trace_files(run_dir) == []
            assert record_files(run_dir) == []
            assert not (run_dir / "report.md").exists()
            assert any(f"{GAP} blocked" in err and "ceiling_test" in err for err in at_write_gate), (
                f"the {size}-character note is refused at the close but not at the write gate: "
                f"{at_write_gate!r}"
            )
            if first_refusal_at is None:
                first_refusal_at = size
            continue
        assert first_refusal_at is None, f"a {size}-character note committed above the bound"
        largest_committing = size
        assert at_write_gate == [], (size, at_write_gate)
        assert result.outcome == STANDS
        assert stages.calls
        _head, body = report_parts(run_dir)
        notes = receipt_note_lines(body)
        assert len(notes) == 1, (size, notes)
        assert notes[0].endswith(note_text(size)), (size, notes)
    assert first_refusal_at is not None, "no note size on the ladder was refused — the note is unbounded"
    assert first_refusal_at > NOTE_LADDER[0], "even a short note is refused"

    # N receipts (the block cap's maximum) × the largest single note that commits: the file
    # cap must stay unreachable by notes alone, so the close is refused at the PRICE GATE or it
    # commits — it is never refused at the commit after the review was spent (a6's hazard).
    assert largest_committing is not None
    many = wide_companion(receipts_at_block_cap(), note_text(largest_committing))
    stages = recording(holds())
    deps, run_dir = deps_over(tmp_path / "many-receipts", many)
    try:
        assert close_with(deps, GAP, stages).outcome == STANDS
        assert len(receipt_note_lines(report_parts(run_dir)[1])) == receipts_at_block_cap()
    except Exception as e:  # noqa: BLE001 — the refusal's TEXT is the observable
        text = str(e)
        assert "report.md is" not in text, f"N receipts × the largest note reached the COMMIT: {text!r}"
        assert "over the 8192-byte limit" not in text, text
        assert "close blocked" in text, text
        assert "ceiling_test" in text, text
        assert stages.calls == [], f"the refused close spent {stages.calls}"
        assert not (run_dir / "report.md").exists()
        assert any(f"{GAP} blocked" in err for err in validate_companion(many, None)), (
            "refused at the close but not at the write gate"
        )

    # Positive control at a modest size: the note rides into the body in full.
    modest = noted_companion(NOTE_LADDER[0])
    deps, run_dir = deps_over(tmp_path / "modest", modest)
    assert close_with(deps, GAP, recording(holds())).outcome == STANDS
    assert len(receipt_note_lines(report_parts(run_dir)[1])) == 1

    # The report delimiter in a note is still the price gate's refusal.
    delimiter = sparse_companion("state=query-failed ref=l-002 note=the note carries </report> inside it")
    stages = recording(holds())
    deps, _run_dir = deps_over(tmp_path / "delimiter", delimiter)
    assert "</report>" in refusal(deps, GAP, stages)
    assert stages.calls == []


def test_vocabularies_and_types_unchanged():
    """`CLOSE_RETURNS` is still exactly (challenged, stands, forced-inconclusive); `REPORT_CAUSES`
    is exactly the six shipped sentences verbatim plus the seventh appended (§7 FK-10) — no
    other sentence added, none reworded; and `CloseResult` / `GateVerdict` carry the same field
    names — no outcome member, type or field was added for the ceiling review."""
    assert CLOSE_RETURNS == ("challenged", "stands", "forced-inconclusive")
    expected_causes = (*SHIPPED_CAUSES, CEILING_EXAMINED)
    assert expected_causes == REPORT_CAUSES, REPORT_CAUSES
    assert len(set(REPORT_CAUSES)) == 7
    assert [f.name for f in fields(CloseResult)] == [
        "outcome", "message", "material", "record_path", "cause", "detail", "turns_used", "failure_kind",
    ]
    assert [f.name for f in fields(GateVerdict)] == [
        "outcome", "disposition", "cause", "detail", "material", "turns_used", "failure_kind",
    ]


def test_case_ticket_closing_comment_reads_a_reviewed_inconclusive_close(tmp_path, monkeypatch):
    """Driving a reviewed, ceiling-held `inconclusive` close through to the ticket bridge, the
    outbound comment's first line carries `disposition: inconclusive` beside the SEVENTH cause
    sentence — "the challenge review examined the ceiling claim and found nothing further
    measurable" — verbatim, and a machinery-failed `inconclusive` (failed closed to
    `unresolved` + failure_kind + CAUSE_REVIEW_INCOMPLETE) renders through the same reader as
    the host's own verdict, never as the ceiling claim the review could not check.

    #767 D2/D3 replaced the close transition and `case_record_to_close`'s `resolution` field
    with a recorded comment and `case_record_to_comment`'s `body`; the membership check this
    test names (REPORT_CAUSES gaining a seventh member) is unaffected by that rename."""
    from defender.tests._spec767 import use_mapping

    settings = use_mapping(monkeypatch, tmp_path / "dfn")
    deps, run_dir = deps_over(tmp_path / "held", ceiling_companion())
    assert close_with(deps, GAP, recording(holds())).outcome == STANDS
    fm = frontmatter(run_dir)
    assert (fm["disposition"], fm["outcome"], fm["cause"]) == (GAP, STANDS, CEILING_EXAMINED)
    rec = case_ticket.read_case_record(run_dir, settings_dir=settings)
    assert rec.disposition == GAP
    assert rec.cause == CEILING_EXAMINED
    comment = case_ticket.case_record_to_comment(rec, settings_dir=settings)
    assert comment["body"].startswith(f"{GAP} — {CEILING_EXAMINED}")

    deps, run_dir = deps_over(tmp_path / "broken", ceiling_companion())
    broken = close_with(deps, GAP, recording(faults={"composer": raises(RuntimeError("down"))}))
    assert broken.outcome == "forced-inconclusive"
    assert broken.failure_kind is not None
    rec = case_ticket.read_case_record(run_dir, settings_dir=settings)
    assert rec.disposition == UNRESOLVED
    assert rec.cause == CAUSE_REVIEW_INCOMPLETE
    assert CEILING_EXAMINED not in case_ticket.case_record_to_comment(rec, settings_dir=settings)["body"]
