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
    CAUSE_EVIDENCE_CANNOT_DISCRIMINATE,
    CAUSE_REVIEW_INCOMPLETE,
    CLOSE_RETURNS,
    FAILURE_KINDS,
    REPORT_CAUSES,
    STAGE_ERROR,
    STANDS,
    UNREADABLE,
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
    SHIPPED_CAUSES,
    V2SSHD_RECEIPTS,
    bounds,
    ceiling_companion,
    close_with,
    deps_over,
    frontmatter,
    gap,
    holds,
    lenient_text,
    non_utf8_companion,
    note_text,
    noted_companion,
    priced_block,
    raises,
    receipt_note_lines,
    receipts_at_block_cap,
    record_files,
    recording,
    refusal,
    replies,
    report_parts,
    sparse_companion,
    trace_files,
    wide_companion,
)

_ONE_TURN = "extra_turns"


def _standing_arms() -> list[tuple[str, object, dict]]:
    """Every arm on which an `inconclusive` STANDS after review: `(name, stages, close kwargs)`
    for the last attempt; a repeat and a spent pool need a challenged attempt first."""
    return [
        ("holds", recording(holds()), {}),
        ("null-ask", recording(gap(None)), {}),
        ("repeat", recording(gap("l-004")), {"after": [recording(gap("l-004"))]}),
        ("spent-pool", recording(gap("l-005")), {"after": [recording(gap("l-004"))], _ONE_TURN: 1}),
        ("machinery-failure", recording(faults={"composer": raises(RuntimeError("down"))}), {}),
    ]


def _stand(deps, name: str, stages, kw: dict):
    limits = bounds(extra_turns=kw[_ONE_TURN]) if _ONE_TURN in kw else None
    for earlier in kw.get("after", []):
        assert close_with(deps, GAP, earlier, bounds=limits).outcome == "challenged", name
    result = close_with(deps, GAP, stages, bounds=limits)
    assert result.outcome == STANDS, (name, result)
    return result


def test_reviewed_inconclusive_carries_receipts(tmp_path):
    """Every `inconclusive` that stands after review — on holds, null ask, repeat, spent pool
    and machinery failure alike — carries into report.md the `ceiling_test:` frontmatter block
    with the exact receipts the entry price gate priced (`state`/`ref`/`cap`, the price gate's
    own parse, never the gate's second read — pinned on a non-UTF-8 companion the price gate
    decodes leniently and the gate's strict read refuses, where the commit stands on
    CAUSE_REVIEW_INCOMPLETE/`error` with the lenient parse's block), one `ceiling_test (...)`
    note line per receipt in
    the body, and the `runtime_evidence` block beside it; receipts land identically when the
    ablation lens was skipped, render identically whatever the review found (the cause alone
    distinguishes), and two rows citing one ref with different states are not collapsed — the
    lead-anchored consistency check refuses the inconsistent one at the price gate (rg4)."""
    golden = ceiling_companion()
    for name, stages, kw in _standing_arms():
        deps, run_dir = deps_over(tmp_path / name, golden)
        _stand(deps, name, stages, kw)
        head, body = report_parts(run_dir)
        assert head.endswith(priced_block(golden)), (name, head)
        assert priced_block(golden).startswith("ceiling_test:\n")
        notes = receipt_note_lines(body)
        assert len(notes) == len(V2SSHD_RECEIPTS), (name, notes)
        for (state, ref), line in zip(V2SSHD_RECEIPTS, notes, strict=True):
            assert line.startswith(f"ceiling_test ({state}, {ref}): "), (name, line)

    # The price gate's OWN parse is the source (design M4, C14, G18 — the judge's corrected
    # value for FK-17/18/19): on the one in-process input where the two reads differ — a
    # non-UTF-8 byte the price gate decodes leniently and the gate's strict read refuses — the
    # commit stands on CAUSE_REVIEW_INCOMPLETE/`error` and carries the block the LENIENT parse
    # of the same bytes renders, which the gate's own read never produced.
    raw = non_utf8_companion()
    deps, run_dir = deps_over(tmp_path / "non-utf8", raw)
    divergent = close_with(deps, GAP, recording(holds()))
    assert (divergent.outcome, divergent.cause, divergent.failure_kind) == (
        STANDS, CAUSE_REVIEW_INCOMPLETE, STAGE_ERROR,
    )
    head, body = report_parts(run_dir)
    assert head.endswith(priced_block(lenient_text(raw))), head
    assert len(receipt_note_lines(body)) == len(V2SSHD_RECEIPTS)

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

    # Identical whatever the review found: the note lines are the same on every arm.
    bodies = {}
    for name in ("holds", "null-ask", "machinery-failure"):
        bodies[name] = receipt_note_lines(report_parts(tmp_path / name / "run")[1])
    assert bodies["holds"] == bodies["null-ask"] == bodies["machinery-failure"]
    assert frontmatter(tmp_path / "holds" / "run")["cause"] != frontmatter(tmp_path / "null-ask" / "run")["cause"]

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
    """A reviewed `inconclusive` with the longest REPORT_CAUSES member, a `failure_kind`, and a
    `ceiling_test` block at `_MAX_CEILING_FRONTMATTER_BYTES` commits inside the 512-byte
    frontmatter cap (G13/a5: 457 of 512 B in the worst reachable case; the seventh member is
    the longest sentence but rides the arm that carries no `failure_kind`); `validate_report`
    refuses an overflow; and the seventh cause exists (d23, §7 FK-10)."""
    rows = _near_cap_rows()
    at_cap = _spec923.paid(*rows)
    block = priced_block(at_cap)
    assert _MAX_CEILING_FRONTMATTER_BYTES - 64 < len(block.encode("utf-8")) <= _MAX_CEILING_FRONTMATTER_BYTES

    arms = {
        "longest-cause": (recording(gap(None)), CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, None),
        "seventh-cause": (recording(holds()), CEILING_EXAMINED, None),
        "with-failure-kind": (recording(replies("not json")), CAUSE_REVIEW_INCOMPLETE, UNREADABLE),
    }
    for name, (stages, cause, kind) in arms.items():
        deps, run_dir = deps_over(tmp_path / name, at_cap)
        assert close_with(deps, GAP, stages).outcome == STANDS, name
        fm = frontmatter(run_dir)
        assert fm["cause"] == cause, (name, fm)
        assert fm.get("failure_kind") == kind, (name, fm)
        head, _body = report_parts(run_dir)
        assert head.endswith(block)
        assert len(head.encode("utf-8")) <= REPORT_FRONTMATTER_MAX, (name, len(head.encode("utf-8")))

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


def test_case_ticket_closing_comment_reads_a_reviewed_inconclusive_close(tmp_path):
    """Driving a reviewed, ceiling-held `inconclusive` close through to the ticket bridge, the
    closing comment carries `disposition: inconclusive`, `outcome: stands` and the SEVENTH cause
    sentence — "the challenge review examined the ceiling claim and found nothing further
    measurable" — verbatim, `case_ticket`'s membership check (which imports REPORT_CAUSES)
    accepts it, and a machinery-failed `inconclusive` (stands + failure_kind +
    CAUSE_REVIEW_INCOMPLETE) renders through the same reader without claiming a settled
    finding."""
    deps, run_dir = deps_over(tmp_path / "held", ceiling_companion())
    assert close_with(deps, GAP, recording(holds())).outcome == STANDS
    fm = frontmatter(run_dir)
    assert (fm["disposition"], fm["outcome"], fm["cause"]) == (GAP, STANDS, CEILING_EXAMINED)
    rec = case_ticket.read_case_record(run_dir)
    assert rec.disposition == GAP
    assert rec.reason == CEILING_EXAMINED
    closing = case_ticket.case_record_to_close(rec)
    assert closing["resolution"].startswith(GAP)
    assert CEILING_EXAMINED in closing["resolution"]
    assert case_ticket.parse_disposition_from_resolution(closing["resolution"]) == GAP

    # The membership check covers seven: the host's own verdict beside the new sentence
    # decodes, where an arbitrary reason is refused.
    host_close = case_ticket.case_record_to_close(case_ticket.CaseRecord(
        case_id="c", signature_id="5710", disposition="unresolved", confidence="medium",
        reason=CEILING_EXAMINED,
    ))
    assert case_ticket.parse_disposition_from_resolution(host_close["resolution"]) == "unresolved"

    deps, run_dir = deps_over(tmp_path / "broken", ceiling_companion())
    broken = close_with(deps, GAP, recording(faults={"composer": raises(RuntimeError("down"))}))
    assert broken.outcome == STANDS
    assert broken.failure_kind is not None
    rec = case_ticket.read_case_record(run_dir)
    assert rec.disposition == GAP
    assert rec.reason == CAUSE_REVIEW_INCOMPLETE
    assert CEILING_EXAMINED not in case_ticket.case_record_to_close(rec)["resolution"]
