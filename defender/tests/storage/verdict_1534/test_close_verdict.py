"""#1534: the close commits the run's one closing record in its session database: host fields, entries and a summary built
from the closing rows (V-ONE, V-FINAL, V-FIELDS, V-SUM, V-TEXT at the builder, V-NOFILE).

Entry: the real close (`_spec923.close`) over MAIN deps from `_spec1534.closing_deps` + `with_store`, and the driver's own
forced close (`_spec1534.drive_forced_close`). Read back through the run-handle lookup (`closing.for_run`)."""
from __future__ import annotations

import threading
import time

import pytest

from defender._vocab import DISPOSITION_VALUES, PROCESS_GAP_DISPOSITION
from defender.tests.storage.verdict_1534 import _close_b as B
from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.runtime.engine import _spec923 as S
from defender.tests.support.runtime.engine import _spec992 as S9
from defender.tests.support.sandbox._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)
from defender.tests.support.shared.contracts import _tacit983 as scene

HOST = S.MEMBER
#: The two free-text rows `S.pays_every_price` writes, in the design's piece order (summary, detection_notes).
JOINED = "one document that owes no keyword anything Groups by host, so the actor the rule names is never tested."
PROCESS_GAP_SUMMARY = "routine maintenance by alice[.]ops with no change record"
LOCK_HELD_S = 2.0


def _opener(cause: str, kind: str | None = None) -> str:
    from defender.records import closing as C

    return C.OPENERS[(cause, kind)]


# --- V-ONE / V-FIELDS: a close that stands, for every model disposition ------------------------------------------------

@pytest.mark.parametrize("disposition", [d for d in DISPOSITION_VALUES if d != HOST])
def test_v_one_every_model_disposition_commits_one_record_and_no_report_file(tmp_path, disposition):
    """A reviewed close that stands commits exactly one record with the host's typed fields, the receipts and the
    summary built from the rows, and no `report.md`. (V-ONE, V-FIELDS, V-SUM, V-NOFILE)"""
    from defender.investigation import challenge_gate
    from defender.records import closing as C

    done = B.close_run(tmp_path, disposition, S.pays_every_price(disposition))

    rec = done.record
    assert len(V.scalar_rows(done.database, done.run_dir.name)) == 1
    cause = C.CAUSE_CEILING_EXAMINED if disposition == S.GAP_MEMBER else C.CAUSE_STORY_SETTLED
    assert (rec.run_id, rec.disposition, rec.outcome, rec.cause, rec.failure_kind, rec.drafted_disposition) == (
        done.run_dir.name, disposition, C.STANDS, cause, None, None)
    gap_free = disposition == PROCESS_GAP_DISPOSITION
    assert B.ceiling_of(rec) == ([] if gap_free else [(
        "query-failed", "l-002", None, "EDR execve logs for web-1 never came back; the collector returned HTTP 503")])
    assert rec.summary == (PROCESS_GAP_SUMMARY if gap_free else JOINED)
    assert not (done.run_dir / "report.md").exists(), "the close wrote report.md"
    assert S9.record_files(done.run_dir) == [1]
    assert challenge_gate.ReviewState.of(done.deps).closed


def test_v_one_a_challenged_attempt_commits_nothing_and_the_final_close_commits_one(tmp_path):
    """A close the review challenges leaves no record; the close that follows commits exactly one. (V-ONE)"""
    with B.opened(tmp_path, B.DOC) as (deps, run_dir, store):
        target = S.real_targets(deps)[0]
        first = S9.close_with(deps, "malicious", S9.recording(S9.gap(target)))
        assert first.outcome == "challenged"
        assert V.scalar_rows(store.path, run_dir.name) == []
        S9.close_with(deps, "malicious", S9.recording(S9.holds()))
        assert len(V.scalar_rows(store.path, run_dir.name)) == 1


# --- V-FIELDS: every committing path ---------------------------------------------------------------------------------

def test_v_fields_the_hosts_forced_close_is_unresolved_not_reviewed_with_its_rows_after_the_opener(tmp_path):
    """The no-review branch: `unresolved`, stands, not reviewed, no draft; the rows follow the opener; receipts and
    baselines of the parse are carried. (V-FIELDS, V-SUM)"""
    from defender.records import closing as C

    rec = B.forced_close(tmp_path, B.DOC).record

    assert (rec.disposition, rec.outcome, rec.cause, rec.failure_kind, rec.drafted_disposition) == (
        HOST, C.STANDS, C.CAUSE_NOT_REVIEWED, None, None)
    assert rec.summary == f"{_opener(C.CAUSE_NOT_REVIEWED)} {B.DOC_SUMMARY}"
    assert B.ceiling_of(rec) == [B.DOC_RECEIPT]
    assert B.baselines_of(rec) == [B.DOC_BASELINE]


@pytest.mark.parametrize("companion", [None, S9.non_utf8_companion()], ids=["absent", "undecodable"])
def test_v_sum_a_forced_close_with_no_document_has_the_opener_alone(tmp_path, companion):
    """No readable document: the summary is the opener only, with no entries. (V-SUM)"""
    from defender.records import closing as C

    rec = B.forced_close(tmp_path, companion).record

    assert (rec.disposition, rec.cause, rec.summary) == (HOST, C.CAUSE_NOT_REVIEWED, _opener(C.CAUSE_NOT_REVIEWED))
    assert (B.ceiling_of(rec), B.baselines_of(rec)) == ([], [])


def test_v_fields_the_overrule_of_an_unreadable_document_keeps_the_opener_only_and_the_draft(tmp_path):
    """`_overrule_unreadable_companion`: review incomplete + error, draft kept, summary the opener alone, no entries.
    (V-FIELDS, V-SUM, OD14)"""
    from defender.records import closing as C

    rec = B.close_run(tmp_path, "malicious", S9.non_utf8_companion()).record

    assert (rec.disposition, rec.outcome, rec.cause, rec.failure_kind, rec.drafted_disposition) == (
        HOST, C.FORCED_INCONCLUSIVE, C.CAUSE_REVIEW_INCOMPLETE, C.STAGE_ERROR, "malicious")
    assert rec.summary == _opener(C.CAUSE_REVIEW_INCOMPLETE, C.STAGE_ERROR)
    assert (B.ceiling_of(rec), B.baselines_of(rec)) == ([], [])


_FAILS = {
    "raises": (lambda: S9.recording(faults={"composer": S9.raises(RuntimeError("the provider dropped the call"))}), None,
               "error"),
    "times-out": (lambda: S9.recording(faults={"composer": S9.sleeps(5.0)}), S9.bounds(stage_timeout=0.05), "timeout"),
    "unreadable": (lambda: S9.recording(S9.replies("not the contract")), None, "unreadable"),
    "unbound": (lambda: None, None, "error"),
}


@pytest.mark.parametrize("name", list(_FAILS))
def test_v_fields_a_review_that_failed_commits_unresolved_with_its_kind_and_opener(tmp_path, name):
    """`_fail` (stage raised / timed out / unreadable reply / no bundle): review incomplete, the kind, the draft; the
    opener keyed on the kind, then the rows; entries kept. (V-FIELDS, V-SUM)"""
    from defender.records import closing as C

    make, bounds, kind = _FAILS[name]
    stages = make()
    if stages is None:
        rec = _unbound(tmp_path)
    else:
        rec = B.close_run(tmp_path, "malicious", B.DOC, stages=stages, bounds=bounds).record

    assert (rec.disposition, rec.outcome, rec.cause, rec.failure_kind, rec.drafted_disposition) == (
        HOST, C.FORCED_INCONCLUSIVE, C.CAUSE_REVIEW_INCOMPLETE, kind, "malicious")
    assert rec.summary == f"{_opener(C.CAUSE_REVIEW_INCOMPLETE, kind)} {B.DOC_SUMMARY}"
    assert B.ceiling_of(rec) == [B.DOC_RECEIPT]
    assert B.baselines_of(rec) == [B.DOC_BASELINE]


def _unbound(tmp_path):
    with B.opened(tmp_path, B.DOC) as (deps, run_dir, store):
        S9.close_with(deps, "malicious", None)
        return B.committed_record(run_dir, store)


@pytest.mark.parametrize("draft", ["malicious", "inconclusive"])
def test_v_fields_a_review_that_cannot_discriminate_overrules_the_draft_and_keeps_the_receipts(tmp_path, draft):
    """The review overrules a drafted `inconclusive` (or confident) close: evidence cannot discriminate, the draft,
    receipts kept, the opener then the rows. (V-FIELDS, V-SUM)"""
    from defender.records import closing as C

    rec = B.close_run(tmp_path, draft, B.DOC, stages=S9.recording(S9.gap(None))).record

    assert (rec.disposition, rec.outcome, rec.cause, rec.failure_kind, rec.drafted_disposition) == (
        HOST, C.FORCED_INCONCLUSIVE, C.CAUSE_EVIDENCE_CANNOT_DISCRIMINATE, None, draft)
    assert rec.summary == f"{_opener(C.CAUSE_EVIDENCE_CANNOT_DISCRIMINATE)} {B.DOC_SUMMARY}"
    assert B.ceiling_of(rec) == [B.DOC_RECEIPT]
    assert B.baselines_of(rec) == [B.DOC_BASELINE]


def test_v_fields_a_repeated_ask_and_a_spent_turn_pool_each_overrule_with_their_own_cause(tmp_path):
    """The two overrules that follow a challenged attempt: nothing left to ask, and turn budget spent. (V-FIELDS, V-SUM)"""
    from defender.records import closing as C

    with B.opened(tmp_path / "repeat", B.DOC) as (deps, run_dir, store):
        target = S.real_targets(deps)[0]
        assert S9.close_with(deps, "malicious", S9.recording(S9.gap(target))).outcome == "challenged"
        S9.close_with(deps, "malicious", S9.recording(S9.gap(target)))
        rec = B.committed_record(run_dir, store)
    assert (rec.cause, rec.failure_kind, rec.drafted_disposition) == (C.CAUSE_NOTHING_LEFT_TO_ASK, None, "malicious")
    assert rec.summary == f"{_opener(C.CAUSE_NOTHING_LEFT_TO_ASK)} {B.DOC_SUMMARY}"

    one = S9.bounds(extra_turns=1)
    with B.opened(tmp_path / "spent", B.DOC) as (deps, run_dir, store):
        first, second = S.real_targets(deps)[:2]
        assert S9.close_with(deps, "malicious", S9.recording(S9.gap(first)), bounds=one).outcome == "challenged"
        S9.close_with(deps, "malicious", S9.recording(S9.gap(second)), bounds=one)
        rec = B.committed_record(run_dir, store)
    assert (rec.cause, rec.failure_kind, rec.drafted_disposition) == (C.CAUSE_TURN_BUDGET_SPENT, None, "malicious")
    assert rec.summary == f"{_opener(C.CAUSE_TURN_BUDGET_SPENT)} {B.DOC_SUMMARY}"
    assert rec.disposition == HOST
    assert rec.outcome == C.FORCED_INCONCLUSIVE


def test_v_fields_a_confident_close_carries_the_ceiling_receipts_and_baselines_of_its_parse(tmp_path):
    """Receipts and baselines ride on every close with a parse, whatever disposition commits. (V-FIELDS)"""
    rec = B.close_run(tmp_path, "malicious", B.DOC).record

    assert rec.disposition == "malicious"
    assert B.ceiling_of(rec) == [B.DOC_RECEIPT]
    assert B.baselines_of(rec) == [B.DOC_BASELINE]
    (baseline,) = rec.runtime_evidence
    assert (baseline.anchor_kind, baseline.grounding_kind) == ("runtime-evidence", "telemetry-baseline")


@pytest.mark.parametrize(("window", "start", "end"), [
    ("2026-04-04T02:00:00+02:00/2026-05-04T02:00:00+02:00", "2026-04-04T00:00:00Z", "2026-05-04T00:00:00Z"),
    ("2026-04-04T00:00:00Z/2026-05-04T00:00:00Z", "2026-04-04T00:00:00Z", "2026-05-04T00:00:00Z"),
    ("2026-04-04T00:00:00.123456Z/2026-05-04T00:00:00Z", "2026-04-04T00:00:00.123456Z", "2026-05-04T00:00:00Z"),
    ("2026-04-04T02:00:00.5+02:00/2026-05-04T00:00:00.000001Z", "2026-04-04T00:00:00.500000Z",
     "2026-05-04T00:00:00.000001Z"),
], ids=["offset", "already-canonical", "microseconds", "offset-and-microseconds"])
def test_v_fields_a_baseline_window_is_stored_as_canonical_utc_instants_and_renders_as_start_over_end(
        tmp_path, window, start, end):
    """A window is kept as ISO-8601 UTC with `Z`, microseconds only when non-zero; the baseline line renders it as
    `start/end` of those instants. (V-FIELDS, M2)"""
    from defender.records import closing as C

    doc = scene.inconclusive_document(rows=scene.consult_block(scene.consultation_row(window=window)))

    (entry,) = B.close_run(tmp_path, "malicious", doc).record.runtime_evidence

    assert (entry.window_start, entry.window_end) == (start, end)
    assert f"{start}/{end}" in C.baseline_line(entry)


@pytest.mark.parametrize(("cell", "column"), [
    ('"runtime-evidence"', "anchor_kind"), (" runtime-evidence ", "anchor_kind"),
    ('"telemetry-baseline"', "grounding"), (" telemetry-baseline ", "grounding"),
], ids=["anchor-quoted", "anchor-padded", "grounding-quoted", "grounding-padded"])
def test_v_fields_a_quoted_or_padded_kind_cell_closes_and_the_entry_holds_the_canonical_member(tmp_path, cell, column):
    """The gate strips a quoted or padded `anchor_kind`/`grounding` cell, so such a document closes; the stored entry
    holds the vocabulary member, not the cell as written. (V-FIELDS, L-5)"""
    from defender.records import closing as C
    from defender.skills.invlang.validate import validate_companion

    doc = scene.inconclusive_document(rows=scene.consult_block(scene.consultation_row(**{column: cell})))
    assert validate_companion(doc, None) == [], "fixture control: the gate accepts the cell"

    (entry,) = B.close_run(tmp_path, "malicious", doc).record.runtime_evidence

    assert (entry.anchor_kind, entry.grounding_kind) == ("runtime-evidence", "telemetry-baseline")
    assert entry.anchor_kind in C.ANCHOR_KINDS
    assert entry.grounding_kind in C.GROUNDING_KINDS


def test_v_fields_a_row_the_walkers_reject_is_dropped_and_the_close_still_commits(tmp_path):
    """On the forced close (no document gate): a receipt contradicting its lead and a baseline that reaches the alert
    are dropped; the accepted rows stay; the build never fails. (V-FIELDS)"""
    late = scene.consultation_row(anchor_id="tk-late", window=scene.WINDOW_STARTING_AT_ALERT)
    doc = scene.document(rows=scene.consult_block(scene.consultation_row(), late), settled=False)
    rec = B.forced_close(tmp_path, B.forced_doc(ceiling=(S.PAYING_ROW, S.SOURCE_ONLY_ROW))).record
    assert [r[:2] for r in B.ceiling_of(rec)] == [("query-failed", "l-002")]

    rec = B.forced_close(tmp_path / "late", doc).record
    assert [b[3] for b in B.baselines_of(rec)] == ["tk-baseline-30d"]


def test_v_fields_the_drivers_forced_close_of_a_run_cut_short_commits_stands_not_reviewed_with_the_rows(tmp_path):
    """A run cut short with `:T conclude` written: unresolved, stands, not reviewed, no draft; the cut-short opener then
    the rows; no review stage ran. (V-FIELDS, V-SUM)"""
    from defender.records import closing as C

    stages = S9.recording(S9.holds())
    with B.opened(tmp_path, B.DOC) as (deps, run_dir, store):
        _run, truncated_by, exit_reason = V.drive_forced_close(deps, store, review_stages=stages.bundle())
        rec = B.committed_record(run_dir, store)

    assert exit_reason == "UnexpectedModelBehavior"
    assert truncated_by is not None
    assert stages.calls == []
    assert (rec.disposition, rec.outcome, rec.cause, rec.failure_kind, rec.drafted_disposition) == (
        HOST, C.STANDS, C.CAUSE_NOT_REVIEWED, None, None)
    assert rec.summary == f"{_opener(C.CAUSE_NOT_REVIEWED)} {B.DOC_SUMMARY}"
    assert B.ceiling_of(rec) == [B.DOC_RECEIPT]


# --- V-SUM: the pieces -----------------------------------------------------------------------------------------------

def _pieces(**rows: str) -> str:
    return S.doc(S.PROLOGUE, S.LEADS, S.LEAD_RESULT, S.conclude(
        disposition="malicious", confidence="high", **{"termination.category": "data-ceiling"}, **rows))


@pytest.mark.parametrize(("rows", "expected"), [
    ({"summary": '"  alpha beta  "', "detection_notes": '" gamma "', "ceiling_rationale": '"   delta"'},
     "alpha beta gamma delta"),
    ({"summary": '"  alpha beta  "', "ceiling_rationale": '"   delta"'}, "alpha beta delta"),
    ({"ceiling_rationale": '"   delta "'}, "delta"),
    ({}, None),
], ids=["all-three", "summary-and-rationale", "rationale-only", "none"])
def test_v_sum_pieces_are_trimmed_joined_by_one_space_with_no_punctuation_added(tmp_path, rows, expected):
    """Order summary, detection_notes, ceiling_rationale; absent skipped; nothing to build from and not unresolved is
    null. (V-SUM)"""
    assert B.close_run(tmp_path, "malicious", _pieces(**rows)).record.summary == expected


# --- V-TEXT at the builder -------------------------------------------------------------------------------------------

def test_v_text_a_model_written_url_in_a_ceiling_note_is_defanged_in_the_record(tmp_path):
    """`see https://evil.example/x` in a ceiling note reads `see hxxps://evil[.]example/x`. (V-TEXT)"""
    rec = B.close_run(tmp_path, S.GAP_MEMBER,
                      S.paid("state=query-failed ref=l-002 note=see https://evil.example/x")).record

    assert [r[3] for r in B.ceiling_of(rec)] == ["see hxxps://evil[.]example/x"]


def test_v_text_the_summary_is_defanged_collapsed_and_cut_once_when_built(tmp_path):
    """URL and host text defanged, whitespace collapsed, an over-long summary cut at a word with the ellipsis inside the
    bound; the close is not refused. (V-TEXT, V-SUM)"""
    from defender.records import closing as C

    tail = " ".join(["the actor re-used the service key"] * 80)
    doc = _pieces(summary=f'"see https://evil.example/pwn and www.evil.example    for   the rest; {tail}"')

    built = B.close_run(tmp_path, "malicious", doc).record.summary

    assert built.startswith("see hxxps://evil[.]example/pwn and www[.]evil[.]example for the rest; the actor")
    assert "  " not in built
    assert len(built) <= C.SUMMARY_BOUND
    assert len(built) > C.SUMMARY_BOUND - 10
    assert built.endswith(C.ELLIPSIS)


@pytest.mark.parametrize("length", [1500, 1501])
def test_v_text_the_summary_bound_is_exact_unchanged_at_the_bound_and_cut_one_past(tmp_path, length):
    """A summary of exactly 1500 characters is kept as written; one more is cut with the ellipsis. (V-TEXT)"""
    from defender.records import closing as C

    text = B.plain(length)
    built = B.close_run(tmp_path, "malicious", _pieces(summary=f'"{text}"')).record.summary

    if length == C.SUMMARY_BOUND:
        assert built == text
    else:
        assert built.endswith(C.ELLIPSIS)
        assert len(built) <= C.SUMMARY_BOUND
        assert text.startswith(built[:-1])


# --- Bounds: the builder cuts on the forced close and never refuses ---------------------------------------------------

def test_v_text_the_forced_close_cuts_an_oversized_summary_after_the_opener_and_never_refuses(tmp_path):
    """The opener leads, the whole stays within the bound, cut at a space. (V-TEXT, V-SUM)"""
    from defender.records import closing as C

    long = " ".join(["the actor re-used the service key"] * 80)
    built = B.forced_close(tmp_path, B.forced_doc(summary=long)).record.summary

    full = f"{_opener(C.CAUSE_NOT_REVIEWED)} {long}"
    assert built.startswith(_opener(C.CAUSE_NOT_REVIEWED))
    assert built.endswith(C.ELLIPSIS)
    assert C.SUMMARY_BOUND - 10 < len(built) <= C.SUMMARY_BOUND
    assert full.startswith(built[:-1])
    assert full[len(built) - 1] == " "


def test_v_text_the_forced_close_cuts_an_oversized_note_and_keeps_the_entry(tmp_path):
    """A 900-character note is cut to the note bound with the ellipsis; the receipt stays. (V-TEXT)"""
    from defender.records import closing as C

    note = B.plain(900)
    (entry,) = B.forced_close(tmp_path, B.forced_doc(ceiling=B.capability_rows(1, lambda _i: note))).record.ceiling_test

    assert entry.cap == "fake-system-000.fake-verb"
    assert len(entry.note) <= C.NOTE_BOUND
    assert entry.note.endswith(C.ELLIPSIS)
    assert note.startswith(entry.note[:-1])


def test_v_text_the_forced_close_keeps_the_first_receipts_up_to_the_count_cap(tmp_path):
    """Twenty short receipts: the first sixteen, in order. (V-TEXT)"""
    from defender.records import closing as C

    rec = B.forced_close(tmp_path, B.forced_doc(ceiling=B.capability_rows(20, lambda i: f"n{i}"))).record

    assert [e.cap for e in rec.ceiling_test] == [f"fake-system-{i:03d}.fake-verb" for i in range(C.CEILING_COUNT_CAP)]


def test_v_text_the_forced_close_keeps_the_longest_prefix_of_receipt_lines_within_the_aggregate(tmp_path):
    """Eight 400-character receipts exceed 2048 rendered characters: a leading run stays, no longer than the bound, and
    one more would not fit. (V-TEXT)"""
    from defender.records import closing as C

    entries = B.forced_close(tmp_path, B.forced_doc(ceiling=B.capability_rows(8, lambda _i: B.plain(400)))).record.ceiling_test

    lines = [C.ceiling_line(e) for e in entries]
    assert 1 <= len(entries) < 8
    assert [e.cap for e in entries] == [f"fake-system-{i:03d}.fake-verb" for i in range(len(entries))]
    assert len("\n".join(lines)) <= C.CEILING_LINES_BOUND
    assert len("\n".join([*lines, lines[-1]])) > C.CEILING_LINES_BOUND


def test_v_text_the_forced_close_cuts_baselines_to_the_aggregate(tmp_path):
    """Forty distinct baselines: the longest leading run whose rendered lines join (separators counted) within the
    aggregate, maximal. (V-TEXT)"""
    from defender.records import closing as C

    rows = [scene.consultation_row(anchor_id=f"tk-b-{i:03d}", result="n", reasoning="r") for i in range(40)]
    rec = B.forced_close(tmp_path, scene.document(rows=scene.consult_block(*rows), settled=False)).record

    entries = rec.runtime_evidence
    lines = [C.baseline_line(e) for e in entries]
    assert [e.anchor_id for e in entries] == [f"tk-b-{i:03d}" for i in range(len(entries))]
    assert 1 <= len(entries) < 40
    assert len("\n".join(lines)) <= C.BASELINE_LINES_BOUND
    assert len("\n".join([*lines, lines[-1]])) > C.BASELINE_LINES_BOUND


_GRID = [(d, name) for d in sorted(set(DISPOSITION_VALUES) - {HOST}) for name in B.CASE_NAMES]
_IDS = [f"{d}-{name}" for d, name in _GRID]


@pytest.mark.parametrize(("disposition", "name"), _GRID, ids=_IDS)
def test_v_text_a_model_close_at_every_bound_passes_both_gates_and_stores_its_rows_treated(tmp_path, disposition, name):
    """Each bounded field, the ceiling count cap and both aggregates, at the bound, for every model disposition: the write
    gate accepts, the close commits, and the stored entries are the parsed rows treated, none cut or dropped. (V-TEXT, M3, OD16)"""
    from defender.skills.invlang.validate import validate_companion

    doc = B.case(name).at
    text = doc.build(disposition)
    assert validate_companion(text, None) == []

    rec = B.close_run(tmp_path, disposition, text).record

    if doc.ceiling:
        assert B.ceiling_of(rec) == doc.ceiling
    if doc.baselines:
        assert B.baselines_of(rec) == doc.baselines
    assert doc.ceiling or doc.baselines, "fixture control: the case expects entries"


@pytest.mark.parametrize(("disposition", "name"), _GRID, ids=_IDS)
def test_v_text_a_model_close_one_over_any_bound_is_refused_at_both_gates_naming_the_field_and_the_bound(
        tmp_path, disposition, name):
    """One over each bound, for every model disposition: the write gate and the close both refuse, naming the field or
    column and the bound's value, and no record is committed. (V-TEXT, M3, OD16)"""
    from defender.skills.invlang.validate import validate_companion

    case = B.case(name)
    text = case.over.build(disposition)

    errors = validate_companion(text, None)
    assert any(B.refusal_names(e, case.names, case.bound) for e in errors), (case.bound, errors)

    with B.opened(tmp_path, text) as (deps, run_dir, store):
        stages = S9.recording(S9.holds())
        message = S9.refusal(deps, disposition, stages)
        assert B.refusal_names(message, case.names, case.bound), (case.bound, message)
        assert V.scalar_rows(store.path, run_dir.name) == []


# --- V-ONE / V-FINAL: the write ---------------------------------------------------------------------------------------

def test_v_one_a_second_write_for_the_same_run_is_refused_and_the_close_is_not_final(tmp_path):
    """A row already stands for this run: `ClosingRecordExists`, the review record written first, the close not final,
    the standing row unchanged; a row for another run does not refuse. (V-ONE, V-FINAL)"""
    from defender.investigation import challenge_gate
    from defender.records.session_store import ClosingRecordExists

    with B.opened(tmp_path / "same", S.pays_every_price("malicious")) as (deps, run_dir, store):
        V.plant(store, V.a_record(run_dir.name, disposition="benign", summary="first"))
        before = V.scalar_rows(store.path, run_dir.name)
        with pytest.raises(ClosingRecordExists):
            S9.close_with(deps, "malicious", S9.recording(S9.holds()))
        assert not challenge_gate.ReviewState.of(deps).closed
        assert V.scalar_rows(store.path, run_dir.name) == before
        assert S9.record_files(run_dir) == [1]

    other = V.a_record("00000000-0000-4000-8000-000000000001")
    with B.opened(tmp_path / "other", S.pays_every_price("malicious")) as (deps, run_dir, store):
        V.plant(store, other)
        S9.close_with(deps, "malicious", S9.recording(S9.holds()))
        assert len(V.scalar_rows(store.path, run_dir.name)) == 1
        assert len(V.scalar_rows(store.path, other.run_id)) == 1


def test_v_final_the_write_waits_for_the_stores_lock_and_the_review_record_is_written_first(tmp_path):
    """A write lock held about two seconds then released: the close commits, its every `closing_record` statement at the
    store's ordinary busy timeout; the review record was on disk meanwhile. (V-FINAL)"""
    from defender.investigation import challenge_gate
    from defender.records.session_store import STORE_BUSY_TIMEOUT_MS

    held, seen, timeouts = threading.Event(), {}, []
    with B.opened(tmp_path, S.pays_every_price("malicious")) as (deps, run_dir, store), \
            B.second_handle(store, None, seen=timeouts) as handle:
        deps = V.with_store(deps, handle)
        def hold():
            with V.write_locked(store.path):
                held.set()
                time.sleep(LOCK_HELD_S)
                seen["review_records"] = S9.record_files(run_dir)

        holder = threading.Thread(target=hold)
        holder.start()
        assert held.wait(10)
        started = time.monotonic()
        S9.close_with(deps, "malicious", S9.recording(S9.holds()))
        waited = time.monotonic() - started
        holder.join()

        assert waited >= LOCK_HELD_S - 0.5
        assert timeouts, "fixture control: the close's write reached the observed handle"
        assert set(timeouts) == {STORE_BUSY_TIMEOUT_MS}, timeouts
        assert seen["review_records"] == [1]
        assert len(V.scalar_rows(store.path, run_dir.name)) == 1
        assert challenge_gate.ReviewState.of(deps).closed


def test_v_final_a_review_record_that_cannot_be_written_does_not_fail_the_close(tmp_path):
    """Only the closing record's fault is raised: a review record path made unwritable is logged and the close commits.
    (V-FINAL)"""
    from defender.investigation import challenge_gate
    from defender.records import RunPaths

    with B.opened(tmp_path, S.pays_every_price("malicious")) as (deps, run_dir, store):
        RunPaths(run_dir).review_record(1).mkdir()
        S9.close_with(deps, "malicious", S9.recording(S9.holds()))
        assert len(V.scalar_rows(store.path, run_dir.name)) == 1
        assert challenge_gate.ReviewState.of(deps).closed


def test_v_final_the_forced_closes_failed_write_reports_forced_close_failed(tmp_path):
    """The driver's forced close whose record write is refused: `ForcedCloseFailed`, the close not final, the standing
    row unchanged. (V-FINAL)"""
    from defender.investigation import challenge_gate

    with B.opened(tmp_path, B.DOC) as (deps, run_dir, store):
        V.plant(store, V.a_record(run_dir.name, disposition="benign", summary="first"))
        before = V.scalar_rows(store.path, run_dir.name)
        _run, _truncated, exit_reason = V.drive_forced_close(deps, store)
        assert exit_reason == "ForcedCloseFailed"
        assert not challenge_gate.ReviewState.of(deps).closed
        assert V.scalar_rows(store.path, run_dir.name) == before


@pytest.mark.parametrize("path", ["model-close", "forced-close"])
@pytest.mark.parametrize("fault", sorted(B.WRITE_FAULTS))
def test_v_final_a_write_fault_that_is_not_the_duplicate_is_raised_and_the_close_is_not_final(tmp_path, fault, path):
    """The database refuses the closing write (not `ClosingRecordExists`): the model close raises that fault, the driver's
    forced close reports `ForcedCloseFailed`; nothing final, no row. A healthy handle commits. (V-FINAL)"""
    from defender.investigation import challenge_gate

    for name, given in (("faulted", fault), ("control", None)):
        doc = B.DOC if path == "forced-close" else S.pays_every_price("malicious")
        with B.opened(tmp_path / name, doc) as (deps, run_dir, store), B.second_handle(store, given) as handle:
            if path == "forced-close":
                exit_reason = B.drive_forced_close_over(deps, store, handle)
                deps = V.with_store(deps, handle)
                assert (exit_reason == "ForcedCloseFailed") is (given is not None), (name, exit_reason)
            elif given is not None:
                deps = V.with_store(deps, handle)
                with pytest.raises(B.WRITE_FAULTS[given]):
                    S9.close_with(deps, "malicious", S9.recording(S9.holds()))
                assert S9.record_files(run_dir) == [1], "the review record is written first"
            else:
                deps = V.with_store(deps, handle)
                S9.close_with(deps, "malicious", S9.recording(S9.holds()))
            assert challenge_gate.ReviewState.of(deps).closed is (given is None), name
            assert len(V.scalar_rows(store.path, run_dir.name)) == (0 if given else 1), name


@pytest.mark.parametrize(("disposition", "forced"), [("malicious", False), (HOST, True)], ids=["reviewed", "forced"])
def test_v_final_a_close_with_no_store_on_its_deps_raises_the_wiring_fault(tmp_path, disposition, forced):
    """No `session_store` on MAIN's deps: `NoSessionStore` at entry, no review stage called, no row written, nothing
    final. (V-FINAL)"""
    from dataclasses import replace

    from defender.investigation import challenge_gate, close_tool

    deps, run_dir = V.closing_deps(tmp_path, S.pays_every_price("malicious"))
    opened = deps.session_store
    assert opened is not None, "fixture control: `main_deps` opened a store"
    stages = S9.recording(S9.holds())
    with pytest.raises(close_tool.NoSessionStore):
        S9.close_with(replace(deps, session_store=None), disposition, stages, forced=forced)
    assert stages.calls == []
    assert V.scalar_rows(opened.path, run_dir.name) == []
    assert not challenge_gate.ReviewState.of(deps).closed


def test_v_nofile_the_layout_no_longer_names_report_md():
    """`report.md` is not named by the run layout any more. (V-NOFILE)"""
    from defender.records import RUN_LAYOUT

    assert not hasattr(RUN_LAYOUT, "report")
