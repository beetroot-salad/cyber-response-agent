"""The baseline consultation's carrier into the closing record through the close fields (#1534)."""

from __future__ import annotations


import dataclasses
import datetime as dt
import json

from defender.investigation import close_tool
from defender.tests.support.shared.contracts import _tacit983 as scene
from defender.tests.support.runtime.engine._spec767 import posted_comment_body

WINDOW_90D = "2026-02-04T00:00:00Z/2026-05-04T00:00:00Z"
ANCHOR_90D = "tk-baseline-90d"
RESULT_90D = "4100 occurrences over 90d; actor uid-0 and host build-runner-07.prod throughout"


def _utc(text: str) -> dt.datetime:
    """The moment an ISO-8601 `Z` timestamp names, as an aware UTC `datetime`."""
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def _receipts(text: str):
    """The baseline receipts a companion carries."""
    from defender.skills.invlang.parser import parse_dense_companion
    from defender.skills.invlang.validate._gating import conclude_runtime_evidence_rows

    return conclude_runtime_evidence_rows(parse_dense_companion(text)[0])

BENIGN_DOC = scene.benign_document(rows=scene.authorized_rows(baseline=True))


def test_runtime_evidence_receipt_carries_the_rows_parsed_fields():
    """A receipt is a frozen, typed record of one `:R consultations` row: lead, anchor, result,
    reasoning, and the window both verbatim and parsed, so the guard and the report read one value."""
    (receipt,) = _receipts(BENIGN_DOC)

    assert dataclasses.is_dataclass(receipt)
    assert type(receipt).__dataclass_params__.frozen, (
        "the receipt is mutable — it crosses the projection, the close and the render"
    )

    assert receipt.resolved_by_lead == scene.LEAD, (
        "the receipt does not say which lead measured the baseline, so the report's reader "
        "cannot get from the claim back to the retrieval"
    )
    assert receipt.anchor_kind == "runtime-evidence"
    assert receipt.grounding_kind == "telemetry-baseline"
    assert receipt.anchor_id == "tk-baseline-30d"
    assert "1500 occurrences over 30d" in receipt.result, (
        "the occurrence count did not survive into the receipt"
    )
    assert "build-runner-07.prod" in receipt.result, "the scope did not survive into the receipt"
    assert "no adverse outcome" in receipt.reasoning

    assert receipt.window == scene.WINDOW_BEFORE_ALERT, (
        "the window cell is not carried verbatim — the report shows the analyst what the row "
        "said, not a re-rendering of it"
    )
    assert receipt.window_start == _utc("2026-04-04T00:00:00Z")
    assert receipt.window_end == _utc("2026-05-04T00:00:00Z"), (
        "the window's end is not parsed, though the guard compares it against the alerted event"
    )


def test_runtime_evidence_rows_project_off_the_consultation_bucket():
    """`conclude_runtime_evidence_rows` selects the `:R consultations` rows whose `anchor_kind` is `runtime-evidence`, in document order, and nothing else."""
    receipts = _receipts(BENIGN_DOC)
    assert [r.anchor_id for r in receipts] == ["tk-baseline-30d"], (
        "the lead's own `tacit-knowledge` lookup record was projected as a baseline — the "
        "selection is on the bucket, not on the anchor kind"
    )

    other_kind = scene.document(
        contract_anchor_kind="iam-policy", system="identity",
        rows=scene.consult_block(scene.consultation_row(
            anchor_kind="change-mgmt", grounding="org-authority")),
    )
    assert _receipts(other_kind) == (), (
        "a consultation under another anchor kind was projected as a baseline"
    )

    no_baseline = scene.document(rows=scene.authorized_rows())
    assert [r.anchor_id for r in _receipts(no_baseline)] == [], (
        "a `:R authz` row reached the baseline channel — the projection is not selecting on "
        "the consultation bucket"
    )


def _closed(tmp_path, disposition, companion):
    """The real close of `companion` (a composer that holds) and its closing record, read back through the lookup."""
    from defender.tests.storage.verdict_1534 import _close_b as B

    return B.close_run(tmp_path, disposition, companion)


def _line_of(entry) -> str:
    from defender.records import closing as C

    return C.baseline_line(entry)


def test_runtime_evidence_consultation_lands_in_the_closing_record(tmp_path):
    """A close stores one baseline entry per qualifying `:R consultations` row, each rendered to one line carrying its
    window, anchor, lead and count; a close with no baseline stores none (the whole-close half is `e2e/test_tacit_authz_e2e.py`)."""
    receipts = _receipts(BENIGN_DOC)
    assert len(receipts) == 1, "fixture control: the document carries one qualifying consultation"
    (receipt,) = receipts

    closed = _closed(tmp_path / "with", "benign", BENIGN_DOC)
    (entry,) = closed.record.runtime_evidence
    line = _line_of(entry)
    assert line.count("runtime-evidence") == 1
    assert (_utc(entry.window_start), _utc(entry.window_end)) == (receipt.window_start, receipt.window_end)
    for field in (scene.WINDOW_BEFORE_ALERT, receipt.anchor_id, receipt.resolved_by_lead):
        assert field in line, f"{field!r} was parsed into the receipt and never rendered"
    assert "1500 occurrences over 30d" in line, (
        "the occurrence count did not reach the line — `result` is the only place the design "
        "leaves for it, since `:R consultations` gains no columns"
    )

    without = _closed(tmp_path / "without", "benign", scene.benign_document(rows=scene.authorized_rows()))
    assert without.record.runtime_evidence == (), (
        "a close with no baseline stored one — the default has to be the empty tuple"
    )


def test_baseline_context_now_reaches_the_recorded_comment(tmp_path):
    """The closing record's baseline line reaches the record leg's posted comment. (#1359, OD15)"""
    closed = _closed(tmp_path / "close", "benign", BENIGN_DOC)
    assert "1500 occurrences" in _line_of(closed.record.runtime_evidence[0]), "fixture control: the record carries the baseline"
    (closed.run_dir / "alert.json").write_text(
        json.dumps({"rule": {"id": "5710", "key": "spec.rule"},
                    "timestamp": "2026-05-05T03:42:11Z"}),
        encoding="utf-8",
    )

    # #1359: observed at the record leg's posted comment (below the agent tag line).
    wire = posted_comment_body(closed.run_dir, tmp_path)
    for crossed in ("runtime-evidence", "1500 occurrences", scene.WINDOW_BEFORE_ALERT):
        assert crossed in wire, (
            f"{crossed!r} did not reach the outbound comment, which carries the record's baseline lines"
        )


def test_the_projection_and_the_record_read_one_set(tmp_path):
    """What `conclude_runtime_evidence_rows` hands back is what the close stores: two rows
    differing in every cell expose a collapsed, duplicated or canned entry."""
    from defender.tests.storage.verdict_1534 import _close_b as B

    rows = [scene.consultation_row(), scene.consultation_row(anchor_id=ANCHOR_90D, result=RESULT_90D, window=WINDOW_90D)]
    doc = scene.document(rows=scene.consult_block(*rows), settled=False)
    receipts = _receipts(doc)
    assert len(receipts) == 2, "fixture control: two qualifying consultations"

    first, second = receipts
    assert (first.anchor_id, first.window) == ("tk-baseline-30d", scene.WINDOW_BEFORE_ALERT)
    assert (second.anchor_id, second.window) == (ANCHOR_90D, WINDOW_90D), (
        "the second row's own cells did not reach its receipt — the projection is not parsing "
        "per row"
    )
    assert second.window_start == _utc("2026-02-04T00:00:00Z")
    assert first.window_start != second.window_start, (
        "both receipts carry one window — a canned value, not two parses"
    )

    closed = _closed(tmp_path, "malicious", B.baseline_document("malicious", rows))
    entries = closed.record.runtime_evidence
    assert [e.anchor_id for e in entries] == [r.anchor_id for r in receipts], "an entry was dropped or reordered"
    for entry, receipt in zip(entries, receipts, strict=True):
        assert (_utc(entry.window_start), _utc(entry.window_end)) == (receipt.window_start, receipt.window_end), (
            f"{receipt.anchor_id}'s window was dropped, or replaced by its sibling's"
        )
        assert receipt.window in _line_of(entry)
    assert "4100 occurrences over 90d" in _line_of(entries[1]), "the second baseline's count never stored"


def test_close_fields_carries_the_baseline_on_every_disposition():
    """`_CloseFields` carries the baseline as a companion-derived field alongside `ceiling_test`, and it defaults empty."""
    fields = {f.name: f for f in dataclasses.fields(close_tool._CloseFields)}
    assert "runtime_evidence" in fields, (
        "`_CloseFields` has no baseline field — the projection has no way onto either close path"
    )
    assert fields["runtime_evidence"].default == (), (
        "the baseline field is not defaulted empty — every existing construction site would "
        "have to name it, and a close with no baseline has none to name"
    )
