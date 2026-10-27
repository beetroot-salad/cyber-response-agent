"""The baseline consultation's carrier into report.md through the close fields."""

from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import dataclasses
import datetime as dt
import json

from defender._frontmatter import split_frontmatter
from defender.investigation import close_tool
from defender.tests.support.shared.contracts import _tacit983 as scene
from defender.tests.support.tenancy._tenants1106 import fixture_run_tenant

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


def _body(report: str) -> str:
    """The report's BODY — everything past the frontmatter, read through the shared splitter
    rather than by counting `---` fences (`lint-frontmatter`)."""
    _fm, _raw, body = split_frontmatter(report)
    return body


def test_runtime_evidence_receipt_carries_the_rows_parsed_fields():
    """A receipt is a TYPED record of one `:R consultations` row — the owning lead, the anchor"""
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
        "the window's END is not parsed — it is the endpoint mechanism A's guard compares "
        "against the alerted event, and a receipt that never parsed it cannot have been "
        "produced by a check that did"
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


def test_runtime_evidence_consultation_lands_in_report_body():
    """A close projects every qualifying `:R consultations` row into `report.md`'s BODY — one"""
    receipts = _receipts(BENIGN_DOC)
    assert len(receipts) == 1, "fixture control: the document carries one qualifying consultation"
    (receipt,) = receipts

    report = close_tool.render_report(
        "benign", outcome=close_tool.STANDS, cause=close_tool.CAUSE_STORY_SETTLED,
        runtime_evidence=receipts,
    )
    _fm, frontmatter, body = split_frontmatter(report)

    assert body.count("runtime-evidence") == len(receipts), (
        "not one body line per receipt — a close with two baselines would render one of them"
    )
    for field in (receipt.window, receipt.anchor_id, receipt.resolved_by_lead):
        assert field in body, f"{field!r} was parsed into the receipt and never rendered"
    assert "1500 occurrences over 30d" in body, (
        "the occurrence count did not reach the body — `result` is the only place the design "
        "leaves for it, since `:R consultations` gains no columns"
    )

    assert "runtime-evidence" not in (frontmatter or ""), (
        "the baseline reached the FRONTMATTER — that block is under a 512-byte cap and a size "
        "cap on ungated model text is itself a gate; the note lane is the body"
    )

    without = close_tool.render_report(
        "benign", outcome=close_tool.STANDS, cause=close_tool.CAUSE_STORY_SETTLED,
    )
    assert "runtime-evidence" not in without, (
        "a close with no baseline rendered one — the default has to be the empty tuple"
    )


def test_baseline_context_now_reaches_the_recorded_comment(tmp_path):
    from defender.tenancy import case_ticket

    receipts = _receipts(BENIGN_DOC)
    report = close_tool.render_report(
        "benign", outcome=close_tool.STANDS, cause=close_tool.CAUSE_STORY_SETTLED,
        runtime_evidence=receipts,
    )
    assert "1500 occurrences" in _body(report), "fixture control: the body carries the baseline"
    run_dir = tmp_path / fixture_uuid("case-983")
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_text(
        json.dumps({"rule": {"id": "5710", "key": "spec.rule"},
                    "timestamp": "2026-05-05T03:42:11Z"}),
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text(report, encoding="utf-8")
    (run_dir / "investigation.md").write_text(BENIGN_DOC, encoding="utf-8")

    payload = case_ticket.case_record_to_comment(
        case_ticket.read_case_record(_run_handle_1165(run_dir), mapping=fixture_run_tenant().ticket_mapping),
        mapping=fixture_run_tenant().ticket_mapping)
    wire = json.dumps(payload, sort_keys=True)
    for crossed in ("runtime-evidence", "1500 occurrences", scene.WINDOW_BEFORE_ALERT):
        assert crossed in wire, (
            f"{crossed!r} did not reach the outbound comment — #767 D3 carries the whole "
            f"report body into it now, deliberately, gated by D4's approval screen on the "
            f"read side rather than by anything withheld on the write side"
        )



def test_the_projection_and_the_render_read_one_set():
    """Whatever `conclude_runtime_evidence_rows` hands back is what `render_report` writes —"""
    doc = scene.document(
        rows=scene.consult_block(
            scene.consultation_row(),
            scene.consultation_row(
                anchor_id=ANCHOR_90D, result=RESULT_90D, window=WINDOW_90D),
        ),
        settled=False,
    )
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

    body = _body(close_tool.render_report(
        "inconclusive", outcome=close_tool.STANDS, cause=close_tool.CAUSE_NOT_REVIEWED,
        runtime_evidence=receipts,
    ))
    assert body.count("runtime-evidence") == 2
    for receipt in receipts:
        assert receipt.anchor_id in body, (
            f"{receipt.anchor_id} was dropped on the way into the body"
        )
        assert receipt.window in body, (
            f"{receipt.anchor_id}'s window was dropped, or replaced by its sibling's"
        )
    assert "4100 occurrences over 90d" in body, "the second baseline's count never rendered"


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
