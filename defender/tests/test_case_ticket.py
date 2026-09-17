"""Unit tests for the case-history mapper (the anti-corruption layer, #317, gated for
approval by #767).

Pure layer only — no transport, no network. `alert_to_open_payload` and `read_case_record` are
the two halves this file drives directly; the render/screen halves D2-D4 add
(`case_record_to_comment`, `approval_predicates`) have their own suite under
`test_767_writer.py` / `test_767_screen.py`, driven against the spec's own mapping fixtures.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.scripts.case_history import case_ticket


ALERT = {
    "rule": {"id": "5710", "description": "sshd: Attempt to login using a non-existent user"},
    "agent": {"name": "target-endpoint"},
    "timestamp": "2026-05-07T07:15:01.561+0000",
}


def _write_run(tmp_path: Path, *, disposition: str = "benign", reason: str = "Routine.",
               confidence: str = "high", with_alert: bool = True) -> Path:
    run_dir = tmp_path / "20260620T000000Z-sshd"
    run_dir.mkdir()
    run_dir.joinpath("report.md").write_text(
        f"---\ncase_id: {run_dir.name}\ndisposition: {disposition}\n"
        f"confidence: {confidence}\n---\n{reason}\n"
    )
    if with_alert:
        run_dir.joinpath("alert.json").write_text(json.dumps(ALERT))
    return run_dir


def test_signature_label_matches_open_label():
    label = case_ticket.signature_label(ALERT)
    assert label == "sig:5710"
    assert label in case_ticket.alert_to_open_payload(ALERT, "c")["labels"]


def test_open_payload_stamps_alert_event_time_label():
    payload = case_ticket.alert_to_open_payload(ALERT, "c")
    assert case_ticket.alert_event_time(ALERT) == ALERT["timestamp"]
    assert case_ticket.ticket_event_time(payload) == ALERT["timestamp"]


def test_read_case_record_parses_internal_model(tmp_path: Path):
    run_dir = _write_run(tmp_path, disposition="malicious", reason="Confirmed C2 beacon.")
    rec = case_ticket.read_case_record(run_dir)
    assert rec.case_id == run_dir.name
    assert rec.signature_id == "5710"
    assert rec.disposition == "malicious"
    # #767 D3: no `cause:` line in this fixture's frontmatter, so `cause` is empty and
    # `narrative` is the report's own body, verbatim — `read_case_record` applies no
    # fence-strip or bound (those are `case_record_to_comment`'s, at render time).
    assert rec.cause == ""
    assert rec.narrative == "Confirmed C2 beacon."


def test_read_case_record_case_id_is_run_dir_not_frontmatter(tmp_path: Path):
    run_dir = tmp_path / "20260620T000000Z-sshd"
    run_dir.mkdir()
    run_dir.joinpath("report.md").write_text(
        "---\ncase_id: SOMETHING-ELSE\ndisposition: benign\n"
        "confidence: high\n---\nRoutine.\n"
    )
    rec = case_ticket.read_case_record(run_dir)
    assert rec.case_id == run_dir.name


def test_read_case_record_signature_unknown_without_alert(tmp_path: Path):
    run_dir = _write_run(tmp_path, with_alert=False)
    rec = case_ticket.read_case_record(run_dir)
    assert rec.signature_id == "unknown"


def test_read_case_record_missing_report_raises(tmp_path: Path):
    run_dir = tmp_path / "empty"
    run_dir.mkdir()
    with pytest.raises(case_ticket.CaseTicketError):
        case_ticket.read_case_record(run_dir)


def test_read_case_record_bad_disposition_raises(tmp_path: Path):
    run_dir = _write_run(tmp_path, disposition="totally-not-a-disposition")
    with pytest.raises(case_ticket.CaseTicketError):
        case_ticket.read_case_record(run_dir)


def test_read_case_record_no_frontmatter_raises(tmp_path: Path):
    run_dir = tmp_path / "nofm"
    run_dir.mkdir()
    run_dir.joinpath("report.md").write_text("just prose, no fence\n")
    with pytest.raises(case_ticket.CaseTicketError):
        case_ticket.read_case_record(run_dir)


def test_alert_to_open_payload_shape_and_signature_label():
    payload = case_ticket.alert_to_open_payload(ALERT, "case-1")
    assert payload["key"] == "case-1"
    assert payload["status"] == "open"
    assert payload["summary"] == ALERT["rule"]["description"]
    assert "sig:5710" in payload["labels"]


def test_alert_to_open_payload_handles_missing_rule():
    payload = case_ticket.alert_to_open_payload({}, "case-2")
    assert payload["labels"] == ["sig:unknown"]
    assert payload["status"] == "open"


def test_alert_to_open_payload_falls_back_on_empty_strings():
    alert = {"rule": {"id": "", "description": ""}}
    payload = case_ticket.alert_to_open_payload(alert, "case-3")
    assert payload["labels"] == ["sig:unknown"]
    assert payload["summary"] == "(no rule description)"


def test_mapping_is_file_driven(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point $DEFENDER_DIR at a tree with a custom mapping.yaml and confirm the open payload
    (label prefix, source path) follows the file."""
    mapping_dir = tmp_path / "knowledge" / "environment" / "systems" / "case-history"
    mapping_dir.mkdir(parents=True)
    (mapping_dir / "mapping.yaml").write_text(
        "source:\n"
        "  signature: detection.ruleId\n"
        "  summary: detection.name\n"
        "open:\n"
        "  key: '{case_id}'\n"
        "  status: open\n"
        "  labels: ['rule/{signature}']\n"
    )
    monkeypatch.setenv("DEFENDER_DIR", str(tmp_path))

    alert = {"detection": {"ruleId": "R-99", "name": "Custom rule"}}
    payload = case_ticket.alert_to_open_payload(alert, "c")
    assert payload["labels"] == ["rule/R-99"]
