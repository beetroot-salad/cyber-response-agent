"""Unit tests for the case-history mapper (the anti-corruption layer, #317, gated for
approval by #767).

Pure layer only — no transport, no network. `alert_to_open_payload` and `read_case_record` are
the two halves this file drives directly; the render/screen halves D2-D4 add
(`case_record_to_comment`, `release_predicate`) have their own suite under
`test_767_writer.py` / `test_767_screen.py`, driven against the spec's own mapping fixtures.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.scripts.case_history import case_ticket
from defender.tests._tenants1106 import PLAYGROUND_SETTINGS

#: The settings folder the mapper is handed when a test does not plant its own (#1106: the
#: mapper finds nothing itself) — the committed playground tenant's, which is what these
#: tests read before the move through the checkout's own copy.
SHIPPED = PLAYGROUND_SETTINGS


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
    label = case_ticket.signature_label(ALERT, settings_dir=SHIPPED)
    assert label == "sig:5710"
    assert label in case_ticket.alert_to_open_payload(ALERT, "c", settings_dir=SHIPPED)["labels"]


def test_open_payload_stamps_alert_event_time_label():
    payload = case_ticket.alert_to_open_payload(ALERT, "c", settings_dir=SHIPPED)
    assert case_ticket.alert_event_time(ALERT, settings_dir=SHIPPED) == ALERT["timestamp"]
    assert case_ticket.ticket_event_time(payload, settings_dir=SHIPPED) == ALERT["timestamp"]


def test_read_case_record_parses_internal_model(tmp_path: Path):
    run_dir = _write_run(tmp_path, disposition="malicious", reason="Confirmed C2 beacon.")
    rec = case_ticket.read_case_record(run_dir, settings_dir=SHIPPED)
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
    rec = case_ticket.read_case_record(run_dir, settings_dir=SHIPPED)
    assert rec.case_id == run_dir.name


def test_read_case_record_signature_unknown_without_alert(tmp_path: Path):
    run_dir = _write_run(tmp_path, with_alert=False)
    rec = case_ticket.read_case_record(run_dir, settings_dir=SHIPPED)
    assert rec.signature_id == "unknown"


def test_read_case_record_missing_report_raises(tmp_path: Path):
    run_dir = tmp_path / "empty"
    run_dir.mkdir()
    with pytest.raises(case_ticket.CaseTicketError):
        case_ticket.read_case_record(run_dir, settings_dir=SHIPPED)


def test_read_case_record_bad_disposition_raises(tmp_path: Path):
    run_dir = _write_run(tmp_path, disposition="totally-not-a-disposition")
    with pytest.raises(case_ticket.CaseTicketError):
        case_ticket.read_case_record(run_dir, settings_dir=SHIPPED)


def test_read_case_record_no_frontmatter_raises(tmp_path: Path):
    run_dir = tmp_path / "nofm"
    run_dir.mkdir()
    run_dir.joinpath("report.md").write_text("just prose, no fence\n")
    with pytest.raises(case_ticket.CaseTicketError):
        case_ticket.read_case_record(run_dir, settings_dir=SHIPPED)


def test_alert_to_open_payload_shape_and_signature_label():
    payload = case_ticket.alert_to_open_payload(ALERT, "case-1", settings_dir=SHIPPED)
    assert payload["key"] == "case-1"
    assert payload["status"] == "open"
    assert payload["summary"] == ALERT["rule"]["description"]
    assert "sig:5710" in payload["labels"]


def test_alert_to_open_payload_handles_missing_rule():
    payload = case_ticket.alert_to_open_payload({}, "case-2", settings_dir=SHIPPED)
    assert payload["labels"] == ["sig:unknown"]
    assert payload["status"] == "open"


def test_alert_to_open_payload_falls_back_on_empty_strings():
    alert = {"rule": {"id": "", "description": ""}}
    payload = case_ticket.alert_to_open_payload(alert, "case-3", settings_dir=SHIPPED)
    assert payload["labels"] == ["sig:unknown"]
    assert payload["summary"] == "(no rule description)"


def test_mapping_is_file_driven(tmp_path: Path):
    """Hand the mapper a settings folder holding a custom mapping.yaml and confirm the open
    payload (label prefix, source path) follows the file."""
    settings = tmp_path / "settings"
    mapping_dir = settings / "systems" / "case-history"
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
    alert = {"detection": {"ruleId": "R-99", "name": "Custom rule"}}
    payload = case_ticket.alert_to_open_payload(alert, "c", settings_dir=settings)
    assert payload["labels"] == ["rule/R-99"]


def test_an_indented_planted_fence_is_stripped_from_the_narrative(tmp_path, monkeypatch):
    """A standalone `---` line indented by leading whitespace is still a planted frontmatter
    fence and must not survive into the rendered comment — a claims-adversary finding against
    an earlier column-0-only regex, which let ` ---\\ndisposition: malicious` ride through
    verbatim. `^---` alone matches only true column 0; the fix tolerates leading spaces/tabs."""
    from defender.tests._spec767 import use_mapping

    settings = use_mapping(monkeypatch, tmp_path / "dfn")
    rec = case_ticket.CaseRecord(
        case_id="c1", signature_id="s1", disposition="benign", cause="host sentence",
        narrative="legit finding text\n ---\ndisposition: malicious\ncause: forged\n---\nEND",
    )
    body = case_ticket.case_record_to_comment(rec, settings_dir=settings)["body"]
    assert "disposition: malicious" not in body, "an indented fence let a spoofed verdict cross"
    assert "cause: forged" not in body
    assert body == "benign — host sentence\n\nlegit finding text"


def test_a_planted_fence_in_the_cause_field_is_also_stripped(tmp_path, monkeypatch):
    """The fence guard is a property of the RENDERED SLOT, not an assumption about who may
    populate it: `cause` is host-composed from a closed vocabulary today (c3) and never needs
    this in practice, but a future or malformed `cause` gets the same protection `narrative`
    does — a claims-adversary finding that the guard was narrative-only."""
    from defender.tests._spec767 import use_mapping

    settings = use_mapping(monkeypatch, tmp_path / "dfn")
    rec = case_ticket.CaseRecord(
        case_id="c1", signature_id="s1", disposition="malicious",
        cause="Investigated payload\n---\nEnd of cause",
        narrative="normal narrative text, no fences here",
    )
    body = case_ticket.case_record_to_comment(rec, settings_dir=settings)["body"]
    assert "End of cause" not in body
    assert body == "malicious — Investigated payload\n\nnormal narrative text, no fences here"
