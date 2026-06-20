"""Unit tests for the case-history mapper (the anti-corruption layer, #317).

Pure layer only — no transport, no network. The mapper's round-trip
(CaseRecord → close payload → parse_disposition) is the executable spec of the
de-facto schema the read PR will rely on.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.scripts.case_history import case_ticket


ALERT = {
    "rule": {"id": "5710", "description": "sshd: Attempt to login using a non-existent user"},
    "agent": {"name": "target-endpoint"},
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


# ---------------------------------------------------------------------------
# Enum drift guard — the local copy must track defender.learning._loop_config.
# (The test may import learning; the production write path must not.)
# ---------------------------------------------------------------------------


def test_disposition_enum_matches_loop_config():
    from defender.learning._loop_config import DISPOSITION_ENUM as canonical

    assert case_ticket.DISPOSITION_ENUM == canonical


# ---------------------------------------------------------------------------
# read_case_record
# ---------------------------------------------------------------------------


def test_read_case_record_parses_internal_model(tmp_path: Path):
    run_dir = _write_run(tmp_path, disposition="malicious", reason="Confirmed C2 beacon.")
    rec = case_ticket.read_case_record(run_dir)
    assert rec.case_id == run_dir.name
    assert rec.signature_id == "5710"
    assert rec.disposition == "malicious"
    assert rec.confidence == "high"
    assert rec.reason == "Confirmed C2 beacon."


def test_read_case_record_case_id_is_run_dir_not_frontmatter(tmp_path: Path):
    # open_case_ticket keys the create on run_dir.name (the only id it has at
    # materialize time); close must target that same key. A report.md whose
    # `case_id:` frontmatter diverges must NOT be honored, or the close would
    # transition a key that was never created (404, ticket left open).
    run_dir = tmp_path / "20260620T000000Z-sshd"
    run_dir.mkdir()
    run_dir.joinpath("report.md").write_text(
        "---\ncase_id: SOMETHING-ELSE\ndisposition: benign\n"
        "confidence: high\n---\nRoutine.\n"
    )
    rec = case_ticket.read_case_record(run_dir)
    assert rec.case_id == run_dir.name  # not "SOMETHING-ELSE"


def test_read_case_record_signature_unknown_without_alert(tmp_path: Path):
    run_dir = _write_run(tmp_path, with_alert=False)
    rec = case_ticket.read_case_record(run_dir)
    assert rec.signature_id == "unknown"  # non-fatal: disposition still records


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


# ---------------------------------------------------------------------------
# Mapper: open payload
# ---------------------------------------------------------------------------


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
    # A present-but-empty rule.id / rule.description is as useless as a missing
    # one — the fallbacks must still apply (not a blank summary / "sig:" label).
    alert = {"rule": {"id": "", "description": ""}}
    payload = case_ticket.alert_to_open_payload(alert, "case-3")
    assert payload["labels"] == ["sig:unknown"]
    assert payload["summary"] == "(no rule description)"


# ---------------------------------------------------------------------------
# Mapper: close payload + round-trip (the de-facto schema contract)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("disposition", sorted(case_ticket.DISPOSITION_ENUM))
def test_close_roundtrip_recovers_disposition(disposition: str):
    rec = case_ticket.CaseRecord(
        case_id="c", signature_id="5710", disposition=disposition,
        confidence="medium", reason="Some reason — with an em dash inside.",
    )
    close = case_ticket.case_record_to_close(rec)
    assert close["status"] == "closed"
    assert close["resolution"].startswith(disposition)
    recovered = case_ticket.parse_disposition_from_resolution(close["resolution"])
    assert recovered == disposition


def test_parse_disposition_ignores_foreign_resolution():
    # A human-edited / non-ours resolution must not be mistaken for a disposition.
    assert case_ticket.parse_disposition_from_resolution("Closed by analyst.") is None
    assert case_ticket.parse_disposition_from_resolution("") is None
    assert case_ticket.parse_disposition_from_resolution(None) is None


def test_end_to_end_read_then_map(tmp_path: Path):
    run_dir = _write_run(tmp_path, disposition="benign", reason="Authorized deploy.")
    rec = case_ticket.read_case_record(run_dir)
    close = case_ticket.case_record_to_close(rec)
    assert case_ticket.parse_disposition_from_resolution(close["resolution"]) == "benign"
    assert "Authorized deploy." in close["resolution"]


# ---------------------------------------------------------------------------
# The mapping is file-driven — changing the convention needs no code change.
# ---------------------------------------------------------------------------


def test_mapping_is_file_driven(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point $DEFENDER_DIR at a tree with a custom mapping.yaml and confirm the
    output (label prefix, resolution separator, source path) follows the file."""
    mapping_dir = tmp_path / "knowledge" / "environment" / "systems" / "case-history"
    mapping_dir.mkdir(parents=True)
    (mapping_dir / "mapping.yaml").write_text(
        "source:\n"
        "  signature: detection.ruleId\n"          # different source path
        "  summary: detection.name\n"
        "open:\n"
        "  key: '{case_id}'\n"
        "  status: open\n"
        "  labels: ['rule/{signature}']\n"          # different label convention
        "close:\n"
        "  status: closed\n"
        "  resolution: '{disposition} :: {reason}'\n"  # different separator
    )
    monkeypatch.setenv("DEFENDER_DIR", str(tmp_path))

    alert = {"detection": {"ruleId": "R-99", "name": "Custom rule"}}
    payload = case_ticket.alert_to_open_payload(alert, "c")
    assert payload["labels"] == ["rule/R-99"]  # honored custom source path + label

    rec = case_ticket.CaseRecord("c", "R-99", "malicious", "low", "why")
    close = case_ticket.case_record_to_close(rec)
    assert close["resolution"] == "malicious :: why"
    # decode tracks the custom separator from the same file
    assert case_ticket.parse_disposition_from_resolution(close["resolution"]) == "malicious"
