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


# ---------------------------------------------------------------------------
# Enum drift guard — the local copy must track defender.learning._loop_config.
# (The test may import learning; the production write path must not.)
# ---------------------------------------------------------------------------


def test_disposition_enum_matches_loop_config():
    from defender.learning._loop_config import DISPOSITION_ENUM as canonical

    assert canonical == case_ticket.DISPOSITION_ENUM


def test_seed_eligible_outcomes_subset_of_outcome_enum():
    # The seed-eligibility polarity is keyed off the adversarial outcome enum;
    # the local copy must stay a subset of the canonical OUTCOME_ENUM.
    from defender.learning._loop_config import OUTCOME_ENUM

    assert case_ticket._SEED_ELIGIBLE_OUTCOMES <= OUTCOME_ENUM


# ---------------------------------------------------------------------------
# Offline enrichment: seed-eligibility comment round-trip + polarity (#317 read)
# ---------------------------------------------------------------------------


def _enrichment_comment(outcome: str) -> dict:
    return {"author": "learning", "body": case_ticket.enrichment_to_comment(outcome)["body"]}


@pytest.mark.parametrize(
    "outcome,eligible",
    [("caught", True), ("skip-passthrough", True),
     ("survived", False), ("undecidable", False), ("incoherent", False)],
)
def test_enrichment_roundtrip_and_polarity(outcome: str, eligible: bool):
    # The load-bearing correctness: a `survived` adversarial probe (the defender
    # MISSED the attack) must NOT mark the benign case seed-eligible.
    comments = [_enrichment_comment(outcome)]
    assert case_ticket.parse_survival_from_comments(comments) is eligible


def test_parse_survival_absent_is_none_not_false():
    assert case_ticket.parse_survival_from_comments([]) is None
    assert case_ticket.parse_survival_from_comments(None) is None


def test_parse_survival_ignores_runtime_close_comment():
    # The runtime close stamps a "Disposition: …" comment — it must never be
    # mistaken for a seed-eligibility flag (that would seed un-probed cases).
    close_comment = {"author": "defender", "body": "Disposition: benign (confidence: high)."}
    assert case_ticket.parse_survival_from_comments([close_comment]) is None


def test_parse_survival_latest_flag_wins():
    comments = [_enrichment_comment("survived"), _enrichment_comment("caught")]
    assert case_ticket.parse_survival_from_comments(comments) is True


def test_parse_survival_tolerates_malformed_comment_entries():
    assert case_ticket.parse_survival_from_comments(
        [None, {"no_body": 1}, {"body": 42}, _enrichment_comment("caught")]
    ) is True


# ---------------------------------------------------------------------------
# Thin external-ticket accessors (the boundary the seed sampler reads through)
# ---------------------------------------------------------------------------


def test_ticket_accessors():
    ticket = {
        "key": "case-7",
        "created": "2026-06-01T00:00:00+00:00",
        "labels": ["sig:5710", "evt:2026-05-30T09:00:00+00:00"],
        "resolution": "benign — nightly vuln scan",
        "comments": [_enrichment_comment("caught")],
    }
    assert case_ticket.ticket_key(ticket) == "case-7"
    assert case_ticket.ticket_created(ticket) == "2026-06-01T00:00:00+00:00"
    # The window keys on the alert event time (the `evt:` label), not `created`.
    assert case_ticket.ticket_event_time(ticket) == "2026-05-30T09:00:00+00:00"
    assert case_ticket.ticket_disposition(ticket) == "benign"
    assert case_ticket.ticket_reason(ticket) == "nightly vuln scan"
    assert case_ticket.ticket_seed_eligible(ticket) is True


def test_ticket_accessors_on_foreign_ticket():
    # A human-closed ticket (resolution not ours, no enrichment comment): the
    # decoders return None rather than mis-parsing.
    ticket = {"key": "h-1", "resolution": "Closed by analyst.", "comments": []}
    assert case_ticket.ticket_disposition(ticket) is None
    assert case_ticket.ticket_reason(ticket) is None
    assert case_ticket.ticket_seed_eligible(ticket) is None
    assert case_ticket.ticket_event_time(ticket) is None  # no labels → None
    assert case_ticket.ticket_key("not-a-dict") is None


def test_signature_label_matches_open_label():
    # The sampler filters the store by this label; it must equal the label the
    # bridge create stamps, and `evt:` must not shift which label is returned.
    label = case_ticket.signature_label(ALERT)
    assert label == "sig:5710"
    assert label in case_ticket.alert_to_open_payload(ALERT, "c")["labels"]


def test_open_payload_stamps_alert_event_time_label():
    # The event-time label round-trips through the event-time accessor — the write
    # side stamps it, the read side (sampler) decodes it.
    payload = case_ticket.alert_to_open_payload(ALERT, "c")
    assert case_ticket.alert_event_time(ALERT) == ALERT["timestamp"]
    assert case_ticket.ticket_event_time(payload) == ALERT["timestamp"]


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


# ---------------------------------------------------------------------------
# Resolution-method grounded predicates (#338) — append / decode / strip
# ---------------------------------------------------------------------------


_METHOD = "identity-confirmed (l-002) + no-egress (l-005); policy: CR-1182; authority: CISO"


def test_append_resolution_method_preserves_disposition_and_reason():
    base = "benign — nightly vuln scan"
    grounded = case_ticket.append_resolution_method(base, _METHOD)
    assert grounded.startswith("benign — nightly vuln scan ")
    # The leading {disposition} — {reason} form is intact, so the existing decoders work.
    assert case_ticket.parse_disposition_from_resolution(grounded) == "benign"
    ticket = {"key": "c", "resolution": grounded, "comments": []}
    assert case_ticket.ticket_disposition(ticket) == "benign"
    # reason strips the appended grounded segment; method decodes separately.
    assert case_ticket.ticket_reason(ticket) == "nightly vuln scan"
    assert case_ticket.ticket_resolution_method(ticket) == _METHOD


def test_append_resolution_method_idempotent():
    base = "benign — routine"
    once = case_ticket.append_resolution_method(base, _METHOD)
    twice = case_ticket.append_resolution_method(once, "different-method (l-009)")
    assert twice == once  # already grounded → no second suffix


def test_append_resolution_method_noops_on_empty_method():
    base = "benign — routine"
    assert case_ticket.append_resolution_method(base, "") == base
    assert case_ticket.append_resolution_method(base, "   ") == base


def test_append_resolution_method_collapses_internal_whitespace():
    grounded = case_ticket.append_resolution_method(
        "benign — r", "identity-confirmed (l-002)\n  + no-egress (l-005)"
    )
    assert case_ticket.resolution_method_from_resolution(grounded) == (
        "identity-confirmed (l-002) + no-egress (l-005)"
    )


def test_resolution_method_absent_or_foreign_is_none():
    # A plain (un-grounded) close resolution, a foreign one, and empties decode to None.
    assert case_ticket.resolution_method_from_resolution("benign — routine") is None
    assert case_ticket.resolution_method_from_resolution("Closed by analyst.") is None
    assert case_ticket.resolution_method_from_resolution("") is None
    assert case_ticket.resolution_method_from_resolution(None) is None
    assert case_ticket.ticket_resolution_method({"resolution": "benign — r"}) is None


def test_ticket_reason_unaffected_when_no_grounded_segment():
    ticket = {"key": "c", "resolution": "benign — nightly vuln scan", "comments": []}
    assert case_ticket.ticket_reason(ticket) == "nightly vuln scan"
    assert case_ticket.ticket_resolution_method(ticket) is None


def test_resolution_method_decodes_last_marker_not_reason_marker():
    # A free-text reason that itself contains the marker must not shadow our appended
    # segment — decode anchors on the LAST marker (our suffix), not the first.
    res = "benign — see [grounded: prior note] context [grounded: identity-confirmed (l-002)]"
    assert case_ticket.resolution_method_from_resolution(res) == "identity-confirmed (l-002)"
    # ticket_reason strips only our suffix, preserving the earlier marker in the reason.
    assert case_ticket.ticket_reason({"resolution": res}) == "see [grounded: prior note] context"


def test_marker_in_reason_without_appended_segment_is_not_decoded():
    # An analyst/LLM reason that contains the marker literal but NO trailing segment
    # terminator is incidental text — not our suffix. It must NOT be truncated, NOT be
    # mis-decoded as a grounded method, and must NOT block a real stamp (our suffix is
    # always the trailing `… ]`, so we anchor on the terminator, not the bare marker).
    res = "benign — see [grounded: prior approval] note"
    assert case_ticket.ticket_reason({"resolution": res}) == "see [grounded: prior approval] note"
    assert case_ticket.resolution_method_from_resolution(res) is None
    # A real method still stamps onto such a reason, and round-trips off the LAST marker.
    grounded = case_ticket.append_resolution_method(res, "identity-confirmed (l-002)")
    assert grounded != res
    assert case_ticket.resolution_method_from_resolution(grounded) == "identity-confirmed (l-002)"
    assert case_ticket.ticket_reason({"resolution": grounded}) == "see [grounded: prior approval] note"
