"""Tests for report validation (Tier 1 + Tier 2 hook architecture).

Tests the validate_report.py hook: PostToolUse event parsing, run directory
extraction, Tier 1 deterministic validation, and Tier 2 helper functions.
"""

import json
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.enums import VALID_CONFIDENCES, VALID_DISPOSITIONS, VALID_STATUSES
from schemas.report_frontmatter import (
    ReportFrontmatter,
    parse_frontmatter,
)
from hooks.scripts.validate_report import (
    check_precedent_exists,
    extract_run_dir,
    get_run_salt,
    is_screen_resolved,
    playbook_has_screen_section,
    validate_precedent_content,
    validate_tier1,
    wrap_untrusted,
)
from schemas.precedent import check_recency, parse_validated_at

FIXTURES = SOC_AGENT_ROOT / "tests" / "fixtures" / "reports"


# --- ReportFrontmatter validation ---


class TestReportFrontmatter:
    def _make_valid(self, **overrides):
        defaults = dict(
            ticket_id="SEC-001",
            signature_id="wazuh-rule-5710",
            status="escalated",
            disposition="true_positive",
            confidence="high",
            matched_precedent=None,
            leads_pursued=3,
        )
        defaults.update(overrides)
        return ReportFrontmatter(**defaults)

    def test_valid_escalate(self):
        r = self._make_valid()
        assert r.validate() == []

    def test_valid_resolved(self):
        r = self._make_valid(
            status="resolved",
            disposition="benign",
            matched_precedent="monitoring-probe-001.json",
        )
        assert r.validate() == []

    def test_missing_ticket_id(self):
        r = self._make_valid(ticket_id="")
        errors = r.validate()
        assert any("ticket_id" in e for e in errors)

    def test_invalid_status(self):
        r = self._make_valid(status="closed")
        errors = r.validate()
        assert any("status" in e for e in errors)

    def test_invalid_disposition(self):
        r = self._make_valid(disposition="malware")
        errors = r.validate()
        assert any("disposition" in e for e in errors)

    def test_invalid_confidence(self):
        r = self._make_valid(confidence="very_high")
        errors = r.validate()
        assert any("confidence" in e for e in errors)

    def test_resolved_requires_precedent(self):
        r = self._make_valid(status="resolved", matched_precedent=None)
        errors = r.validate()
        assert any("matched_precedent" in e for e in errors)

    def test_negative_leads(self):
        r = self._make_valid(leads_pursued=-1)
        errors = r.validate()
        assert any("leads_pursued" in e for e in errors)


# --- parse_frontmatter ---


class TestParseFrontmatter:
    def test_missing_required_fields(self):
        report, errors = parse_frontmatter({"ticket_id": "SEC-001"})
        assert report is None
        assert len(errors) >= 4

    def test_valid_dict(self):
        fields = {
            "ticket_id": "SEC-001",
            "signature_id": "wazuh-rule-5710",
            "status": "escalated",
            "disposition": "true_positive",
            "confidence": "high",
            "matched_precedent": None,
            "leads_pursued": 3,
        }
        report, errors = parse_frontmatter(fields)
        assert errors == []
        assert report.ticket_id == "SEC-001"

    def test_coerces_leads_to_int(self):
        fields = {
            "ticket_id": "SEC-001",
            "signature_id": "wazuh-rule-5710",
            "status": "escalated",
            "disposition": "true_positive",
            "confidence": "high",
            "matched_precedent": None,
            "leads_pursued": "3",
        }
        report, errors = parse_frontmatter(fields)
        assert errors == []
        assert report.leads_pursued == 3


# --- Tier 1 validation with fixtures ---


class TestValidateFixtures:
    def test_valid_resolved_report(self):
        passed, errors, _ = validate_tier1(FIXTURES / "valid_resolved.md")
        assert passed, f"Expected valid but got errors: {errors}"

    def test_valid_escalate_report(self):
        passed, errors, _ = validate_tier1(FIXTURES / "valid_escalate.md")
        assert passed, f"Expected valid but got errors: {errors}"

    def test_invalid_missing_fields(self):
        passed, errors, _ = validate_tier1(FIXTURES / "invalid_missing_fields.md")
        assert not passed
        assert any("missing required field" in e for e in errors)

    def test_invalid_no_precedent(self):
        passed, errors, _ = validate_tier1(FIXTURES / "invalid_no_precedent.md")
        assert not passed
        assert any("not found" in e for e in errors)

    def test_invalid_low_leads(self):
        passed, errors, _ = validate_tier1(FIXTURES / "invalid_low_leads.md")
        assert not passed
        assert any("leads_pursued" in e for e in errors)

    def test_invalid_bad_enums(self):
        passed, errors, _ = validate_tier1(FIXTURES / "invalid_bad_enums.md")
        assert not passed
        assert any("status" in e for e in errors)


# --- Screen-resolved validation ---


class TestScreenResolved:
    """Test that screen-resolved reports are exempt from MIN_LEADS_BY_SEVERITY."""

    SCREEN_REPORT = """\
---
ticket_id: SEC-SCREEN-001
signature_id: wazuh-rule-5710
status: resolved
disposition: benign
confidence: high
matched_precedent: monitoring-probe-001.json
leads_pursued: 1
trace: "screen(monitoring-probe, auth-history) -> benign:monitoring-probe"
---

# Investigation Report: SEC-SCREEN-001

## Summary
Screen-resolved monitoring probe.
"""

    def _setup_screen_run(self, tmp_path, history):
        """Create a run dir with state.json and report.md."""
        run_dir = tmp_path / "run-screen"
        run_dir.mkdir()
        state = {"phase": history[-1], "history": history}
        (run_dir / "state.json").write_text(json.dumps(state))
        (run_dir / "report.md").write_text(self.SCREEN_REPORT)
        return run_dir

    def test_screen_resolved_skips_leads_check(self, tmp_path):
        """Screen-resolved report with 1 lead passes (medium severity needs 2)."""
        run_dir = self._setup_screen_run(
            tmp_path, ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]
        )
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert passed, f"Expected pass but got: {errors}"

    def test_non_screen_still_checks_leads(self, tmp_path):
        """Non-screen report with 1 lead fails for medium severity."""
        run_dir = tmp_path / "run-full"
        run_dir.mkdir()
        state = {
            "phase": "CONCLUDE",
            "history": ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"],
        }
        (run_dir / "state.json").write_text(json.dumps(state))
        (run_dir / "report.md").write_text(self.SCREEN_REPORT)
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert not passed
        assert any("leads_pursued" in e for e in errors)

    def test_screen_resolved_requires_screen_section(self, tmp_path):
        """Screen-resolved report fails if playbook has no ## Screen section."""
        report_text = self.SCREEN_REPORT.replace(
            "wazuh-rule-5710", "nonexistent-sig"
        )
        run_dir = tmp_path / "run-no-playbook"
        run_dir.mkdir()
        state = {"phase": "CONCLUDE", "history": ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]}
        (run_dir / "state.json").write_text(json.dumps(state))
        (run_dir / "report.md").write_text(report_text)
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert not passed
        assert any("Screen section" in e for e in errors)

    def test_is_screen_resolved_no_state(self, tmp_path):
        """No state.json means not screen-resolved."""
        assert is_screen_resolved(tmp_path) is False

    def test_is_screen_resolved_with_hypothesize(self, tmp_path):
        """SCREEN in history but also HYPOTHESIZE means fallthrough, not screen-resolved."""
        state = {
            "history": ["CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        }
        (tmp_path / "state.json").write_text(json.dumps(state))
        assert is_screen_resolved(tmp_path) is False

    def test_playbook_has_screen_section_true(self):
        assert playbook_has_screen_section("wazuh-rule-5710") is True

    def test_playbook_has_screen_section_nonexistent(self):
        assert playbook_has_screen_section("nonexistent-sig") is False


# --- Precedent existence check ---


# --- Precedent content validation ---


class TestValidatePrecedentContent:
    def test_matching_signature_and_recent(self):
        """Valid precedent with matching signature_id and recent validated_at."""
        errors = validate_precedent_content(
            "monitoring-probe-001.json", "wazuh-rule-5710"
        )
        assert errors == []

    def test_signature_id_mismatch(self, tmp_path):
        """Precedent with wrong signature_id is rejected."""
        prec_dir = tmp_path / "knowledge" / "signatures" / "test-sig" / "precedents"
        prec_dir.mkdir(parents=True)
        prec = {
            "signature_id": "WRONG-SIG",
            "validated_at": "2026-04-01",
        }
        (prec_dir / "test.json").write_text(json.dumps(prec))
        # Monkeypatch SOC_AGENT_ROOT
        import hooks.scripts.validate_report as vr
        orig = vr.SOC_AGENT_ROOT
        vr.SOC_AGENT_ROOT = tmp_path
        try:
            errors = validate_precedent_content("test.json", "test-sig")
            assert any("does not match" in e for e in errors)
        finally:
            vr.SOC_AGENT_ROOT = orig

    def test_missing_validated_at(self, tmp_path):
        """Precedent without validated_at is flagged."""
        prec_dir = tmp_path / "knowledge" / "signatures" / "test-sig" / "precedents"
        prec_dir.mkdir(parents=True)
        prec = {"signature_id": "test-sig"}
        (prec_dir / "test.json").write_text(json.dumps(prec))
        import hooks.scripts.validate_report as vr
        orig = vr.SOC_AGENT_ROOT
        vr.SOC_AGENT_ROOT = tmp_path
        try:
            errors = validate_precedent_content("test.json", "test-sig")
            assert any("validated_at" in e for e in errors)
        finally:
            vr.SOC_AGENT_ROOT = orig

    def test_stale_precedent(self, tmp_path):
        """Precedent older than max_age is rejected."""
        prec_dir = tmp_path / "knowledge" / "signatures" / "test-sig" / "precedents"
        prec_dir.mkdir(parents=True)
        prec = {
            "signature_id": "test-sig",
            "validated_at": "2020-01-01",
        }
        (prec_dir / "test.json").write_text(json.dumps(prec))
        import hooks.scripts.validate_report as vr
        orig = vr.SOC_AGENT_ROOT
        vr.SOC_AGENT_ROOT = tmp_path
        try:
            errors = validate_precedent_content("test.json", "test-sig")
            assert any("days old" in e for e in errors)
        finally:
            vr.SOC_AGENT_ROOT = orig

    def test_malformed_json(self, tmp_path):
        """Malformed precedent JSON is caught."""
        prec_dir = tmp_path / "knowledge" / "signatures" / "test-sig" / "precedents"
        prec_dir.mkdir(parents=True)
        (prec_dir / "test.json").write_text("not json {{{")
        import hooks.scripts.validate_report as vr
        orig = vr.SOC_AGENT_ROOT
        vr.SOC_AGENT_ROOT = tmp_path
        try:
            errors = validate_precedent_content("test.json", "test-sig")
            assert any("not valid JSON" in e for e in errors)
        finally:
            vr.SOC_AGENT_ROOT = orig


class TestPrecedentRecency:
    def test_fresh_precedent(self):
        fresh, msg = check_recency("2026-04-01", max_age_days=90)
        assert fresh
        assert msg == ""

    def test_stale_precedent(self):
        fresh, msg = check_recency("2020-01-01", max_age_days=90)
        assert not fresh
        assert "days old" in msg

    def test_iso_datetime_format(self):
        fresh, _ = check_recency("2026-04-01T00:00:00Z", max_age_days=90)
        assert fresh

    def test_invalid_format(self):
        fresh, msg = check_recency("not-a-date")
        assert not fresh
        assert "invalid date format" in msg

    def test_parse_validated_at_date(self):
        dt = parse_validated_at("2026-03-15")
        assert dt.year == 2026
        assert dt.month == 3

    def test_parse_validated_at_datetime(self):
        dt = parse_validated_at("2026-03-15T10:30:00Z")
        assert dt.hour == 10


# --- Precedent existence check ---


class TestCheckPrecedentExists:
    def test_existing_precedent(self):
        assert check_precedent_exists(
            "monitoring-probe-001.json", "wazuh-rule-5710"
        ) is True

    def test_nonexistent_precedent(self):
        assert check_precedent_exists("does-not-exist.json", "wazuh-rule-5710") is False

    def test_nonexistent_signature(self):
        assert check_precedent_exists("anything.json", "nonexistent-sig") is False


# --- PostToolUse event parsing ---


class TestExtractRunDir:
    def test_report_write_in_runs(self, tmp_path, monkeypatch):
        """Write to runs/{id}/report.md extracts the run dir."""
        runs = tmp_path / "runs"
        run_dir = runs / "abc-123"
        run_dir.mkdir(parents=True)
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs))

        hook_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": str(run_dir / "report.md")},
        }
        result = extract_run_dir(hook_data)
        assert result == run_dir

    def test_non_report_file_ignored(self, tmp_path, monkeypatch):
        """Write to a non-report file returns None."""
        runs = tmp_path / "runs"
        run_dir = runs / "abc-123"
        run_dir.mkdir(parents=True)
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs))

        hook_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": str(run_dir / "investigation.md")},
        }
        assert extract_run_dir(hook_data) is None

    def test_file_outside_runs_ignored(self, tmp_path, monkeypatch):
        """Write to report.md outside runs/ returns None."""
        runs = tmp_path / "runs"
        runs.mkdir(parents=True)
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs))

        hook_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/other/report.md"},
        }
        assert extract_run_dir(hook_data) is None

    def test_missing_file_path(self):
        """No file_path in tool_input returns None."""
        hook_data = {"tool_name": "Write", "tool_input": {}}
        assert extract_run_dir(hook_data) is None

    def test_edit_tool_also_works(self, tmp_path, monkeypatch):
        """Edit tool events are also handled."""
        runs = tmp_path / "runs"
        run_dir = runs / "abc-123"
        run_dir.mkdir(parents=True)
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs))

        hook_data = {
            "tool_name": "Edit",
            "tool_input": {"file_path": str(run_dir / "report.md")},
        }
        result = extract_run_dir(hook_data)
        assert result == run_dir


# --- Salt handling ---


class TestRunSalt:
    def test_reads_salt_from_meta(self, tmp_path):
        """Salt is read from meta.json when present."""
        meta = {"run_id": "test", "salt": "abc123"}
        (tmp_path / "meta.json").write_text(json.dumps(meta))
        assert get_run_salt(tmp_path) == "abc123"

    def test_fallback_when_no_meta(self, tmp_path):
        """Generates a fallback salt when meta.json doesn't exist."""
        salt = get_run_salt(tmp_path)
        assert len(salt) == 16  # secrets.token_hex(8) = 16 chars

    def test_fallback_when_meta_corrupt(self, tmp_path):
        """Generates a fallback salt when meta.json is invalid."""
        (tmp_path / "meta.json").write_text("not json")
        salt = get_run_salt(tmp_path)
        assert len(salt) == 16


class TestWrapUntrusted:
    def test_wraps_with_salted_tags(self):
        result = wrap_untrusted("hello", "alert-data", "abc123")
        assert result == "<run-abc123-alert-data>\nhello\n</run-abc123-alert-data>"

    def test_different_salts_produce_different_tags(self):
        a = wrap_untrusted("x", "data", "salt1")
        b = wrap_untrusted("x", "data", "salt2")
        assert a != b
        assert "salt1" in a
        assert "salt2" in b
