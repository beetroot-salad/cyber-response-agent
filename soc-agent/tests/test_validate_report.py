"""Tests for report frontmatter validation.

Tests the validate_report.py hook logic and report_frontmatter schema.
"""

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
    parse_yaml_frontmatter,
    validate,
)

FIXTURES = SOC_AGENT_ROOT / "tests" / "fixtures" / "reports"


# --- YAML frontmatter parsing ---


class TestParseYamlFrontmatter:
    def test_valid_frontmatter(self):
        text = """---
ticket_id: SEC-001
status: resolved
leads_pursued: 3
---
# Body"""
        fields = parse_yaml_frontmatter(text)
        assert fields["ticket_id"] == "SEC-001"
        assert fields["status"] == "resolved"
        assert fields["leads_pursued"] == 3

    def test_null_values(self):
        text = """---
matched_precedent: null
other: ~
empty:
---"""
        fields = parse_yaml_frontmatter(text)
        assert fields["matched_precedent"] is None
        assert fields["other"] is None
        assert fields["empty"] is None

    def test_quoted_values(self):
        text = """---
trace: "a -> b -> c"
name: 'single quoted'
---"""
        fields = parse_yaml_frontmatter(text)
        assert fields["trace"] == "a -> b -> c"
        assert fields["name"] == "single quoted"

    def test_no_frontmatter(self):
        assert parse_yaml_frontmatter("# Just a heading") == {}

    def test_empty_string(self):
        assert parse_yaml_frontmatter("") == {}


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
        assert len(errors) >= 4  # missing signature_id, status, disposition, confidence, leads_pursued

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


# --- Full validation with fixtures ---


class TestValidateFixtures:
    def test_valid_resolved_report(self):
        passed, errors = validate(FIXTURES / "valid_resolved.md")
        assert passed, f"Expected valid but got errors: {errors}"

    def test_valid_escalate_report(self):
        passed, errors = validate(FIXTURES / "valid_escalate.md")
        assert passed, f"Expected valid but got errors: {errors}"

    def test_invalid_missing_fields(self):
        passed, errors = validate(FIXTURES / "invalid_missing_fields.md")
        assert not passed
        assert any("missing required field" in e for e in errors)

    def test_invalid_no_precedent(self):
        passed, errors = validate(FIXTURES / "invalid_no_precedent.md")
        assert not passed
        assert any("not found" in e for e in errors)

    def test_invalid_low_leads(self):
        passed, errors = validate(FIXTURES / "invalid_low_leads.md")
        assert not passed
        assert any("leads_pursued" in e for e in errors)

    def test_invalid_bad_enums(self):
        passed, errors = validate(FIXTURES / "invalid_bad_enums.md")
        assert not passed
        assert any("status" in e for e in errors)


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
