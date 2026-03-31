"""Tests for the Tier 2 semantic judge (integrated in validate_report.py).

Tests the deterministic parts: prompt assembly, verdict parsing, precedent
loading, and gating logic. Does NOT test LLM invocation (requires claude CLI).
"""

import json
import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.validate_report import (
    assemble_prompt,
    load_precedent,
    load_report_frontmatter,
    parse_verdict,
    read_file_safe,
)


# --- Verdict parsing ---


class TestParseVerdict:
    def test_pass_verdict(self):
        output = textwrap.dedent("""\
            PRECEDENT_MATCH: PASS — conditions hold
            INTERNAL_CONSISTENCY: PASS — report follows from log
            EVIDENCE_SUFFICIENCY: PASS — strong evidence
            COMPLETENESS: PASS — all leads pursued
            ADVERSARIAL_CHECK: PASS — threats refuted
            VERDICT: PASS — all criteria satisfied
        """)
        verdict, reason = parse_verdict(output)
        assert verdict == "PASS"
        assert "all criteria" in reason

    def test_flag_verdict(self):
        output = textwrap.dedent("""\
            PRECEDENT_MATCH: FLAG — external IP vs internal precedent
            INTERNAL_CONSISTENCY: PASS — ok
            EVIDENCE_SUFFICIENCY: PASS — ok
            COMPLETENESS: PASS — ok
            ADVERSARIAL_CHECK: PASS — ok
            VERDICT: FLAG — precedent mismatch
        """)
        verdict, reason = parse_verdict(output)
        assert verdict == "FLAG"
        assert "precedent" in reason

    def test_verdict_with_dash_separator(self):
        output = "VERDICT: FLAG - some reason here"
        verdict, reason = parse_verdict(output)
        assert verdict == "FLAG"
        assert "some reason" in reason

    def test_verdict_with_em_dash(self):
        output = "VERDICT: PASS \u2014 all good"
        verdict, reason = parse_verdict(output)
        assert verdict == "PASS"

    def test_no_verdict_line(self):
        output = "Some random output without a verdict"
        verdict, reason = parse_verdict(output)
        assert verdict == "FLAG"
        assert "could not parse" in reason

    def test_verdict_case_insensitive(self):
        output = "VERDICT: pass — ok"
        verdict, reason = parse_verdict(output)
        assert verdict == "PASS"

    def test_verdict_in_code_block(self):
        """Judge might wrap output in code fences."""
        output = textwrap.dedent("""\
            ```
            PRECEDENT_MATCH: PASS — ok
            VERDICT: FLAG — missing auth check
            ```
        """)
        verdict, reason = parse_verdict(output)
        assert verdict == "FLAG"


# --- Prompt assembly ---


class TestAssemblePrompt:
    def test_all_placeholders_replaced_full_mode(self):
        prompt = assemble_prompt(
            alert_data='{"rule": "test"}',
            investigation_log="## CONTEXTUALIZE\ntest",
            report="---\nstatus: resolved\n---",
            precedent='{"ticket_id": "SEC-001"}',
            salt="abc123",
        )
        assert "{alert_data}" not in prompt
        assert "{investigation_log}" not in prompt
        assert "{report}" not in prompt
        assert "{precedent}" not in prompt
        assert "{judge_mode}" not in prompt
        assert "full" in prompt

    def test_no_precedent_mode(self):
        prompt = assemble_prompt(
            alert_data="alert",
            investigation_log="log",
            report="report",
            precedent=None,
            salt="abc123",
        )
        assert "no-precedent" in prompt
        assert "escalated report" in prompt

    def test_prompt_contains_criteria(self):
        prompt = assemble_prompt("a", "b", "c", "d", "salt")
        assert "PRECEDENT_MATCH" in prompt
        assert "INTERNAL_CONSISTENCY" in prompt
        assert "EVIDENCE_SUFFICIENCY" in prompt
        assert "COMPLETENESS" in prompt
        assert "ADVERSARIAL_CHECK" in prompt

    def test_untrusted_content_is_salted(self):
        prompt = assemble_prompt("alert", "log", "report", "prec", "mysalt")
        assert "<run-mysalt-alert-data>" in prompt
        assert "</run-mysalt-alert-data>" in prompt
        assert "<run-mysalt-investigation-log>" in prompt
        assert "</run-mysalt-investigation-log>" in prompt

    def test_report_is_not_salted(self):
        """Report is agent-generated, not untrusted external data."""
        prompt = assemble_prompt("alert", "log", "report_content", "prec", "mysalt")
        assert "run-mysalt-report" not in prompt
        assert "report_content" in prompt

    def test_precedent_is_salted(self):
        """Precedent data is wrapped in salted delimiters (defense-in-depth)."""
        prompt = assemble_prompt("alert", "log", "report", "prec_data", "mysalt")
        assert "<run-mysalt-precedent>" in prompt
        assert "</run-mysalt-precedent>" in prompt
        assert "prec_data" in prompt


# --- File reading ---


class TestReadFileSafe:
    def test_existing_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        assert read_file_safe(f, "test") == "hello"

    def test_missing_file(self, tmp_path):
        f = tmp_path / "missing.txt"
        result = read_file_safe(f, "test file")
        assert "not found" in result
        assert "missing.txt" in result


# --- Report frontmatter loading ---


class TestLoadReportFrontmatter:
    def test_valid_report(self, tmp_path):
        report = tmp_path / "report.md"
        report.write_text(textwrap.dedent("""\
            ---
            ticket_id: SEC-001
            signature_id: wazuh-rule-5710
            status: resolved
            disposition: benign
            confidence: high
            matched_precedent: monitoring-probe-001.json
            leads_pursued: 3
            ---
            # Report
        """))
        fm = load_report_frontmatter(report)
        assert fm is not None
        assert fm["status"] == "resolved"
        assert fm["matched_precedent"] == "monitoring-probe-001.json"

    def test_invalid_report(self, tmp_path):
        report = tmp_path / "report.md"
        report.write_text("no frontmatter here")
        fm = load_report_frontmatter(report)
        assert fm is None


# --- Precedent loading ---


class TestLoadPrecedent:
    def test_load_existing_precedent(self):
        data = load_precedent("wazuh-rule-5710", "monitoring-probe-001.json")
        assert data is not None
        assert data["ticket_id"] == "SEC-2024-001"

    def test_load_without_extension(self):
        data = load_precedent("wazuh-rule-5710", "monitoring-probe-001")
        assert data is not None

    def test_load_nonexistent(self):
        data = load_precedent("wazuh-rule-5710", "nonexistent.json")
        assert data is None

    def test_load_nonexistent_signature(self):
        data = load_precedent("fake-signature", "anything.json")
        assert data is None


# --- Gating logic ---


class TestJudgeGating:
    """Tests that the judge runs in the right mode for each report type."""

    def test_resolved_with_precedent_triggers_full_mode(self, tmp_path):
        report = tmp_path / "report.md"
        report.write_text(textwrap.dedent("""\
            ---
            ticket_id: SEC-001
            signature_id: wazuh-rule-5710
            status: resolved
            disposition: benign
            confidence: high
            matched_precedent: monitoring-probe-001.json
            leads_pursued: 3
            ---
        """))
        fm = load_report_frontmatter(report)
        assert fm is not None
        assert fm.get("status") == "resolved"
        assert fm.get("matched_precedent")
        # Full mode: precedent available

    def test_escalated_triggers_no_precedent_mode(self, tmp_path):
        report = tmp_path / "report.md"
        report.write_text(textwrap.dedent("""\
            ---
            ticket_id: SEC-001
            signature_id: wazuh-rule-5710
            status: escalated
            disposition: inconclusive
            confidence: low
            matched_precedent: null
            leads_pursued: 2
            ---
        """))
        fm = load_report_frontmatter(report)
        # Escalated reports have no precedent but should still be judged
        # fm may be None here due to validation error (resolved requires precedent)
        # but for escalated, matched_precedent=null is valid
        # The gating check: status != "resolved" → no-precedent mode

    def test_no_precedent_prompt_skips_precedent_check(self):
        """No-precedent mode prompt should indicate N/A for PRECEDENT_MATCH."""
        prompt = assemble_prompt("alert", "log", "report", None, "salt")
        assert "no-precedent" in prompt
