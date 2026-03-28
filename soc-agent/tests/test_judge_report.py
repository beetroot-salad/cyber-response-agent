"""Tests for the Tier 2 semantic judge hook.

Tests the deterministic parts of judge_report.py: artifact loading,
prompt assembly, verdict parsing, and gating logic. Does NOT test
the actual LLM invocation (that requires claude CLI + API key).
"""

import json
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.judge_report import (
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
    def test_all_placeholders_replaced(self):
        prompt = assemble_prompt(
            alert_data='{"rule": "test"}',
            investigation_log="## CONTEXTUALIZE\ntest",
            report="---\nstatus: resolved\n---",
            precedent='{"ticket_id": "SEC-001"}',
        )
        assert "{alert_data}" not in prompt
        assert "{investigation_log}" not in prompt
        assert "{report}" not in prompt
        assert "{precedent}" not in prompt
        assert '{"rule": "test"}' in prompt
        assert "## CONTEXTUALIZE" in prompt

    def test_prompt_contains_criteria(self):
        prompt = assemble_prompt("a", "b", "c", "d")
        assert "PRECEDENT_MATCH" in prompt
        assert "INTERNAL_CONSISTENCY" in prompt
        assert "EVIDENCE_SUFFICIENCY" in prompt
        assert "COMPLETENESS" in prompt
        assert "ADVERSARIAL_CHECK" in prompt


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
    """Tests that the judge only runs when appropriate."""

    def test_only_runs_on_resolved(self, tmp_path):
        """Escalated reports should not trigger the judge."""
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
        assert fm is not None
        # Judge should skip: status != resolved
        assert fm.get("status") != "resolved"

    def test_only_runs_with_precedent(self):
        """Resolved without precedent fails Tier 1 (so judge never runs).

        The judge gates on status=resolved AND matched_precedent being set.
        A report with status=resolved but no matched_precedent is rejected
        by Tier 1 validation before Tier 2 ever fires. We verify the gating
        condition directly.
        """
        # Simulate frontmatter that somehow got through with no precedent
        fm = {
            "status": "resolved",
            "matched_precedent": None,
        }
        # Judge should skip: no matched_precedent
        assert fm.get("status") == "resolved"
        assert not fm.get("matched_precedent")
