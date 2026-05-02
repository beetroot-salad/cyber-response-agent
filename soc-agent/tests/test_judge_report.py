"""Tests for the post-report Tier 2 semantic judge (validate_report.py).

The slimmed Tier 2 judge only validates the report↔log delta plus
precedent transfer. Shape/completeness/anchor-leg checks moved to the
pre-REPORT judges (see test_validate_report_precheck.py).

Tests the deterministic parts: prompt assembly, verdict parsing,
precedent loading, and gating logic. Does NOT test LLM invocation
(requires claude CLI).
"""

import json
import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.judge_runner import parse_verdict
from hooks.scripts.validate_report import (
    assemble_prompt,
    load_precedent,
    load_report_frontmatter,
    read_file_safe,
)


# --- Verdict parsing (parse_verdict moved to judge_runner) ---


class TestParseVerdict:
    def test_pass_verdict(self):
        output = textwrap.dedent("""\
            INTERNAL_CONSISTENCY: PASS — report follows from log
            EVIDENCE_SUFFICIENCY: PASS — strong evidence
            PRECEDENT_TRANSFER: PASS — precedent transfers
            VERDICT: PASS — all criteria satisfied
        """)
        verdict, reason = parse_verdict(output)
        assert verdict == "PASS"
        assert "all criteria" in reason

    def test_flag_verdict(self):
        output = textwrap.dedent("""\
            INTERNAL_CONSISTENCY: PASS — ok
            EVIDENCE_SUFFICIENCY: PASS — ok
            PRECEDENT_TRANSFER: FLAG — entity class differs
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
            INTERNAL_CONSISTENCY: PASS — ok
            VERDICT: FLAG — missing evidence
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

    def test_escalation_mode(self):
        prompt = assemble_prompt(
            alert_data="alert",
            investigation_log="log",
            report="report",
            precedent=None,
            salt="abc123",
            status="escalated",
        )
        assert "escalation" in prompt

    def test_full_mode_default(self):
        prompt = assemble_prompt(
            alert_data="alert",
            investigation_log="log",
            report="report",
            precedent='{"ticket_id": "SEC-001"}',
            salt="abc123",
        )
        assert "Mode: **full**" in prompt

    def test_prompt_contains_slimmed_criteria(self):
        prompt = assemble_prompt("a", "b", "c", "d", "salt")
        assert "INTERNAL_CONSISTENCY" in prompt
        assert "EVIDENCE_SUFFICIENCY" in prompt
        assert "PRECEDENT_TRANSFER" in prompt

    def test_prompt_excludes_pre_conclude_criteria(self):
        """Shape/completeness/anchor-leg moved to pre-REPORT judges."""
        prompt = assemble_prompt("a", "b", "c", "d", "salt")
        assert "SHAPE_MATCH" not in prompt
        assert "COMPLETENESS" not in prompt
        assert "GROUNDING_MATCH" not in prompt
        assert "LEGITIMACY_CHECK" not in prompt

    def test_untrusted_content_is_salted(self):
        prompt = assemble_prompt("alert", "log", "report", "prec", "mysalt")
        assert "<run-mysalt-alert-data>" in prompt
        assert "</run-mysalt-alert-data>" in prompt
        assert "<run-mysalt-investigation-log>" in prompt
        assert "</run-mysalt-investigation-log>" in prompt

    def test_report_is_not_salted(self):
        """Report is agent-generated, not untrusted external data."""
        prompt = assemble_prompt(
            "alert", "log", "report_content", "prec", "mysalt"
        )
        assert "run-mysalt-report" not in prompt
        assert "report_content" in prompt

    def test_precedent_is_salted(self):
        """Precedent data is wrapped in salted delimiters (defense-in-depth)."""
        prompt = assemble_prompt(
            "alert", "log", "report", "prec_data", "mysalt"
        )
        assert "<run-mysalt-precedent>" in prompt
        assert "</run-mysalt-precedent>" in prompt
        assert "prec_data" in prompt

    def test_no_precedent_placeholder_message(self):
        prompt = assemble_prompt(
            "alert", "log", "report", None, "mysalt"
        )
        assert "PRECEDENT_TRANSFER is N/A" in prompt


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
            matched_archetype: monitoring-probe
            matched_ticket_id: SEC-2024-001
            trust_anchors_consulted:
              - anchor: approved-monitoring-sources
                kind: org-authority
                result: confirmed
                citation: playground
            leads_pursued: 3
            ---
            # Report
        """))
        fm = load_report_frontmatter(report)
        assert fm is not None
        assert fm["status"] == "resolved"
        assert fm["matched_archetype"] == "monitoring-probe"
        assert fm["matched_ticket_id"] == "SEC-2024-001"

    def test_invalid_report(self, tmp_path):
        report = tmp_path / "report.md"
        report.write_text("no frontmatter here")
        fm = load_report_frontmatter(report)
        assert fm is None


# --- Precedent loading ---


@pytest.fixture
def fake_root(tmp_path, monkeypatch):
    """Redirect SOC_AGENT_ROOT to a temp dir and restore after test."""
    import hooks.scripts.validate_report as vr
    monkeypatch.setattr(vr, "SOC_AGENT_ROOT", tmp_path)
    return tmp_path


def _write_precedent(
    root: Path, sig: str, archetype: str, ticket_id: str, data: dict
) -> Path:
    arch_dir = root / "knowledge" / "signatures" / sig / "archetypes" / archetype
    arch_dir.mkdir(parents=True, exist_ok=True)
    path = arch_dir / f"{ticket_id}.json"
    path.write_text(json.dumps(data))
    return path


class TestLoadPrecedent:
    def test_load_existing_precedent(self, fake_root):
        _write_precedent(
            fake_root, "test-sig", "test-arch", "SEC-001",
            {"ticket_id": "SEC-001", "archetype": "test-arch"},
        )
        data = load_precedent("test-sig", "test-arch", "SEC-001")
        assert data is not None
        assert data["ticket_id"] == "SEC-001"

    def test_load_without_extension(self, fake_root):
        _write_precedent(
            fake_root, "test-sig", "test-arch", "SEC-001",
            {"ticket_id": "SEC-001", "archetype": "test-arch"},
        )
        data = load_precedent("test-sig", "test-arch", "SEC-001")
        assert data is not None

    def test_load_nonexistent(self, fake_root):
        data = load_precedent("test-sig", "test-arch", "nonexistent")
        assert data is None

    def test_load_nonexistent_signature(self, fake_root):
        data = load_precedent("fake-signature", "arch", "SEC-001")
        assert data is None

    def test_load_empty_archetype_returns_none(self, fake_root):
        data = load_precedent("test-sig", "", "SEC-001")
        assert data is None


# --- Gating logic ---


class TestJudgeGating:
    def test_resolved_with_archetype_and_ticket(self, tmp_path):
        report = tmp_path / "report.md"
        report.write_text(textwrap.dedent("""\
            ---
            ticket_id: SEC-001
            signature_id: wazuh-rule-5710
            status: resolved
            disposition: benign
            confidence: high
            matched_archetype: monitoring-probe
            matched_ticket_id: SEC-2024-001
            trust_anchors_consulted:
              - anchor: approved-monitoring-sources
                kind: org-authority
                result: confirmed
                citation: playground
            leads_pursued: 3
            ---
        """))
        fm = load_report_frontmatter(report)
        assert fm is not None
        assert fm.get("status") == "resolved"
        assert fm.get("matched_archetype") == "monitoring-probe"
        assert fm.get("matched_ticket_id") == "SEC-2024-001"

    def test_escalated_has_no_archetype(self, tmp_path):
        report = tmp_path / "report.md"
        report.write_text(textwrap.dedent("""\
            ---
            ticket_id: SEC-001
            signature_id: wazuh-rule-5710
            status: escalated
            disposition: unclear
            confidence: low
            leads_pursued: 2
            ---
        """))
        fm = load_report_frontmatter(report)
        assert fm is not None
        assert fm.get("status") == "escalated"
        assert fm.get("matched_archetype") is None

    def test_escalation_mode_prompt(self):
        prompt = assemble_prompt(
            "alert", "log", "report", None, "salt",
            status="escalated",
        )
        assert "Mode: **escalation**" in prompt
