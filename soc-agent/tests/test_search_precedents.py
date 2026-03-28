"""Tests for the search_precedents.py script."""

import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = SOC_AGENT_ROOT / "scripts" / "search_precedents.py"


class TestSearchPrecedents:
    def test_exit_code_zero(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "wazuh-rule-5710"],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert result.returncode == 0

    def test_output_contains_header(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "wazuh-rule-5710"],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert "## Precedents for wazuh-rule-5710" in result.stdout

    def test_output_contains_hypotheses(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "wazuh-rule-5710"],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert "?monitoring-probe (confirmed)" in result.stdout
        assert "?brute-force" in result.stdout

    def test_output_contains_leads(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "wazuh-rule-5710"],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert "authentication-history" in result.stdout
        assert "source-reputation" in result.stdout

    def test_output_contains_traces(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "wazuh-rule-5710"],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert "Trace:" in result.stdout

    def test_output_contains_key_indicators(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "wazuh-rule-5710"],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert "Key indicators:" in result.stdout

    def test_missing_signature_exits_zero(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "nonexistent-signature"],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert result.returncode == 0
        assert "No precedents found" in result.stdout

    def test_no_args_exits_one(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert result.returncode == 1

    def test_path_traversal_rejected(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "../../../etc"],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert result.returncode == 1
        assert "path traversal" in result.stderr

    def test_both_precedents_present(self):
        """Both monitoring-probe and brute-force precedents should appear."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "wazuh-rule-5710"],
            capture_output=True, text=True, cwd=str(SOC_AGENT_ROOT),
        )
        assert "SEC-2024-001" in result.stdout
        assert "SEC-2024-003" in result.stdout
