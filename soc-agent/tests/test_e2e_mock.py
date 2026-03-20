"""End-to-end integration tests with mock SIEM.

These tests validate the full investigation pipeline structure
without requiring a live LLM or SIEM. They test that:
- Investigation artifacts have the expected structure
- State transitions are valid
- Reports pass validation

Marked with @pytest.mark.llm for selective execution.
When LLM tests are enabled, these use the actual investigator agent.
Without LLM, they test the structural contracts with synthetic data.
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from config.schemas.state import Phase, validate_transition
from config.schemas.report_frontmatter import parse_frontmatter
from hooks.scripts.validate_report import parse_yaml_frontmatter, validate


FIXTURES = SOC_AGENT_ROOT / "tests" / "fixtures"


class TestInvestigationArtifacts:
    """Test that investigation output files have the right structure."""

    def test_valid_report_passes_validation(self):
        """A well-formed report.md passes the validate_report hook."""
        report_path = FIXTURES / "reports" / "valid_resolved.md"
        passed, errors = validate(report_path)
        assert passed, f"Valid report failed validation: {errors}"

    def test_escalation_report_passes_validation(self):
        report_path = FIXTURES / "reports" / "valid_escalate.md"
        passed, errors = validate(report_path)
        assert passed, f"Escalation report failed validation: {errors}"

    def test_report_frontmatter_has_required_fields(self):
        """Report frontmatter must contain all required fields."""
        report_path = FIXTURES / "reports" / "valid_resolved.md"
        content = report_path.read_text()
        fields = parse_yaml_frontmatter(content)

        required = ["ticket_id", "signature_id", "status", "disposition",
                     "confidence", "matched_precedent", "leads_pursued"]
        for field in required:
            assert field in fields, f"Missing field: {field}"


class TestStateTransitionContract:
    """Test that the state machine contract works for full investigations."""

    def test_minimal_investigation_sequence(self):
        """C -> H -> G -> A -> CONCLUDE is a valid minimal investigation."""
        phases = ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"{current} -> {phase}: {error}"
            current = phase

    def test_two_loop_investigation(self):
        """Two hypothesis-gather-analyze loops before concluding."""
        phases = [
            "CONTEXTUALIZE",
            "HYPOTHESIZE", "GATHER", "ANALYZE",
            "HYPOTHESIZE", "GATHER", "ANALYZE",
            "CONCLUDE",
        ]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"{current} -> {phase}: {error}"
            current = phase

    def test_cannot_skip_gather(self):
        """Cannot go from HYPOTHESIZE directly to ANALYZE."""
        valid, _ = validate_transition("HYPOTHESIZE", "ANALYZE")
        assert not valid

    def test_cannot_skip_hypothesize(self):
        """Cannot go from CONTEXTUALIZE directly to GATHER."""
        valid, _ = validate_transition("CONTEXTUALIZE", "GATHER")
        assert not valid


class TestMockSiemResponses:
    """Test that fixture SIEM responses are well-formed."""

    def test_monitoring_probe_fixture_structure(self):
        data = json.loads(
            (FIXTURES / "siem_responses" / "wazuh-5710-monitoring-probe.json").read_text()
        )
        assert "queries" in data
        assert "failed_logins_5min" in data["queries"]
        assert "successful_logins_60s" in data["queries"]

        failed = data["queries"]["failed_logins_5min"]["response"]
        assert failed["total"] == 1
        assert failed["hits"][0]["data"]["srcuser"] == "testuser"

    def test_brute_force_fixture_structure(self):
        data = json.loads(
            (FIXTURES / "siem_responses" / "wazuh-5710-brute-force.json").read_text()
        )
        assert "queries" in data

        failed = data["queries"]["failed_logins_5min"]["response"]
        assert failed["total"] == 47

    def test_monitoring_probe_no_successful_login(self):
        data = json.loads(
            (FIXTURES / "siem_responses" / "wazuh-5710-monitoring-probe.json").read_text()
        )
        success = data["queries"]["successful_logins_60s"]["response"]
        assert success["total"] == 0

    def test_brute_force_no_successful_login(self):
        data = json.loads(
            (FIXTURES / "siem_responses" / "wazuh-5710-brute-force.json").read_text()
        )
        success = data["queries"]["successful_logins_60s"]["response"]
        assert success["total"] == 0


class TestAlertFixtures:
    """Test that alert fixtures are well-formed."""

    @pytest.mark.parametrize(
        "alert_file",
        list(FIXTURES.glob("alerts/*.json")),
        ids=lambda f: f.name,
    )
    def test_alert_has_required_fields(self, alert_file):
        data = json.loads(alert_file.read_text())
        assert "ticket_id" in data
        assert "signature_id" in data

    @pytest.mark.parametrize(
        "alert_file",
        list(FIXTURES.glob("alerts/*.json")),
        ids=lambda f: f.name,
    )
    def test_alert_has_alert_data(self, alert_file):
        data = json.loads(alert_file.read_text())
        assert "alert_data" in data
        assert "rule_id" in data["alert_data"]


class TestWriteStateIntegration:
    """Test write_state.py script produces valid state.json."""

    def test_full_sequence_via_script(self, tmp_path):
        import subprocess

        script = SOC_AGENT_ROOT / "hooks" / "scripts" / "write_state.py"
        run_dir = tmp_path / "run-test"
        run_dir.mkdir()

        phases = ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        for phase in phases:
            result = subprocess.run(
                [sys.executable, str(script), str(run_dir), phase, "TEST-001", "wazuh-rule-5710"],
                capture_output=True, text=True,
            )
            assert result.returncode == 0, f"Phase {phase} failed: {result.stderr}"

        state = json.loads((run_dir / "state.json").read_text())
        assert state["phase"] == "CONCLUDE"
        assert state["history"] == phases
        assert state["ticket_id"] == "TEST-001"
        assert state["signature_id"] == "wazuh-rule-5710"


@pytest.mark.llm
class TestLLMIntegration:
    """Tests requiring LLM execution. Run with: pytest -m llm

    These tests are skipped by default. They invoke the actual
    investigator agent and validate the output structure.
    """

    def test_placeholder(self):
        """Placeholder — real LLM tests require agent invocation infrastructure."""
        pytest.skip("LLM integration tests not yet wired to agent runner")
