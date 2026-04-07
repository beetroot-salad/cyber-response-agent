"""End-to-end integration tests with mock SIEM.

Two test tiers:
1. Structural tests (no LLM) — validate artifacts, state machine, fixture well-formedness
2. LLM integration tests (@pytest.mark.llm) — invoke the investigate skill via claude CLI
   and validate the output structure

Run structural tests: pytest soc-agent/tests/test_e2e_mock.py -v
Run LLM tests:        pytest soc-agent/tests/test_e2e_mock.py -v -m llm
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

sys.path.insert(0, str(Path(__file__).resolve().parent))

from schemas.state import Phase, validate_transition
from schemas.report_frontmatter import parse_frontmatter
from hooks.scripts.validate_report import parse_yaml_frontmatter, validate_tier1
from conftest import FIXTURES, run_investigation_mock


# ---------------------------------------------------------------------------
# Structural tests (no LLM required)
# ---------------------------------------------------------------------------


class TestInvestigationArtifacts:
    """Test that investigation output files have the right structure."""

    def test_valid_report_passes_validation(self):
        """A well-formed report.md passes the validate_report hook."""
        report_path = FIXTURES / "reports" / "valid_resolved.md"
        passed, errors, _ = validate_tier1(report_path)
        assert passed, f"Valid report failed validation: {errors}"

    def test_escalation_report_passes_validation(self):
        report_path = FIXTURES / "reports" / "valid_escalate.md"
        passed, errors, _ = validate_tier1(report_path)
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

    def test_screen_resolve_sequence(self):
        """C -> SCREEN -> CONCLUDE is valid (screen resolved)."""
        phases = ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"{current} -> {phase}: {error}"
            current = phase

    def test_screen_fallthrough_sequence(self):
        """C -> SCREEN -> H -> G -> A -> CONCLUDE (screen didn't resolve)."""
        phases = ["CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        current = None
        for phase in phases:
            valid, error = validate_transition(current, phase)
            assert valid, f"{current} -> {phase}: {error}"
            current = phase

    def test_cannot_skip_gather(self):
        valid, _ = validate_transition("HYPOTHESIZE", "ANALYZE")
        assert not valid

    def test_cannot_skip_hypothesize(self):
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
        failed = data["queries"]["failed_logins_5min"]["response"]
        assert failed["total"] == 47

    def test_monitoring_probe_no_successful_login(self):
        data = json.loads(
            (FIXTURES / "siem_responses" / "wazuh-5710-monitoring-probe.json").read_text()
        )
        assert data["queries"]["successful_logins_60s"]["response"]["total"] == 0

    def test_brute_force_no_successful_login(self):
        data = json.loads(
            (FIXTURES / "siem_responses" / "wazuh-5710-brute-force.json").read_text()
        )
        assert data["queries"]["successful_logins_60s"]["response"]["total"] == 0


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


# ---------------------------------------------------------------------------
# LLM integration tests — require Claude CLI and API access
# Run with: pytest soc-agent/tests/test_e2e_mock.py -v -m llm
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def llm_investigation_run(tmp_path_factory):
    """Run the investigator once and share the results across all LLM tests.

    This avoids invoking claude multiple times (expensive + slow).
    Uses the shared run_investigation_mock() helper from conftest.
    """
    run_dir = tmp_path_factory.mktemp("llm-run") / "investigation"
    run_dir.mkdir()

    alert = json.loads(
        (FIXTURES / "alerts" / "benign-monitoring-probe.json").read_text()
    )

    result = run_investigation_mock(run_dir, alert, timeout=300)

    return {
        "run_dir": result.run_dir,
        "alert": alert,
        "output": result.stdout,
    }


@pytest.mark.llm
class TestLLMInvestigation:
    """Tests that invoke the actual LLM and validate output structure.

    These tests require:
    - Claude CLI installed and authenticated
    - API access with sufficient credits
    - Run with: pytest -m llm -v

    All tests share a single investigation run (module-scoped fixture)
    to minimize API cost.
    """

    def test_investigation_produces_state_json(self, llm_investigation_run):
        """The investigator must write state.json with valid transitions."""
        run_dir = llm_investigation_run["run_dir"]

        state_file = run_dir / "state.json"
        assert state_file.exists(), "state.json was not created"

        state = json.loads(state_file.read_text())
        assert "phase" in state
        assert "history" in state
        history = state["history"]

        # Validate minimum length based on actual path taken
        if "SCREEN" in history and "HYPOTHESIZE" not in history:
            # Screen-resolved path: C -> SCREEN -> CONCLUDE
            assert len(history) >= 3, (
                f"Screen-resolved path needs >= 3 phases, got {history}"
            )
        elif "SCREEN" in history:
            # Screen fallthrough + full loop: C -> SCREEN -> H -> G -> A -> CONCLUDE
            assert len(history) >= 6, (
                f"Screen-fallthrough path needs >= 6 phases, got {history}"
            )
        else:
            # No screen (skip path): C -> H -> G -> A -> CONCLUDE
            assert len(history) >= 5, (
                f"Full investigation path needs >= 5 phases, got {history}"
            )

        # Verify all transitions were legal
        current = None
        for phase in history:
            valid, error = validate_transition(current, phase)
            assert valid, f"Illegal transition {current} -> {phase}: {error}"
            current = phase

    def test_investigation_produces_report(self, llm_investigation_run):
        """The investigator must write report.md with valid frontmatter."""
        run_dir = llm_investigation_run["run_dir"]

        report_file = run_dir / "report.md"
        assert report_file.exists(), "report.md was not created"

        content = report_file.read_text()
        fields = parse_yaml_frontmatter(content)
        assert fields, "report.md has no YAML frontmatter"

        # Check required fields are present
        required = ["ticket_id", "signature_id", "status", "disposition",
                     "confidence", "leads_pursued"]
        for field in required:
            assert field in fields, f"Missing field in report: {field}"

        # Validate via the schema — all errors, not just structural ones
        report, errors = parse_frontmatter(fields)
        assert not errors, f"Report validation errors: {errors}"

    def test_investigation_produces_investigation_md(self, llm_investigation_run):
        """investigation.md must have phase headers and hypothesis references."""
        run_dir = llm_investigation_run["run_dir"]

        inv_file = run_dir / "investigation.md"
        assert inv_file.exists(), "investigation.md was not created"

        content = inv_file.read_text()

        # Must have phase headers
        assert "CONTEXTUALIZE" in content, "Missing CONTEXTUALIZE phase"
        assert "HYPOTHESIZE" in content, "Missing HYPOTHESIZE phase"
        assert "GATHER" in content, "Missing GATHER phase"
        assert "ANALYZE" in content, "Missing ANALYZE phase"

        # Must reference hypotheses with ? prefix
        assert re.search(r'\?[\w-]+', content), (
            "No ?hypothesis references found in investigation.md"
        )

    def test_investigation_has_structured_analysis(self, llm_investigation_run):
        """ANALYZE phase should contain assessment weights."""
        run_dir = llm_investigation_run["run_dir"]

        inv_file = run_dir / "investigation.md"
        if not inv_file.exists():
            pytest.skip("investigation.md not created")

        content = inv_file.read_text()

        has_weights = any(
            marker in content
            for marker in ["++", "--", "strongly supports", "strongly refutes"]
        )
        assert has_weights, "No structured assessment weights found in ANALYZE phase"

    def test_report_passes_validation_hook(self, llm_investigation_run):
        """The report should pass the validate_report.py hook checks."""
        run_dir = llm_investigation_run["run_dir"]

        report_file = run_dir / "report.md"
        if not report_file.exists():
            pytest.skip("report.md not created")

        passed, errors, _ = validate_tier1(report_file)
        assert passed, f"Report validation errors: {errors}"

    def test_no_hallucinated_tools(self, llm_investigation_run):
        """Investigation should not reference non-existent tools or files."""
        run_dir = llm_investigation_run["run_dir"]

        inv_file = run_dir / "investigation.md"
        if not inv_file.exists():
            pytest.skip("investigation.md not created")

        content = inv_file.read_text()

        # Should not reference the deleted siem-mapping.json
        assert "siem-mapping.json" not in content, (
            "investigation.md references removed siem-mapping.json"
        )
