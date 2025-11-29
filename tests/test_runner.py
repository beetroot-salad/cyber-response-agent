"""
Tests for the Investigation Runner.
"""

import json
import os
import shutil
import pytest
from pathlib import Path

from app.agent.investigation.runner import (
    InvestigationConfig,
    InvestigationResult,
    InvestigationRunner,
)


class TestInvestigationConfig:
    """Tests for InvestigationConfig loading."""

    def test_load_existing_signature(self):
        """Should load config from existing signature."""
        config = InvestigationConfig.load("wazuh-rule-5710")
        assert "benign" in config.allowed_dispositions
        assert config.auto_close_enabled is True

    def test_load_unknown_signature_uses_template(self):
        """Unknown signature should fall back to template."""
        config = InvestigationConfig.load("unknown-signature")
        # Should get template defaults
        assert "benign" in config.allowed_dispositions
        assert "false_positive" in config.allowed_dispositions

    def test_defaults(self):
        """Direct instantiation should use defaults."""
        config = InvestigationConfig()
        assert config.allowed_dispositions == ["benign", "false_positive"]
        assert config.allowed_capabilities == ["query_siem", "read_knowledge"]
        assert config.auto_close_enabled is True
        assert config.log_level == "standard"


class TestInvestigationRunner:
    """Tests for InvestigationRunner."""

    @pytest.fixture
    def runner(self):
        """Create a runner for testing."""
        return InvestigationRunner(
            ticket_id="TEST-001",
            signature_id="wazuh-rule-5710",
            alert_data={"srcip": "10.0.1.50", "srcuser": "testuser"},
            cleanup=True,  # Always cleanup test runs
        )

    def test_run_id_format(self, runner):
        """Run ID should contain ticket ID and timestamp."""
        assert runner.run_id.startswith("TEST-001_")
        assert len(runner.run_id) > len("TEST-001_")

    def test_run_dir_path(self, runner):
        """Run dir should be under runs/."""
        assert "runs" in str(runner.run_dir)
        assert runner.run_id in str(runner.run_dir)

    def test_setup_creates_directory_structure(self, runner):
        """Setup should create the full directory structure."""
        try:
            runner.setup()

            # Check directories exist
            assert runner.run_dir.exists()
            assert (runner.run_dir / ".claude" / "skills").exists()
            assert (runner.run_dir / "scratchpad").exists()

            # Check files exist
            assert (runner.run_dir / "alert.json").exists()
            assert (runner.run_dir / "CLAUDE.md").exists()

            # Check skills are copied
            skills_dir = runner.run_dir / ".claude" / "skills"
            assert (skills_dir / "wazuh-rule-5710" / "SKILL.md").exists()
            assert (skills_dir / "common" / "SKILL.md").exists()

        finally:
            runner.teardown()

    def test_setup_copies_alert_data(self, runner):
        """Setup should write alert data to alert.json."""
        try:
            runner.setup()

            alert_file = runner.run_dir / "alert.json"
            with open(alert_file) as f:
                data = json.load(f)

            assert data["ticket_id"] == "TEST-001"
            assert data["signature_id"] == "wazuh-rule-5710"
            assert data["srcip"] == "10.0.1.50"
            assert data["srcuser"] == "testuser"

        finally:
            runner.teardown()

    def test_build_prompt(self, runner):
        """Build prompt should include ticket and alert info."""
        prompt = runner.build_prompt()

        assert "TEST-001" in prompt
        assert "wazuh-rule-5710" in prompt
        assert "10.0.1.50" in prompt
        assert "testuser" in prompt

    def test_teardown_removes_directory(self, runner):
        """Teardown should remove the run directory."""
        runner.setup()
        run_dir = runner.run_dir

        assert run_dir.exists()

        runner.teardown()

        assert not run_dir.exists()

    def test_parse_output_valid_json(self, runner):
        """Should parse valid investigation report."""
        output = '''```json
{
  "recommendation": "benign",
  "confidence": "high",
  "matched_ticket": "SEC-2024-001",
  "matched_tier": "gold",
  "evidence": {"ip_class": "internal"}
}
```

## Threat Assessment
This could be a monitoring probe.

## Verdict
Benign activity.
'''
        result = runner.parse_output(output)

        assert result.success is True
        assert result.recommendation == "benign"
        assert result.confidence == "high"
        assert result.matched_ticket == "SEC-2024-001"
        assert result.matched_tier == "gold"
        assert result.evidence == {"ip_class": "internal"}
        assert "Threat Assessment" in result.report_body

    def test_parse_output_no_json(self, runner):
        """Should handle output without JSON block."""
        output = "This is just text without JSON."

        result = runner.parse_output(output)

        assert result.success is False
        assert result.recommendation == "escalate"
        assert "No JSON findings block" in result.error

    def test_parse_output_invalid_json(self, runner):
        """Should handle invalid JSON."""
        output = '''```json
{invalid json here}
```
'''
        result = runner.parse_output(output)

        assert result.success is False
        assert result.recommendation == "escalate"
        assert "Invalid JSON" in result.error

    def test_parse_output_defaults_to_escalate(self, runner):
        """Missing recommendation should default to escalate."""
        output = '''```json
{
  "evidence": {"something": "here"}
}
```
'''
        result = runner.parse_output(output)

        assert result.success is True
        assert result.recommendation == "escalate"
        assert result.confidence == "low"


class TestInvestigationResult:
    """Tests for InvestigationResult."""

    def test_to_dict(self):
        """Should serialize to dict correctly."""
        result = InvestigationResult(
            success=True,
            recommendation="benign",
            confidence="high",
            matched_ticket="SEC-001",
            matched_tier="gold",
            evidence={"key": "value"},
            report_body="Report text",
            run_id="test-123",
            run_dir=Path("/tmp/test"),
            duration_seconds=1.5,
        )

        d = result.to_dict()

        assert d["success"] is True
        assert d["recommendation"] == "benign"
        assert d["confidence"] == "high"
        assert d["matched_ticket"] == "SEC-001"
        assert d["run_id"] == "test-123"
        assert d["duration_seconds"] == 1.5

    def test_error_result(self):
        """Should handle error results."""
        result = InvestigationResult(
            success=False,
            error="Something went wrong",
        )

        assert result.success is False
        assert result.error == "Something went wrong"
        assert result.recommendation == "escalate"  # Default
