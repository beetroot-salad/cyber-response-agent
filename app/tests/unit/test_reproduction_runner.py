#!/usr/bin/env python3
"""
Unit tests for the Reproduction Runner.

These tests validate runner setup, configuration, and parsing
without spawning actual Claude Code processes.

For integration tests that run full reproductions, see:
    tests/integration/test_reproduction_integration.py
"""

import json
from pathlib import Path

import pytest

from app.agent.models import ReproductionRequest
from app.agent.reproduction.runner import ReproductionRunner, _load_max_timeout


class TestReproductionRunnerSetup:
    """Tests for ReproductionRunner setup and configuration."""

    def test_runner_setup_creates_directory_structure(self):
        """Test that setup creates the expected directory structure."""
        runner = ReproductionRunner(
            ticket_id="TEST-SETUP-001",
            hypothesis="Test hypothesis for setup validation",
            environment_hint="target-endpoint",
        )

        try:
            runner.setup()

            # Verify directory structure
            assert runner.run_dir.exists(), "Run directory should exist"
            assert (runner.run_dir / "output").exists(), "Output directory should exist"
            assert (runner.run_dir / "scratchpad").exists(), "Scratchpad should exist"
            assert (runner.run_dir / "hypothesis.json").exists(), "hypothesis.json should exist"

            # Verify hypothesis.json content
            with open(runner.run_dir / "hypothesis.json") as f:
                hypothesis_data = json.load(f)

            assert hypothesis_data["hypothesis"] == "Test hypothesis for setup validation"
            assert hypothesis_data["ticket_id"] == "TEST-SETUP-001"
            assert hypothesis_data["run_id"] == runner.run_id
        finally:
            # Cleanup
            if runner.run_dir.exists():
                import shutil
                shutil.rmtree(runner.run_dir)

    def test_run_id_format(self):
        """Run ID should contain ticket ID and timestamp."""
        runner = ReproductionRunner(
            ticket_id="TEST-001",
            hypothesis="Test hypothesis",
        )
        assert runner.run_id.startswith("TEST-001_")
        assert len(runner.run_id) > len("TEST-001_")

    def test_from_request_creates_runner(self):
        """Should create runner from ReproductionRequest."""
        request = ReproductionRequest(
            ticket_id="REQ-001",
            hypothesis="Test from request",
            signature_id="test-sig",
            environment_hint="test-container",
            timeout_seconds=120,
        )

        runner = ReproductionRunner.from_request(request)

        assert runner.ticket_id == "REQ-001"
        assert runner.hypothesis == "Test from request"
        assert runner.signature_id == "test-sig"
        assert runner.environment_hint == "test-container"
        assert runner.timeout_seconds == 120


class TestTimeoutEnforcement:
    """Tests for timeout configuration and enforcement."""

    def test_max_timeout_enforcement_with_signature(self):
        """Timeout should be capped to config max_timeout."""
        # wazuh-rule-5710 has max_timeout_seconds: 300
        runner = ReproductionRunner(
            ticket_id="TEST-TIMEOUT-001",
            hypothesis="Test timeout enforcement",
            signature_id="wazuh-rule-5710",
            timeout_seconds=600,  # Request more than max
        )
        assert runner.timeout_seconds == 300  # Should be capped

    def test_max_timeout_enforcement_without_signature(self):
        """Without signature, should use default max timeout."""
        runner = ReproductionRunner(
            ticket_id="TEST-TIMEOUT-002",
            hypothesis="Test timeout enforcement",
            timeout_seconds=600,
        )
        assert runner.timeout_seconds == 300  # Default max

    def test_timeout_under_max_preserved(self):
        """Timeout under max should be preserved."""
        runner = ReproductionRunner(
            ticket_id="TEST-TIMEOUT-003",
            hypothesis="Test timeout enforcement",
            signature_id="wazuh-rule-5710",
            timeout_seconds=60,
        )
        assert runner.timeout_seconds == 60

    def test_load_max_timeout_known_signature(self):
        """Should load max_timeout from known signature config."""
        timeout = _load_max_timeout("wazuh-rule-5710")
        assert timeout == 300

    def test_load_max_timeout_unknown_signature(self):
        """Unknown signature should fall back to template."""
        timeout = _load_max_timeout("unknown-sig")
        assert timeout == 300

    def test_load_max_timeout_none_signature(self):
        """None signature should use default."""
        timeout = _load_max_timeout(None)
        assert timeout == 300
