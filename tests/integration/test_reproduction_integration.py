#!/usr/bin/env python3
"""
Integration tests for the Reproduction Runner.

These tests spawn actual Claude Code processes and may take several minutes.
They are separated from unit tests to allow fast test suite execution.

Usage:
    # Run integration tests explicitly
    pytest tests/integration/test_reproduction_integration.py -v

    # Direct execution
    python tests/integration/test_reproduction_integration.py

    # Custom hypothesis
    python tests/integration/test_reproduction_integration.py --hypothesis "Your hypothesis"
"""

import json
import sys
from pathlib import Path

# Add workspace to path if running directly
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest

from app.agent.models import ReproductionRequest
from app.agent.reproduction.runner import ReproductionRunner


@pytest.mark.integration
@pytest.mark.slow
def test_backup_script_reproduction():
    """
    Test reproducing benign_activity.sh file creation.

    This tests the hypothesis that backup files in /tmp are created
    by the benign_activity.sh workload script on target-endpoint.

    NOTE: This test spawns Claude Code and may take several minutes.
    """
    print("=" * 60)
    print("Reproduction Runner Integration Test")
    print("=" * 60)

    hypothesis = """On target-endpoint container, the file /tmp/backup-*.tar.gz
is created by the scheduled benign_activity.sh script located at
/opt/workloads/benign_activity.sh.

Expected behavior:
- The script creates a tar.gz archive in /tmp
- File naming pattern: backup-YYYYMMDD-HHMMSS.tar.gz
- Archive contains files from /var/log or similar
"""

    runner = ReproductionRunner(
        ticket_id="TEST-REPRO-001",
        hypothesis=hypothesis,
        signature_id="falco:write_below_temp",
        environment_hint="target-endpoint",
        timeout_seconds=300,
    )

    print(f"\nRun ID: {runner.run_id}")
    print(f"Run Dir: {runner.run_dir}")
    print(f"Ticket ID: {runner.ticket_id}")
    print(f"Timeout: {runner.timeout_seconds}s")
    print("\n" + "-" * 60)
    print("Running reproduction test...")
    print("-" * 60 + "\n")

    result = runner.run()

    print("\n" + "=" * 60)
    print("Result:")
    print("=" * 60)
    print(json.dumps(result.to_dict(), indent=2))

    # Basic assertions
    assert result.result in ["confirmed", "refuted", "inconclusive"], \
        f"Result should be confirmed/refuted/inconclusive, got: {result.result}"
    assert result.run_id, "Result should have run_id"
    assert result.duration_seconds >= 0, "Result should have duration_seconds"

    print("\n" + "-" * 60)
    if result.success:
        print("✓ Test completed successfully")
        print(f"  Result: {result.result}")
        print(f"  Duration: {result.duration_seconds:.1f}s")
        if result.report_url:
            print(f"  Report: {result.report_url}")
    else:
        print("✗ Test failed")
        print(f"  Error: {result.error or 'Unknown error'}")
    print("-" * 60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Reproduction Runner Integration Tests")
    parser.add_argument("--hypothesis", help="Custom hypothesis to test")
    parser.add_argument("--ticket-id", default="TEST-CLI-001",
                        help="Ticket ID (default: TEST-CLI-001)")
    parser.add_argument("--environment-hint",
                        help="Environment hint (e.g., container name)")

    args = parser.parse_args()

    if args.hypothesis:
        # Custom hypothesis test
        request = ReproductionRequest(
            ticket_id=args.ticket_id,
            hypothesis=args.hypothesis,
            environment_hint=args.environment_hint,
        )
        runner = ReproductionRunner.from_request(request)
        result = runner.run()
        print(json.dumps(result.to_dict(), indent=2))
    else:
        # Default test
        test_backup_script_reproduction()
