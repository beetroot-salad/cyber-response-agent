#!/usr/bin/env python3
"""
Test script for the Reproduction Runner.

Simple validation that the runner can:
1. Set up a run directory
2. Spawn Claude Code
3. Parse output
4. Clean up containers

Usage:
    # Via pytest
    pytest tests/test_reproduction_runner.py -v

    # Direct execution (setup only)
    python tests/test_reproduction_runner.py --setup-only

    # Direct execution (full test with Claude Code)
    python tests/test_reproduction_runner.py

    # Custom hypothesis
    python tests/test_reproduction_runner.py --hypothesis "Your hypothesis"
"""

import json
import sys
from pathlib import Path

# Add workspace to path if running directly
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent))

from app.agent.models import ReproductionRequest
from app.agent.reproduction.runner import ReproductionRunner


def test_backup_script_reproduction():
    """
    Test reproducing benign_activity.sh file creation.

    This tests the hypothesis that backup files in /tmp are created
    by the benign_activity.sh workload script on target-endpoint.
    """
    print("=" * 60)
    print("Reproduction Runner Test")
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

    return result


def test_runner_setup_only():
    """Test just the setup phase without running Claude Code."""
    print("=" * 60)
    print("Setup-Only Test")
    print("=" * 60)

    runner = ReproductionRunner(
        ticket_id="TEST-SETUP-001",
        hypothesis="Test hypothesis for setup validation",
        environment_hint="target-endpoint",
    )

    print(f"\nRun ID: {runner.run_id}")
    print(f"Run Dir: {runner.run_dir}")

    # Just run setup
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

    print("\n✓ Setup test passed")
    print(f"  Created: {runner.run_dir}")

    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test Reproduction Runner")
    parser.add_argument("--setup-only", action="store_true",
                        help="Only test setup phase, don't run Claude Code")
    parser.add_argument("--hypothesis", help="Custom hypothesis to test")
    parser.add_argument("--ticket-id", default="TEST-CLI-001",
                        help="Ticket ID (default: TEST-CLI-001)")
    parser.add_argument("--environment-hint",
                        help="Environment hint (e.g., container name)")

    args = parser.parse_args()

    if args.setup_only:
        test_runner_setup_only()
    elif args.hypothesis:
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
