"""Contract-compliance tests for adapters shipped in this repo.

For the ticketing-family ActionContract we only ship one reference
connector — `stub_ticket_cli.py` — which is also the template `/connect`
copies when generating a new vendor adapter. These tests confirm the stub
actually implements the contract shape declared in
`schemas/adapter_contract.py`, so the contract documentation and the
reference implementation stay in sync.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.adapter_contract import (
    REQUIRED_ACTION_FLAGS_UNIVERSAL,
    REQUIRED_ACTION_SUBCOMMANDS,
    REQUIRED_TICKETING_CLOSE_FLAGS,
    REQUIRED_TICKETING_SUBCOMMANDS,
)

STUB_CLI = SOC_AGENT_ROOT / "scripts" / "tools" / "stub_ticket_cli.py"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(STUB_CLI), *args],
        capture_output=True,
        text=True,
        timeout=10,
    )


class TestStubTicketCliContract:
    def test_universal_subcommands_in_help(self):
        result = _run("--help")
        assert result.returncode == 0
        for sub in REQUIRED_ACTION_SUBCOMMANDS:
            assert sub in result.stdout, f"missing universal subcommand: {sub}"

    def test_ticketing_subcommands_in_help(self):
        result = _run("--help")
        assert result.returncode == 0
        for sub in REQUIRED_TICKETING_SUBCOMMANDS:
            assert sub in result.stdout, f"missing ticketing subcommand: {sub}"

    def test_close_flags_in_help(self):
        result = _run("close", "--help")
        assert result.returncode == 0
        help_text = result.stdout
        for flag in REQUIRED_TICKETING_CLOSE_FLAGS:
            assert flag in help_text, f"missing close flag: {flag}"
        # Universal action flags — the stub exposes --run-dir, --dry-run, --execute.
        for flag in REQUIRED_ACTION_FLAGS_UNIVERSAL:
            assert flag in help_text, f"missing universal action flag: {flag}"

    def test_health_check_exits_zero(self):
        result = _run("health-check")
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["connected"] is True

    def test_close_dry_run_is_default(self):
        """Omitting --execute must short-circuit with dry_run=True. This is
        the rule that makes the preflight probe safe."""
        result = _run(
            "close",
            "--ticket-id",
            "PROBE-0",
            "--reason",
            "r",
            "--author",
            "a",
            "--documentation",
            "d",
        )
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["dry_run"] is True
        assert payload["success"] is True

    def test_close_dry_run_and_execute_are_mutually_exclusive(self):
        result = _run(
            "close",
            "--ticket-id",
            "X-1",
            "--reason",
            "r",
            "--author",
            "a",
            "--documentation",
            "d",
            "--dry-run",
            "--execute",
        )
        assert result.returncode != 0

    def test_close_missing_required_flag_errors(self):
        result = _run("close", "--ticket-id", "X-1")
        assert result.returncode != 0
