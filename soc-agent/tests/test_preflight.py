"""Tests for scripts/preflight.py — adapter discovery, health check dispatch,
and KB validation across --systems/--kb/--json modes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))
SCRIPT = SOC_AGENT_ROOT / "scripts" / "preflight.py"


# ---------------------------------------------------------------------------
# Fixture: a synthetic soc-agent root with a controllable adapter + KB
# ---------------------------------------------------------------------------


def make_fake_adapter(cli_path: Path, health_exit: int = 0, style: str = "subcommand"):
    """Write a stub adapter that the health check can invoke.

    style="subcommand" — supports `cli.py health-check`
    style="flag"       — supports `cli.py --health-check` (legacy wazuh shape)
    """
    cli_path.parent.mkdir(parents=True, exist_ok=True)
    if style == "subcommand":
        body = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if len(sys.argv) >= 2 and sys.argv[1] == 'health-check':\n"
            f"    sys.exit({health_exit})\n"
            "sys.exit(9)\n"
        )
    else:
        body = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if '--health-check' in sys.argv:\n"
            f"    sys.exit({health_exit})\n"
            "sys.exit(9)\n"
        )
    cli_path.write_text(body)
    cli_path.chmod(0o755)


@pytest.fixture
def fake_root(tmp_path, monkeypatch):
    """Stand up a minimal soc-agent tree the preflight script can run against.

    Creates:
      scripts/tools/           (empty — populate per test)
      scripts/siem/            (empty — populate per test)
      knowledge/signatures/    (empty — populate per test)
      knowledge/environment/systems/

    preflight.py respects SOC_AGENT_DIR, so we point it at this tmp root.
    """
    (tmp_path / "scripts" / "tools").mkdir(parents=True)
    (tmp_path / "scripts" / "siem").mkdir(parents=True)
    (tmp_path / "knowledge" / "signatures").mkdir(parents=True)
    (tmp_path / "knowledge" / "environment" / "systems").mkdir(parents=True)
    (tmp_path / "knowledge" / "environment" / "data-sources").mkdir(parents=True)
    return tmp_path


def run_preflight(fake_root: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "SOC_AGENT_DIR": str(fake_root), "NO_COLOR": "1"}
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
    )


def make_signature(root: Path, name: str, *, complete: bool = True):
    sig_dir = root / "knowledge" / "signatures" / name
    sig_dir.mkdir(parents=True, exist_ok=True)
    if complete:
        (sig_dir / "context.md").write_text("# ctx\n")
        (sig_dir / "playbook.md").write_text("# play\n")
        arch = sig_dir / "archetypes" / "noise"
        arch.mkdir(parents=True)
        (arch / "README.md").write_text("# noise\n")


def make_system_docs(root: Path, system: str):
    d = root / "knowledge" / "environment" / "systems" / system
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(f"# {system}\n")


# ---------------------------------------------------------------------------
# Empty workspace
# ---------------------------------------------------------------------------


class TestEmptyWorkspace:
    def test_no_adapters_exits_2(self, fake_root):
        result = run_preflight(fake_root)
        assert result.returncode == 2, result.stderr
        assert "NOT CONFIGURED" in result.stdout

    def test_no_adapters_kb_only_exits_0_if_no_signatures(self, fake_root):
        # --kb skips the systems check; no signatures = READY (nothing to fail).
        result = run_preflight(fake_root, "--kb")
        assert result.returncode == 0
        assert "READY" in result.stdout
        assert "no adapters found" not in result.stdout


# ---------------------------------------------------------------------------
# Adapter discovery
# ---------------------------------------------------------------------------


class TestAdapterDiscovery:
    def test_discovers_subcommand_adapter_under_tools(self, fake_root):
        make_fake_adapter(fake_root / "scripts" / "tools" / "splunk_cli.py")
        make_system_docs(fake_root, "splunk")
        result = run_preflight(fake_root, "--systems")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "splunk" in result.stdout
        assert "connected" in result.stdout

    def test_discovers_legacy_flag_adapter_under_siem(self, fake_root):
        make_fake_adapter(
            fake_root / "scripts" / "siem" / "wazuh_cli.py",
            style="flag",
        )
        make_system_docs(fake_root, "wazuh")
        result = run_preflight(fake_root, "--systems")
        assert result.returncode == 0, result.stdout + result.stderr
        assert "wazuh" in result.stdout
        assert "connected" in result.stdout

    def test_new_tools_path_wins_over_legacy(self, fake_root):
        """If the same name exists in both scripts/tools/ and scripts/siem/,
        the new contract location wins and the legacy one is ignored."""
        make_fake_adapter(fake_root / "scripts" / "tools" / "splunk_cli.py")
        make_fake_adapter(
            fake_root / "scripts" / "siem" / "splunk_cli.py",
            health_exit=1,
            style="flag",
        )
        make_system_docs(fake_root, "splunk")
        result = run_preflight(fake_root, "--systems", "--json")
        payload = json.loads(result.stdout)
        splunks = [s for s in payload["systems"] if s["system"] == "splunk"]
        assert len(splunks) == 1
        assert splunks[0]["cli_path"].startswith("scripts/tools/")
        assert splunks[0]["connected"] is True


# ---------------------------------------------------------------------------
# Health check outcomes
# ---------------------------------------------------------------------------


class TestHealthCheck:
    def test_failing_health_check_reports_degraded(self, fake_root):
        make_fake_adapter(
            fake_root / "scripts" / "tools" / "edr_cli.py",
            health_exit=1,
        )
        make_system_docs(fake_root, "edr")
        result = run_preflight(fake_root, "--systems")
        assert result.returncode == 1
        assert "DEGRADED" in result.stdout

    def test_missing_system_docs_flagged_as_gap(self, fake_root):
        make_fake_adapter(fake_root / "scripts" / "tools" / "lone_cli.py")
        # Deliberately skip make_system_docs — no per-system knowledge dir.
        result = run_preflight(fake_root, "--systems", "--json")
        payload = json.loads(result.stdout)
        lone = next(s for s in payload["systems"] if s["system"] == "lone")
        assert lone["connected"] is True
        assert lone["knowledge_gaps"], "expected a knowledge gap report"


# ---------------------------------------------------------------------------
# Knowledge base validation
# ---------------------------------------------------------------------------


class TestKBValidation:
    def test_complete_signature_is_ready(self, fake_root):
        make_fake_adapter(fake_root / "scripts" / "tools" / "splunk_cli.py")
        make_system_docs(fake_root, "splunk")
        make_signature(fake_root, "vendor-rule-1", complete=True)
        result = run_preflight(fake_root)
        assert result.returncode == 0
        assert "READY" in result.stdout

    def test_signature_missing_playbook_is_degraded(self, fake_root):
        make_fake_adapter(fake_root / "scripts" / "tools" / "splunk_cli.py")
        make_system_docs(fake_root, "splunk")
        sig_dir = fake_root / "knowledge" / "signatures" / "vendor-rule-2"
        sig_dir.mkdir(parents=True)
        (sig_dir / "context.md").write_text("# ctx\n")
        # missing playbook.md + archetypes/
        result = run_preflight(fake_root)
        assert result.returncode == 1
        assert "vendor-rule-2" in result.stdout
        assert "playbook.md" in result.stdout

    def test_template_signature_dirs_are_skipped(self, fake_root):
        make_fake_adapter(fake_root / "scripts" / "tools" / "splunk_cli.py")
        make_system_docs(fake_root, "splunk")
        make_signature(fake_root, "real-rule", complete=True)
        # `_template` is conventionally skipped.
        skeleton = fake_root / "knowledge" / "signatures" / "_template"
        skeleton.mkdir()
        # Deliberately incomplete.
        result = run_preflight(fake_root, "--kb")
        assert result.returncode == 0
        assert "_template" not in result.stdout


# ---------------------------------------------------------------------------
# Output modes
# ---------------------------------------------------------------------------


class TestOutputModes:
    def test_json_output_is_valid(self, fake_root):
        make_fake_adapter(fake_root / "scripts" / "tools" / "edr_cli.py")
        make_system_docs(fake_root, "edr")
        make_signature(fake_root, "rule-1", complete=True)
        result = run_preflight(fake_root, "--json")
        payload = json.loads(result.stdout)
        assert "systems" in payload
        assert "signatures" in payload
        assert "exit_code" in payload
        assert isinstance(payload["systems"], list)
        assert isinstance(payload["signatures"], list)

    def test_kb_only_json_nulls_systems(self, fake_root):
        make_signature(fake_root, "rule-1", complete=True)
        result = run_preflight(fake_root, "--kb", "--json")
        payload = json.loads(result.stdout)
        assert payload["systems"] is None
        assert payload["signatures"] is not None

    def test_systems_only_json_nulls_signatures(self, fake_root):
        make_fake_adapter(fake_root / "scripts" / "tools" / "edr_cli.py")
        make_system_docs(fake_root, "edr")
        result = run_preflight(fake_root, "--systems", "--json")
        payload = json.loads(result.stdout)
        assert payload["systems"] is not None
        assert payload["signatures"] is None
