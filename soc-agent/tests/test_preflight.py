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


def make_fake_adapter(cli_path: Path, health_exit: int = 0):
    """Write a stub adapter with a `health-check` subcommand.

    The stub also handles `--help` by printing a subcommand listing that
    contains the literal token `health-check` — preflight's adapter
    discovery filters on that to distinguish real adapters from
    agent-facing dev utilities that also live under scripts/tools/.
    """
    cli_path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if len(sys.argv) >= 2 and sys.argv[1] == '--help':\n"
        "    print('usage: stub [-h] {health-check} ...')\n"
        "    sys.exit(0)\n"
        "if len(sys.argv) >= 2 and sys.argv[1] == 'health-check':\n"
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
      knowledge/signatures/    (empty — populate per test)
      knowledge/environment/systems/

    preflight.py respects SOC_AGENT_DIR, so we point it at this tmp root.
    """
    (tmp_path / "scripts" / "tools").mkdir(parents=True)
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
    def test_discovers_cli_suffixed_adapter(self, fake_root):
        """Historical `{name}_cli.py` filenames are accepted for readability;
        the `_cli` suffix is stripped from the reported system name."""
        make_fake_adapter(fake_root / "scripts" / "tools" / "splunk_cli.py")
        make_system_docs(fake_root, "splunk")
        result = run_preflight(fake_root, "--systems", "--json")
        payload = json.loads(result.stdout)
        assert len(payload["systems"]) == 1
        assert payload["systems"][0]["system"] == "splunk"
        assert payload["systems"][0]["connected"] is True

    def test_discovers_plain_name_adapter(self, fake_root):
        """Adapters without the `_cli` suffix (e.g. host_query.py) discover
        cleanly — the filename stem is the system name as-is."""
        make_fake_adapter(fake_root / "scripts" / "tools" / "host_query.py")
        make_system_docs(fake_root, "host_query")
        result = run_preflight(fake_root, "--systems", "--json")
        payload = json.loads(result.stdout)
        assert len(payload["systems"]) == 1
        assert payload["systems"][0]["system"] == "host_query"
        assert payload["systems"][0]["connected"] is True

    def test_skips_private_and_non_python_files(self, fake_root):
        """`__init__.py`, `_private.py`, and non-.py files must not be
        discovered as adapters."""
        make_fake_adapter(fake_root / "scripts" / "tools" / "real_cli.py")
        make_system_docs(fake_root, "real")
        (fake_root / "scripts" / "tools" / "__init__.py").write_text("")
        (fake_root / "scripts" / "tools" / "_helper.py").write_text("# private\n")
        (fake_root / "scripts" / "tools" / "requirements.txt").write_text("")
        result = run_preflight(fake_root, "--systems", "--json")
        payload = json.loads(result.stdout)
        assert len(payload["systems"]) == 1
        assert payload["systems"][0]["system"] == "real"

    def test_skips_non_adapter_scripts_without_health_check(self, fake_root):
        """`scripts/tools/` also hosts agent-facing dev utilities (e.g.
        `list_lead_tags.py`) that are NOT SIEM adapters. Preflight must
        filter them out — an entry in scripts/tools/ whose `--help` output
        does not advertise `health-check` is skipped silently, not flagged
        as a missing-knowledge-dir error that turns the result DEGRADED."""
        # Real adapter — should be discovered.
        make_fake_adapter(fake_root / "scripts" / "tools" / "real_cli.py")
        make_system_docs(fake_root, "real")

        # Non-adapter dev utility (e.g. a tag-lister) — no health-check
        # subcommand, no corresponding environment/systems/ dir. Preflight
        # must not treat it as an adapter.
        dev_util = fake_root / "scripts" / "tools" / "list_lead_tags.py"
        dev_util.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if len(sys.argv) >= 2 and sys.argv[1] == '--help':\n"
            "    print('usage: list_lead_tags [-h] [--root ROOT] [--check PATH]')\n"
            "    sys.exit(0)\n"
            "sys.exit(0)\n"
        )
        dev_util.chmod(0o755)

        result = run_preflight(fake_root, "--systems", "--json")
        assert result.returncode == 0, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert len(payload["systems"]) == 1
        assert payload["systems"][0]["system"] == "real"


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

    def test_hyphenated_knowledge_dir_matches_underscored_adapter(self, fake_root):
        """Python filenames use underscores; knowledge dirs often use hyphens.
        `host_query.py` must find `knowledge/environment/systems/host-query/`
        so the mismatch doesn't show up as a spurious knowledge gap."""
        make_fake_adapter(fake_root / "scripts" / "tools" / "host_query.py")
        hyphen_dir = fake_root / "knowledge" / "environment" / "systems" / "host-query"
        hyphen_dir.mkdir(parents=True)
        (hyphen_dir / "SKILL.md").write_text("# host-query\n")
        result = run_preflight(fake_root, "--systems", "--json")
        payload = json.loads(result.stdout)
        hq = next(s for s in payload["systems"] if s["system"] == "host_query")
        assert hq["connected"] is True
        assert hq["knowledge_gaps"] == []

    def test_uses_adapter_local_venv_python_when_present(self, fake_root):
        """If a `.venv/bin/python` exists at the soc-agent root (two levels above
        scripts/tools/), preflight must invoke the CLI with that interpreter, not
        the system python3. All adapter deps (e.g. opensearch-py for wazuh_cli)
        are declared as pyproject.toml extras and installed into the shared venv."""
        adapter_dir = fake_root / "scripts" / "tools"
        marker = fake_root / "marker.txt"
        cli = adapter_dir / "marker_cli.py"
        cli.parent.mkdir(parents=True, exist_ok=True)
        cli.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if len(sys.argv) >= 2 and sys.argv[1] == '--help':\n"
            "    print('usage: marker [-h] {health-check} ...')\n"
            "    sys.exit(0)\n"
            f"open({str(marker)!r}, 'w').write(sys.executable)\n"
            "if len(sys.argv) >= 2 and sys.argv[1] == 'health-check':\n"
            "    sys.exit(0)\n"
            "sys.exit(9)\n"
        )
        cli.chmod(0o755)
        make_system_docs(fake_root, "marker")

        # Symlink the soc-agent root .venv/bin/python to the current interpreter.
        venv_bin = fake_root / ".venv" / "bin"
        venv_bin.mkdir(parents=True)
        venv_python = venv_bin / "python"
        venv_python.symlink_to(sys.executable)

        result = run_preflight(fake_root, "--systems")
        assert result.returncode == 0, result.stdout + result.stderr
        invoker = marker.read_text().strip()
        assert invoker == str(venv_python), (
            f"expected adapter-local venv python {venv_python}, got {invoker!r}"
        )

    def test_falls_back_to_system_python3_without_venv(self, fake_root):
        """No adapter-local .venv → preflight must still invoke the CLI
        successfully via system python3 (tests, CI, fresh checkouts)."""
        adapter_dir = fake_root / "scripts" / "tools"
        marker = fake_root / "marker2.txt"
        cli = adapter_dir / "bare_cli.py"
        cli.parent.mkdir(parents=True, exist_ok=True)
        cli.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if len(sys.argv) >= 2 and sys.argv[1] == '--help':\n"
            "    print('usage: bare [-h] {health-check} ...')\n"
            "    sys.exit(0)\n"
            f"open({str(marker)!r}, 'w').write(sys.executable)\n"
            "if len(sys.argv) >= 2 and sys.argv[1] == 'health-check':\n"
            "    sys.exit(0)\n"
            "sys.exit(9)\n"
        )
        cli.chmod(0o755)
        make_system_docs(fake_root, "bare")

        # Intentionally no .venv under adapter_dir.
        result = run_preflight(fake_root, "--systems")
        assert result.returncode == 0, result.stdout + result.stderr
        invoker = marker.read_text().strip()
        # With no adapter-local venv, preflight should resolve "python3"
        # on PATH. The interpreter CI hands us may itself live in a venv
        # (e.g. setup-python's runner venv), so we can't assert ".venv"
        # is absent globally — only that the *adapter-local* venv path,
        # which doesn't exist, wasn't used.
        adapter_local_venv = adapter_dir / ".venv"
        assert not invoker.startswith(str(adapter_local_venv)), (
            f"unexpected adapter-local venv python used when none exists: {invoker!r}"
        )
        assert str(fake_root) not in invoker, (
            f"interpreter unexpectedly resolved inside fake_root: {invoker!r}"
        )


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
