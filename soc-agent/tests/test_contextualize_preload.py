"""Tests for contextualize_preload.py (!command preload script).

Tests run-dir discovery, prompt building, and the main() CLI contract —
all without spawning real claude subprocesses.
"""

import json
import sys
from pathlib import Path
import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.contextualize_preload import (
    build_subagent_prompt,
    find_run_dir,
)




# ---------------------------------------------------------------------------
# find_run_dir
# ---------------------------------------------------------------------------


class TestFindRunDir:
    def test_finds_matching_run_dir(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run-abc"
        run_dir.mkdir()
        (run_dir / "alert.json").write_text("{}")
        (run_dir / "meta.json").write_text(json.dumps({"signature_id": "wazuh-rule-5710"}))
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(tmp_path))
        result = find_run_dir("wazuh-rule-5710")
        assert result == run_dir

    def test_returns_none_for_wrong_signature(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run-abc"
        run_dir.mkdir()
        (run_dir / "alert.json").write_text("{}")
        (run_dir / "meta.json").write_text(json.dumps({"signature_id": "wazuh-rule-5710"}))
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(tmp_path))
        result = find_run_dir("wazuh-rule-9999")
        assert result is None

    def test_returns_none_for_missing_alert_json(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run-abc"
        run_dir.mkdir()
        (run_dir / "meta.json").write_text(json.dumps({"signature_id": "wazuh-rule-5710"}))
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(tmp_path))
        result = find_run_dir("wazuh-rule-5710")
        assert result is None

    def test_returns_none_for_empty_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(tmp_path))
        result = find_run_dir("wazuh-rule-5710")
        assert result is None

    def test_returns_none_for_missing_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(tmp_path / "nonexistent"))
        result = find_run_dir("wazuh-rule-5710")
        assert result is None

    def test_picks_most_recent_matching(self, tmp_path, monkeypatch):
        import time

        old_dir = tmp_path / "run-old"
        old_dir.mkdir()
        (old_dir / "alert.json").write_text("{}")
        (old_dir / "meta.json").write_text(json.dumps({"signature_id": "wazuh-rule-5710"}))

        time.sleep(0.05)  # ensure mtime differs

        new_dir = tmp_path / "run-new"
        new_dir.mkdir()
        (new_dir / "alert.json").write_text("{}")
        (new_dir / "meta.json").write_text(json.dumps({"signature_id": "wazuh-rule-5710"}))

        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(tmp_path))
        result = find_run_dir("wazuh-rule-5710")
        assert result == new_dir

    def test_skips_hidden_dirs(self, tmp_path, monkeypatch):
        hidden = tmp_path / ".sessions"
        hidden.mkdir()
        (hidden / "alert.json").write_text("{}")
        (hidden / "meta.json").write_text(json.dumps({"signature_id": "wazuh-rule-5710"}))
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(tmp_path))
        result = find_run_dir("wazuh-rule-5710")
        assert result is None


# ---------------------------------------------------------------------------
# build_subagent_prompt
# ---------------------------------------------------------------------------


class TestBuildSubagentPrompt:
    def test_reads_model_from_frontmatter(self, tmp_path):
        template = tmp_path / "test.md"
        template.write_text("---\nmodel: sonnet\n---\n\nBody text here.")
        body, model = build_subagent_prompt(template, {})
        assert model == "sonnet"
        assert "Body text here." in body

    def test_substitutes_variables(self, tmp_path):
        template = tmp_path / "test.md"
        template.write_text("---\nmodel: haiku\n---\n\nRun dir: {run_dir}, sig: {signature_id}")
        body, model = build_subagent_prompt(
            template, {"run_dir": "/runs/abc", "signature_id": "wazuh-5710"}
        )
        assert "/runs/abc" in body
        assert "wazuh-5710" in body

    def test_raises_on_missing_model(self, tmp_path):
        template = tmp_path / "test.md"
        template.write_text("---\nname: test\n---\n\nBody without model.")
        with pytest.raises(ValueError, match="missing required 'model' field"):
            build_subagent_prompt(template, {})

    def test_raises_on_missing_frontmatter(self, tmp_path):
        template = tmp_path / "test.md"
        template.write_text("No frontmatter at all, just body text.")
        with pytest.raises(ValueError, match="missing"):
            build_subagent_prompt(template, {})

    def test_real_ticket_context_prompt(self):
        """Verify the actual ticket-context.md has valid frontmatter."""
        prompt_path = SOC_AGENT_ROOT / "skills" / "investigate" / "ticket-context.md"
        body, model = build_subagent_prompt(
            prompt_path,
            {"run_dir": "/tmp/test", "signature_id": "test-sig", "runs_dir": "/tmp"},
        )
        assert model == "sonnet"
        assert len(body) > 100

    def test_real_archetype_scan_prompt(self):
        """Verify the actual archetype-scan.md has valid frontmatter."""
        prompt_path = SOC_AGENT_ROOT / "skills" / "investigate" / "archetype-scan.md"
        body, model = build_subagent_prompt(
            prompt_path,
            {"run_dir": "/tmp/test", "signature_id": "test-sig", "runs_dir": "/tmp"},
        )
        assert model == "haiku"
        assert len(body) > 100


# ---------------------------------------------------------------------------
# main() integration — CLI contract
# ---------------------------------------------------------------------------


class TestMainIntegration:
    def _run_script(self, args: list[str], env_override: dict | None = None) -> tuple[str, str, int]:
        """Run the script as a subprocess, return (stdout, stderr, returncode)."""
        import os
        import subprocess

        env = os.environ.copy()
        if env_override:
            env.update(env_override)

        result = subprocess.run(
            [sys.executable, str(SOC_AGENT_ROOT / "scripts" / "contextualize_preload.py")] + args,
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )
        return result.stdout, result.stderr, result.returncode

    def test_no_args_exits_silently(self):
        stdout, stderr, rc = self._run_script([])
        assert rc == 0
        assert stdout.strip() == ""

    def test_no_matching_run_dir_exits_silently(self, tmp_path):
        stdout, stderr, rc = self._run_script(
            ["wazuh-rule-5710"],
            env_override={"SOC_AGENT_RUNS_DIR": str(tmp_path)},
        )
        assert rc == 0
        assert stdout.strip() == ""
        assert "no run directory found" in stderr

    def test_missing_alert_json_exits_silently(self, tmp_path):
        run_dir = tmp_path / "test-run"
        run_dir.mkdir()
        (run_dir / "meta.json").write_text(json.dumps({"signature_id": "wazuh-rule-5710"}))
        # No alert.json
        stdout, stderr, rc = self._run_script(
            ["wazuh-rule-5710"],
            env_override={"SOC_AGENT_RUNS_DIR": str(tmp_path)},
        )
        assert rc == 0
        assert stdout.strip() == ""