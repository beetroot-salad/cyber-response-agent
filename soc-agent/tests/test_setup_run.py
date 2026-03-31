"""Tests for scripts/setup_run.py — run directory creation, alert saving, and sanitization."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))
SCRIPT = SOC_AGENT_ROOT / "scripts" / "setup_run.py"

from scripts.setup_run import sanitize_alert, sanitize_value

VALID_ALERT = json.dumps({"ticket_id": "T-1234", "alert_data": {"srcip": "10.0.1.50"}})


def run_setup(
    signature_id: str = "wazuh-rule-5710",
    alert_json: str = VALID_ALERT,
    *,
    runs_dir: str | None = None,
    omit_alert: bool = False,
) -> subprocess.CompletedProcess:
    """Run setup_run.py as a subprocess."""
    args = [sys.executable, str(SCRIPT), signature_id]
    if not omit_alert:
        args.append(alert_json)
    env = None
    if runs_dir is not None:
        import os

        env = {**os.environ, "SOC_AGENT_RUNS_DIR": runs_dir}
    return subprocess.run(args, capture_output=True, text=True, env=env)


class TestHappyPath:
    """Tests with valid input."""

    def test_exit_code_zero(self, tmp_path):
        result = run_setup(runs_dir=str(tmp_path))
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_creates_run_directory(self, tmp_path):
        result = run_setup(runs_dir=str(tmp_path))
        assert result.returncode == 0
        # Exactly one subdirectory created
        subdirs = list(tmp_path.iterdir())
        assert len(subdirs) == 1
        assert subdirs[0].is_dir()

    def test_writes_alert_json(self, tmp_path):
        result = run_setup(runs_dir=str(tmp_path))
        assert result.returncode == 0
        run_dir = list(tmp_path.iterdir())[0]
        alert_file = run_dir / "alert.json"
        assert alert_file.exists()
        data = json.loads(alert_file.read_text())
        assert data["ticket_id"] == "T-1234"
        assert data["alert_data"]["srcip"] == "10.0.1.50"

    def test_alert_json_is_formatted(self, tmp_path):
        """alert.json should be pretty-printed for readability."""
        run_setup(runs_dir=str(tmp_path))
        run_dir = list(tmp_path.iterdir())[0]
        content = (run_dir / "alert.json").read_text()
        assert "\n" in content  # Not a single-line dump

    def test_stdout_contains_run_directory(self, tmp_path):
        result = run_setup(runs_dir=str(tmp_path))
        assert "Run directory:" in result.stdout

    def test_stdout_contains_signature(self, tmp_path):
        result = run_setup(signature_id="wazuh-rule-5710", runs_dir=str(tmp_path))
        assert "Signature: wazuh-rule-5710" in result.stdout

    def test_stdout_contains_run_id(self, tmp_path):
        result = run_setup(runs_dir=str(tmp_path))
        assert "Run ID:" in result.stdout

    def test_run_dir_name_is_uuid(self, tmp_path):
        """Run directory should be named with a UUID, not derived from alert fields."""
        import re

        run_setup(runs_dir=str(tmp_path))
        run_dir = list(tmp_path.iterdir())[0]
        uuid_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        assert uuid_pattern.match(run_dir.name), f"Expected UUID, got: {run_dir.name}"

    def test_writes_meta_json(self, tmp_path):
        """meta.json should be created with run_id, signature_id, and salt."""
        result = run_setup(runs_dir=str(tmp_path))
        assert result.returncode == 0
        run_dir = list(tmp_path.iterdir())[0]
        meta_file = run_dir / "meta.json"
        assert meta_file.exists()
        meta = json.loads(meta_file.read_text())
        assert "run_id" in meta
        assert meta["signature_id"] == "wazuh-rule-5710"
        assert "salt" in meta
        assert len(meta["salt"]) == 16  # secrets.token_hex(8)

    def test_meta_salt_is_unique(self, tmp_path):
        """Each run should get a different salt."""
        run_setup(runs_dir=str(tmp_path))
        run_setup(runs_dir=str(tmp_path))
        dirs = sorted(tmp_path.iterdir())
        assert len(dirs) == 2
        salt1 = json.loads((dirs[0] / "meta.json").read_text())["salt"]
        salt2 = json.loads((dirs[1] / "meta.json").read_text())["salt"]
        assert salt1 != salt2


class TestRunsDirEnvVar:
    """Tests for SOC_AGENT_RUNS_DIR environment variable."""

    def test_uses_env_var(self, tmp_path):
        custom_dir = tmp_path / "custom-runs"
        result = run_setup(runs_dir=str(custom_dir))
        assert result.returncode == 0
        assert custom_dir.exists()
        assert len(list(custom_dir.iterdir())) == 1

    def test_creates_parent_dirs(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        result = run_setup(runs_dir=str(nested))
        assert result.returncode == 0
        assert nested.exists()


class TestErrorHandling:
    """Tests for invalid input."""

    def test_no_args_fails(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "Usage" in result.stderr

    def test_missing_alert_arg_fails(self):
        result = run_setup(omit_alert=True)
        assert result.returncode == 1
        assert "Usage" in result.stderr

    def test_malformed_json_fails(self, tmp_path):
        result = run_setup(alert_json="not json", runs_dir=str(tmp_path))
        assert result.returncode == 1
        assert "malformed" in result.stderr.lower()
        # No run directory should be created
        assert len(list(tmp_path.iterdir())) == 0

    def test_non_object_json_fails(self, tmp_path):
        result = run_setup(alert_json='"just a string"', runs_dir=str(tmp_path))
        assert result.returncode == 1
        assert "object" in result.stderr.lower()

    def test_array_json_fails(self, tmp_path):
        result = run_setup(alert_json="[1, 2, 3]", runs_dir=str(tmp_path))
        assert result.returncode == 1
        assert "object" in result.stderr.lower()

    def test_empty_string_fails(self, tmp_path):
        result = run_setup(alert_json="", runs_dir=str(tmp_path))
        assert result.returncode == 1


class TestAlertVariations:
    """Tests with different alert shapes — no field name assumptions."""

    def test_empty_object_succeeds(self, tmp_path):
        """An empty JSON object is valid — the agent identifies fields later."""
        result = run_setup(alert_json="{}", runs_dir=str(tmp_path))
        assert result.returncode == 0

    def test_arbitrary_fields_preserved(self, tmp_path):
        """Alert fields pass through unchanged regardless of naming convention."""
        alert = json.dumps({"alertId": "A-99", "src": "1.2.3.4", "custom_field": True})
        result = run_setup(alert_json=alert, runs_dir=str(tmp_path))
        assert result.returncode == 0
        run_dir = list(tmp_path.iterdir())[0]
        data = json.loads((run_dir / "alert.json").read_text())
        assert data["alertId"] == "A-99"
        assert data["custom_field"] is True

    def test_nested_alert_data_preserved(self, tmp_path):
        alert = json.dumps(
            {"id": "X-1", "data": {"nested": {"deep": "value"}, "list": [1, 2, 3]}}
        )
        result = run_setup(alert_json=alert, runs_dir=str(tmp_path))
        assert result.returncode == 0
        run_dir = list(tmp_path.iterdir())[0]
        data = json.loads((run_dir / "alert.json").read_text())
        assert data["data"]["nested"]["deep"] == "value"
        assert data["data"]["list"] == [1, 2, 3]


# --- Input sanitization ---


class TestSanitizeValue:
    def test_normal_text_unchanged(self):
        assert sanitize_value("hello world") == "hello world"

    def test_strips_zero_width_chars(self):
        assert sanitize_value("hello\u200bworld") == "helloworld"

    def test_strips_bidi_overrides(self):
        assert sanitize_value("admin\u202eselur") == "adminselur"

    def test_strips_bidi_isolates(self):
        assert sanitize_value("test\u2066hidden\u2069end") == "testhiddenend"

    def test_strips_bom(self):
        assert sanitize_value("\ufeffdata") == "data"

    def test_strips_ansi_escapes(self):
        assert sanitize_value("\x1b[31mred\x1b[0m") == "red"

    def test_truncates_long_values(self):
        result = sanitize_value("x" * 5000)
        assert len(result) < 5000
        assert result.endswith("[TRUNCATED]")

    def test_preserves_normal_unicode(self):
        text = "cafe\u0301 \u4e16\u754c \U0001f680"
        assert sanitize_value(text) == text

    def test_combined_attack_string(self):
        attack = "\ufeff\u202eignore\u202c\x1b[8m instructions\x1b[0m\u200b"
        result = sanitize_value(attack)
        assert "\ufeff" not in result
        assert "\x1b" not in result
        assert "\u200b" not in result
        assert "ignore" in result


class TestSanitizeAlert:
    def test_sanitizes_nested_structure(self):
        alert = {
            "user": "admin\u200b",
            "data": {"cmd": "ls\x1b[31m -la", "items": ["a\u200b", "b\ufeff"]},
            "count": 42,
        }
        result = sanitize_alert(alert)
        assert result["user"] == "admin"
        assert result["data"]["cmd"] == "ls -la"
        assert result["data"]["items"] == ["a", "b"]
        assert result["count"] == 42


class TestSanitizationIntegration:
    """Integration tests: sanitization applied during setup_run.py execution."""

    def test_dangerous_unicode_stripped_from_alert(self, tmp_path):
        alert = json.dumps({"user": "admin\u200b\u202e"})
        result = run_setup(alert_json=alert, runs_dir=str(tmp_path))
        assert result.returncode == 0
        run_dir = list(tmp_path.iterdir())[0]
        data = json.loads((run_dir / "alert.json").read_text())
        assert data["user"] == "admin"

    def test_ansi_escapes_stripped_from_alert(self, tmp_path):
        alert = json.dumps({"cmd": "ls\x1b[31m -la"})
        result = run_setup(alert_json=alert, runs_dir=str(tmp_path))
        assert result.returncode == 0
        run_dir = list(tmp_path.iterdir())[0]
        data = json.loads((run_dir / "alert.json").read_text())
        assert data["cmd"] == "ls -la"
