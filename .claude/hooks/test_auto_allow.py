#!/usr/bin/env python3
"""Tests for auto_allow.py PostToolUse hook."""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import auto_allow


class TestIsDenied:
    @pytest.mark.parametrize("command", [
        "rm -rf /tmp/foo",
        "rm -r somedir",
        "git push --force origin main",
        "git push -f origin main",
        "git reset --hard HEAD~1",
        "docker stop container1",
        "docker kill container1",
        "kill -9 1234",
        "curl http://example.com -X POST -d data",
        "echo hello > file.txt",
    ])
    def test_denied(self, command):
        assert auto_allow.is_denied(command)

    @pytest.mark.parametrize("command", [
        "ls -la",
        "git push",
        "cat /etc/hosts",
        "docker exec wazuh-manager cat /etc/ossec.conf",
        "docker logs falco --follow",
        "echo hello >> file.txt",
    ])
    def test_safe_command_not_denied(self, command):
        assert not auto_allow.is_denied(command)


class TestIsCompound:
    @pytest.mark.parametrize("command", ["ls && pwd", "ls; pwd", "ls | grep foo"])
    def test_compound(self, command):
        assert auto_allow.is_compound(command)

    @pytest.mark.parametrize("command", [
        "ls -la",
        "echo 'hello && world'",
        'grep "foo|bar" file.txt',
        """python -c 'import os; print(os.getcwd())'""",
    ])
    def test_simple_command(self, command):
        assert not auto_allow.is_compound(command)


class TestPatternMatching:
    @pytest.mark.parametrize(("pattern", "tool", "value"), [
        pytest.param("Bash(git push)", "Bash", "git push", id="exact_bash"),
        pytest.param("Bash(docker logs *)", "Bash", "docker logs falco", id="prefix_with_space_star"),
        pytest.param("Bash(docker logs:*)", "Bash", "docker logs:falco", id="prefix_with_colon_star"),
        pytest.param("Bash(docker*)", "Bash", "docker-compose up", id="prefix_no_word_boundary"),
        pytest.param("Bash(docker *)", "Bash", "docker ps", id="prefix_word_boundary_match"),
        pytest.param("Read(//etc/hosts)", "Read", "//etc/hosts", id="read_exact_path"),
        pytest.param("Read(//var/log/*)", "Read", "//var/log/syslog", id="read_wildcard"),
        pytest.param("Read(//var/log/**)", "Read", "//var/log/nginx/access.log", id="read_recursive_glob"),
        pytest.param("Bash", "Bash", "anything", id="bare_tool_name"),
        pytest.param("Bash(git * main)", "Bash", "git checkout main", id="middle_wildcard"),
    ])
    def test_matches(self, pattern, tool, value):
        assert auto_allow.claude_pattern_matches(pattern, tool, value)

    @pytest.mark.parametrize(("pattern", "tool", "value"), [
        pytest.param("Bash(git push)", "Bash", "git pull", id="exact_bash"),
        # no space after "docker"
        pytest.param("Bash(docker *)", "Bash", "docker-compose up", id="prefix_word_boundary"),
        pytest.param("Read(//etc/hosts)", "Read", "//etc/passwd", id="read"),
        pytest.param("Bash(ls *)", "Read", "ls -la", id="wrong_tool"),
        pytest.param("Bash", "WebFetch", "anything", id="bare_tool_name_wrong"),
    ])
    def test_no_match(self, pattern, tool, value):
        assert not auto_allow.claude_pattern_matches(pattern, tool, value)


class TestIsAlreadyAllowed:
    @pytest.mark.parametrize(("allow", "tool", "value"), [
        pytest.param(["Bash(docker logs:*)"], "Bash", "docker logs:falco --follow", id="wildcard"),
        pytest.param(["Bash(git push)"], "Bash", "git push", id="exact_match"),
        pytest.param(["Bash"], "Bash", "anything at all", id="bare_tool"),
        pytest.param(["Read(//var/log/*)"], "Read", "//var/log/syslog", id="read_wildcard"),
    ])
    def test_covered(self, allow, tool, value):
        assert auto_allow.is_already_allowed(allow, tool, value)

    @pytest.mark.parametrize(("allow", "tool", "value"), [
        pytest.param(["Bash(docker logs:*)"], "Bash", "docker exec foo cat /etc/hosts", id="bash"),
        pytest.param(["Read(//var/log/*)"], "Read", "//etc/hosts", id="read"),
    ])
    def test_not_covered(self, allow, tool, value):
        assert not auto_allow.is_already_allowed(allow, tool, value)


class TestBuildRule:
    @pytest.mark.parametrize(("tool", "tool_input", "rule"), [
        pytest.param("Bash", {"command": "ls -la"}, "Bash(ls -la)", id="bash_simple"),
        pytest.param("Bash", {"command": "rm -rf /"}, None, id="bash_denied"),
        pytest.param("Bash", {"command": "ls && pwd"}, None, id="bash_compound"),
        pytest.param("Bash", {"command": ""}, None, id="bash_empty"),
        pytest.param("Read", {"file_path": "/etc/hosts"}, "Read(//etc/hosts)", id="read_outside_workspace"),
        pytest.param("Read", {"file_path": "/workspace/foo.py"}, None, id="read_inside_workspace_skipped"),
        pytest.param("Read", {"file_path": ""}, None, id="read_empty_path"),
        pytest.param("WebFetch", {"url": "https://example.com"}, None, id="unknown_tool"),
    ])
    def test_build_rule(self, tool, tool_input, rule):
        assert auto_allow.build_rule(tool, tool_input) == rule


class TestUpdateSettings:
    def test_creates_new_file(self, tmp_path):
        settings_path = tmp_path / "settings.local.json"
        with patch.object(auto_allow, "SETTINGS_PATH", settings_path):
            auto_allow.update_settings("Bash(ls -la)")
        data = json.loads(settings_path.read_text())
        assert "Bash(ls -la)" in data["permissions"]["allow"]

    def test_appends_to_existing(self, tmp_path):
        settings_path = tmp_path / "settings.local.json"
        settings_path.write_text(json.dumps({
            "permissions": {"allow": ["Bash(git push)"], "deny": []}
        }))
        with patch.object(auto_allow, "SETTINGS_PATH", settings_path):
            auto_allow.update_settings("Bash(ls -la)")
        data = json.loads(settings_path.read_text())
        assert "Bash(git push)" in data["permissions"]["allow"]
        assert "Bash(ls -la)" in data["permissions"]["allow"]

    def test_no_duplicates(self, tmp_path):
        settings_path = tmp_path / "settings.local.json"
        settings_path.write_text(json.dumps({
            "permissions": {"allow": ["Bash(ls -la)"]}
        }))
        with patch.object(auto_allow, "SETTINGS_PATH", settings_path):
            auto_allow.update_settings("Bash(ls -la)")
        data = json.loads(settings_path.read_text())
        assert data["permissions"]["allow"].count("Bash(ls -la)") == 1

    def test_preserves_other_fields(self, tmp_path):
        settings_path = tmp_path / "settings.local.json"
        settings_path.write_text(json.dumps({
            "permissions": {"allow": [], "deny": ["Bash(rm -rf *)"]},
            "hooks": {"Notification": []}
        }))
        with patch.object(auto_allow, "SETTINGS_PATH", settings_path):
            auto_allow.update_settings("Bash(ls -la)")
        data = json.loads(settings_path.read_text())
        assert "Bash(rm -rf *)" in data["permissions"]["deny"]
        assert "Notification" in data["hooks"]


HOOK_SCRIPT = Path(__file__).parent / "auto_allow.py"


class TestEndToEnd:
    def test_bash_command_added(self, tmp_path):
        # The hook writes the `settings.local.json` beside its own `hooks/` folder: run a copy
        # placed in a tmp project, never the checkout's own.
        script = tmp_path / ".claude" / "hooks" / "auto_allow.py"
        script.parent.mkdir(parents=True)
        shutil.copy2(HOOK_SCRIPT, script)
        settings_path = tmp_path / ".claude" / "settings.local.json"
        settings_path.write_text(json.dumps({"permissions": {"allow": []}}))

        hook_input = json.dumps({
            "session_id": "test-123",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "python3 --version"},
            "tool_use_id": "toolu_test",
        })

        result = subprocess.run(
            [sys.executable, str(script)],
            input=hook_input,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(settings_path.read_text())
        assert data["permissions"]["allow"] == ["Bash(python3 --version)"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
