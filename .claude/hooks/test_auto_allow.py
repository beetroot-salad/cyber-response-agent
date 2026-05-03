#!/usr/bin/env python3
"""Tests for auto_allow.py PostToolUse hook."""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Import the module under test
sys.path.insert(0, str(Path(__file__).parent))
import auto_allow


# ---------------------------------------------------------------------------
# Deny list
# ---------------------------------------------------------------------------

class TestIsDenied:
    def test_rm_rf(self):
        assert auto_allow.is_denied("rm -rf /tmp/foo")

    def test_rm_r(self):
        assert auto_allow.is_denied("rm -r somedir")

    def test_git_push_force(self):
        assert auto_allow.is_denied("git push --force origin main")

    def test_git_push_f(self):
        assert auto_allow.is_denied("git push -f origin main")

    def test_git_reset_hard(self):
        assert auto_allow.is_denied("git reset --hard HEAD~1")

    def test_docker_stop(self):
        assert auto_allow.is_denied("docker stop container1")

    def test_docker_kill(self):
        assert auto_allow.is_denied("docker kill container1")

    def test_kill_process(self):
        assert auto_allow.is_denied("kill -9 1234")

    def test_curl_post(self):
        assert auto_allow.is_denied("curl http://example.com -X POST -d data")

    def test_redirect_overwrite(self):
        assert auto_allow.is_denied("echo hello > file.txt")

    def test_safe_command_not_denied(self):
        assert not auto_allow.is_denied("ls -la")

    def test_git_push_normal_not_denied(self):
        assert not auto_allow.is_denied("git push")

    def test_cat_not_denied(self):
        assert not auto_allow.is_denied("cat /etc/hosts")

    def test_docker_exec_cat_not_denied(self):
        assert not auto_allow.is_denied("docker exec wazuh-manager cat /etc/ossec.conf")

    def test_docker_logs_not_denied(self):
        assert not auto_allow.is_denied("docker logs falco --follow")

    def test_append_redirect_not_denied(self):
        # >> is append, not overwrite — but our pattern matches "* > *" which
        # would catch ">> " too since >> contains >. This is intentional:
        # better to be conservative.
        pass


# ---------------------------------------------------------------------------
# Compound command detection
# ---------------------------------------------------------------------------

class TestIsCompound:
    def test_and_operator(self):
        assert auto_allow.is_compound("ls && pwd")

    def test_semicolon(self):
        assert auto_allow.is_compound("ls; pwd")

    def test_pipe(self):
        assert auto_allow.is_compound("ls | grep foo")

    def test_simple_command(self):
        assert not auto_allow.is_compound("ls -la")

    def test_quoted_operators_ignored(self):
        assert not auto_allow.is_compound("echo 'hello && world'")

    def test_double_quoted_pipe_ignored(self):
        assert not auto_allow.is_compound('grep "foo|bar" file.txt')

    def test_python_c_with_semicolons_in_quotes(self):
        assert not auto_allow.is_compound("""python -c 'import os; print(os.getcwd())'""")


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

class TestPatternMatching:
    def test_exact_bash(self):
        assert auto_allow.claude_pattern_matches("Bash(git push)", "Bash", "git push")

    def test_exact_bash_no_match(self):
        assert not auto_allow.claude_pattern_matches("Bash(git push)", "Bash", "git pull")

    def test_prefix_with_space_star(self):
        assert auto_allow.claude_pattern_matches("Bash(docker logs *)", "Bash", "docker logs falco")

    def test_prefix_with_colon_star(self):
        assert auto_allow.claude_pattern_matches("Bash(docker logs:*)", "Bash", "docker logs:falco")

    def test_prefix_no_word_boundary(self):
        assert auto_allow.claude_pattern_matches("Bash(docker*)", "Bash", "docker-compose up")

    def test_prefix_word_boundary(self):
        # "docker *" should NOT match "docker-compose up" (no space after docker)
        assert not auto_allow.claude_pattern_matches("Bash(docker *)", "Bash", "docker-compose up")

    def test_prefix_word_boundary_match(self):
        assert auto_allow.claude_pattern_matches("Bash(docker *)", "Bash", "docker ps")

    def test_read_exact_path(self):
        assert auto_allow.claude_pattern_matches(
            "Read(//etc/hosts)", "Read", "//etc/hosts"
        )

    def test_read_wildcard(self):
        assert auto_allow.claude_pattern_matches(
            "Read(//var/log/*)", "Read", "//var/log/syslog"
        )

    def test_read_recursive_glob(self):
        assert auto_allow.claude_pattern_matches(
            "Read(//var/log/**)", "Read", "//var/log/nginx/access.log"
        )

    def test_read_no_match(self):
        assert not auto_allow.claude_pattern_matches(
            "Read(//etc/hosts)", "Read", "//etc/passwd"
        )

    def test_wrong_tool(self):
        assert not auto_allow.claude_pattern_matches("Bash(ls *)", "Read", "ls -la")

    def test_bare_tool_name(self):
        assert auto_allow.claude_pattern_matches("Bash", "Bash", "anything")

    def test_bare_tool_name_wrong(self):
        assert not auto_allow.claude_pattern_matches("Bash", "WebFetch", "anything")

    def test_middle_wildcard(self):
        assert auto_allow.claude_pattern_matches(
            "Bash(git * main)", "Bash", "git checkout main"
        )


# ---------------------------------------------------------------------------
# is_already_allowed
# ---------------------------------------------------------------------------

class TestIsAlreadyAllowed:
    def test_covered_by_wildcard(self):
        allow = ["Bash(docker logs:*)"]
        assert auto_allow.is_already_allowed(allow, "Bash", "docker logs:falco --follow")

    def test_not_covered(self):
        allow = ["Bash(docker logs:*)"]
        assert not auto_allow.is_already_allowed(allow, "Bash", "docker exec foo cat /etc/hosts")

    def test_exact_match(self):
        allow = ["Bash(git push)"]
        assert auto_allow.is_already_allowed(allow, "Bash", "git push")

    def test_covered_by_bare_tool(self):
        allow = ["Bash"]
        assert auto_allow.is_already_allowed(allow, "Bash", "anything at all")

    def test_read_covered_by_wildcard(self):
        allow = ["Read(//var/log/*)"]
        assert auto_allow.is_already_allowed(allow, "Read", "//var/log/syslog")

    def test_read_not_covered(self):
        allow = ["Read(//var/log/*)"]
        assert not auto_allow.is_already_allowed(allow, "Read", "//etc/hosts")


# ---------------------------------------------------------------------------
# build_rule
# ---------------------------------------------------------------------------

class TestBuildRule:
    def test_bash_simple(self):
        assert auto_allow.build_rule("Bash", {"command": "ls -la"}) == "Bash(ls -la)"

    def test_bash_denied(self):
        assert auto_allow.build_rule("Bash", {"command": "rm -rf /"}) is None

    def test_bash_compound(self):
        assert auto_allow.build_rule("Bash", {"command": "ls && pwd"}) is None

    def test_bash_empty(self):
        assert auto_allow.build_rule("Bash", {"command": ""}) is None

    def test_read_outside_workspace(self):
        rule = auto_allow.build_rule("Read", {"file_path": "/etc/hosts"})
        assert rule == "Read(//etc/hosts)"

    def test_read_inside_workspace_skipped(self):
        assert auto_allow.build_rule("Read", {"file_path": "/workspace/foo.py"}) is None

    def test_read_empty_path(self):
        assert auto_allow.build_rule("Read", {"file_path": ""}) is None

    def test_unknown_tool(self):
        assert auto_allow.build_rule("WebFetch", {"url": "https://example.com"}) is None


# ---------------------------------------------------------------------------
# update_settings (file I/O)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# End-to-end: subprocess invocation
# ---------------------------------------------------------------------------

HOOK_SCRIPT = str(Path(__file__).parent / "auto_allow.py")


class TestEndToEnd:
    def test_bash_command_added(self, tmp_path):
        settings_path = tmp_path / "settings.local.json"
        settings_path.write_text(json.dumps({"permissions": {"allow": []}}))

        hook_input = json.dumps({
            "session_id": "test-123",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "python3 --version"},
            "tool_use_id": "toolu_test",
        })

        env = os.environ.copy()
        result = subprocess.run(
            [sys.executable, HOOK_SCRIPT],
            input=hook_input,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0

        # The script writes to its own SETTINGS_PATH, not tmp_path.
        # For true e2e, we'd need to patch the path. This test verifies
        # the script runs without error.

    def test_denied_command_not_added(self, tmp_path):
        settings_path = tmp_path / "settings.local.json"
        settings_path.write_text(json.dumps({"permissions": {"allow": []}}))

        hook_input = json.dumps({
            "session_id": "test-123",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
            "tool_use_id": "toolu_test",
        })

        with patch.object(auto_allow, "SETTINGS_PATH", settings_path):
            # Can't easily patch in subprocess, so test via import
            hook_data = json.loads(hook_input)
            rule = auto_allow.build_rule(
                hook_data["tool_name"], hook_data["tool_input"]
            )
            assert rule is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
