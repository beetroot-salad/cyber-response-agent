"""Tests for the constrained host query CLI (scripts/tools/host_query.py).

Focus areas:
  - The deny-list (the load-bearing safety property of file-stat).
  - Argparse routing — each subcommand reaches the right handler with the
    right arg shape, unknown subcommands are rejected.
  - Output formatting for the cases where we mock docker_exec — we don't
    want the agent ever seeing process argv, file content, or PIDs from a
    handler that should only emit names.

We do not run a live `docker exec` from these tests; subprocess.run is
mocked at the module boundary.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# scripts/tools/ isn't a package; insert it on sys.path so the import works.
SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts" / "tools"))

import host_query  # noqa: E402
from host_query import (  # noqa: E402
    ANSWER_KEY_PREFIXES,
    build_parser,
    cmd_file_stat,
    cmd_listening_sockets,
    cmd_package_installed,
    cmd_process_list,
    is_answer_key_path,
)


# ---------------------------------------------------------------------------
# Deny-list (load-bearing safety property)
# ---------------------------------------------------------------------------


class TestAnswerKeyDenyList:
    def test_workloads_dir_root_denied(self):
        assert is_answer_key_path("/opt/workloads")
        assert is_answer_key_path("/opt/workloads/")

    def test_workloads_files_denied(self):
        assert is_answer_key_path("/opt/workloads/suspicious_patterns.sh")
        assert is_answer_key_path("/opt/workloads/benign_activity.sh")
        assert is_answer_key_path("/opt/workloads/dns_activity.sh")

    def test_workloads_nested_denied(self):
        assert is_answer_key_path("/opt/workloads/lib/helper.sh")

    def test_cron_d_root_denied(self):
        assert is_answer_key_path("/etc/cron.d")
        assert is_answer_key_path("/etc/cron.d/")

    def test_cron_d_files_denied(self):
        assert is_answer_key_path("/etc/cron.d/workload")
        assert is_answer_key_path("/etc/cron.d/maintenance-marker")

    def test_path_traversal_normalized(self):
        # `..` segments must not bypass the deny-list
        assert is_answer_key_path("/opt/workloads/../workloads/foo.sh")
        assert is_answer_key_path("/etc/cron.d/./workload")
        assert is_answer_key_path("/opt/workloads/sub/../suspicious_patterns.sh")

    def test_other_paths_allowed(self):
        # Paths the agent should be able to stat
        assert not is_answer_key_path("/etc/passwd")
        assert not is_answer_key_path("/etc/ssh/sshd_config")
        assert not is_answer_key_path("/var/log/auth.log")
        assert not is_answer_key_path("/var/log/syslog")
        assert not is_answer_key_path("/")
        assert not is_answer_key_path("/tmp/foo")
        assert not is_answer_key_path("/proc/self/status")

    def test_prefix_must_be_directory_boundary(self):
        # /opt/workloads-other should NOT match /opt/workloads
        assert not is_answer_key_path("/opt/workloads-other/foo")
        assert not is_answer_key_path("/etc/cron.daily/something")

    def test_case_sensitive(self):
        # Linux paths are case-sensitive
        assert not is_answer_key_path("/OPT/workloads/foo")
        assert not is_answer_key_path("/etc/Cron.d/workload")

    def test_deny_list_matches_documented_set(self):
        # Defends against accidental drift between docs and code.
        assert ANSWER_KEY_PREFIXES == ("/opt/workloads", "/etc/cron.d")


# ---------------------------------------------------------------------------
# Argparse — subcommand routing and required args
# ---------------------------------------------------------------------------


class TestArgparseRouting:
    def test_process_list_routes(self):
        args = build_parser().parse_args(["process-list", "sshd"])
        assert args.subcommand == "process-list"
        assert args.pattern == "sshd"
        assert args.func is cmd_process_list

    def test_process_list_requires_pattern(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["process-list"])

    def test_file_stat_requires_path(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["file-stat"])

    def test_listening_sockets_takes_no_args(self):
        args = build_parser().parse_args(["listening-sockets"])
        assert args.subcommand == "listening-sockets"
        assert args.func is cmd_listening_sockets

    def test_unknown_subcommand_rejected(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["raw-shell", "ls /"])

    def test_no_subcommand_rejected(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args([])

    def test_package_installed_routes(self):
        args = build_parser().parse_args(["package-installed", "openssh-server"])
        assert args.func is cmd_package_installed
        assert args.name == "openssh-server"


class TestHostFlag:
    """The --host flag selects which playground container to docker exec against."""

    def test_default_host_is_target_endpoint(self):
        args = build_parser().parse_args(["listening-sockets"])
        assert args.host == "target-endpoint"

    def test_monitoring_host_selected(self):
        args = build_parser().parse_args(["--host", "monitoring-host", "listening-sockets"])
        assert args.host == "monitoring-host"

    def test_bogus_host_rejected_at_parse(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--host", "wazuh-manager", "listening-sockets"])

    def test_host_is_threaded_to_docker_exec(self):
        """A --host value reaches docker_exec as the first positional arg."""
        args = build_parser().parse_args(
            ["--host", "monitoring-host", "process-list", "sshd"]
        )
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = ("COMMAND\n", 0)
            cmd_process_list(args)
            host_arg, argv = mock_exec.call_args[0]
        assert host_arg == "monitoring-host"
        assert argv[0] == "ps"  # sanity check on the argv side too


# ---------------------------------------------------------------------------
# file-stat denial path through the handler (end-to-end via cmd_file_stat)
# ---------------------------------------------------------------------------


class TestFileStatDenyPath:
    def test_returns_rc2_with_clear_message(self, capsys):
        args = build_parser().parse_args(["file-stat", "/opt/workloads/foo.sh"])
        with patch("host_query.docker_exec") as mock_exec:
            rc = cmd_file_stat(args)
            mock_exec.assert_not_called()  # never reaches docker
        assert rc == 2
        captured = capsys.readouterr()
        assert "denied" in captured.err.lower()
        assert "answer-key" in captured.err.lower()
        assert "/opt/workloads" in captured.err

    def test_allowed_path_reaches_docker(self, capsys):
        args = build_parser().parse_args(["file-stat", "/etc/passwd"])
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = (
                "/etc/passwd size=1234 mtime=2026-04-10 10:00:00 mode=644 owner=root type=regular file",
                0,
            )
            rc = cmd_file_stat(args)
            mock_exec.assert_called_once()
            host_arg, argv = mock_exec.call_args[0]
            assert host_arg == "target-endpoint"
            assert argv[0] == "stat"
            assert "/etc/passwd" in argv
        assert rc == 0
        out = capsys.readouterr().out
        assert "/etc/passwd" in out

    def test_nonexistent_file_clean_negative(self, capsys):
        args = build_parser().parse_args(["file-stat", "/no/such/file"])
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = ("error (rc=1): stat: cannot stat", 1)
            rc = cmd_file_stat(args)
        assert rc == 0
        assert "not found" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# process-list — verify argv shape, ensure no PID/argv leaks
# ---------------------------------------------------------------------------


class TestProcessList:
    def test_uses_comm_format_no_argv(self):
        # We must call ps with -o comm (command name only), not with -f or
        # -o args, because that would leak full argv to the agent.
        args = build_parser().parse_args(["process-list", "sshd"])
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = ("COMMAND\nsshd\nbash\n", 0)
            cmd_process_list(args)
            host_arg, argv = mock_exec.call_args[0]
        assert host_arg == "target-endpoint"
        assert argv == ["ps", "-e", "-o", "comm"]

    def test_filters_by_pattern(self, capsys):
        args = build_parser().parse_args(["process-list", "ssh"])
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = (
                "COMMAND\nsshd\nbash\nsystemd\nssh-agent\n", 0,
            )
            cmd_process_list(args)
        out = capsys.readouterr().out.splitlines()
        assert "sshd" in out
        assert "ssh-agent" in out
        assert "bash" not in out
        assert "COMMAND" not in out  # header dropped

    def test_pattern_is_literal_not_regex(self, capsys):
        # The pattern `ssh.` should NOT match `sshd` if it were a regex; we
        # escape the pattern so it's treated as a literal substring.
        args = build_parser().parse_args(["process-list", "ssh."])
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = ("COMMAND\nsshd\nssh.exe\n", 0)
            cmd_process_list(args)
        out = capsys.readouterr().out.splitlines()
        assert "ssh.exe" in out
        assert "sshd" not in out

    def test_no_matches_reports_empty(self, capsys):
        args = build_parser().parse_args(["process-list", "nosuch"])
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = ("COMMAND\nbash\n", 0)
            cmd_process_list(args)
        assert "(no matching processes)" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# listening-sockets — verify no -p (no process info)
# ---------------------------------------------------------------------------


class TestListeningSockets:
    def test_uses_lntu_no_p(self):
        # `-p` would expose process attribution; we must not pass it.
        args = build_parser().parse_args(["listening-sockets"])
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = ("Netid State\ntcp LISTEN 0.0.0.0:22\n", 0)
            cmd_listening_sockets(args)
            host_arg, argv = mock_exec.call_args[0]
        assert host_arg == "target-endpoint"
        assert argv == ["ss", "-lntu"]
        assert "-p" not in argv


# ---------------------------------------------------------------------------
# package-installed — verify dpkg-query argv shape
# ---------------------------------------------------------------------------


class TestPackageInstalled:
    def test_installed(self, capsys):
        args = build_parser().parse_args(["package-installed", "openssh-server"])
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = ("install ok installed", 0)
            cmd_package_installed(args)
        assert "openssh-server: installed" in capsys.readouterr().out

    def test_not_installed(self, capsys):
        args = build_parser().parse_args(["package-installed", "nosuch"])
        with patch("host_query.docker_exec") as mock_exec:
            mock_exec.return_value = ("error (rc=1)", 1)
            cmd_package_installed(args)
        assert "not installed" in capsys.readouterr().out
