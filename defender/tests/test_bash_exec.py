"""Tests for defender/runtime/bash_exec.py — the shell=False executor.

These assert two things: (1) ordinary read-only shapes the gate approves run
correctly without a shell (single command, pipes, `&&`/`||`/`;`, `cd`, benign
stderr redirects); (2) the security property — bash never re-parses, so `$VAR`
and globs do NOT expand (the whole reason the lane stopped using `shell=True`).
"""
from __future__ import annotations

import os
import subprocess

import pytest

from defender.runtime import bash_exec


def _env(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env.update(extra)
    return env


def _run(cmd: str, *, env=None, cwd="/", timeout: float = 10.0):
    return bash_exec.run_pipeline(cmd, env=env or _env(), cwd=cwd, timeout=timeout)


# --- ordinary shapes execute correctly ------------------------------------

def test_single_command():
    rc, out, err = _run("echo hi")
    assert rc == 0 and out == "hi\n" and err == ""


def test_empty_command_is_noop():
    assert _run("") == (0, "", "")
    assert _run("   ") == (0, "", "")


def test_two_stage_pipe(tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("alpha\nbeta\nalpha\n")
    rc, out, err = _run(f"cat {f} | grep alpha")
    assert rc == 0 and out == "alpha\nalpha\n"


def test_three_stage_pipe():
    rc, out, err = _run("echo hello | cat | cat")
    assert rc == 0 and out == "hello\n"


def test_quoted_pipe_is_not_a_split():
    # A `|` inside a quoted arg (e.g. a jq filter `'.hits | length'`) is token
    # content, not a pipeline separator — the executor must run ONE command.
    rc, out, err = _run("echo 'a | b'")
    assert rc == 0 and out == "a | b\n"


def test_pipe_exit_code_is_last_stage(tmp_path):
    # `grep` finds nothing → rc 1; that is the pipeline's rc (last stage wins).
    f = tmp_path / "p.txt"
    f.write_text("alpha\n")
    rc, out, err = _run(f"cat {f} | grep zzz")
    assert rc == 1 and out == ""


def test_bash_c_is_unwrapped_and_run():
    rc, out, err = _run("bash -c 'echo wrapped'")
    assert rc == 0 and out == "wrapped\n"


def test_timeout_prefix_is_stripped_and_runs():
    rc, out, err = _run("timeout 5 echo hi")
    assert rc == 0 and out == "hi\n"


# --- connectors -----------------------------------------------------------

def test_and_short_circuits_on_failure():
    rc, out, err = _run("false && echo nope")
    assert rc == 1 and "nope" not in out


def test_and_runs_tail_on_success():
    rc, out, err = _run("true && echo yes")
    assert rc == 0 and out == "yes\n"


def test_or_runs_tail_on_failure():
    rc, out, err = _run("false || echo fallback")
    assert rc == 0 and out == "fallback\n"


def test_semicolon_runs_both():
    rc, out, err = _run("echo a ; echo b")
    assert rc == 0 and out == "a\nb\n"


def test_newline_separates_commands():
    rc, out, err = _run("echo a\necho b")
    assert rc == 0 and out == "a\nb\n"


# --- cd threads cwd into later stages -------------------------------------

def test_cd_then_relative_read(tmp_path):
    (tmp_path / "data.txt").write_text("X")
    rc, out, err = _run(f"cd {tmp_path} && cat data.txt")
    assert rc == 0 and out == "X"


def test_cd_missing_dir_fails():
    rc, out, err = _run("cd /no/such/dir/xyz && echo after")
    assert rc == 1 and "after" not in out and "No such file" in err


# --- benign stderr redirects ----------------------------------------------

def test_stderr_to_devnull_is_suppressed():
    rc, out, err = _run("ls /nonexistent_path_xyz 2>/dev/null")
    assert rc != 0 and out == "" and err == ""


def test_stderr_merged_into_stdout():
    rc, out, err = _run("ls /nonexistent_path_xyz 2>&1")
    assert rc != 0 and "nonexistent_path_xyz" in out and err == ""


def test_devnull_in_pipe(tmp_path):
    # cat of a missing file errors (suppressed); wc reads the empty stream.
    rc, out, err = _run("cat /nonexistent_xyz 2>/dev/null | wc -l")
    assert rc == 0 and out.strip() == "0" and err == ""


def test_default_stderr_is_captured():
    rc, out, err = _run("ls /nonexistent_zzz")
    assert rc != 0 and out == "" and "nonexistent_zzz" in err


def test_mid_pipe_stderr_is_captured():
    # A non-last stage's stderr is captured even though its stdout is piped onward.
    rc, out, err = _run("cat /nope_aaa | wc -l")
    assert rc == 0 and out.strip() == "0" and "nope_aaa" in err


# --- the security property: no shell expansion ----------------------------

def test_dollar_var_does_not_expand():
    # The whole point of dropping shell=True: an injected `echo $SECRET` prints
    # the literal token, never the secret in the environment.
    rc, out, err = _run("echo $SECRET", env=_env(SECRET="topsecret-value"))
    assert out == "$SECRET\n"
    assert "topsecret-value" not in out


def test_glob_does_not_expand(tmp_path):
    (tmp_path / "a.json").write_text("{}")
    (tmp_path / "b.json").write_text("{}")
    rc, out, err = _run("echo *.json", cwd=tmp_path)
    assert out == "*.json\n"  # literal, not "a.json b.json"


def test_brace_does_not_expand():
    rc, out, err = _run("echo x{1,2}")
    assert out == "x{1,2}\n"


# --- failure modes --------------------------------------------------------

def test_command_not_found_is_127():
    rc, out, err = _run("no_such_binary_abc123")
    assert rc == 127 and "command not found" in err


def test_timeout_raises():
    with pytest.raises(subprocess.TimeoutExpired):
        _run("sleep 3", timeout=0.3)


def test_unexpected_redirect_fails_closed():
    # A real stdout redirect never passes the gate; if one reached the executor
    # it must fail closed rather than write a file.
    with pytest.raises(bash_exec.BashExecError):
        _run("echo hi > /tmp/should_not_write_xyz")
    assert not os.path.exists("/tmp/should_not_write_xyz")
