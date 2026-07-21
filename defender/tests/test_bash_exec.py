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

from defender.hooks._cmd_segments import unwrap
from defender.runtime import bash_exec


def _env(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env.update(extra)
    return env


def _run(cmd: str, *, env=None, cwd="/", timeout: float = 10.0):
    stripped = cmd.strip()
    if not stripped:
        return 0, "", ""
    inner = unwrap(stripped)
    if inner is None:
        raise bash_exec.BashExecError("command could not be unwrapped for execution")
    return bash_exec.run_parsed(
        bash_exec.parse(inner), command=cmd, env=env or _env(), cwd=cwd, timeout=timeout,
    )



def test_single_command():
    rc, out, err = _run("echo hi")
    assert rc == 0
    assert out == "hi\n"
    assert err == ""


def test_empty_command_is_noop():
    assert _run("") == (0, "", "")
    assert _run("   ") == (0, "", "")


def test_two_stage_pipe(tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("alpha\nbeta\nalpha\n")
    rc, out, err = _run(f"cat {f} | grep alpha")
    assert rc == 0
    assert out == "alpha\nalpha\n"


def test_three_stage_pipe():
    rc, out, err = _run("echo hello | cat | cat")
    assert rc == 0
    assert out == "hello\n"


def test_quoted_pipe_is_not_a_split():
    rc, out, err = _run("echo 'a | b'")
    assert rc == 0
    assert out == "a | b\n"


def test_pipe_exit_code_is_last_stage(tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("alpha\n")
    rc, out, err = _run(f"cat {f} | grep zzz")
    assert rc == 1
    assert out == ""


def test_bash_c_is_unwrapped_and_run():
    rc, out, err = _run("bash -c 'echo wrapped'")
    assert rc == 0
    assert out == "wrapped\n"


def test_timeout_prefix_is_stripped_and_runs():
    rc, out, err = _run("timeout 5 echo hi")
    assert rc == 0
    assert out == "hi\n"



def test_and_short_circuits_on_failure():
    rc, out, err = _run("false && echo nope")
    assert rc == 1
    assert "nope" not in out


def test_and_runs_tail_on_success():
    rc, out, err = _run("true && echo yes")
    assert rc == 0
    assert out == "yes\n"


def test_or_runs_tail_on_failure():
    rc, out, err = _run("false || echo fallback")
    assert rc == 0
    assert out == "fallback\n"


def test_semicolon_runs_both():
    rc, out, err = _run("echo a ; echo b")
    assert rc == 0
    assert out == "a\nb\n"


def test_newline_separates_commands():
    rc, out, err = _run("echo a\necho b")
    assert rc == 0
    assert out == "a\nb\n"



def test_cd_then_relative_read(tmp_path):
    (tmp_path / "data.txt").write_text("X")
    rc, out, err = _run(f"cd {tmp_path} && cat data.txt")
    assert rc == 0
    assert out == "X"


def test_cd_missing_dir_fails():
    rc, out, err = _run("cd /no/such/dir/xyz && echo after")
    assert rc == 1
    assert "after" not in out
    assert "No such file" in err



def test_stderr_to_devnull_is_suppressed():
    rc, out, err = _run("ls /nonexistent_path_xyz 2>/dev/null")
    assert rc != 0
    assert out == ""
    assert err == ""


def test_stderr_merged_into_stdout():
    rc, out, err = _run("ls /nonexistent_path_xyz 2>&1")
    assert rc != 0
    assert "nonexistent_path_xyz" in out
    assert err == ""


def test_devnull_in_pipe(tmp_path):
    rc, out, err = _run("cat /nonexistent_xyz 2>/dev/null | wc -l")
    assert rc == 0
    assert out.strip() == "0"
    assert err == ""


def test_default_stderr_is_captured():
    rc, out, err = _run("ls /nonexistent_zzz")
    assert rc != 0
    assert out == ""
    assert "nonexistent_zzz" in err


def test_mid_pipe_stderr_is_captured():
    rc, out, err = _run("cat /nope_aaa | wc -l")
    assert rc == 0
    assert out.strip() == "0"
    assert "nope_aaa" in err



def test_dollar_var_does_not_expand():
    rc, out, err = _run("echo $SECRET", env=_env(SECRET="topsecret-value"))
    assert out == "$SECRET\n"
    assert "topsecret-value" not in out


def test_glob_does_not_expand(tmp_path):
    (tmp_path / "a.json").write_text("{}")
    (tmp_path / "b.json").write_text("{}")
    rc, out, err = _run("echo *.json", cwd=tmp_path)
    assert out == "*.json\n"


def test_brace_does_not_expand():
    rc, out, err = _run("echo x{1,2}")
    assert out == "x{1,2}\n"



def test_command_not_found_is_127():
    rc, out, err = _run("no_such_binary_abc123")
    assert rc == 127
    assert "command not found" in err


def test_timeout_raises():
    with pytest.raises(subprocess.TimeoutExpired):
        _run("sleep 3", timeout=0.3)


def test_timeout_bounds_nonterminating_upstream():
    import shlex
    import sys
    producer = f"{sys.executable} -c " + shlex.quote(
        "import sys,time; sys.stdout.write('x\\n'); sys.stdout.flush(); time.sleep(30)"
    )
    with pytest.raises(subprocess.TimeoutExpired):
        _run(f"{producer} | head -1", timeout=0.5)


def test_non_utf8_output_does_not_crash():
    import shlex
    import sys
    emit = f"{sys.executable} -c " + shlex.quote(
        "import sys; sys.stdout.buffer.write(b'\\xff\\xfe')"
    )
    rc, out, err = _run(emit)
    assert rc == 0
    assert "�" in out


def test_unexpected_redirect_fails_closed(tmp_path):
    target = tmp_path / "should_not_write"
    with pytest.raises(bash_exec.BashExecError):
        _run(f"echo hi > {target}")
    assert not target.exists()



def test_run_parsed_empty_is_noop():
    assert bash_exec.run_parsed([], command="", env=_env(), cwd="/", timeout=10.0) == (0, "", "")
