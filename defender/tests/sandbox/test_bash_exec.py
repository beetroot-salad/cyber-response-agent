"""Tests for defender/execution/bash_exec.py — the shell=False executor."""
from __future__ import annotations

import os
import subprocess

import pytest

from defender.execution import bash_exec


def _env(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env.update(extra)
    return env


def _run_raw(cmd: str, *, env=None, cwd="/", timeout: float = 10.0) -> tuple[int, bytes, bytes]:
    """The helper's own bytes (#1421: it works in raw bytes, nothing decoded or re-encoded)."""
    return bash_exec.run_parsed(
        bash_exec.parse(cmd), command=cmd, env=env or _env(), cwd=cwd, timeout=timeout,
    )


def _run(cmd: str, *, env=None, cwd="/", timeout: float = 10.0):
    rc, out, err = _run_raw(cmd, env=env, cwd=cwd, timeout=timeout)
    return rc, out.decode("utf-8"), err.decode("utf-8")


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


@pytest.mark.parametrize(("cmd", "rc", "out"), [
    ("echo hello | cat | cat", 0, "hello\n"),        # pipes chain past two stages
    ("echo 'a | b'", 0, "a | b\n"),                  # a QUOTED pipe is data, not a split
    ("bash -c 'echo wrapped'", 0, "wrapped\n"),      # `bash` is an ordinary program here
    ("timeout 5 echo hi", 0, "hi\n"),                # ...and so is `timeout`
    ("true && echo yes", 0, "yes\n"),                # && runs the tail on success ...
    ("false && echo nope", 1, ""),                   # ... and skips it on failure
    ("false || echo fallback", 0, "fallback\n"),     # ... and || runs it on failure
    ("echo a ; echo b", 0, "a\nb\n"),                # `;` runs both, in order
    ("echo a\necho b", 0, "a\nb\n"),                 # a bare NEWLINE separates commands too
], ids=lambda v: v if isinstance(v, str) and "\n" not in v else "")
def test_a_composed_command_runs_and_returns_exactly_bashs_output(cmd, rc, out):
    """Each form composes as bash composes it; exact stdout makes a dropped stage visible, not plausible."""
    assert _run(cmd)[:2] == (rc, out)


def test_pipe_exit_code_is_last_stage(tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("alpha\n")
    rc, out, err = _run(f"cat {f} | grep zzz")
    assert rc == 1
    assert out == ""


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
    assert _run_raw(emit) == (0, b"\xff\xfe", b"")


@pytest.mark.parametrize("cmd", [
    "echo a\n| grep a",
    "echo a |\ngrep a",
    "echo a\n&& echo b",
    "echo a &&\necho b",
    "echo a\n|| echo b",
    "echo a ||\necho b",
    "echo a && ;\necho b",
    "echo a || ;\necho b",
    "| grep a",
    "cat /etc/hostname | ; grep a",
    "cat /etc/hostname | && grep a",
    "cat /etc/hostname | || grep a",
    "cat /etc/hostname | | grep a",
    "cat /etc/hostname | ;",
    "cat /etc/hostname | 2> /dev/null",
])
def test_incomplete_connector_fails_closed(cmd):
    with pytest.raises(bash_exec.UntokenizableCommand):
        _run(cmd)


@pytest.mark.parametrize(("cmd", "out"), [
    ("echo a | grep a | wc -l", "1\n"),   # cur_argv is non-empty at the second `|`
    ("echo a ; ; echo b", "a\nb\n"),      # the leading-`;` carve-out drops NOTHING
    ("echo a 2>&1 | wc -l", "1\n"),       # a stderr redirect is not an empty right side
    ("echo a && ; echo b", "a\nb\n"),
    ("echo a ;\necho b", "a\nb\n"),      # `;` closes a FINISHED command: not a dangling connector
])
def test_the_dangling_pipe_guard_leaves_real_pipelines_alone(cmd, out):
    """Positive control for the guard above: real pipelines still run (refusal-only tests cannot catch over-refusal)."""
    rc, got, _err = _run(cmd)
    assert rc == 0
    assert got == out


def test_unexpected_redirect_fails_closed(tmp_path):
    target = tmp_path / "should_not_write"
    with pytest.raises(bash_exec.BashExecError):
        _run(f"echo hi > {target}")
    assert not target.exists()


def test_run_parsed_empty_is_noop():
    assert bash_exec.run_parsed([], command="", env=_env(), cwd="/", timeout=10.0) == (0, b"", b"")


# ---- #1421: one output budget, kills named, start failures framed, raw bytes ----------------

import errno  # noqa: E402
import resource  # noqa: E402
import shlex  # noqa: E402
import signal  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402

from defender import box as box_mod  # noqa: E402
from defender.execution import box_codec  # noqa: E402
from defender.tests.support.shared.contracts._by_path import DEFENDER  # noqa: E402

OVER_BUDGET_RC = 75
HEADER = len(box_codec.encode_response(box_codec.BoxResult(rc=0, out=b"", err=b"")))
#: What one command may print in all: the host fence's limit less the frame's own header.
BUDGET = box_mod.BOX_OUTPUT_LIMIT - HEADER


def _py(source: str) -> str:
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(source)}"


def _write(fd: int, size: int, byte: str = "x") -> str:
    whole, rest = divmod(size, 1 << 20)
    return _py(f"import os; [os.write({fd}, b'{byte}' * (1 << 20)) for _ in range({whole})]; "
               f"os.write({fd}, b'{byte}' * {rest})" if rest else
               f"import os; [os.write({fd}, b'{byte}' * (1 << 20)) for _ in range({whole})]")


def _entrypoint(cmd: str, *, cwd=None, preexec=None, timeout: int = 60) -> tuple[int, box_codec.BoxResult | None, bytes]:
    """The in-box process as `docker exec` runs it: a request frame in, a response frame out.
    Returns the process's own exit status, the decoded frame (None if it is no frame), stderr."""
    env = _env(DEFENDER_BOX_TIMEOUT=str(timeout), PYTHONPATH=str(DEFENDER.parent))
    proc = subprocess.run(
        [sys.executable, "-P", "-m", "defender.execution.bash_exec"],
        input=box_codec.encode_request(bash_exec.parse(cmd)), capture_output=True, env=env,
        cwd=cwd, preexec_fn=preexec, timeout=timeout + 30)
    try:
        frame = box_codec.decode_response(proc.stdout)
    except box_codec.BoxFault:
        frame = None
    return proc.returncode, frame, proc.stderr


def _one_line(err: bytes) -> bytes:
    lines = [ln for ln in err.splitlines() if ln.strip()]
    assert len(lines) == 1, err[:400]
    assert len(err.strip()) <= 160, f"P1: the digest keeps 160 characters: {err!r}"
    return err


def test_the_budget_is_the_fences_limit_less_the_frames_header_and_lives_beside_the_codec():
    """One figure for both trust levels; the codec owns it and `box` re-exports it. (O5, P4)"""
    assert box_codec.BOX_OUTPUT_LIMIT == box_mod.BOX_OUTPUT_LIMIT == 64 << 20


@pytest.mark.parametrize("over", [0, 1], ids=["exactly-at-budget", "one-byte-over"])
@pytest.mark.parametrize("shape", ["stdout", "both-streams", "cd-error"])
def test_o5_a_command_at_the_budget_passes_and_one_byte_more_is_stopped_with_exit_75(shape, over, tmp_path):
    """Everything entering the frame is charged, `cd` errors included; the frame at the budget
    cannot trip the host fence, which is the same figure. (O5, P4)"""
    target = "d" * 200
    cd_error = len(_run_raw(f"cd {target}", cwd=tmp_path)[2])
    total = BUDGET + over
    cmd, expected_rc = {
        "stdout": (_write(1, total), 0),
        "both-streams": (f"{_write(1, total // 2)} ; {_write(2, total - total // 2)}", 0),
        "cd-error": (f"{_write(1, total - cd_error)} ; cd {target}", 1),
    }[shape]
    status, frame, _ = _entrypoint(cmd, cwd=tmp_path)
    assert status == 0
    assert frame is not None
    if over == 0:
        assert frame.rc == expected_rc
        assert len(frame.out) + len(frame.err) == BUDGET
        assert len(box_codec.encode_response(frame)) == box_mod.BOX_OUTPUT_LIMIT
    else:
        assert frame.rc == OVER_BUDGET_RC
        assert frame.out == b""
        _one_line(frame.err)


def test_o5_stderr_counts_against_the_budget_and_never_fills_the_scratch_disk(tmp_path):
    """Stderr rides a pipe read in the same loop, so a file limit that would have stopped a temp
    file (the box's /tmp is 64 MiB) does not stop it. (O5)"""
    def small_files():
        resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)

    status, frame, _ = _entrypoint(_write(2, 4 << 20), cwd=tmp_path, preexec=small_files)
    assert frame is not None
    assert (frame.rc, len(frame.err)) == (0, 4 << 20)


def test_o5_the_first_pipeline_that_breaks_the_budget_stops_the_command_and_drops_what_it_held(tmp_path):
    """Earlier output goes too; the later pipeline never runs; the reason is not the kill line. (O5, O6)"""
    cmd = f"echo earlier ; {_write(2, BUDGET // 2 + 1)} | cat ; {_write(2, BUDGET // 2 + 1)} ; touch later"
    status, frame, _ = _entrypoint(cmd, cwd=tmp_path)
    assert frame is not None
    assert (frame.rc, frame.out) == (OVER_BUDGET_RC, b"")
    assert b"earlier" not in frame.err
    assert not (tmp_path / "later").exists()
    kill = _entrypoint(f"{_py('import os; os.kill(os.getpid(), 9)')} ; touch later2", cwd=tmp_path)[1]
    assert kill is not None
    assert _one_line(kill.err) != _one_line(frame.err), "the helper's own stop read as a kill"


KILLS = (signal.SIGKILL, signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS)


def _dies(sig: int) -> str:
    return f"sh -c {shlex.quote(f'echo partial-out; echo errmarker >&2; kill -{int(sig)} $$')}"


@pytest.mark.parametrize("last", ["cat", "head -c 3", "wc -c"], ids=["cat", "head", "wc"])
@pytest.mark.parametrize("sig", KILLS, ids=[s.name for s in KILLS])
def test_o6_a_stage_dying_on_a_kill_or_crash_gives_its_signal_one_fixed_line_and_nothing_else(sig, last, tmp_path):
    """Upstream of a last stage that exits 0 included; stdout, stderr and the pipelines before
    it are dropped; no pipeline after it runs. (O6)"""
    cmd = f"echo earlier ; {_dies(sig)} | {last} ; touch later"
    status, frame, _ = _entrypoint(cmd, cwd=tmp_path)
    assert frame is not None
    assert frame.rc == -int(sig)
    assert frame.out == b""
    line = _one_line(frame.err).decode()
    assert "memory" in line.lower(), line
    assert "errmarker" not in line
    assert "earlier" not in line
    assert not (tmp_path / "later").exists()


def test_o6_every_kill_gets_the_same_line_whatever_the_signal_or_the_command(tmp_path):
    """The digest is the pitfall's merge key and already carries the exit code: no variable parts. (O6, P1)"""
    lines = {_entrypoint(f"{_dies(sig)} | cat", cwd=tmp_path)[1].err for sig in KILLS}
    lines.add(_entrypoint(f"echo other ; {_dies(signal.SIGKILL)}", cwd=tmp_path)[1].err)
    assert len(lines) == 1, lines
    assert "exit=" not in next(iter(lines)).decode()


def test_o6_control_sigpipe_upstream_of_head_is_the_normal_case_and_keeps_everything(tmp_path):
    """-13 is not a kill: the output stays, the exit is the last stage's, the next pipeline runs. (O6)"""
    status, frame, _ = _entrypoint("yes | head -n 1 ; touch later", cwd=tmp_path)
    assert frame is not None
    assert (frame.rc, frame.out) == (0, b"y\n")
    assert (tmp_path / "later").exists()


def test_o6_control_a_stage_exiting_137_on_its_own_is_not_a_kill(tmp_path):
    """Only a signal death is a kill; an exit code of 137 keeps its output and code. (O6)"""
    status, frame, _ = _entrypoint("sh -c 'echo kept; echo e >&2; exit 137'", cwd=tmp_path)
    assert frame is not None
    assert (frame.rc, frame.out, frame.err) == (137, b"kept\n", b"e\n")


def test_o5_the_stderr_of_every_stage_shares_one_pipe_in_the_order_it_was_written():
    """Interleaving across stages is kept when stderr leaves the temp file. (O5)"""
    first = _py("import sys, time; sys.stderr.write('1'); sys.stderr.flush(); time.sleep(0.5); "
                "sys.stderr.write('3'); sys.stderr.flush()")
    second = _py("import sys, time; time.sleep(0.25); sys.stderr.write('2'); sys.stderr.flush()")
    rc, out, err = _run_raw(f"{first} | {second}")
    assert err == b"123", err


def test_a_forked_daemon_holding_stderr_does_not_hold_the_command(tmp_path):
    """The shared pipe stays open in the daemon; the command ends when stdout is done and every stage exited. (O5)"""
    daemon = _py("import subprocess, sys; subprocess.Popen(['sleep', '12'], stdout=subprocess.DEVNULL, "
                 "stderr=sys.stderr); print('ok')")
    started = time.monotonic()
    rc, out, err = _run_raw(daemon, timeout=40)
    assert (rc, out) == (0, b"ok\n")
    assert time.monotonic() - started < 8, "the helper waited for the daemon's copy of the pipe"


@pytest.mark.parametrize(("kind", "code"), [
    ("E2BIG", errno.E2BIG), ("ENOTDIR", errno.ENOTDIR), ("ENOEXEC", errno.ENOEXEC),
])
def test_a_stage_that_cannot_start_for_any_other_reason_is_rc_126_with_the_systems_text(kind, code, tmp_path):
    """Keyed on errno; the text is the system's, like the permission branch. (O6)"""
    garbage = tmp_path / "garbage"
    garbage.write_bytes(b"\x01\x02not a program\x00")
    garbage.chmod(0o755)
    program = {"E2BIG": f"cat {'a' * 200_000}", "ENOTDIR": "/etc/hostname/not-a-dir",
               "ENOEXEC": str(garbage)}[kind]
    rc, out, err = _run_raw(program, cwd=tmp_path)
    assert (rc, out) == (126, b""), (rc, err[:200])
    assert os.strerror(code).encode() in err


def test_a_stage_that_cannot_start_for_want_of_a_process_names_the_process_cap(tmp_path):
    """EAGAIN from a real per-user process limit: rc 126 and one fixed line naming the cap, not the system's text. (O6)"""
    def capped():
        if os.geteuid() == 0:
            os.setgid(65534)
            os.setuid(65534)
        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))

    probe = subprocess.run(["true"], preexec_fn=capped, capture_output=True)
    if probe.returncode != 0 and os.geteuid() == 0:
        pytest.skip("cannot run as the unprivileged user here")
    status, frame, err = _entrypoint("echo hi", cwd=tmp_path, preexec=capped)
    assert frame is not None, err[-400:]
    assert (frame.rc, frame.out) == (126, b"")
    line = _one_line(frame.err).decode().lower()
    assert "process" in line, line
    assert os.strerror(errno.EAGAIN).lower() not in line


def test_an_unplanned_failure_in_the_helper_still_returns_a_frame(tmp_path):
    """A working directory that vanished under the command: a frame, not a traceback and no frame at all. (O6)"""
    gone = tmp_path / "gone"
    gone.mkdir()
    status, frame, err = _entrypoint("echo hi", cwd=gone, preexec=lambda: os.rmdir(gone))
    assert frame is not None, err[-400:]
    assert frame.rc != 0
    assert frame.out == b""
    _one_line(frame.err)
    assert b"Traceback" not in frame.err


def test_cd_errors_are_returned_as_bytes_and_charged_like_everything_else(tmp_path):
    """`run_parsed` returns bytes for every part, the `cd` error included. (O5)"""
    rc, out, err = _run_raw("cd nowhere-at-all", cwd=tmp_path)
    assert (rc, out) == (1, b"")
    assert isinstance(err, bytes)
    assert b"nowhere-at-all" in err
