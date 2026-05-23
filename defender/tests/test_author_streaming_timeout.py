"""Streaming-loop timeout guarantee.

Regression for the case where ``invoke_agent`` reads stream-json line
by line: if the child process stalls mid-line (no newline arrives),
a naive ``for raw in proc.stdout`` blocks indefinitely and
``AUTHOR_TIMEOUT`` never fires. The reader must bound every read by
the remaining deadline so the lock is released and the agent killed.
"""
from __future__ import annotations

import time

import pytest


def _fake_claude_script(repo, *, behavior: str) -> str:
    """Write a tiny python script that masquerades as the claude CLI.

    Behaviors:
      - "silent_hang": print one valid stream-json line, then sleep
        forever without emitting another newline. Verifies the
        select-based reader kills the child via the wall-clock deadline.
      - "stderr_flood": write past the 64KiB stderr pipe to confirm
        the reader drains stderr so the child can't deadlock on a
        full pipe.
    """
    path = repo / "fake_claude.py"
    if behavior == "silent_hang":
        body = (
            'import sys, time\n'
            'sys.stdin.read()\n'  # consume the input prompt
            'sys.stdout.write(\'{"type":"system","subtype":"init"}\\n\')\n'
            'sys.stdout.flush()\n'
            'time.sleep(60)\n'  # well past AUTHOR_TIMEOUT in the test
        )
    elif behavior == "stderr_flood":
        body = (
            'import sys, time\n'
            'sys.stdin.read()\n'
            'sys.stderr.write("x" * (256 * 1024))\n'  # 256 KiB > 64 KiB pipe
            'sys.stderr.flush()\n'
            'sys.stdout.write(\'{"type":"result","subtype":"success"}\\n\')\n'
            'sys.stdout.flush()\n'
        )
    elif behavior == "ignore_stdin":
        # Never read stdin — exercises the path where the prompt
        # exceeds the pipe buffer and the parent must not deadlock
        # in proc.stdin.write().
        body = (
            'import sys, time\n'
            'time.sleep(60)\n'
        )
    else:
        raise ValueError(behavior)
    path.write_text(body)
    return str(path)


@pytest.fixture
def shim_claude(tmp_repo, monkeypatch):
    """Replace the `claude` invocation with a controllable python script.

    Patches subprocess.Popen at the author module level: when the
    command starts with ``claude``, swap it for ``[sys.executable, fake_script]``.
    """
    import subprocess as _sub
    import sys as _sys

    real_popen = _sub.Popen

    def make(behavior: str):
        script_path = _fake_claude_script(tmp_repo.root, behavior=behavior)

        def fake_popen(cmd, *args, **kwargs):
            if cmd and cmd[0] == "claude":
                cmd = [_sys.executable, script_path]
            return real_popen(cmd, *args, **kwargs)

        monkeypatch.setattr(
            tmp_repo.author.subprocess, "Popen", fake_popen, raising=True
        )

    return make


def test_silent_hang_is_killed_by_wall_clock(tmp_repo, shim_claude, monkeypatch):
    """Child emits one line then stops — AUTHOR_TIMEOUT must still fire."""
    a = tmp_repo.author
    monkeypatch.setattr(a, "AUTHOR_TIMEOUT", 2)  # seconds
    shim_claude("silent_hang")

    t0 = time.monotonic()
    with pytest.raises(a.AuthorError, match="timed out after 2s"):
        a.invoke_agent([{"finding_id": "x"}], batch_id="test")
    elapsed = time.monotonic() - t0
    # Generous upper bound: timeout=2s, select tick=1s, kill overhead.
    assert elapsed < 6.0, f"timeout did not fire promptly (elapsed={elapsed:.2f}s)"


def test_stdin_write_is_bounded_by_deadline(tmp_repo, shim_claude, monkeypatch):
    """Child never reads stdin; prompt > pipe buffer must not block writer."""
    a = tmp_repo.author
    monkeypatch.setattr(a, "AUTHOR_TIMEOUT", 2)
    shim_claude("ignore_stdin")

    # Findings list large enough that json.dumps(...) exceeds the
    # default 64KiB Linux pipe buffer — forces the writer to wait
    # for the child to drain stdin, which it never will.
    big = {"finding_id": "x", "blob": "y" * (128 * 1024)}

    t0 = time.monotonic()
    with pytest.raises(a.AuthorError, match="timed out after 2s"):
        a.invoke_agent([big], batch_id="test")
    elapsed = time.monotonic() - t0
    assert elapsed < 6.0, f"stdin-write deadlock — elapsed={elapsed:.2f}s"


def test_stderr_flood_does_not_deadlock(tmp_repo, shim_claude, monkeypatch):
    """Child writes 256 KiB to stderr before stdout — reader drains both."""
    a = tmp_repo.author
    monkeypatch.setattr(a, "AUTHOR_TIMEOUT", 5)
    shim_claude("stderr_flood")

    # The fake never emits AUTHOR_RESULT, so we expect that specific
    # error — but only if the reader completed without deadlock first.
    with pytest.raises(a.AuthorError, match="did not emit AUTHOR_RESULT"):
        a.invoke_agent([{"finding_id": "x"}], batch_id="test")
