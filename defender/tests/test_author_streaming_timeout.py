"""Streaming-loop timeout guarantee.

Regression for the case where the ``claude -p`` runner reads stream-json line by line: if
the child process stalls mid-line (no newline arrives), a naive ``for raw in proc.stdout``
blocks indefinitely and the timeout never fires. The reader must bound every read by the
remaining deadline so the lock is released and the agent killed.

NOTE (curator GLM port): the four lesson curators now run IN-PROCESS on PydanticAI, so their
``invoke_agent`` no longer spawns the ``claude -p`` subprocess these tests exercise. The runner's
select-loop driver (``invoke_claude_print`` + ``_drive_subprocess``) is KEPT (still defined, still
covered by ``test_runner_spawn_seam_is_honored``), so these timeout/deadlock guarantees are now
driven against the runner DIRECTLY (the shim on ``runner.subprocess.Popen``) rather than through a
curator's now-in-process seam — same assertions, decoupled from the retired transport wiring. The
runner raises ``RunnerError`` (the curator wrapper used to translate it to ``AuthorError``)."""
from __future__ import annotations

import time

import pytest


def _drive_runner(runner, tmp_repo, *, timeout: int, prompt: str = "the prompt"):
    """Drive the runner's subprocess select-loop DIRECTLY with a short deadline (the shim has
    swapped ``claude`` for the fake child). Mirrors ``test_runner_spawn_seam_is_honored``'s direct
    ``RunnerOptions`` construction; ``invoke_claude_print`` raises ``RunnerError`` on a timeout /
    missing marker."""
    options = runner.RunnerOptions(
        system_prompt_file=tmp_repo.root / "prompt.md",
        allowed_tools="Read",
        model="claude-x",
        effort=None,
        timeout_seconds=timeout,
        cwd=tmp_repo.root,
        log_path=tmp_repo.root / "run.jsonl",
        result_marker="AUTHOR_RESULT:",
        batch_id="test",
    )
    return runner.invoke_claude_print(options, prompt, lambda _m: None)


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

    Patches ``subprocess.Popen`` on the runner module (``_runner``, which owns the
    process spawn): when the command starts with ``claude``, swap it for
    ``[sys.executable, fake_script]``.
    """
    import sys as _sys

    runner = tmp_repo.author._runner
    real_popen = runner.subprocess.Popen

    def make(behavior: str):
        script_path = _fake_claude_script(tmp_repo.root, behavior=behavior)

        def fake_popen(cmd, *args, **kwargs):
            if cmd and cmd[0] == "claude":
                cmd = [_sys.executable, script_path]
            return real_popen(cmd, *args, **kwargs)

        monkeypatch.setattr(
            runner.subprocess, "Popen", fake_popen, raising=True
        )

    return make


def test_silent_hang_is_killed_by_wall_clock(tmp_repo, shim_claude, monkeypatch):
    """Child emits one line then stops — the runner's wall-clock deadline must still fire."""
    runner = tmp_repo.author._runner
    shim_claude("silent_hang")

    t0 = time.monotonic()
    with pytest.raises(runner.RunnerError, match="timed out after 2s"):
        _drive_runner(runner, tmp_repo, timeout=2)
    elapsed = time.monotonic() - t0
    # Generous upper bound: timeout=2s, select tick=1s, kill overhead.
    assert elapsed < 6.0, f"timeout did not fire promptly (elapsed={elapsed:.2f}s)"


def test_stdin_write_is_bounded_by_deadline(tmp_repo, shim_claude, monkeypatch):
    """Child never reads stdin; prompt > pipe buffer must not block writer."""
    runner = tmp_repo.author._runner
    shim_claude("ignore_stdin")

    # A prompt large enough to exceed the default 64KiB Linux pipe buffer — forces the writer
    # to wait for the child to drain stdin, which it never will.
    big_prompt = "y" * (128 * 1024)

    t0 = time.monotonic()
    with pytest.raises(runner.RunnerError, match="timed out after 2s"):
        _drive_runner(runner, tmp_repo, timeout=2, prompt=big_prompt)
    elapsed = time.monotonic() - t0
    assert elapsed < 6.0, f"stdin-write deadlock — elapsed={elapsed:.2f}s"


def test_stderr_flood_does_not_deadlock(tmp_repo, shim_claude, monkeypatch):
    """Child writes 256 KiB to stderr before stdout — reader drains both."""
    runner = tmp_repo.author._runner
    shim_claude("stderr_flood")

    # The fake never emits AUTHOR_RESULT, so we expect that specific error — but only if the
    # reader completed without deadlock first.
    with pytest.raises(runner.RunnerError, match="did not emit AUTHOR_RESULT"):
        _drive_runner(runner, tmp_repo, timeout=5)


def test_runner_spawn_seam_is_honored(tmp_path):
    """#373: the spawn is injectable via RunnerOptions, so the driver is exercisable
    in isolation without a real ``claude`` and without monkeypatching a module attr.
    The runner builds the ``claude`` cmd, hands it to the injected spawn, and drives
    that process through the same select-loop/raw path lead_author uses."""
    import subprocess
    import sys as _sys

    from defender.learning.author import runner as runner

    seen = {}

    def fake_spawn(cmd, **kwargs):
        seen["cmd"] = cmd  # the runner-built `claude …` argv
        seen["env"] = kwargs.get("env")  # the env threaded through to the spawn
        script = "import sys; sys.stdin.read()"  # consume prompt, exit 0
        return subprocess.Popen([_sys.executable, "-c", script], **kwargs)

    # A full env plus a sentinel: the load-bearing #425 wiring is that RunnerOptions.env
    # reaches subprocess spawn(env=...) verbatim, so the curator agent's forward-check
    # subprocesses inherit the pinned DEFENDER_LEARNING_STATE_DIR.
    import os as _os
    pinned_env = {**_os.environ, "DEFENDER_LEARNING_STATE_DIR": "/sentinel/state"}
    options = runner.RunnerOptions(
        system_prompt_file=tmp_path / "prompt.md",
        allowed_tools="Read",
        model="claude-x",
        effort=None,
        timeout_seconds=10,
        cwd=tmp_path,
        log_path=tmp_path / "run.jsonl",
        result_marker=None,
        batch_id="t",
        env=pinned_env,
        spawn=fake_spawn,
    )
    rc, _text = runner.invoke_claude_print_raw(options, "the prompt", lambda _m: None)
    assert rc == 0
    assert seen["cmd"][0] == "claude"
    assert "--allowed-tools" in seen["cmd"]
    # The pinned env threads through unchanged (RunnerOptions.env → _drive_subprocess → spawn).
    assert seen["env"] is not None
    assert seen["env"]["DEFENDER_LEARNING_STATE_DIR"] == "/sentinel/state"
