"""Shared subprocess driver for the two learning-loop authors.

`defender/learning/author.py` and `defender/learning/author_actor.py`
both spawn a `claude -p` curator agent with stream-json output and the
same select-loop discipline (non-blocking stdin, bounded deadline,
stderr drain, line-buffered stdout, tee to disk). This module factors
that machinery so the two callers don't drift.

The driver is generic over:
  - the system-prompt file
  - the user-prompt text
  - the allowed-tools spec
  - the result marker (e.g. ``AUTHOR_RESULT:``)

Callers supply the model + timeout + log-line callback. The driver
returns the parsed result JSON or raises ``RunnerError``.
"""
from __future__ import annotations

import fcntl as _fcntl
import json
import os
import re
import select as _select
import subprocess
import sys
import time as _time
from pathlib import Path
from typing import Callable


class RunnerError(Exception):
    """Fatal subprocess error — caller decides whether to retry."""


# ---------------------------------------------------------------------------
# Result extraction
# ---------------------------------------------------------------------------


def extract_marked_result(text: str, marker: str) -> str | None:
    """Return the JSON object body following the last ``marker`` occurrence.

    Walks forward from the opening brace counting balanced braces while
    respecting JSON string quoting; this handles nested objects/arrays
    that a non-greedy regex would truncate. Returns ``None`` if no
    marker or no balanced object is found. ``marker`` is treated as a
    literal prefix; trailing whitespace before ``{`` is tolerated.
    """
    pat = re.compile(re.escape(marker) + r"\s*(?=\{)")
    matches = list(pat.finditer(text))
    if not matches:
        return None
    start = matches[-1].end()
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


# ---------------------------------------------------------------------------
# Stream-json event helpers (used to summarize progress to stderr)
# ---------------------------------------------------------------------------


def summarize_event(evt: dict) -> str | None:
    """One-liner for a stream-json event; ``None`` to suppress."""
    etype = evt.get("type")
    if etype == "system":
        return f"system subtype={evt.get('subtype')}"
    if etype == "assistant":
        msg = evt.get("message") or {}
        for blk in msg.get("content") or []:
            btype = blk.get("type")
            if btype == "tool_use":
                name = blk.get("name", "?")
                inp = blk.get("input") or {}
                if name == "Bash":
                    cmd = (inp.get("command") or "").splitlines()[0][:120]
                    return f"tool:Bash {cmd}"
                if name in ("Read", "Glob", "Grep"):
                    target = inp.get("file_path") or inp.get("pattern") or ""
                    return f"tool:{name} {target}"
                if name in ("Edit", "Write"):
                    return f"tool:{name} {inp.get('file_path', '')}"
                return f"tool:{name}"
            if btype == "text":
                txt = (blk.get("text") or "").strip().splitlines()
                head = txt[0][:140] if txt else ""
                return f"text {head}" if head else None
        return "assistant (empty)"
    if etype == "user":
        msg = evt.get("message") or {}
        for blk in msg.get("content") or []:
            if blk.get("type") == "tool_result":
                content = blk.get("content")
                if isinstance(content, list):
                    body = "".join(
                        b.get("text", "") for b in content if isinstance(b, dict)
                    )
                else:
                    body = str(content or "")
                size = len(body)
                err = " ERR" if blk.get("is_error") else ""
                return f"tool_result{err} {size}B"
        return None
    if etype == "result":
        return f"result subtype={evt.get('subtype')} duration_ms={evt.get('duration_ms')}"
    return None


def assistant_text(evt: dict) -> str:
    """Concatenate assistant text blocks from one event; empty otherwise."""
    if evt.get("type") != "assistant":
        return ""
    msg = evt.get("message") or {}
    out = []
    for blk in msg.get("content") or []:
        if blk.get("type") == "text":
            out.append(blk.get("text") or "")
    return "".join(out)


# ---------------------------------------------------------------------------
# Verifier python resolution (shared so author_actor inherits the same
# rules; verify_forward isn't used by the actor side but the .venv
# resolution discipline is identical).
# ---------------------------------------------------------------------------


def resolve_verifier_python(repo_root: Path) -> Path:
    """Locate a python interpreter that has pyyaml available.

    Preference order: env override → ``defender/.venv/bin/python3`` next
    to repo root → walking up the parents (so a git-worktree without its
    own venv resolves to the parent checkout's) → ``sys.executable``.
    """
    env = os.environ.get("LEARNING_VERIFIER_PYTHON")
    if env:
        return Path(env).resolve()
    candidates = [repo_root / "defender" / ".venv" / "bin" / "python3"]
    p = repo_root.resolve().parent
    for _ in range(5):
        cand = p / "defender" / ".venv" / "bin" / "python3"
        if cand.is_file():
            candidates.append(cand)
        if p.parent == p:
            break
        p = p.parent
    for c in candidates:
        if c.is_file():
            # Do NOT resolve() — venv launchers are typically symlinks
            # that point to the system interpreter, but pyyaml lives in
            # the venv's site-packages reachable only via the venv path.
            return c
    return Path(sys.executable)


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def invoke_claude_print(
    *,
    system_prompt_file: Path,
    user_prompt: str,
    allowed_tools: str,
    model: str,
    effort: str | None,
    timeout_seconds: int,
    cwd: Path,
    log_path: Path,
    result_marker: str,
    log_fn: Callable[[str], None],
    batch_id: str,
) -> dict:
    """Spawn ``claude -p`` with stream-json output and return the parsed
    result JSON the agent emitted after ``result_marker``.

    Streams events to ``log_path`` (one JSONL line per event, plus a
    leading metadata line) and feeds one-line summaries to ``log_fn``
    for stderr surfacing.

    Raises ``RunnerError`` on timeout, non-zero rc, missing marker, or
    invalid JSON. The caller is responsible for treating the queue as
    intact on any of these failures.
    """
    cmd = [
        "claude",
        "--print",
        "--model", model,
        "--system-prompt-file", str(system_prompt_file),
        "--output-format", "stream-json",
        "--verbose",
        "--include-hook-events",
        *(["--effort", effort] if effort else []),
        "--allowed-tools", allowed_tools,
    ]

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = log_path.open("wb")
    log_fh.write(
        (json.dumps({"batch_id": batch_id, "started_at": _now_iso()}) + "\n").encode()
    )
    log_fh.flush()

    # Binary streams + manual line buffering: a text-mode iterator
    # (`for raw in proc.stdout`) blocks waiting for a newline, so the
    # wall-clock check below never fires when the child stops emitting
    # mid-line (stuck child, hung tool). select() on raw fds bounds
    # every read by the remaining deadline. stderr is drained in the
    # same loop so a full stderr pipe (64KiB on Linux) cannot deadlock
    # the child either. stdin is written through the same select loop
    # so a child that hangs before reading the prompt cannot block the
    # parent in write() — the prompt JSON regularly clears 64KiB.
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None

    # Start the deadline *before* we touch stdin — a hung child must
    # not give us an unbounded grace period during prompt delivery.
    deadline = _time.monotonic() + timeout_seconds

    stdin_fd = proc.stdin.fileno()
    _fcntl.fcntl(stdin_fd, _fcntl.F_SETFL, _fcntl.fcntl(stdin_fd, _fcntl.F_GETFL) | os.O_NONBLOCK)
    prompt_bytes = user_prompt.encode()

    text_buf: list[str] = []
    stderr_chunks: list[bytes] = []
    stdout_buf = b""
    t0 = _time.monotonic()

    def _handle_line(raw: bytes) -> None:
        log_fh.write(raw + b"\n")
        log_fh.flush()
        try:
            line = raw.decode("utf-8", errors="replace").strip()
        except Exception:
            return
        if not line:
            return
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            return
        text_buf.append(assistant_text(evt))
        summary = summarize_event(evt)
        if summary:
            elapsed = _time.monotonic() - t0
            log_fn(f"+{elapsed:5.1f}s {summary}")

    rc: int | None = None
    try:
        stdout_fd = proc.stdout.fileno()
        stderr_fd = proc.stderr.fileno()
        open_read_fds: set[int] = {stdout_fd, stderr_fd}
        stdin_offset = 0
        stdin_closed = False
        while open_read_fds or not stdin_closed:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                proc.kill()
                raise RunnerError(
                    f"agent timed out after {timeout_seconds}s (see {log_path})"
                )
            # Cap the select wait so the deadline check runs at least
            # once per second even when the child is fully silent.
            write_fds = [stdin_fd] if not stdin_closed else []
            ready_r, ready_w, _x = _select.select(
                list(open_read_fds), write_fds, [], min(remaining, 1.0)
            )
            if not ready_r and not ready_w:
                continue
            for fd in ready_r:
                chunk = os.read(fd, 65536)
                if not chunk:
                    open_read_fds.discard(fd)
                    continue
                if fd == stdout_fd:
                    stdout_buf += chunk
                    while b"\n" in stdout_buf:
                        raw, stdout_buf = stdout_buf.split(b"\n", 1)
                        _handle_line(raw)
                else:
                    stderr_chunks.append(chunk)
            if ready_w and not stdin_closed:
                try:
                    n = os.write(stdin_fd, prompt_bytes[stdin_offset:])
                except BlockingIOError:
                    n = 0
                except BrokenPipeError:
                    # Child closed stdin before we finished — finish the
                    # read loop and surface rc/stderr the caller sees.
                    stdin_closed = True
                    proc.stdin.close()
                    n = 0
                stdin_offset += n
                if stdin_offset >= len(prompt_bytes):
                    proc.stdin.close()
                    stdin_closed = True
        if stdout_buf.strip():
            _handle_line(stdout_buf)
        rc = proc.wait(timeout=max(1.0, deadline - _time.monotonic()))
    except subprocess.TimeoutExpired:
        proc.kill()
        raise RunnerError(
            f"agent timed out after {timeout_seconds}s (see {log_path})"
        )
    finally:
        log_fh.close()

    stderr_tail = b"".join(stderr_chunks).decode("utf-8", errors="replace")[-2000:]
    if rc != 0:
        raise RunnerError(f"agent failed (rc={rc}):\nstderr: {stderr_tail}")
    full_text = "".join(text_buf)
    body = extract_marked_result(full_text, result_marker)
    if body is None:
        raise RunnerError(
            f"agent did not emit {result_marker} line:\n" + full_text[-2000:]
        )
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        raise RunnerError(f"{result_marker} JSON invalid: {e}\n{body}") from e


def _now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
