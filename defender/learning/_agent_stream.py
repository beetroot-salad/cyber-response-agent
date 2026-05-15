"""Shared streaming-loop machinery for the defender learning-loop authors.

Both ``author.py`` (gap-side lessons curator) and ``lead_author.py``
(executed-side query-template curator) spawn ``claude --print
--output-format stream-json`` and need:

  * select-based reader with a wall-clock deadline (no naive ``for line
    in proc.stdout`` — that blocks forever on a child that stalls
    mid-line),
  * stderr drain in the same loop (a full 64 KiB stderr pipe can
    deadlock the child otherwise),
  * non-blocking stdin write so a giant prompt can't deadlock the
    parent before the child reads,
  * per-event summarization to stderr in real time so a stuck Bash /
    Read / Edit call is visible.

This module owns those three concerns. Callers wrap exceptions:
``author.py`` translates ``AgentStreamError`` to ``AuthorError``;
``lead_author.py`` translates to ``LeadAuthorError``. The translation
preserves each caller's public test contract while letting the
streaming machinery itself be shared.
"""
from __future__ import annotations

import fcntl as _fcntl
import json
import os
import select as _select
import subprocess
import sys
import time as _time
from pathlib import Path
from typing import Any, Callable


class AgentStreamError(Exception):
    """Raised by the streaming layer on timeout / non-zero exit / decode failure."""


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
    """Concatenate assistant text blocks from one event."""
    if evt.get("type") != "assistant":
        return ""
    msg = evt.get("message") or {}
    out = []
    for blk in msg.get("content") or []:
        if blk.get("type") == "text":
            out.append(blk.get("text") or "")
    return "".join(out)


def run_streaming(
    cmd: list[str],
    *,
    user_prompt: str,
    cwd: Path | str,
    timeout_seconds: int,
    log_path: Path,
    log_header: dict | None = None,
    log_prefix: str = "agent",
    on_event: Callable[[dict], None] | None = None,
) -> str:
    """Spawn ``cmd``, write ``user_prompt`` to stdin, return concatenated assistant text.

    The reader:
      * drains stdout + stderr through select() with a per-iteration
        deadline tick, so a silent child still gets killed at
        ``timeout_seconds``,
      * writes stdin non-blocking through the same select loop, so an
        oversize prompt can't deadlock the parent before the child
        starts reading,
      * tees every line to ``log_path`` and prints summaries to stderr.

    Raises ``AgentStreamError`` on timeout / non-zero exit / decode
    failure. The caller is responsible for parsing whatever marker its
    agent emits inside the returned assistant text.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = log_path.open("wb")
    if log_header is None:
        log_header = {}
    log_fh.write((json.dumps(log_header) + "\n").encode())
    log_fh.flush()

    # Binary streams + manual line buffering: a text-mode iterator
    # (`for raw in proc.stdout`) blocks waiting for a newline, so the
    # wall-clock check below never fires when the child stops emitting
    # mid-line. select() on the raw fds lets us bound every read by the
    # remaining deadline.
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
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
    _fcntl.fcntl(
        stdin_fd, _fcntl.F_SETFL, _fcntl.fcntl(stdin_fd, _fcntl.F_GETFL) | os.O_NONBLOCK
    )
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
            print(f"[{log_prefix}] +{elapsed:5.1f}s {summary}", file=sys.stderr)
        if on_event is not None:
            try:
                on_event(evt)
            except Exception:
                pass

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
                raise AgentStreamError(
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
                    # read loop and surface the rc/stderr the caller sees.
                    stdin_closed = True
                    proc.stdin.close()
                    n = 0
                stdin_offset += n
                if stdin_offset >= len(prompt_bytes):
                    proc.stdin.close()
                    stdin_closed = True
        # Flush any trailing partial stdout line (no terminating newline).
        if stdout_buf.strip():
            _handle_line(stdout_buf)
        rc = proc.wait(timeout=max(1.0, deadline - _time.monotonic()))
    except subprocess.TimeoutExpired:
        proc.kill()
        raise AgentStreamError(
            f"agent timed out after {timeout_seconds}s (see {log_path})"
        )
    finally:
        log_fh.close()

    stderr_tail = b"".join(stderr_chunks).decode("utf-8", errors="replace")[-2000:]
    if rc != 0:
        raise AgentStreamError(f"agent failed (rc={rc}):\nstderr: {stderr_tail}")
    return "".join(text_buf)


def extract_marker_json(text: str, marker_re: Any) -> str | None:
    """Return the JSON object body following the last match of ``marker_re``.

    Walks forward from the opening brace counting balanced braces while
    respecting JSON string quoting; this handles nested objects/arrays
    that a non-greedy regex would truncate. Returns ``None`` if no
    marker or no balanced object is found.
    """
    matches = list(marker_re.finditer(text))
    if not matches:
        return None
    start = matches[-1].end()  # index of the '{'
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
