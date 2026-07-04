"""The ``claude -p`` transport shared by the ``claude -p`` pipeline stages (oracle,
curators).

One-shot subprocess invocation (stream-json parsing, the settings/add-dir/
permission-mode flags) plus the small prompt-assembly helper ``_section``. The stage
drivers under ``pipeline/`` call ``_run_claude``; the ``Subagents`` adapter in
``core/subagents.py`` composes it. A future Agent-SDK transport swaps this module
without touching the stages.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from defender.learning.core.config import (
    RunUnprocessable,
    REPO_ROOT,
    SUBAGENT_TIMEOUT,
    subscription_env,
)


def _run_claude(
    system_prompt_path: Path,
    user_prompt: str,
    model: str,
    *,
    settings_path: Path | None = None,
    add_dir: Path | list[Path] | None = None,
    permission_mode: str | None = None,
    session_id: str | None = None,
    effort: str | None = None,
) -> str:
    """One-shot ``claude -p`` call, returning concatenated assistant text.

    Optional kwargs scope the tool surface (settings + add-dir + permission-mode)
    and pin the session id so the caller can copy the persistent transcript after
    the call. ``effort`` pins reasoning depth; None inherits the global default.

    stream-json + concat all assistant text messages: `--output-format text`
    returns only the final assistant message, silently dropping earlier assistant
    text when the prompt does tool calls mid-output (e.g. the actor emits Section 0,
    consults the lessons corpus, then emits Sections 1-3). Concatenating across
    messages keeps the prompt's design intent intact regardless of tool use.
    """
    cmd = [
        "claude",
        "-p",
        "--model", model,
        "--output-format", "stream-json",
        "--verbose",  # required for stream-json with -p
        "--system-prompt-file", str(system_prompt_path),
    ]
    if effort is not None:
        cmd += ["--effort", effort]
    if settings_path is not None:
        cmd += ["--settings", str(settings_path)]
    if add_dir is not None:
        for d in (add_dir if isinstance(add_dir, list) else [add_dir]):
            cmd += ["--add-dir", str(d)]
    if permission_mode is not None:
        cmd += ["--permission-mode", permission_mode]
    if session_id is not None:
        cmd += ["--session-id", session_id]

    proc = subprocess.run(
        cmd,
        input=user_prompt,
        capture_output=True,
        text=True,
        timeout=SUBAGENT_TIMEOUT,
        cwd=str(REPO_ROOT),
        env=subscription_env(),
    )
    if proc.returncode != 0:
        raise RunUnprocessable(
            f"claude -p failed (rc={proc.returncode}):\nstderr: {proc.stderr[-2000:]}"
        )
    return "\n\n".join(_extract_assistant_text_parts(proc.stdout))


def _extract_assistant_text_parts(stdout: str) -> list[str]:
    parts: list[str] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = ev.get("message") or {}
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    txt = item.get("text", "")
                    if txt:
                        parts.append(txt)
        elif isinstance(content, str) and content:
            parts.append(content)
    return parts


def _section(tag: str, body: str, comment: str | None = None) -> str:
    inner = f"<!-- {comment} -->\n" if comment else ""
    return f"<{tag}>\n{inner}{body.rstrip()}\n</{tag}>\n"
