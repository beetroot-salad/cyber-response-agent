"""Minimal `claude -p` dispatcher for experiment arms.

Decoupled from `scripts/handlers/_subagent` so the experiment doesn't load
plugin hooks and doesn't depend on soc-agent's agent registry. Each arm
hands us a system prompt + user prompt + model; we shell out and capture
stdout + token-cost proxy from the JSON output mode.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


def invoke(
    *,
    system_prompt: str,
    user_prompt: str,
    model: str,
    timeout: int = 300,
) -> dict[str, Any]:
    """Run `claude -p` once. Return {stdout, model, elapsed_s, exit_code, raw_json}.

    Uses --output-format json so we can read token counts back. Falls back
    to plain text if the JSON envelope isn't there.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as tmp:
        tmp.write(system_prompt)
        sys_path = tmp.name

    argv = [
        "claude", "-p",
        "--model", model,
        "--system-prompt-file", sys_path,
        "--output-format", "json",
    ]

    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            input=user_prompt,
            capture_output=True, text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return {
            "stdout": "", "stderr": f"claude CLI not found: {exc}",
            "elapsed_s": 0, "exit_code": 127, "raw_json": None,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "stdout": "", "stderr": f"timeout after {timeout}s: {exc}",
            "elapsed_s": timeout, "exit_code": 124, "raw_json": None,
        }
    finally:
        Path(sys_path).unlink(missing_ok=True)

    elapsed = round(time.monotonic() - started, 3)
    raw = proc.stdout or ""
    parsed: dict | None = None
    text_out: str = raw
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            text_out = parsed.get("result") or parsed.get("text") or raw
    except json.JSONDecodeError:
        parsed = None

    return {
        "stdout": text_out,
        "stderr": proc.stderr,
        "elapsed_s": elapsed,
        "exit_code": proc.returncode,
        "raw_json": parsed,
    }


def extract_selected_lead(stdout: str) -> str | None:
    """Find the first `selected_lead:` value in the output. Tolerant to
    being inside a YAML fence or as a bare line.
    """
    import re
    m = re.search(r"selected_lead\s*:\s*['\"]?([A-Za-z0-9_\-]+)", stdout)
    return m.group(1) if m else None
