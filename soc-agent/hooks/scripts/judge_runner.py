#!/usr/bin/env python3
"""Shared helpers for invoking Haiku judges via the claude CLI.

Used by validate_conclude.py (pre-CONCLUDE gate, two parallel judges)
and validate_report.py (post-report Tier 2). Centralising the
subprocess invocation, salted-delimiter wrapping, and verdict parsing
keeps both gates on the same contract.
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
from pathlib import Path

JUDGE_MODEL = os.environ.get("SOC_AGENT_JUDGE_MODEL", "haiku")
JUDGE_TIMEOUT_SECONDS = int(os.environ.get("SOC_AGENT_JUDGE_TIMEOUT_SECONDS", "90"))


def get_run_salt(run_dir: Path) -> str:
    """Per-run salt from meta.json, or a fresh fallback if missing."""
    import json

    meta_path = run_dir / "meta.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            salt = meta.get("salt", "")
            if salt:
                return salt
        except (json.JSONDecodeError, KeyError, OSError):
            pass
    return secrets.token_hex(8)


def wrap_untrusted(content: str, tag: str, salt: str) -> str:
    """Wrap untrusted content in salted delimiters."""
    return f"<run-{salt}-{tag}>\n{content}\n</run-{salt}-{tag}>"


def invoke_judge(prompt: str, *, timeout: int | None = None) -> tuple[str, int]:
    """Invoke the claude CLI with a judge prompt.

    Returns (stdout, returncode). Returncode 1 covers FileNotFoundError
    and timeout, with the failure reason returned in the stdout slot so
    callers can surface it to the agent.
    """
    t = timeout if timeout is not None else JUDGE_TIMEOUT_SECONDS
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", JUDGE_MODEL, "--output-format", "text"],
            capture_output=True,
            text=True,
            timeout=t,
        )
        return result.stdout.strip(), result.returncode
    except FileNotFoundError:
        return "claude CLI not found", 1
    except subprocess.TimeoutExpired:
        return f"judge timed out after {t}s", 1


def invoke_judges_parallel(
    prompts: list[tuple[str, str]],
    *,
    timeout: int | None = None,
) -> list[tuple[str, str, int]]:
    """Run multiple judges concurrently via subprocess.Popen.

    `prompts` is a list of (label, prompt) tuples. Returns a list of
    (label, stdout, returncode) tuples in the same order. Each child
    process runs to completion or until `timeout` seconds, whichever
    comes first; killed children return (label, "judge timed out…", 1).
    """
    t = timeout if timeout is not None else JUDGE_TIMEOUT_SECONDS

    procs: list[tuple[str, subprocess.Popen | None, str | None]] = []
    for label, prompt in prompts:
        try:
            p = subprocess.Popen(
                [
                    "claude",
                    "-p",
                    prompt,
                    "--model",
                    JUDGE_MODEL,
                    "--output-format",
                    "text",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            procs.append((label, p, None))
        except FileNotFoundError:
            procs.append((label, None, "claude CLI not found"))

    results: list[tuple[str, str, int]] = []
    for label, p, err in procs:
        if p is None:
            results.append((label, err or "judge launch failed", 1))
            continue
        try:
            stdout, _ = p.communicate(timeout=t)
            results.append((label, (stdout or "").strip(), p.returncode))
        except subprocess.TimeoutExpired:
            p.kill()
            try:
                p.communicate(timeout=5)
            except Exception:
                pass
            results.append((label, f"judge timed out after {t}s", 1))
    return results


def parse_verdict(output: str) -> tuple[str, str]:
    """Parse the VERDICT line from judge output. Returns (PASS|FLAG, reason)."""
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("VERDICT:"):
            rest = line[len("VERDICT:"):].strip()
            match = re.match(r"(PASS|FLAG)\s*[—\-]\s*(.*)", rest, re.IGNORECASE)
            if match:
                return match.group(1).upper(), match.group(2)
            if "PASS" in rest.upper():
                return "PASS", rest
            return "FLAG", rest
    return "FLAG", "could not parse judge verdict from output"
