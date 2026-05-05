#!/usr/bin/env python3
"""Shared helpers for invoking Haiku judges via the claude CLI.

Used by validate_report_precheck.py (pre-REPORT gate, two parallel judges)
and validate_report.py (post-report Tier 2). Centralising the
subprocess invocation, salted-delimiter wrapping, and verdict parsing
keeps both gates on the same contract.

Prompts are fed to the `claude` CLI over stdin rather than argv so we
don't inflate argv with multi-megabyte investigation logs and so the
hook stays well clear of ARG_MAX on any platform.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

JUDGE_MODEL = os.environ.get("SOC_AGENT_JUDGE_MODEL", "haiku")
JUDGE_TIMEOUT_SECONDS = int(os.environ.get("SOC_AGENT_JUDGE_TIMEOUT_SECONDS", "120"))


def get_run_salt(run_dir: Path) -> str:
    """Per-run salt from meta.json, or a fresh fallback if missing.

    An empty-string salt would produce forgeable `<run--tag>` delimiters,
    so we treat a missing or falsy salt the same as a missing meta.json
    and generate a fresh per-invocation salt.
    """
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


_CLAUDE_ARGV = ["claude", "-p", "--model", JUDGE_MODEL, "--output-format", "text"]


def invoke_judge(prompt: str, *, timeout: int = JUDGE_TIMEOUT_SECONDS) -> tuple[str, int]:
    """Invoke the claude CLI with a judge prompt.

    Returns (stdout, returncode). Returncode 1 covers FileNotFoundError
    and timeout, with the failure reason returned in the stdout slot so
    callers can surface it to the agent.
    """
    try:
        result = subprocess.run(
            _CLAUDE_ARGV,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.returncode
    except FileNotFoundError:
        return "claude CLI not found", 1
    except subprocess.TimeoutExpired:
        return f"judge timed out after {timeout}s", 1


def _run_one_judge(prompt: str, deadline: float, total_timeout: int) -> tuple[str, int]:
    """Spawn one claude judge subprocess, feed the prompt over stdin,
    and wait for its output — bounded by the shared `deadline`."""
    try:
        p = subprocess.Popen(
            _CLAUDE_ARGV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        return "claude CLI not found", 1
    remaining = max(0.1, deadline - time.monotonic())
    try:
        stdout, _ = p.communicate(input=prompt, timeout=remaining)
        return (stdout or "").strip(), p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        with contextlib.suppress(Exception):
            p.communicate(timeout=5)
        return f"judge timed out after {total_timeout}s", 1


def invoke_judges_parallel(
    prompts: list[tuple[str, str]],
    *,
    timeout: int = JUDGE_TIMEOUT_SECONDS,
) -> list[tuple[str, str, int]]:
    """Run multiple judges concurrently, each in its own thread, sharing
    a single wall-clock deadline.

    `prompts` is a list of (label, prompt) tuples. Returns a list of
    (label, stdout, returncode) tuples in the same order. Total wall-time
    is bounded by `timeout` regardless of per-child cost: a judge still
    running when the deadline elapses is killed and reported as a timeout.
    """
    if not prompts:
        return []
    deadline = time.monotonic() + timeout
    with ThreadPoolExecutor(max_workers=len(prompts)) as ex:
        futures = [
            (label, ex.submit(_run_one_judge, prompt, deadline, timeout))
            for label, prompt in prompts
        ]
        return [(label, *f.result()) for label, f in futures]


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
