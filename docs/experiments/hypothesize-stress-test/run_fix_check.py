#!/usr/bin/env python3
"""Targeted re-run of fixtures 2 and 3 under the CURRENT (fixed) prompt to
verify the stdout-emission regression is fixed. Uses the same direct claude -p
call as run_ab.py to keep variables controlled."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SOC_AGENT_ROOT = REPO_ROOT / "soc-agent"
CURRENT_PROMPT = SOC_AGENT_ROOT / "agents" / "hypothesize.md"

TIMEOUT_S = 450

FIXTURES = [
    ("fixture-2-compound-pressure", "wazuh-rule-100001"),
    ("fixture-3-subsequent-event", "wazuh-rule-5710"),
]


def strip_frontmatter(path: Path) -> str:
    text = path.read_text()
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        return text[end + len("\n---\n"):].strip()
    return text.strip()


def prepare(fixture: str, outputs_root: Path) -> Path:
    src = REPO_ROOT / "docs/experiments/hypothesize-stress-test" / fixture
    run_dir = outputs_root / f"fixed-{fixture}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    shutil.copy(src / "alert.json", run_dir / "alert.json")
    shutil.copy(src / "investigation.md", run_dir / "investigation.md")
    return run_dir


def invoke(prompt_body: str, user_prompt: str, run_dir: Path) -> tuple[int, str, float]:
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as tmp:
        tmp.write(prompt_body)
        tmp_path = tmp.name
    session_id = str(uuid.uuid4())
    env = dict(os.environ)
    venv_bin = SOC_AGENT_ROOT / ".venv" / "bin"
    if venv_bin.is_dir():
        env["PATH"] = f"{venv_bin}:{env.get('PATH', '')}"
        env["VIRTUAL_ENV"] = str(SOC_AGENT_ROOT / ".venv")
    env["SOC_AGENT_RUN_DIR"] = str(run_dir)
    argv = [
        "claude", "-p", "--model", "sonnet",
        "--system-prompt-file", tmp_path,
        "--session-id", session_id,
        "--plugin-dir", str(SOC_AGENT_ROOT),
        "--output-format", "text",
        "--allowed-tools", "Read,Bash",
    ]
    t0 = time.monotonic()
    try:
        r = subprocess.run(argv, input=user_prompt, capture_output=True, text=True,
                           timeout=TIMEOUT_S, env=env)
        return r.returncode, r.stdout, time.monotonic() - t0
    except subprocess.TimeoutExpired:
        return -1, "<TIMEOUT>", time.monotonic() - t0
    finally:
        os.unlink(tmp_path)


def main() -> int:
    outputs_root = REPO_ROOT / "docs/experiments/hypothesize-stress-test/ab-outputs"
    prompt_body = strip_frontmatter(CURRENT_PROMPT)
    for fixture, sig in FIXTURES:
        run_dir = prepare(fixture, outputs_root)
        user_prompt = f"run_dir={run_dir}\nsignature_id={sig}\nloop_n=1"
        print(f"=== fixed × {fixture} ({sig}) ===", flush=True)
        rc, stdout, dur = invoke(prompt_body, user_prompt, run_dir)
        (run_dir / "subagent_output.md").write_text(stdout)
        print(f"  rc={rc} in {dur:.1f}s, stdout {len(stdout)} chars", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
