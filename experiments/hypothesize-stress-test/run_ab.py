#!/usr/bin/env python3
"""A/B runner — invoke the hypothesize subagent with BOTH the pre-session
prompt and the current prompt on each fixture. Produces a side-by-side for
the 3 fixtures so we can tell whether prompt edits changed subagent behavior.

Pre-session prompt lives at /tmp/hypothesize-pre-session.md (dumped from
git HEAD before any edits this session). Current prompt is read from disk.

Usage:
    soc-agent/.venv/bin/python3 docs/experiments/hypothesize-stress-test/run_ab.py
"""

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
sys.path.insert(0, str(SOC_AGENT_ROOT))

CURRENT_PROMPT = SOC_AGENT_ROOT / "agents" / "hypothesize.md"
PRE_SESSION_PROMPT = Path("/tmp/hypothesize-pre-session.md")

TIMEOUT_S = 450  # longer than initial run to accommodate heavier sigs

FIXTURES = [
    ("fixture-1-legitimacy-axis", "wazuh-rule-5710"),
    ("fixture-2-compound-pressure", "wazuh-rule-100001"),
    ("fixture-3-subsequent-event", "wazuh-rule-5710"),
]


def strip_frontmatter(prompt_path: Path) -> str:
    text = prompt_path.read_text()
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        return text[end + len("\n---\n"):].strip()
    return text.strip()


def prepare_run(fixture: str, variant: str, outputs_root: Path) -> Path:
    src = REPO_ROOT / "docs/experiments/hypothesize-stress-test" / fixture
    run_dir = outputs_root / f"{variant}-{fixture}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    shutil.copy(src / "alert.json", run_dir / "alert.json")
    shutil.copy(src / "investigation.md", run_dir / "investigation.md")
    return run_dir


def invoke(prompt_body: str, user_prompt: str, run_dir: Path) -> tuple[int, str, str, float]:
    """Direct claude -p invocation — bypasses _subagent wrapper so we can
    swap the system-prompt file per variant."""
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
        "claude", "-p",
        "--model", "sonnet",
        "--system-prompt-file", tmp_path,
        "--session-id", session_id,
        "--plugin-dir", str(SOC_AGENT_ROOT),
        "--output-format", "text",
        "--allowed-tools", "Read,Bash",
    ]

    t0 = time.monotonic()
    try:
        result = subprocess.run(
            argv, input=user_prompt, capture_output=True, text=True,
            timeout=TIMEOUT_S, env=env,
        )
        duration = time.monotonic() - t0
        return result.returncode, result.stdout, result.stderr, duration
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - t0
        return -1, "<TIMEOUT>", f"timed out after {TIMEOUT_S}s", duration
    finally:
        os.unlink(tmp_path)


def main() -> int:
    outputs_root = REPO_ROOT / "docs/experiments/hypothesize-stress-test/ab-outputs"
    outputs_root.mkdir(exist_ok=True)

    variants = {
        "baseline": strip_frontmatter(PRE_SESSION_PROMPT),
        "current": strip_frontmatter(CURRENT_PROMPT),
    }

    results = []
    for fixture, sig in FIXTURES:
        for variant_name, prompt_body in variants.items():
            run_dir = prepare_run(fixture, variant_name, outputs_root)
            user_prompt = "\n".join([
                f"run_dir={run_dir}",
                f"signature_id={sig}",
                "loop_n=1",
            ])
            print(f"=== {variant_name} × {fixture} ({sig}) ===", flush=True)
            rc, stdout, stderr, dur = invoke(prompt_body, user_prompt, run_dir)
            (run_dir / "subagent_output.md").write_text(stdout)
            (run_dir / "stderr.txt").write_text(stderr)
            status = "timeout" if rc == -1 else f"rc={rc}"
            print(f"  {status} in {dur:.1f}s, stdout {len(stdout)} chars", flush=True)
            results.append((variant_name, fixture, rc, len(stdout), dur))

    print("\n=== A/B summary ===")
    for v, f, rc, n, dur in results:
        marker = "  OK" if rc == 0 else "FAIL"
        print(f"  {marker} {v:8s} × {f:32s} — rc={rc:3d} {n:5d}ch {dur:5.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
