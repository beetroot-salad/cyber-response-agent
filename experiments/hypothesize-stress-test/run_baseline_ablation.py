#!/usr/bin/env python3
"""Isolated A/B — baseline-anchoring bullet on vs off. Everything else
identical. One fixture only (fixture-1 — has 2 prior repeats in
ticket-context where baseline anchoring is load-bearing)."""

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

# The baseline-anchoring bullet is discipline #7 in §Causal story — starts
# with "7. **Baseline anchoring when available.**" and ends before the
# "## Discipline" section header. Marker-based excision keeps the split
# deterministic across minor line-edits elsewhere in the prompt.
BULLET_START = "7. **Baseline anchoring when available.**"
BULLET_END_MARKER = "\n## Discipline\n"

TIMEOUT_S = 450


def strip_frontmatter(text: str) -> str:
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        return text[end + len("\n---\n"):].strip()
    return text.strip()


def build_variants() -> dict[str, str]:
    full = CURRENT_PROMPT.read_text()
    with_bullet = strip_frontmatter(full)

    bullet_idx = full.find(BULLET_START)
    discipline_idx = full.find(BULLET_END_MARKER, bullet_idx)
    if bullet_idx == -1 or discipline_idx == -1:
        raise SystemExit("could not locate baseline-anchoring bullet markers")

    # Excise from bullet start up to the blank line before ## Discipline.
    without_full = full[:bullet_idx].rstrip() + "\n" + full[discipline_idx:]
    without_bullet = strip_frontmatter(without_full)

    # Sanity: the "without" variant must not mention "Baseline anchoring".
    assert "Baseline anchoring" not in without_bullet, "excision left residue"
    assert "Baseline anchoring" in with_bullet, "with-variant lost the bullet"
    return {"without": without_bullet, "with": with_bullet}


def prepare(outputs_root: Path, label: str) -> Path:
    src = REPO_ROOT / "docs/experiments/hypothesize-stress-test/fixture-1-legitimacy-axis"
    run_dir = outputs_root / f"baseline-ablation-{label}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    shutil.copy(src / "alert.json", run_dir / "alert.json")
    shutil.copy(src / "investigation.md", run_dir / "investigation.md")
    return run_dir


def invoke(system_prompt: str, user_prompt: str, run_dir: Path) -> tuple[int, str, float]:
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as tmp:
        tmp.write(system_prompt)
        tmp_path = tmp.name
    env = dict(os.environ)
    venv_bin = SOC_AGENT_ROOT / ".venv" / "bin"
    if venv_bin.is_dir():
        env["PATH"] = f"{venv_bin}:{env.get('PATH', '')}"
        env["VIRTUAL_ENV"] = str(SOC_AGENT_ROOT / ".venv")
    env["SOC_AGENT_RUN_DIR"] = str(run_dir)
    argv = [
        "claude", "-p", "--model", "sonnet",
        "--system-prompt-file", tmp_path,
        "--session-id", str(uuid.uuid4()),
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
    variants = build_variants()
    print(f"without-bullet prompt: {len(variants['without'])} chars")
    print(f"with-bullet    prompt: {len(variants['with'])} chars")
    print(f"delta (bullet size): {len(variants['with']) - len(variants['without'])} chars\n")

    for label, system_prompt in variants.items():
        run_dir = prepare(outputs_root, label)
        user_prompt = f"run_dir={run_dir}\nsignature_id=wazuh-rule-5710\nloop_n=1"
        print(f"=== {label}-bullet ===", flush=True)
        rc, stdout, dur = invoke(system_prompt, user_prompt, run_dir)
        (run_dir / "subagent_output.md").write_text(stdout)
        print(f"  rc={rc} in {dur:.1f}s, stdout {len(stdout)} chars", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
