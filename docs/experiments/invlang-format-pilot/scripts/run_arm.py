#!/usr/bin/env python3
"""Run one trial: invoke the hypothesize subagent with a rendered prior,
capture its output.

Usage:
    run_arm.py <case_dir> <depth> <arm> --out <round_dir>

Pipeline:
  1. render_prior.py <case_dir> <depth> <arm>  → prior context
  2. Stage a temp run_dir:
       {tmp}/alert.json         = copy of source/alert.json
       {tmp}/investigation.md   = rendered prior
  3. Read the hypothesize subagent prompt (soc-agent/agents/hypothesize.md),
     strip frontmatter, substitute {run_dir}/{signature_id}/{loop_n}.
  4. Invoke `claude -p --bare --dangerously-skip-permissions --model sonnet`
     with the composed prompt.
  5. Write raw output to {round_dir}/{trial_id}/output.md and the
     composed prompt + prior to the same dir for reproducibility.

trial_id = {case_name}__{depth}__arm{arm}. Fresh temp run_dir per trial
so state can't leak.

Deliberately minimal — no token metering, no multi-turn loop, no
retries. This is the sanity-check runner, not the production harness.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path("/workspace")
HYPOTHESIZE_PROMPT_PATH = REPO_ROOT / "soc-agent/agents/hypothesize.md"
RENDER_SCRIPT = Path(__file__).parent / "render_prior.py"
PYTHON = REPO_ROOT / "soc-agent/.venv/bin/python3"


def strip_frontmatter(md: str) -> str:
    """Remove a leading `---\\n...\\n---\\n` block if present."""
    if md.startswith("---\n"):
        end = md.find("\n---\n", 4)
        if end != -1:
            return md[end + 5 :]
    return md


def signature_from_case(case_dir: Path) -> str:
    """Read the signature id from case.yaml without a YAML dep here — the
    renderer already depends on PyYAML but this subroutine is a one-liner
    grep."""
    text = (case_dir / "case.yaml").read_text()
    m = re.search(r"^\s*signature:\s*(\S+)\s*$", text, flags=re.MULTILINE)
    if not m:
        raise ValueError(f"signature not found in {case_dir}/case.yaml")
    return m.group(1)


def render_prior(case_dir: Path, depth: str, arm: str) -> str:
    """Run render_prior.py and return its stdout."""
    result = subprocess.run(
        [str(PYTHON), str(RENDER_SCRIPT), str(case_dir), depth, arm],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def compose_prompt(prior: str, run_dir: Path, signature_id: str, loop_n: int) -> str:
    """Build the user-prompt body that invokes the hypothesize subagent.

    The subagent's instruction text becomes the system prompt (via
    --append-system-prompt). The user prompt only needs to carry the
    caller's substitutions and point at the staged run_dir.
    """
    return (
        f"You are acting as the hypothesize subagent. Caller substitutions:\n\n"
        f"- run_dir = {run_dir}\n"
        f"- signature_id = {signature_id}\n"
        f"- loop_n = {loop_n}\n\n"
        f"Read the files listed in your instructions and produce the HYPOTHESIZE "
        f"block (or a GATHER block if no fork is observable) for loop {loop_n}. "
        f"Output exactly the block; do not add preamble or explanation.\n"
    )


def determine_loop_n(prior: str) -> int:
    """Infer which loop the subagent should produce, by finding the
    highest `## HYPOTHESIZE (loop N)` header in the prior and adding 1.
    If no HYPOTHESIZE phase is present, loop_n = 1."""
    highest = 0
    for m in re.finditer(r"^##\s+HYPOTHESIZE\s*\(loop\s+(\d+)\)", prior, flags=re.MULTILINE):
        highest = max(highest, int(m.group(1)))
    return highest + 1 if highest else 1


def invoke_claude(system_prompt: str, user_prompt: str, run_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "claude",
            "-p",
            "--model",
            "sonnet",
            "--allowedTools",
            "Read Bash",
            "--append-system-prompt",
            system_prompt,
            "--add-dir",
            str(run_dir),
            str(REPO_ROOT / "soc-agent/knowledge"),
        ],
        input=user_prompt,
        capture_output=True,
        text=True,
        timeout=300,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("case_dir", type=Path)
    ap.add_argument("depth", choices=["shallow", "deep"])
    ap.add_argument("arm", choices=["A", "B", "C"])
    ap.add_argument("--out", dest="round_dir", type=Path, required=True)
    args = ap.parse_args()

    case_name = args.case_dir.name.removeprefix("case-")
    trial_id = f"{case_name}__{args.depth}__arm{args.arm}"
    trial_dir = args.round_dir / trial_id
    trial_dir.mkdir(parents=True, exist_ok=True)

    signature_id = signature_from_case(args.case_dir)
    prior = render_prior(args.case_dir, args.depth, args.arm)
    loop_n = determine_loop_n(prior)

    with tempfile.TemporaryDirectory(prefix=f"pilot-{trial_id}-") as tmp_str:
        tmp = Path(tmp_str)
        shutil.copy(args.case_dir / "source" / "alert.json", tmp / "alert.json")
        (tmp / "investigation.md").write_text(prior)

        system_prompt = strip_frontmatter(HYPOTHESIZE_PROMPT_PATH.read_text())
        user_prompt = compose_prompt(prior, tmp, signature_id, loop_n)

        # Persist what we sent.
        (trial_dir / "prior.md").write_text(prior)
        (trial_dir / "user_prompt.txt").write_text(user_prompt)
        (trial_dir / "meta.txt").write_text(
            f"trial_id: {trial_id}\n"
            f"case_dir: {args.case_dir}\n"
            f"signature_id: {signature_id}\n"
            f"loop_n: {loop_n}\n"
            f"depth: {args.depth}\n"
            f"arm: {args.arm}\n"
            f"staged_run_dir: {tmp}\n"
        )

        try:
            result = invoke_claude(system_prompt, user_prompt, tmp)
        except subprocess.TimeoutExpired:
            (trial_dir / "output.md").write_text("(TIMEOUT)\n")
            print(f"TIMEOUT {trial_id}", file=sys.stderr)
            return 1

        (trial_dir / "output.md").write_text(result.stdout)
        if result.stderr:
            (trial_dir / "stderr.log").write_text(result.stderr)
        if result.returncode != 0:
            print(f"FAIL {trial_id} (exit {result.returncode})", file=sys.stderr)
            return result.returncode

    print(f"OK  {trial_id}  ({len((trial_dir / 'output.md').read_text())} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
