#!/usr/bin/env python3
"""Re-run the judge step against a fixed learning-run dir.

Two variants, N=3 trials each. Only the judge call varies; alert,
investigation, actor_story, and projected_telemetry are read from
the persisted learning run dir.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

EXP = Path(__file__).resolve().parent
FIXTURE = EXP / "fixtures" / "rerun-100001-envelope-split"
RUNS = EXP / "runs"
VARIANTS = {
    "baseline": EXP / "variants" / "judge_baseline.md",
    "proposed": EXP / "variants" / "judge_with_shard_subagents.md",
}

MODEL = "claude-sonnet-4-6"
TIMEOUT = 600
N = 3


def build_user_prompt() -> str:
    alert = (FIXTURE / "alert.json").read_text().rstrip()
    investigation = (FIXTURE / "investigation.md").read_text().rstrip()
    actor_story = (FIXTURE / "actor_story.md").read_text().rstrip()
    projected = (FIXTURE / "projected_telemetry.yaml").read_text().rstrip()
    return (
        "<alert>\n" + alert + "\n</alert>\n"
        "<investigation>\n" + investigation + "\n</investigation>\n"
        "<actor_story>\n" + actor_story + "\n</actor_story>\n"
        "<projected_telemetry>\n" + projected + "\n</projected_telemetry>\n"
    )


def run_trial(variant: str, trial: int, user: str) -> dict:
    out_dir = RUNS / variant / str(trial)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "claude", "-p",
        "--model", MODEL,
        "--output-format", "text",
        "--system-prompt-file", str(VARIANTS[variant]),
    ]
    if variant == "proposed":
        cmd += ["--allowed-tools", "Task"]
    t0 = time.time()
    proc = subprocess.run(cmd, input=user, capture_output=True, text=True, timeout=TIMEOUT)
    dt = time.time() - t0
    (out_dir / "stdout.txt").write_text(proc.stdout)
    (out_dir / "stderr.txt").write_text(proc.stderr)
    (out_dir / "meta.txt").write_text(
        f"rc={proc.returncode}\nseconds={dt:.1f}\ncmd={' '.join(cmd)}\n"
    )
    print(f"[{variant}/{trial}] rc={proc.returncode} t={dt:.1f}s "
          f"stdout={len(proc.stdout)}B stderr={len(proc.stderr)}B",
          file=sys.stderr)
    return {"variant": variant, "trial": trial, "rc": proc.returncode, "seconds": dt}


def main() -> int:
    user = build_user_prompt()
    print(f"user prompt: {len(user)} bytes", file=sys.stderr)
    results = []
    for variant in ("baseline", "proposed"):
        for trial in range(1, N + 1):
            results.append(run_trial(variant, trial, user))
    # crude summary
    lines = ["variant,trial,rc,seconds"]
    for r in results:
        lines.append(f"{r['variant']},{r['trial']},{r['rc']},{r['seconds']:.1f}")
    (EXP / "results" / "trials.csv").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
