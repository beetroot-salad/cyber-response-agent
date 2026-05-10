#!/usr/bin/env python3
"""Validation-pass dispatcher for the predict-haiku-story-shapeM experiment.

One trial per arm, on the single fixture. Writes stdout + per-arm metadata to
runs/validation/<arm>/trial-1/.

Each trial is one `claude -p --model <model>` invocation seeded with the
trimmed harness prompt, the alert, the prologue, and (for arms that include it)
the environment-quirk doc. The relative-description block is appended for
arm proposed-B.

This script does NOT score outputs — that's analyze.py (written before scale-up).
Validation is human-eyeballed: did each arm produce parseable Shape M output
with two stories, both at mechanism-class abstraction, no candidate-bake-in.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

EXP_DIR = Path(__file__).resolve().parent
HARNESS_PATH = EXP_DIR / "variants" / "predict-story-only.md"
FIXTURE_DIR = EXP_DIR / "fixtures" / "shapeM-winword-burst-quirky"
RUNS_DIR = EXP_DIR / "runs" / "validation"

ARMS = ["current", "proposed-A", "proposed-B"]


def load_arm(arm: str) -> dict:
    with (EXP_DIR / "variants" / f"{arm}.frontmatter.yaml").open() as f:
        return yaml.safe_load(f)


def build_prompt(arm_cfg: dict) -> str:
    harness = HARNESS_PATH.read_text()
    if arm_cfg.get("relative_description_block"):
        rel_block = arm_cfg["relative_description_text"].strip()
        marker = "## Disciplines"
        harness = harness.replace(marker, f"{rel_block}\n\n{marker}", 1)

    alert = (FIXTURE_DIR / "alert.json").read_text()
    investigation = (FIXTURE_DIR / "investigation.md").read_text()

    parts = [
        harness,
        "\n---\n",
        f"<alert>\n{alert}\n</alert>\n",
        f"<investigation>\n{investigation}\n</investigation>\n",
    ]
    if arm_cfg.get("include_environment_context"):
        env = (FIXTURE_DIR / "environment-quirk.md").read_text()
        parts.append(f"<environment-context>\n{env}\n</environment-context>\n")

    parts.append("\nLoop number: 1. Author the Shape M output now.\n")
    return "\n".join(parts)


def model_id(model: str) -> str:
    if model == "sonnet":
        return "claude-sonnet-4-6"
    if model == "haiku":
        return "claude-haiku-4-5-20251001"
    raise ValueError(f"unknown model: {model}")


def run_trial(arm: str) -> None:
    cfg = load_arm(arm)
    out_dir = RUNS_DIR / arm / "trial-1"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    prompt = build_prompt(cfg)
    (out_dir / "prompt.txt").write_text(prompt)
    (out_dir / "config.json").write_text(json.dumps(cfg, indent=2))

    cmd = ["claude", "-p", "--model", model_id(cfg["model"])]
    print(f"[{arm}] dispatching ({cfg['model']}) …", flush=True)
    t0 = time.time()
    proc = subprocess.run(
        cmd, input=prompt, capture_output=True, text=True, timeout=600
    )
    elapsed = time.time() - t0

    (out_dir / "stdout.txt").write_text(proc.stdout)
    (out_dir / "stderr.txt").write_text(proc.stderr)
    (out_dir / "meta.json").write_text(
        json.dumps(
            {
                "arm": arm,
                "model": cfg["model"],
                "elapsed_s": round(elapsed, 2),
                "returncode": proc.returncode,
            },
            indent=2,
        )
    )
    print(f"[{arm}] done in {elapsed:.1f}s (rc={proc.returncode})", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", choices=ARMS + ["all"], default="all")
    args = ap.parse_args()

    targets = ARMS if args.arm == "all" else [args.arm]
    for arm in targets:
        run_trial(arm)
    return 0


if __name__ == "__main__":
    sys.exit(main())
