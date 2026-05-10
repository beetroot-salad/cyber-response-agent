#!/usr/bin/env python3
"""Thinking-effort=low A/B harness — N reps, single fixture.

Reuses run_voice_mirror.py's harness functions. Sets
SOC_AGENT_PREDICT_EFFORT=low for the duration of the run, which the shared
`_subagent.invoke_subagent` plumbs through to `claude -p --effort low`.

Output:
    experiments/predict-rewrite/effort-low-output/{fixture}/baseline/rep{N}/
        prompt.txt
        stdout.txt
        timing.json
    experiments/predict-rewrite/effort-low-output/summary.json

Compare against the existing voice-mirror-output/.../baseline/ which used
default effort.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from statistics import mean, stdev

EXPERIMENT_DIR = Path(__file__).resolve().parent
SOC_AGENT_ROOT = EXPERIMENT_DIR.parent.parent
FIXTURES_DIR = EXPERIMENT_DIR / "fixtures"
OUTPUT_DIR = EXPERIMENT_DIR / "effort-low-output"

sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
sys.path.insert(0, str(EXPERIMENT_DIR))

from run_voice_mirror import (  # noqa: E402
    _build_ctx, _patched_load_agent, _read_meta, _stage_run_dir, VARIANTS,
)
from scripts.handlers import _subagent  # noqa: E402
from scripts.handlers import predict as predict_handler  # noqa: E402


def _run_one(
    fixture_dir: Path,
    rep: int,
    staging_root: Path,
    output_root: Path,
    timeout: int,
) -> dict:
    signature_id, loop_n = _read_meta(fixture_dir)
    tag = f"effort-low__rep{rep}"
    run_dir = _stage_run_dir(fixture_dir, staging_root, tag)
    ctx = _build_ctx(run_dir, signature_id, loop_n)

    os.environ["SOC_AGENT_RUN_DIR"] = str(run_dir)
    os.environ["SOC_AGENT_SIGNATURE_ID"] = signature_id
    os.environ["SOC_AGENT_PREDICT_EFFORT"] = "low"  # the lever under test

    prompt = predict_handler._assemble_prompt(ctx)

    patched, original = _patched_load_agent(VARIANTS["baseline"])
    _subagent._load_agent_definition = patched
    t0 = time.monotonic()
    err = None
    stdout = ""
    try:
        stdout = _subagent.invoke_subagent("predict", prompt, timeout=timeout)
    except Exception as e:
        err = repr(e)
    finally:
        _subagent._load_agent_definition = original
    wall_s = time.monotonic() - t0

    out_dir = output_root / fixture_dir.name / "baseline" / f"rep{rep}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prompt.txt").write_text(prompt)
    (out_dir / "stdout.txt").write_text(stdout)
    timing = {
        "variant": "baseline-effort-low",
        "rep": rep,
        "wall_s": round(wall_s, 2),
        "prompt_chars": len(prompt),
        "stdout_chars": len(stdout),
        "error": err,
    }
    (out_dir / "timing.json").write_text(json.dumps(timing, indent=2))

    ckpt_dir = run_dir / "subagent_checkpoints"
    if ckpt_dir.exists():
        for ckpt in ckpt_dir.glob("predict-loop-*.yaml"):
            shutil.copy(ckpt, out_dir / ckpt.name)

    print(
        f"  [effort=low rep{rep}] wall={timing['wall_s']}s "
        f"prompt={timing['prompt_chars']}c stdout={timing['stdout_chars']}c"
        + (f" ERROR={err}" if err else "")
    )
    return timing


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", default="shape-i-loop2-post-enrichment")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    fixture_dir = FIXTURES_DIR / args.fixture
    if not fixture_dir.is_dir():
        print(f"fixture missing: {fixture_dir}", file=sys.stderr)
        return 2

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="effort-low-") as td:
        staging_root = Path(td)
        print(f"fixture: {fixture_dir.name}  reps: {args.reps}  effort=low")
        for rep in range(1, args.reps + 1):
            results.append(_run_one(fixture_dir, rep, staging_root, OUTPUT_DIR, args.timeout))

    ok = [r for r in results if not r["error"]]
    walls = [r["wall_s"] for r in ok]
    stdouts = [r["stdout_chars"] for r in ok]
    summary = {
        "fixture": args.fixture,
        "variant": "baseline-effort-low",
        "reps": len(results),
        "n_ok": len(ok),
        "wall_s_mean": round(mean(walls), 2) if walls else None,
        "wall_s_stdev": round(stdev(walls), 2) if len(walls) > 1 else None,
        "wall_s_min": min(walls) if walls else None,
        "wall_s_max": max(walls) if walls else None,
        "stdout_chars_mean": round(mean(stdouts), 1) if stdouts else None,
        "errors": [r["error"] for r in results if r["error"]],
    }
    (OUTPUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nSummary: {OUTPUT_DIR / 'summary.json'}")
    print(f"  effort=low: wall_mean={summary['wall_s_mean']}s "
          f"(stdev={summary['wall_s_stdev']}, n={summary['n_ok']}/{summary['reps']})")
    print(f"  reference (effort=default, baseline from voice-mirror): "
          f"wall_mean=160.26s, stdev=70.26")
    return 0


if __name__ == "__main__":
    sys.exit(main())
