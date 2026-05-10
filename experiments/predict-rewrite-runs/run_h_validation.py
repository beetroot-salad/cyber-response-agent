#!/usr/bin/env python3
"""H-validation harness — runs effort=low (3 reps) and effort=default (1 rep)
against multiple fixtures so we can confirm H generalizes beyond the loop-2
fixture it was validated on.

Output:
    experiments/predict-rewrite/h-validation-output/{fixture}/{variant}/rep{N}/
        prompt.txt
        stdout.txt
        timing.json
    experiments/predict-rewrite/h-validation-output/summary.json
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
OUTPUT_DIR = EXPERIMENT_DIR / "h-validation-output"

sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
sys.path.insert(0, str(EXPERIMENT_DIR))

from run_voice_mirror import (  # noqa: E402
    _build_ctx, _patched_load_agent, _read_meta, _stage_run_dir, VARIANTS,
)
from scripts.handlers import _subagent  # noqa: E402
from scripts.handlers import predict as predict_handler  # noqa: E402


FIXTURES = ["shape-a-runc-exec", "shape-i-monitoring-probe", "shape-i-bait-5710"]
VARIANT_LOW_REPS = 3
VARIANT_DEFAULT_REPS = 1


def _run_one(
    fixture_dir: Path,
    variant: str,
    rep: int,
    staging_root: Path,
    output_root: Path,
    timeout: int,
) -> dict:
    signature_id, loop_n = _read_meta(fixture_dir)
    tag = f"{variant}__rep{rep}"
    run_dir = _stage_run_dir(fixture_dir, staging_root, tag)
    ctx = _build_ctx(run_dir, signature_id, loop_n)

    os.environ["SOC_AGENT_RUN_DIR"] = str(run_dir)
    os.environ["SOC_AGENT_SIGNATURE_ID"] = signature_id
    if variant == "effort-low":
        os.environ["SOC_AGENT_PREDICT_EFFORT"] = "low"
    else:
        os.environ.pop("SOC_AGENT_PREDICT_EFFORT", None)

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

    out_dir = output_root / fixture_dir.name / variant / f"rep{rep}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prompt.txt").write_text(prompt)
    (out_dir / "stdout.txt").write_text(stdout)
    timing = {
        "fixture": fixture_dir.name,
        "variant": variant,
        "rep": rep,
        "wall_s": round(wall_s, 2),
        "prompt_chars": len(prompt),
        "stdout_chars": len(stdout),
        "error": err,
        "loop_n": loop_n,
        "signature_id": signature_id,
    }
    (out_dir / "timing.json").write_text(json.dumps(timing, indent=2))

    ckpt_dir = run_dir / "subagent_checkpoints"
    if ckpt_dir.exists():
        for ckpt in ckpt_dir.glob("predict-loop-*.yaml"):
            shutil.copy(ckpt, out_dir / ckpt.name)

    print(
        f"  [{fixture_dir.name} {variant} rep{rep}] wall={timing['wall_s']}s "
        f"prompt={timing['prompt_chars']}c stdout={timing['stdout_chars']}c"
        + (f" ERROR={err}" if err else "")
    )
    return timing


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="h-validation-") as td:
        staging_root = Path(td)
        for fname in FIXTURES:
            fdir = FIXTURES_DIR / fname
            if not fdir.is_dir():
                print(f"SKIP missing fixture: {fname}", file=sys.stderr)
                continue
            print(f"=== fixture: {fname} ===")
            for rep in range(1, VARIANT_DEFAULT_REPS + 1):
                results.append(_run_one(fdir, "default", rep, staging_root, OUTPUT_DIR, args.timeout))
            for rep in range(1, VARIANT_LOW_REPS + 1):
                results.append(_run_one(fdir, "effort-low", rep, staging_root, OUTPUT_DIR, args.timeout))

    summary: dict = {}
    for fname in FIXTURES:
        per_fix = [r for r in results if r["fixture"] == fname]
        if not per_fix:
            continue
        by_var: dict[str, list[dict]] = {}
        for r in per_fix:
            by_var.setdefault(r["variant"], []).append(r)
        s = {}
        for v, rs in by_var.items():
            ok = [r for r in rs if not r["error"]]
            walls = [r["wall_s"] for r in ok]
            stdouts = [r["stdout_chars"] for r in ok]
            s[v] = {
                "n_total": len(rs),
                "n_ok": len(ok),
                "wall_s_mean": round(mean(walls), 2) if walls else None,
                "wall_s_stdev": round(stdev(walls), 2) if len(walls) > 1 else None,
                "wall_s_min": min(walls) if walls else None,
                "wall_s_max": max(walls) if walls else None,
                "stdout_chars_mean": round(mean(stdouts), 1) if stdouts else None,
                "errors": [r["error"] for r in rs if r["error"]],
            }
        summary[fname] = s

    (OUTPUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\n=== Summary -> {OUTPUT_DIR / 'summary.json'} ===")
    for fname, s in summary.items():
        print(f"  {fname}:")
        for v, st in s.items():
            print(f"    {v}: wall_mean={st['wall_s_mean']}s "
                  f"(stdev={st['wall_s_stdev']}, n={st['n_ok']}/{st['n_total']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
