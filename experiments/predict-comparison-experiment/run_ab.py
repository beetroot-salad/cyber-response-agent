#!/usr/bin/env python3
"""A/B harness for the comparison-technique candidate against the live baseline.

Each fixture under ./fixtures/ is staged into a fresh tmp run dir, the predict
subagent is invoked once per variant, and outputs go to ./output/{fixture}/{variant}/.

Variants:
  baseline   — soc-agent/agents/predict.md (current production prompt)
  candidate  — ./predict.candidate.md (baseline + comparison sub-structure)

Usage:
  python3 run_ab.py
  python3 run_ab.py --fixture endpoint-falco-nginx-child-loop1
  python3 run_ab.py --variant candidate
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
from typing import Optional

import yaml

EXPERIMENT_DIR = Path(__file__).resolve().parent
SOC_AGENT_ROOT = EXPERIMENT_DIR.parent.parent / "soc-agent"
FIXTURES_DIR = EXPERIMENT_DIR / "fixtures"
OUTPUT_DIR = EXPERIMENT_DIR / "output"

sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))

from schemas.state import Phase  # noqa: E402
from scripts.handlers import _subagent  # noqa: E402
from scripts.handlers import predict as predict_handler  # noqa: E402
from scripts.orchestrate import Context  # noqa: E402

VARIANTS = {
    "baseline": SOC_AGENT_ROOT / "agents" / "predict.md",
    "candidate": EXPERIMENT_DIR / "predict.candidate-v2.md",
}


def _stage_run_dir(fixture_dir: Path, dest_parent: Path) -> Path:
    run_dir = dest_parent / fixture_dir.name
    if run_dir.exists():
        shutil.rmtree(run_dir)
    shutil.copytree(fixture_dir, run_dir)
    (run_dir / "subagent_checkpoints").mkdir(exist_ok=True)
    return run_dir


def _patched_load_agent(agent_file: Path):
    body_text = agent_file.read_text()
    m = _subagent._FRONTMATTER_RE.match(body_text)
    if not m:
        raise RuntimeError(f"variant file missing YAML frontmatter: {agent_file}")
    frontmatter = yaml.safe_load(m.group(1)) or {}
    body = m.group(2).strip()
    if not body:
        raise RuntimeError(f"variant file has empty body: {agent_file}")
    original = _subagent._load_agent_definition

    def patched(name: str):
        if name == "predict":
            return body, frontmatter
        return original(name)

    return patched, original


def _build_ctx(run_dir: Path, signature_id: str, predict_loop_n: int = 1) -> Context:
    alert = {}
    alert_path = run_dir / "alert.json"
    if alert_path.exists():
        alert = json.loads(alert_path.read_text())
    history: list[str] = []
    for _ in range(predict_loop_n - 1):
        history.extend([Phase.PREDICT.value, Phase.GATHER.value, Phase.ANALYZE.value])
    history.append(Phase.PREDICT.value)
    return Context(
        run_dir=run_dir,
        signature_id=signature_id,
        ticket_id="EXP-COMP",
        alert=alert,
        history=history,
        current_phase=Phase.PREDICT,
    )


def _read_meta(fixture_dir: Path) -> tuple[str, int]:
    meta = json.loads((fixture_dir / "meta.json").read_text())
    sid = meta.get("signature_id")
    if not sid:
        raise RuntimeError(f"fixture {fixture_dir} missing signature_id in meta.json")
    return sid, int(meta.get("predict_loop_n", 1))


def _run_one(
    fixture_dir: Path,
    variant: str,
    staging_root: Path,
    output_root: Path,
    *,
    seed: int = 1,
    timeout: int = 600,
) -> dict:
    signature_id, predict_loop_n = _read_meta(fixture_dir)
    run_dir = _stage_run_dir(fixture_dir, staging_root / f"{variant}-s{seed}")
    ctx = _build_ctx(run_dir, signature_id, predict_loop_n=predict_loop_n)

    os.environ["SOC_AGENT_RUN_DIR"] = str(run_dir)
    os.environ["SOC_AGENT_SIGNATURE_ID"] = signature_id

    prompt = predict_handler._assemble_prompt(ctx)

    patched, original = _patched_load_agent(VARIANTS[variant])
    _subagent._load_agent_definition = patched
    t0 = time.time()
    try:
        stdout = _subagent.invoke_subagent("predict", prompt, timeout=timeout)
    finally:
        _subagent._load_agent_definition = original
    elapsed = time.time() - t0

    out_dir = output_root / fixture_dir.name / variant / f"seed-{seed}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prompt.txt").write_text(prompt)
    (out_dir / "stdout.txt").write_text(stdout)

    ckpt_dir = run_dir / "subagent_checkpoints"
    if ckpt_dir.exists():
        for ckpt in ckpt_dir.glob("predict-loop-*.yaml"):
            shutil.copy(ckpt, out_dir / ckpt.name)

    metrics = {
        "variant": variant,
        "fixture": fixture_dir.name,
        "seed": seed,
        "elapsed_sec": round(elapsed, 1),
        "stdout_chars": len(stdout),
        "prompt_chars": len(prompt),
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(
        f"  [{variant} s{seed}] {elapsed:>5.1f}s  prompt={len(prompt):>6}c  stdout={len(stdout):>5}c"
    )
    return metrics


def _discover_fixtures(filter_name: Optional[str]) -> list[Path]:
    if not FIXTURES_DIR.exists():
        return []
    out = []
    for p in sorted(FIXTURES_DIR.iterdir()):
        if not p.is_dir():
            continue
        if filter_name and p.name != filter_name:
            continue
        if not (p / "alert.json").exists() or not (p / "meta.json").exists():
            continue
        out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", default=None)
    ap.add_argument("--variant", default=None, choices=list(VARIANTS.keys()))
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--seeds", type=int, default=1, help="Seeds per fixture x variant.")
    args = ap.parse_args()

    fixtures = _discover_fixtures(args.fixture)
    if not fixtures:
        print(f"no fixtures under {FIXTURES_DIR}", file=sys.stderr)
        return 2

    variants = [args.variant] if args.variant else list(VARIANTS.keys())
    for v in variants:
        if not VARIANTS[v].exists():
            print(f"variant file missing: {VARIANTS[v]}", file=sys.stderr)
            return 2

    all_metrics: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="predict-comp-") as td:
        staging_root = Path(td)
        for fx in fixtures:
            print(f"fixture: {fx.name}")
            for v in variants:
                for s in range(1, args.seeds + 1):
                    m = _run_one(
                        fx,
                        v,
                        staging_root,
                        OUTPUT_DIR,
                        seed=s,
                        timeout=args.timeout,
                    )
                    all_metrics.append(m)

    summary_path = OUTPUT_DIR / "summary.json"
    summary_path.write_text(json.dumps(all_metrics, indent=2))
    print(f"\nWrote {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
