#!/usr/bin/env python3
"""PREDICT prompt A/B experiment harness.

Stages each fixture into an isolated run_dir, builds the handler-identical
user prompt via `predict._assemble_prompt`, then invokes the predict
subagent once per variant (baseline = agents/predict.md,
candidate = experiments/predict-rewrite/predict.candidate.md) by
monkey-patching `_load_agent_definition` to load from the chosen file.

Output layout:
    experiments/predict-rewrite/output/{fixture}/{variant}/
        prompt.txt        — user prompt handed to the subagent
        stdout.txt        — subagent stdout
        checkpoint.yaml   — progress checkpoint (if the subagent wrote one)

Invocation:
    python3 experiments/predict-rewrite/run_experiment.py
    python3 experiments/predict-rewrite/run_experiment.py --fixture shape-i-monitoring-probe
    python3 experiments/predict-rewrite/run_experiment.py --variant candidate
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

import yaml

EXPERIMENT_DIR = Path(__file__).resolve().parent
SOC_AGENT_ROOT = EXPERIMENT_DIR.parent.parent
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
    "candidate": EXPERIMENT_DIR / "predict.candidate.md",
}


def _stage_run_dir(fixture_dir: Path, dest_parent: Path) -> Path:
    """Copy fixture contents into a fresh run dir under `dest_parent`."""
    run_dir = dest_parent / fixture_dir.name
    if run_dir.exists():
        shutil.rmtree(run_dir)
    shutil.copytree(fixture_dir, run_dir)
    (run_dir / "subagent_checkpoints").mkdir(exist_ok=True)
    return run_dir


def _patched_load_agent(agent_file: Path):
    """Return a _load_agent_definition replacement that swaps `predict` only."""
    body_text = agent_file.read_text()
    m = _subagent._FRONTMATTER_RE.match(body_text)
    if not m:
        raise RuntimeError(
            f"variant file missing YAML frontmatter: {agent_file}"
        )
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
    import json
    alert = {}
    alert_path = run_dir / "alert.json"
    if alert_path.exists():
        alert = json.loads(alert_path.read_text())
    # Build history with (loop_n - 1) prior PREDICT→GATHER→ANALYZE cycles
    # followed by the current PREDICT. `_compute_loop_n` subtracts 1 for the
    # current PREDICT entry, yielding the expected loop number.
    history: list[str] = []
    for _ in range(predict_loop_n - 1):
        history.extend([Phase.PREDICT.value, Phase.GATHER.value, Phase.ANALYZE.value])
    history.append(Phase.PREDICT.value)
    return Context(
        run_dir=run_dir,
        signature_id=signature_id,
        ticket_id="EXP-0001",
        alert=alert,
        history=history,
        current_phase=Phase.PREDICT,
    )


def _run_one(
    fixture_dir: Path,
    variant: str,
    staging_root: Path,
    output_root: Path,
    *,
    timeout: int = 600,
) -> None:
    signature_id, predict_loop_n = _read_meta(fixture_dir)
    run_dir = _stage_run_dir(fixture_dir, staging_root / variant)
    ctx = _build_ctx(run_dir, signature_id, predict_loop_n=predict_loop_n)

    # Export env so invoke_subagent can resolve run_dir for session mapping.
    os.environ["SOC_AGENT_RUN_DIR"] = str(run_dir)
    os.environ["SOC_AGENT_SIGNATURE_ID"] = signature_id

    prompt = predict_handler._assemble_prompt(ctx)

    # Swap in the variant's agent definition only for this call.
    patched, original = _patched_load_agent(VARIANTS[variant])
    _subagent._load_agent_definition = patched
    try:
        stdout = _subagent.invoke_subagent("predict", prompt, timeout=timeout)
    finally:
        _subagent._load_agent_definition = original

    out_dir = output_root / fixture_dir.name / variant
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prompt.txt").write_text(prompt)
    (out_dir / "stdout.txt").write_text(stdout)

    # Grab the checkpoint if the subagent wrote one.
    ckpt_dir = run_dir / "subagent_checkpoints"
    if ckpt_dir.exists():
        for ckpt in ckpt_dir.glob("predict-loop-*.yaml"):
            shutil.copy(ckpt, out_dir / ckpt.name)

    print(f"  [{variant}] wrote {out_dir}")


def _read_meta(fixture_dir: Path) -> tuple[str, int]:
    import json
    meta = json.loads((fixture_dir / "meta.json").read_text())
    sid = meta.get("signature_id")
    if not sid:
        raise RuntimeError(f"fixture {fixture_dir} missing signature_id in meta.json")
    loop_n = int(meta.get("predict_loop_n", 1))
    return sid, loop_n


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
    ap.add_argument("--fixture", default=None, help="Run only this fixture by dir name.")
    ap.add_argument(
        "--variant",
        default=None,
        choices=list(VARIANTS.keys()),
        help="Run only this variant. Default: both.",
    )
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    fixtures = _discover_fixtures(args.fixture)
    if not fixtures:
        print(f"no fixtures found under {FIXTURES_DIR} (filter={args.fixture})", file=sys.stderr)
        return 2

    variants = [args.variant] if args.variant else list(VARIANTS.keys())
    for v in variants:
        if not VARIANTS[v].exists():
            print(f"variant file missing: {VARIANTS[v]}", file=sys.stderr)
            return 2

    with tempfile.TemporaryDirectory(prefix="predict-experiment-") as td:
        staging_root = Path(td)
        for fx in fixtures:
            print(f"fixture: {fx.name}")
            for v in variants:
                _run_one(fx, v, staging_root, OUTPUT_DIR, timeout=args.timeout)

    print(f"\nOutputs under: {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
