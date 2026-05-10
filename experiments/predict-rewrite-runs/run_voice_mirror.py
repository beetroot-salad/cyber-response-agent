#!/usr/bin/env python3
"""Voice-mirror A/B harness — N reps per variant, single fixture.

Hypothesis under test: phrasing the predict subagent's prompt in Sonnet's
own first-person running-thought voice (the cadence visible in its captured
thinking blocks) negates Sonnet's restatement habit, since the model has
less translation work to do before reasoning.

Usage:
    python3 experiments/predict-rewrite/run_voice_mirror.py
    python3 experiments/predict-rewrite/run_voice_mirror.py --reps 3 \\
        --fixture shape-i-loop2-post-enrichment

Output:
    experiments/predict-rewrite/voice-mirror-output/{fixture}/{variant}/{rep}/
        prompt.txt
        stdout.txt
        timing.json   — {wall_s, stdout_chars, prompt_chars}
    experiments/predict-rewrite/voice-mirror-output/summary.json
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

import yaml

EXPERIMENT_DIR = Path(__file__).resolve().parent
SOC_AGENT_ROOT = EXPERIMENT_DIR.parent.parent
FIXTURES_DIR = EXPERIMENT_DIR / "fixtures"
OUTPUT_DIR = EXPERIMENT_DIR / "voice-mirror-output"

sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))

from schemas.state import Phase  # noqa: E402
from scripts.handlers import _subagent  # noqa: E402
from scripts.handlers import predict as predict_handler  # noqa: E402
from scripts.orchestrate import Context  # noqa: E402

VARIANTS = {
    "baseline": SOC_AGENT_ROOT / "agents" / "predict.md",
    "voice-mirror": EXPERIMENT_DIR / "predict.voice-mirror.md",
}


def _stage_run_dir(fixture_dir: Path, dest_parent: Path, tag: str) -> Path:
    run_dir = dest_parent / f"{fixture_dir.name}__{tag}"
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


def _read_meta(fixture_dir: Path) -> tuple[str, int]:
    meta = json.loads((fixture_dir / "meta.json").read_text())
    sid = meta.get("signature_id")
    if not sid:
        raise RuntimeError(f"fixture {fixture_dir} missing signature_id")
    return sid, int(meta.get("predict_loop_n", 1))


def _build_ctx(run_dir: Path, signature_id: str, predict_loop_n: int) -> Context:
    alert_path = run_dir / "alert.json"
    alert = json.loads(alert_path.read_text()) if alert_path.exists() else {}
    history: list[str] = []
    for _ in range(predict_loop_n - 1):
        history.extend([Phase.PREDICT.value, Phase.GATHER.value, Phase.ANALYZE.value])
    history.append(Phase.PREDICT.value)
    return Context(
        run_dir=run_dir,
        signature_id=signature_id,
        ticket_id="EXP-VM-0001",
        alert=alert,
        history=history,
        current_phase=Phase.PREDICT,
    )


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

    prompt = predict_handler._assemble_prompt(ctx)

    patched, original = _patched_load_agent(VARIANTS[variant])
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
        "variant": variant,
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
        f"  [{variant} rep{rep}] wall={timing['wall_s']}s "
        f"prompt={timing['prompt_chars']}c stdout={timing['stdout_chars']}c"
        + (f" ERROR={err}" if err else "")
    )
    return timing


def _summarize(results: list[dict]) -> dict:
    by_variant: dict[str, list[dict]] = {}
    for r in results:
        by_variant.setdefault(r["variant"], []).append(r)

    summary = {}
    for variant, rs in by_variant.items():
        ok = [r for r in rs if not r["error"]]
        walls = [r["wall_s"] for r in ok]
        stdouts = [r["stdout_chars"] for r in ok]
        summary[variant] = {
            "n_total": len(rs),
            "n_ok": len(ok),
            "wall_s_mean": round(mean(walls), 2) if walls else None,
            "wall_s_stdev": round(stdev(walls), 2) if len(walls) > 1 else None,
            "wall_s_min": min(walls) if walls else None,
            "wall_s_max": max(walls) if walls else None,
            "stdout_chars_mean": round(mean(stdouts), 1) if stdouts else None,
            "errors": [r["error"] for r in rs if r["error"]],
        }
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", default="shape-i-loop2-post-enrichment")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--variants", nargs="+", default=list(VARIANTS.keys()))
    ap.add_argument("--timeout", type=int, default=600)
    args = ap.parse_args()

    fixture_dir = FIXTURES_DIR / args.fixture
    if not fixture_dir.is_dir():
        print(f"fixture missing: {fixture_dir}", file=sys.stderr)
        return 2
    for v in args.variants:
        if v not in VARIANTS:
            print(f"unknown variant: {v}", file=sys.stderr)
            return 2
        if not VARIANTS[v].exists():
            print(f"variant file missing: {VARIANTS[v]}", file=sys.stderr)
            return 2

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="voice-mirror-") as td:
        staging_root = Path(td)
        print(f"fixture: {fixture_dir.name}  reps: {args.reps}")
        for variant in args.variants:
            for rep in range(1, args.reps + 1):
                results.append(
                    _run_one(
                        fixture_dir,
                        variant,
                        rep,
                        staging_root,
                        OUTPUT_DIR,
                        args.timeout,
                    )
                )

    summary = _summarize(results)
    summary_path = OUTPUT_DIR / "summary.json"
    summary_path.write_text(json.dumps({"fixture": args.fixture, "variants": summary}, indent=2))
    print(f"\nSummary: {summary_path}")
    for v, s in summary.items():
        print(
            f"  {v}: wall_mean={s['wall_s_mean']}s "
            f"(stdev={s['wall_s_stdev']}, n={s['n_ok']}/{s['n_total']})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
