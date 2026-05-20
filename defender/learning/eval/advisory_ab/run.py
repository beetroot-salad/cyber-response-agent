#!/usr/bin/env python3
"""Per-arm runner for the advisory A/B/C/D experiment.

Spawns one defender run per (arm, case, trial) and writes a metrics
JSON to results/<timestamp>/<arm>-<case_id>-t<trial>.json. The arm
overlay (a/b/c/d.md) is prepended to the standard defender prompt so
the SKILL.md on disk stays untouched.

Cases live as synthetic fixtures under fixtures/<id>/{alert.json,
ground_truth.yaml}. The corpus visible to B/C/D is the unmodified
/tmp/defender-runs tree — test alerts are net-new entities, so they
do not appear in the corpus and no exclusion plumbing is needed.

Usage:
    python3 run.py --arm b --case POS-1 --trial 1
    python3 run.py --all --trials 3            # pilot: 1 pos + 1 neg × 4 arms × 3 trials
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFENDER_DIR = HERE.parents[2]  # .../defender
REPO_ROOT = DEFENDER_DIR.parent
DEFENDER_RUN_PY = DEFENDER_DIR / "run.py"
ARMS_DIR = HERE / "arms"
CASES_FILE = HERE / "cases.json"
RESULTS_DIR = HERE / "results"


def load_cases() -> dict:
    return json.loads(CASES_FILE.read_text())


def case_by_id(cases: dict, case_id: str) -> dict:
    for bucket in ("positives", "negatives"):
        for c in cases[bucket]:
            if c["id"] == case_id:
                return {**c, "_category": bucket[:-1]}  # "positive" / "negative"
    sys.exit(f"unknown case_id: {case_id}")


def arm_overlay(arm: str) -> str:
    path = ARMS_DIR / f"{arm}.md"
    if not path.is_file():
        sys.exit(f"unknown arm: {arm} (expected one of a/b/c/d)")
    return path.read_text()


def fixture_alert(case: dict) -> Path:
    """Resolve the synthetic alert.json from the case's fixture_dir."""
    fixture = HERE / case["fixture_dir"]
    alert = fixture / "alert.json"
    if not alert.is_file():
        sys.exit(f"fixture alert missing for case {case['id']}: {alert}")
    return alert


def build_prompt(arm: str, run_id: str, run_dir: Path) -> str:
    overlay = arm_overlay(arm).strip()
    base = (
        f"## Run context\n"
        f"case_id: {run_id}\n"
        f"run_dir: {run_dir}\n"
        f"alert: {run_dir / 'alert.json'}\n\n"
    )
    arm_section = ""
    if overlay and not overlay.startswith("<!--"):
        arm_section = (
            "## Arm-specific PLAN extension\n\n"
            "The following extends defender/SKILL.md §PLAN for this run. "
            "Apply it wherever it conflicts with the SKILL.\n\n"
            f"{overlay}\n\n"
        )
    return (
        base
        + arm_section
        + "Read defender/SKILL.md and follow it end-to-end.\n"
        + "Work through ORIENT → PLAN → GATHER → ANALYZE → REPORT, dispatching "
        + "gather subagents per defender/SKILL.md §GATHER. Stop when "
        + "investigation.md and report.md both exist.\n"
    )


def spawn_run(arm: str, case: dict, trial: int, *, model: str | None) -> Path:
    """Spawn defender against the case's synthetic alert and return run_dir."""
    cases = load_cases()
    corpus = Path(cases["corpus_root"])
    alert = fixture_alert(case)

    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"advisory-ab-{arm}-{case['id'].lower()}-t{trial}-{ts}"
    run_dir = corpus / run_id
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(alert, run_dir / "alert.json")

    # We import defender/run.py's helpers to spawn claude with the same
    # settings + permissions, but build our own prompt with the arm overlay.
    sys.path.insert(0, str(DEFENDER_DIR))
    try:
        import run as defender_run  # type: ignore
    finally:
        sys.path.pop(0)

    settings_path = defender_run.build_settings_file()
    prompt = build_prompt(arm, run_id, run_dir)
    model = model or os.environ.get("DEFENDER_MODEL") or defender_run.DEFAULT_MODEL

    t0 = time.monotonic()
    rc = defender_run.spawn_claude(prompt, run_dir, settings_path, model, effort=None)
    wall_clock = time.monotonic() - t0
    (run_dir / "_arm.json").write_text(json.dumps({
        "arm": arm,
        "case_id": case["id"],
        "category": case["_category"],
        "gold": case["gold"],
        "predicted_relevance": case["predicted_relevance"],
        "trial": trial,
        "rc": rc,
        "wall_clock_seconds": wall_clock,
        "model": model,
    }, indent=2))
    return run_dir


def extract_metrics(run_dir: Path, arm: str, case: dict) -> dict:
    """Parse tool_trace.jsonl + investigation.md + report.md into one record."""
    meta = json.loads((run_dir / "_arm.json").read_text())
    metrics: dict = {
        "arm": arm,
        "case_id": case["id"],
        "category": case["_category"],
        "gold": case["gold"],
        "predicted_relevance": case["predicted_relevance"],
        "trial": meta.get("trial", 1),
        "run_dir": str(run_dir),
        "rc": meta["rc"],
        "wall_clock_seconds": meta["wall_clock_seconds"],
        "model": meta["model"],
    }

    # Disposition from report.md frontmatter.
    report = run_dir / "report.md"
    disposition = None
    if report.is_file():
        head = report.read_text().split("---", 2)
        if len(head) >= 3:
            for line in head[1].splitlines():
                if line.startswith("disposition:"):
                    disposition = line.split(":", 1)[1].strip()
                    break
    metrics["disposition_observed"] = disposition
    metrics["disposition_match"] = (disposition == case["gold"])

    # Lead + loop counts from investigation.md.
    inv = run_dir / "investigation.md"
    loops_count = 0
    leads_count = 0
    if inv.is_file():
        txt = inv.read_text()
        loops_count = sum(1 for ln in txt.splitlines() if ln.strip().startswith("## PHASE: PLAN"))
        leads_count = sum(1 for ln in txt.splitlines() if ln.strip().startswith(":L "))
    metrics["loops_count"] = loops_count
    metrics["leads_count"] = leads_count

    # Token + cost totals from stream-json trace.
    trace = run_dir / "tool_trace.jsonl"
    total_in = total_out = 0
    total_cost = 0.0
    advisory_calls = 0
    if trace.is_file():
        with trace.open() as fh:
            for line in fh:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Token accounting — stream-json puts usage on "result" events
                # (full-run total) and on intermediate "message" events.
                if ev.get("type") == "result":
                    usage = ev.get("usage", {}) or {}
                    total_in += usage.get("input_tokens", 0) or 0
                    total_out += usage.get("output_tokens", 0) or 0
                    if "total_cost_usd" in ev:
                        total_cost += float(ev["total_cost_usd"])
                # Count advisory invocations.
                if ev.get("type") == "tool_use":
                    name = ev.get("name", "")
                    payload = ev.get("input", {}) or {}
                    if name == "Bash" and "invlang.cli advisory" in str(payload.get("command", "")):
                        advisory_calls += 1
                    elif name in ("Task", "Agent"):
                        subagent = str(payload.get("subagent_type", ""))
                        prompt = str(payload.get("prompt", ""))
                        if subagent == "advisory" or "defender/skills/advisory" in prompt:
                            advisory_calls += 1
    metrics["total_input_tokens"] = total_in
    metrics["total_output_tokens"] = total_out
    metrics["total_cost_usd"] = round(total_cost, 4)
    metrics["advisory_call_count"] = advisory_calls
    metrics["advisory_invocation_rate"] = (
        round(advisory_calls / loops_count, 3) if loops_count else None
    )
    return metrics


def run_one(arm: str, case_id: str, results_dir: Path, *,
            trial: int = 1, model: str | None = None) -> dict:
    cases = load_cases()
    case = case_by_id(cases, case_id)
    run_dir = spawn_run(arm, case, trial, model=model)
    metrics = extract_metrics(run_dir, arm, case)
    out_path = results_dir / f"{arm}-{case_id}-t{trial}.json"
    out_path.write_text(json.dumps(metrics, indent=2))
    print(f"[advisory-ab] {arm}/{case_id}/t{trial}: "
          f"disposition={metrics['disposition_observed']} "
          f"match={metrics['disposition_match']} "
          f"loops={metrics['loops_count']} leads={metrics['leads_count']} "
          f"advisory_calls={metrics['advisory_call_count']} "
          f"cost=${metrics['total_cost_usd']} "
          f"wall={metrics['wall_clock_seconds']:.1f}s", file=sys.stderr)
    return metrics


def run_all(results_dir: Path, *, trials: int = 1, model: str | None = None) -> None:
    cases = load_cases()
    for arm in cases["arms"]:
        for bucket in ("positives", "negatives"):
            for c in cases[bucket]:
                for trial in range(1, trials + 1):
                    run_one(arm, c["id"], results_dir, trial=trial, model=model)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--arm", choices=["a", "b", "c", "d"])
    p.add_argument("--case", help="case_id from cases.json")
    p.add_argument("--trial", type=int, default=1, help="trial index for single-run mode (default 1)")
    p.add_argument("--trials", type=int, default=3, help="trials per (arm, case) in --all mode (default 3)")
    p.add_argument("--all", action="store_true", help="run every (arm, case, trial) sequentially")
    p.add_argument("--model", default=None)
    p.add_argument("--results-dir", default=None, help="override results subdir (default: results/<timestamp>)")
    ns = p.parse_args(argv)

    if not ns.all and not (ns.arm and ns.case):
        p.error("provide --arm and --case, or --all")

    if ns.results_dir:
        results_dir = Path(ns.results_dir)
    else:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        results_dir = RESULTS_DIR / ts
    results_dir.mkdir(parents=True, exist_ok=True)

    if ns.all:
        run_all(results_dir, trials=ns.trials, model=ns.model)
    else:
        run_one(ns.arm, ns.case, results_dir, trial=ns.trial, model=ns.model)
    print(f"[advisory-ab] results in {results_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
