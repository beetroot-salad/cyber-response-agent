#!/usr/bin/env python3
"""Capture arm-A post-ORIENT anchor per case.

Spawns defender once per case (POS-1, NEG-1) with a prompt that
forces the agent to stop after ORIENT (no PLAN, no GATHER, no
REPORT). The resulting investigation.md is the shared PLAN-time
anchor for replay.py — every arm's PLAN-only run starts from this
exact on-disk state.

Outputs:
    anchors/<CASE_ID>/investigation.md   — post-ORIENT snapshot
    anchors/<CASE_ID>/_capture.json      — run dir + cost + wall-clock
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent                       # .../plan_only
AB_DIR = HERE.parent                                          # .../advisory-ab
REPO_ROOT = AB_DIR.parents[1]                                 # repo root
DEFENDER_DIR = REPO_ROOT / "defender"
ANCHORS_DIR = HERE / "anchors"
FIXTURES_DIR = AB_DIR / "fixtures"

CASES = ["POS-1", "NEG-1"]

CAPTURE_PROMPT = """## Run context
case_id: {run_id}
run_dir: {run_dir}
alert: {run_dir}/alert.json

Read defender/SKILL.md.

**Scope for this run: ORIENT ONLY.** Author `investigation.md` with a
single `## ORIENT` section containing the `:V prologue.vertices` and
`:E prologue.edges` blocks derived from the alert, plus the one-line
triage question that names what the disposition turns on.

After writing the triage question, **STOP**. Do NOT:
- Author any `## PLAN` section
- Write `:H` (hypotheses) or `:L` (leads) blocks
- Dispatch the gather subagent
- Write `report.md`

The run dir already has `alert.json` and an empty `gather_raw/`.
Write only `investigation.md`. Do not call any tools after the final
Write/Edit on `investigation.md`.
"""


def materialize_run_dir(case_id: str, alert: Path) -> Path:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"plan-only-anchor-{case_id.lower()}-{ts}"
    run_dir = Path("/tmp/defender-runs") / run_id
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(alert, run_dir / "alert.json")
    return run_dir


def spawn_capture(case_id: str) -> dict:
    fixture = FIXTURES_DIR / case_id
    alert = fixture / "alert.json"
    if not alert.is_file():
        sys.exit(f"missing fixture alert: {alert}")

    run_dir = materialize_run_dir(case_id, alert)

    sys.path.insert(0, str(DEFENDER_DIR))
    try:
        import run as defender_run  # type: ignore
    finally:
        sys.path.pop(0)

    settings_path = defender_run.build_settings_file()
    prompt = CAPTURE_PROMPT.format(run_id=run_dir.name, run_dir=run_dir)
    model = defender_run.DEFAULT_MODEL

    print(f"[capture] {case_id}: run_dir={run_dir}", file=sys.stderr)
    t0 = time.monotonic()
    rc = defender_run.spawn_claude(prompt, run_dir, settings_path, model, effort=None)
    wall = time.monotonic() - t0

    inv = run_dir / "investigation.md"
    if not inv.is_file():
        sys.exit(f"[capture] {case_id}: investigation.md not written; rc={rc}")

    # Persist the anchor.
    case_anchor = ANCHORS_DIR / case_id
    case_anchor.mkdir(parents=True, exist_ok=True)
    shutil.copy(inv, case_anchor / "investigation.md")

    # Pull cost from tool_trace.
    cost = 0.0
    tin = tout = 0
    trace = run_dir / "tool_trace.jsonl"
    if trace.is_file():
        for line in trace.read_text().splitlines():
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("type") == "result":
                cost += float(ev.get("total_cost_usd", 0) or 0)
                usage = ev.get("usage", {}) or {}
                tin += usage.get("input_tokens", 0) or 0
                tout += usage.get("output_tokens", 0) or 0

    meta = {
        "case_id": case_id,
        "run_dir": str(run_dir),
        "rc": rc,
        "wall_clock_s": round(wall, 2),
        "total_cost_usd": round(cost, 4),
        "input_tokens": tin,
        "output_tokens": tout,
        "model": model,
    }
    (case_anchor / "_capture.json").write_text(json.dumps(meta, indent=2))
    print(f"[capture] {case_id}: cost=${meta['total_cost_usd']} "
          f"wall={meta['wall_clock_s']}s rc={rc}", file=sys.stderr)
    return meta


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--case", choices=CASES, help="Capture one case only (default: all)")
    ns = p.parse_args(argv)

    cases = [ns.case] if ns.case else CASES
    ANCHORS_DIR.mkdir(parents=True, exist_ok=True)
    for c in cases:
        spawn_capture(c)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
