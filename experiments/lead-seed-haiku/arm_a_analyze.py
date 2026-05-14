#!/usr/bin/env python3
"""Arm A analyzer: score selection outputs against ground truth.

Verdict logic:
  clear-match  -> 'correct' if SELECT names the correct lead as the (first) match,
                  'partial' if SELECT names it among multiple,
                  'wrong' if SELECT names a different lead,
                  'no-match' if PROPOSE_NEW.
  no-match     -> 'correct' if PROPOSE_NEW,
                  'wrong' if SELECT names any catalog lead.
  ambiguous    -> 'correct' if SELECT lists ALL expected leads (any order),
                  'partial' if SELECT lists one of the expected leads,
                  'wrong' otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent
RUNS_DIR = ROOT / "runs_arm_a"
RESULTS_DIR = ROOT / "results"


def parse_selection(stdout: str) -> tuple[str, list[str], str]:
    """Return (mode, names, raw_decision_line).

    mode: 'SELECT' | 'PROPOSE_NEW' | 'UNPARSEABLE'
    names: lead names selected (empty for PROPOSE_NEW or UNPARSEABLE)
    """
    if not stdout:
        return "UNPARSEABLE", [], ""

    def _clean(s: str) -> str:
        return s.strip().lstrip("`*").rstrip("`*").strip()

    lines = [_clean(ln) for ln in stdout.splitlines() if _clean(ln)]
    decision_lines = [ln for ln in lines if ln.startswith("SELECT") or ln.startswith("PROPOSE_NEW")]
    if not decision_lines:
        return "UNPARSEABLE", [], ""

    line = decision_lines[-1]
    if line.startswith("PROPOSE_NEW"):
        return "PROPOSE_NEW", [], line

    rest = line[len("SELECT"):].strip()
    rest = re.sub(r"[`*]", "", rest)
    names = [n.strip() for n in rest.split(",") if n.strip()]
    return "SELECT", names, line


def score(fixture_class: str, expected: list[str], mode: str, names: list[str]) -> tuple[str, dict]:
    detail = {"mode": mode, "selected": names, "expected": expected}

    if mode == "UNPARSEABLE":
        return "unparseable", detail

    if fixture_class == "clear-match":
        target = expected[0]
        if mode == "PROPOSE_NEW":
            return "wrong", {**detail, "reason": "proposed new when catalog has match"}
        if not names:
            return "wrong", {**detail, "reason": "SELECT empty"}
        if names[0] == target:
            return "correct" if len(names) == 1 else "partial-overselected", detail
        if target in names:
            return "partial-not-first", detail
        return "wrong", {**detail, "reason": f"selected {names[0]}, expected {target}"}

    if fixture_class == "no-match":
        if mode == "PROPOSE_NEW":
            return "correct", detail
        return "wrong", {**detail, "reason": f"selected {names} when no match exists"}

    if fixture_class == "ambiguous":
        if mode == "PROPOSE_NEW":
            return "wrong", {**detail, "reason": "proposed new when composite of catalog leads would satisfy"}
        expected_set = set(expected)
        selected_set = set(names)
        if expected_set <= selected_set and selected_set <= expected_set:
            return "correct", detail
        if expected_set <= selected_set:
            return "partial-overselected", detail
        intersection = expected_set & selected_set
        if intersection:
            return "partial-incomplete", detail
        return "wrong", {**detail, "reason": f"selected {names}, expected any of {expected}"}

    return "unparseable", detail


def main():
    runs = sorted(RUNS_DIR.glob("*.json"))
    if not runs:
        print("no runs found", file=sys.stderr)
        return 1

    rows = []
    for run_path in runs:
        run = json.loads(run_path.read_text())
        mode, names, line = parse_selection(run["stdout"])
        verdict, detail = score(run["class"], run["correct_leads"], mode, names)
        rows.append({
            "fixture": run["fixture_id"],
            "class": run["class"],
            "catalog_size": run["catalog_size"],
            "trial": run["trial"],
            "verdict": verdict,
            "detail": detail,
            "decision_line": line,
            "elapsed_s": run["elapsed_s"],
        })

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "arm_a_scores.json").write_text(json.dumps(rows, indent=2))

    print(f"{'fixture':<6} {'class':<14} {'N':<5} {'trial':<6} {'verdict':<22} {'decision':<60}")
    print("-" * 115)
    for r in rows:
        dec = r["decision_line"][:58]
        print(f"{r['fixture']:<6} {r['class']:<14} {r['catalog_size']:<5} {r['trial']:<6} "
              f"{r['verdict']:<22} {dec:<60}")

    print()
    by_n = defaultdict(lambda: defaultdict(int))
    by_class = defaultdict(lambda: defaultdict(int))
    for r in rows:
        by_n[r["catalog_size"]][r["verdict"]] += 1
        by_class[(r["catalog_size"], r["class"])][r["verdict"]] += 1

    print("=== Rollup by catalog size ===")
    for n in sorted(by_n):
        d = by_n[n]
        total = sum(d.values())
        correct = d.get("correct", 0)
        partial = sum(v for k, v in d.items() if k.startswith("partial"))
        wrong = d.get("wrong", 0)
        unp = d.get("unparseable", 0)
        print(f"  N={n:<5} n={total:<3} correct={correct:<3} partial={partial:<3} "
              f"wrong={wrong:<3} unparseable={unp}")

    print()
    print("=== Rollup by (N, class) ===")
    for key in sorted(by_class):
        n, cls = key
        d = by_class[key]
        total = sum(d.values())
        correct = d.get("correct", 0)
        partial = sum(v for k, v in d.items() if k.startswith("partial"))
        wrong = d.get("wrong", 0)
        print(f"  N={n:<5} class={cls:<14} n={total:<3} correct={correct:<3} "
              f"partial={partial:<3} wrong={wrong:<3}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
