#!/usr/bin/env python3
"""Arm B analyzer: score every run in runs/ against its rubric.

Output: results/scores.json and a printed summary table.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
RUNS_DIR = ROOT / "runs"
RESULTS_DIR = ROOT / "results"


def extract_query(stdout: str) -> str | None:
    """Pull out the bash command line(s). Looks for the wazuh_cli.py invocation.

    Joins backslash-continuations into a single logical line.
    Returns None if no command can be located.
    """
    if not stdout:
        return None
    text = re.sub(r"\\\n\s*", " ", stdout)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    candidates = [ln for ln in lines if "wazuh_cli.py" in ln and "query" in ln]
    if candidates:
        return candidates[-1]
    return lines[-1] if lines else None


def score(query: str | None, rubric: dict) -> tuple[str, dict]:
    """Return (verdict, detail)."""
    if not query:
        return "unparseable", {"reason": "no query line found"}

    missing = [s for s in rubric.get("expected_substrings", []) if s not in query]
    forbidden_hits = [s for s in rubric.get("forbidden_substrings", []) if s in query]

    detail = {
        "query": query,
        "missing_expected": missing,
        "forbidden_hits": forbidden_hits,
    }

    if not missing and not forbidden_hits:
        verdict = "correct"
    elif forbidden_hits:
        verdict = "wrong"
    elif len(missing) <= 1 and not forbidden_hits:
        verdict = "partially-correct"
    else:
        verdict = "wrong"

    return verdict, detail


def main():
    runs = sorted(RUNS_DIR.glob("*.json"))
    if not runs:
        print("no runs found", file=sys.stderr)
        return 1

    rows = []
    for run_path in runs:
        run = json.loads(run_path.read_text())
        query = extract_query(run["stdout"])
        verdict, detail = score(query, run["rubric"])
        rows.append({
            "fixture": run["fixture_id"],
            "category": run["category"],
            "trial": run["trial"],
            "verdict": verdict,
            "detail": detail,
            "elapsed_s": run["elapsed_s"],
        })

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "scores.json").write_text(json.dumps(rows, indent=2))

    print(f"{'fixture':<32} {'trial':<6} {'verdict':<20} {'elapsed':<8}")
    print("-" * 70)
    for r in rows:
        print(f"{r['fixture']:<32} {r['trial']:<6} {r['verdict']:<20} {r['elapsed_s']:<8}")

    verdicts = [r["verdict"] for r in rows]
    n = len(verdicts)
    print()
    print(f"n={n}  correct={verdicts.count('correct')}  "
          f"partial={verdicts.count('partially-correct')}  "
          f"wrong={verdicts.count('wrong')}  "
          f"unparseable={verdicts.count('unparseable')}")

    failed = [r for r in rows if r["verdict"] != "correct"]
    if failed:
        print()
        print("=== failures ===")
        for r in failed:
            print(f"\n--- {r['fixture']} trial {r['trial']} ({r['verdict']}) ---")
            d = r["detail"]
            print(f"  query: {d.get('query', '<none>')}")
            if d.get("missing_expected"):
                print(f"  missing: {d['missing_expected']}")
            if d.get("forbidden_hits"):
                print(f"  forbidden hits: {d['forbidden_hits']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
