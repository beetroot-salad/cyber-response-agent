#!/usr/bin/env python3
"""Aggregate lead-classifier-ablation trial verdicts.

Reads runs/<variant>/<fixture>/<trial>/verdict.txt (first line = PASS|WEAK-PASS|
FAIL, written by harness_lead.py's capture()). Reports, per (variant, fixture):
  underfold_rate = FAIL / N        # the headline: promoting a narrow sibling
  discard_rate   = PASS / N        # clean fold
  skip_rate      = WEAK-PASS / N   # tolerable non-fold
with N shown as support. Ranks nothing count-weighted — per-occurrence means only.

Usage: python analyze.py [runs_dir]
"""
import sys
from collections import defaultdict
from pathlib import Path

RUNS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "runs"
LEVELS = ("FAIL", "WEAK-PASS", "PASS")


def main():
    # counts[(variant, fixture)][level] = n
    counts = defaultdict(lambda: defaultdict(int))
    for vtxt in sorted(RUNS.glob("*/*/*/verdict.txt")):
        variant, fixture = vtxt.parts[-4], vtxt.parts[-3]
        level = vtxt.read_text().splitlines()[0].strip() if vtxt.read_text().strip() else "MISSING"
        counts[(variant, fixture)][level] += 1

    if not counts:
        print(f"no verdicts under {RUNS}")
        return

    fixtures = sorted({f for _, f in counts})
    variants = sorted({v for v, _ in counts})
    for fixture in fixtures:
        print(f"\n## {fixture}")
        print(f"{'variant':12s} {'N':>3s} {'FAIL':>6s} {'WEAK':>6s} {'PASS':>6s}  underfold  discard")
        for variant in variants:
            c = counts.get((variant, fixture))
            if not c:
                continue
            n = sum(c.get(lvl, 0) for lvl in LEVELS)
            fail, weak, pas = c.get("FAIL", 0), c.get("WEAK-PASS", 0), c.get("PASS", 0)
            uf = fail / n if n else 0.0
            dr = pas / n if n else 0.0
            print(f"{variant:12s} {n:3d} {fail:6d} {weak:6d} {pas:6d}   {uf:6.1%}   {dr:6.1%}")
    # Headline comparison: per fixture, Δ underfold (proposed - current).
    print("\n## Δ underfold (proposed − current), positive = removal hurts")
    for fixture in fixtures:
        def rate(v):
            c = counts.get((v, fixture), {})
            n = sum(c.get(lvl, 0) for lvl in LEVELS)
            return (c.get("FAIL", 0) / n) if n else None
        cur, prop = rate("current"), rate("proposed")
        if cur is None or prop is None:
            print(f"  {fixture:28s} (incomplete)")
        else:
            print(f"  {fixture:28s} {prop - cur:+.1%}")


if __name__ == "__main__":
    main()
