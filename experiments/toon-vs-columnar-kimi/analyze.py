"""Metrics, aggregation and comparison for the TOON-vs-columnar run.

Ranking is by per-occurrence mean with n shown as support.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

HERE = Path(__file__).parent


def norm(v) -> str:
    s = str(v).strip().strip('"').strip("'").lower()
    try:
        f = float(s)
        return str(int(f)) if f == int(f) else str(f)
    except (TypeError, ValueError):
        return s


def correct(rec: dict) -> bool:
    return norm(rec["got"]) == norm(rec["expected"])


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def main() -> None:
    allrecs = [json.loads(p.read_text()) for p in sorted((HERE / "runs").glob("*.json"))]
    if not allrecs:
        print("no runs")
        return
    # A length-capped trial emitted no answer — invalid, not incorrect. Report, then drop.
    trunc = [r for r in allrecs if r.get("finish_reason") == "length"]
    recs = [r for r in allrecs if r.get("finish_reason") != "length"]
    if trunc:
        by_arm = {a: sum(1 for r in trunc if r["arm"] == a) for a in sorted({r["arm"] for r in trunc})}
        print(f"EXCLUDED (finish_reason=length, no answer emitted): {len(trunc)} — {by_arm}\n")
    arms = sorted({r["arm"] for r in recs})

    print(f"trials: {len(recs)}\n")
    print(f"{'arm':<9} {'kind':<12} {'n':>4} {'acc':>7} {'wilson95':>16} {'tokens':>9}")
    print("-" * 62)
    for arm in arms:
        for kind in ("cell_lookup", "arity", "extremum", "ALL"):
            sub = [r for r in recs if r["arm"] == arm and (kind == "ALL" or r["kind"] == kind)]
            if not sub:
                continue
            k = sum(correct(r) for r in sub)
            lo, hi = wilson(k, len(sub))
            tok = sum(r["prompt_tokens"] for r in sub) / len(sub)
            print(f"{arm:<9} {kind:<12} {len(sub):>4} {k / len(sub):>6.1%} "
                  f"  [{lo:>5.1%},{hi:>5.1%}] {tok:>9.0f}")
        print()

    # paired comparison on identical (fixture, question)
    pairs: dict[tuple, dict] = {}
    for r in recs:
        pairs.setdefault((r["fixture"], r["qi"]), {})[r["arm"]] = r
    both = [p for p in pairs.values() if len(p) == len(arms)]
    if len(arms) == 2 and both:
        a, b = arms  # "current", "toon"
        ta = sum(p[a]["prompt_tokens"] for p in both)
        tb = sum(p[b]["prompt_tokens"] for p in both)
        ba = sum(p[a]["view_bytes"] for p in both)
        bb = sum(p[b]["view_bytes"] for p in both)
        print(f"paired fixtures/questions: {len(both)}")
        print(f"  input tokens  {a}={ta:,}  {b}={tb:,}   delta={100 * (tb - ta) / ta:+.1f}%")
        print(f"  view bytes    {a}={ba:,}  {b}={bb:,}   delta={100 * (bb - ba) / ba:+.1f}%")

        for kind in ("cell_lookup", "ALL"):
            sel = [p for p in both if kind == "ALL" or p[a]["kind"] == kind]
            ka = sum(correct(p[a]) for p in sel)
            kb = sum(correct(p[b]) for p in sel)
            # Wilson bound on the DIFFERENCE via independent intervals (conservative)
            loa, hia = wilson(ka, len(sel))
            lob, hib = wilson(kb, len(sel))
            print(f"  {kind:<12} {a}={ka}/{len(sel)} ({ka / len(sel):.1%})  "
                  f"{b}={kb}/{len(sel)} ({kb / len(sel):.1%})  "
                  f"worst-case delta={100 * (lob - hia):+.1f}pp")
            flips = [(p[a]["fixture"], p[a]["qi"]) for p in sel
                     if correct(p[a]) and not correct(p[b])]
            if flips:
                print(f"    {b} lost on: {flips[:8]}")


if __name__ == "__main__":
    main()
