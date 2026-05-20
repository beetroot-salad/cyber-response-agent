#!/usr/bin/env python3
"""Aggregate advisory_ab/results/<ts>/*.json into per-arm comparison tables.

Three tables:

  1. Outcome × category — disposition_match by arm, split positive/negative.
  2. Cost × category    — mean cost / wall-clock / tokens by arm, split.
                          The split matters because the load-bearing
                          question is whether always-on advisory pays its
                          way on cases where it doesn't help.
  3. Invocation rate    — for B/C only; what fraction of PLAN turns
                          actually called advisory? Predicts whether the
                          discretion arm matches A on negatives (low rate)
                          or matches D on positives (high rate).
"""
from __future__ import annotations

import argparse
import json
import statistics as stats
import sys
from collections import defaultdict
from pathlib import Path


def load_results(results_dir: Path) -> list[dict]:
    out = []
    for path in sorted(results_dir.glob("*.json")):
        try:
            out.append(json.loads(path.read_text()))
        except json.JSONDecodeError:
            print(f"skipping unparseable {path}", file=sys.stderr)
    return out


def by_arm_cat(records: list[dict]) -> dict[tuple[str, str], list[dict]]:
    out: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in records:
        out[(r["arm"], r["category"])].append(r)
    return out


def fmt(v, n=2):
    if v is None: return "—"
    if isinstance(v, float): return f"{v:.{n}f}"
    return str(v)


def render_outcome_table(grouped: dict) -> str:
    arms = sorted({a for a, _ in grouped.keys()})
    cats = ["positive", "negative"]
    lines = ["## Outcome: disposition_match by arm × category (across trials)", ""]
    lines.append("| arm | positive (match/total) | negative (match/total) |")
    lines.append("|---|---|---|")
    for arm in arms:
        cells = [arm]
        for cat in cats:
            recs = grouped.get((arm, cat), [])
            matches = sum(1 for r in recs if r["disposition_match"])
            cells.append(f"{matches}/{len(recs)}")
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def render_cost_table(grouped: dict) -> str:
    arms = sorted({a for a, _ in grouped.keys()})
    cats = ["positive", "negative"]
    lines = ["", "## Cost: mean per run by arm × category", ""]
    lines.append("| arm | cat | n | mean $ | mean tokens (in/out) | mean wall (s) | mean loops | mean leads |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for arm in arms:
        for cat in cats:
            recs = grouped.get((arm, cat), [])
            if not recs: continue
            cost = stats.mean(r["total_cost_usd"] for r in recs)
            t_in = stats.mean(r["total_input_tokens"] for r in recs)
            t_out = stats.mean(r["total_output_tokens"] for r in recs)
            wall = stats.mean(r["wall_clock_seconds"] for r in recs)
            loops = stats.mean(r["loops_count"] for r in recs)
            leads = stats.mean(r["leads_count"] for r in recs)
            lines.append(
                f"| {arm} | {cat} | {len(recs)} | {fmt(cost, 3)} | "
                f"{int(t_in)}/{int(t_out)} | {fmt(wall, 1)} | "
                f"{fmt(loops, 1)} | {fmt(leads, 1)} |"
            )
    return "\n".join(lines)


def render_invocation_table(grouped: dict) -> str:
    """For arms B and C only — discretion arms. D always fires (rate=1.0 by
    construction); A never fires."""
    lines = ["", "## Invocation discipline (arms b/c only)", ""]
    lines.append("| arm | cat | n | mean calls | mean rate (calls/loop) |")
    lines.append("|---|---|---|---|---|")
    for arm in ("b", "c"):
        for cat in ("positive", "negative"):
            recs = grouped.get((arm, cat), [])
            if not recs: continue
            calls = stats.mean(r["advisory_call_count"] for r in recs)
            rates = [r["advisory_invocation_rate"] for r in recs if r["advisory_invocation_rate"] is not None]
            rate = stats.mean(rates) if rates else None
            lines.append(
                f"| {arm} | {cat} | {len(recs)} | {fmt(calls, 1)} | "
                f"{fmt(rate, 2)} |"
            )
    return "\n".join(lines)


def render_relevance_check(grouped: dict, records: list[dict]) -> str:
    """Did the case-level predicted_relevance bear out? For each arm, show
    cost delta vs A on cases predicted relevant vs not. Sanity check on the
    case-labelling."""
    lines = ["", "## Predicted relevance vs realized Δcost vs A", ""]
    arms = sorted({a for a, _ in grouped.keys()} - {"a"})
    a_means: dict[str, float] = {}
    for cat in ("positive", "negative"):
        recs = grouped.get(("a", cat), [])
        if recs:
            a_means[cat] = stats.mean(r["total_cost_usd"] for r in recs)
    lines.append("| arm | cat | n | mean $ | Δ$ vs A |")
    lines.append("|---|---|---|---|---|")
    for arm in arms:
        for cat in ("positive", "negative"):
            recs = grouped.get((arm, cat), [])
            if not recs: continue
            cost = stats.mean(r["total_cost_usd"] for r in recs)
            base = a_means.get(cat)
            delta = (cost - base) if base is not None else None
            lines.append(f"| {arm} | {cat} | {len(recs)} | {fmt(cost, 3)} | {fmt(delta, 3)} |")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("results_dir", type=Path)
    ns = p.parse_args(argv)
    records = load_results(ns.results_dir)
    if not records:
        sys.exit(f"no results in {ns.results_dir}")
    grouped = by_arm_cat(records)
    print(render_outcome_table(grouped))
    print(render_cost_table(grouped))
    print(render_invocation_table(grouped))
    print(render_relevance_check(grouped, records))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
