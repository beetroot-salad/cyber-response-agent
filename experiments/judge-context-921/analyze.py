#!/usr/bin/env python3
"""Aggregate grades per (arm, fixture). Rank by per-occurrence mean; n shown as support."""
from __future__ import annotations
import json, sys
from collections import defaultdict
from pathlib import Path
HERE = Path(__file__).resolve().parent
SCORE = {"hit": 1.0, "partial": 0.5, "miss": 0.0}


def main() -> int:
    cells: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for g in sorted((HERE / "runs").glob("*/*/t*/grade.json")):
        arm, fixture = g.parts[-4], g.parts[-3]
        grade = json.loads(g.read_text())
        meta = json.loads((g.parent / "meta.json").read_text()) if (g.parent / "meta.json").is_file() else {}
        ref = grade.get("reference", {})
        um = grade.get("unmatched", []) or []
        cells[(arm, fixture)].append({
            "trial": g.parent.name,
            "R": {k: SCORE.get((v or {}).get("verdict"), 0.0) for k, v in ref.items()},
            "recall": sum(SCORE.get((v or {}).get("verdict"), 0.0) for v in ref.values()),
            "um_true": sum(1 for u in um if u.get("verdict") == "true"),
            "um_false": sum(1 for u in um if u.get("verdict") == "false"),
            "um_dup": sum(1 for u in um if u.get("verdict") == "duplicate"),
            "grounded": grade.get("grounded_pointer_share"),
            "tok_in": (meta.get("usage") or {}).get("input_tokens"),
            "tok_out": (meta.get("usage") or {}).get("output_tokens"),
        })
    lines = ["| arm | fixture | n | recall/3 (mean) | R1 | R2 | R3 | unmatched true | unmatched false | dup | grounded | tok in | tok out |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    def mean(xs):
        xs = [x for x in xs if x is not None]
        return round(sum(xs) / len(xs), 2) if xs else None
    for (arm, fixture), rows in sorted(cells.items()):
        n = len(rows)
        lines.append(f"| {arm} | {fixture} | {n} | {mean([r['recall'] for r in rows])} | "
                     + " | ".join(str(mean([r['R'].get(k, 0.0) for r in rows])) for k in ("R1", "R2", "R3"))
                     + f" | {mean([r['um_true'] for r in rows])} | {mean([r['um_false'] for r in rows])} | {mean([r['um_dup'] for r in rows])} | "
                     f"{mean([r['grounded'] for r in rows])} | {mean([r['tok_in'] for r in rows])} | {mean([r['tok_out'] for r in rows])} |")
    lines.append("\nPer-trial:")
    for (arm, fixture), rows in sorted(cells.items()):
        for r in rows:
            lines.append(f"- {arm}/{fixture}/{r['trial']}: recall={r['recall']} R={r['R']} um_true={r['um_true']} um_false={r['um_false']} dup={r['um_dup']} grounded={r['grounded']}")
    out = "\n".join(lines)
    print(out)
    if len(sys.argv) > 1:
        (HERE / "results" / sys.argv[1]).write_text(out + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
