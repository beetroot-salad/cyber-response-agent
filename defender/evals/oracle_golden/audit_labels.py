#!/usr/bin/env python3
"""Calibrate the labeler against the hand-derived seed labels (#711 M9a / O6).

When labels are produced by a program, that program is itself calibrated against
hand-derived truth before its output is trusted. This is not the same obligation
as having a lot of cases: a labeler bug biases *every* case the same way, and no
amount of `n` detects a systematic error — unlike human error, which is at least
uncorrelated across cases.

The seed six are the audit set. They are hand-derived and were already
re-verified once against the environment, and this is the one job a pool that
prompt iteration has already seen can still do honestly, because nothing here
involves the oracle's output at all.

**A divergence is adjudicated by re-measurement, never by adjusting the labeler
to agree.** That direction is the whole point — a labeler tuned until it
reproduces the hand labels has been fitted to them and calibrates nothing.

Exit code is non-zero on a CLASS divergence. `needs-label` is not a divergence:
it is the labeler declining to decide, which is a designed outcome for a state
system with no declared rule and for a query with no measurable control.

Usage: audit_labels.py [<cases_dir>] [--json <out.json>]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import yaml

GOLDEN_DIR = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


LABEL = _load("oracle_golden_label", GOLDEN_DIR / "label.py")


def audit_case(case_dir: Path) -> list[dict]:
    """One row per lead: the hand label, the derived label, and whether they agree."""
    expected = yaml.safe_load((case_dir / "expected.yaml").read_text(encoding="utf-8"))
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    leads = {}
    text = (case_dir / "oracle_visible" / "leads.jsonl").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.strip():
            row = json.loads(line)
            leads[row["lead_id"]] = row

    rows = []
    for lead_id, hand in sorted(expected["leads"].items()):
        derived = LABEL.label_lead(
            case_dir, lead_id, leads.get(lead_id, {}).get("queries", []),
            hand["system"], manifest)
        hand_het = hand.get("heterogeneous", False)
        rows.append({
            "case": case_dir.name,
            "lead": lead_id,
            "system": hand["system"],
            "hand_class": hand["class"],
            "derived_class": derived["class"],
            "class_agrees": derived["class"] == hand["class"],
            "undecided": derived["class"] == LABEL.NEEDS_LABEL,
            "hand_heterogeneous": hand_het,
            "derived_heterogeneous": derived["heterogeneous"],
            "per_query": [q["class"] for q in derived["per_query"]],
        })
    return rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cases_dir", type=Path, nargs="?", default=GOLDEN_DIR / "cases")
    p.add_argument("--json", type=Path, default=None, dest="json_out")
    ns = p.parse_args(argv)

    rows: list[dict] = []
    for case_dir in sorted(d for d in ns.cases_dir.iterdir() if d.is_dir()):
        if not (case_dir / "hidden" / "observed").is_dir():
            continue          # derived case: labels are definitional, nothing measured
        rows.extend(audit_case(case_dir))

    decided = [r for r in rows if not r["undecided"]]
    divergent = [r for r in decided if not r["class_agrees"]]
    het_changed = [r for r in rows
                   if r["derived_heterogeneous"] is not None
                   and r["derived_heterogeneous"] != r["hand_heterogeneous"]]

    print(f"{'case':34} {'lead':6} {'hand':11} {'derived':11} het(hand->derived)")
    for r in rows:
        mark = "" if (r["class_agrees"] or r["undecided"]) else "   <-- CLASS DIVERGENCE"
        het = ""
        if r["derived_heterogeneous"] is not None and \
                r["derived_heterogeneous"] != r["hand_heterogeneous"]:
            het = f"  {r['hand_heterogeneous']} -> {r['derived_heterogeneous']}"
        print(f"{r['case'][:34]:34} {r['lead']:6} {r['hand_class']:11} "
              f"{r['derived_class']:11}{het}{mark}")

    print(f"\nleads: {len(rows)}   decided by the labeler: {len(decided)}   "
          f"undecided (needs-label): {len(rows) - len(decided)}")
    print(f"class divergences: {len(divergent)}")
    print(f"heterogeneous corrections: {len(het_changed)}"
          + (f" ({', '.join(r['lead'] for r in het_changed)})" if het_changed else ""))

    if ns.json_out:
        ns.json_out.parent.mkdir(parents=True, exist_ok=True)
        ns.json_out.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {ns.json_out}")

    if divergent:
        print("\n!! A class divergence must be resolved by RE-MEASURING the environment,")
        print("   never by adjusting the labeler until it agrees with the hand label.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
