#!/usr/bin/env python3
"""Score an oracle projection against a golden case's ground-truth labels.

Reports the #693 dimensions, not one accuracy number:
  - four-way result-class agreement (0 | +noise | +event | -noise), stratified
    by system;
  - field/value grounding on +event leads: concrete-correct / wrong / unknown
    (placeholder) / missing — `wrong` is the dangerous error, placeholders are
    never `wrong`;
  - occurrence precision/recall: emitted +event where expected (recall), stayed
    empty where expected 0 (precision);
  - false suppression: any -noise predicted where the stream is alive.

Compares the projection to `expected.yaml` (authoritative envelope truth). The
lead's stated intent is reported to explain divergence, never to excuse it.

Usage: score.py <case_dir> <projection.yaml> [--json <out.json>]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml


def project_class(events: list) -> str:
    if not events:
        return "0"
    markers = [e for e in events if isinstance(e, str)]
    if markers:
        return "-noise" if any(m.strip().startswith("<suppressed") for m in markers) else "+noise"
    return "+event"


def concrete_fields(events: list) -> dict:
    """Union of concrete (non-placeholder) key/value pairs across event mappings."""
    out = {}
    for e in events:
        if not isinstance(e, dict):
            continue
        for k, v in e.items():
            if not str(v).startswith("<"):
                out.setdefault(k, str(v))
    return out


def grade_fields(expected: dict, got: dict, events: list) -> dict:
    """For each expected distinguishing field: correct / wrong / unknown / missing."""
    # was the field emitted at all (even as a placeholder)?
    emitted_keys = {k for e in events if isinstance(e, dict) for k in e}
    result = {}
    for k, want in expected.items():
        if k in got:
            result[k] = "correct" if got[k] == str(want) else f"wrong(got {got[k]})"
        elif k in emitted_keys:
            result[k] = "unknown"          # emitted only as a placeholder
        else:
            result[k] = "missing"
    return result


def main() -> None:
    case_dir = Path(sys.argv[1])
    proj_path = Path(sys.argv[2])
    json_out = None
    if "--json" in sys.argv:
        json_out = Path(sys.argv[sys.argv.index("--json") + 1])

    expected = yaml.safe_load((case_dir / "expected.yaml").read_text())["leads"]
    proj = yaml.safe_load(proj_path.read_text())
    preds = {p["lead_id"]: p["events"] for p in proj["projections"]}

    rows = []
    by_system = {}
    for lead_id, exp in expected.items():
        events = preds.get(lead_id, [])
        pred_c = project_class(events)
        exp_c = exp["class"]
        system = exp["system"]
        match = pred_c == exp_c
        fields = grade_fields(exp.get("fields", {}), concrete_fields(events), events) if exp_c == "+event" else {}
        rows.append({
            "lead": lead_id, "system": system, "expected": exp_c, "predicted": pred_c,
            "class_match": match, "heterogeneous": exp.get("heterogeneous", False),
            "fields": fields, "intent_note": bool(exp.get("intent_note")),
        })
        st = by_system.setdefault(system, {"n": 0, "match": 0})
        st["n"] += 1
        st["match"] += match

    # aggregate metrics
    n = len(rows)
    class_agree = sum(r["class_match"] for r in rows)
    ev_expected = [r for r in rows if r["expected"] == "+event"]
    zero_expected = [r for r in rows if r["expected"] == "0"]
    recall = sum(r["predicted"] == "+event" for r in ev_expected) / (len(ev_expected) or 1)
    precision_zero = sum(r["predicted"] == "0" for r in zero_expected) / (len(zero_expected) or 1)
    all_field_grades = [g for r in rows for g in r["fields"].values()]
    wrong = [g for g in all_field_grades if g.startswith("wrong")]
    false_suppress = [r for r in rows if r["predicted"] == "-noise" and r["expected"] != "-noise"]

    summary = {
        "projection": proj_path.name,
        "n_leads": n,
        "class_agreement": f"{class_agree}/{n}",
        "by_system": {s: f"{v['match']}/{v['n']}" for s, v in sorted(by_system.items())},
        "plus_event_recall": round(recall, 3),
        "zero_precision": round(precision_zero, 3),
        "field_grades": {g: all_field_grades.count(g) for g in sorted(set(all_field_grades))},
        "wrong_concrete_fields": len(wrong),
        "false_suppression": len(false_suppress),
        "rows": rows,
    }

    # human view
    print(f"== score: {proj_path.name} vs {case_dir.name} ==")
    print(f"class agreement: {class_agree}/{n}   +event recall: {recall:.2f}   "
          f"0 precision: {precision_zero:.2f}")
    print(f"by system: {summary['by_system']}")
    print(f"field grounding: {summary['field_grades']}   "
          f"WRONG concrete: {len(wrong)}   false-suppression: {len(false_suppress)}")
    print()
    for r in rows:
        tag = "ok " if r["class_match"] else "DIS"
        het = " het" if r["heterogeneous"] else ""
        fld = ("  fields=" + json.dumps(r["fields"])) if r["fields"] else ""
        note = "  [intent-scoped divergence]" if (not r["class_match"] and r["intent_note"]) else ""
        print(f"  {tag} {r['lead']:<6} {r['system']:<12} exp={r['expected']:<7} pred={r['predicted']:<7}{het}{fld}{note}")

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {json_out}")


if __name__ == "__main__":
    main()
