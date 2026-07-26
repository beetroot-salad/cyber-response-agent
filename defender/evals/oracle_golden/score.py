#!/usr/bin/env python3
"""Score an oracle projection against a golden case's ground-truth labels.

Reports the #693 dimensions, not one accuracy number:
  - four-way result-class agreement (0 | +noise | +event | -noise), stratified
    by system;
  - field/value grounding on +event leads: concrete-correct / wrong / unknown
    (placeholder) / missing — `wrong` is the dangerous error, placeholders are
    never `wrong`;
  - the volunteered-value check (`observed_fields`): ground truth for fields the
    labels do NOT require, graded only where the projection emitted a concrete
    value for the key. Grading only the required fields lets a projection invent
    refuted values for free — the fabrication that manufactures a catch;
  - occurrence precision/recall: emitted +event where expected (recall), stayed
    empty where expected 0 (precision) — `null` when the case has no lead of
    that class, never 0.0, so aggregating slices cannot read "undefined" as
    "worst possible";
  - false suppression: any -noise predicted where the stream is alive;
  - lead-set integrity: a projection that is missing leads, carries leads the
    labels do not cover, or repeats a lead_id is reported and exits non-zero. A
    missing lead is NOT scored as an empty one — silent under-coverage would let
    a truncated projection pass an all-`0` case perfectly.

Compares the projection to `expected.yaml` (authoritative envelope truth). The
lead's stated intent is reported to explain divergence, never to excuse it.

Pure and deterministic given (expected.yaml, projection.yaml) — that is what lets
`defender/tests/test_oracle_golden_693.py` assert every checked-in
`scores/<tag>.json` still reproduces from its `projections/<tag>.yaml`.

Usage: score.py <case_dir> <projection.yaml> [--json <out.json>]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

# The oracle's output grammar is closed (defender/learning/pipeline/oracle/prompt.md
# §"Output"): a lead's events are either event MAPPINGS, or exactly one of two
# marker STRINGS. Anything else is malformed model output and must not be folded
# into a real class — a degraded model emitting prose would otherwise score as a
# clean `+noise`.
_SUPPRESSED_PREFIX = "<suppressed"
_NOISE_MARKER = "<standard environment noise>"
MALFORMED = "malformed"

# The predicted-class value for a labelled lead the projection never produced.
# Distinct from every real class — most importantly from `0`, which it would
# otherwise impersonate on exactly the cases (all-`0` negative controls) where a
# truncated projection is hardest to notice.
NOT_PROJECTED = "missing"

# Punctuation trimmed off a token before a leak comparison — `<`/`>` included, so
# the closing bracket of a marker ("…on office-ws-1>") does not hide a real leak.
# A whole `<placeholder>` is exempt (see _tokens): trimming those would turn the
# placeholder vocabulary into bare words and let `<port>` collide with `port`.
_TOKEN_TRIM = "\"'`,;:()[]{}<>"


def _norm(value: object) -> str:
    """One coercion for both sides of a value comparison (YAML ints/bools vs strings)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _marker_class(marker: str) -> str:
    text = marker.strip()
    if text.startswith(_SUPPRESSED_PREFIX):
        return "-noise"
    if text == _NOISE_MARKER:
        return "+noise"
    return MALFORMED


def project_class(events: list) -> str:
    """Map a lead's emitted events onto the oracle's four result classes.

    Returns `malformed` — never a real class — when the events fall outside the
    oracle's closed grammar: an unrecognized marker string, a marker mixed with
    event mappings (prompt.md: "Never mix a marker with event mappings in the
    same list"), or an item that is neither. `malformed` agrees with no expected
    class, so it scores as a disagreement instead of passing silently.

    Repeated markers of the SAME class still read as that class — unambiguous in
    meaning, even though prompt.md asks for a single marker item.
    """
    if not events:
        return "0"
    if all(isinstance(e, dict) for e in events):
        return "+event"
    if all(isinstance(e, str) for e in events):
        classes = {_marker_class(m) for m in events}
        return classes.pop() if len(classes) == 1 else MALFORMED
    return MALFORMED


def concrete_values(events: list) -> dict[str, set[str]]:
    """Concrete (non-placeholder) values per key, across every event mapping.

    A key collects the SET of values it takes, not the first one. A lead whose
    events legitimately carry the same field twice (an alert row plus the auth
    row it summarizes) must not grade `wrong` merely because ground truth
    matches the second event. `wrong` is the grade that gates a slice to
    `no-update`, so it has to mean "the projection contradicts ground truth",
    never "the projection emitted it in the wrong position".
    """
    out: dict[str, set[str]] = {}
    for e in events:
        if not isinstance(e, dict):
            continue
        for k, v in e.items():
            text = _norm(v)
            if not text.startswith("<"):  # `<placeholder>` = stated-unknown, not a value
                out.setdefault(str(k), set()).add(text)
    return out


def grade_fields(expected: dict, got: dict[str, set[str]], events: list) -> dict:
    """For each expected distinguishing field: correct / wrong / unknown / missing."""
    # was the field emitted at all (even as a placeholder)?
    emitted_keys = {str(k) for e in events if isinstance(e, dict) for k in e}
    result = {}
    for k, want in expected.items():
        key = str(k)
        values = got.get(key)
        if values:
            result[key] = ("correct" if _norm(want) in values
                           else f"wrong(got {', '.join(sorted(values))})")
        elif key in emitted_keys:
            result[key] = "unknown"          # emitted only as a placeholder
        else:
            result[key] = "missing"
    return result


def grade_contradictions(observed: dict, got: dict[str, set[str]]) -> dict:
    """Ground truth for fields the labels do NOT require the projection to commit to.

    Graded only where the projection volunteered a concrete value for the key —
    never `missing`, never `unknown`. `fields` asks "did you commit to the
    distinguishing values?"; this asks the separate question "is anything else you
    made up contradicted by the telemetry?". Without it a projection scores a clean
    `0 wrong` while emitting concrete values the hidden payloads refute (case-002
    emits `evt.type: write` where the capture says `openat`), and inventing a
    concrete value is exactly what prompt.md forbids and what manufactures a catch
    downstream.
    """
    result = {}
    for k, want in observed.items():
        key = str(k)
        values = got.get(key)
        if not values:      # absent, or emitted only as a `<placeholder>` — not a claim
            continue
        result[key] = ("correct" if _norm(want) in values
                       else f"wrong(got {', '.join(sorted(values))})")
    return result


def emitted_values(events: list) -> list[str]:
    """Every value a projection emits — mapping values and marker strings.

    Keys are excluded on purpose: they are schema field names (`user.name`),
    never the mutated entities a mutation case forbids, so scanning them only
    invents false leaks.
    """
    out: list[str] = []
    for e in events:
        if isinstance(e, dict):
            out.extend(_norm(v) for v in e.values())
        elif isinstance(e, str):
            out.append(e)
    return out


def _tokens(value: str) -> set[str]:
    """Whitespace-delimited, punctuation-trimmed tokens of an emitted value.

    A whole `<placeholder>` survives intact — it names a value the story did not
    state, and reducing it to a bare word would let it collide with a real one.
    """
    out = set()
    for token in value.split():
        out.add(token if token.startswith("<") and token.endswith(">")
                else token.strip(_TOKEN_TRIM))
    return out


def leaks(forbidden: list, preds: dict[str, list]) -> list[str]:
    """Forbidden original values a mutation case's projection actually emitted.

    Matches a forbidden value against a whole emitted value or one of its
    whitespace-delimited, punctuation-trimmed tokens — never as a bare
    substring. Substring matching cannot tell `user.name: root` (a real leak)
    from `file.path: /root/.ssh/authorized_keys` (an unrelated path that merely
    contains the token), and case-002 in this very suite emits the latter.
    Free-text fields still leak correctly: "Failed password for root from
    172.18.0.15" tokenizes to both forbidden values.
    """
    seen: set[str] = set()
    for events in preds.values():
        for value in emitted_values(events):
            seen.add(value)
            seen |= _tokens(value)
    seen.discard("")
    return [f for f in forbidden if _norm(f) in seen]


def _ratio(numerator: int, denominator: int) -> float | None:
    """`None` — not 0.0 — when the class is unexercised, so slices aggregate honestly."""
    return round(numerator / denominator, 3) if denominator else None


def _fmt(ratio: float | None) -> str:
    return "n/a" if ratio is None else f"{ratio:.2f}"


def load_predictions(proj: dict) -> tuple[dict[str, list], list[str]]:
    """Projection rows as {lead_id: events}, plus any lead_id repeated in the doc."""
    preds: dict[str, list] = {}
    duplicates: list[str] = []
    for row in proj.get("projections") or []:
        lead_id = row["lead_id"]
        if lead_id in preds:
            duplicates.append(lead_id)
        preds[lead_id] = row["events"]
    return preds, duplicates


def score_projection(spec: dict, proj: dict, projection_name: str) -> dict:
    """The whole measurement, as the dict written to `scores/<tag>.json`."""
    expected = spec["leads"]
    forbidden = spec.get("must_not_emit", [])  # mutation cases: originals that must not leak
    preds, duplicate_leads = load_predictions(proj)

    missing_leads = [lead_id for lead_id in expected if lead_id not in preds]
    unscored_leads = [lead_id for lead_id in preds if lead_id not in expected]

    rows = []
    by_system: dict[str, dict[str, int]] = {}
    for lead_id, exp in expected.items():
        # A lead the projection never produced is scored `missing`, never as the
        # empty `0` it would otherwise impersonate — see the module docstring.
        events = preds.get(lead_id, [])
        pred_c = project_class(events) if lead_id in preds else NOT_PROJECTED
        exp_c = exp["class"]
        system = exp["system"]
        match = pred_c == exp_c
        concrete = concrete_values(events)
        fields = (grade_fields(exp.get("fields", {}), concrete, events)
                  if exp_c == "+event" else {})
        # Contradictions are graded on EVERY class: a fabricated concrete value on a
        # lead labelled `0` is the same error as one on a `+event` lead, and the
        # class disagreement alone does not say the value was refuted.
        contradictions = grade_contradictions(exp.get("observed_fields", {}), concrete)
        rows.append({
            "lead": lead_id, "system": system, "expected": exp_c, "predicted": pred_c,
            "class_match": match, "heterogeneous": exp.get("heterogeneous", False),
            "fields": fields, "contradictions": contradictions,
            "intent_note": bool(exp.get("intent_note")),
        })
        st = by_system.setdefault(system, {"n": 0, "match": 0})
        st["n"] += 1
        st["match"] += match

    # aggregate metrics
    n = len(rows)
    class_agree = sum(r["class_match"] for r in rows)
    ev_expected = [r for r in rows if r["expected"] == "+event"]
    zero_expected = [r for r in rows if r["expected"] == "0"]
    recall = _ratio(sum(r["predicted"] == "+event" for r in ev_expected), len(ev_expected))
    precision_zero = _ratio(sum(r["predicted"] == "0" for r in zero_expected), len(zero_expected))
    all_field_grades = [g for r in rows for g in r["fields"].values()]
    all_contradiction_grades = [g for r in rows for g in r["contradictions"].values()]
    # `wrong` gates a slice to `no-update`, so it spans both grading paths: a refuted
    # value is no less wrong for being one the labels did not ask for.
    wrong = [g for g in all_field_grades + all_contradiction_grades if g.startswith("wrong")]
    false_suppress = [r for r in rows if r["predicted"] == "-noise" and r["expected"] != "-noise"]
    malformed = [r for r in rows if r["predicted"] == MALFORMED]

    return {
        "projection": projection_name,
        "n_leads": n,
        "class_agreement": f"{class_agree}/{n}",
        "by_system": {s: f"{v['match']}/{v['n']}" for s, v in sorted(by_system.items())},
        "plus_event_recall": recall,
        "zero_precision": precision_zero,
        "field_grades": {g: all_field_grades.count(g) for g in sorted(set(all_field_grades))},
        "contradiction_grades": {g: all_contradiction_grades.count(g)
                                 for g in sorted(set(all_contradiction_grades))},
        "wrong_concrete_fields": len(wrong),
        "false_suppression": len(false_suppress),
        "malformed_projections": len(malformed),
        "forbidden_emitted": leaks(forbidden, preds),  # mutation: leaked originals (should be [])
        "missing_leads": missing_leads,      # labelled but absent from the projection
        "unscored_leads": unscored_leads,    # projected but not labelled
        "duplicate_leads": duplicate_leads,  # lead_id repeated in the projection doc
        "rows": rows,
    }


def print_report(summary: dict, case_name: str, forbidden: list) -> None:
    print(f"== score: {summary['projection']} vs {case_name} ==")
    print(f"class agreement: {summary['class_agreement']}   "
          f"+event recall: {_fmt(summary['plus_event_recall'])}   "
          f"0 precision: {_fmt(summary['zero_precision'])}")
    print(f"by system: {summary['by_system']}")
    print(f"field grounding: {summary['field_grades']}   "
          f"volunteered-value check: {summary['contradiction_grades']}   "
          f"WRONG concrete: {summary['wrong_concrete_fields']}   "
          f"false-suppression: {summary['false_suppression']}   "
          f"malformed: {summary['malformed_projections']}")
    if forbidden:
        hits = summary["forbidden_emitted"]
        print(f"mutation — forbidden original values: {'CLEAN' if not hits else f'LEAKED {hits}'}")
    for label, key in (("MISSING from projection", "missing_leads"),
                       ("projected but UNLABELLED", "unscored_leads"),
                       ("DUPLICATED in projection", "duplicate_leads")):
        if summary[key]:
            print(f"!! lead-set integrity — {label}: {summary[key]}")
    print()
    for r in summary["rows"]:
        tag = "ok " if r["class_match"] else "DIS"
        het = " het" if r["heterogeneous"] else ""
        fld = ("  fields=" + json.dumps(r["fields"])) if r["fields"] else ""
        con = ("  volunteered=" + json.dumps(r["contradictions"])) if r["contradictions"] else ""
        note = "  [intent-scoped divergence]" if (not r["class_match"] and r["intent_note"]) else ""
        print(f"  {tag} {r['lead']:<6} {r['system']:<12} exp={r['expected']:<7} "
              f"pred={r['predicted']:<9}{het}{fld}{con}{note}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("case_dir", type=Path, help="golden case directory (holds expected.yaml)")
    p.add_argument("projection", type=Path, help="projections/<tag>.yaml to score")
    p.add_argument("--json", type=Path, default=None, dest="json_out",
                   help="also write the full summary here")
    ns = p.parse_args(argv)

    spec = yaml.safe_load((ns.case_dir / "expected.yaml").read_text(encoding="utf-8"))
    proj = yaml.safe_load(ns.projection.read_text(encoding="utf-8"))
    summary = score_projection(spec, proj, ns.projection.name)

    print_report(summary, ns.case_dir.name, spec.get("must_not_emit", []))

    if ns.json_out:
        ns.json_out.parent.mkdir(parents=True, exist_ok=True)
        ns.json_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {ns.json_out}")

    # Non-zero on a lead-set mismatch: a partial or mislabelled projection is not
    # a result, and a caller scripting the suite must not read it as one.
    return 1 if (summary["missing_leads"] or summary["unscored_leads"]
                 or summary["duplicate_leads"]) else 0


if __name__ == "__main__":
    sys.exit(main())
