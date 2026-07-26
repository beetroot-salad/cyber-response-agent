#!/usr/bin/env python3
"""Write a generated case's `expected.yaml` from its measured telemetry (#711 M9).

The last step of the generator. `label.py` decides the classes; this renders them
into the file `score.py` reads, together with the two field sets the grounding
metrics need:

  fields            the distinguishing values — present in the attack window and
                    absent from every control. These are what an accurate
                    projection must commit to.
  observed_fields   every other concrete value the capture carries. Graded only
                    where the projection VOLUNTEERS a concrete value, which is
                    what catches a fabricated value inside a correctly-classified
                    lead (mut-001's invented `alerts: 1`).

Refuses to overwrite an existing `expected.yaml`. A case's labels are its ground
truth; silently regenerating them after a projection has been scored is exactly
the move the procedure doc forbids — a label may be corrected from the
environment, never from the projection, and "re-run the generator" is only the
former if it is a deliberate act. Pass `--force` to mean it.

Anything the labeler could not decide is written as `needs-label`, which
`score.py` will not match against any real class. That is deliberate: an
undecided lead should fail loudly in the score rather than quietly count as `0`.

Usage: write_expected.py <case_dir> [--force]
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
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


LABEL = _load("oracle_golden_label", GOLDEN_DIR / "label.py")

#: Columns that describe the measurement rather than the activity. Committing a
#: projection to these would be asking it to reproduce our aggregation, not the
#: telemetry — and they are never stable across a control window anyway.
_NOT_GROUND_TRUTH = frozenset({
    "@timestamp", "first_seen", "last_seen", "first_in_minute", "last_in_minute",
    "minute", "event.ingested", "event.created",
})


def _scalar(value: object) -> bool:
    return isinstance(value, (str, int, float, bool)) and str(value).strip() != ""


def _attack_payload(case_dir: Path, lead_id: str, seq: int, record: dict) -> dict | None:
    """The rows the activity contributed: the window-restricted re-measurement
    where one exists, else the stored payload. `None` when neither is a row set."""
    contribution = (record.get("attack_contribution") or {}).get("payload")
    if isinstance(contribution, dict) and LABEL._is_rowset(contribution):
        return contribution
    path = case_dir / "hidden" / "observed" / lead_id / f"{seq}.json"
    if not path.is_file() or path.stat().st_size == 0:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return payload if LABEL._is_rowset(payload) else None


def _baseline_keys(record: dict, query: str, query_id: str) -> set[tuple]:
    """Row keys every live control window carries."""
    baseline: set[tuple] = set()
    for control in record.get("controls") or []:
        if control.get("live") is False:
            continue
        payload = control.get("payload")
        if isinstance(payload, dict) and LABEL._is_rowset(payload):
            rows = LABEL.distinguishing_rows(
                payload, control.get("query", query), query_id)
            if rows:
                baseline |= rows
    return baseline


def _field_sets(case_dir: Path, lead_id: str, queries: list[dict]) -> tuple[dict, dict]:
    """(fields, observed_fields) for a lead, from its attack rows vs its controls."""
    fields: dict[str, object] = {}
    observed: dict[str, object] = {}
    for seq, q in enumerate(queries):
        query = (q.get("params") or {}).get("query") or ""
        query_id = q.get("query_id", "")
        record = LABEL.load_control_record(case_dir, lead_id, seq)
        payload = _attack_payload(case_dir, lead_id, seq, record)
        if payload is None:
            continue
        keys = LABEL.row_key_columns(payload, query, query_id)
        baseline = _baseline_keys(record, query, query_id)

        for row in payload.get("values") or []:
            if LABEL._is_empty_summary_row(row):
                continue
            key = (tuple(json.dumps(row.get(k), sort_keys=True, default=str) for k in keys)
                   if keys else None)
            distinguishing = key is not None and key not in baseline
            for column, value in row.items():
                if column in _NOT_GROUND_TRUTH or not _scalar(value):
                    continue
                if distinguishing and keys and column in keys:
                    fields.setdefault(column, value)
                else:
                    observed.setdefault(column, value)
    # A value cannot be both required and merely observed.
    for column in fields:
        observed.pop(column, None)
    return fields, observed


def build_expected(case_dir: Path) -> dict:
    manifest = yaml.safe_load((case_dir / "manifest.yaml").read_text(encoding="utf-8")) or {}
    leads: dict[str, dict] = {}
    text = (case_dir / "oracle_visible" / "leads.jsonl").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.strip():
            row = json.loads(line)
            leads[row["lead_id"]] = row

    out_leads: dict[str, dict] = {}
    classes: set[str] = set()
    for lead_id, lead in leads.items():
        queries = lead.get("queries", [])
        system = (queries[0].get("query_id", "").split(".")[0] if queries else "unknown")
        derived = LABEL.label_lead(case_dir, lead_id, queries, system, manifest)
        entry: dict = {"system": system, "class": derived["class"]}
        templates = sorted({q.get("query_id", "").split(".", 1)[-1] for q in queries})
        if templates:
            entry["template"] = templates[0] if len(templates) == 1 else templates
        if derived["heterogeneous"] is not None:
            entry["heterogeneous"] = derived["heterogeneous"]
        if derived["class"] == LABEL.PLUS_EVENT:
            fields, observed = _field_sets(case_dir, lead_id, queries)
            if fields:
                entry["fields"] = fields
            if observed:
                entry["observed_fields"] = observed
        out_leads[lead_id] = entry
        classes.add(derived["class"])

    return {
        "case_id": case_dir.name,
        "kind": manifest.get("kind", "observed"),
        "result_classes_covered": sorted(classes),
        "leads": out_leads,
    }


HEADER = """\
# Ground-truth labels for {case_id}, DERIVED MECHANICALLY by write_expected.py
# from hidden/observed/ and hidden/controls/ (#711 M9). The projection is not one
# of the inputs, which is the mechanical form of the rule "a label may be
# corrected from the environment, never from the projection".
#
# Review before trusting, in this order:
#   1. any lead labelled `needs-label` — the labeler declined to decide, and
#      score.py will not match it against any real class. Declare the system in
#      manifest.yaml `state_classes`, or measure a control it can use.
#   2. `fields` — the values a correct projection must commit to. Derived as the
#      row-key values present in the attack window and absent from every live
#      control. Drop any that are an artifact of the query rather than the
#      activity.
#   3. `observed_fields` — everything else concrete the capture carries, graded
#      only where the projection volunteers a value for the key.
#
# `intent_note` is never derived: it is a human's reading of what the lead was
# FOR, and it explains a divergence without excusing it.
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("case_dir", type=Path)
    p.add_argument("--force", action="store_true",
                   help="overwrite an existing expected.yaml (a deliberate act)")
    ns = p.parse_args(argv)

    out = ns.case_dir / "expected.yaml"
    if out.exists() and not ns.force:
        print(f"!! {out} exists — refusing to regenerate ground truth silently. "
              f"Pass --force if that is what you mean.", file=sys.stderr)
        return 1

    expected = build_expected(ns.case_dir)
    body = yaml.safe_dump(expected, sort_keys=False, allow_unicode=True, width=100)
    out.write_text(HEADER.format(case_id=ns.case_dir.name) + body, encoding="utf-8")

    counts: dict[str, int] = {}
    for entry in expected["leads"].values():
        counts[entry["class"]] = counts.get(entry["class"], 0) + 1
    print(f"wrote {out}")
    print(f"  {len(expected['leads'])} leads: {counts}")
    if counts.get(LABEL.NEEDS_LABEL):
        print(f"  !! {counts[LABEL.NEEDS_LABEL]} lead(s) need a human decision "
              f"before this case can be scored")
    return 0


if __name__ == "__main__":
    sys.exit(main())
