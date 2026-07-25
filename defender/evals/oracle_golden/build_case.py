#!/usr/bin/env python3
"""Mechanize capture of one oracle-calibration golden case from a defender run.

A case binds four things (#693):
  - the ground-truth STORY (what actually happened — the oracle's story input),
  - the ORACLE-VISIBLE input per lead (what_to_summarize + queries + the redacted
    sample skeleton the production oracle would see),
  - the HIDDEN observed telemetry (full query payloads — held back as ground truth),
  - the CONTROL-window baseline (so `+event` vs `+noise` is decidable).

The hidden/visible split is enforced at the FILE level: `oracle_visible/` is
exactly what a projection may read; `hidden/` is the scoring target. `replay.py`
reads only `oracle_visible/`; `score.py` reads `hidden/`.

Redaction reuses the production seam (`oracle.sample.lead_sample_text`) so the
stored oracle-visible sample is byte-identical to what the live oracle receives.

Usage:
  build_case.py <case_id> <run_dir> <story.md> <controls.yaml> <out_dir>

controls.yaml (hand-authored from the capture session) is copied verbatim into
hidden/ and is the record of the shape-matched control-window measurements.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, "/workspace")

from defender.learning import lead_repository
from defender.learning.pipeline.oracle.sample import lead_sample_text


def main() -> None:
    case_id, run_dir_s, story_s, controls_s, out_s = sys.argv[1:6]
    run_dir, out = Path(run_dir_s), Path(out_s)
    vis = out / "oracle_visible"
    hidden = out / "hidden"
    (vis / "samples").mkdir(parents=True, exist_ok=True)
    (hidden / "observed").mkdir(parents=True, exist_ok=True)

    # Story — oracle-visible.
    shutil.copyfile(story_s, vis / "story.md")
    # Controls — hidden ground-truth baseline.
    shutil.copyfile(controls_s, hidden / "controls.yaml")

    leads = lead_repository.joined(run_dir)
    leads_rows = []
    for jl in leads:
        # ORACLE-VISIBLE: exactly the fields build_lead_user_prompt consumes.
        leads_rows.append({
            "lead_id": jl.lead_id,
            "goal": jl.goal,
            "what_to_summarize": jl.what_to_summarize,
            "queries": [{"query_id": q.query_id, "params": q.params or {}} for q in jl.queries],
        })
        # ORACLE-VISIBLE: the redacted sample skeleton, via the production seam.
        (vis / "samples" / f"{jl.lead_id}.txt").write_text(
            lead_sample_text(jl), encoding="utf-8")
        # HIDDEN: the full observed payloads for every query in this lead.
        od = hidden / "observed" / jl.lead_id
        od.mkdir(parents=True, exist_ok=True)
        for q in jl.queries:
            if q.raw_ref is not None and q.raw_ref.is_file():
                shutil.copyfile(q.raw_ref, od / q.raw_ref.name)

    (vis / "leads.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in leads_rows), encoding="utf-8")

    print(f"built case {case_id} at {out}")
    print(f"  leads: {len(leads_rows)}  "
          f"(oracle-visible: story + leads.jsonl + {len(leads_rows)} samples)")
    print(f"  hidden: observed payloads + controls.yaml")


if __name__ == "__main__":
    main()
