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
reads only `oracle_visible/`. `score.py` reads neither — it scores against
`expected.yaml`, the labels a human authors *from* `hidden/`.

Redaction reuses the production seam (`oracle.sample.lead_sample_text`) so the
stored oracle-visible sample is byte-identical to what the live oracle receives.

The case id is the output directory's name — one anchor, rather than an id
argument that can drift from the path it is written to.

Usage:
  build_case.py <run_dir> <story.md> <controls.yaml> <out_dir>

controls.yaml (hand-authored from the capture session) is copied verbatim into
hidden/ and is the record of the shape-matched control-window measurements.

NOTE: no scrubbing happens here. Everything under `hidden/observed/` is committed
verbatim, which is correct for the synthetic `playground-v2` stack and ONLY for
it — never point this at a run over real telemetry.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender.learning import lead_repository  # noqa: E402
from defender.learning.pipeline.oracle.sample import lead_sample_text  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("run_dir", type=Path, help="defender run dir to capture leads/queries from")
    p.add_argument("story", type=Path, help="hand-authored ground-truth story.md")
    p.add_argument("controls", type=Path, help="hand-authored control-window controls.yaml")
    p.add_argument("out_dir", type=Path, help="cases/<case-id> — its name IS the case id")
    ns = p.parse_args(argv)

    out = ns.out_dir
    case_id = out.name
    vis = out / "oracle_visible"
    hidden = out / "hidden"

    # Re-capturing overwrites in place, so clear the two trees this script OWNS
    # first — otherwise a lead dropped since the last capture keeps a stale
    # sample and stale observed payloads, and the case silently describes a run
    # that no longer exists. Hand-authored siblings (expected.yaml, manifest.yaml,
    # projections/, scores/) are never touched.
    for owned in (vis / "samples", hidden / "observed"):
        if owned.exists():
            shutil.rmtree(owned)
    (vis / "samples").mkdir(parents=True, exist_ok=True)
    (hidden / "observed").mkdir(parents=True, exist_ok=True)

    # Story — oracle-visible.
    shutil.copyfile(ns.story, vis / "story.md")
    # Controls — hidden ground-truth baseline.
    shutil.copyfile(ns.controls, hidden / "controls.yaml")

    leads = lead_repository.joined(ns.run_dir)
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
    print("  hidden: observed payloads + controls.yaml")
    print(f"  next: author {out / 'expected.yaml'} and {out / 'manifest.yaml'} from hidden/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
