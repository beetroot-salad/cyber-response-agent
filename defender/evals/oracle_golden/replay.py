#!/usr/bin/env python3
"""Replay the production oracle over a golden case, reading ONLY oracle_visible/.

This is the calibration equivalent of the production projection: it drives the
exact production seam (`invoke_oracle_lead` → `_run_oracle_pydantic`, the same
`build_lead_user_prompt`) so the projection is production-identical — but it
sources its inputs from the case's `oracle_visible/` tree, never touching
`hidden/`. That file-level boundary is the guarantee that a projection cannot
peek at the ground truth it is scored against.

Emits `projections/<model>_<effort>.yaml` in the same shape as the production
oracle doc (`{projections: [{lead_id, events}]}`).

Usage: replay.py <case_dir> [--tag <label>]
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, "/workspace")

from defender.learning.core.config import ORACLE_EFFORT, ORACLE_MODEL
from defender.learning.core.validate import dump_oracle_doc
from defender.learning.pipeline.oracle.run import invoke_oracle_lead
from defender.learning.pipeline.oracle.sample import assemble_oracle_doc
from defender.learning.pipeline.oracle_engine import _run_oracle_pydantic


@dataclass(frozen=True)
class _Query:
    query_id: str
    params: dict


@dataclass(frozen=True)
class _Lead:
    """Minimal lead satisfying build_lead_user_prompt's reads."""
    lead_id: str
    goal: str | None
    what_to_summarize: list
    queries: list


def load_visible_leads(case_dir: Path) -> list[_Lead]:
    rows = [json.loads(l) for l in (case_dir / "oracle_visible" / "leads.jsonl").read_text().splitlines() if l.strip()]
    return [
        _Lead(r["lead_id"], r.get("goal"), r.get("what_to_summarize") or [],
              [_Query(q["query_id"], q.get("params") or {}) for q in r.get("queries", [])])
        for r in rows
    ]


def main() -> None:
    case_dir = Path(sys.argv[1]).resolve()   # bind() requires an absolute trace root
    tag = None
    if "--tag" in sys.argv:
        tag = sys.argv[sys.argv.index("--tag") + 1]
    tag = tag or f"{ORACLE_MODEL}_effort-{ORACLE_EFFORT}"

    story = (case_dir / "oracle_visible" / "story.md").read_text(encoding="utf-8")
    leads = load_visible_leads(case_dir)
    learning_dir = case_dir / "projections" / f"_trace_{tag}"
    learning_dir.mkdir(parents=True, exist_ok=True)

    projections = []
    for lead in leads:
        sample = (case_dir / "oracle_visible" / "samples" / f"{lead.lead_id}.txt").read_text(encoding="utf-8")
        events = invoke_oracle_lead(
            lead, story, sample, learning_dir,
            trace_prefix=tag, oracle_fn=_run_oracle_pydantic, salt=uuid4().hex)
        projections.append((lead.lead_id, events))
        print(f"  {lead.lead_id}: {len(events)} event(s)")

    out = case_dir / "projections" / f"{tag}.yaml"
    out.write_text(dump_oracle_doc(assemble_oracle_doc(projections)), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
