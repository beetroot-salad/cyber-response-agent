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

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender._io import read_text_utf8  # noqa: E402
from defender.learning.core.config import ORACLE_EFFORT, ORACLE_MODEL  # noqa: E402
from defender.learning.core.validate import dump_oracle_doc  # noqa: E402
from defender.learning.pipeline.oracle.run import invoke_oracle_lead  # noqa: E402
from defender.learning.pipeline.oracle.sample import assemble_oracle_doc  # noqa: E402
from defender.learning.pipeline.oracle_engine import _run_oracle_pydantic  # noqa: E402


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
    text = read_text_utf8(case_dir / "oracle_visible" / "leads.jsonl")
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [
        _Lead(r["lead_id"], r.get("goal"), r.get("what_to_summarize") or [],
              [_Query(q["query_id"], q.get("params") or {}) for q in r.get("queries", [])])
        for r in rows
    ]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("case_dir", type=Path, help="golden case directory")
    p.add_argument("--tag", default=f"{ORACLE_MODEL}_effort-{ORACLE_EFFORT}",
                   help="projection tag (default: <model>_effort-<effort>)")
    ns = p.parse_args(argv)

    case_dir = ns.case_dir.resolve()   # bind() requires an absolute trace root
    tag = ns.tag

    story = read_text_utf8(case_dir / "oracle_visible" / "story.md")
    leads = load_visible_leads(case_dir)
    learning_dir = case_dir / "projections" / f"_trace_{tag}"
    learning_dir.mkdir(parents=True, exist_ok=True)

    projections = []
    for lead in leads:
        sample = read_text_utf8(case_dir / "oracle_visible" / "samples" / f"{lead.lead_id}.txt")
        # `salt` is left to invoke_oracle_lead's own per-stage default — one anchor.
        events = invoke_oracle_lead(
            lead, story, sample, learning_dir,
            trace_prefix=tag, oracle_fn=_run_oracle_pydantic)
        projections.append((lead.lead_id, events))
        print(f"  {lead.lead_id}: {len(events)} event(s)")

    out = case_dir / "projections" / f"{tag}.yaml"
    out.write_text(dump_oracle_doc(assemble_oracle_doc(projections)), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
