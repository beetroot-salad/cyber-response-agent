#!/usr/bin/env python3
"""Invoke the production oracle over a real defender run's leads, with the
ground-truth story substituted for the invented actor story.

This is the exact production call site (defender/learning/core/subagents.py:48-50):
    invoke_oracle(run_dir, actor_story_path, learning_run_dir,
                  oracle_fn=_run_oracle_pydantic)

Nothing about the oracle is patched: same ORACLE_PROMPT / ORACLE_MODEL /
ORACLE_EFFORT, same per-lead user-prompt assembly (build_lead_user_prompt →
sanitize_wtc + scrubbed sample skeleton), same YAML output contract. The only
non-production input is `actor_story_path`, which points at the true story.

Usage: run_oracle.py <run_dir> <story.md> <out_projection.yaml> <learning_run_dir>
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, "/workspace")

from defender.learning.pipeline.oracle.run import invoke_oracle
from defender.learning.pipeline.oracle_engine import _run_oracle_pydantic


def main() -> None:
    run_dir = Path(sys.argv[1])
    story_path = Path(sys.argv[2])
    out_path = Path(sys.argv[3])
    learning_run_dir = Path(sys.argv[4])
    learning_run_dir.mkdir(parents=True, exist_ok=True)

    doc = invoke_oracle(run_dir, story_path, learning_run_dir,
                        oracle_fn=_run_oracle_pydantic)
    out_path.write_text(doc, encoding="utf-8")
    print(f"wrote {out_path} ({len(doc)} bytes)")


if __name__ == "__main__":
    main()
