from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from uuid import uuid4

from defender.learning import lead_repository
from defender.learning.core.config import (
    ORACLE_EFFORT,
    ORACLE_MAX_CONCURRENCY,
    ORACLE_MODEL,
    ORACLE_PROMPT,
)
from defender.learning.core.validate import dump_oracle_doc
from defender.learning.pipeline.oracle.sample import (
    assemble_oracle_doc,
    build_lead_user_prompt,
    lead_sample_text,
    parse_lead_events,
)


def invoke_oracle_lead(lead, story: str, sample_text: str, learning_run_dir: Path,
                       *, trace_prefix: str, oracle_fn, salt: str | None = None) -> list:
    stage_salt = salt if salt is not None else uuid4().hex
    user = build_lead_user_prompt(lead, story, sample_text, salt=stage_salt)
    raw = oracle_fn(
        ORACLE_PROMPT, ORACLE_MODEL, ORACLE_EFFORT,
        f"oracle_{trace_prefix}_{lead.lead_id}.trace.jsonl", f"oracle:{lead.lead_id}",
        user, learning_run_dir,
        salt=stage_salt,
    )
    return parse_lead_events(raw, lead.lead_id)


def invoke_oracle(run_dir: Path, actor_story_path: Path, learning_run_dir: Path,
                  *, oracle_fn) -> str:
    story = actor_story_path.read_text(encoding="utf-8")
    trace_prefix = actor_story_path.stem
    leads = lead_repository.joined(run_dir)
    samples = [lead_sample_text(jl) for jl in leads]
    max_workers = max(1, min(ORACLE_MAX_CONCURRENCY, len(leads) or 1))
    events_per_lead: list = [None] * len(leads)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_to_idx = {
            pool.submit(invoke_oracle_lead, jl, story, s, learning_run_dir,
                        trace_prefix=trace_prefix, oracle_fn=oracle_fn): i
            for i, (jl, s) in enumerate(zip(leads, samples, strict=True))
        }
        try:
            for fut in as_completed(fut_to_idx):
                events_per_lead[fut_to_idx[fut]] = fut.result()
        except Exception:
            for f in fut_to_idx:
                f.cancel()
            raise
    projections = [
        (jl.lead_id, events) for jl, events in zip(leads, events_per_lead, strict=True)
    ]
    return dump_oracle_doc(assemble_oracle_doc(projections))
