"""Telemetry oracle stage — synthesizes the per-lead events the actor's story implies.

One ``claude -p`` per lead, fanned out concurrently, reassembled into the
``{projections: [{lead_id, events}]}`` doc the validator + judge consume. The
prompt-assembly / sampling / parsing helpers live in ``sample.py``.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from defender.learning import lead_repository
from defender.learning.core.config import (
    ORACLE_EFFORT,
    ORACLE_MAX_CONCURRENCY,
    ORACLE_MODEL,
    ORACLE_PROMPT,
)
from defender.learning.core.runner import _run_claude
from defender.learning.core.validate import dump_oracle_doc
from defender.learning.pipeline.oracle.sample import (
    assemble_oracle_doc,
    build_lead_user_prompt,
    lead_sample_text,
    parse_lead_events,
)


def invoke_oracle_lead(lead, story: str, sample_text: str) -> list:
    """Project one lead. Sees only this lead — sanitized ``what_to_summarize`` +
    queries + a scrubbed sample event — plus the story; no goal, no alert, no other lead.
    Returns the lead's ``events`` list (mappings, a single baseline-diff marker, or empty).

    ``lead`` is a ``lead_repository.JoinedLead``.
    """
    user = build_lead_user_prompt(lead, story, sample_text)
    raw = _run_claude(ORACLE_PROMPT, user, model=ORACLE_MODEL, effort=ORACLE_EFFORT)
    return parse_lead_events(raw, lead.lead_id)


def invoke_oracle(run_dir: Path, actor_story_path: Path) -> str:
    """Run the per-lead oracle over a run's leads and assemble the doc.

    One ``claude -p`` per lead, fanned out concurrently (bounded by
    ``ORACLE_MAX_CONCURRENCY``); results are reassembled in lead order into the
    ``{projections: [{lead_id, events}]}`` doc the validator + judge consume. Reads the
    leads from the joined two-table surface. Returns the serialized YAML string.
    """
    story = actor_story_path.read_text()
    leads = lead_repository.joined(run_dir)
    samples = [lead_sample_text(jl) for jl in leads]
    max_workers = max(1, min(ORACLE_MAX_CONCURRENCY, len(leads) or 1))
    events_per_lead: list = [None] * len(leads)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_to_idx = {
            pool.submit(invoke_oracle_lead, jl, story, s): i
            for i, (jl, s) in enumerate(zip(leads, samples, strict=True))
        }
        try:
            # Surface the first failing lead as soon as it completes (rather than after
            # every sibling finishes) and cancel any leads still queued behind the cap.
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
