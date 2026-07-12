"""Telemetry oracle stage — synthesizes the per-lead events the actor's story implies.

One in-process PydanticAI call per lead (``pipeline/oracle_engine._run_oracle_pydantic``, GLM
5.2 with reasoning disabled), fanned out concurrently and reassembled into the
``{projections: [{lead_id, events}]}`` doc the validator + judge consume. The transport rides a
REQUIRED ``oracle_fn`` DI seam — the composition root (``InProcessSubagents.oracle``) is the
single place that names the production engine, mirroring the judge's ``judge_fn``; the
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
from defender.learning.core.validate import dump_oracle_doc
from defender.learning.pipeline.oracle.sample import (
    assemble_oracle_doc,
    build_lead_user_prompt,
    lead_sample_text,
    parse_lead_events,
)


def invoke_oracle_lead(lead, story: str, sample_text: str, learning_run_dir: Path,
                       *, trace_prefix: str, oracle_fn) -> list:
    """Project one lead. Sees only this lead — sanitized ``what_to_summarize`` +
    queries + a scrubbed sample event — plus the story; no goal, no alert, no other lead.
    Returns the lead's ``events`` list (mappings, a single baseline-diff marker, or empty).

    Runs in-process via ``oracle_fn`` (the shared ``run_stage`` transport) with a trace name keyed
    on BOTH ``trace_prefix`` (the per-direction discriminator — see ``invoke_oracle``) AND the lead
    id, so neither the concurrent per-lead fan-out NOR the two direction legs (which share one
    ``learning_run_dir`` and the same lead set) collide on a single ``RequestLogger`` file. ``lead``
    is a ``lead_repository.JoinedLead``.
    """
    user = build_lead_user_prompt(lead, story, sample_text)
    raw = oracle_fn(
        ORACLE_PROMPT, ORACLE_MODEL, ORACLE_EFFORT,
        f"oracle_{trace_prefix}_{lead.lead_id}.trace.jsonl", f"oracle:{lead.lead_id}",
        user, learning_run_dir,
    )
    return parse_lead_events(raw, lead.lead_id)


def invoke_oracle(run_dir: Path, actor_story_path: Path, learning_run_dir: Path,
                  *, oracle_fn) -> str:
    """Run the per-lead oracle over a run's leads and assemble the doc.

    One in-process PydanticAI call per lead, fanned out concurrently (bounded by
    ``ORACLE_MAX_CONCURRENCY``); results are reassembled in lead order into the
    ``{projections: [{lead_id, events}]}`` doc the validator + judge consume. Reads the leads from
    the joined two-table surface (``run_dir``); per-lead traces land under ``learning_run_dir``.
    Returns the serialized YAML string.

    ``oracle_fn`` is REQUIRED (the mirror of ``invoke_judge``'s ``judge_fn``): the composition root
    ``InProcessSubagents.oracle`` names the production engine (``_run_oracle_pydantic``) in one
    place, and every other caller — the secondary harness, tests — routes through that adapter or
    injects its own fn, so this module never imports the pydantic-ai graph.
    """
    story = actor_story_path.read_text(encoding="utf-8")
    # Per-direction trace discriminator. The adversarial + benign legs run concurrently and share
    # one ``learning_run_dir`` and the same lead set (both read ``run_dir``), so a lead-only trace
    # name would collide across legs (RequestLogger opens mode "w" → the legs truncate/interleave
    # each other's trace). ``actor_story_path`` is per-direction (``spec.story_name`` —
    # actor_story.md vs actor_benign_story.md), so its stem disambiguates, mirroring the per-
    # direction trace names the actor/judge already use (actor_trace vs actor_benign_trace, …).
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
