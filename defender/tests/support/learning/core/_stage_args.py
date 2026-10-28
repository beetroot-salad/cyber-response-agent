"""Fold a suite's flat per-spawn kwargs into `run_curator_stage`'s grouped `wiring`/`ctx` shape.

The curator suites override one knob at a time; the grouping is a detail of the call, assembled
here once. Deliberately NOT a `**kwargs` passthrough: every moved field is named, so a field
that stops existing fails loudly here.
"""
from __future__ import annotations

from defender.learning.core.config import StageContext, StageWiring

def as_curator_stage_args(kw: dict) -> dict:
    """`kw` is consumed. Returns the kwargs `run_curator_stage` takes."""
    wiring = StageWiring.for_batch(
        kw.pop("system_prompt_file"), kw.pop("model"), kw.pop("effort"),
        batch_id=kw.pop("batch_id"), label="curator",
    )
    ctx = StageContext(
        learning_run_dir=kw.pop("learning_run_dir"),
        user=kw.pop("user_prompt"),
        request_limit=kw.pop("request_limit"),
        wall_clock_timeout=kw.pop("timeout"),
        repo_root=kw.pop("repo_root"),
        box=kw.pop("box", None),
        salt=kw.pop("salt", None),
    )
    return dict(
        wiring=wiring, ctx=ctx,
        corpus_dir=kw.pop("corpus_dir"), **kw,
    )
