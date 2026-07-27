"""Fold a suite's flat per-spawn kwargs into the #713 grouped `run_curator_stage` shape.

The curator suites drive the real entry point and override one knob at a time
(`model=`, `learning_run_dir=`, `run_author=`, `queued_ids=`). The wiring/context
grouping is an implementation detail of the CALL, not of what those cases are testing,
so it is assembled here instead of being respelled at every case.

This is deliberately NOT a `**kwargs` passthrough: it names every field it moves, so a
field that stops existing fails loudly here rather than being silently absorbed.
"""
from __future__ import annotations

from defender.learning.author.curator_engine import ForwardCheckConfig
from defender.learning.core.config import StageContext, StageWiring

_FORWARD_CHECK = ("check", "runs_dir", "pending", "queued_ids", "run_verify")


def as_curator_stage_args(kw: dict) -> dict:
    """`kw` is consumed. Returns the kwargs `run_curator_stage` now takes."""
    batch_id = kw.pop("batch_id")
    wiring = StageWiring.for_batch(
        kw.pop("system_prompt_file"), kw.pop("model"), kw.pop("effort"),
        batch_id=batch_id, label="curator",
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
    cfg = ForwardCheckConfig(**{k: kw.pop(k) for k in _FORWARD_CHECK if k in kw})
    return dict(
        wiring=wiring, ctx=ctx, batch_id=batch_id,
        corpus_dir=kw.pop("corpus_dir"), cfg=cfg, **kw,
    )
