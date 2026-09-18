"""Fold a suite's flat per-spawn kwargs into the #713 grouped `run_curator_stage` shape.

The curator suites drive the real entry point and override one knob at a time
(`model=`, `learning_run_dir=`, `run_author=`, `queued_ids=`). The wiring/context
grouping is an implementation detail of the CALL, not of what those cases are testing,
so it is assembled here instead of being respelled at every case.

This is deliberately NOT a `**kwargs` passthrough: it names every field it moves, so a
field that stops existing fails loudly here rather than being silently absorbed.
"""
from __future__ import annotations

from defender.learning.core.config import StageContext, StageWiring

#: #773 M1: the forward-check config group is gone — the check moved out of the curator's
#: own spawn entirely. A caller still passing one of these fields gets it silently dropped
#: here rather than a `TypeError` from a stale kwarg, since the shape these suites drive
#: (`run_curator_stage`) genuinely no longer takes them.
_FORWARD_CHECK = ("check", "runs_dir", "pending", "queued_ids", "exempt_ids", "run_verify")


def as_curator_stage_args(kw: dict) -> dict:
    """`kw` is consumed. Returns the kwargs `run_curator_stage` now takes."""
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
    for k in _FORWARD_CHECK:
        kw.pop(k, None)
    return dict(
        wiring=wiring, ctx=ctx,
        corpus_dir=kw.pop("corpus_dir"), **kw,
    )
