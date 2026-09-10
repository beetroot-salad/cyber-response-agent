"""The episode's stage timing record — wall time per step, written at the source (#1025 O7).

One file at the episode root, `timing.jsonl`, one row per step the launcher COMPLETED:
`{step, started_at, ended_at}`. The launcher (`branch/cli.py::_run_episode`) is the only frame
that sees every step boundary, so it is the one writer, and it writes AFTER each step — never
before — so an aborted episode leaves exactly the steps that ran and nothing that claims a step
which never finished.

Why a record and not a derivation: every other clock on the archive is an INNER one (a run's
`tool_trace.jsonl` result event, a trace row's `duration_ms`) or a file's mtime, and a page that
reconstructs "how long did this episode take" from either is O4's named failing. The outer
clock is the launcher's, and it is written down here once.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from defender._io import read_jsonl_rows, write_guarded

#: The record's name at the episode root — sibling of `review.yaml` and `staged.yaml`.
TIMING_NAME = "timing.jsonl"

#: The launcher's steps, in launch order. A row's `step` is one of these and nothing else:
#: they are what every reader of the record keys on, so a misspelt step is an unreadable row.
STEPS: tuple[str, ...] = ("questioner", "staging", "review", "runs", "verify", "judge")


def timing_path(episode_dir: Path) -> Path:
    """Where the record lives under `episode_dir`."""
    return Path(episode_dir) / TIMING_NAME


def record_step(episode_dir: Path, step: str, *, started_at: str, ended_at: str) -> dict[str, Any]:
    """Append one completed step to the record and return the row written.

    @owns the timing row: `{step, started_at, ended_at}`, timestamps as `_clock.now_iso` spells
    them. Through `write_guarded(mode="append")`, so an alias planted at the record's name is
    refused rather than written through — the episode dir is a tree a sibling's box can write
    into. A `step` outside `STEPS` is refused BEFORE anything is opened.
    """
    if step not in STEPS:
        raise ValueError(f"unknown episode step {step!r}; the record's steps are {STEPS}")
    row = {"step": step, "started_at": started_at, "ended_at": ended_at}
    write_guarded(timing_path(episode_dir), json.dumps(row) + "\n", mode="append")
    return row


def read_stage_timings(episode_dir: Path) -> list[dict[str, Any]]:
    """The recorded steps, in file order; `[]` for an episode that recorded none.

    Tolerant on purpose: the writer can be killed mid-append, and a reader that raised on the
    torn line would lose every step that did complete. The canonical JSONL reader skips it.
    """
    return read_jsonl_rows(timing_path(episode_dir))
