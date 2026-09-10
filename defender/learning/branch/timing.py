"""The episode's stage timing record — wall time per step, written at the source (#1025 O7).

One file at the episode root, `timing.jsonl`, one row per step the launcher COMPLETED:
`{step, started_at, ended_at}`. The launcher (`branch/cli.py`) is the only frame that sees
every step boundary, so it is the one writer, and it writes AFTER each step — never before —
so an aborted episode leaves exactly the steps that ran and nothing that claims a step which
never finished. The append is best-effort at the launcher's frame (`cli._timed`): a row the
record could not take is printed and absent, never a failure of the step it clocks.

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
from defender._run_paths import artifact_file
from defender.learning.branch.steps import STEPS

#: The record's name at the episode root — sibling of `review.yaml` and `staged.yaml`.
TIMING_NAME = "timing.jsonl"


def timing_path(episode_dir: Path) -> Path:
    """Where the record lives under `episode_dir`."""
    return Path(episode_dir) / TIMING_NAME


def record_step(episode_dir: Path, step: str, *, started_at: str, ended_at: str) -> dict[str, Any]:
    """Append one completed step to the record and return the row written.

    @owns started_at
    @owns ended_at
    The timing row is `{step, started_at, ended_at}`, timestamps as `_clock.now_iso` spells
    them; `step` is `steps.Step`'s. Through `write_guarded(mode="append")`, so an alias
    planted at the record's name is refused rather than written through — the episode dir is
    a tree a sibling's box can write into. A `step` outside `steps.STEPS` — the launcher's one
    declaration of its sequence — is refused BEFORE anything is opened: the step names are
    what every reader of the record keys on, so a misspelt step is an unreadable row.

    A TORN TAIL IS CLOSED BEFORE THE ROW IS APPENDED (the F-11 rule `judge/enqueue.py`'s
    appender applies to its queue): a writer that died — or, at the launcher's best-effort
    frame, one whose short write was held and printed — can leave half a row with no newline,
    and appended straight onto it this row and the fragment become ONE unreadable line, so the
    reader drops the completed step along with the torn one. A leading newline closes the
    fragment's own line without touching its bytes; it stays exactly as unreadable as it was.
    """
    if step not in STEPS:
        raise ValueError(
            f"unknown episode step {step!r}; the record's steps are {', '.join(STEPS)}")
    # `str(...)`: a `Step` member in, the bare name out — the row returned IS the row read back.
    row = {"step": str(step), "started_at": started_at, "ended_at": ended_at}
    path = timing_path(episode_dir)
    text = json.dumps(row) + "\n"
    if artifact_file(path) and path.stat().st_size > 0:
        with path.open("rb") as fh:
            fh.seek(-1, 2)
            if fh.read(1) != b"\n":
                text = "\n" + text
    write_guarded(path, text, mode="append")
    return row


def read_stage_timings(episode_dir: Path) -> list[dict[str, Any]]:
    """The recorded steps, in file order; `[]` for an episode that recorded none.

    Tolerant on purpose: the writer can be killed mid-append, and a reader that raised on the
    torn line would lose every step that did complete. The canonical JSONL reader skips it.

    `artifact_file` (lstat), not `is_file()` — the posture every other reader of the episode
    tree takes (`episode.py`, `staging.read_staged`, the judge's readers): the record sits in
    the tree the writer above refuses to alias-write into, and `is_file()` stats THROUGH a
    link, so a link planted at this name would hand back another file's rows as this
    episode's clock. An entry that is not a plain file reads as no record at all.
    """
    path = timing_path(episode_dir)
    if not artifact_file(path):
        return []
    return read_jsonl_rows(path)
