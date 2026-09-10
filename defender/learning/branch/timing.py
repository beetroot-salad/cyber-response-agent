"""The episode's stage timing record — wall time per step, written at the source (#1025 O7).

One document at the episode root, `timing.json`: `{"steps": [{step, started_at, ended_at}, …]}`,
one entry per step the launcher COMPLETED, in the order they completed. The launcher
(`branch/cli.py`) is the only frame that sees every step boundary, so it holds the one
`StageClock` for the episode and draws each step's frame with it; the clock writes AFTER each
step — never before — so an aborted episode leaves exactly the steps that ran and nothing
that claims a step which never finished.

A WHOLE DOCUMENT, REPLACED, NOT A LOG APPENDED TO. The clock keeps the completed steps in
memory and rewrites the whole record through `write_guarded`'s replace lane (staged under an
unpredictable name, swapped into place) after every step. Appended, the record had the shape
that breeds guards: a line torn by a kill mid-write, a torn TAIL with no newline that fuses
with the next row, a reader that has to skip what it cannot parse and must not re-sort, a
writer that opens the existing file. A replaced document is either the previous whole or the
new whole — there is nothing to tolerate, so the reader tolerates nothing: a document that is
not the record's shape is a positive statement someone made, and it raises.

THE WRITE IS BEST-EFFORT AT THE FRAME, like every other observability writer in this repo
(`judge._write_wire_log`, `_deps._record_lesson_load` take the same posture for the same
reason). The record sits in the episode dir, so the guarded write can refuse (an alias planted
at its name) or fail (`ENOSPC`, a read-only root), and raised through the step's frame that
was the STEP's own failure: after `RUNS` it reached `_launch`'s abort arm — "no sibling started
and every staged name is torn down", false of every arm that had just run — and after `JUDGE`
it left `main` as a bare `OSError` traceback for a fully graded episode. A clock that costs the
archive is the wrong trade, so the fault is printed and the step is simply not on the record —
which the record's own rule already reads as "not seen to finish". A step name outside `Step`
is a programming error, not an I/O fault, and still raises.

Why a record and not a derivation: every other clock on the archive is an INNER one (a run's
`tool_trace.jsonl` result event, a trace row's `duration_ms`) or a file's mtime, and a page that
reconstructs "how long did this episode take" from either is O4's named failing. The outer
clock is the launcher's, and it is written down here once.
"""
from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from defender._clock import now_iso
from defender._io import read_guarded, write_guarded
from defender.learning.branch.steps import STEPS, Step

#: The record's name at the episode root — sibling of `provenance.json`, the family stamp.
TIMING_NAME = "timing.json"


def timing_path(episode_dir: Path) -> Path:
    """Where the record lives under `episode_dir`."""
    return Path(episode_dir) / TIMING_NAME


class StageClock:
    """The launcher's outer clock for ONE episode: every step it has seen finish, and the
    record those steps are written to.

    One per episode run, held by the launcher for the episode's whole life: the steps live
    here, in memory, and the file is their projection — never read back to be extended, so
    the writer has no reader in its path and nothing on disk can make it write a row it did
    not see finish.
    """

    def __init__(self, episode_dir: Path) -> None:
        self.path = timing_path(episode_dir)
        self._rows: list[dict[str, Any]] = []

    def record(self, step: str, *, started_at: str, ended_at: str) -> dict[str, Any]:
        """Add one completed step and rewrite the record; returns the entry written.

        @owns started_at
        @owns ended_at
        The entry is `{step, started_at, ended_at}`, timestamps as `_clock.now_iso` spells
        them; `step` is `steps.Step`'s. A `step` outside `steps.STEPS` — the launcher's one
        declaration of its sequence — is refused BEFORE anything is written: the step names
        are what every reader of the record keys on. Through `write_guarded(mode="replace")`,
        so an alias planted at the record's name is refused rather than written through — the
        episode dir is a tree a sibling's box can write into — and a reader sees the previous
        whole document or this one, never a part.
        """
        if step not in STEPS:
            raise ValueError(
                f"unknown episode step {step!r}; the record's steps are {', '.join(STEPS)}")
        # `str(...)`: a `Step` member in, the bare name out — the entry returned IS the entry
        # read back.
        row = {"step": str(step), "started_at": started_at, "ended_at": ended_at}
        write_guarded(self.path, _record_text(self._rows + [row]))
        self._rows.append(row)
        return row

    @contextlib.contextmanager
    def step(self, step: Step) -> Iterator[None]:
        """One step of the episode on the outer clock — its entry lands on the record AFTER
        the body returns, and only on a normal return (#1025 O7).

        A body that raised is not on the record, so an aborted episode's record reads as
        exactly the steps that ran, and a reader never meets an entry claiming a step whose
        end this frame never saw. The moments are the launcher's own clock at the step's real
        start and end — the one outer clock the archive has.

        A record that cannot be written is printed, not raised — the module docstring says why.

        WHILE A STEP RUNS, ITS OWN ENTRY IS NOT YET ON THE RECORD. A reader called from
        INSIDE the judge pass — the episode page, if it is rendered there as #1025's key flow
        says — sees the five steps before `JUDGE` and no judge wall; anything that needs the
        whole record has to run from the launcher after the `JUDGE` frame has closed.
        """
        started_at = now_iso()
        yield
        ended_at = now_iso()
        try:
            self.record(step, started_at=started_at, ended_at=ended_at)
        except OSError as unwritable:
            print(f"[branch] the {step} entry could not be written to the timing record "
                  f"({unwritable!r}); the episode itself is unaffected", file=sys.stderr)


def _record_text(rows: list[dict[str, Any]]) -> str:
    """The record's whole text for these steps — `sort_keys` so the bytes are a function of the
    steps and nothing else, like the family stamp beside it."""
    return json.dumps({"steps": rows}, indent=2, sort_keys=True) + "\n"


def read_stage_timings(episode_dir: Path) -> list[dict[str, Any]]:
    """The recorded steps, in the order they completed; `[]` for an episode that recorded
    none — an abort before the first step finished is a legitimate archived state.

    Through `read_guarded`, the posture every other reader of the episode tree takes: the
    record sits in the tree the writer refuses to alias-write into, and an entry at its name
    that is not a plain file — a planted link, a squatting directory — is a refusal that reads
    as NO record, never as whatever the entry points at. A document that IS there but is not
    the record's shape raises: the writer replaces the whole document atomically, so a torn
    or foreign document is not something this writer left, and reading it as "no steps" would
    make tampering look like an early abort.
    """
    text, _refusal = read_guarded(timing_path(episode_dir))
    if text is None:
        return []
    try:
        document = json.loads(text)
    except ValueError as malformed:
        raise ValueError(f"{TIMING_NAME} is not a JSON document: {malformed}") from malformed
    rows = document.get("steps") if isinstance(document, dict) else None
    if not isinstance(rows, list) or not all(_is_entry(row) for row in rows):
        raise ValueError(f'{TIMING_NAME} is not the timing record: expected {{"steps": [...]}} '
                         "with one {step, started_at, ended_at} entry per completed step")
    return rows


def _is_entry(row: Any) -> bool:
    return (isinstance(row, dict) and set(row) == {"step", "started_at", "ended_at"}
            and all(isinstance(row[key], str) for key in row))
