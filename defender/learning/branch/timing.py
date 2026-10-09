"""The episode's stage timing record: wall time per step, written by the launcher.

One document at the episode root, `timing.json`: `{"steps": [{step, started_at, ended_at}, …]}`,
one entry per step the launcher completed, in completion order. The launcher is the only frame
that sees every step boundary, so it holds the episode's one `StageClock`. Entries are written
after each step, so an aborted episode records exactly the steps that finished.

The whole document is replaced through the episode handle's `timing.write` after every step rather than appended
to, so a reader sees either the previous whole or the new whole. The reader therefore tolerates
nothing: a document not in the record's shape was put there by someone else, and it raises.

The write is best-effort at the frame, like the repo's other observability writers: the record
sits in the episode dir, where the guarded write can be refused (an alias planted at its name)
or fail (`ENOSPC`, read-only root). Raised through the step's frame, that would turn a finished
step into a failed one — sending `RUNS` into the abort arm or a fully graded episode out of
`main` as an `OSError`. So the fault is logged and the step is simply absent, which the record
already reads as "not seen to finish". A step name outside `Step` is a programming error and
still raises.

A record rather than a derivation because the archive's other clocks are inner ones (a run's
trace events, `duration_ms`) or file mtimes, neither of which gives the episode's wall time.
"""
from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Iterator
from typing import Any

from defender._clock import now_iso, parse_iso_utc
from defender._episode_handle import Episode
from defender._episode_paths import LAYOUT
from defender._io import Bound
from defender.learning.branch.steps import STEPS, Step

_logger = logging.getLogger(__name__)


class StageClock:
    """The launcher's outer clock for one episode, and the record its steps are written to.

    The steps live in memory and the file is their projection — never read back to be extended,
    so nothing on disk can make it write a row it did not see finish.
    """

    def __init__(self, episode: Episode) -> None:
        self._record = episode.timing
        self.path = self._record.path
        self._rows: list[dict[str, Any]] = []

    def record(self, step: str, *, started_at: str, ended_at: str) -> dict[str, Any]:
        """Add one completed step and rewrite the record; returns the entry written.

        A `step` outside `steps.STEPS` is refused before anything is written. The write goes
        through the episode handle (a replace that follows nothing below the episode dir), so an
        alias planted at the record's name is refused rather than written through.

        The step is kept before the write is tried: it finished regardless of whether the disk
        took the document, and dropping it on a failed write would leave a gap in every later
        document (e.g. `runs` recorded without the `review` it depends on). Kept first, the
        next rewrite carries it.
        """
        if step not in STEPS:
            raise ValueError(
                f"unknown episode step {step!r}; the record's steps are {', '.join(STEPS)}")
        # `str(...)`: a `Step` member in, the bare name out, so the returned entry equals the
        # one read back.
        row = {"step": str(step), "started_at": started_at, "ended_at": ended_at}
        self._rows.append(row)
        self._record.write(_record_text(self._rows))
        return row

    @contextlib.contextmanager
    def step(self, step: Step) -> Iterator[None]:
        """Time one step; its entry is recorded after the body returns normally, never on raise.

        @owns started_at
        @owns ended_at
        Both moments are stamped here from `_clock.now_iso`, either side of the body; `record`
        only carries them.

        An unwritable record is logged, not raised (see the module docstring). A reader called
        inside a step (e.g. a page rendered during the judge pass) sees no entry for that step,
        so anything needing the whole record must run after the `JUDGE` frame closes.
        """
        started_at = now_iso()
        yield
        ended_at = now_iso()
        try:
            self.record(step, started_at=started_at, ended_at=ended_at)
        except OSError as unwritable:
            _logger.warning(f"the {step} entry could not be written to the timing record "
                            f"({unwritable!r}); the episode itself is unaffected")


def _record_text(rows: list[dict[str, Any]]) -> str:
    """The record's whole text; `sort_keys` so the bytes are a function of the steps alone."""
    return json.dumps({"steps": rows}, indent=2, sort_keys=True) + "\n"


def read_stage_timings(bound: Bound) -> list[dict[str, Any]] | None:
    """The recorded steps in completion order; `None` when nothing is at the name (an abort
    before the first step finished).

    Anything else that is not the record raises `ValueError` naming the file: a non-regular
    entry (planted link, directory, non-text bytes) via the bound reader's screen, or a
    document of the wrong shape — since the writer replaces the whole document atomically, a
    malformed one is not something it left.
    """
    rec = bound.read(LAYOUT.timing)
    if rec.absent:
        return None
    if rec.text is None:
        raise ValueError(f"{LAYOUT.timing} could not be read: {rec.reason}")
    try:
        document = json.loads(rec.text)
    # `RecursionError` too: a deeply nested planted document leaves `json.loads` through that
    # class, not `ValueError`.
    except (ValueError, RecursionError) as malformed:
        raise ValueError(f"{LAYOUT.timing} is not a JSON document: {malformed}") from malformed
    rows = document.get("steps") if isinstance(document, dict) else None
    retired = sorted({row["step"] for row in rows if isinstance(row, dict)
                      and row.get("step") in RETIRED_STEPS}) if isinstance(rows, list) else []
    if retired:
        raise ValueError(
            f"{LAYOUT.timing} records the {', '.join(retired)} step(s), which predates the "
            "oracle (#1224: staging and review were replaced by pre-flight); an episode timed "
            "before the change is not read as this one's record")
    if not isinstance(rows, list) or not all(_is_entry(row) for row in rows):
        raise ValueError(f'{LAYOUT.timing} is not the timing record: expected {{"steps": [...]}} '
                         "with one {step, started_at, ended_at} entry per completed step, the "
                         f"step one of {', '.join(STEPS)} and both moments ISO-8601")
    return rows


#: Steps an episode launched before the oracle recorded, and no launch records now.
RETIRED_STEPS: frozenset[str] = frozenset({"staging", "review"})


def _is_entry(row: Any) -> bool:
    return (isinstance(row, dict) and set(row) == {"step", "started_at", "ended_at"}
            and row["step"] in STEPS
            and all(isinstance(row[key], str) and parse_iso_utc(row[key]) is not None
                    for key in ("started_at", "ended_at")))
