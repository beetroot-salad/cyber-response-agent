"""The run clock's source, held by a run's `RunState` (#1255, design rev 4 "Time").

The run clock is host-owned: every time the model can see (a stamp in a readable file, a capture
stamp, a budget limit) is a reading of it, never a fresh read of the host's wall clock. This
module is its SOURCE half: a reading of where the run's time stands, in two forms —

  * `ticks()`, non-decreasing float seconds: what elapsed time is measured in (`RunState`
    subtracts its origin tick and the seconds oracle turns held the world);
  * `at(ticks)`, the absolute instant that tick count names (aware UTC).

There are two kinds of source:

  * the HOST's (`RunClock()`, production's natural run): anchored at the wall clock's reading
    when the clock was made, advancing by `time.monotonic()`. A wall clock stepped back or
    forward (NTP) moves no reading: the run's own time only ever runs forward.
  * an INJECTED one (`RunClock(source)`, `run_investigation(clock=…)`): a zero-argument callable
    returning an aware UTC datetime. Its forward moves accumulate; a step back is absorbed —
    the reading holds where it was and the source's later forward moves count from its new
    position (rev 5 C10: "elapsed accumulates only the source's forward moves").

Pauses (oracle turns) and an arm's start at its source's reading are `RunState`'s, which reads
this clock and keeps the origin and credits beside it.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

#: An injected run clock source: a zero-argument callable returning an aware UTC datetime.
ClockSource = Callable[[], datetime]


def _aware_utc(moment: object, *, what: str) -> datetime:
    """`moment` as aware UTC, or `TypeError`/`ValueError`: the source contract is an aware
    datetime, and a naive one would be read in the host's zone by `astimezone`."""
    if not isinstance(moment, datetime):
        raise TypeError(f"{what} returned {type(moment).__name__}, not a datetime")
    if moment.utcoffset() is None:
        raise ValueError(f"{what} returned a naive datetime ({moment!r}); the run clock reads "
                         "aware UTC")
    return moment.astimezone(UTC)


class RunClock:
    """A run clock's source (see the module docstring). Thread-safe: gather leads and oracle
    turns read it from worker threads."""

    def __init__(self, source: ClockSource | None = None) -> None:
        self._lock = threading.Lock()
        self.injected = source is not None
        if source is None:
            # The host's: wall anchor, monotonic progress.
            self._source: ClockSource | None = None
            self._anchor_tick = time.monotonic()
            self._anchor = datetime.now(UTC)
        else:
            self._source = source
            self._last = _aware_utc(source(), what="the run clock's source")
            self._acc = 0.0
            self._anchor_tick = 0.0
            self._anchor = self._last

    def ticks(self) -> float:
        """The clock's progress in seconds: non-decreasing, whatever the source does."""
        if self._source is None:
            return time.monotonic()
        with self._lock:
            raw = _aware_utc(self._source(), what="the run clock's source")
            step = (raw - self._last).total_seconds()
            if step > 0:
                self._acc += step
            # A step back is absorbed: the next forward move counts from where the source is.
            self._last = raw
            return self._acc

    def at(self, ticks: float) -> datetime:
        """The absolute instant `ticks` names on this clock (aware UTC)."""
        return self._anchor + timedelta(seconds=ticks - self._anchor_tick)
