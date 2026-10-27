"""The run clock's source, held by a run's `RunState` (#1255, design rev 4 "Time")."""
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
