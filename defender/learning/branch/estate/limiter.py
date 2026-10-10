"""The per-process rate limiter for every query branching issues on its own behalf (#1224, M13).

One `RateLimiter` per process: the launcher's during pre-flight holds the episode rate R, each
sibling's holds its slice R/k (S18). No state or lock is shared across processes (S16), so a
holder that dies can stall no one, and a relaunch starts a fresh limiter (N17).

Spacing, not a token bucket: permits are at least `1 / rate` seconds apart, the first one is
immediate, and an idle gap banks no burst (S14). A saturated limiter waits, never refuses
(M11=A). A limiter that cannot read its clock raises rather than admit unthrottled (S17).
"""
from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable


class LimiterStateError(RuntimeError):
    """The limiter could not read its own state; nothing was admitted (fails closed, S17)."""


class RateLimiter:
    """Admits at most `rate` permits per second, spaced evenly."""

    def __init__(self, rate: float, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if isinstance(rate, bool) or not (
                isinstance(rate, int | float) and math.isfinite(rate) and rate > 0):
            raise ValueError(f"a rate limiter needs a positive finite rate, got {rate!r}")
        interval = 1.0 / float(rate)
        if not math.isfinite(interval):  # a subnormal rate's spacing overflows to inf
            raise ValueError(f"a rate limiter's rate {rate!r} is too small to space permits")
        self._interval = interval
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._last: float | None = None

    def _now(self) -> float:
        try:
            reading = float(self._clock())
        except Exception as exc:  # noqa: BLE001 — any unreadable clock fails closed
            raise LimiterStateError(f"the rate limiter could not read its clock: {exc}") from exc
        if not math.isfinite(reading):
            raise LimiterStateError(f"the rate limiter read a corrupt clock value: {reading!r}")
        return reading

    def acquire(self) -> float:
        """Wait for the next permit; returns the seconds waited (callers exclude it from their
        own deadlines). The slot is reserved under the lock and the wait happens outside it, so
        a caller killed in its wait leaves the next caller at most one interval behind."""
        with self._lock:
            now = self._now()
            slot = now if self._last is None else max(now, self._last + self._interval)
            self._last = slot
        wait = slot - now
        if wait > 0:
            self._sleep(wait)
        return max(wait, 0.0)
