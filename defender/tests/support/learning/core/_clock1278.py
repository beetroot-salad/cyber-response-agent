"""#1278 repair 2, family 11: a host clock that is wrong, for the test that every recovery path judges a lapse by the database's.

Nothing here implements policy: it moves what a host process reads as the time (`datetime.datetime.now`, `time.time`)
and nothing else; the database's `now()` is the server's and does not move.
"""
from __future__ import annotations

import datetime as dt
import time
from collections.abc import Iterator
from contextlib import contextmanager
from unittest import mock


@contextmanager
def host_clock_skewed(hours: float) -> Iterator[None]:
    """For the block, `datetime.datetime.now()`, `utcnow()` and `time.time()` read `hours` ahead (negative: behind)."""
    real_datetime, real_time = dt.datetime, time.time
    shift = dt.timedelta(hours=hours)

    class Skewed(real_datetime):  # type: ignore[misc, valid-type]
        @classmethod
        def now(cls, tz=None):  # type: ignore[no-untyped-def]
            return real_datetime.now(tz) + shift

        @classmethod
        def utcnow(cls):  # type: ignore[no-untyped-def]
            return real_datetime.utcnow() + shift  # noqa: DTZ003 — the call being skewed

    def later() -> float:
        return real_time() + hours * 3600

    with mock.patch.object(dt, "datetime", Skewed), mock.patch.object(time, "time", later):
        yield
