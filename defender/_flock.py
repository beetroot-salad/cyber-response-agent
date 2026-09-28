"""A shared `fcntl.flock` primitive: take an exclusive lock (once, until a deadline, or forever)
and release it. Expiry returns `False` rather than raising, since callers treat it differently.

Lives at `defender/` level so `learning/core` can use it without importing `learning/author`.
"""
from __future__ import annotations

import fcntl
import time
from pathlib import Path
from typing import IO, Any

#: Retry interval for a waiting acquirer. A repo lock is held for a whole authoring run (slow
#: poll is fine); a channel append lock is held for one row (a slow poll would dominate).
SLOW_POLL = 0.2
FAST_POLL = 0.05


def open_lock(path: Path) -> IO[str]:
    """The lock file, created if absent. `a+` neither truncates a file another holder has open
    nor fails on a missing one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("a+", encoding="utf-8")


def take(fh: Any, *, timeout_seconds: float | None, poll: float = FAST_POLL) -> bool:
    """Take the exclusive lock on `fh`. `True` if taken, `False` if the deadline expired.

    `timeout_seconds=0` tries exactly once; `None` blocks forever (for appenders, where giving
    up would lose the row). Never closes `fh` — the caller owns it on every path.
    """
    if timeout_seconds is None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        return True
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(poll)


def release(fh: Any) -> None:
    """Unlock and close. `None` is accepted so a caller that may hold nothing needs no branch."""
    if fh is None:
        return
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()
