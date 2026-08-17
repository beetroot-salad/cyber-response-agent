"""One `fcntl.flock` primitive, and the one deadline loop its callers share.

Two behaviours: take an exclusive lock on a file (immediately, retried until a deadline, or
waiting forever), and release it. What a caller does when the deadline expires differs and is
therefore a parameter — `author/drain.py`'s retire decision keys on a raise, while the drain's
channel wait must NOT raise, because an appender's ordinary hold is not a fault.

This lives at `defender/` level rather than in either caller: `learning/core/persist.py` and
`learning/author/shared.py` both need it, and `core` importing `author` would invert the
dependency and drag the pipeline prompt machinery into the persistence layer.
"""
from __future__ import annotations

import fcntl
import time
from pathlib import Path
from typing import IO, Any

#: How often a waiting acquirer retries. The two live values are deliberate, not drift: a
#: repo lock is held across a whole authoring run so polling it fast buys nothing, while a
#: channel's append lock is held for a single row and a slow poll would dominate the wait.
SLOW_POLL = 0.2
FAST_POLL = 0.05


def open_lock(path: Path) -> IO[str]:
    """The lock file, created if absent. Append mode: the bytes are irrelevant, the inode
    is the lock, and `a+` neither truncates a file another holder has open nor fails on a
    missing one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("a+", encoding="utf-8")


def take(fh: Any, *, timeout_seconds: float | None, poll: float = FAST_POLL) -> bool:
    """Take the exclusive lock on `fh`. `True` if taken, `False` if the deadline expired.

    `timeout_seconds=0` tries exactly once — the "skip this tick" acquisition.
    `timeout_seconds=None` blocks forever, which is what an APPENDER wants: giving up would
    lose the row it is carrying, and it waits on nothing but other appenders and a short
    rewrite window.

    Never closes `fh`. The caller opened it and owns it on every path, including failure,
    because the three callers dispose of a failed acquisition differently.
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
