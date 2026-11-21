"""Shared by the three `test_r6_publish_stop_*` modules (one file was ~577s on one xdist worker, so it was split)."""
from __future__ import annotations

import os
import time
from pathlib import Path



WORKTREE = Path(__file__).resolve().parents[4]
OID = "0123456789abcdef0123456789abcdef01234567"


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):  # reaped between the kill(0) and the read
        return False
    return stat[stat.rindex(")") + 2] != "Z"


def _outlives(pid: int) -> bool:
    """Still alive after 2 seconds? A SIGKILL is delivered asynchronously: the launch returns
    once the group's pipes close, which can be a moment before the grandchild's exit."""
    deadline = time.monotonic() + 2.0
    while _alive(pid):
        if time.monotonic() > deadline:
            return True
        time.sleep(0.02)
    return False

