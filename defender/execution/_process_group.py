"""Signalling a child's whole process group: for a child started in a session of its own
(`start_new_session=True`), whose group id is its pid. Kept apart from `_git.py`, which is
pinned to use `os` for nothing but a git child's environment (#1134: it judges nothing on
disk); a group kill opens no path."""
from __future__ import annotations

import contextlib
import os
import signal


def kill_group(pgid: int) -> None:
    """SIGKILL every process left in the group `pgid`; nothing when none is left (or the
    group is not this user's to signal)."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)
