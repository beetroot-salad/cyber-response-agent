"""Ending a child's whole process group: for a child started in a session of its own
(`start_new_session=True`), whose group id is its pid. Kept apart from `_git.py`, which is
pinned to use `os` for nothing but a git child's environment (#1134: it judges nothing on
disk). The kill opens no path; the wait for the group to be gone reads only `/proc`.

A run's end is its whole group gone, not its child's exit: a SIGKILL is sent at once but
lands when each member is next scheduled, so a member can still run a moment after the
signal. `end_group` sends the kill and waits for that moment to pass."""
from __future__ import annotations

import contextlib
import logging
import os
import signal
import time
from collections.abc import Callable

_logger = logging.getLogger(__name__)

#: How long `end_group` waits for a killed group's members to be gone. A killed process exits
#: within milliseconds; one that does not (stuck in an uninterruptible read, say) is logged and
#: left, so no stop or cleanup ever hangs on it.
GROUP_END_LIMIT = 10.0
_POLL = 0.01


def kill_group(pgid: int) -> None:
    """SIGKILL every process left in the group `pgid`, without waiting for them to be gone;
    nothing when none is left (or the group is not this user's to signal). For a caller that
    must not wait; any other ends the group with `end_group`."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)


def end_group(pgid: int, *, limit: float = GROUP_END_LIMIT,
              running: Callable[[int], bool] | None = None) -> bool:
    """SIGKILL every process left in the group `pgid`, then wait until none of them still runs
    (gone, or exited and awaiting its parent's wait), at most `limit` seconds. True when the
    group is gone; False, logged, when a member still ran at the limit. `running` is the
    liveness test (default `group_running`), a door for tests."""
    is_running = group_running if running is None else running
    kill_group(pgid)
    deadline = time.monotonic() + limit
    while is_running(pgid):
        if time.monotonic() >= deadline:
            _logger.error("process group %d still ran %gs after it was killed; leaving it", pgid, limit)
            return False
        time.sleep(_POLL)
    return True


def group_running(pgid: int) -> bool:
    """Whether any member of the group `pgid` still runs. A member that has exited but not been
    waited for (a zombie: a killed grandchild is reparented, and its new parent reaps it when
    it will) runs nothing, so it does not count. Without `/proc`, any member left counts."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False  # no member at all, zombie or not
    except PermissionError:
        pass  # a member this user cannot signal: judged from /proc like the rest
    try:
        entries = os.listdir("/proc")
    except OSError:
        return True
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as handle:
                stat = handle.read()
        except OSError:
            continue  # exited while the folder was listed
        # `pid (comm) state ppid pgrp ...`; comm may hold spaces and parentheses.
        fields = stat[stat.rindex(b")") + 2:].split()
        if len(fields) > 2 and int(fields[2]) == pgid and fields[0] not in (b"Z", b"X"):
            return True
    return False
