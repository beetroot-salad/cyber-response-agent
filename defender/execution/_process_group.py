"""Ending a child's whole process group: for a child started in a session of its own
(`start_new_session=True`), whose group id is its pid. Kept apart from `_git.py`, which is
pinned to use `os` for nothing but a git child's environment (#1134: it judges nothing on
disk). The kill opens no path; the wait for the group to be gone reads only `/proc`.

A run's end is its whole group gone, not its child's exit: a SIGKILL is sent at once but
lands when each member is next scheduled, so a member can still run a moment after the
signal. `end_group` sends the kill and waits for that moment to pass; a caller that must send
the kill on one thread and wait on another uses `kill_group`, then `wait_group_gone`."""
from __future__ import annotations

import contextlib
import logging
import os
import signal
import time
from collections.abc import Callable

_logger = logging.getLogger(__name__)

#: How long the wait for a killed group's members to be gone lasts. A killed process exits
#: within milliseconds; one that does not (stuck in an uninterruptible read, say) is logged and
#: left, so no stop or cleanup ever hangs on it.
GROUP_END_LIMIT = 10.0
#: The first and the longest gap between two looks at the group: most groups are gone at the
#: first look; a stuck one is looked at a few times a second, not a hundred.
_FIRST_POLL, _LONGEST_POLL = 0.005, 0.25


def kill_group(pgid: int) -> None:
    """SIGKILL every process left in the group `pgid`, without waiting for them to be gone;
    nothing when none is left (or the group is not this user's to signal)."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)


def wait_group_gone(pgid: int, *, limit: float = GROUP_END_LIMIT,
                    running: Callable[[int], bool] | None = None) -> bool:
    """Wait, at most `limit` seconds, until no member of the group `pgid` still runs (its kill
    already sent). True when none does; False, logged, when one still ran at the limit.
    `running` is the liveness test (default `group_running`), a door for tests."""
    is_running = group_running if running is None else running
    deadline = time.monotonic() + limit
    gap = _FIRST_POLL
    while is_running(pgid):
        left = deadline - time.monotonic()
        if left <= 0:
            _logger.error("process group %d still ran %gs after it was killed; leaving it", pgid, limit)
            return False
        time.sleep(min(gap, left))
        gap = min(gap * 2, _LONGEST_POLL)
    return True


def end_group(pgid: int, *, limit: float = GROUP_END_LIMIT,
              running: Callable[[int], bool] | None = None) -> bool:
    """SIGKILL every process left in the group `pgid`, then `wait_group_gone`."""
    kill_group(pgid)
    return wait_group_gone(pgid, limit=limit, running=running)


def group_running(pgid: int, *, proc: str = "/proc") -> bool:
    """Whether any member of the group `pgid` still runs that waiting can see end. Not counted:
    a member that has exited but not been waited for (a zombie: a killed grandchild is
    reparented, and its new parent reaps it when it will), and one this user cannot signal (the
    kill never reached it, so waiting for it would only spend the limit). Without `proc` a
    zombie cannot be told from a live member, so nothing is counted: the kill was sent, and
    that is all that can be known. `proc` is a door for tests."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False  # no member at all, zombie or not
    except PermissionError:
        pass  # some member this user cannot signal: the rest are judged one by one below
    try:
        entries = os.listdir(proc)
    except OSError:
        return False
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(f"{proc}/{name}/stat", "rb") as handle:
                stat = handle.read()
        except OSError:
            continue  # exited while the folder was listed
        # `pid (comm) state ppid pgrp ...`; comm may hold spaces and parentheses.
        fields = stat[stat.rindex(b")") + 2:].split()
        if len(fields) <= 2 or int(fields[2]) != pgid or fields[0] in (b"Z", b"X"):
            continue
        try:
            os.kill(int(name), 0)
        except ProcessLookupError:
            continue  # gone since its stat was read
        except PermissionError:
            continue  # not this user's to kill: the kill never reached it
        return True
    return False
