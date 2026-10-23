"""Who owns a per-owner scratch folder (a draft or a run copy), and whether that owner is alive.

The record is JSON `{"pid": int, "start": str}` in a file named `owner` inside the folder, where
`start` is field 22 of `/proc/<pid>/stat` (clock ticks since boot, compared as text). The same pid
with another start time is a different process, so a recycled pid never keeps a dead owner's folder."""
from __future__ import annotations

import json
import os
from pathlib import Path

from defender import _io

OWNER_FILE = "owner"


def process_start(pid: int) -> str | None:
    """`pid`'s kernel start time as text, or None when no such process runs (a zombie, exited
    but not yet reaped, runs no more)."""
    try:
        stat = _io.read_text_utf8(Path(f"/proc/{pid}/stat"))
    except OSError:
        return None
    # The command name (field 2) may hold spaces and parentheses; fields resume after the last ")".
    fields = stat[stat.rindex(")") + 2:].split()
    if len(fields) < 20 or fields[0] in {"Z", "X"}:
        return None
    return fields[19]


def write_owner(folder: Path, pid: int | None = None) -> None:
    """Record the calling process (or `pid`) as `folder`'s owner."""
    pid = os.getpid() if pid is None else pid  # lint-default: ok — the calling process is known only at call time (a signature default is fixed at import, wrong after a fork)
    start = process_start(pid)
    if start is None:
        raise OSError(f"no process {pid} to own {folder}")
    _io.write_guarded(Path(folder) / OWNER_FILE, json.dumps({"pid": pid, "start": start}) + "\n")


def owner_alive(folder: Path) -> bool:
    """False when `folder`'s owner is gone, or its record is missing or unreadable.

    A folder with no valid owner can never be claimed back, so it counts as dead."""
    try:
        record = json.loads(_io.read_text_utf8(Path(folder) / OWNER_FILE))
        pid, start = record["pid"], record["start"]
    except (OSError, ValueError, KeyError, TypeError):
        return False
    if not isinstance(pid, int) or isinstance(pid, bool):
        return False
    return process_start(pid) == str(start)
