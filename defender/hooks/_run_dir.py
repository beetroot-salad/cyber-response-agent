
from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender._io import _refuse_unless_plain, open_nofollow_fd


def update_json_locked(
    path: Path, mutate: Callable[[dict], Any], *, default: Callable[[], dict] = dict
) -> dict:
    """Locked read-modify-write. `_refuse_unless_plain` + `O_NOFOLLOW` (#771 M3): the old
    `path.touch(exist_ok=True)` + `open(path, "r+")` both followed a planted symlink — `touch`
    would create/update the OUTSIDE target, and the `r+` open would then lock and rewrite it.
    The refusal happens before the lock is ever taken."""
    path = Path(path)
    _refuse_unless_plain(path)
    fd = open_nofollow_fd(path, os.O_RDWR | os.O_CREAT)
    with os.fdopen(fd, "r+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        raw = f.read()
        try:
            state = json.loads(raw) if raw else default()
        except json.JSONDecodeError:
            state = default()
        mutate(state)
        f.seek(0)
        f.truncate()
        f.write(json.dumps(state, indent=2))
    return state


def read_json_locked(path: Path) -> dict:
    path = Path(path)
    if not path.is_file():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            raw = f.read()
    except OSError:
        return {}
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}
