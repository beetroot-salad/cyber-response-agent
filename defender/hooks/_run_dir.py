
from __future__ import annotations

import fcntl
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender._io import TEXT_READ_ERRORS, locked_for_rewrite, read_locked_whole


def update_json_locked(
    path: Path, mutate: Callable[[dict], Any], *, default: Callable[[], dict] = dict
) -> dict:
    """Locked read-modify-write through `_io.locked_for_rewrite`, which refuses a planted
    symlink before taking the lock.

    An undecodable, unparseable, or non-dict document falls back to `default()`, so `mutate`
    always receives a dict."""
    path = Path(path)
    with locked_for_rewrite(path) as f:
        try:
            raw = read_locked_whole(f)
        except UnicodeDecodeError:
            raw = ""
        try:
            state = json.loads(raw) if raw else default()
        except json.JSONDecodeError:
            state = default()
        if not isinstance(state, dict):
            state = default()
        mutate(state)
        f.seek(0)
        f.truncate()
        f.write(json.dumps(state, indent=2))
    return state


def read_json_locked(path: Path) -> dict:
    """The document at `path` as a dict — `{}` for absent, symlinked, unreadable, unparseable,
    or non-dict. Narrowed here so no reader has to handle a non-dict `json.loads` result."""
    path = Path(path)
    if not path.is_file():
        return {}
    # `is_file()` follows links; a symlink at the state's name is a planted alias, not state.
    if path.is_symlink():
        return {}
    # `TEXT_READ_ERRORS` also covers `UnicodeDecodeError` from non-UTF-8 bytes.
    try:
        with open(path, encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            raw = f.read()
    except TEXT_READ_ERRORS:
        return {}
    try:
        doc = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}
    return doc if isinstance(doc, dict) else {}
