
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender._io import locked_for_read, locked_for_rewrite, locked_json_read, locked_json_update


def update_json_locked(
    path: Path, mutate: Callable[[dict], Any], *, default: Callable[[], dict] = dict
) -> dict:
    """Locked read-modify-write of the run-state JSON at `path` through
    `_io.locked_json_update`: a planted link or other non-plain entry is refused before the
    lock, and content unusable as state (too big, undecodable, not JSON, too deep, not an
    object) starts over from `default()`, so `mutate` always receives a dict (#1174)."""
    return locked_json_update(locked_for_rewrite(Path(path)), mutate, default=default)


def read_json_locked(path: Path) -> dict:
    """The document at `path` as a dict — `{}` for absent, linked or otherwise non-plain,
    unreadable, too big, unparseable, or non-dict — under a shared lock, creating nothing
    (`_io.locked_json_read`, #1174 O8). Narrowed here so no reader has to handle a non-dict."""
    return locked_json_read(locked_for_read(Path(path)))
