
from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender._io import locked_for_read, locked_for_rewrite, locked_json_read, locked_json_update


def update_json_locked(
    path: Path, mutate: Callable[[dict], Any], *, default: Callable[[], dict] = dict,
    os_: Any = os,
) -> dict:
    """Locked read-modify-write of the run-state JSON at `path` through
    `_io.locked_json_update`: a planted link or other non-plain entry is refused before the
    lock, and content unusable as state (too big, undecodable, not JSON, too deep, not an
    object) starts over from `default()`, so `mutate` always receives a dict; any other read
    fault propagates and nothing is written (#1174). `os_` is the seam, for opener and read
    alike."""
    return locked_json_update(locked_for_rewrite(Path(path), os_=os_), mutate, default=default,
                              os_=os_)


def read_json_locked(path: Path, *, os_: Any = os) -> dict:
    """The document at `path` as a dict — `{}` for absent, linked or otherwise non-plain,
    unreadable, too big, unparseable, or non-dict — under a shared lock, creating nothing
    (`_io.locked_json_read`, #1174 O8). Narrowed here so no reader has to handle a non-dict."""
    return locked_json_read(locked_for_read(Path(path), os_=os_), os_=os_)
