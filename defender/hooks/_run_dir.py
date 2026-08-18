
from __future__ import annotations

import fcntl
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender._io import TEXT_READ_ERRORS, locked_for_rewrite


def update_json_locked(
    path: Path, mutate: Callable[[dict], Any], *, default: Callable[[], dict] = dict
) -> dict:
    """Locked read-modify-write. The refuse-then-`O_NOFOLLOW`-then-lock prefix is
    `_io.locked_for_rewrite`'s, not a second copy of it: `path.touch(exist_ok=True)` +
    `open(path, "r+")` both follow a planted symlink — `touch` creates/updates the OUTSIDE
    target and the `r+` open then locks and rewrites it. The refusal happens before the lock is
    ever taken.

    A document that parses to a NON-DICT falls back to `default()` too. `[]`, `3`, `"x"` and
    `null` are all valid JSON and none is a state written through here; each `mutate` opens with
    `state[...]` or `state.setdefault(...)`, so a non-dict would raise
    `TypeError`/`AttributeError` out of the writer. Coercing at this seam keeps the signature's
    promise once instead of in each `mutate`."""
    path = Path(path)
    with locked_for_rewrite(path) as f:
        # UNDECODABLE is the same case as unparseable, reached one step EARLIER: the handle is
        # text-mode utf-8, so a `budget.json` holding non-UTF-8 bytes raises `UnicodeDecodeError`
        # out of the read, above every guard below it. `""` here, so `default()` applies.
        try:
            raw = f.read()
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
    """The document at `path` as a dict — `{}` for absent, unreadable, unparseable, and for a
    document that parses to something that is not a dict.

    `json.loads` is typed `Any`, which satisfies every annotation, so without the last clause
    `3`, `"x"`, `null` and `[]` type-check clean and come back as the state. Callers then
    dereference them (`{**state, …}`, `state.get("alias_refusals", [])`) and raise
    `TypeError`/`AttributeError` from a fault path with no handler for it.

    Narrowed HERE rather than at each reader, which is the argument
    `scripts/lint/lint_unnarrowed_parse.py` makes for gating this seam: fixing the seam fixes
    every reader, present and future."""
    path = Path(path)
    if not path.is_file():
        return {}
    # A SYMLINK at the state's name is not this run's state — the same judgement
    # `locked_for_rewrite` makes on the write side. `is_file()` above DEREFERENCES, so without
    # this the reader follows a planted alias and reads whatever it points at as `budget.json`.
    if path.is_symlink():
        return {}
    # `TEXT_READ_ERRORS`, not a bare `OSError`: `f.read()` on a text handle also raises
    # `UnicodeDecodeError` (a `ValueError`), and non-UTF-8 bytes in the rw-bound run root would
    # otherwise come back out of `read_budget` un-caught.
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
