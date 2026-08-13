
from __future__ import annotations

import fcntl
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender._io import locked_for_rewrite


def update_json_locked(
    path: Path, mutate: Callable[[dict], Any], *, default: Callable[[], dict] = dict
) -> dict:
    """Locked read-modify-write. The refuse-then-`O_NOFOLLOW`-then-lock prefix is
    `_io.locked_for_rewrite`'s, not a second copy of it (#771 M3): the old
    `path.touch(exist_ok=True)` + `open(path, "r+")` both followed a planted symlink — `touch`
    would create/update the OUTSIDE target, and the `r+` open would then lock and rewrite it.
    The refusal happens before the lock is ever taken.

    A document that parses to a NON-DICT falls back to `default()` too (#878 F-17/F-25). `[]`,
    `3`, `"x"` and `null` are all valid JSON and none of them is any of the three states written
    through here; each `mutate` is typed `Callable[[dict], Any]` and opens with `state[...]` or
    `state.setdefault(...)`, so a non-dict raised `TypeError`/`AttributeError` out of the
    writer — out of `open_budget` before MAIN's first prompt, and out of
    `circuit_breaker.record_outcome` past every handler in the run. Coercing at this seam keeps
    the signature's promise once instead of in each of the three `mutate`s, and it is the same
    judgement `json.JSONDecodeError` above already makes: a document this function cannot
    read as state is a document it starts over from."""
    path = Path(path)
    with locked_for_rewrite(path) as f:
        raw = f.read()
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
    """The document at `path` as a dict — `{}` for absent, unreadable, unparseable, and (since
    #878 F-17) for a document that parses to something that is not a dict.

    `-> dict` was a claim this function did not keep: `json.loads` is typed `Any` and `Any`
    satisfies every annotation, so `3`, `"x"`, `null` and `[]` type-checked clean and came back
    as the state. Every caller then dereferenced them — `read_budget`'s state is spread with
    `{**state, …}`, `_record_alias_refusal` does `state.get("alias_refusals", [])` — and raised
    `TypeError`/`AttributeError` from a fault path with no handler for it, ending the run with
    no disposition.

    Narrowed HERE rather than at each reader, which is the argument
    `scripts/lint/lint_unnarrowed_parse.py` makes for gating this seam and deliberately not the
    readers of what it launders: fixing the seam fixes every reader, present and future."""
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
        doc = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}
    return doc if isinstance(doc, dict) else {}
