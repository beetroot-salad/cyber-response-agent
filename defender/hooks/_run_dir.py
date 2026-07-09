#!/usr/bin/env python3
"""Shared run-dir + per-run-salt resolution for the defender PostToolUse hooks.

The defender runs one in-process agent per run and exports
``DEFENDER_RUN_DIR`` into the process (run.py), so both the budget
enforcer and the tag hook anchor on that single env var rather than a
session→run map. Centralizing the lookup here keeps the contract (env
var name, ``is_dir`` guard, ``meta.json`` location) in one place — the
defender analogue of soc-agent's ``hooks/scripts/run_context.py``.
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender._run_paths import RunPaths


def update_json_locked(
    path: Path, mutate: Callable[[dict], Any], *, default: Callable[[], dict] = dict
) -> dict:
    """Atomic read-modify-write of a JSON file under an exclusive ``flock``.

    Reads ``path`` (empty or corrupt content → ``default()``), calls
    ``mutate(state)`` to update the dict in place *while the lock is held*,
    writes it back pretty-printed, and returns the mutated state. The single
    locked-update primitive behind the per-run ``budget.json`` and
    ``circuit_breaker.json`` files, so concurrent gather subagents can't race.
    """
    path = Path(path)
    path.touch(exist_ok=True)
    with open(path, "r+") as f:
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


def resolve_run_dir() -> Path | None:
    """The run dir from ``DEFENDER_RUN_DIR``, or None if unset/not a dir."""
    raw = os.environ.get("DEFENDER_RUN_DIR")
    if not raw:
        return None
    run_dir = Path(raw)
    return run_dir if run_dir.is_dir() else None


def read_meta_salt() -> str:
    """The stable per-run salt from ``{run_dir}/meta.json`` (written by
    run.py). Falls back to a fresh random salt only when no run dir / meta
    is available — callers that need a *stable* salt should treat a missing
    run dir as degraded."""
    run_dir = resolve_run_dir()
    if run_dir is not None:
        meta_path = RunPaths(run_dir).meta
        if meta_path.exists():
            try:
                salt = json.loads(meta_path.read_text()).get("salt", "")
                if salt:
                    return salt
            except (json.JSONDecodeError, OSError):
                pass
    return secrets.token_hex(8)
