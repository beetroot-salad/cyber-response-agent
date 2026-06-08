#!/usr/bin/env python3
"""Shared run-dir + per-run-salt resolution for the defender PostToolUse hooks.

The defender spawns one ``claude -p`` per run and exports
``DEFENDER_RUN_DIR`` into the process (run.py), so both the budget
enforcer and the tag hook anchor on that single env var rather than a
session→run map. Centralizing the lookup here keeps the contract (env
var name, ``is_dir`` guard, ``meta.json`` location) in one place — the
defender analogue of soc-agent's ``hooks/scripts/run_context.py``.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path


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
        meta_path = run_dir / "meta.json"
        if meta_path.exists():
            try:
                salt = json.loads(meta_path.read_text()).get("salt", "")
                if salt:
                    return salt
            except (json.JSONDecodeError, OSError):
                pass
    return secrets.token_hex(8)
