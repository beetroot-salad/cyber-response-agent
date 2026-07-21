"""Locked JSON state for the defender gate modules.

``update_json_locked`` is the single locked-update primitive behind the per-run
``budget.json`` and ``circuit_breaker.json`` files. Its two consumers — the budget
enforcer and the circuit breaker — are each handed their run dir as an argument.

This module used to also resolve the run dir from ``DEFENDER_RUN_DIR`` for the
gate modules that ran as `claude -p` hook subprocesses and had no other way to
learn it. Every such entrypoint is gone (#631, #667), and the in-process gates
take the run dir from ``AgentDeps``, so ``resolve_run_dir`` went with the last of
them. The env var still crosses into the bash tool's subprocess environment for
the ticket adapter, which reads it directly (``scripts/adapters/ticket_adapter``).

This module resolves no salt. The run's trust token is minted in process by
``run_common.materialize_run_dir`` and threaded to its consumers as a value; it
has no run-dir file to be read back out of.
"""

from __future__ import annotations

import fcntl
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any


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
    with open(path, "r+", encoding="utf-8") as f:
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
    """Read a JSON file under a SHARED ``flock`` — the consistent-read twin of
    ``update_json_locked``.

    A shared lock blocks only while a writer holds the exclusive lock, so a reader
    never observes the truncate-then-write window an in-place update opens: it sees
    a whole record or waits. Missing file, empty content, or corrupt JSON all return
    ``{}`` (the caller decides what an absent/torn state means), and an unreadable
    file (``OSError``) does too rather than propagating out of a gate.
    """
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
