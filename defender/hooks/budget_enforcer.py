#!/usr/bin/env python3
"""PostToolUse hook: per-run tool-call budget tracking (warning-only).

Counts tool calls and subagent spawns per run and prints stderr
warnings when usage crosses 75% / 100% of the configured caps, plus a
wall-clock check. **Warning-only** — always exits 0, never blocks the
agent (the same posture as soc-agent's enforcer; hard enforcement can
be switched on later by returning 2).

Run identification: the defender spawns one ``claude -p`` per run, so
the run dir is the single ``DEFENDER_RUN_DIR`` env var that run.py
exports into the claude process (and thus into hook subshells). No
session→run map is needed. If the var is unset or not a directory the
hook is a silent no-op.

Counters live in ``{run_dir}/budget.json``, incremented under an
exclusive ``flock`` so concurrent PostToolUse invocations don't race.

Exit codes:
    0 — always.
"""

from __future__ import annotations

import fcntl
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

# Sibling-import the shared run-dir helper. Inserting our own dir covers
# the importlib-loaded test path; running as a script adds it automatically.
_HOOK_DIR = Path(__file__).resolve().parent
if str(_HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(_HOOK_DIR))
from _run_dir import resolve_run_dir  # noqa: E402

# Caps are intentionally inline + single-default: the defender has no
# per-signature permissions.yaml to overlay, so there is nothing to
# layer. Tune here if a real run proves these wrong.
DEFAULT_LIMITS = {
    "max_tool_calls": 200,
    "max_subagent_spawns": 40,
    "wall_clock_timeout": 1800,  # seconds (30 min); warn at 75% (22.5 min)
}
WARNING_THRESHOLD = 0.75


def make_budget_state(run_id: str) -> dict:
    return {
        "run_id": run_id,
        "tool_calls": 0,
        "subagent_spawns": 0,
        "started_at": datetime.now(UTC).isoformat(),
    }


def update_budget_locked(run_dir: Path, run_id: str, tool_name: str) -> dict:
    """Atomic read-modify-write of budget.json under an exclusive lock."""
    budget_path = run_dir / "budget.json"
    budget_path.touch(exist_ok=True)
    with open(budget_path, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        raw = f.read()
        try:
            budget = json.loads(raw) if raw else make_budget_state(run_id)
        except json.JSONDecodeError:
            budget = make_budget_state(run_id)
        # Backfill started_at if an older/partial budget.json lacks it, so the
        # wall-clock check never silently drops out for the rest of the run.
        budget.setdefault("started_at", datetime.now(UTC).isoformat())
        budget["tool_calls"] = budget.get("tool_calls", 0) + 1
        if tool_name in ("Task", "Agent"):
            budget["subagent_spawns"] = budget.get("subagent_spawns", 0) + 1
        f.seek(0)
        f.truncate()
        f.write(json.dumps(budget, indent=2))
    return budget


def _ratio_warning(label: str, current: float, cap: float, unit: str = "") -> str | None:
    if cap <= 0:
        return None
    ratio = current / cap
    cur_s = f"{int(current)}{unit}"
    cap_s = f"{int(cap)}{unit}"
    if ratio >= 1.0:
        return (
            f"Budget exceeded: {label} at {cur_s}/{cap_s}. "
            "Investigation should conclude with current evidence."
        )
    if ratio >= WARNING_THRESHOLD:
        return (
            f"Budget warning: {label} at {cur_s}/{cap_s} "
            f"({int(ratio * 100)}%). Consider wrapping up."
        )
    return None


def check_budgets(budget: dict, limits: dict) -> list[str]:
    warnings: list[str] = []
    try:
        started = datetime.fromisoformat(budget["started_at"])
        elapsed = (datetime.now(UTC) - started).total_seconds()
        w = _ratio_warning("wall_clock", elapsed, limits["wall_clock_timeout"], "s")
        if w:
            warnings.append(w)
    except (KeyError, ValueError):
        pass
    w = _ratio_warning("tool_calls", budget.get("tool_calls", 0), limits["max_tool_calls"])
    if w:
        warnings.append(w)
    w = _ratio_warning(
        "subagent_spawns", budget.get("subagent_spawns", 0), limits["max_subagent_spawns"]
    )
    if w:
        warnings.append(w)
    return warnings


def main(*, stdin=None) -> int:
    try:
        hook_data = json.loads((stdin or sys.stdin).read())
    except (json.JSONDecodeError, ValueError):
        return 0

    run_dir = resolve_run_dir()
    if run_dir is None:
        return 0

    tool_name = hook_data.get("tool_name", "")
    budget = update_budget_locked(run_dir, run_dir.name, tool_name)
    for warning in check_budgets(budget, DEFAULT_LIMITS):
        print(f"⚠ {warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
