"""Per-run tool-call budget logic — a LIBRARY, not a hook.

Counts tool calls and subagent spawns per run and produces stderr
warnings when usage crosses 75% / 100% of the configured caps, plus a
wall-clock check. **Warning-only**: `check_budgets` returns strings and
nothing here blocks — see #631 for the blocking posture.

The sole consumer is `runtime/driver.py`'s `after_tool_execute` hook,
which passes the run dir from `AgentDeps`. This module used to double as
a `claude -p` PostToolUse hook script (stdin JSON in, exit code out);
that runtime and its `run-settings.json` wiring were retired, so the
entrypoint went with them — the logic is imported directly now.

Counters live in ``{run_dir}/budget.json``, incremented under an
exclusive ``flock`` so concurrent gather subagents don't race.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from defender.hooks._run_dir import update_json_locked

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
    def _mutate(budget: dict) -> None:
        # Backfill started_at if an older/partial budget.json lacks it, so the
        # wall-clock check never silently drops out for the rest of the run.
        budget.setdefault("started_at", datetime.now(UTC).isoformat())
        budget["tool_calls"] = budget.get("tool_calls", 0) + 1
        # "gather" is the in-process PydanticAI dispatch tool — the only spawn
        # there is. ("Task"/"Agent", the retired claude -p subagent dispatch,
        # counted here too; no tool by either name is registered any more.)
        if tool_name == "gather":
            budget["subagent_spawns"] = budget.get("subagent_spawns", 0) + 1

    return update_json_locked(
        run_dir / "budget.json", _mutate, default=lambda: make_budget_state(run_id)
    )


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
