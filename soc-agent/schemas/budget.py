"""Budget tracking schema and validation.

Defines the budget state (per-run counters) and default limits for
resource consumption. Used by hooks/scripts/budget_enforcer.py.
"""

from datetime import datetime, timezone


# Default limits — overridable via config/budget-defaults.yaml and
# per-signature in config/signatures/{id}/permissions.yaml.
DEFAULT_LIMITS = {
    "max_tool_calls": 150,
    "max_subagent_spawns": 10,
    "wall_clock_timeout": 600,  # seconds
}

# Fraction of each limit at which a warning is emitted.
WARNING_THRESHOLD = 0.75


def make_budget_state(run_id: str) -> dict:
    """Create an initial budget.json dict for a new run."""
    return {
        "run_id": run_id,
        "tool_calls": 0,
        "subagent_spawns": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
