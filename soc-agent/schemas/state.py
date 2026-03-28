"""Investigation state machine schema and validation.

Defines the legal phases and transitions for an investigation run.
Used by hooks/scripts/write_state.py to enforce state machine integrity.
"""

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Phase(str, Enum):
    CONTEXTUALIZE = "CONTEXTUALIZE"
    HYPOTHESIZE = "HYPOTHESIZE"
    GATHER = "GATHER"
    ANALYZE = "ANALYZE"
    CONCLUDE = "CONCLUDE"


# Legal transitions: from_phase -> set of allowed to_phases
TRANSITIONS: dict[Phase, set[Phase]] = {
    Phase.CONTEXTUALIZE: {Phase.HYPOTHESIZE},
    Phase.HYPOTHESIZE: {Phase.GATHER},
    Phase.GATHER: {Phase.ANALYZE},
    Phase.ANALYZE: {Phase.HYPOTHESIZE, Phase.CONCLUDE},
    Phase.CONCLUDE: set(),  # Terminal
}

# CONTEXTUALIZE is the only valid initial phase
INITIAL_PHASE = Phase.CONTEXTUALIZE

# Maximum number of hypothesis-gather-analyze loops before forced conclusion.
# 7 loops is generous — most investigations resolve in 2-3. If you're past 5
# without convergence, the hypothesis space is likely incomplete.
MAX_LOOPS = 7


def validate_transition(current: Optional[str], proposed: str) -> tuple[bool, str]:
    """Validate a state transition.

    Args:
        current: Current phase name (None if first transition)
        proposed: Proposed next phase name

    Returns:
        (is_valid, error_message). error_message is empty if valid.
    """
    try:
        proposed_phase = Phase(proposed)
    except ValueError:
        return False, f"unknown phase '{proposed}'. Valid phases: {[p.value for p in Phase]}"

    if current is None:
        if proposed_phase != INITIAL_PHASE:
            return False, f"initial phase must be {INITIAL_PHASE.value}, got '{proposed}'"
        return True, ""

    try:
        current_phase = Phase(current)
    except ValueError:
        return False, f"unknown current phase '{current}'"

    allowed = TRANSITIONS.get(current_phase, set())
    if proposed_phase not in allowed:
        allowed_names = [p.value for p in allowed] if allowed else ["(none - terminal state)"]
        return False, (
            f"illegal transition {current_phase.value} -> {proposed_phase.value}. "
            f"Allowed from {current_phase.value}: {allowed_names}"
        )

    return True, ""


def count_loops(history: list[str]) -> int:
    """Count the number of HYPOTHESIZE phases in the history (proxy for loop count)."""
    return sum(1 for p in history if p == Phase.HYPOTHESIZE.value)


def make_state(
    phase: str,
    run_id: str,
    ticket_id: str = "",
    signature_id: str = "",
    history: Optional[list[str]] = None,
) -> dict:
    """Create a state.json dict."""
    return {
        "run_id": run_id,
        "ticket_id": ticket_id,
        "signature_id": signature_id,
        "phase": phase,
        "history": history or [],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
