"""Investigation state machine schema and validation.

Defines the legal phases and transitions for an investigation run.
Used by hooks/scripts/infer_state.py to enforce state machine integrity.
"""

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Phase(str, Enum):
    CONTEXTUALIZE = "CONTEXTUALIZE"
    SCREEN = "SCREEN"
    HYPOTHESIZE = "HYPOTHESIZE"
    GATHER = "GATHER"
    ANALYZE = "ANALYZE"
    CONCLUDE = "CONCLUDE"


# Legal transitions: from_phase -> set of allowed to_phases.
#
# HYPOTHESIZE is on-demand (invlang v2.7): the agent enters it when the lead
# space branches, not as a fixed phase gate. This means:
#   - CONTEXTUALIZE may go directly to GATHER for pure-gathering first leads
#     (the no-branching / interpretation-vulnerable cell of the ASSESS matrix).
#   - GATHER may go directly to HYPOTHESIZE when the agent realises mid-lead
#     that a new fork has opened and wants to articulate it before ANALYZE.
#   - ANALYZE → HYPOTHESIZE remains the canonical loop re-entry.
TRANSITIONS: dict[Phase, set[Phase]] = {
    Phase.CONTEXTUALIZE: {Phase.SCREEN, Phase.HYPOTHESIZE, Phase.GATHER, Phase.CONCLUDE},
    Phase.SCREEN: {Phase.HYPOTHESIZE, Phase.CONCLUDE},       # resolve or fall through
    Phase.HYPOTHESIZE: {Phase.GATHER},
    Phase.GATHER: {Phase.ANALYZE, Phase.HYPOTHESIZE},
    Phase.ANALYZE: {Phase.HYPOTHESIZE, Phase.CONCLUDE},
    Phase.CONCLUDE: set(),  # Terminal
}

# CONTEXTUALIZE is the only valid initial phase
INITIAL_PHASE = Phase.CONTEXTUALIZE

# Maximum number of investigation cycles before forced conclusion. A cycle is
# any entry into HYPOTHESIZE or ANALYZE — both bound investigation depth, and
# with on-demand HYPOTHESIZE (invlang v2.7) a run can accumulate many
# GATHER→ANALYZE cycles without re-entering HYPOTHESIZE. Counting ANALYZE too
# restores the guardrail: a runaway agent that keeps gathering without ever
# re-hypothesizing still trips the cap. Bumped from 7 to 12 to compensate for
# the broader counting rule — most investigations still resolve in 2-3 cycles.
MAX_LOOPS = 12


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
    """Count investigation cycles in the history.

    A cycle is any entry into HYPOTHESIZE or ANALYZE. With on-demand
    HYPOTHESIZE (invlang v2.7), counting only HYPOTHESIZE would let a runaway
    agent accumulate unbounded GATHER→ANALYZE cycles. Counting ANALYZE closes
    that loophole — every completed gather/analyze cycle contributes one,
    every hypothesis re-entry contributes one, and MAX_LOOPS bounds the sum.
    """
    return sum(1 for p in history if p in {Phase.HYPOTHESIZE.value, Phase.ANALYZE.value})


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
