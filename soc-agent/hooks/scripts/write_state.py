#!/usr/bin/env python3
"""Write and validate investigation state transitions.

Called by the agent via bash to advance the investigation state machine.

Usage:
    python3 hooks/scripts/write_state.py <run_dir> <new_phase> [ticket_id] [signature_id]

Exit codes:
    0 - Transition successful, state.json written
    1 - Illegal transition (agent sees error and must adjust)
"""

import json
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import (
    MAX_LOOPS,
    count_loops,
    make_state,
    validate_transition,
)


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: python3 hooks/scripts/write_state.py <run_dir> <new_phase> [ticket_id] [signature_id]",
            file=sys.stderr,
        )
        sys.exit(1)

    run_dir = Path(sys.argv[1])
    new_phase = sys.argv[2]
    ticket_id = sys.argv[3] if len(sys.argv) > 3 else ""
    signature_id = sys.argv[4] if len(sys.argv) > 4 else ""

    state_file = run_dir / "state.json"

    # Load existing state or start fresh
    current_phase = None
    history = []
    run_id = run_dir.name

    if state_file.exists():
        with open(state_file) as f:
            existing = json.load(f)
        current_phase = existing.get("phase")
        history = existing.get("history", [])
        run_id = existing.get("run_id", run_dir.name)
        if not ticket_id:
            ticket_id = existing.get("ticket_id", "")
        if not signature_id:
            signature_id = existing.get("signature_id", "")

    # Validate transition
    valid, error = validate_transition(current_phase, new_phase)
    if not valid:
        print(f"Illegal state transition: {error}", file=sys.stderr)
        sys.exit(1)

    # Check loop count
    new_history = history + [new_phase]
    loops = count_loops(new_history)
    if loops > MAX_LOOPS:
        print(
            f"Maximum investigation loops ({MAX_LOOPS}) exceeded. "
            f"Must transition to CONCLUDE.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Write state
    run_dir.mkdir(parents=True, exist_ok=True)
    state = make_state(
        phase=new_phase,
        run_id=run_id,
        ticket_id=ticket_id,
        signature_id=signature_id,
        history=new_history,
    )

    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)

    print(f"State: {current_phase or '(init)'} -> {new_phase}")
    sys.exit(0)


if __name__ == "__main__":
    main()
