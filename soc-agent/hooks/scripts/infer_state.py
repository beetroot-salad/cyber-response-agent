#!/usr/bin/env python3
"""PostToolUse hook: Infer state transitions from investigation.md headers.

Fires on Write/Edit tool calls. Checks if the written file is an
investigation.md inside a run directory. If so, extracts ## PHASE section
headers, validates each new transition against the state machine, and
updates state.json automatically.

This replaces the agent's explicit write_state.py Bash calls — the agent
just writes its investigation log naturally and the state machine enforces
itself. This is a cooperative guardrail, not a security boundary; OS-level
protection (permissions, inotify) is the hard boundary for adversarial cases.

Exit codes:
    0 - Passed (valid transitions, or not an investigation.md write)
    2 - Illegal transition (message fed back to agent, blocks the write)
"""

import json
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.investigation_parse import iter_phase_headers
from hooks.scripts.run_context import extract_run_dir
from schemas.state import (
    MAX_LOOPS,
    count_loops,
    make_state,
    validate_transition,
)


# ---------------------------------------------------------------------------
# Phase extraction
# ---------------------------------------------------------------------------

def extract_phases(file_path: Path) -> list[str]:
    """Extract ordered phase names from ## headers in investigation.md.

    Returns a list like ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE"].
    Ignores suffixes like (loop N) — only the phase name matters.
    """
    if not file_path.exists():
        return []
    return list(iter_phase_headers(file_path.read_text()))


# ---------------------------------------------------------------------------
# State inference
# ---------------------------------------------------------------------------

def load_or_bootstrap_state(run_dir: Path) -> dict:
    """Load state.json, or bootstrap from meta.json if state doesn't exist yet.

    Returns a state dict with at minimum: run_id, signature_id, phase (None ok),
    history (empty list ok).
    """
    state_path = run_dir / "state.json"
    if state_path.exists():
        return json.loads(state_path.read_text())

    # Bootstrap: read metadata from meta.json (created by setup_run.py)
    meta_path = run_dir / "meta.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        run_id = meta.get("run_id", run_dir.name)
        signature_id = meta.get("signature_id", "")
    else:
        run_id = run_dir.name
        signature_id = ""

    return {
        "run_id": run_id,
        "ticket_id": "",
        "signature_id": signature_id,
        "phase": None,
        "history": [],
    }


def infer_transitions(run_dir: Path, observed_phases: list[str]) -> None:
    """Validate and apply new transitions inferred from investigation.md headers.

    Compares observed_phases against the current state.json history. For each
    new phase, validates the transition and updates state. Raises SystemExit(2)
    on the first illegal transition.
    """
    state = load_or_bootstrap_state(run_dir)
    history = state.get("history", [])
    current_phase = state.get("phase")

    # Verify that existing history matches the prefix of observed phases.
    # If they diverge, the agent rewrote or reordered sections — that's an error.
    # Also catches the case where phases were removed (observed shorter than history).
    if len(observed_phases) < len(history):
        print(
            f"Phase sections were removed from investigation.md: "
            f"expected at least {len(history)} phase headers, found {len(observed_phases)}. "
            f"Do not remove phase sections.",
            file=sys.stderr,
        )
        sys.exit(2)

    for i, (hist, obs) in enumerate(zip(history, observed_phases)):
        if hist != obs:
            print(
                f"Phase history mismatch at position {i}: "
                f"state.json has '{hist}' but investigation.md has '{obs}'. "
                f"Do not reorder or remove phase sections.",
                file=sys.stderr,
            )
            sys.exit(2)

    # Find new phases: the tail of observed_phases beyond what's in history.
    if len(observed_phases) == len(history):
        # No new phases — edit didn't add a section header. Nothing to do.
        return

    new_phases = observed_phases[len(history):]

    # Validate each new transition in sequence
    for new_phase in new_phases:
        valid, error = validate_transition(current_phase, new_phase)
        if not valid:
            print(f"Illegal state transition: {error}", file=sys.stderr)
            sys.exit(2)

        # Check loop count before allowing HYPOTHESIZE
        tentative_history = history + [new_phase]
        loops = count_loops(tentative_history)
        if loops > MAX_LOOPS:
            print(
                f"Maximum investigation loops ({MAX_LOOPS}) exceeded. "
                f"Must transition to CONCLUDE.",
                file=sys.stderr,
            )
            sys.exit(2)

        # Transition accepted — advance
        history = tentative_history
        current_phase = new_phase

    # Write updated state
    state_dict = make_state(
        phase=current_phase,
        run_id=state.get("run_id", run_dir.name),
        ticket_id=state.get("ticket_id", ""),
        signature_id=state.get("signature_id", ""),
        history=history,
    )

    state_path = run_dir / "state.json"
    with open(state_path, "w") as f:
        json.dump(state_dict, f, indent=2)

    # Feedback to agent
    loops = count_loops(history)
    if len(new_phases) == 1:
        prev = new_phases[0]
        # Show the transition that just happened
        from_label = history[-2] if len(history) >= 2 else "(init)"
        print(f"State: {from_label} -> {current_phase} (loop {loops}/{MAX_LOOPS})")
    else:
        # Multiple transitions in one write (rare)
        print(
            f"State: {' -> '.join(new_phases)} (loop {loops}/{MAX_LOOPS})"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    run_dir = extract_run_dir(hook_data)
    if run_dir is None:
        sys.exit(0)

    file_path = run_dir / "investigation.md"
    observed_phases = extract_phases(file_path)
    if not observed_phases:
        sys.exit(0)

    infer_transitions(run_dir, observed_phases)
    sys.exit(0)


if __name__ == "__main__":
    main()
