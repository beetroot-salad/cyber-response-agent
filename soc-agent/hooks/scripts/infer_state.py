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
from hooks.scripts.run_context import extract_run_dir, get_runs_dir, write_session_mapping
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

    Returns a list like ["CONTEXTUALIZE", "PREDICT", "GATHER", "ANALYZE"].
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


def validate_phase_sequence(
    observed_phases: list[str],
    history: list[str],
    current_phase: str | None,
) -> tuple[list[str], list[str], str | None]:
    """Validate new phase transitions without writing state.

    Compares observed_phases against the known history. Calls sys.exit(2) on
    the first violation. On success returns (new_phases, updated_history,
    updated_phase) — new_phases is empty if there were no new headers.

    Importable by infer_state_pre.py so the validation logic stays in one place.
    """
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

    if len(observed_phases) == len(history):
        return [], history, current_phase

    new_phases = observed_phases[len(history):]

    for new_phase in new_phases:
        valid, error = validate_transition(current_phase, new_phase)
        if not valid:
            print(f"Illegal state transition: {error}", file=sys.stderr)
            sys.exit(2)

        tentative_history = history + [new_phase]
        loops = count_loops(tentative_history)
        if loops > MAX_LOOPS:
            print(
                f"Maximum investigation loops ({MAX_LOOPS}) exceeded. "
                f"Must transition to CONCLUDE.",
                file=sys.stderr,
            )
            sys.exit(2)

        history = tentative_history
        current_phase = new_phase

    return new_phases, history, current_phase


def infer_transitions(run_dir: Path, observed_phases: list[str]) -> None:
    """Validate and apply new transitions inferred from investigation.md headers.

    Delegates validation to validate_phase_sequence (which exits on error),
    then writes state.json and prints feedback on success.
    """
    state = load_or_bootstrap_state(run_dir)
    history = state.get("history", [])
    current_phase = state.get("phase")

    new_phases, history, current_phase = validate_phase_sequence(
        observed_phases, history, current_phase
    )

    if not new_phases:
        # No new phases — edit didn't add a section header. Nothing to do.
        return

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

    # Belt-and-suspenders: write session→run mapping on the first
    # investigation.md write if setup_run.py didn't already do it
    # (i.e. CLAUDE_SESSION_ID wasn't available at !command time).
    session_id = hook_data.get("session_id", "")
    if run_dir is not None and session_id:
        signature_id = ""
        meta_path = run_dir / "meta.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                signature_id = meta.get("signature_id", "")
            except Exception:
                pass
        write_session_mapping(session_id, run_dir, signature_id, get_runs_dir())

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
