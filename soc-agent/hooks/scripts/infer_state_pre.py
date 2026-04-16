#!/usr/bin/env python3
"""PreToolUse hook: Validate state transitions before investigation.md is written.

Fires on Write/Edit tool calls targeting investigation.md. Simulates the
post-edit file content and validates the resulting phase sequence against the
state machine. Exits 2 to block the write if a transition would be illegal —
the file is never modified.

This is the blocking companion to infer_state.py (PostToolUse), which writes
state.json after a successful write. Together they form a two-leg guardrail:
Pre blocks bad writes before they land; Post records valid transitions after.

Exit codes:
    0 - Passed (valid transitions, or not an investigation.md write)
    2 - Illegal transition (blocks the write; message fed back to agent)
"""

import json
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.infer_state import load_or_bootstrap_state, validate_phase_sequence
from hooks.scripts.investigation_parse import iter_phase_headers
from hooks.scripts.run_context import extract_run_dir_from_path


# ---------------------------------------------------------------------------
# Edit simulation
# ---------------------------------------------------------------------------

def simulate_content(hook_data: dict) -> str | None:
    """Return the file content that would result from applying this tool call.

    Returns None if the simulation cannot be performed (e.g. old_string not
    found in an Edit — the Edit itself would fail, so we let it pass through).
    """
    tool_name = hook_data.get("tool_name", "")
    tool_input = hook_data.get("tool_input", {})

    if tool_name == "Write":
        return tool_input.get("content", "")

    if tool_name == "Edit":
        file_path = Path(tool_input.get("file_path", ""))
        if not file_path.exists():
            return None  # Edit on non-existent file will fail naturally

        current = file_path.read_text()
        old_string = tool_input.get("old_string", "")
        new_string = tool_input.get("new_string", "")
        replace_all = tool_input.get("replace_all", False)

        if old_string not in current:
            return None  # old_string absent — Edit will fail naturally

        if replace_all:
            return current.replace(old_string, new_string)
        return current.replace(old_string, new_string, 1)

    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_input = hook_data.get("tool_input", {})
    run_dir = extract_run_dir_from_path(tool_input.get("file_path"))
    if run_dir is None:
        sys.exit(0)

    content = simulate_content(hook_data)
    if content is None:
        sys.exit(0)

    observed_phases = list(iter_phase_headers(content))
    if not observed_phases:
        sys.exit(0)

    state = load_or_bootstrap_state(run_dir)
    validate_phase_sequence(
        observed_phases,
        state.get("history", []),
        state.get("phase"),
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
