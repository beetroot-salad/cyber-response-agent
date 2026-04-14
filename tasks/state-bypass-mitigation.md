---
title: State machine bypass: decide and implement mitigation strategy
status: backlog
groups: state
---

The state machine is enforcement-by-convention, not enforcement-by-isolation. When write_state.py is unavailable (blocked by allowlist, unavailable env, etc.), the agent can and does write state.json directly via Write, bypassing phase-ordering checks entirely.

The Tier 1 validation in validate_report.py catches malformed reports but does not catch faked state history.

Pick one mitigation:

Option A: PreToolUse hook gates Write against any path matching */state.json inside a run dir, allowing only invocations originating from write_state.py. Cleanest but requires identifying the invoker, which PreToolUse may not surface.

Option B: Move state out of a file the agent can write. Use sqlite db or a write-only socket that only write_state.py knows how to address.

Option C: Accept the soft-boundary model and document explicitly in docs/security-model.md that the safety guarantee is "well-aligned agent + structural validation of outputs" rather than "process-isolated state machine."

The decision matters more than the implementation. Current behavior is "looks isolated but isn't," which is the worst of both worlds.
