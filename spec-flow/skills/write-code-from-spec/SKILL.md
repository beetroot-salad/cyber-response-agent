---
name: write-code-from-spec
description: "Compatibility entry for existing write-code-from-spec invocations. Delegates tests-first implementation to write-code-from-tests; accepts historical tests-plus-graph handoffs. Prefer write-code-from-tests for new work."
argument-hint: "[issue # or design doc path]"
effort: medium
---

# Write code from spec — compatibility entry

Use the sibling [write-code-from-tests](../write-code-from-tests/SKILL.md) and its references as the complete workflow. Preserve the existing contract ref, original base, design decisions and optional graph. Historical handoffs are accepted; do not rebuild a graph or reauthor tests just to rename the stage. On resume, distinguish the immutable contract ref from implementation HEAD and apply the new workflow's current-input and repair checks.
