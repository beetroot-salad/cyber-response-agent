#!/usr/bin/env python3
"""PreToolUse hook: enforce the defender invlang schema on investigation.md.

Fires on Write|Edit. Acts only when the target file is named
``investigation.md``; everything else passes through. Computes the
proposed post-write text, runs the structural validator
(`defender/skills/invlang/validate.py`), and BLOCKS the write (exit 2)
on any violation — the messages on stderr are fed back to the agent so
it can fix the block and retry.

The rules validate the *current* defender invlang spec
(`defender/skills/invlang/SKILL.md` + the parser/vocab in that package),
not soc-agent's. Pre-MVP, historical runs written against earlier
invlang variants are expected to fail — that is intentional, not a
regression. The validator passes the current spec's own worked examples
(guarded by tests) and blocks only genuine current-spec violations.

This is the defender analogue of soc-agent's `invlang_validate.py` hook,
adapted to the defender run-dir convention: the run dir is simply the
parent of the investigation.md path (one `claude -p` per run, so there
is no session→run map to consult).

Exit codes:
    0 — passed (or unrelated write).
    2 — validation failed; stderr is fed back to the agent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# defender/hooks/<this>.py → parents[2] is the repo root, so the
# `defender.skills.invlang` package imports resolve.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender.skills.invlang.validate import validate_companion  # noqa: E402


def resolve_proposed_text(hook_data: dict) -> str | None:
    """Return the proposed investigation.md text, or None if unrelated.

    For Write: the full ``content``.
    For Edit:  the current file with ``old_string → new_string`` applied
               (honoring ``replace_all``).
    """
    tool_name = hook_data.get("tool_name", "")
    tool_input = hook_data.get("tool_input") or {}
    file_path = tool_input.get("file_path", "")
    if not isinstance(file_path, str) or Path(file_path).name != "investigation.md":
        return None

    if tool_name == "Write":
        content = tool_input.get("content", "")
        return content if isinstance(content, str) else ""

    if tool_name == "Edit":
        inv_path = Path(file_path)
        if not inv_path.exists():
            return None
        try:
            current = inv_path.read_text()
        except OSError:
            return None
        old = tool_input.get("old_string", "")
        new = tool_input.get("new_string", "")
        if not isinstance(old, str) or not isinstance(new, str):
            return None
        if tool_input.get("replace_all"):
            return current.replace(old, new)
        return current.replace(old, new, 1)

    return None


def main() -> int:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return 0

    if hook_data.get("tool_name") not in ("Write", "Edit"):
        return 0

    proposed = resolve_proposed_text(hook_data)
    if proposed is None:
        return 0

    file_path = (hook_data.get("tool_input") or {}).get("file_path", "")
    inv_path = Path(file_path)
    current_text: str | None = None
    if inv_path.exists():
        try:
            current_text = inv_path.read_text()
        except OSError:
            current_text = None

    errors = validate_companion(proposed, current_text)
    if not errors:
        return 0

    print("invlang validation failed:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    print(
        "Next action: fix the ```invlang block(s) and retry the write.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
