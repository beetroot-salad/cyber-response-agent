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
import os
import sys
from pathlib import Path

# defender/hooks/<this>.py → parents[2] is the repo root, so the
# `defender.skills.invlang` package imports resolve.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender.skills.invlang.validate import validate_companion  # noqa: E402


def _is_target_investigation(file_path: str) -> bool:
    """True only for the run's canonical ``investigation.md``.

    Basename must match, and — when ``DEFENDER_RUN_DIR`` is set (the
    production anchor) — the path must resolve inside it, so a stray
    ``investigation.md`` elsewhere on disk is neither validated nor
    blocked. With no run anchor (tests) the basename alone scopes.
    """
    if not isinstance(file_path, str) or Path(file_path).name != "investigation.md":
        return False
    run_raw = os.environ.get("DEFENDER_RUN_DIR")
    if not run_raw:
        return True
    try:
        run_dir = Path(run_raw).resolve()
        target = Path(file_path).resolve()
    except OSError:
        return True
    return target.parent == run_dir or run_dir in target.parents


def _read_current(file_path: str) -> str | None:
    p = Path(file_path)
    if not p.exists():
        return None
    try:
        return p.read_text()
    except OSError:
        return None


def resolve_proposed_text(hook_data: dict, current_text: str | None) -> str | None:
    """Return the proposed investigation.md text, or None if unrelated.

    For Write: the full ``content``.
    For Edit:  ``current_text`` with ``old_string → new_string`` applied
               (honoring ``replace_all``). ``current_text`` is read once by
               the caller and threaded through, so the file isn't re-read.
    """
    tool_name = hook_data.get("tool_name", "")
    tool_input = hook_data.get("tool_input") or {}

    if tool_name == "Write":
        content = tool_input.get("content", "")
        return content if isinstance(content, str) else ""

    if tool_name == "Edit":
        if current_text is None:
            return None
        old = tool_input.get("old_string", "")
        new = tool_input.get("new_string", "")
        if not isinstance(old, str) or not isinstance(new, str):
            return None
        if tool_input.get("replace_all"):
            return current_text.replace(old, new)
        return current_text.replace(old, new, 1)

    return None


def main() -> int:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError):
        return 0

    if hook_data.get("tool_name") not in ("Write", "Edit"):
        return 0

    file_path = (hook_data.get("tool_input") or {}).get("file_path", "")
    if not _is_target_investigation(file_path):
        return 0

    current_text = _read_current(file_path)
    proposed = resolve_proposed_text(hook_data, current_text)
    if proposed is None:
        return 0

    try:
        errors = validate_companion(proposed, current_text)
    except Exception as exc:  # noqa: BLE001 — a blocking gate must fail CLOSED
        # An internal validator error must not silently let the write through
        # (exit ≠ 2 is non-blocking). Block and surface the failure instead.
        print("invlang validation errored — failing closed:", file=sys.stderr)
        print(f"  - {type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            "Next action: simplify the ```invlang block(s) and retry, or escalate.",
            file=sys.stderr,
        )
        return 2

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
