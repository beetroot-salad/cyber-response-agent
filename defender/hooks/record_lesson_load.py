#!/usr/bin/env python3
"""PostToolUse hook: record which runtime lessons a run loaded into context.

At PLAN the agent enumerates ``defender/lessons/*.md`` and Reads the bodies it
deems relevant (defender/SKILL.md §PLAN). This hook captures each such Read into
``{run_dir}/lessons_loaded.jsonl``, feeding the post-merge "which cases had this
lesson in context, and what did they conclude" traceability surface
(``defender/learning/trace_lesson.py``).

**Signal caveat:** a PostToolUse-on-Read cannot tell a frontmatter-triage Read from
an influence Read, and agents often Read whole files — so this records lessons loaded
**into context**, not lessons that demonstrably *influenced* the disposition. The
trace surface is post-merge visibility, not a strict causal claim.

Scoped to ``defender/lessons/`` only — ``lessons-actor/`` and ``lessons-environment/``
are author corpora the runtime agent never loads. Always exits 0 (best-effort).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Sibling-import the shared run-dir helper. defender/hooks/<this>.py → parents[2]
# is the repo root, so `defender.hooks.*` resolves whether imported or run as a script.
if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)
from defender._clock import now_iso
from defender.hooks._run_dir import resolve_run_dir


def lesson_name(file_path: str) -> str | None:
    """The lesson slug if ``file_path`` is a ``defender/lessons/<name>.md`` file,
    else None. Matches the runtime corpus exactly — a sibling ``lessons-actor/`` /
    ``lessons-environment/`` (parent name differs) or a nested subdir (parent isn't
    ``lessons``) does not match."""
    p = Path(file_path)
    if p.suffix == ".md" and p.parent.name == "lessons" and p.parent.parent.name == "defender":
        return p.stem
    return None


def main(*, stdin=None) -> int:
    try:
        hook_data = json.loads((stdin or sys.stdin).read())
    except (json.JSONDecodeError, ValueError):
        return 0
    if not isinstance(hook_data, dict) or hook_data.get("tool_name") != "Read":
        return 0
    try:
        # Cheap string filter before resolve_run_dir's stat — most Reads aren't lessons.
        tool_input = hook_data.get("tool_input")
        file_path = tool_input.get("file_path", "") if isinstance(tool_input, dict) else ""
        name = lesson_name(str(file_path))
        if name is None:
            return 0
        run_dir = resolve_run_dir()
        if run_dir is None:
            return 0
        row = {"lesson_name": name, "ts": now_iso()}
        with (run_dir / "lessons_loaded.jsonl").open("a") as fh:
            fh.write(json.dumps(row) + "\n")
    except Exception:  # noqa: BLE001 — best-effort; the contract is to always exit 0
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
