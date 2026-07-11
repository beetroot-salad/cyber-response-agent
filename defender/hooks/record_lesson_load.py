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

Scoped to the three lesson corpora — ``defender/lessons/`` plus the author corpora
``lessons-actor/`` and ``lessons-environment/`` (#559 F3 widened the matcher from
``lessons/`` only, so a curator's ``lesson_read`` records an actor/env lesson load
symmetrically with a findings one). The widening is opt-IN per caller: the in-process
runtime readers narrow it back to ``RUNTIME_LESSON_CORPORA`` (see ``lesson_name``).
Always exits 0 (best-effort).
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
from defender._io import append_jsonl
from defender.hooks._run_dir import resolve_run_dir


# Every corpus a lesson can live in. The hook (a Claude Code ``Read``) and the curators'
# ``lesson_read`` match against this full set (#559 F3).
LESSON_CORPORA = frozenset({"lessons", "lessons-actor", "lessons-environment"})

# The corpus a RUNTIME reader loads: the defender's own. The author corpora are NOT defender
# lessons, and a runtime reader's ``run_dir`` is its durable per-case bundle — the same dir
# ``trace_lesson`` scans for "lessons this DEFENDER run had in context". The gray-box actor
# reads ``lessons-actor/`` tradecraft through ``read_file`` on every run (its ``read_confine``
# names it, and it carries no ``read_shapes``), so matching the author corpora there would
# append attacker-corpus rows straight into that trace. The widening is the CURATOR's, so it
# is the curator's tool that opts into ``LESSON_CORPORA`` — not every reader by default.
RUNTIME_LESSON_CORPORA = frozenset({"lessons"})


def lesson_name(file_path: str, corpora: frozenset[str] = LESSON_CORPORA) -> str | None:
    """The lesson slug if ``file_path`` is a ``defender/<corpus>/<name>.md`` file for one of
    ``corpora``, else None. ``corpora`` defaults to all three lesson corpora — the hook's scope,
    widened from ``lessons/`` only by #559 F3 so a curator's ``lesson_read`` of an actor/env
    lesson records symmetrically with a findings one. The in-process runtime readers pass
    ``RUNTIME_LESSON_CORPORA`` instead, keeping the author corpora out of their case trace.

    A nested subdir (parent isn't a corpus), a non-``.md`` file, or a ``_``-prefixed file
    (``_TEMPLATE.md`` — the schema a curator reads, not a lesson) does not match; the ``_`` skip
    matches the corpus convention ``build_corpus_manifest`` / ``existing_observation_ids``
    already follow."""
    p = Path(file_path)
    if (
        p.suffix == ".md"
        and not p.name.startswith("_")
        and p.parent.name in corpora
        and p.parent.parent.name == "defender"
    ):
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
        append_jsonl(run_dir / "lessons_loaded.jsonl", [row])
    except Exception:  # noqa: BLE001 — best-effort; the contract is to always exit 0
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
