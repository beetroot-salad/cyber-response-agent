"""Lesson-corpus naming — a LIBRARY, not a hook.

``lesson_name`` maps a ``defender/<corpus>/<name>.md`` path to its lesson slug. The
runtime's ``lesson_read`` tool uses it to record which lessons a run loaded into
context, into ``{run_dir}/lessons_loaded.jsonl`` — feeding the post-merge "which
cases had this lesson in context, and what did they conclude" traceability surface
(``defender/learning/ops/trace_lesson.py``).

**Signal caveat:** a read cannot tell a frontmatter-triage read from an influence
read, and agents often read whole files — so this records lessons loaded **into
context**, not lessons that demonstrably *influenced* the disposition. The trace
surface is post-merge visibility, not a strict causal claim.

Scoped to the three lesson corpora — ``defender/lessons/`` plus the author corpora
``lessons-actor/`` and ``lessons-environment/`` (#559 F3 widened the matcher from
``lessons/`` only, so a curator's ``lesson_read`` records an actor/env lesson load
symmetrically with a findings one). The widening is opt-IN per caller: the in-process
runtime readers narrow it back to ``RUNTIME_LESSON_CORPORA`` (see ``lesson_name``).

The live consumers are ``runtime/tools.py`` (``RUNTIME_LESSON_CORPORA`` +
``lesson_name``) and ``learning/author/lesson_read.py`` (``LESSON_CORPORA``). This
module used to double as a `claude -p` PostToolUse hook script that watched every
``Read`` and appended the row itself (stdin JSON in, exit code out); that runtime and
its ``run-settings.json`` wiring were retired, so the entrypoint went with them —
and with it this module's only reason to reach ``resolve_run_dir``, ``now_iso`` and
``append_jsonl``. The ``lesson_read`` tool writes the row now; what is left here is
the naming rule it asks about.
"""
from __future__ import annotations

from pathlib import Path

# Every corpus a lesson can live in. The retired hook (a Claude Code ``Read``) and the
# curators' ``lesson_read`` match against this full set (#559 F3).
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


