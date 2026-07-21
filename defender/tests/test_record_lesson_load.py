"""Tests for defender/hooks/record_lesson_load.py.

``lesson_name`` maps a ``defender/<corpus>/<name>.md`` path to its lesson slug, over
the three corpora (defender/{lessons,lessons-actor,lessons-environment}/ — widened by
#559 F3 from lessons/ only), with ``RUNTIME_LESSON_CORPORA`` narrowing a runtime
reader back to the defender's own.

Driven through ``lesson_name`` — the function the live callers reach
(``runtime/tools.py``'s ``lesson_read`` tool; ``learning/author/lesson_read.py``).
These used to run through the module's `claude -p` PostToolUse ``main()``, which
watched every ``Read`` and appended the ``lessons_loaded.jsonl`` row itself. Nothing
invokes it; the ``lesson_read`` tool owns the append now, and
``tests/test_lesson_read_tool.py`` pins it there end-to-end — including the row shape
and the three-corpora case (its demand L12).
"""
from __future__ import annotations

from defender.hooks.record_lesson_load import (
    LESSON_CORPORA,
    RUNTIME_LESSON_CORPORA,
    lesson_name,
)


def test_names_a_runtime_lesson():
    assert lesson_name("/repo/defender/lessons/foo.md") == "foo"


def test_names_all_three_lesson_corpora():
    """#559 F3 widened the matcher from lessons/ only to all three lesson corpora: a
    findings, actor, OR env lesson names (the curators' lesson_read reuses this matcher;
    the runtime read_file does too — the accepted cross-role blast radius)."""
    assert lesson_name("/repo/defender/lessons/a.md") == "a"
    assert lesson_name("/repo/defender/lessons-actor/x.md") == "x"
    assert lesson_name("/repo/defender/lessons-environment/y.md") == "y"
    assert sorted(LESSON_CORPORA) == ["lessons", "lessons-actor", "lessons-environment"]


def test_ignores_template_schema():
    """``_TEMPLATE.md`` is the corpus SCHEMA (the shape a curator reads before authoring), not a
    lesson — naming it would put a `_TEMPLATE` slug in the trace that no corpus can resolve."""
    for corpus in ("lessons", "lessons-actor", "lessons-environment"):
        assert lesson_name(f"/repo/defender/{corpus}/_TEMPLATE.md") is None


def test_runtime_corpora_narrows_to_the_defender_lessons():
    """The in-process runtime readers pass ``RUNTIME_LESSON_CORPORA``, keeping the AUTHOR corpora
    out of their case trace — the actor reads lessons-actor/ tradecraft via read_file every run and
    its run_dir IS the durable bundle trace_lesson scans. Only the curators' ``lesson_read`` opts
    into the full ``LESSON_CORPORA``."""
    assert lesson_name("/repo/defender/lessons/a.md", RUNTIME_LESSON_CORPORA) == "a"
    assert lesson_name("/repo/defender/lessons-actor/x.md", RUNTIME_LESSON_CORPORA) is None
    assert lesson_name("/repo/defender/lessons-environment/y.md", RUNTIME_LESSON_CORPORA) is None


def test_ignores_nested_and_non_md():
    assert lesson_name("/repo/defender/lessons/sub/z.md") is None
    assert lesson_name("/repo/defender/lessons/readme.txt") is None


def test_ignores_a_corpus_dir_not_under_defender():
    """The grandparent must be ``defender/`` — a ``lessons/`` dir anywhere else in a
    checkout (or in a staged learning tree) is not the corpus."""
    assert lesson_name("/repo/elsewhere/lessons/foo.md") is None
