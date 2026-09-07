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
    lesson_name,
)


def test_names_a_runtime_lesson():
    assert lesson_name("/repo/defender/lessons/foo.md") == "foo"








def test_ignores_nested_and_non_md():
    assert lesson_name("/repo/defender/lessons/sub/z.md") is None
    assert lesson_name("/repo/defender/lessons/readme.txt") is None


def test_ignores_a_corpus_dir_not_under_defender():
    """The grandparent must be ``defender/`` — a ``lessons/`` dir anywhere else in a
    checkout (or in a staged learning tree) is not the corpus."""
    assert lesson_name("/repo/elsewhere/lessons/foo.md") is None
