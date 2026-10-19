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
