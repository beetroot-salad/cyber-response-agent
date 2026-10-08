"""Tests for the lint_lesson_text gate: raw lesson text is read only where a line says why."""
from __future__ import annotations

import ast

import pytest

from defender.tests._by_path import load_lint_gate

_GATE = load_lint_gate("lint_lesson_text")


def _flagged(src: str) -> list[str]:
    return [n.attr for n in _GATE.raw_reads(ast.parse(src))]


@pytest.mark.parametrize(("src", "want"), [
    ("x = lesson.fm.get('description')", ["fm"]),
    ("x = hit.fm", ["fm"]),
    ("x = lesson.raw", ["raw"]),
    ("x = lessons[0].body", []),
    ("x = self.lesson.body", ["body"]),
    ("x = report.body + doc.raw", []),
    ("lesson.fm = {}", []),
    ("x = hit.frontmatter", ["frontmatter"]),
    ("x = report.frontmatter", []),
])
def test_raw_reads_are_fm_anywhere_and_raw_or_body_on_a_lesson(src, want):
    assert _flagged(src) == want


def test_the_shipped_tree_is_clean_and_the_loader_is_exempt():
    """Positive control for the scan: today's tree has raw reads, every one annotated."""
    assert _GATE.OWNER == "defender/_corpus.py"
    frontier = _GATE.DEFENDER / "runtime" / "lessons_engine" / "lessons_frontier.py"
    reads = _GATE.raw_reads(ast.parse(frontier.read_text(encoding="utf-8")))
    assert [n.attr for n in reads] == ["fm", "frontmatter"], "control: the scan sees the annotated reads"
    assert _GATE._scan() == []


@pytest.mark.parametrize(("src", "flagged"), [
    ("x = lesson.fm  # lint-lesson-text: ok — compared, never printed\n", False),
    ("x = lesson.fm  # lint-lesson-text: ok\n", True),
    ("x = lesson.fm  # lint-lesson-text: ok —\n", True),
    # A suppression on any line the read spans counts.
    ("x = (load(\n    p).fm)  # lint-lesson-text: ok — compared, never printed\n", False),
])
def test_a_suppression_needs_a_reason_on_a_line_the_read_spans(src, flagged):
    lines = src.splitlines()
    (node,) = _GATE.raw_reads(ast.parse(src))
    assert (not _GATE.suppressed(node, lines)) is flagged
