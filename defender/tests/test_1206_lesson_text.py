"""#1206: lesson text leaves the shared loader in one of three forms the caller picks.

A lesson's frontmatter is corpus text a model wrote. `Lesson.line` / `Lesson.lines` give a value
as one printed line (line breaks become spaces, controls and zero-width characters are dropped,
blank list items are skipped); `Lesson.match_text` gives the frontmatter as the lines a search
pattern runs over, one `key: value` line per key, built from the same one-line form so a value
`--tags` lists is a value a search finds.
"""

from __future__ import annotations

import re
from pathlib import Path

from defender._corpus import iter_lessons
from defender._text import one_line


def _lesson(tmp_path: Path, text: str):
    corpus = tmp_path / "lessons"
    corpus.mkdir()
    (corpus / "l.md").write_text(text, encoding="utf-8")
    (lesson,) = list(iter_lessons(corpus))
    return lesson


def test_one_line_drops_every_control_character_whitespace_or_not():
    """U+001F is `isspace()` in Python and not a TSV breaker, so it slipped through."""
    assert one_line("a\x1fb") == "ab"
    assert one_line("a\x1b[2Kb") == "a[2Kb"
    assert one_line("a\u2028b\nc\td") == "a b c d"
    assert one_line("  a\u200b  ") == "a"


def test_line_and_lines_give_one_line_values(tmp_path):
    lesson = _lesson(tmp_path, (
        "---\nname: l\n"
        'description: "a\\nb\\e[1A"\n'
        'telemetry_source: [sshd, " sshd ", "\\n", "x\\u2028y", "\\u200b"]\n'
        "attack_phase: persistence\n"
        "---\nbody\n"))
    assert lesson.line("description") == "a b[1A"
    assert lesson.line("missing") == ""
    assert lesson.lines("telemetry_source") == ["sshd", "sshd", "x y"]
    assert lesson.lines("attack_phase") == ["persistence"]
    assert lesson.lines("missing") == []


def test_match_text_finds_a_listed_value_and_keeps_fields_apart(tmp_path):
    """A block-scalar tag is found by the one-line spelling `--tags` lists; a pattern cannot
    run from one key into the next."""
    lesson = _lesson(tmp_path, (
        "---\nname: l\n"
        "telemetry_source:\n  - |\n    a\n    b\n"
        "source_signature: [v2-x]\n"
        "attack_phase: [persistence]\n"
        "---\nbody mentions sshd\n"))
    text = lesson.match_text()
    assert text.splitlines() == [
        "name: l",
        "telemetry_source: [a b]",
        "source_signature: [v2-x]",
        "attack_phase: [persistence]",
    ]
    assert re.search(r"telemetry_source:.*\ba b\b", text, re.I)
    assert re.search(r"source_signature:.*v2-x", text, re.I)
    assert not re.search(r"telemetry_source:.*persistence", text, re.I)
    assert "sshd" not in text
