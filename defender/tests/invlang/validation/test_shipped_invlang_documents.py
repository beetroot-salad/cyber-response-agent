"""Every invlang document the SKILL ships (examples, e2e fixtures, SKILL.md Example A, the grammar reference) parses without warnings and, where it is a whole document, passes the write gate."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import validate_companion
from defender.tests.support.invlang.validation._invlang_corpus import corpus_docs, corpus_id

_DEFENDER = Path(__file__).resolve().parents[3]
_FENCE_RE = re.compile(r"```invlang\n.*?```", re.S)


@pytest.mark.parametrize("path", corpus_docs(), ids=corpus_id)
def test_a_shipped_document_parses_without_warnings(path: Path) -> None:
    """A dropped row is not a diagnostic the reader of an EXAMPLE ever sees — the file renders
    fine in markdown. Only the parser knows, so it has to be asked."""
    _body, warnings = parse_dense_companion(path.read_text(encoding="utf-8"))
    assert [w.format() for w in warnings] == []


@pytest.mark.parametrize("path", corpus_docs(), ids=corpus_id)
def test_a_shipped_document_would_survive_the_write_gate(path: Path) -> None:
    """`validate_companion` is what `permission/files.py` runs on every `investigation.md`
    write. An example it refuses is an example teaching a write that cannot land."""
    assert validate_companion(path.read_text(encoding="utf-8"), None) == []


def _example_a_fences() -> str:
    """Example A's fences, concatenated in document order — the document the run would hold
    after writing every block the example shows, which is what the gate sees."""
    text = (_DEFENDER / "SKILL.md").read_text(encoding="utf-8")
    start = text.index("### Example A — FIM checksum change")
    end = text.index("### More worked examples", start)
    fences = _FENCE_RE.findall(text[start:end])
    # A renamed header must fail LOUDLY. Silently finding zero fences is the shape of a guard
    # that stopped guarding, which is the failure this whole module exists to end.
    assert len(fences) >= 3, "Example A's invlang fences moved — re-anchor this walk"
    return "\n".join(fences)


def test_example_a_accumulates_clean() -> None:
    """The flagship example, and the only one inlined into every ORIENT rather than loaded on
    demand — so it is the example the model imitates whether it reads the others or not."""
    doc = _example_a_fences()
    _body, warnings = parse_dense_companion(doc)
    assert [w.format() for w in warnings] == []
    assert validate_companion(doc, None) == []


def _invlang_grammar_fences() -> str:
    """`skills/invlang/SKILL.md`'s ```invlang fences, concatenated in document order."""
    text = (_DEFENDER / "skills" / "invlang" / "SKILL.md").read_text(encoding="utf-8")
    fences = _FENCE_RE.findall(text)
    assert len(fences) >= 10, "the invlang SKILL fence walk broke — re-anchor it"
    return "\n".join(fences)


def test_the_invlang_grammar_reference_parses_clean() -> None:
    """The densest prompt surface in the system, and until now the one no test read."""
    _body, warnings = parse_dense_companion(_invlang_grammar_fences())
    assert [w.format() for w in warnings] == []
