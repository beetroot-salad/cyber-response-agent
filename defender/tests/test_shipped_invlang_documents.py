"""Every invlang document the SKILL ships is one the runtime would accept.

`examples/example-b` shipped for months anchoring both its hypotheses on `e-001`, an EDGE id
— `:H` is discovery-only, so the parser dropped the whole `:H` block and then reported five
sub-blocks referencing hypotheses that no longer existed: 7 parse warnings, 12 validator
errors, in a document `defender/SKILL.md` tells the agent to LOAD as a worked example.
`example-c` was worse in kind if not in count: `endpoint` and `package` as vertex types,
`queried_dns` and `loaded` as relations — a vocabulary two renames behind the enum the
validator reads.

Nothing noticed, because the corpus rules that existed asked narrower questions.
`test_invlang_prediction_refs` and `test_invlang_hypothesis_refs` parametrize over the same
`corpus_docs()` list and check reference integrity over WHAT SURVIVED PARSING — a document
whose `:H` block was dropped entirely has no dangling references left to find. This asks the
question those cannot: does the document parse at all, and would the write gate take it.

`docs/decisions/defender-invlang-enforcement-ramp.md` credited two guards for exactly this
— `test_skill_worked_examples_all_pass` and `test_skill_example_a_accumulates_clean` — and
neither has ever existed in this repo. This module is what those names promised, and the ramp
doc now names it instead.

The examples are prompt surface, not fixtures: an agent reads them for SHAPE, so a shape the
validator refuses is a shape the run learns to write and is then denied for. #934 is the
standing case — the fork examples taught a class tuple minted to carry a difference the
predictions already carried, and every tuple-class sibling pair in the corpus copied it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import validate_companion
from defender.tests._invlang_corpus import corpus_docs, corpus_id

_DEFENDER = Path(__file__).resolve().parents[1]
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
    after writing every block the example shows, which is what the gate sees.

    Per-fence validation would be the weaker question: each fragment parses alone, and the
    defects that matter across an accumulating document (a hypothesis id the later `:T` cites,
    an `:R attr_updates` target the prologue must declare) only appear once the blocks are
    stacked.
    """
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
    """`skills/invlang/SKILL.md`'s ```invlang fences, concatenated in document order.

    THE WHOLE FILE is the unit, and neither smaller nor larger one works. Per-fence is too
    small: a `:H h-001.authz` sub-block is attached at PARSE time, so a lone fence is refused
    for a hypothesis the fence three sections up declares. Per-section is the same defect one
    step out. The file read whole gives every sub-block its declaring row, which is the
    question worth asking of a grammar reference — does the parser accept every shape this
    file teaches an author to write.
    """
    text = (_DEFENDER / "skills" / "invlang" / "SKILL.md").read_text(encoding="utf-8")
    fences = _FENCE_RE.findall(text)
    # A renamed fence language or a moved file must fail LOUDLY, for the reason
    # `_example_a_fences` gives: finding zero and passing is the shape of a guard that stopped
    # guarding. Loose on purpose — it fires on the walk breaking, not on ordinary editing.
    assert len(fences) >= 10, "the invlang SKILL fence walk broke — re-anchor it"
    return "\n".join(fences)


def test_the_invlang_grammar_reference_parses_clean() -> None:
    """The densest prompt surface in the system, and until now the one no test read.

    `skills/invlang/SKILL.md` is inlined VERBATIM into every ORIENT message
    (`runtime/orient._invlang_grammar`, pinned by `test_hardening_772`), while `corpus_docs()`
    globs `examples/` and `fixtures-e2e/` and the two walks above read `defender/SKILL.md`. So
    the file that teaches the grammar was checked by nothing, and it had drifted twice: five
    lines of markdown prose sat INSIDE a `:L findings` fence, where a language with no comment
    syntax read each `#` line as a 1-cell row against an 8-column header, and the authz example
    tagged its block `:H h-NNN.authz` — the prose placeholder, which as a block tag names a
    hypothesis nothing declares. Both are shapes an author copies and is then refused for.

    PARSE and not VALIDATE, which is a real limit and not an oversight. A worked example
    accumulates to one document and can be asked whether the write gate takes it; this file
    teaches BLOCKS, and stitching its sections manufactures contradictions no section holds —
    an authz section resolving a contract `unauthorized` lands beside a conclude section
    grading `benign`, and the pair refuses for a disagreement between two different lessons.
    Asking the write-gate question of this file needs it restructured into worked examples,
    which is a decision about the prompt rather than a guard over it.
    """
    _body, warnings = parse_dense_companion(_invlang_grammar_fences())
    assert [w.format() for w in warnings] == []
