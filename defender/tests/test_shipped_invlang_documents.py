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


#: The documents that ship concluding the priced keyword, NAMED rather than filtered.
#:
#: A filter would make the cheap repair invisible: a document that stopped concluding
#: `inconclusive` would simply leave the parametrization, and the test that exists to forbid
#: that repair would go green by losing its subject. Both are named, and the census below fails
#: in both directions — one leaving, or a sixth arriving unclassified.
_INCONCLUSIVE_DOCS = (
    _DEFENDER / "examples" / "example-c-cumulative-escalation.md",
    _DEFENDER / "fixtures-e2e" / "golden-v2sshd" / "investigation.md",
)


def _concluded_disposition(path: Path) -> str | None:
    body, _warnings = parse_dense_companion(path.read_text(encoding="utf-8"))
    value = (body.get("conclude") or {}).get("disposition")
    return value if isinstance(value, str) else None


def _with_only_gap_row(text: str, row: str) -> str:
    """The same document with its `:T conclude` gap rows replaced by exactly one `row`.

    Inserts when the document carries none yet, which is the state on this base: the mutant is
    then a document whose ONLY gap row is the one under test, in both directions, whether or
    not the fixture repair has landed."""
    kept = [ln for ln in text.splitlines(keepends=True) if not ln.startswith("ceiling_test")]
    out: list[str] = []
    inserted = False
    for line in kept:
        out.append(line)
        if not inserted and line.rstrip("\n") == ":T conclude":
            out.append(f"{'ceiling_test':<22} \"{row}\"\n")
            inserted = True
    assert inserted, "the `:T conclude` fence moved — re-anchor this walk"
    return "".join(out)


@pytest.mark.parametrize("path", _INCONCLUSIVE_DOCS, ids=corpus_id)
def test_a_shipped_inconclusive_document_names_its_gap_in_the_ceiling_test_block(
    path: Path,
) -> None:
    """#923. A shipped document concluding `inconclusive` PAYS the entry price at both
    boundaries, and what makes it pay is a row naming an unretrieved DATA SOURCE or an
    unavailable CAPABILITY — J1's settled predicate as §7 round 4 widened it, collected here
    through the real gate rather than through any predicate this test owns.

    THE TWO REPAIRS THIS FORBIDS ARE THE TWO CHEAP ONES, and the shape of the test is what
    forbids them. Re-concluding under an unpriced keyword is refused by the census assertion:
    the documents that conclude this keyword are named, so a document leaving the set fails
    here instead of quietly leaving a filter. Satisfying the gate with a row that merely states
    something is refused by the mutation control: the same document, its gap rows replaced by a
    row naming a host and no source, must be REFUSED at both boundaries — that is the assertion
    a build implementing `_row_states_something` fails, and the reason this test reads the real
    price and never that helper.

    WHAT EACH DOCUMENT OWES IS NOT THE SAME. BOTH of the prose gaps in
    `fixtures-e2e/golden-v2sshd/investigation.md` are data sources — process identity
    unresolvable because auditd was not collected, and the Zeek outbound query blocked — so
    that document's repair lifts sentences the run already wrote.
    `examples/example-c-cumulative-escalation.md` has no unretrieved-source sentence at all,
    and under J1's ROUND-3 wording its repair had to author one: its `termination.rationale`
    says the hypothesis "cannot be driven to ++ with available tooling", and calling that
    tooling a data source was a relabelling a human had to vouch for. THE ROUND-4 WIDENING
    REMOVES THAT: the document's own prose already states the gap as a CAPABILITY — "confirming
    C2 would require sandbox detonation or traffic-content inspection, and neither is in the
    runtime tool surface" — so its repair lifts a sentence the run wrote, exactly as the other
    document's does, and the row it owes names the missing sandbox rather than a source that
    was never missing. Retiring it from the corpus was refused: it is the only shipped
    escalation-shaped close.
    """
    from defender.skills.invlang.validate import disposition_entry_price

    from defender.tests._spec923 import (
        CAPABILITY_ROW,
        GAP_MEMBER,
        HOST_ONLY_ROW,
        SOURCE_ONLY_ROW,
    )

    concluding = {p for p in corpus_docs() if _concluded_disposition(p) == GAP_MEMBER}
    assert concluding == set(_INCONCLUSIVE_DOCS), (
        f"the shipped `{GAP_MEMBER}` census moved: "
        f"{sorted(corpus_id(p) for p in concluding ^ set(_INCONCLUSIVE_DOCS))} — a document "
        f"that stopped concluding the priced keyword satisfied the gate by re-concluding, "
        f"which is the repair this demand exists to forbid; a new one has to be classified"
    )

    text = path.read_text(encoding="utf-8")
    assert validate_companion(text, None) == [], (
        f"{corpus_id(path)} concludes `{GAP_MEMBER}` and does not pay at the write gate"
    )
    assert disposition_entry_price(GAP_MEMBER, text).owed == (), (
        f"{corpus_id(path)} concludes `{GAP_MEMBER}` and does not pay at the close — the gap "
        f"it describes in prose never reached the receipt"
    )

    host_only = _with_only_gap_row(text, HOST_ONLY_ROW)
    assert validate_companion(host_only, None) != [], (
        "a row naming a host and neither a data source nor a capability paid at the write "
        "gate — the price is the predicate J1 REJECTED, and this document's gap is a sentence "
        "anyone can go and check"
    )
    assert disposition_entry_price(GAP_MEMBER, host_only).owed, (
        "a row naming a host and neither a data source nor a capability paid at the close"
    )

    # And the refusal above is the PREDICATE, not the edit: the same surgery with a row that
    # DOES pay clears both boundaries. Without this the mutation control is also satisfied by
    # a build that refuses every edited document. Both paying shapes are driven, because the
    # capability row is the one this fixture actually owes and a build that pays only for
    # source-shaped rows leaves the escalation document unrepairable in its own words.
    for row, why in (
        (SOURCE_ONLY_ROW, "a deployment-wide row naming a source and no host was refused"),
        (CAPABILITY_ROW, "a row naming an unavailable capability and no data source was "
                         "refused — that is the shape this document's own prose states its "
                         "gap in, and the shape §7 round 4 widened the predicate to accept"),
    ):
        pays = _with_only_gap_row(text, row)
        assert validate_companion(pays, None) == [], f"{why} at the write gate"
        assert disposition_entry_price(GAP_MEMBER, pays).owed == (), f"{why} at the close"


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
