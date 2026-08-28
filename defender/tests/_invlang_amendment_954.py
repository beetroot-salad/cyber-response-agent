"""Shared documents and readers for the #954 suite — F-46 (a repeated `:L findings` lead id)
and F-47 (a repair suggestion rebuilt from parsed cells).

Nothing here is a test. Every fixture below was EXECUTED against the real parser/validator at
base `505b8d1c` while this file was written, and each one's recorded observation is stated in
its comment — a fixture that quietly carried a second fault would let a weaker implementation
pass every `_only`-shaped assertion in the suite.

FOUR FIXTURE FACTS ARE LOAD-BEARING AND EASY TO GET WRONG:

  * a minimal `:R attr_updates` fixture draws CO-RESIDENT ERROR diagnostics (`undeclared lead
    'l-001'`, `refines 'v-001', which no :V or :E block declares`) alongside the warn-severity
    illegal-key one. Every F-47 assertion selects the warn diagnostic explicitly — via
    `key_warning` — or it rides a sibling's refusal and a null implementation passes.
  * `locus.row_text` is the row the TOKENIZER kept: `_tokenize_fence` strips every line, so a
    row written with trailing padding arrives without it (J7). O8's byte-identity is against
    that text, and a fixture whose expectation carries trailing padding tests something the
    mechanism cannot deliver.
  * the projection does not write the cells the `:L findings` header names. `loop` is coerced
    through `int()`, `window` lands at `query_details["time_window"]` and `fail_reason` at
    `outcome["failure_reason"]` (J5) — `lead["window"]`, `lead["fail_reason"]` and
    `lead["loop"] == "2"` are all assertions about keys nothing writes.
  * the HEADER spelling and the BUCKET KEY differ for `trust_root` too: the column is
    `trust_root` and the projected key is `trust_root_reached`. A header declaring the bucket
    key projects the cell nowhere, silently, and an assertion over C1's own five-field list
    then reads as "the value did not survive" when nothing ever wrote it.
    `STRAND_FINDINGS_HEADER` carries the spelling that works.

Symbols this spec MINTS are imported inside function bodies, never at module scope: the suite
must still COLLECT against `505b8d1c`, where the fix does not exist. Red is the expected state
of a spec; an uncollectable file is not.

Underscore-prefixed so pytest does not collect it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

__all__ = [
    "ATTR_HEADER",
    "CONCLUDE_BENIGN",
    "CONCLUDE_FALSE_POSITIVE",
    "FINDINGS_HEADER",
    "OPTIONAL_ATTR_HEADER",
    "REPEAT_PHRASE",
    "STRAND_FINDINGS_HEADER",
    "UNDECLARED_LEAD_PHRASE",
    "VERTICES",
    "VERTICES_WITH_AN_ESCAPED_PIPE_ID",
    "VERTICES_WITH_A_QUOTED_PIPE_ID",
    "attr_block",
    "attr_doc",
    "cells",
    "close_block",
    "diagnostics",
    "entry_price",
    "findings_block",
    "key_warning",
    "leads",
    "main_deps",
    "parse",
    "repeat_diagnostics",
    "seed_investigation",
    "warnings_of",
]

# documents

#: Two declared vertices, and no `:L findings` block — every F-46 document below opens its
#: own, because a lead re-listed in a SECOND block is the legal cross-block amendment (C4),
#: not the within-block repeat this change is about.
#: EXECUTED: `diagnose(VERTICES, None) == []`.
VERTICES = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical
v-002|identity|user/known-corp|jsmith|
```
"""

#: The same prologue, plus a vertex whose id is a QUOTED cell carrying a `|`. It exists so
#: D8's discriminating row can stand a pipe-bearing cell to the LEFT of its key cell without
#: drawing a second, error-severity diagnostic (`refines '"v-001|v-002"', which no :V or :E
#: block declares`) that would refuse the document out from under the warn-family assertion.
#: EXECUTED at base: the refinement row below draws the warn diagnostic and nothing else.
VERTICES_WITH_A_QUOTED_PIPE_ID = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical
"v-001|v-002"|compute|bastion/internal/known-corp|bastion-09.corp|kind=physical
```
"""

#: The same prologue, plus a vertex whose id cell carries a BACKSLASH-ESCAPED `|`. It exists so
#: D8's third row can stand an *escaped* pipe-bearing cell to the LEFT of its key cell without
#: drawing a second, error-severity diagnostic: `_row_dict` unescapes, so the refinement row's
#: target reads as `bastion|01` and the vertex declared here is the one it refines.
#: EXECUTED at base (J16): the refinement row below draws the warn diagnostic and nothing else,
#: and both offered candidates come back CORRUPTED — `bastion|01`, five cells under a
#: four-column header.
VERTICES_WITH_AN_ESCAPED_PIPE_ID = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical
bastion\\|01|compute|bastion/internal/known-corp|bastion-09.corp|kind=physical
```
"""

#: The `:L findings` header the F-46 fixtures declare. `fail_reason`, `mode` and
#: `screen_result` are named because three of the strand cases need them, and marked `?` so a
#: row that has nothing to say about them is a legal seven-cell row rather than three trailing
#: pipes on every fixture. A column a fixture leaves blank costs nothing either way —
#: `_lead_header_record` writes the five conditional fields only when the cell is non-empty.
FINDINGS_HEADER = (
    "[id|loop|name|target|tests|system|window|fail_reason?|mode?|screen_result?]"
)

#: The same header widened to carry every one of C1's five verified non-empty-only columns.
#: THE COLUMN IS SPELLED `trust_root`, not `trust_root_reached`: `_lead_header_record` maps
#: `("trust_root", "trust_root_reached")`, so a header declaring the bucket key projects
#: nothing at all — EXECUTED, and the reason D27's first draft could not exercise the field
#: C1's own list names.
STRAND_FINDINGS_HEADER = (
    "[id|loop|name|target|tests|system|window|fail_reason?|mode?|screen_result?"
    "|trust_root?|status?]"
)

#: The `:R attr_updates` header both in-repo blocks declare — four columns, none optional
#: (C18).
ATTR_HEADER = "[resolved_by|target|key|value]"

#: The same block with its trailing column marked optional. Reachable-in-principle and
#: unattested-in-fact (C18); `_check_attr_update_keys`'s own docstring is explicit that it
#: reads "whatever header the block declares", so header variation is a case the check is
#: deliberately built for.
OPTIONAL_ATTR_HEADER = "[resolved_by|target|key|value?]"

#: The substring the existing repeated-id check interpolates the id into. The assertion is on
#: the id appearing in the message prose, never on an exact sentence.
REPEAT_PHRASE = "is declared twice in this block"

#: What `_check_lead_refs` says about a bucket no `:L findings` row declares. D12's narrowed
#: obligation is that this is NOT said about the surviving lead.
UNDECLARED_LEAD_PHRASE = "undeclared lead"

#: A `:T conclude` claiming the one disposition with a structural gate (`benign`). Needed by
#: the corpus loader, which skips a document missing any of prologue / findings / conclude.
CONCLUDE_BENIGN = """
```invlang
:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      routine-admin-login
summary                "Login matched established bastion usage"
```
"""

#: A `:T conclude` claiming `false-positive` — the OTHER disposition `_DISPOSITION_GATES`
#: prices, and the one whose price reads the lead buckets. Its `entity_check` gate resolves
#: `l-001` in `:L findings` and then asks whether THAT LEAD'S `target` is a vertex the prologue
#: carried (validate.py:2429-2455), which is the one channel in the C11 waiver-candidate class
#: where the survivor rule is observable (J18).
CONCLUDE_FALSE_POSITIVE = """
```invlang
:T conclude
termination.category   adversarial-refuted
disposition            false-positive
detection_notes        "the rule keys on a path the deploy moved"
entity_check           l-001
```
"""


def findings_block(*rows: str, header: str = FINDINGS_HEADER) -> str:
    """One `:L findings` block, its rows exactly as written."""
    return "\n```invlang\n:L findings " + header + "\n" + "\n".join(rows) + "\n```\n"


def attr_block(*rows: str, header: str = ATTR_HEADER) -> str:
    """One `:R attr_updates` block, its rows exactly as written — padding, quoting and
    escapes intact, because those are what F-47's mechanism has to survive."""
    body = "\n".join(rows)
    return (
        "\n```invlang\n:R attr_updates " + header + "\n"
        + (body + "\n" if body else "")
        + "```\n"
    )


def close_block(loop: int) -> str:
    """A `:T close` block — the row that closes a loop, written through `append_block` like
    every other block."""
    return f"\n```invlang\n:T close\nloop {loop}\n```\n"


def attr_doc(*rows: str, header: str = ATTR_HEADER, prologue: str = VERTICES) -> str:
    """A complete document whose ONLY fault is whatever the given `:R attr_updates` rows
    carry: two declared vertices, one declared lead, one refinement block.

    `prologue` is anchored in the signature, like `header` beside it, rather than resolved
    from `None` in the body (`defender/CLAUDE.md` — "Anchor a default in one place")."""
    return (
        prologue
        + findings_block("l-001|1|cmdb-lookup|v-001||cmdb|n/a")
        + attr_block(*rows, header=header)
    )


# the readers, through the real primitives

def parse(text: str) -> tuple[Any, list[Any]]:
    """`parse_dense_companion(text)` — the projector's two return surfaces."""
    from defender.skills.invlang.parser import parse_dense_companion

    return parse_dense_companion(text)


def leads(text: str) -> list[dict]:
    """`companion["findings"]` — the published lead buckets, in first-mention order."""
    companion, _warnings = parse(text)
    return list(companion.get("findings", []))


def warnings_of(text: str) -> list[Any]:
    """Slot 2 of the parser's return."""
    _companion, warnings = parse(text)
    return list(warnings)


def diagnostics(text: str) -> list[Any]:
    """`diagnose(text, None)` — the validator's findings, warn and error alike."""
    from defender.skills.invlang.validate import diagnose

    return list(diagnose(text, None))


def repeat_diagnostics(text: str) -> list[Any]:
    """Every diagnostic of the repeated-lead-id family, selected on the id-bearing prose the
    existing check emits rather than on an exact sentence."""
    return [d for d in diagnostics(text) if REPEAT_PHRASE in d.message]


def key_warning(text: str) -> Any:
    """THE warn-severity `:R attr_updates` illegal-key diagnostic for this document.

    Selected explicitly, and asserted unique: a minimal refinement fixture draws co-resident
    ERROR diagnostics, and an F-47 assertion that took `diagnose(...)[0]` would ride one of
    them."""
    warns = [d for d in diagnostics(text) if d.severity == "warning"]
    assert len(warns) == 1, f"expected exactly one warn diagnostic, got {warns}"
    return warns[0]


def entry_price(disposition: str, text: str) -> tuple[str, ...]:
    """`disposition_entry_price(disposition, text).owed` — what the close still owes for its
    keyword, computed over a companion parsed WITHOUT validation (validate.py:2608)."""
    from defender.skills.invlang.validate import disposition_entry_price

    return disposition_entry_price(disposition, text).owed


def cells(row: str) -> list[str]:
    """`_split_cells(row)` — the SAME splitter the parser reads a row with, never
    `row.count("|")`: counting pipes is the reasoning that produced F-47."""
    from defender.skills.invlang._cells import _split_cells

    return _split_cells(row)


# deps and the run dir — the write verbs' real seam

def main_deps(tmp_path: Path) -> tuple[Any, Path]:
    """MAIN deps through the real `bind` seam — real compiled policy, real gate.

    Shared with `_invlang_warn_836`, which is the same construction path
    `test_append_only_write_lane_810.py` uses, so the three suites exercise one seam rather
    than three."""
    from defender.tests._invlang_warn_836 import main_deps as _main_deps

    return _main_deps(tmp_path)


def seed_investigation(run_dir: Path, text: str) -> Path:
    """Put `text` on disk as the run's investigation.md, bypassing the write verbs.

    Deliberately not through `append_block`: the F-L scenarios need a document ALREADY
    holding the repeat as their starting state, and after this change no GATED VERB can
    produce one — which is the whole point of a uniform formation gate. Said that way on
    purpose: the gate is uniform across the verbs the agent writes through, and this fixture
    is a third writer of the same shape as the one production writer that also bypasses it
    (`lead_zero._declare_l_finding`, filed as #964). The difference is that this one is a test
    device and says so."""
    from defender.tests._invlang_warn_836 import seed_investigation as _seed

    return _seed(run_dir, text)
