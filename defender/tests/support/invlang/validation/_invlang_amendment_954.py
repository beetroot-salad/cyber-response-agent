"""Shared documents and readers for the #954 suite — F-46 (a repeated `:L findings` lead id)
and F-47 (a repair suggestion rebuilt from parsed cells)."""
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
    "VERTICES_FREEFORM_CLASS",
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

#: Two declared vertices and no `:L findings` block: each F-46 document opens its own, since a
#: lead re-listed in a SECOND block is a legal amendment, not a repeat.
#: `diagnose(VERTICES, None) == []`.
VERTICES = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical
v-002|identity|user/known-corp|jsmith|
```
"""

#: The same two vertices with v-001 a `process`, the one type whose `class` cell the grammar
#: leaves free. On a `compute` target `compute.role` (#986) would refuse the values the paste
#: round trips carry and withhold the offer's `class` candidate; here the refinement key stays
#: the document's only fault.
VERTICES_FREEFORM_CLASS = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|process|bash|bash[pid=4120]|
v-002|identity|user/known-corp|jsmith|
```
"""

#: Plus a vertex whose id is a QUOTED cell carrying a `|`, so a refinement row can put a
#: pipe-bearing target cell LEFT of its key cell without also drawing an undeclared-target
#: error. A `process`, for the reason `VERTICES_FREEFORM_CLASS` gives.
VERTICES_WITH_A_QUOTED_PIPE_ID = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical
"v-001|v-002"|process|bash|bash[pid=4121]|
```
"""

#: Plus a vertex whose id cell carries a BACKSLASH-ESCAPED `|`: `_row_dict` unescapes, so a
#: refinement row targeting `bastion\|01` refines this vertex and draws no undeclared-target
#: error. A `process`, for the reason `VERTICES_FREEFORM_CLASS` gives.
VERTICES_WITH_AN_ESCAPED_PIPE_ID = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical
bastion\\|01|process|bash|bash[pid=4122]|
```
"""

#: The `:L findings` header the F-46 fixtures declare. The strand cases need `fail_reason`,
#: `mode` and `screen_result`; optional, so other rows stay seven cells.
FINDINGS_HEADER = (
    "[id|loop|name|target|tests|system|window|fail_reason?|mode?|screen_result?]"
)

#: Widened to all five lead columns written only when non-empty. Spelled `trust_root`:
#: `_lead_header_record` maps it to the bucket key `trust_root_reached`, and a header
#: declaring the bucket key projects nothing.
STRAND_FINDINGS_HEADER = (
    "[id|loop|name|target|tests|system|window|fail_reason?|mode?|screen_result?"
    "|trust_root?|status?]"
)

#: The four-column `:R attr_updates` header the in-repo blocks declare.
ATTR_HEADER = "[resolved_by|target|key|value]"

#: The same header with its trailing column optional: unattested in the corpus, but
#: `_check_attr_update_keys` reads whatever header the block declares.
OPTIONAL_ATTR_HEADER = "[resolved_by|target|key|value?]"

#: The repeated-id message's fixed phrase; tests match on it, never on an exact sentence.
REPEAT_PHRASE = "is declared twice in this block"

#: What `_check_lead_refs` says about a bucket no `:L findings` row declares.
UNDECLARED_LEAD_PHRASE = "undeclared lead"

#: A `:T conclude` claiming `benign`. The corpus loader skips a document missing any of
#: prologue / findings / conclude.
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

#: A `:T conclude` claiming `false-positive`, whose price reads the lead buckets: its
#: `entity_check` resolves `l-001` and asks whether THAT LEAD'S `target` is a declared vertex,
#: which makes the surviving row of a repeated lead observable.
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
    """One `:R attr_updates` block, its rows exactly as written (padding, quoting and
    escapes intact)."""
    body = "\n".join(rows)
    return (
        "\n```invlang\n:R attr_updates " + header + "\n"
        + (body + "\n" if body else "")
        + "```\n"
    )


def close_block(loop: int) -> str:
    """A `:T close` block closing `loop`."""
    return f"\n```invlang\n:T close\nloop {loop}\n```\n"


def attr_doc(*rows: str, header: str = ATTR_HEADER, prologue: str = VERTICES) -> str:
    """A complete document whose ONLY fault is whatever the given `:R attr_updates` rows
    carry: two declared vertices, one declared lead, one refinement block."""
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
    """Every diagnostic of the repeated-lead-id family."""
    return [d for d in diagnostics(text) if REPEAT_PHRASE in d.message]


def key_warning(text: str) -> Any:
    """THE warn-severity `:R attr_updates` illegal-key diagnostic for this document.

    Selected by severity and asserted unique: minimal refinement fixtures also draw ERROR
    diagnostics, which `diagnose(...)[0]` could pick up."""
    warns = [d for d in diagnostics(text) if d.severity == "warning"]
    assert len(warns) == 1, f"expected exactly one warn diagnostic, got {warns}"
    return warns[0]


def entry_price(disposition: str, text: str) -> tuple[str, ...]:
    """`disposition_entry_price(disposition, text).owed` — what the close still owes for its
    keyword, computed over a companion parsed WITHOUT validation."""
    from defender.skills.invlang.validate import disposition_entry_price

    return disposition_entry_price(disposition, text).owed


def cells(row: str) -> list[str]:
    """`split_cells(row)` — the SAME splitter the parser reads a row with, never
    `row.count("|")`, which miscounts quoted and escaped pipes."""
    from defender.skills.invlang._cells import split_cells

    return split_cells(row)


# deps and the run dir — the write verbs' real seam

def main_deps(tmp_path: Path) -> tuple[Any, Path]:
    """MAIN deps through the real `bind` seam: `_invlang_warn_836.main_deps`."""
    from defender.tests.support.invlang.validation._invlang_warn_836 import main_deps as _main_deps

    return _main_deps(tmp_path)


def seed_investigation(run_dir: Path, text: str) -> Path:
    """Put `text` on disk as the run's investigation.md, bypassing the write verbs."""
    from defender.tests.support.invlang.validation._invlang_warn_836 import seed_investigation as _seed

    return _seed(run_dir, text)
