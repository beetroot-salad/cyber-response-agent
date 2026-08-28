"""The validator's own vocabulary: what a finding IS, and the one check over the whole
document surface rather than over any parsed row.

The base of the validator's layering — split out of `validate.py` when it reached 4038
lines. Imports none of its siblings; every other family imports from here.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

from . import vocab
from .parser import (
    ParseWarning,
    scan_fences,
)


STRONG_AUTH_KINDS = vocab.STRONG_AUTH_KINDS
STRONG_WEIGHTS = vocab.STRONG_WEIGHTS
CONFIRMED_WEIGHT = vocab.CONFIRMED_WEIGHT
REFUTED_WEIGHT = vocab.REFUTED_WEIGHT
_STRONG_AUTH_KINDS_STR = " / ".join(sorted(STRONG_AUTH_KINDS))

_YAML_FENCE_RE = re.compile(r"```ya?ml\b")

#: `Diagnostic.severity`'s closed set. Declared once, beside the type that carries it.
Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class Locus:
    """Where a diagnostic's offending row actually is, when there is one row to point at.

    `row_text` is the row as the author WROTE it — never a reconstruction. Both families that
    populate a locus read it from the document: a parse warning carries its row, and the
    `:R attr_updates` check walks blocks rather than folded records. `row_index` is the ordinal
    WITHIN the block, not a file line number, and only the parse warnings have it."""

    block: str
    row_text: str
    row_index: int | None = None


@dataclass(frozen=True)
class Diagnostic:
    """One validation failure. `message` is the prose the model sees; `locus` and `fix` are
    optional structure alongside it.

    Only the families that can name a single offending row populate `locus` — parse warnings
    and `:R attr_updates`. The document-global checks (append-only, lead and prediction refs,
    strong-move provenance, benign gating, loop close, surface) have no row to point at and
    leave it `None`; so do the vocab sub-checks over `:V`/`:E`/`:H`, whose rows cannot be
    rebuilt without the block's declared column list."""

    message: str
    locus: Locus | None = None
    fix: tuple[str, ...] = field(default_factory=tuple)
    #: `"error"` (the write is refused and nothing is written) or `"warning"` (the write LANDS
    #: and the row gates the NEXT one until it is repaired). Assigned per check family at
    #: diagnose time, never document content — so no migration exists for older bytes.
    #: A closed `Literal`, not a bare `str`: the partition is read THREE ways across three
    #: modules (`== "warning"` here, `!= "warning"` in `validate_companion` and in
    #: `_artifact_schema.validate_investigation`), so a mistyped value would not fail — it
    #: would file silently as error severity at every one of them.
    severity: Severity = "error"


def _plain(messages: list[str]) -> list[Diagnostic]:
    """Lift the checks that carry no row into `Diagnostic`s. Those checks stay on `list[str]`
    deliberately: they gain nothing from the type."""
    return [Diagnostic(m) for m in messages]


def _parse_diagnostic(w: ParseWarning) -> Diagnostic:
    """A parse warning already knows its block, ordinal and raw row — `w.format()` folds them
    into prose. Keep the prose and carry the structure alongside it."""
    return Diagnostic(
        message=f"parse error: {w.format()}",
        locus=Locus(block=w.block, row_text=w.row, row_index=w.row_index),
    )


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")




def _check_surface(proposed_text: str, current_text: str | None) -> list[str]:
    """The on-disk surface is ```invlang fences, and this is the family that says so.

    Two ways to miss it. Writing the block under a ```yaml fence is the loud one — the
    document says invlang and the fence says otherwise. Writing it under NO fence is the
    quiet one, and it is the one that cost a run: a model that closes its ORIENT fence,
    writes a paragraph of prose, then continues with `## PLAN` and its `:H` blocks without
    reopening produces a file that reads correctly to a human and parses to nothing.
    `parse_dense_companion` returns no hypotheses, so #23, #5's declaring half, #6 and #34
    all have nothing to look at and all pass in silence, and `_check_append_only` — which
    counts ```invlang pairs and refuses a DECREASE — sees no decrease, because the write
    added no pair rather than removing one. Every hypothesis-side gate stood down on a
    document whose PLAN was never validated (#932, run `live-867-old`).

    `parser.scan_fences` does the accounting and carries the reasons the complement is
    reported rather than raised, and why a trailing unterminated fence is exempt. What is
    decided HERE is the policy over it.

    **Scoped to what THIS write introduces**, by subtracting the baseline's orphans from the
    proposal's rather than refusing any unfenced header in the document. `investigation.md`
    is append-only: a file that already carries unfenced rows cannot have them fenced after
    the fact, so a whole-document reading would refuse every later write for bytes no repair
    can reach — the append-only wedge the v2.22 delta closed on rules #6 and #17. The
    subtraction is a MULTISET difference over the header lines, not a count comparison: a
    write that drops one committed orphan while adding two would otherwise net to "+1" and
    name the wrong line. It also survives `fix_row`, which rewrites a row in place and adds
    no header. With no baseline every unfenced header is new, which is the right reading for
    a first write.

    **A baseline that stopped MID-BLOCK is exempt entirely.** With an unterminated ```invlang
    on disk, `INVLANG_FENCE_RE` pairs it with the OPENING delimiter of the next append, so
    that append's own block reads as orphaned — and `append_block` sends exactly one fenced
    block per call, so the refusal would name a repair the model had already made and every
    retry would be refused the same way. `scan_fences(...).open_tail` is that state, read off
    the baseline.

    The repair is the one the author can take: re-send the block inside a ```invlang fence.
    Bytes already committed unfenced stay as prose and parse to nothing, which is what they
    already did; the correctly fenced copy is what lands.
    """
    errors: list[str] = []
    if _YAML_FENCE_RE.search(proposed_text):
        # Reported ALONGSIDE the unfenced-header half, not instead of it: returning here
        # would hide every orphan behind the yaml fence until the author fixed that first.
        errors.append(
            "non-invlang surface: investigation.md contains a ```yaml/```yml "
            "fenced block, but the on-disk surface is ```invlang (defender "
            "SKILL §dense format). Rewrite the block(s) as ```invlang."
        )
    if current_text is not None and scan_fences(current_text).open_tail is not None:
        return errors
    baseline = Counter(
        scan_fences(current_text).orphaned_headers if current_text is not None else ()
    )
    introduced: list[str] = []
    for line in scan_fences(proposed_text).orphaned_headers:
        if baseline[line]:
            baseline[line] -= 1
        else:
            introduced.append(line)
    if not introduced:
        return errors
    shown = ", ".join(repr(line.strip()) for line in introduced[:3])
    if len(introduced) > 3:
        shown += f", … ({len(introduced)} in all)"
    errors.append(
        f"non-invlang surface: this write adds {len(introduced)} block header(s) OUTSIDE "
        f"any ```invlang fence — {shown}. Content outside a fence is not parsed, so the "
        f"rows under those headers reach no validator rule and no corpus query: they are "
        f"invisible, not merely unchecked. This is what a `## PLAN` section written after a "
        f"closed fence looks like. Re-send the block with ```invlang on its own line before "
        f"the first header and ``` after the last row."
    )
    return errors




#: The repair for an id the author may legitimately declare — carried by BOTH arms that can
#: report one, so the two cannot drift. It names the harness-reserved case explicitly: the seed
#: that writes `l-000`'s declaring row validates the document first and declines rather than
#: laundering unvalidated bytes past the gate (#964), so "already claimed" and "undeclared
#: lead" can both be true at once, and a model told only the first has no move.
_DECLARE_IT_YOURSELF = (
    ". Declare it in a `:L findings` block and re-send — that holds for a "
    "HARNESS-RESERVED id whose declaring row is not on the page too: the harness "
    "reserves the id so you do not attach new work to it, and writing the row it "
    "is missing is not reusing it"
)
