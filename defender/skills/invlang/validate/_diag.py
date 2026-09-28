"""The validator's own vocabulary (`Diagnostic`, `Locus`) and the whole-document surface check.

The base of the validator's layering: imports none of its siblings.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import field
from typing import Literal

from defender._model import model

from .. import vocab
from ..parser import (
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


@model(frozen=True)
class Locus:
    """Where a diagnostic's offending row is, when there is one row to point at.

    `row_text` is the row as the author wrote it, never a reconstruction. `row_index` is the
    ordinal within the block, not a file line number, and only parse warnings set it."""

    block: str
    row_text: str
    row_index: int | None = None


@model(frozen=True)
class Diagnostic:
    """One validation failure. `message` is the prose the model sees; `locus` and `fix` are
    optional structure alongside it.

    Only parse warnings and the `:R attr_updates` checks can name a single offending row, so
    only they populate `locus`."""

    message: str
    locus: Locus | None = None
    fix: tuple[str, ...] = field(default_factory=tuple)
    #: `"error"` (the write is refused) or `"warning"` (the write lands and the row gates the
    #: next one until repaired). Assigned per check family, never read from document content.
    #: A `Literal` because callers partition on `== "warning"` / `!= "warning"`, where a
    #: mistyped value would silently file as an error.
    severity: Severity = "error"


def _plain(messages: list[str]) -> list[Diagnostic]:
    """Lift the row-less checks, which stay on `list[str]`, into `Diagnostic`s."""
    return [Diagnostic(m) for m in messages]


def _parse_diagnostic(w: ParseWarning) -> Diagnostic:
    """Keep the parse warning's prose and carry its block, ordinal and row alongside it."""
    return Diagnostic(
        message=f"parse error: {w.format()}",
        locus=Locus(block=w.block, row_text=w.row, row_index=w.row_index),
    )


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")




def _check_surface(proposed_text: str, current_text: str | None) -> list[str]:
    """Refuse invlang block headers this write puts outside a ```invlang fence.

    A ```yaml fence is the loud case. No fence at all is the quiet one: a model that closes a
    fence, writes prose, then continues with `## PLAN` and `:H` blocks produces a file that
    reads correctly and parses to nothing, so every hypothesis-side rule passes vacuously and
    `_check_append_only` sees no drop in fence pairs. `parser.scan_fences` does the accounting;
    this is the policy over it.

    Scoped to headers this write introduces: the baseline's orphans are subtracted as a
    multiset, not a count, so dropping one committed orphan while adding two still names the
    right lines. `investigation.md` is append-only, so committed unfenced rows can never be
    fenced and a whole-document reading would refuse every later write.

    A baseline ending inside an unterminated ```invlang fence is exempt: the fence regex pairs
    it with the next append's opening delimiter, so that append's own block reads as orphaned
    and every retry would be refused identically.
    """
    errors: list[str] = []
    if _YAML_FENCE_RE.search(proposed_text):
        # Reported alongside the unfenced-header half, not instead of it, so orphans are not
        # hidden until the yaml fence is fixed.
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




#: Repair text for an id the author may declare, shared by both arms that report one. It names
#: the harness-reserved case: the harness declines to seed `l-000`'s declaring row into an
#: invalid document, so "already claimed" and "undeclared lead" can both be true at once.
_DECLARE_IT_YOURSELF = (
    ". Declare it in a `:L findings` block and re-send — that holds for a "
    "HARNESS-RESERVED id whose declaring row is not on the page too: the harness "
    "reserves the id so you do not attach new work to it, and writing the row it "
    "is missing is not reusing it"
)
