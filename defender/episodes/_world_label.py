"""The naming rules a world label is held to, as pure text checks with no dependencies.

The family model judges a world label (a label must not claim a reserved name, and must be in
the world-token alphabet). The rules and their words live here once, so a reader that holds no
model stack (the runs repository's arm-roster reader, #1187) judges a label the same way. Each
`*_fault` function returns the refusal's sentence, or `None` when the label passes; a label is
shown `quoted`, so a model-authored megabyte cannot flood the refusal.
"""
from __future__ import annotations

import re

from defender._shown import quoted

#: Labels no world may claim. `base` names the family's shared capture (a world using it would
#: append live rows into the recording its siblings replay); `family` would give a per-world judge
#: draw the family-level call's agent id `judge:family:<n>`, interleaving two streams in one
#: wire log.
RESERVED_WORLD_LABELS: frozenset[str] = frozenset({"base", "family"})

#: `family_<digits>` too, defensively: the colon fold that names a wire-log file is not obviously
#: injective across `judge:<world>:<n>` and `judge:family:<n>`, so the whole near-miss shape is
#: refused.
_RESERVED_FAMILY_DRAW_LABEL = re.compile(r"\Afamily_\d+\Z", re.IGNORECASE)

def is_reserved_world_label(label: str) -> bool:
    """The membership test for the reserved namespace (the set, case-folded, and the
    `family_<digits>` shape). Other gates, such as the judge's, ask this rather than re-deriving
    the fold."""
    return (label.casefold() in RESERVED_WORLD_LABELS
            or _RESERVED_FAMILY_DRAW_LABEL.match(label) is not None)


def reserved_label_fault(label: str, *, at: str = "") -> str | None:
    """Why `label` is reserved, or `None`. The shape arm runs first so `family_1` is refused for
    the rule that actually matched it; `at` prefixes where the label was found."""
    where = f"{at} " if at else ""
    if _RESERVED_FAMILY_DRAW_LABEL.match(label):
        return (f"{where}world label {quoted(label)} matches family_<n> — the colon fold that names a "
                "wire log file is not injective, and this label's own agent id would fold to "
                "the same stem as one of the family call's draws")
    if is_reserved_world_label(label):
        return (f"{where}world label {quoted(label)} is the reserved name of the family's own base "
                "capture or the family-level judge call — a world claiming it would append its "
                "live rows into the recording its siblings replay, or collide with the family "
                "call's own agent id")
    return None


#: The world-token rule's alphabet: lower-case ASCII letters, digits and `_`, starting with a
#: letter or digit. No `-` and no `.`: the world token is `<episode token>.<label>`, and the
#: episode token is the episode's UUID with its hyphens rendered as dots, so a label holding
#: either would blur where the token's label begins. (An arm's run folder is named by its roster
#: UUID since #1187, never by the label.) Lower case only: a label names an archived world, a
#: ledger file and an oracle-side store, and two labels one case fold apart would be one file
#: wherever the filesystem folds case.
_WORLD_LABEL = re.compile(r"\A[a-z0-9][a-z0-9_]*\Z")


def world_label_fault(label: object, *, at: str = "") -> str | None:
    """Why `label` cannot be a world label, or `None`: a string in the world-token alphabet
    that does not claim a reserved name. `at` prefixes where the label was found.

    The one statement of the shape rule; the manifest loader asks it of every world, so every
    reader of a manifest (the launcher, the sibling, the judge, the page) holds labels to it."""
    where = f"{at} " if at else ""
    if not isinstance(label, str) or not _WORLD_LABEL.match(label):
        return (f"{where}world label {quoted(label)} is outside the world-token alphabet (lower-"
                "case ASCII letters, digits and '_', starting with a letter or digit) — a label "
                "names an archived world, a ledger file and an oracle-side store, and ends the "
                "world token `<episode token>.<label>`")
    return reserved_label_fault(label, at=at)
