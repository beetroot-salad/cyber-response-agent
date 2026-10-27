"""The naming rules a world label is held to, as pure text checks with no dependencies.

The family model judges a world label (a label must not claim a reserved name, and must be in
the world-label alphabet). The rules and their words live here once, so a reader that holds no
model stack (the runs repository's arm-roster reader, #1187) judges a label the same way. Each
`*_fault` function returns the refusal's sentence, or `None` when the label passes; a label is
shown `quoted`, so a model-authored megabyte cannot flood the refusal.
"""
from __future__ import annotations

import re

from defender._shown import quoted

#: Logical names reserved for the family's capture and family-level reporting. These are
#: selector conventions; filesystem separation is provided by world UUIDs.
RESERVED_WORLD_LABELS: frozenset[str] = frozenset({"base", "family"})

#: The family judgement's numbered selector namespace is reserved as well.
_RESERVED_FAMILY_DRAW_LABEL = re.compile(r"\Afamily_\d+\Z", re.IGNORECASE)

def is_reserved_world_label(label: str) -> bool:
    """The membership test for the reserved namespace (the set, case-folded, and the
    `family_<digits>` shape). Other gates, such as the judge's, ask this rather than re-deriving
    the fold."""
    return (label.casefold() in RESERVED_WORLD_LABELS
            or _RESERVED_FAMILY_DRAW_LABEL.match(label) is not None)


def reserved_label_fault(label: str, *, at: str = "") -> str | None:
    """Why a selector claims the family's reporting namespace, or `None`."""
    where = f"{at} " if at else ""
    if _RESERVED_FAMILY_DRAW_LABEL.match(label):
        return (f"{where}world label {quoted(label)} matches family_<n>, the reserved "
                "namespace for numbered family judgements")
    if is_reserved_world_label(label):
        return (f"{where}world label {quoted(label)} is reserved for the family's capture "
                "or family-level reporting")
    return None


#: Descriptive selectors are lower-case ASCII letters, digits and `_`, starting alphanumeric.
#: Labels are metadata, never filename components or pieces of world IDs. Their length has
#: no filesystem-derived bound; persisted world UUIDs address every world-specific artifact.
_WORLD_LABEL = re.compile(r"\A[a-z0-9][a-z0-9_]*\Z")


def world_label_fault(label: object, *, at: str = "") -> str | None:
    """Why `label` cannot be a world label, or `None`: a string in the world-label alphabet
    that does not claim a reserved name. `at` prefixes where the label was found.

    The one statement of the shape rule; the manifest loader asks it of every world, so every
    reader of a manifest (the launcher, the sibling, the judge, the page) holds labels to it."""
    where = f"{at} " if at else ""
    if not isinstance(label, str) or not _WORLD_LABEL.match(label):
        return (f"{where}world label {quoted(label)} is outside the world-label alphabet (lower-"
                "case ASCII letters, digits and '_', starting with a letter or digit)")
    return reserved_label_fault(label, at=at)
