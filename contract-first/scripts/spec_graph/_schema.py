#!/usr/bin/env python3
"""Closed vocabularies shared by check_gate, check_lint, and check_claims. Keep in sync
with schema.md."""
from __future__ import annotations

RULES: tuple[str, ...] = ("R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8")
#: The halves no slot predicate computes; their `evaluated` entry is demanded, not derived.
JUDGMENT: dict[str, str] = {
    "R0": "the bidirectional prose reconciliation (design sentence ↔ element)",
    "R5": "the tightening/safe-by-construction extension",
    "R6": "the rendered-sink chooser/sanitizer walk",
    "R8": "the re-keyed field's join census (which readers key on the changed value)",
}

#: The artifact schema versions this corpus contains. Closed, and ordered: a graph declares
#: which contract it was authored against, and `SINCE` reads that declaration.
SCHEMA_VERSIONS: tuple[int, ...] = (1, 2)
CURRENT_SCHEMA_VERSION: int = SCHEMA_VERSIONS[-1]

#: The artifact version at which each rule's `gate.evaluated` entry became owed.
#:
#: A graph authored before a rule existed cannot carry its entry; without this map, adding a
#: rule means baselining every graph (masking real findings) or leaving the corpus red.
#:
#: Applies to the entry demand only. Computed triggers fire on every graph regardless of
#: version, since they report structure that is really there. R8 has no slot predicate, so
#: for it the entry demand is the whole rule.
SINCE: dict[str, int] = {rule: 1 for rule in RULES} | {"R8": 2}
