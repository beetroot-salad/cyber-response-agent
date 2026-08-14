#!/usr/bin/env python3
"""The closed vocabularies more than one checker reads — the judgment-vs-computed rule
partition is load-bearing across check_gate, check_lint, and check_claims, so it lives
once. Grow schema.md and this module in one commit."""
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
#: A rule added after a graph was authored demands an entry that graph structurally CANNOT
#: carry — the run that would have recorded it is over. Without this map the only ways to add
#: a rule are to baseline every existing graph (which raises 32 ceilings by one and masks a
#: first real finding in each of the graphs that were clean) or to leave the corpus red. Both
#: pay for a new rule by weakening the ratchet over unrelated history, which is the trade this
#: gate exists to refuse.
#:
#: Scope is deliberately the ENTRY DEMAND only — the "you did not record that you considered
#: this" arm. Computed triggers still fire on every graph regardless of version: those are
#: findings about structure that is really there, they are held at their baselined counts
#: already, and suppressing them by authoring date would hide live defects rather than absent
#: paperwork. R8 has no slot predicate, so for it the entry arm is the whole rule.
SINCE: dict[str, int] = {rule: 1 for rule in RULES} | {"R8": 2}
