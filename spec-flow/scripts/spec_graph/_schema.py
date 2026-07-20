#!/usr/bin/env python3
"""The closed vocabularies more than one checker reads — the judgment-vs-computed rule
partition is load-bearing across check_gate, check_lint, and check_claims, so it lives
once. Grow schema.md and this module in one commit."""
from __future__ import annotations

RULES: tuple[str, ...] = ("R0", "R1", "R2", "R3", "R4", "R5", "R6")
#: The halves no slot predicate computes; their `evaluated` entry is demanded, not derived.
JUDGMENT: dict[str, str] = {
    "R0": "the bidirectional prose reconciliation (design sentence ↔ element)",
    "R5": "the tightening/safe-by-construction extension",
    "R6": "the rendered-sink chooser/sanitizer walk",
}
