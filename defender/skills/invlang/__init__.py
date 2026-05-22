"""Defender-side invlang loader + cross-case query helpers.

Standalone — does not import from soc-agent. Tolerates the surface drift
in defender-emitted investigation.md (unescaped `|` in attrs, extra empty
hypothesis cells, missing `⟂` in resolutions).
"""

from .corpus import Companion, LoadReport, load_corpus
from .queries import (
    hypothesis_name_wildcard,
    lead_branch_effects,
    lead_sequence_pattern,
)

__all__ = [
    "Companion",
    "LoadReport",
    "load_corpus",
    "hypothesis_name_wildcard",
    "lead_branch_effects",
    "lead_sequence_pattern",
]
