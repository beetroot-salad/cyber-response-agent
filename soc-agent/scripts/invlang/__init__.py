"""Investigation-language query library.

Programmatic API for loading investigation companions and running
retrieval queries against the corpus.

Example:
    from soc_agent.scripts.invlang import load_corpus, lead_effectiveness_for_hypothesis

    corpus = load_corpus()
    result = lead_effectiveness_for_hypothesis(corpus, "?*compromise*")
"""

from .corpus import (
    Companion,
    PILOT_CORPUS_FILES,
    conclude_field,
    load_corpus,
)
from .queries import (
    ENUM_CHOICES,
    anchor_calibration,
    coarse_case_lookup,
    dead_lead_lookup,
    enumerate_corpus,
    hypothesis_name_wildcard,
    lead_effectiveness,
    lead_effectiveness_for_hypothesis,
    lead_sequence_pattern,
    prose_substring,
    refinement_chain_shapes,
)

__all__ = [
    # corpus
    "Companion",
    "PILOT_CORPUS_FILES",
    "conclude_field",
    "load_corpus",
    # queries
    "ENUM_CHOICES",
    "anchor_calibration",
    "coarse_case_lookup",
    "dead_lead_lookup",
    "enumerate_corpus",
    "hypothesis_name_wildcard",
    "lead_effectiveness",
    "lead_effectiveness_for_hypothesis",
    "lead_sequence_pattern",
    "prose_substring",
    "refinement_chain_shapes",
]
