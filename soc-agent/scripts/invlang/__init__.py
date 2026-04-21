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
    hypothesis_topology,
    load_corpus,
)
from .queries import (
    ENUM_CHOICES,
    anchor_calibration,
    coarse_case_lookup,
    dead_lead_lookup,
    enumerate_corpus,
    enumerate_hypothesis_tree,
    hypothesis_name_wildcard,
    independent_datasource_metric,
    lead_discrimination_score,
    lead_effectiveness,
    lead_effectiveness_for_hypothesis,
    lead_effectiveness_for_topology,
    lead_pair_synergy,
    lead_sequence_pattern,
    peer_hypothesis_distribution_for_topology,
    post_failure_recovery,
    prose_substring,
    refinement_chain_shapes,
    weight_reversal_mining,
)

__all__ = [
    # corpus
    "Companion",
    "PILOT_CORPUS_FILES",
    "conclude_field",
    "load_corpus",
    # queries — classes 1–8 (original)
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
    # queries — axis 1 additions
    "enumerate_hypothesis_tree",
    "lead_discrimination_score",
    # queries — classes 9–12 (axis 2)
    "weight_reversal_mining",
    "lead_pair_synergy",
    "post_failure_recovery",
    "independent_datasource_metric",
    # topology-conditioned retrieval (handler-facing)
    "hypothesis_topology",
    "lead_effectiveness_for_topology",
    "peer_hypothesis_distribution_for_topology",
]
