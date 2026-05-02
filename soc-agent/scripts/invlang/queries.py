"""Investigation-language query library — backward-compat re-export facade.

All public symbols are defined in the submodules below; this file re-exports
them so that existing `from invlang.queries import ...` calls continue to work.

Submodules (import directly for finer-grained dependencies):
  queries_lookup       — classes 1–7 (field lookups, trace scans)
  queries_effectiveness — class 8 (lead effectiveness + topology/prologue retrieval)
  queries_cache        — class 8c (loop-N lead distribution, cache-key lookup)
  queries_mining       — classes 9–12 (weight reversal, synergy, recovery, datasource)
  queries_recall       — vertex-where filter, classes 13–14 (exemplars, authz calibration)
  queries_enum         — corpus enumeration
"""

from __future__ import annotations

# Shared helpers (also re-exported for cli.py back-compat)
from ._shared import companion_signature_id, _parse_created_at  # noqa: F401

# Classes 1–7
from .queries_lookup import (  # noqa: F401
    anchor_calibration,
    coarse_case_lookup,
    dead_lead_lookup,
    hypothesis_name_wildcard,
    lead_sequence_pattern,
    prose_substring,
    refinement_chain_shapes,
)

# Class 8 + topology / prologue retrieval
from .queries_effectiveness import (  # noqa: F401
    lead_discrimination_score,
    lead_effectiveness,
    lead_effectiveness_for_hypothesis,
    lead_effectiveness_for_prologue,
    lead_effectiveness_for_topology,
    peer_hypothesis_distribution_for_prologue,
    peer_hypothesis_distribution_for_topology,
    prologue_signature,
)

# Class 8c
from .queries_cache import (  # noqa: F401
    key_attribute_signature,
    loop_lead_distribution,
)

# Classes 9–12
from .queries_mining import (  # noqa: F401
    independent_datasource_metric,
    lead_pair_synergy,
    post_failure_recovery,
    weight_reversal_mining,
)

# Vertex-where filter + classes 13–14
from .queries_recall import (  # noqa: F401
    authorization_calibration,
    lead_exemplars,
    parse_vertex_where_spec,
    _parse_vertex_where_spec,
    _vertex_where_match,
)

# Enumeration
from .queries_enum import (  # noqa: F401
    ENUM_CHOICES,
    enumerate_corpus,
    enumerate_hypothesis_tree,
)
