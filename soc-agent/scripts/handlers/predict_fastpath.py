"""PREDICT loop-1 fast-path — cache lookup over past investigations.

Memoizes the question "what lead would the predict subagent select at loop 1
given this prologue topology + key-attribute family signature?" The corpus
is the cache; this module is the lookup. A cache miss falls through to the
existing PREDICT subagent path — wrong-answer risk requires a wrong cache
*entry*, not a wrong *prediction*.

Cache key components (all four):
  - signature_id                — exact playbook
  - prologue topology signature — vertex_types / vertex_classifications /
                                  edge_relations (frozensets) all equal
  - key-attribute signature     — per-classification regex-family bucket
                                  per playbook frontmatter (the
                                  adversarial-collision guard)
  - frontier signature          — None at loop 1; placeholder slot for
                                  loop-N expansion later

Selection (when ≥ min_support primary leads aggregate at this key):
  - one lead seen above threshold → "single" pick (deterministic)
  - several leads each above threshold → "weighted" pick (sampled by count
    among the top-K). Bounded to leads that all individually clear the gate
    so the safety contract still holds.

Public surface:
  - build_cache_key(...)         — pure constructor (no I/O)
  - lookup(corpus, key, ...)     — returns FastpathHit | None
  - FastpathHit                  — dataclass

The handler is responsible for the actual side effects (writing the marker
section, writing the JSONL log, returning a PhaseResult). This module is
pure aside from the optional injectable RNG.
"""

from __future__ import annotations

import random as _random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from invlang.corpus import Companion
from invlang.queries import (
    key_attribute_signature,
    loop_lead_distribution,
    prologue_signature,
)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_MIN_SUPPORT = 3        # ≥3 companions must have picked a lead
DEFAULT_TOP_K = 3              # consider at most the 3 most-picked leads
DEFAULT_MAX_AGE_DAYS = 180     # 6-month recency window


# ---------------------------------------------------------------------------
# Cache key + hit
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheKey:
    """Tuple-shaped cache key for the PREDICT lead-choice cache.

    Loop 1 cache key = (signature_id, prologue topology, key-attribute family).
    Loop N cache key = loop-1 key PLUS `frontier_signature` — a frozen summary
    of the *upstream proposed frontier* the agent is choosing a discriminating
    lead against. Two loop-2 states with the same prologue but different
    proposed-parent classifications must produce different cache keys, or the
    fast-path would memoize the wrong decision.

    `frontier_signature` is `None` at loop 1 because the frontier doesn't
    exist yet (PREDICT loop 1 *creates* it). The placeholder slot exists so
    loop-N support is a parameter change — derive a signature from the active
    `hypothesize` block's proposed_edge.parent_vertex classifications + edge
    relations, plug it in, and the lookup naturally narrows to companions
    that faced the same upstream branch.

    The current `lookup()` returns a structured miss with
    `frontier_not_supported: true` in telemetry when this is non-None, so an
    accidental loop-N invocation can't fabricate an answer before the corpus
    query supports it.
    """
    signature_id: str
    prologue_signature: dict[str, Any]
    key_attribute_signature: frozenset[tuple[str, str]]
    # TODO(loop-N): tighten to `frozenset[tuple[str, str]] | None` once the
    # frontier-signature derivation lands. `Any | None` today reflects that
    # the shape is not yet pinned.
    frontier_signature: Any | None = None

    def to_log_dict(self) -> dict[str, Any]:
        """JSON-safe shape for the priors JSONL log line."""
        return {
            "signature_id": self.signature_id,
            "prologue_signature": {
                k: sorted(v) for k, v in self.prologue_signature.items()
            },
            "key_attribute_signature": sorted(
                [list(t) for t in self.key_attribute_signature]
            ),
            "frontier_signature": self.frontier_signature,
        }


@dataclass
class FastpathHit:
    """A successful cache lookup."""
    selected_lead: str
    selection_method: str  # "single" | "weighted"
    lead_distribution: dict[str, int]   # full {lead: count} returned
    matched_case_ids: list[str]
    telemetry: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def build_cache_key(
    *,
    signature_id: str,
    prologue: dict[str, Any],
    discriminating_classifications: dict[str, list[str]] | None,
    frontier: Any | None = None,
) -> CacheKey | None:
    """Construct the cache key for a (signature, prologue, frontier) triple.

    Returns None when `discriminating_classifications` is missing — the
    signature has not opted into the fast-path (gate is per-signature
    opt-in). The handler treats None as "skip the lookup."
    """
    if discriminating_classifications is None:
        return None
    sig = prologue_signature(prologue)
    return CacheKey(
        signature_id=signature_id,
        prologue_signature={
            "vertex_types": sig["vertex_types"],
            "vertex_classifications": sig["vertex_classifications"],
            "edge_relations": sig["edge_relations"],
        },
        key_attribute_signature=key_attribute_signature(
            prologue, discriminating_classifications
        ),
        frontier_signature=frontier,
    )


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def lookup(
    corpus: list[Companion],
    cache_key: CacheKey,
    *,
    prologue: dict[str, Any],
    discriminating_classifications: dict[str, list[str]],
    lead_catalog: set[str],
    loop: int = 1,
    min_support: int = DEFAULT_MIN_SUPPORT,
    top_k: int = DEFAULT_TOP_K,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    now: datetime | None = None,
    rng: _random.Random | None = None,
) -> tuple[FastpathHit | None, dict[str, Any]]:
    """Cache lookup. Returns `(hit_or_None, telemetry)`.

    Loop-N support: today this only accepts `cache_key.frontier_signature is
    None` (loop 1). When frontier_signature is non-None, returns a miss with
    `frontier_not_supported: true` in telemetry — placeholder that will
    become the loop-N entry point once corpus + query support land.

    Selection:
      - filter: every lead in current `lead_catalog` AND count ≥ min_support
      - if exactly one survives → single pick
      - if several survive → weighted random pick across top-K by count
      - if none survive → cache miss

    Miss interpretation is read from the structured counters (no `reason`
    string): `scoped_signature/recent/prologue/key_attrs` + `lead_distribution`
    + `eligible_leads` together encode every miss mode unambiguously.
    """
    if cache_key.frontier_signature is not None:
        return None, {"frontier_not_supported": True, "loop": loop}

    dist_result = loop_lead_distribution(
        corpus,
        signature_id=cache_key.signature_id,
        prologue=prologue,
        discriminating_classifications=discriminating_classifications,
        loop=loop,
        max_age_days=max_age_days,
        now=now,
    )
    distribution = dist_result["distribution"]
    base_telemetry: dict[str, Any] = {
        "lead_distribution": distribution,
        "matched_case_ids": dist_result["matched_case_ids"],
        **dist_result["telemetry"],
    }

    if not distribution:
        return None, base_telemetry

    eligible = [
        (lead, count) for lead, count in distribution.items()
        if lead in lead_catalog and count >= min_support
    ]
    if not eligible:
        base_telemetry["min_support"] = min_support
        return None, base_telemetry

    eligible.sort(key=lambda pair: (-pair[1], pair[0]))
    top = eligible[:top_k]
    if len(top) == 1:
        chosen, _ = top[0]
        method = "single"
    else:
        # Unseeded `random.Random()` is intentional in production: when several
        # leads each clear the support threshold, sampling proportionally to
        # past-pick frequency load-balances across viable choices instead of
        # always picking the alphabetic-tiebreaker winner. Tests inject a
        # seeded Random for determinism.
        rng = rng or _random.Random()
        leads = [lead for lead, _ in top]
        weights = [count for _, count in top]
        chosen = rng.choices(leads, weights=weights, k=1)[0]
        method = "weighted"

    return (
        FastpathHit(
            selected_lead=chosen,
            selection_method=method,
            lead_distribution=distribution,
            matched_case_ids=dist_result["matched_case_ids"],
            telemetry={
                **base_telemetry,
                "min_support": min_support,
                "top_k": top_k,
                "eligible_leads": [lead for lead, _ in top],
            },
        ),
        {**base_telemetry, "selection_method": method, "selected_lead": chosen},
    )
