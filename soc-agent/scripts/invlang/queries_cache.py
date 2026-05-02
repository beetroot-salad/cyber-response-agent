"""Query class 8c: cache-key-shaped loop-N lead distribution.

Public functions:
  key_attribute_signature  — bucket prologue vertex identifiers into family signatures
  loop_lead_distribution   — [PREDICT] recall the primary lead chosen at loop N

Distinct from lead_effectiveness_* in queries_effectiveness.py:
  - those score "how well a lead performed" across all loops in matched cases
  - this records "what lead was picked" at exactly one loop in cases whose
    cache key matches today's alert (memoize the past PREDICT decision).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, UTC
from typing import Any

from .corpus import Companion
from ._shared import _parse_created_at, companion_signature_id
from .queries_effectiveness import prologue_signature


# ---------------------------------------------------------------------------
# Key-attribute family signature
# ---------------------------------------------------------------------------

def key_attribute_signature(
    prologue: dict[str, Any],
    discriminating_classifications: dict[str, list[str]],
) -> frozenset[tuple[str, str]]:
    """Bucket vertex identifiers into family signatures per playbook policy.

    For each prologue vertex whose `classification` appears in
    `discriminating_classifications`, emit `(classification, family_bucket)`
    where `family_bucket` is `"family_<idx>"` for the first matching pattern
    or `"no-match"` when the identifier matches none. Two prologues with the
    same topology but identifiers in different family buckets produce
    different signatures — the adversarial-collision guard.
    """
    out: set[tuple[str, str]] = set()
    for v in prologue.get("vertices") or []:
        if not isinstance(v, dict):
            continue
        cls = v.get("classification")
        if not isinstance(cls, str):
            continue
        patterns = discriminating_classifications.get(cls)
        if not patterns:
            continue
        ident = v.get("identifier") or ""
        if not isinstance(ident, str):
            ident = str(ident)
        bucket = "no-match"
        for idx, pat in enumerate(patterns):
            try:
                if re.match(pat, ident):
                    bucket = f"family_{idx}"
                    break
            except re.error:
                continue
        out.add((cls, bucket))
    return frozenset(out)


def _exact_prologue_match(
    case_prologue: dict[str, Any], query_prologue: dict[str, Any]
) -> bool:
    """All three frozensets equal: vertex_types, vertex_classifications, edge_relations.

    Stricter than _prologue_tier_match tier 0 — the cache lookup needs full
    equality so a different classification set never produces a hit.
    """
    cs = prologue_signature(case_prologue)
    qs = prologue_signature(query_prologue)
    return (
        cs["vertex_types"] == qs["vertex_types"]
        and cs["vertex_classifications"] == qs["vertex_classifications"]
        and cs["edge_relations"] == qs["edge_relations"]
    )


def _primary_lead_at_loop(c: Companion, loop: int) -> str | None:
    """The first lead entry stamped with `loop` is the PREDICT-selected lead.

    Composite dispatches emit secondary leads at the same loop, but the
    primary `selected_lead` lands first by the gather handler's ordering.
    Returns None when no findings entry carries this loop.
    """
    for lead in c.leads:
        if lead.get("loop") == loop:
            name = lead.get("name")
            return name if isinstance(name, str) else None
    return None


# ---------------------------------------------------------------------------
# Class 8c — loop-N lead distribution
# ---------------------------------------------------------------------------

def loop_lead_distribution(
    corpus: list[Companion],
    *,
    signature_id: str,
    prologue: dict[str, Any],
    discriminating_classifications: dict[str, list[str]] | None,
    loop: int = 1,
    max_age_days: int = 180,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Cache-key-shaped lookup over the corpus for past loop-N lead choices.

    Filters companions by:
      - signature_id exact
      - created_at present AND within `max_age_days` of `now`
      - prologue topology exact (vertex_types / vertex_classifications /
        edge_relations equal)
      - key-attribute family signature exact (per `discriminating_classifications`)

    Aggregates the primary lead at `loop` (first findings[] entry stamped
    with that loop number) per surviving companion.

    `discriminating_classifications=None` → no fast-path opt-in for this
    signature; returns an empty distribution with telemetry showing
    `scoped_key_attrs=0`.

    Returns:
      {
        distribution:    {lead_name: count, ...},  # sorted desc
        matched_case_ids: [...],
        telemetry: {
          scoped_signature, scoped_recent, scoped_prologue, scoped_key_attrs,
          loop, max_age_days,
        },
      }
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=max_age_days)

    if discriminating_classifications is None:
        return {
            "distribution": {},
            "matched_case_ids": [],
            "telemetry": {
                "scoped_signature": 0,
                "scoped_recent": 0,
                "scoped_prologue": 0,
                "scoped_key_attrs": 0,
                "loop": loop,
                "max_age_days": max_age_days,
            },
        }

    target_key_attrs = key_attribute_signature(prologue, discriminating_classifications)

    scoped_sig = [c for c in corpus if companion_signature_id(c) == signature_id]
    scoped_recent: list[Companion] = []
    for c in scoped_sig:
        ts = _parse_created_at(c.created_at)
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        if ts >= cutoff:
            scoped_recent.append(c)

    scoped_prologue = [
        c for c in scoped_recent if _exact_prologue_match(c.prologue, prologue)
    ]
    scoped_key_attrs = [
        c for c in scoped_prologue
        if key_attribute_signature(c.prologue, discriminating_classifications)
        == target_key_attrs
    ]

    distribution: dict[str, int] = {}
    matched_ids: list[str] = []
    for c in scoped_key_attrs:
        lead_name = _primary_lead_at_loop(c, loop)
        if lead_name is None:
            continue
        distribution[lead_name] = distribution.get(lead_name, 0) + 1
        matched_ids.append(c.case_id)

    sorted_dist = dict(
        sorted(distribution.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return {
        "distribution": sorted_dist,
        "matched_case_ids": matched_ids,
        "telemetry": {
            "scoped_signature": len(scoped_sig),
            "scoped_recent": len(scoped_recent),
            "scoped_prologue": len(scoped_prologue),
            "scoped_key_attrs": len(scoped_key_attrs),
            "loop": loop,
            "max_age_days": max_age_days,
        },
    }
