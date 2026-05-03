"""Shared constants and helpers used across the invlang query modules.

This module is private to the invlang package — import from queries.py or
specific query submodules, not directly from here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .corpus import Companion


# ---------------------------------------------------------------------------
# Weight / ordering tables
# ---------------------------------------------------------------------------

_WEIGHT_NUMERIC: dict[Any, int] = {None: 0, "++": 2, "+": 1, "-": -1, "--": -2}
_CONFIDENCE_ORDER: dict[str, int] = {"high": 3, "medium": 2, "low": 1}
_FINAL_WEIGHT_SORT: dict[Any, int] = {"++": 4, "+": 3, None: 2, "-": 1, "--": 0}
_WEIGHT_BUCKETS = ("++", "+", "null", "-", "--")


# ---------------------------------------------------------------------------
# Per-hypothesis helpers
# ---------------------------------------------------------------------------

def _hypothesis_name(h: dict[str, Any]) -> str:
    return h.get("name", "") or ""


def _parse_hypothesis_chain(h_id: str) -> list[str]:
    """h-001-002-003 → ['h-001', 'h-001-002', 'h-001-002-003']."""
    parts = h_id.split("-")
    if not parts or parts[0] != "h":
        return [h_id]
    return ["-".join(parts[:i]) for i in range(2, len(parts) + 1)]


# ---------------------------------------------------------------------------
# Per-lead helpers
# ---------------------------------------------------------------------------

_LEAD_KINDS = ("branching", "interpretive", "trust", "fail", "mechanical")


def _lead_kind(lead: dict[str, Any]) -> str:
    """Classify a lead by its declared schema shape.

    consult:      outcome.anchor_consultations[] non-empty
    fail:         outcome.failure_reason present
    branching:    lead.tests non-empty (collapses a hypothesis fork)
    interpretive: lead.predictions non-empty (pre-committed reading)
    mechanical:   none of the above — pure enrichment
    """
    outcome = lead.get("outcome") or {}
    if outcome.get("failure_reason"):
        return "fail"
    if outcome.get("anchor_consultations"):
        return "consult"
    if lead.get("tests"):
        return "branching"
    if lead.get("predictions"):
        return "interpretive"
    return "mechanical"


def _abs_delta(before: Any, after: Any) -> float:
    return abs(_WEIGHT_NUMERIC.get(after, 0) - _WEIGHT_NUMERIC.get(before, 0))


def _signed_delta(before: Any, after: Any) -> float:
    return float(_WEIGHT_NUMERIC.get(after, 0) - _WEIGHT_NUMERIC.get(before, 0))


# ---------------------------------------------------------------------------
# Shared aggregation helpers (used across multiple query modules)
# ---------------------------------------------------------------------------

def _last_weight_map(c: Companion) -> dict[str, Any]:
    """Last resolution weight per hypothesis_id across all leads."""
    weights: dict[str, Any] = {}
    for lead in c.leads:
        for r in lead.get("resolutions", []) or []:
            h_id = r.get("hypothesis")
            if h_id:
                weights[h_id] = r.get("after")
    return weights


def _build_peer_hits(
    peer_counts: dict[str, int],
    peer_weights: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    return [
        {
            "classification": name,
            "peer_count": peer_counts[name],
            "final_weight_histogram": peer_weights[name],
        }
        for name in sorted(peer_counts.keys(), key=lambda n: (-peer_counts[n], n))
    ]


def _sort_effectiveness_rows(rows: list[dict[str, Any]]) -> None:
    rows.sort(
        key=lambda r: (
            r["mean_branching_delta"] if r["mean_branching_delta"] is not None else float("-inf"),
            r["fidelity_rate"] if r["fidelity_rate"] is not None else float("-inf"),
            r["branching_support"],
        ),
        reverse=True,
    )


# ---------------------------------------------------------------------------
# Timestamp / companion helpers
# ---------------------------------------------------------------------------

def _parse_created_at(ts: str | None) -> datetime | None:
    """ISO-8601 parse for Companion.created_at. Parse failures treated as absent."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def companion_signature_id(c: Companion) -> str | None:
    from .corpus import signature_id_from_path
    return signature_id_from_path(c.source_path)
