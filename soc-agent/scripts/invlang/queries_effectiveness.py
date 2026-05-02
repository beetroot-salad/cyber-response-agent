"""Query class 8: lead effectiveness, plus topology- and prologue-conditioned retrieval.

Public functions:
  lead_effectiveness                        — [PREDICT] score all leads on two orthogonal axes
  lead_effectiveness_for_hypothesis         — [PREDICT] lead_effectiveness restricted by hypothesis pattern
  lead_discrimination_score                 — [PREDICT] signed lift: moves H1 up, H2 down
  lead_effectiveness_for_topology           — [PREDICT] pre-baked class-8 for a frontier topology
  peer_hypothesis_distribution_for_topology — [PREDICT] co-proposed classifications at a topology
  prologue_signature                        — fingerprint a prologue for retrieval matching
  lead_effectiveness_for_prologue           — [PREDICT] lead_effectiveness keyed on prologue shape
  peer_hypothesis_distribution_for_prologue — [PREDICT] classification distribution for prologue shape
"""

from __future__ import annotations

import fnmatch
import sys
from math import log1p
from typing import Any

from .corpus import Companion, conclude_field, hypothesis_topology
from ._shared import (
    _WEIGHT_BUCKETS,
    _abs_delta,
    _build_peer_hits,
    _hypothesis_name,
    _last_weight_map,
    _LEAD_KINDS,
    _lead_kind,
    _signed_delta,
    _sort_effectiveness_rows,
    companion_signature_id,
)


# ---------------------------------------------------------------------------
# Class 8 — lead effectiveness (PREDICT — lead-selection priors)
# ---------------------------------------------------------------------------

def _lead_effectiveness_rows(
    corpus: list[Companion],
    patterns: tuple[str, ...] = (),
    *,
    hypothesis_id_filter: set[tuple[int, str]] | None = None,
) -> list[dict[str, Any]]:
    """Core aggregation for lead_effectiveness and topology/prologue variants.

    patterns — fnmatch patterns, all of which must match a hypothesis name (conjunction).
               Empty = match all hypotheses.
    hypothesis_id_filter — optional `{(case_idx, hypothesis_id)}` restriction, used by
               topology-conditioned callers. When set, takes precedence over `patterns`.

    Scores per lead name (both count-weighted and per-occurrence forms):
      branching_delta        — log1p(count) × mean_abs_weight_delta (count-weighted;
                               retained for CLI class 8 compat).
      mean_branching_delta   — per-occurrence mean_abs_weight_delta. Use this for
                               retrieval ranking; `branching_support` is its n.
      prediction_fidelity    — log1p(count) × route-match rate (count-weighted).
      fidelity_rate          — per-occurrence route-match rate. `fidelity_support` is n.
      kind_mix               — histogram of kinds for this lead name across the corpus.
    """
    def matches(case_idx: int, hyp_id: str, h_name: str) -> bool:
        if hypothesis_id_filter is not None:
            return (case_idx, hyp_id) in hypothesis_id_filter
        return all(fnmatch.fnmatchcase(h_name, p) for p in patterns)

    filter_active = bool(patterns) or hypothesis_id_filter is not None

    branching_deltas: dict[str, list[float]] = {}
    fidelity_hits: dict[str, list[int]] = {}  # 1 if route matched, 0 otherwise
    kind_mix: dict[str, dict[str, int]] = {}
    total_counts: dict[str, int] = {}

    for case_idx, c in enumerate(corpus):
        h_names: dict[str, str] = {
            h["id"]: _hypothesis_name(h) for h in c.iter_new_hypotheses()
        }
        leads = c.leads
        for idx, lead in enumerate(leads):
            name = lead.get("name", "?")
            kind = _lead_kind(lead)

            # Filter applies per-score, not per-lead: a hypothesis filter
            # excludes a lead from the branching-delta accounting when its
            # resolutions never touched a matching hypothesis, but the lead's
            # interpretive routing (prediction_fidelity) and kind_mix are
            # orthogonal to resolution targeting — gathering-dominant leads
            # should remain visible. Only drop the lead entirely when no score
            # would accept it.
            touches_filter = True
            if filter_active:
                touches_filter = any(
                    matches(
                        case_idx,
                        r.get("hypothesis", ""),
                        h_names.get(r.get("hypothesis", ""), ""),
                    )
                    for r in (lead.get("resolutions", []) or [])
                )
                # If the lead has no branching contribution and no predictions,
                # the filter has nothing orthogonal to preserve — skip.
                if not touches_filter and not lead.get("predictions"):
                    continue

            total_counts[name] = total_counts.get(name, 0) + 1
            kind_mix.setdefault(name, {k: 0 for k in _LEAD_KINDS})[kind] += 1

            # Branching-delta: only over leads with declared tests (fork-collapsing)
            # AND (if filter set) touching a matching hypothesis.
            if lead.get("tests") and touches_filter:
                resolutions = lead.get("resolutions", []) or []
                deltas = [
                    _abs_delta(r.get("before"), r.get("after"))
                    for r in resolutions
                    if not filter_active or matches(
                        case_idx,
                        r.get("hypothesis", ""),
                        h_names.get(r.get("hypothesis", ""), ""),
                    )
                ]
                if deltas:
                    branching_deltas.setdefault(name, []).append(sum(deltas) / len(deltas))

            # Prediction-fidelity: route compliance for leads with predictions.
            # Orthogonal to the hypothesis filter.
            if lead.get("predictions"):
                advance_tos = {
                    p.get("advance_to")
                    for p in (lead.get("predictions") or [])
                    if isinstance(p, dict) and p.get("advance_to")
                }
                next_lead_name = leads[idx + 1].get("name") if idx + 1 < len(leads) else None
                if next_lead_name is None:
                    matched = "REPORT" in advance_tos
                else:
                    matched = next_lead_name in advance_tos
                fidelity_hits.setdefault(name, []).append(1 if matched else 0)

    rows: list[dict[str, Any]] = []
    for name in sorted(total_counts.keys()):
        count = total_counts[name]
        bd = branching_deltas.get(name, [])
        if bd:
            mean_bd = sum(bd) / len(bd)
            branching_delta = round(log1p(len(bd)) * mean_bd, 4)
            mean_branching_delta = round(mean_bd, 4)
        else:
            branching_delta = None
            mean_branching_delta = None

        fh = fidelity_hits.get(name, [])
        if fh:
            rate = sum(fh) / len(fh)
            prediction_fidelity = round(log1p(len(fh)) * rate, 4)
            fidelity_rate = round(rate, 4)
        else:
            prediction_fidelity = None
            fidelity_rate = None

        rows.append({
            "lead_name": name,
            "count": count,
            "branching_delta": branching_delta,
            "prediction_fidelity": prediction_fidelity,
            "mean_branching_delta": mean_branching_delta,
            "fidelity_rate": fidelity_rate,
            "branching_support": len(bd),
            "fidelity_support": len(fh),
            "kind_mix": kind_mix[name],
        })

    # Sort: branching_delta desc, then prediction_fidelity desc, then count desc.
    # None sorts as -inf so non-scoring leads fall to the bottom within each tier.
    rows.sort(
        key=lambda r: (
            r["branching_delta"] if r["branching_delta"] is not None else float("-inf"),
            r["prediction_fidelity"] if r["prediction_fidelity"] is not None else float("-inf"),
            r["count"],
        ),
        reverse=True,
    )
    return rows


def lead_effectiveness(corpus: list[Companion]) -> dict[str, Any]:
    """Score each lead name on two orthogonal axes plus a kind histogram.

    branching_delta     — log1p(count_branching) × mean_abs_weight_delta. None if
                          the lead never appeared in a branching (fork-collapsing)
                          form — correct handling of pure-gathering leads rather
                          than penalising them as "low effectiveness."
    prediction_fidelity — log1p(count_interpretive) × route-match rate. None if
                          the lead never carried pre-committed `predictions`.
    kind_mix            — histogram over {branching, interpretive, trust, fail,
                          mechanical} for this lead name.
    """
    rows = _lead_effectiveness_rows(corpus)
    return {"hits": rows, "count": len(rows)}


def lead_effectiveness_for_hypothesis(
    corpus: list[Companion],
    *patterns: str,
) -> dict[str, Any]:
    """Lead effectiveness restricted to hypotheses matching ALL supplied fnmatch patterns.

    Patterns are AND-ed: a resolution counts only when its hypothesis name satisfies
    every pattern. Leads that never touched a matching hypothesis are excluded.
    """
    if not patterns:
        raise ValueError("supply at least one fnmatch pattern")
    rows = _lead_effectiveness_rows(corpus, patterns)
    if not rows:
        print(
            f"warning: no leads touched hypotheses matching all of {list(patterns)}. "
            "Run --enumerate hypotheses to see the full hypothesis vocabulary in this corpus.",
            file=sys.stderr,
        )
    return {"hits": rows, "count": len(rows), "patterns": list(patterns)}


def lead_discrimination_score(
    corpus: list[Companion],
    pattern1: str,
    pattern2: str,
) -> dict[str, Any]:
    """Score each lead by how consistently it moves H1 positively and H2 negatively.

    For each lead, across cases where both hypothesis patterns are present,
    computes: mean(signed_delta_H1) - mean(signed_delta_H2).

    A lead scoring high positively: moves H1 upward, H2 downward.
    A lead scoring high negatively: moves H2 upward, H1 downward.

    Returns hits sorted by abs(discrimination_score) desc.
    """
    per_lead: dict[str, list[tuple[float, float]]] = {}

    for c in corpus:
        h_names: dict[str, str] = {
            h["id"]: _hypothesis_name(h) for h in c.iter_new_hypotheses()
        }
        has_p1 = any(fnmatch.fnmatchcase(name, pattern1) for name in h_names.values())
        has_p2 = any(fnmatch.fnmatchcase(name, pattern2) for name in h_names.values())
        if not (has_p1 and has_p2):
            continue

        for lead in c.leads:
            resolutions = lead.get("resolutions", []) or []
            deltas_h1 = [
                _signed_delta(r.get("before"), r.get("after"))
                for r in resolutions
                if fnmatch.fnmatchcase(h_names.get(r.get("hypothesis", ""), ""), pattern1)
            ]
            deltas_h2 = [
                _signed_delta(r.get("before"), r.get("after"))
                for r in resolutions
                if fnmatch.fnmatchcase(h_names.get(r.get("hypothesis", ""), ""), pattern2)
            ]
            mean_h1 = sum(deltas_h1) / len(deltas_h1) if deltas_h1 else 0.0
            mean_h2 = sum(deltas_h2) / len(deltas_h2) if deltas_h2 else 0.0
            per_lead.setdefault(lead.get("name", "?"), []).append((mean_h1, mean_h2))

    rows: list[dict[str, Any]] = []
    for name, case_pairs in per_lead.items():
        case_count = len(case_pairs)
        mean_h1 = sum(p[0] for p in case_pairs) / case_count
        mean_h2 = sum(p[1] for p in case_pairs) / case_count
        disc = mean_h1 - mean_h2
        rows.append({
            "lead_name": name,
            "discrimination_score": round(disc, 4),
            "mean_signed_delta_h1": round(mean_h1, 4),
            "mean_signed_delta_h2": round(mean_h2, 4),
            "case_count": case_count,
        })
    rows.sort(key=lambda r: abs(float(r["discrimination_score"])), reverse=True)
    if not rows:
        print(
            f"warning: no cases contain hypotheses matching both {pattern1!r} and {pattern2!r}.\n"
            "  Patterns use fnmatch syntax against hypothesis names (which start with '?').\n"
            "  Example: --discriminate-between '?*scanner*' '?*targeted*'\n"
            "  Run --enumerate hypotheses to see the exact vocabulary in this corpus.",
            file=sys.stderr,
        )
    return {"hits": rows, "count": len(rows), "pattern1": pattern1, "pattern2": pattern2}


# ---------------------------------------------------------------------------
# Topology-conditioned retrieval (handler-facing)
# ---------------------------------------------------------------------------

# Labels describe the *cumulative* relaxation at each tier.
_TIER_LABELS = {
    0: "exact",
    1: "dropped parent-class",
    2: "also dropped parent-type",
    3: "also dropped attached-class",
    4: "name-glob fallback",
}


def _fp_get(fp: dict[str, Any], *path: str) -> Any:
    cur: Any = fp
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _topology_match_at_tier(fp_case: dict[str, Any], fp_query: dict[str, Any], tier: int) -> bool:
    """Return True when a case-side fingerprint matches the query at the given tier.

    Tiers narrow the match by dropping fields cumulatively:
      0 — exact: attached.type, attached.class, relation, parent.type, parent.class
      1 — drop parent.classification
      2 — also drop parent.type
      3 — also drop attached.classification
      4 — name-glob fallback (handled in the caller, not here)

    Any required field that's None on either side fails the match at tiers 0–3.
    """
    if tier >= 4:
        return False

    pairs: list[tuple[Any, Any]] = [
        (_fp_get(fp_case, "attached_vertex", "type"), _fp_get(fp_query, "attached_vertex", "type")),
        (_fp_get(fp_case, "relation"), _fp_get(fp_query, "relation")),
    ]
    if tier <= 2:
        pairs.append((
            _fp_get(fp_case, "attached_vertex", "classification"),
            _fp_get(fp_query, "attached_vertex", "classification"),
        ))
    if tier <= 1:
        pairs.append(
            (_fp_get(fp_case, "parent_vertex", "type"), _fp_get(fp_query, "parent_vertex", "type"))
        )
    if tier <= 0:
        pairs.append((
            _fp_get(fp_case, "parent_vertex", "classification"),
            _fp_get(fp_query, "parent_vertex", "classification"),
        ))

    for case_val, query_val in pairs:
        if case_val is None or query_val is None:
            return False
        if case_val != query_val:
            return False
    return True


def _collect_topology_ids(
    corpus: list[Companion],
    fp_query: dict[str, Any],
    tier: int,
) -> set[tuple[int, str]]:
    """Return {(case_idx, hypothesis_id)} for hypotheses matching `fp_query` at `tier`.

    Tier 4 uses fnmatch on hypothesis name, keyed on parent_vertex.classification:
        ?<parent-class>*  (matches '?authorized-monitoring-probe', '?monitoring-probe', …)
    When parent classification is missing at tier 4, returns the empty set.
    """
    out: set[tuple[int, str]] = set()
    if tier == 4:
        parent_class = _fp_get(fp_query, "parent_vertex", "classification")
        if not parent_class:
            return out
        name_pattern = f"?*{parent_class}*"
        for case_idx, c in enumerate(corpus):
            for h in c.iter_new_hypotheses():
                h_id = h.get("id")
                h_name = _hypothesis_name(h)
                if not h_id or not h_name:
                    continue
                if fnmatch.fnmatchcase(h_name, name_pattern):
                    out.add((case_idx, h_id))
        return out

    for case_idx, c in enumerate(corpus):
        prologue = c.prologue
        siblings = c.hypotheses
        for h in c.iter_new_hypotheses():
            h_id = h.get("id")
            if not h_id:
                continue
            fp_case = hypothesis_topology(prologue, h, siblings)
            if _topology_match_at_tier(fp_case, fp_query, tier):
                out.add((case_idx, h_id))
    return out


def _walk_tiers(
    corpus: list[Companion],
    fp_query: dict[str, Any],
) -> tuple[set[tuple[int, str]], int]:
    """Walk tiers 0→4; return (matched_ids, tier_used). Empty set → tier 4."""
    for tier in range(0, 5):
        ids = _collect_topology_ids(corpus, fp_query, tier)
        if ids:
            return ids, tier
    return set(), 4


def lead_effectiveness_for_topology(
    corpus: list[Companion],
    fp: dict[str, Any],
) -> dict[str, Any]:
    """Lead effectiveness ranked for a topology fingerprint.

    Walks tiers 0→4 (exact → name-glob) and returns the first non-empty tier's
    rows ranked by per-occurrence effectiveness.

    Returns `{hits, count, tier_used, tier_label}`. When no tier produces hits,
    returns `{hits: [], count: 0, tier_used: 4, tier_label: "no match"}`.
    """
    ids, tier_used = _walk_tiers(corpus, fp)
    if not ids:
        return {"hits": [], "count": 0, "tier_used": 4, "tier_label": "no match"}
    rows = _lead_effectiveness_rows(corpus, hypothesis_id_filter=ids)
    _sort_effectiveness_rows(rows)
    return {
        "hits": rows,
        "count": len(rows),
        "tier_used": tier_used,
        "tier_label": _TIER_LABELS[tier_used],
    }


def peer_hypothesis_distribution_for_topology(
    corpus: list[Companion],
    fp: dict[str, Any],
) -> dict[str, Any]:
    """Peer-classification distribution for a topology fingerprint.

    For each hypothesis in the corpus matching the topology at the first
    non-empty tier, enumerate its co-attached peers (other hypotheses in the
    same `hypothesize:` block of the same case) and aggregate:

      [{classification, peer_count, final_weight_histogram}]

    Returns `{hits, count, tier_used, tier_label}`.
    """
    ids, tier_used = _walk_tiers(corpus, fp)
    if not ids:
        return {"hits": [], "count": 0, "tier_used": 4, "tier_label": "no match"}

    cases_in_scope: set[int] = {case_idx for case_idx, _ in ids}

    peer_counts: dict[str, int] = {}
    peer_weights: dict[str, dict[str, int]] = {}

    for case_idx in cases_in_scope:
        c = corpus[case_idx]
        last_weight = _last_weight_map(c)
        seen_this_case: set[str] = set()
        for sib in c.hypotheses:
            classification = _hypothesis_name(sib)
            sib_id = sib.get("id")
            if not classification or not sib_id or classification in seen_this_case:
                continue
            seen_this_case.add(classification)
            peer_counts[classification] = peer_counts.get(classification, 0) + 1
            bucket_key = "null" if last_weight.get(sib_id) is None else str(last_weight[sib_id])
            hist = peer_weights.setdefault(classification, {b: 0 for b in _WEIGHT_BUCKETS})
            if bucket_key in hist:
                hist[bucket_key] += 1

    hits = _build_peer_hits(peer_counts, peer_weights)
    return {
        "hits": hits,
        "count": len(hits),
        "tier_used": tier_used,
        "tier_label": _TIER_LABELS[tier_used],
    }


# ---------------------------------------------------------------------------
# Prologue-keyed retrieval (loop-1 priors — no hypothesis yet)
# ---------------------------------------------------------------------------
# At loop 1 the frontier has no proposed upstream edges, so hypothesis_topology
# fingerprints cannot match tiers 0–3. This section keys retrieval off the
# *prologue* instead: dense at loop 1, carries the alert topology directly,
# and matches across hypothesis-name drift.

_PROLOGUE_TIER_LABELS = {
    0: "exact vertex+edge shape",
    1: "vertex-type set exact",
    2: "vertex-type set overlap",
    3: "no match",
}


def prologue_signature(prologue: dict[str, Any]) -> dict[str, Any]:
    """Frozen signature for prologue-shape retrieval.

    Returns `{vertex_types, vertex_classifications, edge_relations}` — three
    frozensets. Missing values are dropped.
    """
    if not isinstance(prologue, dict):
        return {"vertex_types": frozenset(), "vertex_classifications": frozenset(), "edge_relations": frozenset()}

    vertices = prologue.get("vertices") or []
    edges = prologue.get("edges") or []
    v_types: set[str] = set()
    v_classes: set[str] = set()
    for v in vertices:
        if not isinstance(v, dict):
            continue
        t = v.get("type")
        c = v.get("classification")
        if isinstance(t, str):
            v_types.add(t)
        if isinstance(c, str):
            v_classes.add(c)
    e_rels: set[str] = set()
    for e in edges:
        if not isinstance(e, dict):
            continue
        r = e.get("relation")
        if isinstance(r, str):
            e_rels.add(r)
    return {
        "vertex_types": frozenset(v_types),
        "vertex_classifications": frozenset(v_classes),
        "edge_relations": frozenset(e_rels),
    }


def _prologue_tier_match(case_sig: dict[str, Any], query_sig: dict[str, Any], tier: int) -> bool:
    """Three-tier prologue matcher.

      0 — exact: vertex_types == AND edge_relations ==
      1 — vertex_types == (ignore edges)
      2 — vertex_types & query != ∅  (any overlap)
      3 — no match
    """
    if tier >= 3:
        return False
    qv, cv = query_sig["vertex_types"], case_sig["vertex_types"]
    qe, ce = query_sig["edge_relations"], case_sig["edge_relations"]
    if tier == 0:
        return qv == cv and qe == ce
    if tier == 1:
        return qv == cv
    if tier == 2:
        return bool(qv & cv)
    return False


def _walk_prologue_tiers(
    corpus: list[Companion],
    query_sig: dict[str, Any],
    *,
    signature_id: str | None,
) -> tuple[list[int], int]:
    """Return `(case_indices, tier_used)`. Empty → tier 3."""
    scoped = [
        i for i, c in enumerate(corpus)
        if signature_id is None or companion_signature_id(c) == signature_id
    ]
    for tier in range(0, 3):
        hits: list[int] = []
        for i in scoped:
            case_sig = prologue_signature(corpus[i].prologue)
            if _prologue_tier_match(case_sig, query_sig, tier):
                hits.append(i)
        if hits:
            return hits, tier
    return [], 3


def lead_effectiveness_for_prologue(
    corpus: list[Companion],
    prologue: dict[str, Any],
    *,
    signature_id: str | None = None,
) -> dict[str, Any]:
    """Lead effectiveness across past cases whose prologue shape matches.

    `signature_id` — when provided, restricts the scope to same-signature past
    cases. Pass `None` for cross-signature retrieval.

    Returns `{hits, count, tier_used, tier_label, cases_matched}`.
    """
    query_sig = prologue_signature(prologue)
    case_indices, tier_used = _walk_prologue_tiers(
        corpus, query_sig, signature_id=signature_id
    )
    if not case_indices:
        return {
            "hits": [], "count": 0,
            "tier_used": 3, "tier_label": _PROLOGUE_TIER_LABELS[3],
            "cases_matched": 0,
        }
    hypothesis_ids: set[tuple[int, str]] = set()
    for case_idx in case_indices:
        for h in corpus[case_idx].iter_new_hypotheses():
            hid = h.get("id")
            if hid:
                hypothesis_ids.add((case_idx, hid))
    rows = _lead_effectiveness_rows(corpus, hypothesis_id_filter=hypothesis_ids)
    _sort_effectiveness_rows(rows)
    return {
        "hits": rows,
        "count": len(rows),
        "tier_used": tier_used,
        "tier_label": _PROLOGUE_TIER_LABELS[tier_used],
        "cases_matched": len(case_indices),
    }


def peer_hypothesis_distribution_for_prologue(
    corpus: list[Companion],
    prologue: dict[str, Any],
    *,
    signature_id: str | None = None,
) -> dict[str, Any]:
    """Classification distribution of hypotheses proposed across prologue-matching cases.

    One entry per distinct `?<name>`; counts cases (dedup within case), and
    carries the final-weight histogram.
    """
    query_sig = prologue_signature(prologue)
    case_indices, tier_used = _walk_prologue_tiers(
        corpus, query_sig, signature_id=signature_id
    )
    if not case_indices:
        return {
            "hits": [], "count": 0,
            "tier_used": 3, "tier_label": _PROLOGUE_TIER_LABELS[3],
            "cases_matched": 0,
        }
    peer_counts: dict[str, int] = {}
    peer_weights: dict[str, dict[str, int]] = {}
    for case_idx in case_indices:
        c = corpus[case_idx]
        last_weight = _last_weight_map(c)
        seen: set[str] = set()
        for sib in c.iter_new_hypotheses():
            classification = _hypothesis_name(sib)
            sib_id = sib.get("id")
            if not classification or not sib_id or classification in seen:
                continue
            seen.add(classification)
            peer_counts[classification] = peer_counts.get(classification, 0) + 1
            bucket_key = "null" if last_weight.get(sib_id) is None else str(last_weight[sib_id])
            hist = peer_weights.setdefault(classification, {b: 0 for b in _WEIGHT_BUCKETS})
            if bucket_key in hist:
                hist[bucket_key] += 1
    hits = _build_peer_hits(peer_counts, peer_weights)
    return {
        "hits": hits,
        "count": len(hits),
        "tier_used": tier_used,
        "tier_label": _PROLOGUE_TIER_LABELS[tier_used],
        "cases_matched": len(case_indices),
    }
