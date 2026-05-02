"""Query classes 9–12: weight-reversal mining, pair synergy, failure recovery, datasource metric.

Classes:
  9  weight_reversal_mining      — [ANALYZE]  resolutions where weight moved positive→negative
  10 lead_pair_synergy           — [PREDICT]  composite-dispatch pairs where combined > individual
  11 post_failure_recovery       — [GATHER]   after a dead lead, what lead came next?
  12 independent_datasource_metric — [REPORT] distinct system count per case, grouped by disposition
"""

from __future__ import annotations

import fnmatch
import sys
from typing import Any

import polars as pl

from .corpus import Companion, conclude_field
from ._shared import _abs_delta, _hypothesis_name, _signed_delta


_POSITIVE_WEIGHTS = {None, "+", "++"}
_NEGATIVE_WEIGHTS = {"-", "--"}


# ---------------------------------------------------------------------------
# Class 9 — weight-reversal mining (ANALYZE — pitfall extraction)
# ---------------------------------------------------------------------------

def weight_reversal_mining(
    corpus: list[Companion],
    *,
    hypothesis_pattern: str | None = None,
    reversals_only: bool = False,
) -> dict[str, Any]:
    """Find resolutions where hypothesis weight moved from positive to negative.

    'Positive' means before ∈ {null, +, ++}; 'negative' means after ∈ {-, --}.
    These reversals surface pitfall text — evidence that appeared supportive but
    turned out not to be.

    hypothesis_pattern  — fnmatch filter on hypothesis name.
    reversals_only      — when True, return only rows where is_true_reversal=True
                          (before ∈ {+, ++}), excluding null→negative first-scores.
    Default sort: (hypothesis_name, case_id) asc.
    """
    hits = []
    for c in corpus:
        h_names: dict[str, str] = {h["id"]: h.get("name", "") for h in c.iter_new_hypotheses()}
        for lead in c.leads:
            for r in lead.get("resolutions", []) or []:
                before = r.get("before")
                after = r.get("after")
                if before not in _POSITIVE_WEIGHTS or after not in _NEGATIVE_WEIGHTS:
                    continue
                h_id = r.get("hypothesis", "")
                h_name = h_names.get(h_id, "")
                if hypothesis_pattern is not None and not fnmatch.fnmatchcase(h_name, hypothesis_pattern):
                    continue
                is_true_reversal = before in {"+", "++"}
                if reversals_only and not is_true_reversal:
                    continue
                hits.append({
                    "case_id": c.case_id,
                    "lead_id": lead.get("id"),
                    "lead_name": lead.get("name"),
                    "loop": lead.get("loop"),
                    "hypothesis_id": h_id,
                    "hypothesis_name": h_name,
                    "before": before,
                    "after": after,
                    "is_true_reversal": is_true_reversal,
                    "reasoning": r.get("reasoning", ""),
                    "severity_of_test": r.get("severity_of_test"),
                })
    hits.sort(key=lambda r: (r["hypothesis_name"] or "", r["case_id"] or ""))
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 10 — lead pair synergy (PREDICT / GATHER — composite-dispatch design)
# ---------------------------------------------------------------------------

def lead_pair_synergy(corpus: list[Companion]) -> dict[str, Any]:
    """For composite dispatches (same loop), measure whether lead pairs discriminate more together.

    Synergy = abs(combined_delta) - max(abs(individual_A_delta), abs(individual_B_delta))

    Positive synergy: the pair together produces more total evidence movement than the stronger
    lead alone (both leads reinforce in the same direction).
    Negative synergy: the pair partially cancels (leads pull in opposite directions).
    Aggregated across corpus as mean per (lead_a, lead_b) pair.

    Default sort: mean_synergy desc.
    """
    pair_data: dict[tuple[str, str], list[tuple[float, str]]] = {}

    for c in corpus:
        h_names: dict[str, str] = {h["id"]: h.get("name", "") for h in c.iter_new_hypotheses()}

        by_loop: dict[int, list[dict[str, Any]]] = {}
        for lead in c.leads:
            loop = lead.get("loop") or 0
            by_loop.setdefault(loop, []).append(lead)

        for loop_leads in by_loop.values():
            if len(loop_leads) < 2:
                continue

            for i, lead_a in enumerate(loop_leads):
                for lead_b in loop_leads[i + 1:]:
                    name_a = lead_a.get("name", "?")
                    name_b = lead_b.get("name", "?")
                    pair_key = (min(name_a, name_b), max(name_a, name_b))

                    res_a = {r.get("hypothesis"): r for r in (lead_a.get("resolutions") or [])}
                    res_b = {r.get("hypothesis"): r for r in (lead_b.get("resolutions") or [])}
                    shared_h_ids = set(res_a) & set(res_b)

                    if not shared_h_ids:
                        continue

                    for h_id in shared_h_ids:
                        ra = res_a[h_id]
                        rb = res_b[h_id]
                        delta_a = _signed_delta(ra.get("before"), ra.get("after"))
                        delta_b = _signed_delta(rb.get("before"), rb.get("after"))
                        combined = delta_a + delta_b
                        synergy = abs(combined) - max(abs(delta_a), abs(delta_b))
                        pair_data.setdefault(pair_key, []).append(
                            (synergy, h_names.get(h_id, h_id))
                        )

    rows: list[dict[str, Any]] = []
    for (name_a, name_b), observations in pair_data.items():
        case_count = len(observations)
        mean_synergy = sum(s for s, _ in observations) / case_count
        rows.append({
            "lead_a": name_a,
            "lead_b": name_b,
            "mean_synergy": round(mean_synergy, 4),
            "case_count": case_count,
            "example_hypothesis": observations[0][1],
        })
    rows.sort(key=lambda r: float(r["mean_synergy"]), reverse=True)
    return {"hits": rows, "count": len(rows)}


# ---------------------------------------------------------------------------
# Class 11 — post-failure recovery map (GATHER — recovery-lead planning)
# ---------------------------------------------------------------------------

def post_failure_recovery(
    corpus: list[Companion],
    *,
    system: str | None = None,
    failure_reason: str | None = None,
) -> dict[str, Any]:
    """For each failed lead, what lead came next and how effective was it?

    Aggregates: for each (failed_lead_name, system) pair, the typical next lead
    and mean absolute weight delta that next lead produced.

    Leads that are last in the sequence (no successor) are recorded with
    next_lead=null and mean_effectiveness=null.

    Default sort: mean_effectiveness_of_next desc (None sorted last).
    """
    recovery: dict[tuple[str, str, str], list[float]] = {}

    for c in corpus:
        leads = c.leads
        for i, lead in enumerate(leads):
            outcome = lead.get("outcome") or {}
            fr = outcome.get("failure_reason")
            if not fr:
                continue
            lead_system = (lead.get("query_details") or {}).get("system") or ""
            if system is not None and lead_system != system:
                continue
            if failure_reason is not None and fr != failure_reason:
                continue

            failed_name = lead.get("name", "?")
            next_lead = leads[i + 1] if i + 1 < len(leads) else None
            if next_lead is None:
                key = (failed_name, lead_system, "__none__")
                recovery.setdefault(key, []).append(0.0)
            else:
                next_name = next_lead.get("name", "?")
                next_resolutions = next_lead.get("resolutions") or []
                deltas = [_abs_delta(r.get("before"), r.get("after")) for r in next_resolutions]
                next_eff = sum(deltas) / len(deltas) if deltas else 0.0
                key = (failed_name, lead_system, next_name)
                recovery.setdefault(key, []).append(next_eff)

    rows: list[dict[str, Any]] = []
    for (failed_name, lead_system, next_name), effs in recovery.items():
        case_count = len(effs)
        mean_eff = sum(effs) / case_count if effs else 0.0
        rows.append({
            "failed_lead": failed_name,
            "system": lead_system or None,
            "typical_next_lead": None if next_name == "__none__" else next_name,
            "mean_effectiveness_of_next": round(mean_eff, 4) if next_name != "__none__" else None,
            "case_count": case_count,
        })
    rows.sort(
        key=lambda r: (
            r["mean_effectiveness_of_next"] is None,
            -float(r["mean_effectiveness_of_next"] or 0),
        )
    )
    if rows and all(r["case_count"] == 1 for r in rows):
        print(
            "warning: all recovery patterns are based on a single case each (case_count=1). "
            "Patterns may not generalize — expand the corpus for more reliable recovery maps.",
            file=sys.stderr,
        )
    return {"hits": rows, "count": len(rows)}


# ---------------------------------------------------------------------------
# Class 12 — independent data source metric (REPORT — termination grounding)
# ---------------------------------------------------------------------------

def independent_datasource_metric(
    corpus: list[Companion],
    *,
    disposition: str | None = None,
) -> dict[str, Any]:
    """Count distinct systems per case; distribution grouped by termination × disposition × confidence.

    More epistemologically meaningful than loop depth for measuring investigation
    convergence: 'for this class of alert at this severity, how many independent
    data sources are typically needed?'

    Default sort: hits by distinct_system_count desc; distribution by group key.
    """
    rows: list[dict[str, Any]] = []
    for c in corpus:
        disp = c.conclude.get("disposition")
        if disposition is not None and disp != disposition:
            continue
        systems = {
            (lead.get("query_details") or {}).get("system")
            for lead in c.leads
            if (lead.get("query_details") or {}).get("system")
        }
        rows.append({
            "case_id": c.case_id,
            "distinct_system_count": len(systems),
            "systems": sorted(s for s in systems if isinstance(s, str)),
            "termination_category": conclude_field(c.conclude, "termination", "category"),
            "disposition": disp,
            "confidence": c.conclude.get("confidence"),
        })

    rows.sort(key=lambda r: r["distinct_system_count"], reverse=True)

    if not rows:
        return {"hits": [], "distribution": [], "count": 0}

    df = pl.DataFrame([
        {
            "distinct_system_count": r["distinct_system_count"],
            "termination_category": r["termination_category"] or "",
            "disposition": r["disposition"] or "",
            "confidence": r["confidence"] or "",
        }
        for r in rows
    ])
    dist = (
        df.group_by(["termination_category", "disposition", "confidence"])
        .agg(
            pl.len().alias("case_count"),
            pl.col("distinct_system_count").mean().round(2).alias("mean_distinct_systems"),
            pl.col("distinct_system_count").min().alias("min_distinct_systems"),
            pl.col("distinct_system_count").max().alias("max_distinct_systems"),
        )
        .sort(["termination_category", "disposition", "confidence"])
    )
    return {"hits": rows, "distribution": dist.to_dicts(), "count": len(rows)}
