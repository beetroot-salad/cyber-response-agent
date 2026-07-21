
from __future__ import annotations

import fnmatch
from typing import Any
from collections.abc import Iterable

from . import _walkers, vocab
from .corpus import Companion
from .schema import Conclude, FindingRecord, HypothesisRecord



def _hypothesis_name(h: HypothesisRecord) -> str:
    return h.get("name", "") or ""


def _all_hypotheses(c: Companion) -> Iterable[HypothesisRecord]:
    return _walkers.all_hypotheses(c.body).values()


def _lead_outcome_empty(lead: FindingRecord) -> bool:
    obs = (lead.get("outcome") or {}).get("observations") or {}
    return not obs.get("vertices") and not obs.get("edges")


def _conclude_field(conclude: Conclude, *path: str) -> Any:
    cur: Any = conclude
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur



def _lead_trace(c: Companion) -> str:
    parts: list[str] = []
    for lead in c.leads:
        name = lead.get("name", "?")
        outcome = lead.get("outcome") or {}
        if outcome.get("failure_reason"):
            parts.append(f"{name}:FAIL")
        elif outcome.get("anchor_consultations"):
            parts.append(f"{name}:consult")
        else:
            parts.append(name)
    terminal = _conclude_field(c.conclude, "termination", "category") or "?"
    disposition = c.conclude.get("disposition", "?")
    parts.append(f"{terminal}:{disposition}")
    return "→".join(parts)


def lead_sequence_pattern(
    corpus: list[Companion],
    *,
    contains: str | None = None,
    disposition: str | None = None,
    signature_id: str | None = None,
) -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    for c in corpus:
        if disposition is not None and c.conclude.get("disposition") != disposition:
            continue
        if signature_id is not None and c.signature_id != signature_id:
            continue
        trace = _lead_trace(c)
        if contains is not None and contains not in trace:
            continue
        hits.append({
            "case_id": c.case_id,
            "signature_id": c.signature_id,
            "trace": trace,
            "lead_count": len(c.leads),
            "termination": _conclude_field(c.conclude, "termination", "category"),
            "disposition": c.conclude.get("disposition"),
        })
    hits.sort(key=lambda r: r["lead_count"], reverse=True)
    return {"hits": hits, "count": len(hits)}



def hypothesis_name_wildcard(
    corpus: list[Companion],
    pattern: str,
    *,
    final_weight: str | None = None,
    disposition: str | None = None,
    signature_id: str | None = None,
) -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    for c in corpus:
        if disposition is not None and c.conclude.get("disposition") != disposition:
            continue
        if signature_id is not None and c.signature_id != signature_id:
            continue
        final = _compute_final_weights(c)
        for h in _all_hypotheses(c):
            name = _hypothesis_name(h)
            if not fnmatch.fnmatchcase(name, pattern):
                continue
            weight = final.get(h.get("id") or "")
            if final_weight is not None and weight != final_weight:
                continue
            hits.append({
                "case_id": c.case_id,
                "signature_id": c.signature_id,
                "name": name,
                "final_weight": weight,
                "disposition": c.conclude.get("disposition"),
                "status": h.get("status", "active"),
            })
    hits.sort(key=lambda r: (vocab.WEIGHT_ORDER.get(r["final_weight"], 2), r["case_id"]), reverse=True)
    return {"hits": hits, "count": len(hits), "pattern": pattern}



def _empty_bucket() -> dict[str, int]:
    return {b: 0 for b in vocab.WEIGHT_BUCKETS}


def lead_branch_effects(
    corpus: list[Companion],
    *,
    hypothesis_patterns: tuple[str, ...] = (),
    min_support: int = 1,
    max_hypotheses_per_lead: int = 5,
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    empties: dict[str, int] = {}
    per_hyp: dict[str, dict[str, dict[str, int]]] = {}
    patterns_active = bool(hypothesis_patterns)

    for c in corpus:
        h_names = {h["id"]: _hypothesis_name(h) for h in _all_hypotheses(c) if "id" in h}
        for lead in c.leads:
            _accumulate_lead_effects(
                lead, h_names, hypothesis_patterns, patterns_active,
                counts, empties, per_hyp,
            )

    rows = _build_lead_effect_rows(
        counts, empties, per_hyp,
        min_support=min_support,
        max_hypotheses_per_lead=max_hypotheses_per_lead,
        patterns_active=patterns_active,
    )
    rows.sort(key=lambda r: (-r["n"], r["lead_name"]))
    return {
        "leads": rows,
        "count": len(rows),
        "frontier": list(hypothesis_patterns) if patterns_active else None,
    }


def _accumulate_lead_effects(
    lead: FindingRecord,
    h_names: dict[str, str],
    hypothesis_patterns: tuple[str, ...],
    patterns_active: bool,
    counts: dict[str, int],
    empties: dict[str, int],
    per_hyp: dict[str, dict[str, dict[str, int]]],
) -> None:
    name = lead.get("name")
    if not name:
        return
    touched = _touched_hypothesis_names(lead, h_names)
    matching = (
        {h for h in touched if _hyp_pattern_matches(h, hypothesis_patterns)}
        if patterns_active else touched
    )
    if patterns_active and not matching:
        return
    counts[name] = counts.get(name, 0) + 1
    if _lead_outcome_empty(lead):
        empties[name] = empties.get(name, 0) + 1
    for hn in sorted(matching):
        per_hyp.setdefault(name, {}).setdefault(hn, _empty_bucket())
    for r in lead.get("resolutions", []) or []:
        hn = h_names.get(r.get("hypothesis", ""), "")
        if not hn or (patterns_active and not _hyp_pattern_matches(hn, hypothesis_patterns)):
            continue
        shift = r.get("after")
        if shift not in vocab.WEIGHT_BUCKETS:
            continue
        per_hyp[name][hn][shift] += 1


def _hyp_pattern_matches(name: str, patterns: tuple[str, ...]) -> bool:
    if not patterns:
        return True
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def _touched_hypothesis_names(
    lead: FindingRecord, h_names: dict[str, str]
) -> set[str]:
    touched: set[str] = set()
    for h_id in lead.get("tests_hypotheses", []) or []:
        if (hn := h_names.get(h_id)):
            touched.add(hn)
    for r in lead.get("resolutions", []) or []:
        if (hn := h_names.get(r.get("hypothesis", ""))):
            touched.add(hn)
    return touched


def _build_lead_effect_rows(
    counts: dict[str, int],
    empties: dict[str, int],
    per_hyp: dict[str, dict[str, dict[str, int]]],
    *,
    min_support: int,
    max_hypotheses_per_lead: int,
    patterns_active: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, n in counts.items():
        if n < min_support:
            continue
        hyp_table = per_hyp.get(name, {})
        if not patterns_active and len(hyp_table) > max_hypotheses_per_lead:
            ordered = sorted(
                hyp_table.items(),
                key=lambda kv: (-sum(kv[1].values()), kv[0]),
            )[:max_hypotheses_per_lead]
            hyp_table = dict(ordered)
        rows.append({
            "lead_name": name,
            "n": n,
            "empty_rate": f"{empties.get(name, 0)}/{n}",
            "per_hypothesis_effect": hyp_table,
        })
    return rows



def _compute_final_weights(c: Companion) -> dict[str, Any]:
    return _walkers.final_weights(c.body)


def _hypothesis_matches_shape(
    h: HypothesisRecord,
    v_type: dict[str, str],
    *,
    parent_type: str | None,
    parent_class: str | None,
    rel: str | None,
    attached_to_type: str | None,
) -> bool:
    pe = h.get("proposed_edge") or {}
    pv = pe.get("parent_vertex") or {}
    return (
        (not parent_type or pv.get("type", "") == parent_type)
        and (not parent_class or fnmatch.fnmatchcase(pv.get("classification", ""), parent_class))
        and (not rel or pe.get("relation", "") == rel)
        and (
            not attached_to_type
            or v_type.get(h.get("anchor", ""), "") == attached_to_type
        )
    )


def hypothesis_shape_match(
    corpus: list[Companion],
    *,
    parent_type: str | None = None,
    parent_class: str | None = None,
    rel: str | None = None,
    attached_to_type: str | None = None,
) -> dict[str, Any]:
    if not (parent_type or parent_class or rel or attached_to_type):
        raise ValueError(
            "at least one of parent_type, parent_class, rel, "
            "attached_to_type required"
        )

    agg: dict[str, dict[str, Any]] = {}

    for c in corpus:
        v_type: dict[str, str] = {}
        for v in c.prologue.get("vertices", []) or []:
            if isinstance(v, dict) and v.get("id"):
                v_type[v["id"]] = v.get("type", "")

        final = _compute_final_weights(c)
        disp = c.conclude.get("disposition") or "unknown"

        for h in _all_hypotheses(c):
            if not _hypothesis_matches_shape(
                h, v_type,
                parent_type=parent_type, parent_class=parent_class,
                rel=rel, attached_to_type=attached_to_type,
            ):
                continue
            name = _hypothesis_name(h)
            if not name:
                continue
            entry = agg.setdefault(name, {
                "n": 0,
                "weights": {**_empty_bucket(), "null": 0},
                "dispositions": {},
                "cases": set(),
            })
            entry["n"] += 1
            w = final.get(h.get("id") or "")
            entry["weights"][w if w in vocab.WEIGHT_BUCKETS else "null"] += 1
            entry["dispositions"][disp] = entry["dispositions"].get(disp, 0) + 1
            entry["cases"].add(c.case_id)

    hits: list[dict[str, Any]] = []
    for name, data in sorted(agg.items(), key=lambda kv: (-kv[1]["n"], kv[0])):
        hits.append({
            "name": name,
            "n": data["n"],
            "final_weight_distribution": data["weights"],
            "dispositions": dict(sorted(data["dispositions"].items())),
            "cases": sorted(data["cases"]),
        })

    return {
        "hits": hits,
        "count": len(hits),
        "shape": {
            "parent_type": parent_type,
            "parent_class": parent_class,
            "rel": rel,
            "attached_to_type": attached_to_type,
        },
    }
