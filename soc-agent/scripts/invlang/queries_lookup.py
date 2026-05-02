"""Query classes 1–7: field-based lookups and corpus scans.

Classes:
  1  coarse_case_lookup      — filter by conclude-block fields         [ad-hoc]
  2  anchor_calibration      — anchor results × authority → disposition [GATHER]
  3  refinement_chain_shapes — hypothesis refinement tree depth/branching [PREDICT]
  4  dead_lead_lookup        — leads that errored or returned degraded data [GATHER]
  5  lead_sequence_pattern   — serialize gather blocks as trace strings [ad-hoc]
  6  hypothesis_name_wildcard — fnmatch on hypothesis names             [PREDICT]
  7  prose_substring         — substring scan across all prose fields    [ad-hoc]
"""

from __future__ import annotations

import fnmatch
from typing import Any, Iterator

import polars as pl

from .corpus import Companion, conclude_field
from ._shared import (
    _CONFIDENCE_ORDER,
    _FINAL_WEIGHT_SORT,
    _hypothesis_name,
    _lead_kind,
    _parse_hypothesis_chain,
)


# ---------------------------------------------------------------------------
# Class 1 — coarse case lookup (ad-hoc / general exploration)
# ---------------------------------------------------------------------------

def coarse_case_lookup(
    corpus: list[Companion],
    *,
    disposition: str | None = None,
    termination_category: str | None = None,
    confidence: str | None = None,
    matched_archetype: str | None = None,
    ceiling_test_kind: str | None = None,
) -> dict[str, Any]:
    """Filter cases by conclude-block structured fields.

    Default sort: confidence desc (high → medium → low → unknown).
    """
    hits = []
    for c in corpus:
        co = c.conclude
        if disposition is not None and co.get("disposition") != disposition:
            continue
        if termination_category is not None and conclude_field(co, "termination", "category") != termination_category:
            continue
        if confidence is not None and co.get("confidence") != confidence:
            continue
        if matched_archetype is not None and co.get("matched_archetype") != matched_archetype:
            continue
        if ceiling_test_kind is not None and (co.get("ceiling_test") or {}).get("kind") != ceiling_test_kind:
            continue
        hits.append({
            "case_id": c.case_id,
            "disposition": co.get("disposition"),
            "termination_category": conclude_field(co, "termination", "category"),
            "confidence": co.get("confidence"),
            "matched_archetype": co.get("matched_archetype"),
            "ceiling_test": co.get("ceiling_test"),
            "summary_head": (co.get("summary") or "").strip().split("\n", 1)[0][:120],
        })
    hits.sort(key=lambda r: _CONFIDENCE_ORDER.get(r["confidence"] or "", 0), reverse=True)
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 2 — anchor calibration (GATHER — authority consultation priors)
# ---------------------------------------------------------------------------

def _anchor_rows(corpus: list[Companion]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for c in corpus:
        for lead in c.leads:
            outcome = lead.get("outcome") or {}
            for cons in outcome.get("anchor_consultations") or []:
                if not isinstance(cons, dict):
                    continue
                rows.append({
                    "case_id": c.case_id,
                    "lead_id": lead.get("id"),
                    "lead_name": lead.get("name"),
                    "loop": lead.get("loop"),
                    "anchor_id": cons.get("anchor_id"),
                    "kind": cons.get("grounding_kind"),
                    "result": cons.get("result"),
                    "authority_for_question": cons.get("authority_for_question"),
                    "as_of": cons.get("as_of"),
                    "disposition": c.conclude.get("disposition"),
                    "termination_category": conclude_field(c.conclude, "termination", "category"),
                })
    return rows


def anchor_calibration(
    corpus: list[Companion],
    *,
    anchor_id: str | None = None,
    result: str | None = None,
    authority_for_question: str | None = None,
) -> dict[str, Any]:
    """Distribution of (result × authority) → disposition for a given anchor.

    Default sort: hits sorted by (anchor_id, result, authority_for_question, disposition).
    Distribution already sorted by same key group.
    """
    rows = _anchor_rows(corpus)
    if not rows:
        return {"hits": [], "distribution": [], "count": 0}
    df = pl.DataFrame(rows)
    if anchor_id is not None:
        df = df.filter(pl.col("anchor_id") == anchor_id)
    if result is not None:
        df = df.filter(pl.col("result") == result)
    if authority_for_question is not None:
        df = df.filter(pl.col("authority_for_question") == authority_for_question)
    dist = (
        df.group_by(["anchor_id", "result", "authority_for_question", "disposition"])
        .len(name="count")
        .sort(["anchor_id", "result", "authority_for_question", "disposition"])
    )
    hits_sorted = df.sort(["anchor_id", "result", "authority_for_question", "disposition"]).to_dicts()
    return {"hits": hits_sorted, "distribution": dist.to_dicts(), "count": df.height}


# ---------------------------------------------------------------------------
# Class 3 — refinement chain shapes (PREDICT — refine vs propose directly)
# ---------------------------------------------------------------------------

def refinement_chain_shapes(corpus: list[Companion]) -> dict[str, Any]:
    """Per-case hypothesis refinement tree: depth and branching per root.

    Default sort: max_depth desc, then descendant_count desc.
    """
    hits = []
    for c in corpus:
        ids = [h["id"] for h in c.iter_new_hypotheses()]
        roots: dict[str, list[str]] = {}
        for h_id in ids:
            root = _parse_hypothesis_chain(h_id)[0]
            roots.setdefault(root, []).append(h_id)
        for root, descendants in roots.items():
            max_depth = max(len(_parse_hypothesis_chain(d)) for d in descendants)
            hits.append({
                "case_id": c.case_id,
                "root": root,
                "descendant_count": len(descendants),
                "max_depth": max_depth,
                "descendants": sorted(descendants),
            })
    hits.sort(key=lambda r: (r["max_depth"], r["descendant_count"]), reverse=True)
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 4 — dead-lead lookup (GATHER — data-source-debug / recovery)
# ---------------------------------------------------------------------------

def dead_lead_lookup(
    corpus: list[Companion],
    *,
    system: str | None = None,
    failure_reason: str | None = None,
) -> dict[str, Any]:
    """Leads that errored or returned degraded data.

    Default sort: loop asc (chronological order within investigation).
    """
    hits = []
    for c in corpus:
        for lead in c.leads:
            outcome = lead.get("outcome") or {}
            fr = outcome.get("failure_reason")
            if not fr:
                continue
            lead_system = (lead.get("query_details") or {}).get("system")
            if system is not None and lead_system != system:
                continue
            if failure_reason is not None and fr != failure_reason:
                continue
            hits.append({
                "case_id": c.case_id,
                "lead_id": lead.get("id"),
                "lead_name": lead.get("name"),
                "loop": lead.get("loop"),
                "system": lead_system,
                "failure_reason": fr,
                "concerns": lead.get("concerns", []),
                "target": lead.get("target"),
            })
    hits.sort(key=lambda r: (r["loop"] or 0))
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 5 — lead sequence pattern (ad-hoc / retrospective)
# ---------------------------------------------------------------------------

def _lead_sequence(c: Companion) -> str:
    parts = []
    for lead in c.leads:
        name = lead.get("name", "?")
        outcome = lead.get("outcome") or {}
        consultations = [
            cons for cons in (outcome.get("anchor_consultations") or [])
            if isinstance(cons, dict)
        ]
        fr = outcome.get("failure_reason")
        kind = _lead_kind(lead)
        if kind == "consult" and consultations:
            first = consultations[0]
            parts.append(
                f"consult({first.get('anchor_id', name)}:{first.get('result', '?')})"
            )
        elif kind == "fail":
            parts.append(f"{name}:FAIL={fr}")
        elif kind == "interpretive":
            parts.append(f"{name}[preds]")
        else:
            parts.append(name)
    terminal = conclude_field(c.conclude, "termination", "category") or "?"
    disposition = c.conclude.get("disposition", "?")
    parts.append(f"{terminal}:{disposition}")
    return "→".join(parts)


def lead_sequence_pattern(
    corpus: list[Companion],
    *,
    contains: str | None = None,
) -> dict[str, Any]:
    """Serialize each case's gather block as a trace string.

    Default sort: lead_count desc (most complex investigations first).
    """
    hits = []
    for c in corpus:
        trace = _lead_sequence(c)
        if contains is not None and contains not in trace:
            continue
        hits.append({
            "case_id": c.case_id,
            "trace": trace,
            "lead_count": len(c.leads),
            "termination": conclude_field(c.conclude, "termination", "category"),
            "disposition": c.conclude.get("disposition"),
        })
    hits.sort(key=lambda r: r["lead_count"], reverse=True)
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 6 — hypothesis name wildcard (PREDICT — seed-vocabulary discovery)
# ---------------------------------------------------------------------------

def hypothesis_name_wildcard(
    corpus: list[Companion],
    pattern: str,
    *,
    final_weight: str | None = None,
    disposition: str | None = None,
) -> dict[str, Any]:
    """Match hypothesis names against an fnmatch pattern (e.g. '?*compromise*').

    Default sort: final_weight desc (++ → + → null/unknown → - → --).
    """
    hits = []
    for c in corpus:
        if disposition is not None and c.conclude.get("disposition") != disposition:
            continue
        final: dict[str, Any] = {h["id"]: h.get("weight") for h in c.iter_new_hypotheses()}
        for lead in c.leads:
            for r in lead.get("resolutions", []) or []:
                final[r["hypothesis"]] = r.get("after")
        for h in c.iter_new_hypotheses():
            name = h.get("name", "")
            if not fnmatch.fnmatchcase(name, pattern):
                continue
            weight = final.get(h["id"])
            if final_weight is not None and weight != final_weight:
                continue
            hits.append({
                "case_id": c.case_id,
                "hypothesis_id": h["id"],
                "name": name,
                "final_weight": weight,
                "disposition": c.conclude.get("disposition"),
                "status": h.get("status", "active"),
            })
    hits.sort(key=lambda r: _FINAL_WEIGHT_SORT.get(r["final_weight"], 2), reverse=True)
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 7 — prose substring (ad-hoc / general exploration)
# ---------------------------------------------------------------------------

def _prose_snippets(c: Companion) -> Iterator[tuple[str, str]]:
    for v in c.prologue.get("vertices", []) or []:
        for concern in v.get("concerns", []) or []:
            yield (f"prologue.vertex({v.get('id')}).concerns", concern)
    for h in c.iter_new_hypotheses():
        for concern in h.get("concerns", []) or []:
            yield (f"hypothesis({h.get('id')}).concerns", concern)
    for lead in c.leads:
        for concern in lead.get("concerns", []) or []:
            yield (f"lead({lead.get('id')}).concerns", concern)
        for r in lead.get("resolutions", []) or []:
            reasoning = r.get("reasoning")
            if reasoning:
                yield (f"lead({lead.get('id')}).resolutions[{r.get('hypothesis')}].reasoning", reasoning)
    co = c.conclude
    for field_path in ["ceiling_rationale", "summary"]:
        val = co.get(field_path)
        if val:
            yield (f"conclude.{field_path}", val)
    term_rationale = (co.get("termination") or {}).get("rationale")
    if term_rationale:
        yield ("conclude.termination.rationale", term_rationale)


def prose_substring(
    corpus: list[Companion],
    phrase: str,
    *,
    case_sensitive: bool = False,
) -> dict[str, Any]:
    """Substring scan across all prose fields of every companion.

    Default sort: case_id asc (groups snippets from the same case together).
    """
    hits = []
    needle = phrase if case_sensitive else phrase.lower()
    for c in corpus:
        for path, text in _prose_snippets(c):
            haystack = text if case_sensitive else text.lower()
            if needle in haystack:
                idx = haystack.find(needle)
                start = max(0, idx - 40)
                end = min(len(text), idx + len(phrase) + 80)
                hits.append({
                    "case_id": c.case_id,
                    "path": path,
                    "snippet": text[start:end].strip(),
                })
    hits.sort(key=lambda r: r["case_id"])
    return {"hits": hits, "count": len(hits)}
