"""Investigation-language query classes 1–8 and corpus enumeration.

Each function takes a corpus (list[Companion]) and returns a dict with
at minimum a 'count' key and a 'hits' or 'values' list. All functions
are side-effect-free and safe to call from the CLI or programmatically.
"""

from __future__ import annotations

import fnmatch
from math import log1p
from typing import Any, Iterator

import polars as pl

from .corpus import Companion, conclude_field


# ---------------------------------------------------------------------------
# Class 1 — coarse case lookup
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
    """Filter cases by conclude-block structured fields."""
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
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 2 — anchor calibration
# ---------------------------------------------------------------------------

def _anchor_rows(corpus: list[Companion]) -> list[dict[str, Any]]:
    rows = []
    for c in corpus:
        for lead in c.leads:
            tar = (lead.get("outcome") or {}).get("trust_anchor_result")
            if not tar:
                continue
            rows.append({
                "case_id": c.case_id,
                "lead_id": lead.get("id"),
                "lead_name": lead.get("name"),
                "loop": lead.get("loop"),
                "anchor_id": tar.get("anchor_id"),
                "kind": tar.get("kind"),
                "result": tar.get("result"),
                "authority_for_question": tar.get("authority_for_question"),
                "as_of": tar.get("as_of"),
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
    """Distribution of (result × authority) → disposition for a given anchor."""
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
    return {"hits": df.to_dicts(), "distribution": dist.to_dicts(), "count": df.height}


# ---------------------------------------------------------------------------
# Class 3 — refinement chain shapes
# ---------------------------------------------------------------------------

def _parse_hypothesis_chain(h_id: str) -> list[str]:
    """h-001-002-003 → ['h-001', 'h-001-002', 'h-001-002-003']."""
    parts = h_id.split("-")
    if not parts or parts[0] != "h":
        return [h_id]
    return ["-".join(parts[:i]) for i in range(2, len(parts) + 1)]


def refinement_chain_shapes(corpus: list[Companion]) -> dict[str, Any]:
    """Per-case hypothesis refinement tree: depth and branching per root."""
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
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 4 — dead-lead lookup
# ---------------------------------------------------------------------------

def dead_lead_lookup(
    corpus: list[Companion],
    *,
    system: str | None = None,
    failure_reason: str | None = None,
) -> dict[str, Any]:
    """Leads that errored or returned degraded data."""
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
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 5 — lead sequence pattern
# ---------------------------------------------------------------------------

def _infer_lead_type(lead: dict[str, Any]) -> str:
    """Infer lead type from outcome content (v2.5 — no mode field).

    trust:   trust_anchor_result present
    refine:  attribute_updates only (no observations vertices/edges)
    scope:   observations with vertices or edges, or empty outcome
    fail:    failure_reason present
    """
    outcome = lead.get("outcome") or {}
    if outcome.get("failure_reason"):
        return "fail"
    if outcome.get("trust_anchor_result"):
        return "trust"
    obs = outcome.get("observations") or {}
    if outcome.get("attribute_updates") and not (obs.get("vertices") or obs.get("edges")):
        return "refine"
    return "scope"


def _lead_sequence(c: Companion) -> str:
    parts = []
    for lead in c.leads:
        name = lead.get("name", "?")
        outcome = lead.get("outcome") or {}
        tar = outcome.get("trust_anchor_result") or {}
        fr = outcome.get("failure_reason")
        lead_type = _infer_lead_type(lead)
        if lead_type == "trust":
            parts.append(f"trust({tar.get('anchor_id', name)}:{tar.get('result', '?')})")
        elif lead_type == "fail":
            parts.append(f"{name}:FAIL={fr}")
        elif lead_type == "refine":
            parts.append(name if name.startswith("refine(") else f"refine({name})")
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
    """Serialize each case's gather block as a trace string."""
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
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 6 — hypothesis name wildcard
# ---------------------------------------------------------------------------

def hypothesis_name_wildcard(
    corpus: list[Companion],
    pattern: str,
    *,
    final_weight: str | None = None,
    disposition: str | None = None,
) -> dict[str, Any]:
    """Match hypothesis names against an fnmatch pattern (e.g. '?*compromise*')."""
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
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 7 — prose substring
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
    """Substring scan across all prose fields of every companion."""
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
    return {"hits": hits, "count": len(hits)}


# ---------------------------------------------------------------------------
# Class 8 — lead effectiveness
# ---------------------------------------------------------------------------

_WEIGHT_NUMERIC: dict[Any, int] = {None: 0, "++": 2, "+": 1, "-": -1, "--": -2}


def _abs_delta(before: Any, after: Any) -> float:
    return abs(_WEIGHT_NUMERIC.get(after, 0) - _WEIGHT_NUMERIC.get(before, 0))


def _lead_effectiveness_rows(
    corpus: list[Companion],
    patterns: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Core aggregation for lead_effectiveness and lead_effectiveness_for_hypothesis.

    patterns — fnmatch patterns, all of which must match a hypothesis name (conjunction).
               Empty = match all hypotheses.
    """
    def matches(h_name: str) -> bool:
        return all(fnmatch.fnmatchcase(h_name, p) for p in patterns)

    per_name: dict[str, list[float]] = {}
    for c in corpus:
        h_names: dict[str, str] = {h["id"]: h.get("name", "") for h in c.iter_new_hypotheses()}
        for lead in c.leads:
            resolutions = lead.get("resolutions", []) or []
            if patterns:
                deltas = [
                    _abs_delta(r.get("before"), r.get("after"))
                    for r in resolutions
                    if matches(h_names.get(r.get("hypothesis", ""), ""))
                ]
                if not deltas:
                    continue
            else:
                deltas = [_abs_delta(r.get("before"), r.get("after")) for r in resolutions]
            lead_mean = sum(deltas) / len(deltas) if deltas else 0.0
            per_name.setdefault(lead.get("name", "?"), []).append(lead_mean)

    rows = []
    for name, corpus_deltas in sorted(per_name.items()):
        count = len(corpus_deltas)
        mean_delta = sum(corpus_deltas) / count
        rows.append({
            "lead_name": name,
            "count": count,
            "mean_abs_weight_delta": round(mean_delta, 3),
            "effectiveness": round(log1p(count) * mean_delta, 4),
        })
    rows.sort(key=lambda r: r["effectiveness"], reverse=True)
    return rows


def lead_effectiveness(corpus: list[Companion]) -> dict[str, Any]:
    """Score each lead name by log1p(count) × mean_abs_weight_delta across all hypotheses.

    count           — occurrences of the lead name across the corpus
    mean_abs_weight — mean |numeric(after) - numeric(before)| across all resolutions
    effectiveness   — log1p(count) × mean_abs_weight_delta
    """
    return {"hits": _lead_effectiveness_rows(corpus), "count": len(_lead_effectiveness_rows(corpus))}


def lead_effectiveness_for_hypothesis(
    corpus: list[Companion],
    *patterns: str,
) -> dict[str, Any]:
    """Lead effectiveness restricted to hypotheses matching ALL supplied fnmatch patterns.

    Patterns are AND-ed: a resolution counts only when its hypothesis name satisfies
    every pattern. Leads that never touched a matching hypothesis are excluded.

    Examples:
      lead_effectiveness_for_hypothesis(corpus, '?*compromise*')
      lead_effectiveness_for_hypothesis(corpus, '?*monitoring*', '?*compromise*')
    """
    if not patterns:
        raise ValueError("supply at least one fnmatch pattern")
    rows = _lead_effectiveness_rows(corpus, patterns)
    return {"hits": rows, "count": len(rows), "patterns": list(patterns)}


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

ENUM_CHOICES = ("leads", "anchors", "archetypes", "hypotheses", "dispositions")


def enumerate_corpus(corpus: list[Companion], kind: str) -> dict[str, Any]:
    """List distinct values of a corpus dimension.

    kind — one of: leads, anchors, archetypes, hypotheses, dispositions
    """
    values: set[str] = set()
    for c in corpus:
        if kind == "leads":
            for lead in c.leads:
                values.add(lead.get("name", "?"))
        elif kind == "anchors":
            for lead in c.leads:
                tar = (lead.get("outcome") or {}).get("trust_anchor_result")
                if tar and tar.get("anchor_id"):
                    values.add(tar["anchor_id"])
        elif kind == "archetypes":
            a = c.conclude.get("matched_archetype")
            if a:
                values.add(a)
        elif kind == "hypotheses":
            for h in c.iter_new_hypotheses():
                name = h.get("name")
                if name:
                    values.add(name)
        elif kind == "dispositions":
            d = c.conclude.get("disposition")
            if d:
                values.add(d)
        else:
            raise ValueError(f"unknown kind {kind!r}; choose from {ENUM_CHOICES}")
    return {"kind": kind, "values": sorted(values), "count": len(values)}
