"""Investigation-language query classes 1–12 and corpus enumeration.

Each function takes a corpus (list[Companion]) and returns a dict with
at minimum a 'count' key and a 'hits' or 'values' list. Most functions
are side-effect-free; a few emit warnings to stderr when results are empty
and the caller is likely querying against the wrong vocabulary.

Classes (phase tag = which investigation phase typically consumes the output):
  1  coarse_case_lookup            — [ad-hoc]        filter by conclude-block fields
  2  anchor_calibration            — [GATHER]        anchor results × authority → disposition
  3  refinement_chain_shapes       — [HYPOTHESIZE]   hypothesis refinement tree depth/branching
  4  dead_lead_lookup              — [GATHER]        leads that errored or returned degraded data
  5  lead_sequence_pattern         — [ad-hoc]        serialize gather blocks as trace strings
  6  hypothesis_name_wildcard      — [HYPOTHESIZE]   fnmatch on hypothesis names; filter by final weight
  7  prose_substring               — [ad-hoc]        substring scan across all prose fields
  8  lead_effectiveness            — [HYPOTHESIZE]   score leads on branching_delta + prediction_fidelity + kind_mix
  9  weight_reversal_mining        — [ANALYZE]       resolutions where weight moved positive→negative
  10 lead_pair_synergy             — [HYPOTHESIZE]   composite-dispatch pairs where combined > sum of individual deltas
  11 post_failure_recovery         — [GATHER]        after a dead lead, what lead came next and how effective was it?
  12 independent_datasource_metric — [CONCLUDE]      distinct system count per case, grouped by disposition + confidence

Handler-facing topology retrieval (separate from the numbered classes):
  lead_effectiveness_for_topology            — [HYPOTHESIZE] pre-baked class-8 conditioned on frontier topology
  peer_hypothesis_distribution_for_topology  — [HYPOTHESIZE] co-proposed classifications at the same topology
"""

from __future__ import annotations

import fnmatch
import sys
from math import log1p
from typing import Any, Iterator

import polars as pl

from .corpus import Companion, conclude_field, hypothesis_topology


def _hypothesis_name(h: dict[str, Any]) -> str:
    """Return the hypothesis display name."""
    return h.get("name", "") or ""


# ---------------------------------------------------------------------------
# Shared weight / ordering tables
# ---------------------------------------------------------------------------

_WEIGHT_NUMERIC: dict[Any, int] = {None: 0, "++": 2, "+": 1, "-": -1, "--": -2}

_CONFIDENCE_ORDER: dict[str, int] = {"high": 3, "medium": 2, "low": 1}

# Higher number = more severe weight (used for final_weight sort in Class 6)
_FINAL_WEIGHT_SORT: dict[Any, int] = {"++": 4, "+": 3, None: 2, "-": 1, "--": 0}


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
# Class 3 — refinement chain shapes (HYPOTHESIZE — refine vs propose directly)
# ---------------------------------------------------------------------------

def _parse_hypothesis_chain(h_id: str) -> list[str]:
    """h-001-002-003 → ['h-001', 'h-001-002', 'h-001-002-003']."""
    parts = h_id.split("-")
    if not parts or parts[0] != "h":
        return [h_id]
    return ["-".join(parts[:i]) for i in range(2, len(parts) + 1)]


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
# Class 5 — lead sequence pattern (ad-hoc / retrospective — full investigation trace)
# ---------------------------------------------------------------------------

def _lead_kind(lead: dict[str, Any]) -> str:
    """Classify a lead by its declared schema shape (v2.7 — tests + predictions drive).

    trust:       outcome.trust_anchor_result present
    fail:        outcome.failure_reason present
    branching:   lead.tests non-empty (collapses a hypothesis fork)
    interpretive: lead.predictions non-empty (pre-committed reading, non-branching)
    mechanical:  none of the above — pure enrichment
    """
    outcome = lead.get("outcome") or {}
    if outcome.get("failure_reason"):
        return "fail"
    if outcome.get("trust_anchor_result"):
        return "trust"
    if lead.get("tests"):
        return "branching"
    if lead.get("predictions"):
        return "interpretive"
    return "mechanical"


def _lead_sequence(c: Companion) -> str:
    parts = []
    for lead in c.leads:
        name = lead.get("name", "?")
        outcome = lead.get("outcome") or {}
        tar = outcome.get("trust_anchor_result") or {}
        fr = outcome.get("failure_reason")
        kind = _lead_kind(lead)
        if kind == "trust":
            parts.append(f"trust({tar.get('anchor_id', name)}:{tar.get('result', '?')})")
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
# Class 6 — hypothesis name wildcard (HYPOTHESIZE — seed-vocabulary discovery)
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


# ---------------------------------------------------------------------------
# Class 8 — lead effectiveness (HYPOTHESIZE — lead-selection priors; pre-baked into handler)
# ---------------------------------------------------------------------------

def _abs_delta(before: Any, after: Any) -> float:
    return abs(_WEIGHT_NUMERIC.get(after, 0) - _WEIGHT_NUMERIC.get(before, 0))


def _signed_delta(before: Any, after: Any) -> float:
    return float(_WEIGHT_NUMERIC.get(after, 0) - _WEIGHT_NUMERIC.get(before, 0))


_LEAD_KINDS = ("branching", "interpretive", "trust", "fail", "mechanical")


def _lead_effectiveness_rows(
    corpus: list[Companion],
    patterns: tuple[str, ...] = (),
    *,
    hypothesis_id_filter: set[tuple[int, str]] | None = None,
) -> list[dict[str, Any]]:
    """Core aggregation for lead_effectiveness and lead_effectiveness_for_hypothesis.

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
                if filter_active:
                    deltas = [
                        _abs_delta(r.get("before"), r.get("after"))
                        for r in resolutions
                        if matches(
                            case_idx,
                            r.get("hypothesis", ""),
                            h_names.get(r.get("hypothesis", ""), ""),
                        )
                    ]
                else:
                    deltas = [_abs_delta(r.get("before"), r.get("after")) for r in resolutions]
                if deltas:
                    lead_mean = sum(deltas) / len(deltas)
                    branching_deltas.setdefault(name, []).append(lead_mean)

            # Prediction-fidelity: route compliance for leads with predictions.
            # Orthogonal to the hypothesis filter.
            if lead.get("predictions"):
                advance_tos = {
                    p.get("advance_to")
                    for p in (lead.get("predictions") or [])
                    if isinstance(p, dict) and p.get("advance_to")
                }
                # Next lead in the companion, if any
                next_lead_name = leads[idx + 1].get("name") if idx + 1 < len(leads) else None
                if next_lead_name is None:
                    matched = "CONCLUDE" in advance_tos
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

    Examples:
      lead_effectiveness_for_hypothesis(corpus, '?*compromise*')
      lead_effectiveness_for_hypothesis(corpus, '?*monitoring*', '?*compromise*')
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
    Each hit: lead_name, discrimination_score, mean_signed_delta_h1, mean_signed_delta_h2, case_count.
    """
    # per_lead → list of (signed_delta_h1_for_lead, signed_delta_h2_for_lead) per case
    per_lead: dict[str, list[tuple[float, float]]] = {}

    for c in corpus:
        h_names: dict[str, str] = {
            h["id"]: _hypothesis_name(h) for h in c.iter_new_hypotheses()
        }

        # Check whether this case contains both pattern classes
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
# Topology-conditioned retrieval (handler-facing; library-only, no CLI flag)
# ---------------------------------------------------------------------------


# Labels describe the *cumulative* relaxation at each tier. Tier N drops
# every field tier N-1 already dropped, plus the one named; the label names
# only the newly-relaxed field so the reader sees what each step gave up.
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
      1 — drop parent.classification      → {attached.type, attached.class, relation, parent.type}
      2 — also drop parent.type           → {attached.type, attached.class, relation}
      3 — also drop attached.classification → {attached.type, relation}
      4 — name-glob fallback (handled in the caller, not here)

    Any required field that's None on either side fails the match at tiers 0–3 —
    topology matching needs concrete values; gaps fall through to the next tier.
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
    rows. Rows are ranked by per-occurrence effectiveness — `mean_branching_delta`
    desc, then `fidelity_rate` desc, then `branching_support` desc — with
    `branching_support` / `fidelity_support` surfaced as `n` for the reader.

    Returns `{hits, count, tier_used, tier_label}`. When no tier produces hits,
    returns `{hits: [], count: 0, tier_used: 4, tier_label: "no match"}`.
    """
    ids, tier_used = _walk_tiers(corpus, fp)
    if not ids:
        return {"hits": [], "count": 0, "tier_used": 4, "tier_label": "no match"}
    rows = _lead_effectiveness_rows(corpus, hypothesis_id_filter=ids)
    rows.sort(
        key=lambda r: (
            r["mean_branching_delta"] if r["mean_branching_delta"] is not None else float("-inf"),
            r["fidelity_rate"] if r["fidelity_rate"] is not None else float("-inf"),
            r["branching_support"],
        ),
        reverse=True,
    )
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

    `final_weight_histogram` counts the peer's final weight as recorded in the
    case's resolutions (last-resolution-wins per peer within its case); buckets
    are `++ / + / null / - / --`. Sorted by `peer_count` desc.

    The matched-hypothesis classifications themselves appear in the output —
    they *are* peers at the query position (a topology is a position, not a
    named pick; classifications that sit at the same position are the
    alternatives we care about). Their presence is useful signal: the caller
    reads it as "this classification has been proposed here N times before."

    Returns `{hits, count, tier_used, tier_label}`.
    """
    ids, tier_used = _walk_tiers(corpus, fp)
    if not ids:
        return {"hits": [], "count": 0, "tier_used": 4, "tier_label": "no match"}

    # Group matched ids by case — a case is in-scope if it contains ≥1
    # hypothesis at the query topology.
    cases_in_scope: set[int] = {case_idx for case_idx, _ in ids}

    peer_counts: dict[str, int] = {}
    peer_weights: dict[str, dict[str, int]] = {}
    weight_buckets = ("++", "+", "null", "-", "--")

    for case_idx in cases_in_scope:
        c = corpus[case_idx]
        # Resolve last-weight per hypothesis_id in this case from resolutions.
        last_weight: dict[str, Any] = {}
        for lead in c.leads:
            for r in lead.get("resolutions", []) or []:
                h_id = r.get("hypothesis")
                if h_id:
                    last_weight[h_id] = r.get("after")
        # Count each classification once per in-scope case (dedup per case).
        seen_this_case: set[str] = set()
        for sib in c.hypotheses:
            classification = _hypothesis_name(sib)
            sib_id = sib.get("id")
            if not classification or not sib_id or classification in seen_this_case:
                continue
            seen_this_case.add(classification)
            peer_counts[classification] = peer_counts.get(classification, 0) + 1
            bucket_key = "null" if last_weight.get(sib_id) is None else str(last_weight[sib_id])
            hist = peer_weights.setdefault(
                classification, {b: 0 for b in weight_buckets}
            )
            if bucket_key in hist:
                hist[bucket_key] += 1

    hits = [
        {
            "classification": name,
            "peer_count": peer_counts[name],
            "final_weight_histogram": peer_weights[name],
        }
        for name in sorted(peer_counts.keys(), key=lambda n: (-peer_counts[n], n))
    ]
    return {
        "hits": hits,
        "count": len(hits),
        "tier_used": tier_used,
        "tier_label": _TIER_LABELS[tier_used],
    }


# ---------------------------------------------------------------------------
# Class 9 — weight-reversal mining (ANALYZE — pitfall extraction before grading)
# ---------------------------------------------------------------------------

_POSITIVE_WEIGHTS = {None, "+", "++"}
_NEGATIVE_WEIGHTS = {"-", "--"}


def weight_reversal_mining(
    corpus: list[Companion],
    *,
    hypothesis_pattern: str | None = None,
    reversals_only: bool = False,
) -> dict[str, Any]:
    """Find resolutions where hypothesis weight moved from positive to negative.

    'Positive' means before ∈ {null, +, ++}; 'negative' means after ∈ {-, --}.
    These reversals surface pitfall text — evidence that appeared supportive but
    turned out not to be. Useful for pre-registering pitfalls at HYPOTHESIZE time.

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
# Class 10 — lead pair synergy (HYPOTHESIZE / GATHER — composite-dispatch design)
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
    # per_pair → list of (synergy_value, hypothesis_name)
    pair_data: dict[tuple[str, str], list[tuple[float, str]]] = {}

    for c in corpus:
        h_names: dict[str, str] = {h["id"]: h.get("name", "") for h in c.iter_new_hypotheses()}

        # Group leads by loop
        by_loop: dict[int, list[dict[str, Any]]] = {}
        for lead in c.leads:
            loop = lead.get("loop") or 0
            by_loop.setdefault(loop, []).append(lead)

        for loop, loop_leads in by_loop.items():
            if len(loop_leads) < 2:
                continue

            # For each ordered pair (A, B)
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
        # Pick an example hypothesis (first observed)
        example_hyp = observations[0][1]
        rows.append({
            "lead_a": name_a,
            "lead_b": name_b,
            "mean_synergy": round(mean_synergy, 4),
            "case_count": case_count,
            "example_hypothesis": example_hyp,
        })
    rows.sort(key=lambda r: float(r["mean_synergy"]), reverse=True)
    return {"hits": rows, "count": len(rows)}


# ---------------------------------------------------------------------------
# Class 11 — post-failure recovery map (GATHER — recovery-lead planning after a dead lead)
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
    # key: (failed_lead_name, system, next_lead_name) → list of abs_deltas
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

            # Find next lead
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
# Class 12 — independent data source metric (CONCLUDE — termination / confidence grounding)
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


def enumerate_hypothesis_tree(corpus: list[Companion]) -> dict[str, Any]:
    """Return the parent-child hierarchy of hypothesis IDs across the corpus.

    Hierarchy is inferred from the h-001-002 ID structure via _parse_hypothesis_chain.

    Returns:
      tree  — dict mapping root_id → list of {"id": child_id, "name": child_name}
      flat  — list of {"parent_id": str, "parent_name": str, "child_id": str, "child_name": str}
      count — total distinct hypothesis IDs seen
    """
    # Collect all hypothesis (id, name) pairs
    id_to_name: dict[str, str] = {}
    for c in corpus:
        for h in c.iter_new_hypotheses():
            h_id = h.get("id", "")
            name = h.get("name", "")
            if h_id:
                id_to_name[h_id] = name

    # Build parent → children mapping from ID structure
    tree: dict[str, list[str]] = {}  # root_id → [child_id, ...]
    child_ids: set[str] = set()

    for h_id in id_to_name:
        chain = _parse_hypothesis_chain(h_id)
        if len(chain) >= 2:
            parent_id = chain[-2]
            tree.setdefault(parent_id, []).append(h_id)
            child_ids.add(h_id)

    # Collect root IDs (hypotheses that are not children of any other)
    root_ids = [h_id for h_id in id_to_name if h_id not in child_ids]

    # Build structured tree output: root_id → sorted children
    tree_out: dict[str, list[dict[str, str]]] = {}
    for root_id in sorted(root_ids):
        children = tree.get(root_id, [])
        tree_out[root_id] = [
            {"id": c_id, "name": id_to_name.get(c_id, "")}
            for c_id in sorted(children)
        ]

    # Build flat list from ALL parent-child edges (not just roots → direct children)
    flat: list[dict[str, str]] = []
    for parent_id, children_ids in sorted(tree.items()):
        for child_id in sorted(children_ids):
            flat.append({
                "parent_id": parent_id,
                "parent_name": id_to_name.get(parent_id, ""),
                "child_id": child_id,
                "child_name": id_to_name.get(child_id, ""),
            })

    return {
        "tree": tree_out,
        "flat": flat,
        "count": len(id_to_name),
    }
