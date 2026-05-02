"""Query classes 13–14: ANALYZE-phase episodic recall.

Shared graph-context filter (--vertex-where):
  Both classes accept a graph-context filter so ANALYZE can scope its recall
  to cases whose confirmed graph resembles the current case.

  Spec: KIND[:KEY=VAL[,KEY=VAL...]]
    KIND       — exact vertex.kind match, or '*' for any
    KEY=VAL    — vertex.attributes.KEY matches VAL (fnmatch; '*' = presence-only)

  Multiple specs AND together.

Public functions:
  parse_vertex_where_spec       — parse one --vertex-where string
  lead_exemplars                — [ANALYZE] past resolutions of leads matching a pattern
  authorization_calibration     — [ANALYZE] verdict distribution for an authz contract pattern
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime, UTC
from typing import Any
from collections.abc import Iterator

import polars as pl

from .corpus import Companion, conclude_field
from ._shared import (
    _lead_kind,
    _parse_created_at,
)


# ---------------------------------------------------------------------------
# Shared graph-context filter: --vertex-where
# ---------------------------------------------------------------------------

def parse_vertex_where_spec(spec: str) -> tuple[str, dict[str, str]]:
    """Parse one '--vertex-where' string into (kind, {attr: pattern}).

    Accepted forms:
      'endpoint'                         — kind only (no attribute predicates)
      'endpoint:'                        — same; trailing colon tolerated
      'endpoint:*'                       — same; '*' alone means no attribute predicates
      'endpoint:classification=high'     — kind + one attribute predicate
      'endpoint:classification=*,os=lin' — kind + multiple (AND) attribute predicates
    """
    head, _, rest = spec.partition(":")
    kind = head.strip()
    attrs: dict[str, str] = {}
    rest = rest.strip()
    if rest and rest != "*":
        for pair in rest.split(","):
            pair = pair.strip()
            if not pair:
                continue
            k, eq, v = pair.partition("=")
            if not eq:
                raise ValueError(
                    f"--vertex-where: expected key=value in {pair!r} "
                    f"(use 'KIND' or 'KIND:*' for kind-only filters)"
                )
            attrs[k.strip()] = v.strip()
    return kind, attrs


# Underscore alias preserved for cli.py back-compat.
_parse_vertex_where_spec = parse_vertex_where_spec


def _confirmed_vertices(c: Companion) -> Iterator[dict[str, Any]]:
    """Yield every confirmed vertex in the case: prologue + observations."""
    for v in c.prologue.get("vertices") or []:
        if isinstance(v, dict):
            yield v
    for lead in c.leads:
        obs = (lead.get("outcome") or {}).get("observations") or {}
        for v in obs.get("vertices") or []:
            if isinstance(v, dict):
                yield v


def _target_vertex(c: Companion, lead: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve a lead's target vertex_id against the confirmed graph."""
    target_id = lead.get("target")
    if not target_id:
        return None
    for v in _confirmed_vertices(c):
        if v.get("id") == target_id:
            return v
    return None


def _vertex_matches_spec(v: dict[str, Any], kind: str, attrs: dict[str, str]) -> bool:
    if kind != "*" and v.get("kind") != kind and v.get("type") != kind:
        # invlang vertices use either `kind` or `type` depending on schema vintage.
        return False
    v_attrs = v.get("attributes") or {}
    cls = v.get("classification")
    for k, pat in attrs.items():
        candidate = v_attrs.get(k) if k != "classification" else cls
        if candidate is None:
            return False
        if pat == "*":
            continue
        if not fnmatch.fnmatchcase(str(candidate), pat):
            return False
    return True


def _vertex_where_match(
    c: Companion,
    specs: list[tuple[str, dict[str, str]]] | None,
    scope: str = "any",
    *,
    lead: dict[str, Any] | None = None,
) -> bool:
    """Check whether `c`'s confirmed graph satisfies every spec (AND) under `scope`.

    scope ∈ {"target", "prologue", "any"}:
      target   — single vertex resolved from `lead.target`. All specs must match it.
      prologue — only vertices declared in `prologue.vertices`.
      any      — any confirmed vertex (prologue + observations).
    """
    if not specs:
        return True
    if scope == "target":
        if lead is None:
            return False
        v = _target_vertex(c, lead)
        if v is None:
            return False
        return all(_vertex_matches_spec(v, kind, attrs) for kind, attrs in specs)
    candidates: list[dict[str, Any]]
    if scope == "prologue":
        candidates = [v for v in (c.prologue.get("vertices") or []) if isinstance(v, dict)]
    else:
        candidates = list(_confirmed_vertices(c))
    for kind, attrs in specs:
        if not any(_vertex_matches_spec(v, kind, attrs) for v in candidates):
            return False
    return True


# ---------------------------------------------------------------------------
# Class 13 — lead-exemplars (ANALYZE — episodic recall keyed by lead)
# ---------------------------------------------------------------------------

_LEAD_EXEMPLAR_KEY_ATTRS = ("kind", "type", "classification", "role", "environment", "os")


def _target_vertex_summary(v: dict[str, Any] | None) -> dict[str, Any] | None:
    if v is None:
        return None
    out: dict[str, Any] = {}
    if v.get("kind") is not None:
        out["kind"] = v.get("kind")
    elif v.get("type") is not None:
        out["kind"] = v.get("type")
    if v.get("classification") is not None:
        out["classification"] = v.get("classification")
    attrs = v.get("attributes") or {}
    for k in _LEAD_EXEMPLAR_KEY_ATTRS:
        if k in ("kind", "type", "classification"):
            continue
        if k in attrs:
            out[k] = attrs[k]
    return out


def _observation_summary(lead: dict[str, Any]) -> dict[str, Any]:
    obs = (lead.get("outcome") or {}).get("observations") or {}
    vertices = [v for v in (obs.get("vertices") or []) if isinstance(v, dict)]
    edges = [e for e in (obs.get("edges") or []) if isinstance(e, dict)]
    v_kinds: list[str] = []
    for v in vertices:
        k = v.get("kind") or v.get("type")
        if isinstance(k, str) and k not in v_kinds:
            v_kinds.append(k)
    e_kinds: list[str] = []
    for e in edges:
        k = e.get("kind") or e.get("relation")
        if isinstance(k, str) and k not in e_kinds:
            e_kinds.append(k)
    return {
        "vertex_count": len(vertices),
        "edge_count": len(edges),
        "vertex_kinds": v_kinds[:5],
        "edge_kinds": e_kinds[:5],
    }


def _resolution_summary(
    resolutions: list[dict[str, Any]],
    h_names: dict[str, str],
) -> list[dict[str, Any]]:
    """Project resolutions to cross-case-displayable rows (drops scoped hypothesis_id)."""
    out: list[dict[str, Any]] = []
    for r in resolutions:
        if not isinstance(r, dict):
            continue
        h_id = r.get("hypothesis", "")
        reasoning = r.get("reasoning") or ""
        out.append({
            "hypothesis_name": h_names.get(h_id, ""),
            "before": r.get("before"),
            "after": r.get("after"),
            "severity_of_test": r.get("severity_of_test"),
            "reasoning_head": reasoning.strip().split("\n", 1)[0][:160],
        })
    return out


def lead_exemplars(
    corpus: list[Companion],
    lead_pattern: str,
    *,
    vertex_where: list[tuple[str, dict[str, str]]] | None = None,
    vertex_scope: str = "any",
    limit: int | None = None,
) -> dict[str, Any]:
    """Recall past resolutions of leads whose name matches `lead_pattern`.

    Returns hits (raw exemplars) plus an aggregate `summary` over the full
    matched set: disposition mix, assessment mix, modal hypothesis outcomes,
    and surprise count (cases where a hypothesis went `+`/`++` then `-`/`--`).

    Output drops investigation-scoped IDs (lead_id, hypothesis_id) — only
    cross-case fields.

    Default sort: most-recent first by `Companion.created_at`; case_id tiebreak.
    """
    hits: list[dict[str, Any]] = []
    disposition_mix: dict[str, int] = {}
    assessment_mix: dict[str, int] = {}
    hyp_outcome_acc: dict[str, dict[str, Any]] = {}
    surprises = 0

    for c in corpus:
        if not _vertex_where_match(c, vertex_where, vertex_scope):
            if vertex_scope != "target":
                continue
        h_names: dict[str, str] = {h["id"]: h.get("name", "") for h in c.iter_new_hypotheses()}
        for lead in c.leads:
            name = lead.get("name") or ""
            if not fnmatch.fnmatchcase(name, lead_pattern):
                continue
            if vertex_scope == "target" and not _vertex_where_match(
                c, vertex_where, vertex_scope, lead=lead,
            ):
                continue
            resolutions = lead.get("resolutions") or []
            disp = c.conclude.get("disposition")
            if disp:
                disposition_mix[disp] = disposition_mix.get(disp, 0) + 1
            saw_reversal = False
            for r in resolutions:
                if not isinstance(r, dict):
                    continue
                after = r.get("after")
                key = after if after is not None else "null"
                assessment_mix[key] = assessment_mix.get(key, 0) + 1
                before = r.get("before")
                if before in {"+", "++"} and after in {"-", "--"}:
                    saw_reversal = True
                h_name = h_names.get(r.get("hypothesis", ""), "")
                if h_name:
                    bucket = hyp_outcome_acc.setdefault(
                        h_name,
                        {"weights": {}, "dispositions": {}, "n": 0},
                    )
                    bucket["n"] += 1
                    wkey = after if after is not None else "null"
                    bucket["weights"][wkey] = bucket["weights"].get(wkey, 0) + 1
                    if disp:
                        bucket["dispositions"][disp] = bucket["dispositions"].get(disp, 0) + 1
            if saw_reversal:
                surprises += 1
            hits.append({
                "case_id": c.case_id,
                "lead_name": name,
                "loop": lead.get("loop"),
                "system": (lead.get("query_details") or {}).get("system"),
                "kind": _lead_kind(lead),
                "target_vertex": _target_vertex_summary(_target_vertex(c, lead)),
                "observation_summary": _observation_summary(lead),
                "resolutions": _resolution_summary(resolutions, h_names),
                "disposition": disp,
                "termination_category": conclude_field(c.conclude, "termination", "category"),
                "confidence": c.conclude.get("confidence"),
                "_sort_ts": _parse_created_at(c.created_at),
            })

    def _sort_key(h: dict[str, Any]) -> tuple[int, datetime, str]:
        ts = h["_sort_ts"]
        if ts is None:
            return (1, datetime.min.replace(tzinfo=UTC), h["case_id"])
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return (0, ts, h["case_id"])

    hits.sort(key=_sort_key, reverse=True)
    for h in hits:
        h.pop("_sort_ts", None)

    displayed = hits if limit is None else hits[:limit]

    modal: list[dict[str, Any]] = []
    for hname, bucket in sorted(
        hyp_outcome_acc.items(), key=lambda kv: (-kv[1]["n"], kv[0])
    )[:3]:
        weights = bucket["weights"]
        modal_weight = max(weights.items(), key=lambda kv: kv[1])[0] if weights else None
        modal.append({
            "hypothesis_name": hname,
            "n": bucket["n"],
            "modal_final_weight": modal_weight,
            "weight_mix": dict(sorted(weights.items())),
            "disposition_mix": dict(sorted(bucket["dispositions"].items())),
        })

    summary = {
        "disposition_mix": dict(sorted(disposition_mix.items())),
        "assessment_mix": dict(sorted(assessment_mix.items())),
        "modal_hypothesis_outcome": modal,
        "surprises": surprises,
    }

    return {
        "hits": displayed,
        "summary": summary,
        "count": len(hits),
        "displayed": len(displayed),
    }


# ---------------------------------------------------------------------------
# Class 14 — authorization calibration (ANALYZE — authz-contract recall)
# ---------------------------------------------------------------------------

def _hypothesis_predicate(h: dict[str, Any], ac_idx: int) -> str | None:
    """Pull the predicate text of the n-th authorization_contract on h."""
    contracts = h.get("authorization_contract") or h.get("authorization_contracts")
    if isinstance(contracts, dict):
        return contracts.get("predicate") if ac_idx in (0, 1) else None
    if isinstance(contracts, list):
        if 0 <= ac_idx - 1 < len(contracts):
            entry = contracts[ac_idx - 1]
            if isinstance(entry, dict):
                return entry.get("predicate")
        if 0 <= ac_idx < len(contracts):
            entry = contracts[ac_idx]
            if isinstance(entry, dict):
                return entry.get("predicate")
    return None


_FULFILLS_RE = re.compile(r"^(h-[A-Za-z0-9\-]+)\.ac(\d+)$")


def _resolve_contract(
    fulfills: str,
    hypotheses_by_id: dict[str, dict[str, Any]],
) -> tuple[str | None, str | None]:
    """`h-001.ac1` → (hypothesis_name, predicate_text). Either may be None."""
    if not isinstance(fulfills, str):
        return None, None
    m = _FULFILLS_RE.match(fulfills)
    if not m:
        return None, None
    h_id, ac_str = m.group(1), m.group(2)
    h = hypotheses_by_id.get(h_id)
    if h is None:
        return None, None
    return h.get("name"), _hypothesis_predicate(h, int(ac_str))


def _iter_authorized_edges(c: Companion) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Yield (edge, resolution) pairs for every authorization_resolutions entry.

    Walks prologue.edges, lead observations, and edge-targeted attribute_updates
    that themselves carry an authorization_resolutions block.
    """
    for e in c.prologue.get("edges") or []:
        if not isinstance(e, dict):
            continue
        for r in e.get("authorization_resolutions") or []:
            if isinstance(r, dict):
                yield e, r
    for lead in c.leads:
        outcome = lead.get("outcome") or {}
        obs = outcome.get("observations") or {}
        for e in obs.get("edges") or []:
            if not isinstance(e, dict):
                continue
            for r in e.get("authorization_resolutions") or []:
                if isinstance(r, dict):
                    yield e, r
        for upd in outcome.get("attribute_updates") or []:
            if not isinstance(upd, dict):
                continue
            target_id = upd.get("target_edge") or upd.get("target")
            if not target_id:
                continue
            ar_list = (upd.get("attributes") or {}).get("authorization_resolutions") or upd.get("authorization_resolutions") or []
            if not isinstance(ar_list, list):
                continue
            shadow_edge = {"id": target_id}
            for r in ar_list:
                if isinstance(r, dict):
                    yield shadow_edge, r


def _lead_owning_edge(c: Companion, edge_id: str | None) -> str | None:
    """Find the lead whose observations contain this edge_id (best-effort)."""
    if not edge_id:
        return None
    for lead in c.leads:
        obs = (lead.get("outcome") or {}).get("observations") or {}
        for e in obs.get("edges") or []:
            if isinstance(e, dict) and e.get("id") == edge_id:
                return lead.get("name")
    return None


def authorization_calibration(
    corpus: list[Companion],
    contract_pattern: str,
    *,
    vertex_where: list[tuple[str, dict[str, str]]] | None = None,
    vertex_scope: str = "any",
) -> dict[str, Any]:
    """Distribution + exemplars of authorization_resolutions verdicts for a contract pattern.

    `contract_pattern` is fnmatch-matched against the fulfilling hypothesis's
    name **and** substring-matched against the contract's predicate text. Match
    on either is sufficient.

    Output `surprises` counts edges that received divergent verdicts across
    multiple resolutions for the same contract.
    """
    matched_rows: list[dict[str, Any]] = []
    matched_contracts: set[str] = set()
    edge_verdicts: dict[tuple[str, str, str], set[str]] = {}
    pattern_lower = contract_pattern.lower().strip("*")

    for c in corpus:
        if not _vertex_where_match(c, vertex_where, vertex_scope):
            continue
        hypotheses_by_id = {h["id"]: h for h in c.iter_new_hypotheses() if h.get("id")}
        for edge, r in _iter_authorized_edges(c):
            fulfills = r.get("fulfills_contract") or ""
            h_name, predicate = _resolve_contract(fulfills, hypotheses_by_id)
            name_match = bool(h_name) and fnmatch.fnmatchcase(h_name, contract_pattern)
            predicate_match = (
                bool(predicate)
                and pattern_lower
                and pattern_lower in predicate.lower()
            )
            if not (name_match or predicate_match):
                continue
            if predicate:
                matched_contracts.add(predicate)
            elif h_name:
                matched_contracts.add(h_name)
            verdict = r.get("verdict") or "unknown"
            edge_id = edge.get("id") or "?"
            key = (c.case_id, edge_id, fulfills)
            edge_verdicts.setdefault(key, set()).add(verdict)
            cond_ctx = r.get("conditioning_context") or []
            cond_head = " | ".join(str(x) for x in cond_ctx)[:160] if isinstance(cond_ctx, list) else ""
            matched_rows.append({
                "verdict": verdict,
                "case_id": c.case_id,
                "lead_name": _lead_owning_edge(c, edge.get("id")),
                "anchor_kind": r.get("anchor_kind"),
                "anchor_id": r.get("anchor_id"),
                "grounding_kind": r.get("grounding_kind"),
                "authority_for_question": r.get("authority_for_question"),
                "as_of": r.get("as_of"),
                "disposition": c.conclude.get("disposition"),
                "confidence": c.conclude.get("confidence"),
                "conditioning_context_head": cond_head,
                "contract_name": h_name,
                "contract_predicate": predicate,
            })

    if not matched_rows:
        return {
            "distribution": [],
            "exemplars": {},
            "matched_contracts": [],
            "surprises": 0,
            "count": 0,
        }

    df = pl.DataFrame(matched_rows)
    dist = (
        df.group_by("verdict")
        .agg(
            pl.len().alias("count"),
            (pl.col("authority_for_question") == "full").mean().alias("full_authority_rate"),
            pl.col("disposition").alias("dispositions"),
        )
        .sort("verdict")
    )
    total = df.height
    distribution: list[dict[str, Any]] = []
    for row in dist.to_dicts():
        disp_list = row.get("dispositions") or []
        disp_mix: dict[str, int] = {}
        for d in disp_list:
            if d:
                disp_mix[d] = disp_mix.get(d, 0) + 1
        full_rate = row.get("full_authority_rate")
        distribution.append({
            "verdict": row["verdict"],
            "count": row["count"],
            "share": round(row["count"] / total, 4),
            "full_authority_rate": round(full_rate, 4) if full_rate is not None else None,
            "disposition_mix": dict(sorted(disp_mix.items())),
        })

    exemplars: dict[str, list[dict[str, Any]]] = {}
    for row in matched_rows:
        bucket = exemplars.setdefault(row["verdict"], [])
        if len(bucket) >= 3:
            continue
        bucket.append({k: v for k, v in row.items() if k != "verdict"})

    surprises = sum(1 for verdicts in edge_verdicts.values() if len(verdicts) > 1)

    return {
        "distribution": distribution,
        "exemplars": exemplars,
        "matched_contracts": sorted(matched_contracts),
        "surprises": surprises,
        "count": total,
    }
