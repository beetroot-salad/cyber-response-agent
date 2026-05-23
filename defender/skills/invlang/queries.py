"""Cross-case advisory retrieval over a loaded defender companion corpus.

Three query helpers, ported from the soc-agent equivalents under
`soc-agent/scripts/invlang/queries_{lookup,effectiveness}.py` and adapted
to the defender parser's canonical companion dict shape:

- `lead_sequence_pattern` (Class 5)  — what did past cases like this do?
- `hypothesis_name_wildcard` (Class 6) — what hypotheses spawned + how
  did they terminate?
- `lead_branch_effects` (Class 8)    — per-lead, per-hypothesis effect
  distribution + empty-rate; the discussion-anchor query for PLAN.
- `hypothesis_shape_match`           — topology-shape → ?names used,
  with weight + disposition distributions. Cross-signature: the answer
  to "what have we called this kind of fork before?"

All three operate on `list[Companion]` from `defender.skills.invlang.corpus`
and return dicts safe to dump as JSON. Investigation-scoped ids
(`hypothesis_id`, `lead_id`) are deliberately stripped from outputs —
cross-case retrieval ranks on observable attributes, not record handles.

The defender parser emits `tests_hypotheses` (not `tests`) for the lead
column that names which hypotheses a lead is forking; the helpers read
that field directly.
"""

from __future__ import annotations

import fnmatch
from typing import Any
from collections.abc import Iterable

from .corpus import Companion


# ---------------------------------------------------------------------------
# Weight / ordering tables
# ---------------------------------------------------------------------------

_WEIGHT_NUMERIC: dict[Any, int] = {None: 0, "++": 2, "+": 1, "-": -1, "--": -2}
_FINAL_WEIGHT_SORT: dict[Any, int] = {"++": 4, "+": 3, None: 2, "-": 1, "--": 0}
_WEIGHT_BUCKETS = ("++", "+", "-", "--")


# ---------------------------------------------------------------------------
# Per-record helpers
# ---------------------------------------------------------------------------

def _hypothesis_name(h: dict[str, Any]) -> str:
    return h.get("name", "") or ""


def _all_hypotheses(c: Companion) -> Iterable[dict[str, Any]]:
    """Hypothesize-block hypotheses plus any new_hypotheses spawned in leads."""
    yield from c.hypotheses
    for lead in c.leads:
        for h in lead.get("new_hypotheses", []) or []:
            if isinstance(h, dict):
                yield h


def _lead_outcome_empty(lead: dict[str, Any]) -> bool:
    """A lead is 'empty' when its analyzed observations carry no vertices and no
    edges. Defender's gather records payload-shape sidecars separately, but at
    the invlang level the observations block is the only signal we have.
    """
    obs = (lead.get("outcome") or {}).get("observations") or {}
    return not obs.get("vertices") and not obs.get("edges")


def _conclude_field(conclude: dict[str, Any], *path: str) -> Any:
    cur: Any = conclude
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


# ---------------------------------------------------------------------------
# Class 5 — lead sequence pattern (PLAN-time: "what did past cases do?")
# ---------------------------------------------------------------------------

def _lead_trace(c: Companion) -> str:
    """Compact per-case trace: lead1→lead2→...→termination:disposition.

    Annotates the bare lead name with a 1–2 char suffix that surfaces failure
    or consultation shape without exploding to full observations. Branching
    vs. interpretive vs. mechanical is intentionally NOT in the trace — that
    would duplicate Class 8's signal and bloat the line.
    """
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
    """Serialize each case's gather sequence as a trace string.

    Filters are AND-ed. Default sort: longest investigation first (proxy for
    the cases that branched the most — usually the most informative).
    """
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


# ---------------------------------------------------------------------------
# Class 6 — hypothesis name wildcard (PLAN-time: seed vocabulary discovery)
# ---------------------------------------------------------------------------

def hypothesis_name_wildcard(
    corpus: list[Companion],
    pattern: str,
    *,
    final_weight: str | None = None,
    disposition: str | None = None,
    signature_id: str | None = None,
) -> dict[str, Any]:
    """Match hypothesis names against an fnmatch pattern (e.g. '?*brute-force*').

    For each matching hypothesis: emit `case_id`, the hypothesis `name`, its
    final weight (last assessment seen across the case's lead resolutions, or
    the initial weight if never assessed), the case disposition, and the
    hypothesis status. `hypothesis_id` is deliberately omitted — it's
    investigation-scoped and meaningless cross-case.

    Sort: final_weight desc (++ → + → null → - → --), then case_id for
    stability.
    """
    hits: list[dict[str, Any]] = []
    for c in corpus:
        if disposition is not None and c.conclude.get("disposition") != disposition:
            continue
        if signature_id is not None and c.signature_id != signature_id:
            continue
        final: dict[str, Any] = {h["id"]: h.get("weight") for h in _all_hypotheses(c) if "id" in h}
        for lead in c.leads:
            for r in lead.get("resolutions", []) or []:
                h_id = r.get("hypothesis")
                if h_id:
                    final[h_id] = r.get("after")
        for h in _all_hypotheses(c):
            name = _hypothesis_name(h)
            if not fnmatch.fnmatchcase(name, pattern):
                continue
            weight = final.get(h.get("id"))
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
    hits.sort(key=lambda r: (_FINAL_WEIGHT_SORT.get(r["final_weight"], 2), r["case_id"]), reverse=True)
    return {"hits": hits, "count": len(hits), "pattern": pattern}


# ---------------------------------------------------------------------------
# Class 8 — per-lead, per-hypothesis effect distribution (PLAN discrimination)
# ---------------------------------------------------------------------------

def _empty_bucket() -> dict[str, int]:
    return {b: 0 for b in _WEIGHT_BUCKETS}


def lead_branch_effects(
    corpus: list[Companion],
    *,
    hypothesis_patterns: tuple[str, ...] = (),
    min_support: int = 1,
    max_hypotheses_per_lead: int = 5,
) -> dict[str, Any]:
    """For each lead name observed across the corpus, surface:

    - `n`               — total appearances
    - `empty_rate`      — "K/N" string: K of N appearances returned no
                          observations
    - `per_hypothesis_effect` — for each touched hypothesis (filtered to
                          `hypothesis_patterns` if supplied), a histogram of
                          assessment shifts ({++, +, -, --} counts) PLUS the
                          number of appearances where the lead's resolutions
                          named that hypothesis (`support`).

    The output is data, not a recommendation. Ranking the leads is the
    caller's job — we sort by `n` desc as a tiebreaker stable enough for
    LLM consumption, then by lead_name for determinism.

    `min_support` drops lead-rows whose total `n` falls below the threshold.
    `max_hypotheses_per_lead` caps the per-lead breakdown to the K
    most-touched hypotheses (by resolution count) when no patterns are
    supplied; with patterns, all matching hypotheses are shown regardless.

    The defender corpus stores per-resolution shifts on the lead's
    `resolutions[]` (each row carries `hypothesis` + `before` + `after`),
    keyed by `hypothesis` = the synthetic id `h-NNN`. We resolve the id to a
    name via the case's hypothesis index.
    """
    counts: dict[str, int] = {}
    empties: dict[str, int] = {}
    per_hyp: dict[str, dict[str, dict[str, int]]] = {}

    patterns_active = bool(hypothesis_patterns)

    def hyp_matches(name: str) -> bool:
        if not patterns_active:
            return True
        return any(fnmatch.fnmatchcase(name, p) for p in hypothesis_patterns)

    for c in corpus:
        h_names = {h["id"]: _hypothesis_name(h) for h in _all_hypotheses(c) if "id" in h}
        for lead in c.leads:
            name = lead.get("name")
            if not name:
                # Nameless leads can't be cross-case keys — drop them silently
                # rather than collapsing them into a "?" bucket that the caller
                # can't act on. Parser-side issue, not retrieval's to fix.
                continue

            # Which hypothesis names did this lead occurrence touch? Two
            # sources: declared via `tests_hypotheses` (the lead's fork
            # declaration, surfaces empty-gather attempts that produced no
            # resolution) plus actual `resolutions[]` entries (rows that
            # produced an assessment shift). Resolution-only would lose the
            # high-empty-rate signal precisely when it matters — a lead that
            # forked for ?H but returned nothing.
            touched: set[str] = set()
            for h_id in lead.get("tests_hypotheses", []) or []:
                if (hn := h_names.get(h_id)):
                    touched.add(hn)
            for r in lead.get("resolutions", []) or []:
                if (hn := h_names.get(r.get("hypothesis", ""))):
                    touched.add(hn)

            if patterns_active:
                matching = {h for h in touched if hyp_matches(h)}
                if not matching:
                    # No frontier match — this occurrence is irrelevant to
                    # the caller's question. Skip entirely so `n` and
                    # `empty_rate` reflect frontier-specific support only.
                    continue
            else:
                matching = touched

            counts[name] = counts.get(name, 0) + 1
            if _lead_outcome_empty(lead):
                empties[name] = empties.get(name, 0) + 1

            # Initialize a zero-bucket entry for every matching touched
            # hypothesis. Leads that forked for ?H but never resolved still
            # surface here with all-zero counts; combined with `empty_rate`
            # they carry the "this lead failed on ?H" signal. Iterate
            # sorted so per-lead dict insertion order is stable across
            # PYTHONHASHSEED (matching is a set).
            for hn in sorted(matching):
                per_hyp.setdefault(name, {}).setdefault(hn, _empty_bucket())

            for r in lead.get("resolutions", []) or []:
                hn = h_names.get(r.get("hypothesis", ""), "")
                if not hn or (patterns_active and not hyp_matches(hn)):
                    continue
                shift = r.get("after")
                if shift not in _WEIGHT_BUCKETS:
                    continue
                per_hyp[name][hn][shift] += 1

    rows: list[dict[str, Any]] = []
    for name, n in counts.items():
        if n < min_support:
            continue
        hyp_table = per_hyp.get(name, {})
        if not patterns_active and len(hyp_table) > max_hypotheses_per_lead:
            # Keep the K hypotheses this lead most often resolved against.
            # Name is the tiebreaker so equal-count entries stay deterministic
            # across Python hash seeds (matching sets and dicts inherit set
            # iteration order).
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

    rows.sort(key=lambda r: (-r["n"], r["lead_name"]))
    return {
        "leads": rows,
        "count": len(rows),
        "frontier": list(hypothesis_patterns) if patterns_active else None,
    }


# ---------------------------------------------------------------------------
# Topology-shape -> ?hypothesis-names (PLAN: "what have we called this fork?")
# ---------------------------------------------------------------------------

def hypothesis_shape_match(
    corpus: list[Companion],
    *,
    parent_type: str | None = None,
    parent_class: str | None = None,
    rel: str | None = None,
    attached_to_type: str | None = None,
) -> dict[str, Any]:
    """Group ?hypothesis-names by topology shape across the corpus.

    Filters (all optional, AND-ed):
      - `parent_type`        exact match on :H parent_type (closed vocab).
      - `parent_class`       fnmatch pattern on :H parent_class
                             (`bastion/*`, `*/internal/*`, exact string).
      - `rel`                exact match on the proposed-edge relation.
      - `attached_to_type`   exact match on the type of the vertex named
                             by the hypothesis's `attached_to` field
                             (resolved through the case's prologue).

    At least one filter is required — a wide-open query returns the whole
    catalog with no actionable signal. Cross-signature by design: same
    topology shape recurs across signatures, and the caller is asking
    "what have we called this kind of fork before?", not "what did we
    call it for this rule?".

    For each matching ?name, emit per-occurrence aggregates: total `n`,
    final-weight histogram (using the last assessment seen in any lead's
    resolutions, or the initial weight if never assessed), disposition
    histogram, and supporting `case_ids`. Investigation-scoped ids
    (`hypothesis_id`) are intentionally omitted.
    """
    if not (parent_type or parent_class or rel or attached_to_type):
        raise ValueError(
            "at least one of parent_type, parent_class, rel, "
            "attached_to_type required"
        )

    agg: dict[str, dict[str, Any]] = {}

    for c in corpus:
        # vertex id -> type for attached_to_type resolution
        v_type: dict[str, str] = {}
        for v in c.prologue.get("vertices", []) or []:
            if isinstance(v, dict) and v.get("id"):
                v_type[v["id"]] = v.get("type", "")

        # Final weight per hypothesis id (mirror hypothesis_name_wildcard).
        final: dict[str, Any] = {
            h["id"]: h.get("weight") for h in _all_hypotheses(c) if "id" in h
        }
        for lead in c.leads:
            for r in lead.get("resolutions", []) or []:
                h_id = r.get("hypothesis")
                if h_id:
                    final[h_id] = r.get("after")

        for h in _all_hypotheses(c):
            pe = h.get("proposed_edge") or {}
            pv = pe.get("parent_vertex") or {}

            h_parent_type = pv.get("type", "")
            h_parent_class = pv.get("classification", "")
            h_rel = pe.get("relation", "")
            h_attached_to_type = v_type.get(h.get("anchor", ""), "")

            if parent_type and h_parent_type != parent_type:
                continue
            if parent_class and not fnmatch.fnmatchcase(
                h_parent_class, parent_class
            ):
                continue
            if rel and h_rel != rel:
                continue
            if attached_to_type and h_attached_to_type != attached_to_type:
                continue

            name = _hypothesis_name(h)
            if not name:
                continue

            entry = agg.setdefault(name, {
                "n": 0,
                "weights": {**{b: 0 for b in _WEIGHT_BUCKETS}, "null": 0},
                "dispositions": {},
                "cases": set(),
            })
            entry["n"] += 1
            w = final.get(h.get("id"))
            bucket = w if w in _WEIGHT_BUCKETS else "null"
            entry["weights"][bucket] += 1
            disp = c.conclude.get("disposition") or "unknown"
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
