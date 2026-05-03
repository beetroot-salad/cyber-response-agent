"""Prior-recall context block for the ANALYZE phase.

Consults the invlang corpus (classes 13/14) for past resolutions of the
leads this loop just executed and the open authorization contracts on
live hypotheses, then renders a one-line digest per lead/contract.

The block is **advisory only** — it is *what graders did before*, not
evidence about *this* alert. The analyze subagent is told (via
`agents/analyze.md`) that recall cannot upgrade a `+` to `++`; severe
field-reads on authoritative edges still own the decisive grades.

Failure modes are silent: corpus load errors, query exceptions, or
empty results all collapse to "no block emitted" so recall never blocks
grading.
"""

from __future__ import annotations

from typing import Any
from collections.abc import Iterable

from scripts.handlers._markdown import iter_companion_dicts
from scripts.invlang import (
    authorization_calibration,
    lead_exemplars,
    load_corpus,
    parse_vertex_where_spec,
)


# How many corpus hits one --vertex-where-narrowed query must produce
# before we trust the narrowed view. Below this, drop the filter and use
# the unscoped digest. Pilot corpus is small (~6 cases); narrowing too
# hard zeroes out recall.
VERTEX_WHERE_MIN_NARROW_HITS = 10

# Maximum classifications-per-target distinct vertex-where specs we
# generate from the prologue. Keeps the recall block bounded.
MAX_VERTEX_WHERE_SPECS = 2


# ---------------------------------------------------------------------------
# Investigation.md → live hypotheses with open authorization_contract list
# ---------------------------------------------------------------------------


def _merge_companion_blocks(text: str) -> dict[str, Any]:
    """Merge every companion fence in investigation.md into one dict.

    Walks the dense ```invlang surface via `iter_companion_dicts`,
    projecting only the keys ANALYZE recall cares about (`prologue`,
    `hypothesize.hypotheses`, `findings`). Hypotheses are merged
    **last-wins** by id (mirrors
    `predict_priors.parse_prologue_and_last_hypothesize`); in-loop
    hypotheses authored under `findings[*].new_hypotheses` are folded
    into the same map so the open-contract scan sees them.
    """
    merged: dict[str, Any] = {
        "prologue": {"vertices": [], "edges": []},
        "hypothesize": {"hypotheses": []},
        "findings": [],
    }
    # Last-wins by id: a later block (typically the dense fence)
    # replaces an older copy of the same hypothesis. Insertion order is
    # preserved on first sight so the rendered list still reflects the
    # order PREDICT introduced the hypotheses in.
    hyps_by_id: dict[str, dict[str, Any]] = {}
    hyp_order: list[str] = []
    for doc in iter_companion_dicts(text):
        if isinstance(doc.get("prologue"), dict):
            merged["prologue"] = doc["prologue"]
        hyps = (doc.get("hypothesize") or {}).get("hypotheses") or []
        for h in hyps:
            if isinstance(h, dict) and h.get("id"):
                hid = h["id"]
                if hid not in hyps_by_id:
                    hyp_order.append(hid)
                hyps_by_id[hid] = h
        for findings_key in ("findings", "gather"):
            entries = doc.get(findings_key)
            if isinstance(entries, list):
                merged["findings"].extend(entries)
    # In-loop hypotheses authored under findings[*].new_hypotheses —
    # folded in only when no top-level record exists, so a later
    # hypothesize: block still wins.
    for lead in merged["findings"]:
        for h in (lead.get("new_hypotheses") or []) if isinstance(lead, dict) else []:
            if isinstance(h, dict) and h.get("id"):
                hid = h["id"]
                if hid not in hyps_by_id:
                    hyp_order.append(hid)
                    hyps_by_id[hid] = h
    merged["hypothesize"]["hypotheses"] = [hyps_by_id[hid] for hid in hyp_order]
    return merged


def _live_hypotheses(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Return hypotheses whose latest weight is not '--'."""
    out = []
    for h in (body.get("hypothesize") or {}).get("hypotheses") or []:
        if not isinstance(h, dict):
            continue
        if h.get("weight") == "--":
            continue
        out.append(h)
    return out


def _open_contracts(body: dict[str, Any]) -> list[tuple[str, str]]:
    """Return [(hyp_name, contract_predicate), ...] for live hypotheses
    with at least one declared authorization_contract. The hyp_name is
    used as the class-14 query key by default; the predicate is the
    fallback when two contracts share a hypothesis name.
    """
    out: list[tuple[str, str]] = []
    for h in _live_hypotheses(body):
        contracts = h.get("authorization_contract") or h.get("authorization_contracts") or []
        if isinstance(contracts, dict):
            contracts = [contracts]
        if not isinstance(contracts, list):
            continue
        for c in contracts:
            if not isinstance(c, dict):
                continue
            predicate = c.get("predicate") or ""
            name = h.get("name") or ""
            if name:
                out.append((name, predicate))
    return out


# ---------------------------------------------------------------------------
# Prologue → vertex-where specs (target endpoint classifications)
# ---------------------------------------------------------------------------


def _vertex_where_specs(body: dict[str, Any]) -> list[str]:
    """One spec per load-bearing classification on the prologue's primary
    endpoint. Caps at MAX_VERTEX_WHERE_SPECS. Returns spec strings ready
    for parse_vertex_where_spec().
    """
    specs: list[str] = []
    for v in (body.get("prologue") or {}).get("vertices") or []:
        if not isinstance(v, dict) or v.get("type") != "endpoint":
            continue
        classification = v.get("classification")
        if classification:
            specs.append(f"endpoint:classification={classification}")
        if len(specs) >= MAX_VERTEX_WHERE_SPECS:
            break
    return specs


# ---------------------------------------------------------------------------
# Digest renderers (one line per lead / per contract)
# ---------------------------------------------------------------------------


def _digest_lead(payload: dict[str, Any]) -> str:
    """`n=12, modal=benign 8/12, surprises=2`. Returns "" when the
    payload is empty (no hits)."""
    if not payload or not payload.get("count"):
        return ""
    n = payload["count"]
    summary = payload.get("summary") or {}
    disp_mix = summary.get("disposition_mix") or {}
    parts = [f"n={n}"]
    if disp_mix:
        modal_disp, modal_n = max(disp_mix.items(), key=lambda kv: kv[1])
        parts.append(f"modal={modal_disp} {modal_n}/{n}")
    surprises = summary.get("surprises") or 0
    if surprises:
        parts.append(f"surprises={surprises}")
    return ", ".join(parts)


def _digest_authz(payload: dict[str, Any]) -> str:
    """`n=7, authorized=5 unauthorized=1 indeterminate=1`. "" when empty."""
    if not payload or not payload.get("count"):
        return ""
    n = payload["count"]
    parts = [f"n={n}"]
    verdict_bits = []
    for entry in payload.get("distribution") or []:
        verdict_bits.append(f"{entry['verdict']}={entry['count']}")
    if verdict_bits:
        parts.append(" ".join(verdict_bits))
    surprises = payload.get("surprises") or 0
    if surprises:
        parts.append(f"surprises={surprises}")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Query wrappers — try unscoped first, then narrow if hits are dense
# ---------------------------------------------------------------------------


def _parse_specs(spec_strings: Iterable[str]) -> list[tuple[str, dict[str, str]]]:
    out = []
    for s in spec_strings:
        try:
            out.append(parse_vertex_where_spec(s))
        except Exception:
            continue
    return out


def _lead_pattern(lead_name: str) -> str:
    """Translate an exact lead name into an fnmatch pattern that tolerates
    naming drift across runs.

    Lead names in this repo follow a `family-of-action[-modifier]` shape:
    `approved-monitoring-sources`, `approved-monitoring-sources-anchor`,
    `approved-monitoring-sources-lookup`, `approved-monitoring-sources-authorization`.
    Exact match across this family returns zero (run #52 finding); the
    24-hit recall the corpus already has is locked behind a wildcard.

    Strategy: when the name has 4+ hyphen-separated segments, anchor on
    the first three and trail-glob the rest (covers the modifier-suffix
    drift). Otherwise just substring-glob the whole name. Pre-globbed
    patterns (containing `*`) pass through.
    """
    if "*" in lead_name:
        return lead_name
    parts = lead_name.split("-")
    if len(parts) >= 4:
        return "-".join(parts[:3]) + "*"
    return f"*{lead_name}*"


def _recall_lead(corpus: list, lead_name: str, vw_specs: list[str]) -> dict[str, Any] | None:
    """Run class 13 unscoped first; only narrow when n>=threshold."""
    pattern = _lead_pattern(lead_name)
    try:
        unscoped = lead_exemplars(corpus, lead_pattern=pattern)
    except Exception:
        return None
    if (unscoped.get("count") or 0) < VERTEX_WHERE_MIN_NARROW_HITS or not vw_specs:
        return unscoped
    parsed = _parse_specs(vw_specs)
    if not parsed:
        return unscoped
    try:
        narrowed = lead_exemplars(corpus, lead_pattern=pattern, vertex_where=parsed)
    except Exception:
        return unscoped
    return narrowed if (narrowed.get("count") or 0) > 0 else unscoped


def _recall_authz(corpus: list, hyp_name: str, predicate: str, vw_specs: list[str]) -> dict[str, Any] | None:
    """Try hyp-name first; if the matched_contracts set is ambiguous
    (multiple distinct contracts under one name), fall back to a 6-token
    predicate slice."""
    try:
        hit = authorization_calibration(corpus, contract_pattern=hyp_name)
    except Exception:
        hit = None
    if (not hit or not hit.get("count")) and predicate:
        slice_tok = " ".join(predicate.split()[:6])
        try:
            hit = authorization_calibration(corpus, contract_pattern=slice_tok)
        except Exception:
            return None
    if not hit or not hit.get("count"):
        return None
    if (hit.get("count") or 0) < VERTEX_WHERE_MIN_NARROW_HITS or not vw_specs:
        return hit
    parsed = _parse_specs(vw_specs)
    if not parsed:
        return hit
    try:
        narrowed = authorization_calibration(corpus, contract_pattern=hyp_name, vertex_where=parsed)
    except Exception:
        return hit
    return narrowed if (narrowed.get("count") or 0) > 0 else hit


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build_prior_recall_block(
    gather_leads: list[dict[str, Any]],
    investigation_md: str,
    salt: str,
) -> str:
    """Return the `<prior-recall-{salt}>...</prior-recall-{salt}>` block
    for inline injection into the analyze subagent prompt, or "" when
    the corpus has no usable hits.
    """
    lead_names: list[str] = []
    seen: set[str] = set()
    for lead in gather_leads or []:
        name = (lead or {}).get("name")
        if name and name not in seen:
            seen.add(name)
            lead_names.append(name)

    body = _merge_companion_blocks(investigation_md)
    contracts = _open_contracts(body)
    vw_specs = _vertex_where_specs(body)

    if not lead_names and not contracts:
        return ""

    try:
        corpus = load_corpus()
    except Exception:
        return ""

    digest_lines: list[str] = []
    for name in lead_names:
        payload = _recall_lead(corpus, name, vw_specs)
        line = _digest_lead(payload) if payload else ""
        if line:
            digest_lines.append(f"lead {name}: {line}")
    for hyp_name, predicate in contracts:
        payload = _recall_authz(corpus, hyp_name, predicate, vw_specs)
        line = _digest_authz(payload) if payload else ""
        if line:
            digest_lines.append(f"contract {hyp_name}: {line}")

    if not digest_lines:
        return ""

    header = (
        f"<prior-recall-{salt}>\n"
        "# Advisory only — NOT grading evidence. Severity rules unchanged.\n"
        "# Drill-down: bash soc-agent/scripts/invlang/run.sh "
        "--class 13 --lead-pattern <name>  |  --class 14 --contract-pattern <hyp>"
    )
    body_str = "\n".join(digest_lines)
    return f"{header}\n{body_str}\n</prior-recall-{salt}>"
