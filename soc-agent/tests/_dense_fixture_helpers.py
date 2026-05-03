"""Test-only convenience layer for building dense ```invlang fixtures.

Production emitters in `scripts/handlers/_*_dense.py` are strict about
fields the dense wire format itself encodes (e.g. resolutions require
`<before> → <after>` and a severity token; validator rule #5 enforces
edge authority for `++`/`--`). That strictness is justified by the
guardrail + retrieval-scaffolding lens but makes ad-hoc test fixtures
verbose.

This helper takes a minimal companion dict — the same shape the legacy
yaml fixtures used — and fills in safe defaults for the structurally
required fields so the existing emitters can run. The output is a
single ```invlang fence with all four phase blocks present (any phase
the input dict omits is simply skipped).

Defaults applied:
    - resolution `before_weight`: "none"
    - resolution `severity`: "low"
    - resolution `supporting_edges`: []
    - hypothesis `predictions`/`refutation_shape`/`authorization_contract`/
      `attribute_predictions`: [] when missing
    - finding `mode`: "analyze" when resolutions are present, else "gather"
    - finding `query_details`: {} when missing
    - finding `outcome`: {"observations": {"vertices": [], "edges": []}} when missing
"""

from __future__ import annotations

from typing import Any

from scripts.handlers._analyze_dense import emit_analyze_findings_dense
from scripts.handlers._conclude_dense import emit_conclude_dense
from scripts.handlers._gather_dense import emit_gather_findings_dense
from scripts.handlers._hypothesize_dense import emit_hypothesize_dense
from scripts.handlers._prologue_dense import emit_prologue_dense_body


def _normalize_hypothesis(h: dict[str, Any]) -> dict[str, Any]:
    out = dict(h)
    out.setdefault("predictions", [])
    out.setdefault("attribute_predictions", [])
    out.setdefault("refutation_shape", [])
    contracts = out.get("authorization_contract") or []
    # Ensure each contract carries the cells the dense surface requires.
    # `id` must match `ac\d+`; `anchor_kind` cannot be empty (parser regex
    # requires `[^:]+`); `edge_ref` defaults to `proposed`. These defaults
    # only fire for under-specified test fixtures — production
    # PREDICT-emit paths supply real values.
    out["authorization_contract"] = [
        {
            **c,
            "id": c.get("id") or f"ac{i+1}",
            "anchor_kind": c.get("anchor_kind") or "org-authority",
            "edge_ref": c.get("edge_ref") or "proposed",
        }
        for i, c in enumerate(contracts)
    ]
    return out


def _normalize_resolution(res: dict[str, Any]) -> dict[str, Any]:
    out = dict(res)
    out.setdefault("before_weight", "none")
    out.setdefault("severity", "low")
    out.setdefault("supporting_edges", [])
    return out


def _normalize_finding(lead: dict[str, Any]) -> dict[str, Any]:
    out = dict(lead)
    has_resolutions = bool(out.get("resolutions"))
    outcome = out.get("outcome") or {}
    obs = outcome.get("observations") or {}
    has_observations = bool(
        (obs.get("vertices") if isinstance(obs, dict) else None)
        or (obs.get("edges") if isinstance(obs, dict) else None)
    )
    has_attr_updates = bool(outcome.get("attribute_updates"))
    # Default to gather (lead-pick); promote to analyze when the outcome
    # carries analyze-shape content (resolutions / observations / attr
    # updates), since the gather emitter rejects resolutions and is
    # under-specified for the rest.
    needs_analyze = has_resolutions or has_observations or has_attr_updates
    out.setdefault("mode", "analyze" if needs_analyze else "gather")
    out.setdefault("query_details", {})
    out.setdefault(
        "outcome",
        {"observations": {"vertices": [], "edges": []}},
    )
    if has_resolutions:
        out["resolutions"] = [_normalize_resolution(r) for r in out["resolutions"]]
    return out


def companion_to_invlang_fence(companion: dict[str, Any]) -> str:
    """Render a companion dict as a single ```invlang fence body.

    Recognized top-level keys: `prologue`, `hypothesize.hypotheses`,
    `findings`, `conclude`. Missing keys produce no block. Empty lists
    produce no block (matches the production "skip the write entirely
    when empty" convention).
    """
    parts: list[str] = []

    prologue = companion.get("prologue")
    if isinstance(prologue, dict):
        parts.append(emit_prologue_dense_body(prologue))

    hyps = (companion.get("hypothesize") or {}).get("hypotheses") or []
    if hyps:
        parts.append(emit_hypothesize_dense([_normalize_hypothesis(h) for h in hyps]))

    findings = companion.get("findings") or []
    shelved_rows: list[str] = []  # collected across all leads
    if findings:
        normalized = [_normalize_finding(f) for f in findings]
        # Split by mode: analyze leads (with resolutions / authz / etc.) go
        # through emit_analyze_findings_dense; pure gather lead-picks go
        # through emit_gather_findings_dense. The dense parser merges
        # `:L findings` rows from any number of fences.
        analyze_rows = [f for f in normalized if f["mode"] == "analyze"]
        gather_rows = [f for f in normalized if f["mode"] == "gather"]
        if analyze_rows:
            parts.append(emit_analyze_findings_dense(analyze_rows))
        if gather_rows:
            parts.append(emit_gather_findings_dense(gather_rows))
        # Collect shelved entries from any lead and emit a single `:T shelved`
        # block. Canonical shape: `lead.shelved` is a list of bare hypothesis
        # ids; rationale (if any) lives in `lead.shelved_rationales`.
        for f in normalized:
            rationales = f.get("shelved_rationales") or {}
            for hyp_id in f.get("shelved") or []:
                rationale = rationales.get(hyp_id, "") if isinstance(hyp_id, str) else ""
                shelved_rows.append(f"{hyp_id}|{rationale}|{f['id']}")
    if shelved_rows:
        parts.append("\n".join([
            ":T shelved [hyp_id|rationale|by_lead]",
            *shelved_rows,
        ]))

    conclude = companion.get("conclude")
    if isinstance(conclude, dict):
        parts.append(emit_conclude_dense(conclude))

    body = "\n\n".join(p for p in parts if p)
    return f"```invlang\n{body}\n```"


def companion_md(companion: dict[str, Any], header: str = "## CONTEXTUALIZE") -> str:
    """Wrap `companion_to_invlang_fence(...)` inside a minimal investigation.md."""
    return f"{header}\n\n{companion_to_invlang_fence(companion)}\n"
