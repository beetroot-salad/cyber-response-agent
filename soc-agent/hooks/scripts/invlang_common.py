"""Shared helpers, constants, and dataclasses for invlang validation checks.

This module is consumed by the per-concern check modules:
- `invlang_checks_structural.py`
- `invlang_checks_authorization.py`
- `invlang_checks_impact.py`
- `invlang_checks_hypothesis.py`

All symbols here are implementation detail of `invlang_validate`; the
entrypoint (`invlang_validate.py`) re-exports what external callers need.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(SOC_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_walkers import iter_hypotheses  # noqa: E402

# ---------------------------------------------------------------------------
# Block extraction + merge
# ---------------------------------------------------------------------------

# Same regex used by corpus.py — extract ```yaml ... ``` spans from markdown
YAML_BLOCK_RE = re.compile(r"```yaml\n(.*?)\n```", re.DOTALL)

COMPANION_TOP_LEVEL = {"prologue", "hypothesize", "gather", "conclude"}

# ---------------------------------------------------------------------------
# ID patterns
# ---------------------------------------------------------------------------

# Loose ID format: one of the known prefixes followed by alphanumerics and hyphens
_ID_RE = re.compile(r"^[vehl]-[a-z0-9][a-z0-9-]*$")

# Lead-level prediction IDs are local to the lead; different namespace from
# hypothesis predictions (p1, p2) to avoid collision.
_LEAD_PREDICTION_ID_RE = re.compile(r"^lp\d+$")

# Every authorization contract's id must be `ac` followed by digits. Used to
# compose the back-reference format `h-{id}.ac{n}` that
# `authorization_resolutions[].fulfills_contract` must cite.
_AUTHORIZATION_CONTRACT_ID_RE = re.compile(r"^ac\d+$")

# Lead-level impact-prediction IDs match `ip\d+`; the full cross-lead
# identity is `l-{lead_id}.ip{n}` (used by rule #30 back-refs and rule
# #31 closure).
_IMPACT_PREDICTION_ID_RE = re.compile(r"^ip\d+$")

# ---------------------------------------------------------------------------
# Structural constants
# ---------------------------------------------------------------------------

# Required fields on every lead entry under gather:
_LEAD_REQUIRED = {"id", "loop", "name", "target", "query_details", "outcome", "resolutions"}

# Required fields on every lead.predictions entry
_LEAD_PREDICTION_REQUIRED = {"id", "if", "read_as", "advance_to"}

# IDs that are valid authority kinds for strong (++/--) resolutions
_STRONG_AUTHORITY_KINDS = {"siem-event", "runtime-audit", "authoritative-source"}

_AUTHORIZATION_VERDICTS = {"authorized", "unauthorized", "indeterminate"}

# Grounding-kind tuples for rule #11 (split by surface).
_AUTHZ_GROUNDING_KINDS = {"org-authority", "past-case"}
_CONSULTATION_GROUNDING_KINDS = {"org-authority", "telemetry-baseline"}
_IMPACT_GROUNDING_KINDS = {
    "telemetry-baseline",
    "business-owner-attestation",
    "dlp-policy",
}

# Required fields on every authorization_resolutions[] entry (rule #11).
_AUTHZ_REQUIRED_FIELDS = (
    "verdict",
    "anchor_kind",
    "anchor_id",
    "grounding_kind",
    "authority_for_question",
    "as_of",
    "resolved_by_lead",
    "fulfills_contract",
)

# Required fields on every anchor_consultations[] entry (rule #11).
_CONSULTATION_REQUIRED_FIELDS = (
    "anchor_id",
    "anchor_kind",
    "grounding_kind",
    "result",
    "as_of",
    "authority_for_question",
)

# Required fields on every impact_resolutions[] entry (rule #30).
_IMPACT_RES_REQUIRED_FIELDS = (
    "prediction_ref",
    "dimension",
    "verdict",
    "grounding_kind",
    "authority_for_question",
    "as_of",
    "reasoning",
)

# Acting-entity vertex types (rule #32).
_ACTING_ENTITY_TYPES = {"session", "identity", "process"}

# Impact-axis enums.
_IMPACT_DIMENSIONS = {"confidentiality", "integrity", "availability", "scope"}
_IMPACT_VERDICTS = {"within", "exceeds", "indeterminate"}
_IMPACT_SEVERITIES = {None, "low", "moderate", "high"}
_CONCLUDE_IMPACT_VERDICTS = {"none", "within", "exceeds", "indeterminate"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value))


def _merge_blocks(blocks: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge multiple YAML companion blocks into a single body dict."""
    merged: dict[str, Any] = {}
    for doc in blocks:
        for key in COMPANION_TOP_LEVEL:
            if key not in doc:
                continue
            if key == "gather":
                merged.setdefault("gather", [])
                if isinstance(doc[key], list):
                    merged["gather"].extend(doc[key])
            else:
                merged[key] = doc[key]
    return merged


def _collect_declared_ids(merged: dict[str, Any]) -> set[str]:
    """Collect all IDs declared anywhere in the companion body."""
    ids: set[str] = set()

    for v in merged.get("prologue", {}).get("vertices", []):
        if vid := v.get("id"):
            ids.add(vid)
    for e in merged.get("prologue", {}).get("edges", []):
        if eid := e.get("id"):
            ids.add(eid)
    for h in merged.get("hypothesize", {}).get("hypotheses", []):
        if hid := h.get("id"):
            ids.add(hid)
    for lead in merged.get("gather", []):
        if not isinstance(lead, dict):
            continue
        if lid := lead.get("id"):
            ids.add(lid)
        obs = lead.get("outcome", {}).get("observations", {})
        for v in obs.get("vertices", []):
            if vid := v.get("id"):
                ids.add(vid)
        for e in obs.get("edges", []):
            if eid := e.get("id"):
                ids.add(eid)
        for h in lead.get("new_hypotheses", []) or []:
            if hid := h.get("id"):
                ids.add(hid)
    return ids


def _index_hypothesis_id_field_ids(merged: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    """For every hypothesis: collect prediction and refutation IDs.

    Returns {hypothesis_id: {"predictions": {pid, ...}, "refutations": {rid, ...}}}.
    Used by the lifecycle guard to diff between current and proposed companions.
    """
    out: dict[str, dict[str, set[str]]] = {}
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str):
            continue
        preds = {
            p.get("id") for p in (h.get("predictions") or [])
            if isinstance(p, dict) and isinstance(p.get("id"), str)
        }
        refs = {
            r.get("id") for r in (h.get("refutation_shape") or [])
            if isinstance(r, dict) and isinstance(r.get("id"), str)
        }
        # Union across multiple declarations (same hypothesis appearing in
        # hypothesize and later lead.new_hypotheses — shouldn't happen in a
        # valid companion, but union is the safe conservative choice).
        entry = out.setdefault(hid, {"predictions": set(), "refutations": set()})
        entry["predictions"] |= preds
        entry["refutations"] |= refs
    return out


def _collect_declared_edge_ids(merged: dict[str, Any]) -> set[str]:
    """All declared edge IDs (prologue + lead observations). Used by rule #19."""
    eids: set[str] = set()
    for e in merged.get("prologue", {}).get("edges", []) or []:
        if isinstance(e, dict):
            eid = e.get("id")
            if isinstance(eid, str):
                eids.add(eid)
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        for e in lead.get("outcome", {}).get("observations", {}).get("edges", []) or []:
            if isinstance(e, dict):
                eid = e.get("id")
                if isinstance(eid, str):
                    eids.add(eid)
    return eids


def _collect_contract_ids(merged: dict[str, Any]) -> set[str]:
    """All `h-{id}.ac{n}` back-reference targets declared across hypotheses."""
    out: set[str] = set()
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str):
            continue
        for c in h.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if isinstance(cid, str):
                out.add(f"{hid}.{cid}")
    return out


def _collect_impact_prediction_refs(merged: dict[str, Any]) -> set[str]:
    """All `l-{lead_id}.ip{n}` impact prediction ids declared across leads.

    Rule #30 back-refs use these; rule #31 closure joins against them.
    """
    out: set[str] = set()
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id")
        if not isinstance(lid, str):
            continue
        for ip in lead.get("impact_predictions") or []:
            if not isinstance(ip, dict):
                continue
            ipid = ip.get("id")
            if isinstance(ipid, str):
                out.add(f"{lid}.{ipid}")
    return out


# ---------------------------------------------------------------------------
# Lead-outcome authorization resolution walkers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LeadResolution:
    """One authorization_resolutions entry, walked in declaration order.

    `lead_idx` + `entry_idx` preserve declaration order across all leads for
    reporting. v2.11 dropped the supersede-chain mechanism — entries have
    no ids and cannot be superseded. The walker still emits every entry in
    order so rule-#21 aggregation can count verdicts per contract.
    """
    lead_idx: int
    entry_idx: int
    location: str             # for error messages
    contract_ref: str         # "h-{id}.ac{n}"
    target: str               # edge id if the authz entry targeted an existing
                              # edge via attribute_updates, else "<inline edge>"
    verdict: str


def _iter_resolutions(
    merged: dict[str, Any],
) -> Iterator[tuple[str, str, dict[str, Any], int, int]]:
    """Yield (location, target_id, resolution, lead_idx, entry_idx) for every
    authorization_resolutions[] entry the companion declares.

    v2.11 embeds authz resolutions on the edge object — two sources:
      (a) inline on newly-materialized edges under
          `gather[].outcome.observations.edges[].authorization_resolutions[]`;
      (b) on already-confirmed edges via attribute_updates —
          `gather[].outcome.attribute_updates[].updates.authorization_resolutions[]`
          where the update's `target` is the edge id.

    `target_id` is the edge id in case (b); in case (a) it's the edge's own
    id (the edge the entry lives on). `entry_idx` is the per-source entry
    index (0 is the first entry on that edge record).
    """
    for lead_idx, lead in enumerate(merged.get("gather", []) or []):
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        outcome = lead.get("outcome", {}) if isinstance(lead.get("outcome"), dict) else {}

        # (a) inline on new edges
        obs = outcome.get("observations") if isinstance(outcome.get("observations"), dict) else {}
        for e_idx, e in enumerate(obs.get("edges", []) or []):
            if not isinstance(e, dict):
                continue
            eid = e.get("id") if isinstance(e.get("id"), str) else "?"
            entries = e.get("authorization_resolutions") or []
            for entry_idx, r in enumerate(entries):
                if not isinstance(r, dict):
                    continue
                loc = (
                    f"lead {lid} outcome.observations.edges[{e_idx}] "
                    f"({eid}) authorization_resolutions[{entry_idx}]"
                )
                yield loc, eid, r, lead_idx, entry_idx

        # (b) on attribute_updates targeting an existing edge
        for u_idx, upd in enumerate(outcome.get("attribute_updates") or []):
            if not isinstance(upd, dict):
                continue
            target = upd.get("target") if isinstance(upd.get("target"), str) else "?"
            updates = upd.get("updates") if isinstance(upd.get("updates"), dict) else {}
            entries = updates.get("authorization_resolutions") or []
            for entry_idx, r in enumerate(entries):
                if not isinstance(r, dict):
                    continue
                loc = (
                    f"lead {lid} attribute_updates[{u_idx}].updates"
                    f".authorization_resolutions[{entry_idx}] (target {target})"
                )
                yield loc, target, r, lead_idx, entry_idx


def _collect_lead_resolutions(merged: dict[str, Any]) -> list[LeadResolution]:
    """Walk _iter_resolutions and build structured LeadResolution records.

    Skips malformed entries (missing/wrong-type `fulfills_contract` or
    `verdict`) — those are caught by the provenance and back-ref checks
    with dedicated error messages; this builder just needs well-formed
    rows for aggregation.
    """
    out: list[LeadResolution] = []
    for location, target_id, r, lead_idx, entry_idx in _iter_resolutions(merged):
        cref = r.get("fulfills_contract")
        verdict = r.get("verdict")
        if not isinstance(cref, str) or not isinstance(verdict, str):
            continue
        out.append(LeadResolution(
            lead_idx=lead_idx,
            entry_idx=entry_idx,
            location=location,
            contract_ref=cref,
            target=target_id,
            verdict=verdict,
        ))
    return out
