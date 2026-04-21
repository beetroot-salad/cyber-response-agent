"""Shared helpers, constants, and dataclasses for invlang validation checks.

This module is consumed by the per-concern check modules:
- `invlang_checks_structural.py`
- `invlang_checks_legitimacy.py`
- `invlang_checks_hypothesis.py`
- `invlang_warnings.py`

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

# Every contract's id must be `lc` followed by digits. Used to compose the
# back-reference format `h-{id}.lc{n}` that legitimacy_resolutions must cite.
_LEGITIMACY_CONTRACT_ID_RE = re.compile(r"^lc\d+$")

# Every lead-outcome resolution carries an `lr-{n}` id; agents reference
# earlier entries via `supersedes: lr-X`. Legacy edge-attached resolutions
# predate this and carry no id — they are always live (can't be superseded).
_LR_ID_RE = re.compile(r"^lr\d+$")

# ---------------------------------------------------------------------------
# Structural constants
# ---------------------------------------------------------------------------

# Required fields on every lead entry under gather:
_LEAD_REQUIRED = {"id", "loop", "name", "target", "query_details", "outcome", "resolutions"}

# trust_anchor_result must have all five of these when present
_TRUST_ANCHOR_FIELDS = {"anchor_id", "kind", "result", "as_of", "authority_for_question"}

# Required fields on every lead.predictions entry
_LEAD_PREDICTION_REQUIRED = {"id", "if", "read_as", "advance_to"}

# IDs that are valid authority kinds for strong (++/--) resolutions
_STRONG_AUTHORITY_KINDS = {"siem-event", "runtime-audit", "authoritative-source"}

_LEGITIMACY_VERDICTS = {"authorized", "unauthorized", "indeterminate"}


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
    """All `h-{id}.lc{n}` back-reference targets declared across hypotheses."""
    out: set[str] = set()
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str):
            continue
        for c in h.get("legitimacy_contract") or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if isinstance(cid, str):
                out.add(f"{hid}.{cid}")
    return out


# ---------------------------------------------------------------------------
# Lead-outcome legitimacy resolution walkers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LeadResolution:
    """One legitimacy_resolutions entry, walked in declaration order.

    `lead_idx` + `entry_idx` preserve declaration order across all leads
    for rule #21's supersede-chain resolution. `lr_id` is None for legacy
    edge-attached resolutions (they predate the supersede mechanism and
    are always live). `supersedes` is None for first-time resolutions and
    for legacy entries.
    """
    lead_idx: int
    entry_idx: int
    location: str             # for error messages
    lr_id: str | None         # None for legacy edge-attached
    contract_ref: str         # "h-{id}.lc{n}"
    target: str               # "v-{id}" or "e-{id}"
    verdict: str
    supersedes: str | None


def _iter_resolutions(
    merged: dict[str, Any],
) -> Iterator[tuple[str, str, dict[str, Any], int, int]]:
    """Yield (location, target_id, resolution, lead_idx, entry_idx) for every
    legitimacy_resolutions entry.

    Resolutions live on lead outcomes — `gather[i].outcome.legitimacy_resolutions[j]`
    — as a sibling of `attribute_updates`. Edge records are write-once and
    carry no resolution list; an edge's authorization state is a computed
    rollup over every lead that names it as its `target`, in declaration
    order. `lead_idx` and `entry_idx` preserve that order for rule #21's
    supersede-chain resolution.
    """
    for lead_idx, lead in enumerate(merged.get("gather", []) or []):
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        outcome = lead.get("outcome", {}) if isinstance(lead.get("outcome"), dict) else {}
        for entry_idx, r in enumerate(outcome.get("legitimacy_resolutions") or []):
            if not isinstance(r, dict):
                continue
            target = r.get("target")
            target_id = target if isinstance(target, str) else "?"
            yield f"lead {lid} outcome.legitimacy_resolutions[{entry_idx}]", target_id, r, lead_idx, entry_idx


def _collect_lead_resolutions(merged: dict[str, Any]) -> list[LeadResolution]:
    """Walk _iter_resolutions and build structured LeadResolution records.

    Skips malformed entries (missing/wrong-type `fulfills_contract` or
    `verdict`) — those are caught by rule #20 / rule #21's shape checks
    with dedicated error messages; this builder just needs well-formed
    rows for aggregation.
    """
    out: list[LeadResolution] = []
    for location, target_id, r, lead_idx, entry_idx in _iter_resolutions(merged):
        cref = r.get("fulfills_contract")
        verdict = r.get("verdict")
        if not isinstance(cref, str) or not isinstance(verdict, str):
            continue
        raw_id = r.get("id")
        lr_id = raw_id if isinstance(raw_id, str) else None
        raw_sup = r.get("supersedes")
        supersedes = raw_sup if isinstance(raw_sup, str) else None
        out.append(LeadResolution(
            lead_idx=lead_idx,
            entry_idx=entry_idx,
            location=location,
            lr_id=lr_id,
            contract_ref=cref,
            target=target_id,
            verdict=verdict,
            supersedes=supersedes,
        ))
    return out


def _compute_effective_resolutions(
    all_res: list[LeadResolution],
) -> list[LeadResolution]:
    """Filter superseded entries out of the full list.

    An entry is excluded when some later resolution names it as its
    `supersedes` target. Legacy entries (lr_id is None) cannot be
    referenced and are never filtered.
    """
    superseded_ids = {r.supersedes for r in all_res if r.supersedes is not None}
    return [r for r in all_res if r.lr_id is None or r.lr_id not in superseded_ids]
