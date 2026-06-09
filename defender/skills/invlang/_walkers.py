"""Dict-level companion walkers shared by the validator and corpus queries.

The parser emits a canonical companion *dict*; both the write-time
validator (`validate.py`, raw dict) and the corpus queries
(`queries.py`, via `Companion.body`) need to enumerate "every vertex",
"every hypothesis", "the final weight per hypothesis", etc. Keeping a
single definition here means a parser-shape change is patched in one
place instead of drifting between consumers (the soc-agent analogue is
`hooks/scripts/invlang_walkers.py`).

Every function takes the raw companion *dict* (`Companion.body` or the
validator's `companion`), never the `Companion` wrapper, so the module
has no dependency on `corpus`.
"""

from __future__ import annotations

from typing import Any

# Numeric ladder for resolution weights, worst → best. `--` (strongly
# refuted) is the only weight that takes a hypothesis out of contention.
WEIGHT_ORDER: dict[Any, int] = {"--": 0, "-": 1, None: 2, "+": 3, "++": 4}
REFUTED_WEIGHT = "--"


def all_vertices(companion: dict[str, Any]) -> list[dict[str, Any]]:
    """Every vertex: prologue + per-lead observations, in document order."""
    out: list[dict[str, Any]] = []
    pro = companion.get("prologue") or {}
    out.extend(v for v in (pro.get("vertices") or []) if isinstance(v, dict))
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        obs = (lead.get("outcome") or {}).get("observations") or {}
        out.extend(v for v in (obs.get("vertices") or []) if isinstance(v, dict))
    return out


def all_edges(companion: dict[str, Any]) -> list[dict[str, Any]]:
    """Every edge: prologue + per-lead observations, in document order."""
    out: list[dict[str, Any]] = []
    pro = companion.get("prologue") or {}
    out.extend(e for e in (pro.get("edges") or []) if isinstance(e, dict))
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        obs = (lead.get("outcome") or {}).get("observations") or {}
        out.extend(e for e in (obs.get("edges") or []) if isinstance(e, dict))
    return out


def all_hypotheses(companion: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Hypotheses by id: the PREDICT frontier plus any lead-discovered ones.

    First declaration of an id wins (the frontier outranks a later
    lead's `new_hypotheses` re-mention).
    """
    out: dict[str, dict[str, Any]] = {}
    hyps = (companion.get("hypothesize") or {}).get("hypotheses") or []
    for h in hyps:
        if isinstance(h, dict) and isinstance(h.get("id"), str):
            out.setdefault(h["id"], h)
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        for h in lead.get("new_hypotheses") or []:
            if isinstance(h, dict) and isinstance(h.get("id"), str):
                out.setdefault(h["id"], h)
    return out


def iter_resolutions(companion: dict[str, Any]):
    """Yield (lead_id, resolution) for every `:T resolutions` row."""
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for res in lead.get("resolutions") or []:
            if isinstance(res, dict):
                yield lid, res


def iter_authz_resolutions(companion: dict[str, Any]):
    """Yield every `:R authz` resolution row across all leads, in order."""
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        for row in (lead.get("outcome") or {}).get("authorization_resolutions") or []:
            if isinstance(row, dict):
                yield row


def final_weights(companion: dict[str, Any]) -> dict[str, Any]:
    """Per-hypothesis weight: declared weight overlaid by the last resolution."""
    final: dict[str, Any] = {
        hid: h.get("weight") for hid, h in all_hypotheses(companion).items()
    }
    for _lid, res in iter_resolutions(companion):
        hid = res.get("hypothesis")
        if isinstance(hid, str):
            final[hid] = res.get("after")
    return final


def live_hypothesis_ids(companion: dict[str, Any]) -> list[str]:
    """Hypothesis ids that survived: final weight is not ``--`` (strongly
    refuted). Computed from the resolution record; ``:T conclude`` carries
    no sub-tables to restate this."""
    return [
        hid
        for hid, w in final_weights(companion).items()
        if w != REFUTED_WEIGHT
    ]
