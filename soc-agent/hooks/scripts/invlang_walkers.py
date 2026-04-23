"""Shared walkers for invlang companion dicts.

`invlang_validate.py` and `validate_report_precheck.py` both traverse the merged
companion to reason about hypotheses, predictions, and resolutions. The
walkers live here so both hooks agree on what "all hypotheses" or "final
status" means.

The merged companion dict shape is produced by `invlang_validate._merge_blocks`
and has top-level keys `prologue`, `hypothesize`, `gather`, `conclude`.
"""

from __future__ import annotations

from typing import Any, Iterator, Literal

# Numeric ordering for hypothesis weights. Used by the rollup check and any
# other comparison that needs "stronger than" semantics.
WEIGHT_NUMERIC: dict[Any, int] = {None: 0, "++": 2, "+": 1, "-": -1, "--": -2}

FinalStatus = Literal["active", "confirmed", "refuted", "shelved"]


def iter_hypotheses(merged: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield every hypothesis record declared anywhere in the companion.

    Sources: the initial `hypothesize.hypotheses` list and every lead's
    `new_hypotheses` list. Non-dict entries are skipped silently — the
    structural validator flags malformed records separately.
    """
    for h in merged.get("hypothesize", {}).get("hypotheses", []) or []:
        if isinstance(h, dict):
            yield h
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        for h in lead.get("new_hypotheses", []) or []:
            if isinstance(h, dict):
                yield h


def parent_hypothesis_id(h_id: str) -> str | None:
    """Return the parent ID for a hierarchical hypothesis ID, else None.

    `h-001-002` → `h-001`. `h-001` → None (top-level). Anything not matching
    `h-{a}[-{b}...]` returns None.
    """
    if not isinstance(h_id, str) or not h_id.startswith("h-"):
        return None
    parts = h_id.split("-")
    # Top-level: h-001 → len 2. Child: h-001-002 → len 3+.
    if len(parts) < 3:
        return None
    return "-".join(parts[:-1])


def resolution_weight(resolution: dict[str, Any]) -> Any:
    """Extract the `after` weight of a resolution (None if absent/invalid)."""
    if not isinstance(resolution, dict):
        return None
    after = resolution.get("after")
    return after if after in WEIGHT_NUMERIC else None


def compute_final_weight(merged: dict[str, Any], h_id: str) -> Any:
    """Return the latest `after` weight observed for hypothesis `h_id`.

    Walks leads in document order; the last resolution touching `h_id`
    wins. Returns None if no resolution mentioned this hypothesis.
    """
    final: Any = None
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        for res in lead.get("resolutions", []) or []:
            if not isinstance(res, dict):
                continue
            if res.get("hypothesis") == h_id:
                after = resolution_weight(res)
                if after is not None:
                    final = after
    return final


def compute_final_status(merged: dict[str, Any], h_id: str) -> FinalStatus:
    """Return the terminal status for hypothesis `h_id`.

    Precedence (later entries win, but shelved is sticky):
      1. `shelved` — appears in any lead's `shelved` list
      2. `refuted` — last `after` ∈ {"--"}, or explicit `status: refuted`
      3. `confirmed` — last `after` ∈ {"++"}, or explicit `status: confirmed`
      4. `active` — otherwise

    A hypothesis that was shelved at any point stays `shelved` even if a
    later (buggy) resolution touches it — shelving is append-only and
    terminal by schema convention.
    """
    # Check explicit shelving first — terminal.
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        for sid in lead.get("shelved", []) or []:
            if sid == h_id:
                return "shelved"

    # Check explicit status on the hypothesis record itself.
    for h in iter_hypotheses(merged):
        if h.get("id") == h_id:
            status = h.get("status")
            if status == "shelved":
                return "shelved"
            if status == "refuted":
                return "refuted"
            if status == "confirmed":
                return "confirmed"

    # Derive from resolutions — last resolution wins.
    final_weight = compute_final_weight(merged, h_id)
    if final_weight == "++":
        return "confirmed"
    if final_weight == "--":
        return "refuted"
    return "active"


def collect_hypothesis_ids(merged: dict[str, Any]) -> list[str]:
    """Return every hypothesis ID declared in the companion, in document order."""
    ids: list[str] = []
    seen: set[str] = set()
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if isinstance(hid, str) and hid not in seen:
            ids.append(hid)
            seen.add(hid)
    return ids


def iter_resolutions(merged: dict[str, Any]) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    """Yield (lead, resolution) pairs across the whole companion."""
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        for res in lead.get("resolutions", []) or []:
            if isinstance(res, dict):
                yield lead, res


def iter_siblings(merged: dict[str, Any], h_id: str) -> Iterator[dict[str, Any]]:
    """Yield hypotheses sharing `(parent_hypothesis_id, attached_to_vertex)` with h_id.

    Returns the "sibling group" used by rule #23 (fork distinctness) and
    rule #32 (integrity peer discipline). The hypothesis identified by
    `h_id` is excluded from the yielded set — "siblings of" means others
    in the same group.
    """
    target_parent = parent_hypothesis_id(h_id)
    target_attached = None
    for h in iter_hypotheses(merged):
        if h.get("id") == h_id:
            target_attached = h.get("attached_to_vertex")
            break
    if target_attached is None:
        return
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str) or hid == h_id:
            continue
        if parent_hypothesis_id(hid) != target_parent:
            continue
        if h.get("attached_to_vertex") != target_attached:
            continue
        yield h
