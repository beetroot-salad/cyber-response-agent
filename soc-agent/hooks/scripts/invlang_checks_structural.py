"""Structural invlang checks (rules 1-9 in the validator docstring).

Covers: lead required fields, ID formats, ID references, edge authority,
refutation IDs, trust_anchor_result completeness, screen_result scope,
lead.predictions structural shape.
"""

from __future__ import annotations

from typing import Any

from hooks.scripts.invlang_common import (
    _LEAD_PREDICTION_ID_RE,
    _LEAD_PREDICTION_REQUIRED,
    _LEAD_REQUIRED,
    _STRONG_AUTHORITY_KINDS,
    _TRUST_ANCHOR_FIELDS,
    _collect_declared_ids,
    _is_valid_id,
)
from schemas.enums import VALID_ANCHOR_KINDS


def _check_lead_required_fields(merged: dict[str, Any]) -> list[str]:
    errors = []
    for i, lead in enumerate(merged.get("gather", [])):
        if not isinstance(lead, dict):
            errors.append(f"gather[{i}]: entry must be a mapping (lead object)")
            continue
        missing = _LEAD_REQUIRED - lead.keys()
        if missing:
            lid = lead.get("id", f"gather[{i}]")
            errors.append(f"lead {lid}: missing required field(s): {sorted(missing)}")
    return errors


def _check_id_formats(merged: dict[str, Any]) -> list[str]:
    """Check that all declared IDs match the expected pattern."""
    errors = []

    def _check(id_val: Any, context: str) -> None:
        if id_val is not None and not _is_valid_id(id_val):
            errors.append(
                f"{context}: id {id_val!r} does not match expected pattern "
                f"(e.g. v-001, e-001, h-001, l-001)"
            )

    for v in merged.get("prologue", {}).get("vertices", []):
        _check(v.get("id"), "prologue vertex")
    for e in merged.get("prologue", {}).get("edges", []):
        _check(e.get("id"), "prologue edge")
    for h in merged.get("hypothesize", {}).get("hypotheses", []):
        _check(h.get("id"), "hypothesize hypothesis")
    for lead in merged.get("gather", []):
        if not isinstance(lead, dict):
            continue
        _check(lead.get("id"), "gather lead")
        obs = lead.get("outcome", {}).get("observations", {})
        for v in obs.get("vertices", []):
            _check(v.get("id"), f"lead {lead.get('id','?')} observation vertex")
        for e in obs.get("edges", []):
            _check(e.get("id"), f"lead {lead.get('id','?')} observation edge")
        for h in lead.get("new_hypotheses", []) or []:
            _check(h.get("id"), f"lead {lead.get('id','?')} new_hypothesis")

    return errors


def _check_id_references(merged: dict[str, Any]) -> list[str]:
    """Check that all ID references point to declared IDs."""
    errors = []
    declared = _collect_declared_ids(merged)

    def _ref(id_val: Any, context: str) -> None:
        if isinstance(id_val, str) and id_val and id_val not in declared:
            errors.append(f"{context}: references unknown ID {id_val!r}")

    for lead in merged.get("gather", []):
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        _ref(lead.get("target"), f"lead {lid} target")
        for tid in lead.get("tests", []) or []:
            _ref(tid, f"lead {lid} tests")
        for obs in lead.get("observes", []) or []:
            _ref(obs.get("hypothesis"), f"lead {lid} observes.hypothesis")
        for attr_upd in lead.get("outcome", {}).get("attribute_updates", []) or []:
            if isinstance(attr_upd, dict):
                _ref(attr_upd.get("target"), f"lead {lid} attribute_updates.target")
        for se in lead.get("resolutions", []) or []:
            _ref(se.get("hypothesis"), f"lead {lid} resolution.hypothesis")
            for eid in se.get("supporting_edges", []) or []:
                _ref(eid, f"lead {lid} resolution.supporting_edges")
        tr = lead.get("outcome", {}).get("trust_root_reached")
        if tr:
            _ref(tr, f"lead {lid} outcome.trust_root_reached")

    for h in merged.get("hypothesize", {}).get("hypotheses", []):
        hid = h.get("id", "?")
        _ref(h.get("attached_to_vertex"), f"hypothesis {hid} attached_to_vertex")

    return errors


def _check_edge_authority(merged: dict[str, Any]) -> list[str]:
    """++/-- resolutions must cite at least one authoritative edge in supporting_edges."""
    errors = []
    # Build edge→authority kind map from prologue + lead observations
    edge_authority: dict[str, str] = {}
    for e in merged.get("prologue", {}).get("edges", []):
        eid = e.get("id")
        kind = e.get("authority", {}).get("kind", "")
        if eid:
            edge_authority[eid] = kind
    for lead in merged.get("gather", []):
        if not isinstance(lead, dict):
            continue
        obs = lead.get("outcome", {}).get("observations", {})
        for e in obs.get("edges", []):
            eid = e.get("id")
            kind = e.get("authority", {}).get("kind", "")
            if eid:
                edge_authority[eid] = kind

    for lead in merged.get("gather", []):
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for res in lead.get("resolutions", []) or []:
            after = res.get("after", "")
            if after not in ("++", "--"):
                continue
            hyp = res.get("hypothesis", "?")
            supporting = res.get("supporting_edges", []) or []
            if not supporting:
                errors.append(
                    f"lead {lid}: resolution for {hyp} has after: {after!r} "
                    f"but supporting_edges is empty — ++/-- requires at least one "
                    f"supporting edge"
                )
                continue
            # At least one edge must have authoritative kind
            has_authoritative = any(
                edge_authority.get(eid, "") in _STRONG_AUTHORITY_KINDS
                for eid in supporting
            )
            if not has_authoritative:
                errors.append(
                    f"lead {lid}: resolution for {hyp} has after: {after!r} but none "
                    f"of its supporting_edges ({supporting}) have authority.kind in "
                    f"{sorted(_STRONG_AUTHORITY_KINDS)}"
                )

    return errors


def _check_refutation_ids(merged: dict[str, Any]) -> list[str]:
    """-- resolutions must have non-empty matched_refutation_ids."""
    errors = []
    for lead in merged.get("gather", []):
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for res in lead.get("resolutions", []) or []:
            if res.get("after") == "--":
                hyp = res.get("hypothesis", "?")
                if not (res.get("matched_refutation_ids") or []):
                    errors.append(
                        f"lead {lid}: resolution for {hyp} has after: \"--\" "
                        f"but matched_refutation_ids is empty"
                    )
    return errors


def _check_trust_anchor_completeness(merged: dict[str, Any]) -> list[str]:
    """trust_anchor_result must have all 5 required fields when present, and
    `kind` must be drawn from the anchor taxonomy (not the edge-authority
    taxonomy, which agents commonly conflate)."""
    errors = []
    for lead in merged.get("gather", []):
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        tar = lead.get("outcome", {}).get("trust_anchor_result")
        if tar is None:
            continue
        if not isinstance(tar, dict):
            errors.append(f"lead {lid}: trust_anchor_result must be a mapping")
            continue
        missing = _TRUST_ANCHOR_FIELDS - tar.keys()
        if missing:
            errors.append(
                f"lead {lid}: trust_anchor_result missing required field(s): "
                f"{sorted(missing)}"
            )
        kind = tar.get("kind")
        if kind is not None and kind not in VALID_ANCHOR_KINDS:
            errors.append(
                f"lead {lid}: trust_anchor_result.kind must be one of "
                f"{list(VALID_ANCHOR_KINDS)}, got {kind!r}. This is the anchor "
                f"taxonomy — not `edge.authority.kind`. `authoritative-source`, "
                f"`siem-event`, `runtime-audit` belong on edges; use "
                f"`org-authority` (curated registry / policy doc) or "
                f"`telemetry-baseline` (derived from historical telemetry) here."
            )
    return errors


def _check_screen_result_scope(merged: dict[str, Any]) -> list[str]:
    """screen_result is only valid on leads where mode: screen."""
    errors = []
    for lead in merged.get("gather", []):
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        outcome = lead.get("outcome", {})
        if "screen_result" in outcome and lead.get("mode") != "screen":
            errors.append(
                f"lead {lid}: outcome.screen_result is set but lead.mode is not "
                f"'screen' — screen_result is only valid on SCREEN-dispatched leads"
            )
    return errors


def _check_lead_predictions(merged: dict[str, Any]) -> list[str]:
    """Validate lead.predictions structural shape when present.

    Each entry: {id, if, read_as, advance_to}. IDs match ^lp\\d+$ and are
    unique within the lead. advance_to is either REPORT, PREDICT, or a
    lead name declared elsewhere in the companion.
    """
    errors: list[str] = []

    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        preds = lead.get("predictions")
        if preds is None:
            continue
        lid = lead.get("id", "?")
        if not isinstance(preds, list):
            errors.append(f"lead {lid}: predictions must be a list")
            continue

        seen_ids: set[str] = set()
        for i, pred in enumerate(preds):
            ctx = f"lead {lid} predictions[{i}]"
            if not isinstance(pred, dict):
                errors.append(f"{ctx}: entry must be a mapping")
                continue

            missing = _LEAD_PREDICTION_REQUIRED - pred.keys()
            if missing:
                errors.append(f"{ctx}: missing required field(s): {sorted(missing)}")

            pid = pred.get("id")
            if isinstance(pid, str):
                if not _LEAD_PREDICTION_ID_RE.match(pid):
                    errors.append(
                        f"{ctx}: id {pid!r} does not match pattern ^lp\\d+$ "
                        f"(e.g. lp1, lp2)"
                    )
                elif pid in seen_ids:
                    errors.append(f"{ctx}: duplicate id {pid!r} within lead")
                else:
                    seen_ids.add(pid)

            # advance_to is a forward reference — the target lead may not exist
            # yet when this block is written. Require non-empty string only;
            # post-hoc route compliance is measured in queries.py Class 8.
            advance_to = pred.get("advance_to")
            if "advance_to" in pred and not (isinstance(advance_to, str) and advance_to.strip()):
                errors.append(f"{ctx}: advance_to must be a non-empty string")

    return errors
