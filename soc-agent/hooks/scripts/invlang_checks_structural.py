"""Structural invlang checks.

Covers: lead required fields, ID formats, ID references, edge authority,
refutation IDs, screen_result scope, lead.predictions structural shape,
plus rule #11 provenance checks (split by surface):
- authorization_resolutions[] entries
- anchor_consultations[] entries
"""

from __future__ import annotations

from typing import Any

from hooks.scripts.invlang_common import (
    _AUTHZ_GROUNDING_KINDS,
    _AUTHZ_REQUIRED_FIELDS,
    _CONSULTATION_GROUNDING_KINDS,
    _CONSULTATION_REQUIRED_FIELDS,
    _LEAD_PREDICTION_ID_RE,
    _LEAD_PREDICTION_REQUIRED,
    _LEAD_REQUIRED,
    _STRONG_AUTHORITY_KINDS,
    _collect_declared_ids,
    _is_valid_id,
    _iter_resolutions,
)


def _check_lead_required_fields(merged: dict[str, Any]) -> list[str]:
    errors = []
    for i, lead in enumerate(merged.get("findings", [])):
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
    for lead in merged.get("findings", []):
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

    for lead in merged.get("findings", []):
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
    for lead in merged.get("findings", []):
        if not isinstance(lead, dict):
            continue
        obs = lead.get("outcome", {}).get("observations", {})
        for e in obs.get("edges", []):
            eid = e.get("id")
            kind = e.get("authority", {}).get("kind", "")
            if eid:
                edge_authority[eid] = kind

    for lead in merged.get("findings", []):
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
    for lead in merged.get("findings", []):
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


def _check_screen_result_scope(merged: dict[str, Any]) -> list[str]:
    """screen_result is only valid on leads where mode: screen."""
    errors = []
    for lead in merged.get("findings", []):
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

    for lead in merged.get("findings", []) or []:
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


# ---------------------------------------------------------------------------
# Rule #11 — provenance (split by surface)
# ---------------------------------------------------------------------------


def _check_authorization_resolution_provenance(merged: dict[str, Any]) -> list[str]:
    """Rule #11 (authz surface): required fields + grounding-kind enum.

    Every `authorization_resolutions[]` entry (whether inline on a new
    edge or embedded on an attribute_updates target) must carry the
    required fields listed in `_AUTHZ_REQUIRED_FIELDS`. `grounding_kind`
    must be `org-authority` or `past-case` — `telemetry-baseline` is
    forbidden on authorization resolutions (baselines answer expectation,
    not authorization). When `grounding_kind: past-case`, the entry must
    also carry `cites_past_case.run_id` and `cites_past_case.contract_ref`.
    """
    errors: list[str] = []
    for location, _target_id, r, _li, _ei in _iter_resolutions(merged):
        missing = [f for f in _AUTHZ_REQUIRED_FIELDS if f not in r]
        if missing:
            errors.append(
                f"{location}: authorization_resolutions entry missing "
                f"required field(s): {sorted(missing)}"
            )
        grounding = r.get("grounding_kind")
        if grounding is not None and grounding not in _AUTHZ_GROUNDING_KINDS:
            errors.append(
                f"{location}: grounding_kind {grounding!r} not in "
                f"{sorted(_AUTHZ_GROUNDING_KINDS)} — authorization_resolutions "
                f"forbid 'telemetry-baseline' (baselines answer expectation, not "
                f"authorization; baseline lookups belong in anchor_consultations[])"
            )
        if grounding == "past-case":
            cites = r.get("cites_past_case")
            if not isinstance(cites, dict):
                errors.append(
                    f"{location}: grounding_kind 'past-case' requires a "
                    f"`cites_past_case` mapping with run_id + contract_ref"
                )
            else:
                for sub in ("run_id", "contract_ref"):
                    if not cites.get(sub):
                        errors.append(
                            f"{location}: cites_past_case missing {sub!r} "
                            f"(required when grounding_kind: past-case)"
                        )
    return errors


def _check_anchor_consultation_provenance(merged: dict[str, Any]) -> list[str]:
    """Rule #11 (consultation surface): required fields + grounding-kind enum.

    Every `anchor_consultations[]` entry on a lead outcome must carry the
    required fields listed in `_CONSULTATION_REQUIRED_FIELDS`.
    `grounding_kind` must be `org-authority` or `telemetry-baseline` —
    `past-case` is forbidden on consultations (past-case citations are
    authz evidence and live in `authorization_resolutions[]`).
    """
    errors: list[str] = []
    for lead in merged.get("findings", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        outcome = lead.get("outcome") if isinstance(lead.get("outcome"), dict) else {}
        for i, entry in enumerate(outcome.get("anchor_consultations") or []):
            ctx = f"lead {lid} outcome.anchor_consultations[{i}]"
            if not isinstance(entry, dict):
                errors.append(f"{ctx}: entry must be a mapping")
                continue
            missing = [f for f in _CONSULTATION_REQUIRED_FIELDS if f not in entry]
            if missing:
                errors.append(
                    f"{ctx}: missing required field(s): {sorted(missing)}"
                )
            grounding = entry.get("grounding_kind")
            if grounding is not None and grounding not in _CONSULTATION_GROUNDING_KINDS:
                errors.append(
                    f"{ctx}: grounding_kind {grounding!r} not in "
                    f"{sorted(_CONSULTATION_GROUNDING_KINDS)} — anchor_consultations "
                    f"forbid 'past-case' (past-case citations are authz evidence "
                    f"and belong in authorization_resolutions[])"
                )
    return errors
