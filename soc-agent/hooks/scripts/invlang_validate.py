#!/usr/bin/env python3
"""PreToolUse hook: investigation-language YAML block structural validator.

Fires on Write/Edit targeting `investigation.md` (narrowed by `if` filters in
plugin.json). Computes the proposed post-write text, extracts all ```yaml blocks,
merges them into a single companion body, and checks structural rules.

Passes immediately if:
- The event does not target a valid investigation.md path
- The proposed content contains no ```yaml blocks (narrative-only write)

Checks performed (deterministic — no LLM):
1. Each YAML block parses without error
2. Lead required fields present (id, loop, name, target, query_details, outcome, resolutions)
3. ID format valid (v-*, e-*, h-*, l-* pattern)
4. ID references resolve within the companion
5. Append-only: existing YAML blocks not removed (Edit/Write over existing file)
6. Edge authority: ++/-- resolutions cite at least one authoritative edge in supporting_edges
7. Refutation IDs: -- resolutions have non-empty matched_refutation_ids
8. trust_anchor_result completeness: all 5 fields present when block is present
9. screen_result scope: only on leads with mode: screen
10. lead.predictions structural: {id, if, read_as, advance_to}; ids match ^lp\\d+$ and are unique per lead
11. Prediction coverage (rule 3): ++ requires union of matched_prediction_ids to cover full set
12. Partial-authority cap (rule 6): anchor-only grounding on a partial-authority anchor cannot produce ++/--
13. Prediction-lifecycle guard: prediction and refutation IDs are append-only at ID granularity (catches deletion-to-pass)
14. Rollup-parent weight: a parent hypothesis's final weight cannot exceed the strongest child's final weight
15. Legitimacy contract edge_ref (spec rule #19): hypothesis.legitimacy_contract[].edge_ref is `proposed` or an existing e-* id
16. Legitimacy resolution back-reference (spec rule #20): edge.legitimacy_resolutions[].fulfills_contract of shape `h-{id}.lc{n}` points to an existing hypothesis + contract entry
17. Legitimacy-gated disposition (spec rule #21): conclude.disposition=benign requires every contract on a live-weight hypothesis to have ≥1 fulfilling resolution with verdict=authorized; unauthorized/indeterminate verdicts cap disposition
18. Attribute-update target shape (spec rule #22): each attribute_updates entry has exactly one of `target: v-{id}` or `target: e-{id}`, and the id exists

Warnings (non-blocking, printed to stderr with exit 0):
- Route compliance: when a lead with `predictions` is followed by another lead in
  the same companion, the follower's `name` should match at least one
  `advance_to`; terminal leads with no follower should have `CONCLUDE` in at
  least one `advance_to`.
- Lead dedup: two leads share the same template + query + substitutions.
- Silent empty result: a discriminating lead returns no observations, no
  trust_anchor_result, and no failure_reason.
- Tool-audit cross-ref: a lead's query has no matching entry in tool_audit.jsonl
  for this session (possible fabrication or subagent dispatch).

Exit codes:
    0 - Passed (or warnings only)
    2 - Validation failed (message fed back to agent, blocks the write)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.investigation_parse import resolve_proposed_text
from hooks.scripts.invlang_walkers import (
    WEIGHT_NUMERIC,
    iter_hypotheses,
    parent_hypothesis_id,
    compute_final_weight,
    compute_final_status,
)

# Same regex used by corpus.py — extract ```yaml ... ``` spans from markdown
YAML_BLOCK_RE = re.compile(r"```yaml\n(.*?)\n```", re.DOTALL)

COMPANION_TOP_LEVEL = {"prologue", "hypothesize", "gather", "conclude"}

# IDs that are valid authority kinds for strong (+/--) resolutions
_STRONG_AUTHORITY_KINDS = {"siem-event", "runtime-audit", "authoritative-source"}

# Required fields on every lead entry under gather:
_LEAD_REQUIRED = {"id", "loop", "name", "target", "query_details", "outcome", "resolutions"}

# trust_anchor_result must have all five of these when present
_TRUST_ANCHOR_FIELDS = {"anchor_id", "kind", "result", "as_of", "authority_for_question"}

# Loose ID format: one of the known prefixes followed by alphanumerics and hyphens
_ID_RE = re.compile(r"^[vehl]-[a-z0-9][a-z0-9-]*$")

# Lead-level prediction IDs are local to the lead; different namespace from
# hypothesis predictions (p1, p2) to avoid collision.
_LEAD_PREDICTION_ID_RE = re.compile(r"^lp\d+$")

# Required fields on every lead.predictions entry
_LEAD_PREDICTION_REQUIRED = {"id", "if", "read_as", "advance_to"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value))


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


# ---------------------------------------------------------------------------
# Validation checks — each returns a list of error strings
# ---------------------------------------------------------------------------

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
    """trust_anchor_result must have all 5 required fields when present."""
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
    unique within the lead. advance_to is either CONCLUDE, HYPOTHESIZE, or a
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


def _check_route_compliance(merged: dict[str, Any]) -> list[str]:
    """Warn when a lead's predictions don't cover the actually-next lead.

    For each lead with `predictions`:
      - if there's a following lead in the same companion, its `name` should
        appear in at least one `advance_to`.
      - if there's no following lead (this is the last lead in `gather`),
        `CONCLUDE` should appear in at least one `advance_to`.

    Returns a list of warning strings (empty if all compliant). Warnings do not
    block the write; route mismatches are legitimate signals (the fork space
    was incomplete) rather than structural errors.
    """
    warnings: list[str] = []
    leads = merged.get("gather", []) or []
    if not isinstance(leads, list):
        return warnings

    for idx, lead in enumerate(leads):
        if not isinstance(lead, dict):
            continue
        preds = lead.get("predictions")
        if not isinstance(preds, list) or not preds:
            continue

        advance_tos = {
            p.get("advance_to")
            for p in preds
            if isinstance(p, dict) and isinstance(p.get("advance_to"), str) and p.get("advance_to").strip()
        }
        if not advance_tos:
            continue

        lid = lead.get("id", "?")
        next_lead = leads[idx + 1] if idx + 1 < len(leads) else None
        if next_lead is None:
            # Terminal lead in this companion — CONCLUDE should be a declared route.
            if "CONCLUDE" not in advance_tos:
                warnings.append(
                    f"lead {lid}: terminal lead with predictions but no advance_to names "
                    f"CONCLUDE (declared: {sorted(a for a in advance_tos if a)})"
                )
            continue

        next_name = next_lead.get("name") if isinstance(next_lead, dict) else None
        if not isinstance(next_name, str):
            continue
        if next_name not in advance_tos:
            warnings.append(
                f"lead {lid}: next lead {next_name!r} does not match any advance_to "
                f"(declared: {sorted(a for a in advance_tos if a)}). "
                f"If the fork space was incomplete, HYPOTHESIZE to extend it."
            )

    return warnings


def _check_append_only(proposed_text: str, current_text: str) -> list[str]:
    """Fail if the proposed content has fewer YAML blocks than the on-disk content."""
    current_count = len(YAML_BLOCK_RE.findall(current_text))
    proposed_count = len(YAML_BLOCK_RE.findall(proposed_text))
    if proposed_count < current_count:
        return [
            f"append-only violation: proposed content has {proposed_count} YAML "
            f"block(s) but the on-disk file has {current_count} — existing YAML "
            f"blocks must not be removed"
        ]
    return []


def _check_prediction_coverage(merged: dict[str, Any]) -> list[str]:
    """Rule 3 (prediction completeness): ++ requires full prediction coverage.

    For every hypothesis with any resolution graded `++`, the union of
    `matched_prediction_ids` across all resolutions that touched that
    hypothesis must equal the full prediction set declared on it. Partial
    coverage caps at `+`; graders that want `++` with partial coverage
    must add more evidence or accept the ceiling.
    """
    errors: list[str] = []

    # Index the declared prediction IDs per hypothesis.
    declared: dict[str, set[str]] = {}
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str):
            continue
        preds = h.get("predictions") or []
        declared[hid] = {
            p.get("id") for p in preds
            if isinstance(p, dict) and isinstance(p.get("id"), str)
        }

    # Aggregate covered IDs and track which hypotheses reached ++.
    covered: dict[str, set[str]] = {}
    reached_pp: dict[str, str] = {}  # h_id → lead_id where ++ first seen
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for res in lead.get("resolutions", []) or []:
            if not isinstance(res, dict):
                continue
            hid = res.get("hypothesis")
            if not isinstance(hid, str):
                continue
            matched = res.get("matched_prediction_ids") or []
            if isinstance(matched, list):
                covered.setdefault(hid, set()).update(
                    m for m in matched if isinstance(m, str)
                )
            if res.get("after") == "++" and hid not in reached_pp:
                reached_pp[hid] = lid

    for hid, lid in reached_pp.items():
        required = declared.get(hid)
        if required is None:
            # Hypothesis not declared anywhere — separate error path (ID ref check).
            continue
        if not required:
            # No predictions declared — nothing to cover. Let it pass; the
            # rollup/adversarial checks have coverage for this pathology.
            continue
        got = covered.get(hid, set())
        missing = sorted(required - got)
        if missing:
            errors.append(
                f"lead {lid}: resolution for {hid} has after: \"++\" but "
                f"matched_prediction_ids across all resolutions touching {hid} "
                f"does not cover the full prediction set "
                f"(declared: {sorted(required)}, missing: {missing}). "
                f"Partial coverage caps at \"+\"."
            )

    return errors


def _check_partial_authority_cap(merged: dict[str, Any]) -> list[str]:
    """Rule 6 (partial authority cap): anchor-only grounding cannot produce ++/--.

    If a lead's `trust_anchor_result.authority_for_question == "partial"`,
    any resolution on that lead that has no `supporting_edges` (i.e. the
    only grounding is the partial anchor) cannot be graded `++` or `--`.
    Mixed grounding — a partial anchor plus a qualifying supporting edge —
    passes; the rule only caps resolutions grounded *solely* by the anchor.
    """
    errors: list[str] = []
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        tar = lead.get("outcome", {}).get("trust_anchor_result")
        if not isinstance(tar, dict):
            continue
        if tar.get("authority_for_question") != "partial":
            continue
        lid = lead.get("id", "?")
        for res in lead.get("resolutions", []) or []:
            if not isinstance(res, dict):
                continue
            after = res.get("after")
            if after not in ("++", "--"):
                continue
            if res.get("supporting_edges") or []:
                continue  # edge-grounded — cap doesn't apply
            hid = res.get("hypothesis", "?")
            errors.append(
                f"lead {lid}: resolution for {hid} has after: {after!r} but is "
                f"grounded solely by trust_anchor_result with "
                f"authority_for_question: \"partial\" (empty supporting_edges). "
                f"Partial authority caps the weight at \"+\" or \"-\"."
            )
    return errors


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


def _check_prediction_lifecycle(
    proposed_merged: dict[str, Any], current_merged: dict[str, Any] | None
) -> list[str]:
    """Append-only guard at prediction-ID granularity.

    The block-level append-only check (`_check_append_only`) doesn't
    catch the v2.2 H3 perverse incentive: the agent rewriting a
    hypothesis record with fewer predictions to satisfy the
    prediction-coverage rule. This check diffs prediction and
    refutation IDs per hypothesis between the on-disk and proposed
    companions — any ID that existed before and is missing now is an
    append-only violation at the prediction level.
    """
    if current_merged is None:
        return []
    errors: list[str] = []
    current_ids = _index_hypothesis_id_field_ids(current_merged)
    proposed_ids = _index_hypothesis_id_field_ids(proposed_merged)
    for hid, fields in current_ids.items():
        if hid not in proposed_ids:
            # Hypothesis record itself disappeared — block-level append-only
            # will flag this; skip to avoid a duplicate message.
            continue
        cur_preds = fields["predictions"]
        new_preds = proposed_ids[hid]["predictions"]
        missing_preds = sorted(cur_preds - new_preds)
        if missing_preds:
            errors.append(
                f"hypothesis {hid}: prediction ID(s) {missing_preds} existed in "
                f"the on-disk companion but are absent from the proposed write. "
                f"Predictions are append-only — never delete one to satisfy "
                f"completeness. Add evidence to cover it, or leave the grade at "
                f"the ceiling partial coverage implies."
            )
        cur_refs = fields["refutations"]
        new_refs = proposed_ids[hid]["refutations"]
        missing_refs = sorted(cur_refs - new_refs)
        if missing_refs:
            errors.append(
                f"hypothesis {hid}: refutation ID(s) {missing_refs} existed in "
                f"the on-disk companion but are absent from the proposed write. "
                f"refutation_shape entries are append-only."
            )
    return errors


def _check_rollup_parent_weight(merged: dict[str, Any]) -> list[str]:
    """Reject rollup grading — parent weight exceeding max child weight.

    When hierarchical hypothesis IDs indicate a parent with children
    (e.g. `h-001` with `h-001-001`, `h-001-002`), the parent's final
    weight must not exceed the strongest child's final weight. A parent
    at `++` while all children are at `+` or below is rollup — the
    parent's grade was lifted by the disjunction of its children rather
    than by evidence bearing directly on the parent's own mechanism.
    """
    errors: list[str] = []

    # Identify parent→children relationships among declared IDs.
    all_ids: set[str] = set()
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if isinstance(hid, str):
            all_ids.add(hid)

    children: dict[str, list[str]] = {}
    for hid in all_ids:
        pid = parent_hypothesis_id(hid)
        if pid is None:
            continue
        if pid not in all_ids:
            continue  # orphaned hierarchical ID — separate validator concern
        children.setdefault(pid, []).append(hid)

    for pid, child_ids in children.items():
        parent_w = compute_final_weight(merged, pid)
        if parent_w is None:
            continue  # parent never resolved; nothing to check
        parent_num = WEIGHT_NUMERIC.get(parent_w, 0)
        child_weights = [compute_final_weight(merged, c) for c in child_ids]
        child_nums = [WEIGHT_NUMERIC.get(w, 0) for w in child_weights]
        max_child_num = max(child_nums) if child_nums else 0
        if parent_num > max_child_num:
            max_child_sym = max(
                (w for w in child_weights if w is not None),
                key=lambda w: WEIGHT_NUMERIC.get(w, 0),
                default=None,
            )
            errors.append(
                f"hypothesis {pid}: parent weight {parent_w!r} exceeds the "
                f"strongest child weight {max_child_sym!r} "
                f"(children: {sorted(child_ids)}). This is rollup grading — "
                f"the parent's grade must rest on evidence bearing on its own "
                f"mechanism, not on the disjunction of its children."
            )

    return errors


# ---------------------------------------------------------------------------
# Legitimacy-as-edge-attribute rules (spec v2.8, rules #19–#22)
# ---------------------------------------------------------------------------

# Every contract's id must be `lc` followed by digits. Used to compose the
# back-reference format `h-{id}.lc{n}` that legitimacy_resolutions must cite.
_LEGITIMACY_CONTRACT_ID_RE = re.compile(r"^lc\d+$")

_LEGITIMACY_VERDICTS = {"authorized", "unauthorized", "indeterminate"}


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


def _iter_edge_resolutions(
    merged: dict[str, Any],
) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield (location, edge_id, resolution) for every legitimacy_resolutions entry.

    Sources (all valid per spec): edges in prologue, edges in lead
    observations, and attribute_updates entries targeting an edge with
    `updates.legitimacy_resolutions`.
    """
    for e in merged.get("prologue", {}).get("edges", []) or []:
        if not isinstance(e, dict):
            continue
        eid = e.get("id")
        if not isinstance(eid, str):
            continue
        for r in e.get("legitimacy_resolutions") or []:
            if isinstance(r, dict):
                yield "prologue edge", eid, r
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for e in lead.get("outcome", {}).get("observations", {}).get("edges", []) or []:
            if not isinstance(e, dict):
                continue
            eid = e.get("id")
            if not isinstance(eid, str):
                continue
            for r in e.get("legitimacy_resolutions") or []:
                if isinstance(r, dict):
                    yield f"lead {lid} observation edge", eid, r
        for upd in lead.get("outcome", {}).get("attribute_updates") or []:
            if not isinstance(upd, dict):
                continue
            target = upd.get("target")
            if not (isinstance(target, str) and target.startswith("e-")):
                continue
            updates = upd.get("updates")
            if not isinstance(updates, dict):
                continue
            for r in updates.get("legitimacy_resolutions") or []:
                if isinstance(r, dict):
                    yield f"lead {lid} attribute_updates", target, r


def _check_legitimacy_contract_edge_ref(merged: dict[str, Any]) -> list[str]:
    """Spec rule #19: hypothesis.legitimacy_contract[].edge_ref resolves.

    Each entry's `edge_ref` must be the literal `proposed` (referring to
    the hypothesis's own `proposed_edge`) or an `e-*` id declared
    elsewhere in the companion.
    """
    errors: list[str] = []
    declared_edges = _collect_declared_edge_ids(merged)
    for h in iter_hypotheses(merged):
        hid = h.get("id", "?")
        contracts = h.get("legitimacy_contract") or []
        if not isinstance(contracts, list):
            errors.append(f"hypothesis {hid}: legitimacy_contract must be a list")
            continue
        for i, c in enumerate(contracts):
            if not isinstance(c, dict):
                errors.append(f"hypothesis {hid}: legitimacy_contract[{i}] must be a mapping")
                continue
            cid = c.get("id", f"[{i}]")
            if isinstance(c.get("id"), str) and not _LEGITIMACY_CONTRACT_ID_RE.match(c["id"]):
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} id does not "
                    f"match pattern ^lc\\d+$ (e.g. lc1, lc2)"
                )
            edge_ref = c.get("edge_ref")
            if edge_ref is None:
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} missing edge_ref"
                )
                continue
            if edge_ref == "proposed":
                continue
            if not isinstance(edge_ref, str):
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} edge_ref must be "
                    f"'proposed' or an e-* id (got {edge_ref!r})"
                )
                continue
            if not edge_ref.startswith("e-"):
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} edge_ref "
                    f"{edge_ref!r} must be 'proposed' or an e-* id"
                )
                continue
            if edge_ref not in declared_edges:
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} edge_ref "
                    f"{edge_ref!r} is not a declared edge in this companion"
                )
    return errors


def _check_legitimacy_resolution_backrefs(merged: dict[str, Any]) -> list[str]:
    """Spec rule #20: legitimacy_resolutions[].fulfills_contract resolves.

    Every `fulfills_contract` must be of shape `h-{id}.lc{n}` where the
    named hypothesis exists and its `legitimacy_contract` contains an
    entry with that id.
    """
    errors: list[str] = []
    contract_ids = _collect_contract_ids(merged)
    for location, eid, r in _iter_edge_resolutions(merged):
        verdict = r.get("verdict")
        if isinstance(verdict, str) and verdict not in _LEGITIMACY_VERDICTS:
            errors.append(
                f"{location} {eid}: legitimacy_resolutions.verdict {verdict!r} not in "
                f"{sorted(_LEGITIMACY_VERDICTS)}"
            )
        back = r.get("fulfills_contract")
        if back is None:
            errors.append(
                f"{location} {eid}: legitimacy_resolutions entry missing fulfills_contract"
            )
            continue
        if not isinstance(back, str) or "." not in back:
            errors.append(
                f"{location} {eid}: legitimacy_resolutions.fulfills_contract {back!r} "
                f"must be of shape 'h-{{id}}.lc{{n}}'"
            )
            continue
        if back not in contract_ids:
            errors.append(
                f"{location} {eid}: legitimacy_resolutions.fulfills_contract {back!r} "
                f"does not resolve to any declared hypothesis + contract entry"
            )
    return errors


def _check_legitimacy_gated_disposition(merged: dict[str, Any]) -> list[str]:
    """Spec rule #21: conclude.disposition is gated by contract resolutions.

    For every hypothesis with weight ∈ {++, +} and status ∈ {confirmed,
    active}, every declared `legitimacy_contract` must have at least one
    `legitimacy_resolutions` entry fulfilling it. Then:

    - disposition=benign requires every contract to have ≥1 verdict=authorized
      (unfulfilled contracts and non-authorized verdicts are incompatible with
      benign — the investigation must escalate instead).
    - Any contract resolved with verdict=unauthorized → disposition must not
      be benign.
    - Any contract with only verdict=indeterminate → disposition must not be
      benign.

    The spec names `unclear` as the escalation disposition, but the surrounding
    system also uses `inconclusive` / `escalated` in the same slot. Rather than
    hard-code a single value, this rule enforces the load-bearing invariant —
    benign is gated on authorized — and lets any non-benign disposition stand
    for the escalation cases. Tighter disposition-vocabulary alignment is a
    separate cleanup.
    """
    errors: list[str] = []
    conclude = merged.get("conclude")
    if not isinstance(conclude, dict):
        return errors
    disposition = conclude.get("disposition")
    if disposition is None:
        return errors

    # Aggregate verdicts per contract (all edges considered).
    verdicts_by_contract: dict[str, list[str]] = {}
    for _, _, r in _iter_edge_resolutions(merged):
        cid = r.get("fulfills_contract")
        verdict = r.get("verdict")
        if isinstance(cid, str) and isinstance(verdict, str):
            verdicts_by_contract.setdefault(cid, []).append(verdict)

    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str):
            continue
        contracts = h.get("legitimacy_contract") or []
        if not contracts:
            continue
        final_weight = compute_final_weight(merged, hid)
        if final_weight not in ("++", "+"):
            continue
        status = compute_final_status(merged, hid)
        if status not in ("active", "confirmed"):
            continue

        for c in contracts:
            if not isinstance(c, dict):
                continue
            lc_id = c.get("id")
            if not isinstance(lc_id, str):
                continue
            contract_ref = f"{hid}.{lc_id}"
            verdicts = verdicts_by_contract.get(contract_ref, [])
            has_authorized = "authorized" in verdicts
            has_unauthorized = "unauthorized" in verdicts
            has_indeterminate = "indeterminate" in verdicts

            if disposition == "benign":
                if not verdicts:
                    errors.append(
                        f"hypothesis {hid}: legitimacy_contract {lc_id} on a live-weight "
                        f"hypothesis has no fulfilling legitimacy_resolutions entry, "
                        f"but conclude.disposition is 'benign'. Resolve the contract "
                        f"against its declared anchor, or escalate."
                    )
                elif has_unauthorized:
                    errors.append(
                        f"hypothesis {hid}: legitimacy_contract {lc_id} has a "
                        f"resolution with verdict 'unauthorized' but "
                        f"conclude.disposition is 'benign'. Escalate instead."
                    )
                elif has_indeterminate and not has_authorized:
                    errors.append(
                        f"hypothesis {hid}: legitimacy_contract {lc_id} has only "
                        f"'indeterminate' resolution(s); conclude.disposition is "
                        f"'benign'. Escalate instead."
                    )
                elif not has_authorized:
                    errors.append(
                        f"hypothesis {hid}: legitimacy_contract {lc_id} fulfilled with "
                        f"verdict(s) {sorted(set(verdicts))} — none are 'authorized' — "
                        f"yet conclude.disposition is 'benign'. Benign requires every "
                        f"contract on a live-weight hypothesis to resolve 'authorized'."
                    )
    return errors


def _check_attribute_updates_target_shape(merged: dict[str, Any]) -> list[str]:
    """Spec rule #22: every attribute_updates entry has exactly one target.

    Target is `v-{id}` or `e-{id}`, and the id exists in the companion.
    Existence is also covered by the generic id-reference check; this
    rule additionally enforces shape (target key present, single id,
    correct prefix).
    """
    errors: list[str] = []
    declared_ids = _collect_declared_ids(merged)
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for i, upd in enumerate(lead.get("outcome", {}).get("attribute_updates") or []):
            ctx = f"lead {lid} attribute_updates[{i}]"
            if not isinstance(upd, dict):
                errors.append(f"{ctx}: entry must be a mapping")
                continue
            if "vertex" in upd and "target" not in upd:
                errors.append(
                    f"{ctx}: uses legacy `vertex:` field — use `target: v-{{id}} | e-{{id}}`"
                )
                continue
            target = upd.get("target")
            if not isinstance(target, str) or not target:
                errors.append(
                    f"{ctx}: missing `target:` (required, must be v-{{id}} or e-{{id}})"
                )
                continue
            if not (target.startswith("v-") or target.startswith("e-")):
                errors.append(
                    f"{ctx}: target {target!r} must start with 'v-' or 'e-'"
                )
                continue
            if target not in declared_ids:
                errors.append(
                    f"{ctx}: target {target!r} does not resolve to a declared id"
                )
            if "updates" not in upd or not isinstance(upd.get("updates"), dict):
                errors.append(
                    f"{ctx}: missing or non-mapping `updates` field"
                )
    return errors


def _check_lead_dedup_warnings(merged: dict[str, Any]) -> list[str]:
    """Warn when two leads share the same template + query + substitutions.

    Re-issuing an identical query across loops signals the investigation
    is stalling — no new information is being collected. The warning is
    non-blocking because a re-issue can be legitimate (re-running after
    a transient failure, confirming a result on a fresh time window),
    but it's worth surfacing so the agent notices.
    """
    warnings: list[str] = []
    seen: dict[tuple[str, str, tuple[tuple[str, Any], ...]], str] = {}
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        qd = lead.get("query_details") or {}
        if not isinstance(qd, dict):
            continue
        template = qd.get("template") or ""
        query = qd.get("query") or ""
        subs = qd.get("substitutions") or {}
        if not isinstance(subs, dict):
            subs = {}
        if not (template or query):
            continue
        # Hash key: template + query + sorted substitutions (JSON-comparable).
        try:
            subs_key = tuple(sorted(
                (str(k), json.dumps(v, sort_keys=True, default=str))
                for k, v in subs.items()
            ))
        except TypeError:
            subs_key = ()
        key = (str(template), str(query), subs_key)
        lid = lead.get("id", "?")
        if key in seen:
            warnings.append(
                f"lead {lid}: reissues the query from lead {seen[key]!r} with "
                f"identical template, query, and substitutions — no progress "
                f"toward discrimination. If a retry is intentional, note the "
                f"reason in selection_rationale."
            )
        else:
            seen[key] = lid
    return warnings


def _check_silent_empty_result_warnings(merged: dict[str, Any]) -> list[str]:
    """Warn when a discriminating lead returns nothing without a positive signal.

    A lead that declares `tests: [h-*, ...]` claims to discriminate
    between hypotheses. If it returns zero observations AND has no
    trust_anchor_result AND no failure_reason, the outcome is silently
    empty — the agent can't tell whether the query was correct but the
    world has nothing, or whether the query was broken. Proof-of-absence
    should be recorded explicitly: set `trust_anchor_result.result:
    unavailable` or `failure_reason`.
    """
    warnings: list[str] = []
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        tests = lead.get("tests") or []
        if not tests:
            continue  # non-discriminating lead — silent empty is fine
        outcome = lead.get("outcome") or {}
        if not isinstance(outcome, dict):
            continue
        obs = outcome.get("observations") or {}
        verts = obs.get("vertices") or [] if isinstance(obs, dict) else []
        edges = obs.get("edges") or [] if isinstance(obs, dict) else []
        attr_upd = outcome.get("attribute_updates") or []
        if verts or edges or attr_upd:
            continue
        if outcome.get("trust_anchor_result"):
            continue
        if outcome.get("failure_reason"):
            continue
        lid = lead.get("id", "?")
        warnings.append(
            f"lead {lid}: declares tests {list(tests)!r} but outcome has no "
            f"observations, no attribute_updates, no trust_anchor_result, and "
            f"no failure_reason. If the query genuinely returned nothing, "
            f"record it explicitly via trust_anchor_result.result: unavailable "
            f"or failure_reason — silent empty results are indistinguishable "
            f"from a broken query."
        )
    return warnings


def _load_tool_audit_entries(run_dir: Path) -> list[dict[str, Any]] | None:
    """Load all tool_audit.jsonl entries from the runs directory.

    `tool_audit.jsonl` lives in the runs root (one global file for all
    runs), not per-run. No session filter is applied — leads are
    dispatched to subagents by default, and the subagent's SIEM query
    lands in the audit log under the subagent's session_id, not the
    main agent's. Session-based filtering would therefore false-positive
    on every subagent-dispatched lead.

    The trade-off is FP across concurrent runs of the same signature
    (same query text appearing in some *other* run's audit entry would
    satisfy the substring match). Query text is specific enough in
    practice — signatures parameterize on IP / user / host — that
    cross-run collisions are rare. The check remains WARN-level to
    absorb whatever false-positive rate does occur.

    Returns None when the audit file does not exist (audit hook not
    running — no signal, caller skips silently). Returns an empty list
    when the file exists but contains no parsable entries.
    """
    runs_root = run_dir.parent
    audit_path = runs_root / "tool_audit.jsonl"
    if not audit_path.exists():
        return None
    try:
        lines = audit_path.read_text().splitlines()
    except OSError:
        return None
    entries: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def _audit_blob(entry: dict[str, Any]) -> str:
    """Flatten a tool_audit entry's tool_input into a searchable string."""
    tool_input = entry.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return ""
    try:
        return json.dumps(tool_input, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return ""


def _check_tool_audit_cross_ref_warnings(
    merged: dict[str, Any], run_dir: Path | None
) -> list[str]:
    """Warn when a lead's query_details has no corresponding tool_audit entry.

    For each lead's `query_details.query`, scan the global
    tool_audit.jsonl for any tool call whose `tool_input` (serialized)
    contains the query as a substring. No session filter: lead queries
    are executed by gather subagents under their own session_id, so
    session-based matching would miss every subagent-dispatched query.
    The trade-off is false-positive risk from concurrent runs of the
    same signature that happen to issue the same parameterized query —
    rare in practice because queries parameterize on IPs, users, and
    hosts.

    `tool_input` is truncated to 2000 chars by the audit hook, so the
    check matches on a prefix of the query to avoid false negatives on
    long queries. When no match is found, emit a warning — this is
    the deterministic signal for fabricated leads (the companion claims
    a query was run that no tool call evidences).

    Warning-only because:
    - The audit hook may lag or be disabled.
    - Truncation at the 2000-char boundary can land in the middle of a
      query prefix.
    - Cross-run FP risk described above.

    A future rollout can promote to ERROR once false-positive rate is
    measured against the case fixtures.
    """
    if run_dir is None:
        return []
    entries = _load_tool_audit_entries(run_dir)
    if entries is None:
        # Audit hook not running — no signal available; don't warn.
        return []
    blobs = [_audit_blob(e) for e in entries]

    # Match on the first 500 chars of the query to stay well under the
    # 2000-char truncation boundary with room for JSON escaping.
    MATCH_PREFIX_LEN = 500
    # Ignore very short queries — they're too generic to pin down.
    MIN_QUERY_LEN = 12

    warnings: list[str] = []
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        qd = lead.get("query_details") or {}
        if not isinstance(qd, dict):
            continue
        query = qd.get("query")
        if not isinstance(query, str) or len(query.strip()) < MIN_QUERY_LEN:
            continue
        needle = query[:MATCH_PREFIX_LEN]
        # JSON-serialized tool_input will have quotes around string values;
        # the substring must appear literally in the serialized form.
        if any(needle in b for b in blobs):
            continue
        lid = lead.get("id", "?")
        preview = query if len(query) <= 80 else query[:80] + "..."
        warnings.append(
            f"lead {lid}: query {preview!r} has no matching entry anywhere "
            f"in tool_audit.jsonl. Either the query was fabricated, or the "
            f"audit log was truncated / truncated mid-prefix — verify the "
            f"query was actually executed."
        )
    return warnings


# ---------------------------------------------------------------------------
# Main validation entry
# ---------------------------------------------------------------------------

def _parse_blocks(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract and parse all ```yaml blocks from `text`.

    Returns (parsed_dicts, parse_errors). Non-dict YAML documents and
    malformed blocks are surfaced via the error list.
    """
    blocks: list[dict[str, Any]] = []
    errors: list[str] = []
    for match in YAML_BLOCK_RE.finditer(text):
        raw = match.group(1)
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            errors.append(f"YAML parse error in block: {e}")
            continue
        if isinstance(doc, dict):
            blocks.append(doc)
    return blocks, errors


def validate_companion(proposed_text: str, current_text: str | None) -> list[str]:
    """Parse and validate all YAML companion blocks from proposed_text.

    current_text is the pre-write on-disk content (for append-only check
    and prediction-lifecycle diff). Returns a list of error strings;
    empty = pass.
    """
    blocks, errors = _parse_blocks(proposed_text)

    # Append-only check: runs even when proposed has no blocks (removing all is a violation)
    if current_text is not None:
        errors.extend(_check_append_only(proposed_text, current_text))

    if not blocks:
        return errors  # no YAML blocks in proposed — nothing structural to check

    merged = _merge_blocks(blocks)

    errors.extend(_check_lead_required_fields(merged))
    errors.extend(_check_id_formats(merged))
    errors.extend(_check_id_references(merged))
    errors.extend(_check_edge_authority(merged))
    errors.extend(_check_refutation_ids(merged))
    errors.extend(_check_trust_anchor_completeness(merged))
    errors.extend(_check_screen_result_scope(merged))
    errors.extend(_check_lead_predictions(merged))
    errors.extend(_check_prediction_coverage(merged))
    errors.extend(_check_partial_authority_cap(merged))
    errors.extend(_check_rollup_parent_weight(merged))
    errors.extend(_check_legitimacy_contract_edge_ref(merged))
    errors.extend(_check_legitimacy_resolution_backrefs(merged))
    errors.extend(_check_legitimacy_gated_disposition(merged))
    errors.extend(_check_attribute_updates_target_shape(merged))

    # Prediction-lifecycle guard needs the on-disk companion as well.
    if current_text is not None:
        current_blocks, _ = _parse_blocks(current_text)
        if current_blocks:
            current_merged = _merge_blocks(current_blocks)
            errors.extend(_check_prediction_lifecycle(merged, current_merged))

    return errors


def collect_warnings(
    proposed_text: str,
    run_dir: Path | None = None,
) -> list[str]:
    """Non-blocking checks that emit warnings rather than errors.

    Run after `validate_companion` clears structural errors. `run_dir`
    enables the tool_audit cross-reference check; when missing, that
    check is skipped silently.
    """
    warnings: list[str] = []
    blocks, _ = _parse_blocks(proposed_text)

    if not blocks:
        return warnings

    merged = _merge_blocks(blocks)
    warnings.extend(_check_route_compliance(merged))
    warnings.extend(_check_lead_dedup_warnings(merged))
    warnings.extend(_check_silent_empty_result_warnings(merged))
    warnings.extend(_check_tool_audit_cross_ref_warnings(merged, run_dir))
    return warnings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    run_dir, proposed_text = resolve_proposed_text(hook_data)
    if run_dir is None or proposed_text is None:
        sys.exit(0)

    # Read on-disk content for append-only comparison
    inv_path = run_dir / "investigation.md"
    current_text: str | None = None
    if inv_path.exists():
        try:
            current_text = inv_path.read_text()
        except OSError:
            pass

    errors = validate_companion(proposed_text, current_text)
    if errors:
        print("invlang validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        print(
            "Next action: fix the YAML block(s) and retry the write.",
            file=sys.stderr,
        )
        sys.exit(2)

    warnings = collect_warnings(proposed_text, run_dir)
    if warnings:
        print("invlang warnings:", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
