"""Prediction-discipline checks (rules 11-14 in the validator docstring).

Covers: prediction coverage, partial authority cap, prediction lifecycle
(append-only at ID granularity), and rollup parent weight.
"""

from __future__ import annotations

from typing import Any

from hooks.scripts.invlang_common import _index_hypothesis_id_field_ids
from hooks.scripts.invlang_walkers import (
    WEIGHT_NUMERIC,
    compute_final_weight,
    iter_hypotheses,
    parent_hypothesis_id,
)


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
    """Rule #14 (partial authority cap): anchor-only grounding cannot produce ++/--.

    A resolution on a lead is capped at `+` or `-` when *every* grounding
    source on the lead is partial. The cap applies across all three v2.11
    grounding surfaces:

    - `authorization_resolutions[]` on edges emitted by this lead
      (either inline on new edges in `outcome.observations.edges[]` or
      via `outcome.attribute_updates[].updates.authorization_resolutions[]`)
    - `anchor_consultations[]` on the lead outcome
    - `impact_resolutions[]` on the lead outcome

    Scoping: `has_partial` tracks "any partial entry present"; `has_full`
    tracks "any full-authority entry present". The cap fires only when
    `has_partial and not has_full` — a full-authority entry on the same
    lead is load-bearing on its own and lets the weight land past `+`/`-`
    regardless of a co-located partial consultation. Mixed grounding via
    `supporting_edges` continues to exempt the resolution row-wise.
    """
    errors: list[str] = []
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        outcome = lead.get("outcome") if isinstance(lead.get("outcome"), dict) else {}
        has_partial = False
        has_full = False

        def _classify(entry: Any) -> None:
            nonlocal has_partial, has_full
            if not isinstance(entry, dict):
                return
            afq = entry.get("authority_for_question")
            if afq == "partial":
                has_partial = True
            elif afq == "full":
                has_full = True

        # anchor_consultations (baseline / registry lookups)
        for entry in outcome.get("anchor_consultations") or []:
            _classify(entry)
        # impact_resolutions
        for entry in outcome.get("impact_resolutions") or []:
            _classify(entry)
        # edge-inline authorization_resolutions
        obs = outcome.get("observations") if isinstance(outcome.get("observations"), dict) else {}
        for e in obs.get("edges", []) or []:
            if not isinstance(e, dict):
                continue
            for entry in e.get("authorization_resolutions") or []:
                _classify(entry)
        # attribute_updates authorization_resolutions
        for upd in outcome.get("attribute_updates") or []:
            if not isinstance(upd, dict):
                continue
            updates = upd.get("updates") if isinstance(upd.get("updates"), dict) else {}
            for entry in updates.get("authorization_resolutions") or []:
                _classify(entry)

        if not has_partial or has_full:
            continue  # either no partial at all, or a co-located full grounds it

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
                f"grounded solely by a partial-authority consultation / resolution "
                f"(authority_for_question: \"partial\") with empty supporting_edges. "
                f"Partial authority caps the weight at \"+\" or \"-\"."
            )
    return errors


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
