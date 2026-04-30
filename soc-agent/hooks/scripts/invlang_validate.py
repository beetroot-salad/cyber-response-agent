#!/usr/bin/env python3
"""PreToolUse hook: investigation-language YAML block structural validator.

Fires on Write/Edit targeting `investigation.md` (narrowed by `if` filters in
plugin.json). Computes the proposed post-write text, extracts all ```yaml blocks,
merges them into a single companion body, and checks structural rules.

Passes immediately if:
- The event does not target a valid investigation.md path
- The proposed content contains no ```yaml blocks (narrative-only write)

Rule surface is split across companion modules for maintainability:
- `invlang_common.py` — shared helpers, constants, dataclasses
- `invlang_checks_structural.py` — structural rules (lead fields, IDs, edge
  authority, refutation IDs, screen structural integrity, lead predictions,
  rule #11 provenance for authz resolutions and anchor consultations)
- `invlang_checks_predictions.py` — prediction discipline (coverage, partial
  authority cap across authz/consultation/impact surfaces, prediction
  lifecycle, rollup parent weight)
- `invlang_checks_authorization.py` — authorization-as-edge-attribute
  rules (contract edge_ref and resolution back-refs are sub-cases of
  spec rule #7 reference resolution post-v2.14; gated disposition is
  rule #21; attribute_updates target shape is rules #1 + #7)
- `invlang_checks_impact.py` — lead-level impact_predictions /
  impact_resolutions + CONCLUDE two-axis (impact_verdict /
  impact_severity / deferred_impact_predictions)
- `invlang_checks_hypothesis.py` — hypothesis-discipline rules (fork
  distinctness, persistence, prediction-id scope, compound claims,
  evaluation-prefixed classifications, leanness, subject scope, refutation
  link, integrity-peer discipline)

This file orchestrates them and owns the block-level append-only check plus
the warning pipeline (route compliance, dedup, silent empty, tool audit
cross-ref).

Exit codes:
    0 - Passed (or warnings only)
    2 - Validation failed (message fed back to agent, blocks the write)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(SOC_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.investigation_parse import resolve_proposed_text
from hooks.scripts.invlang_common import (
    COMPANION_TOP_LEVEL,
    INVLANG_BLOCK_RE,
    YAML_BLOCK_RE,
    _merge_blocks,
)
from hooks.scripts.invlang_checks_structural import (
    _check_anchor_consultation_provenance,
    _check_authorization_resolution_provenance,
    _check_edge_authority,
    _check_id_formats,
    _check_id_references,
    _check_lead_predictions,
    _check_lead_required_fields,
    _check_refutation_ids,
    _check_screen_result_scope,
)
from hooks.scripts.invlang_checks_predictions import (
    _check_partial_authority_cap,
    _check_prediction_closure,
    _check_prediction_coverage,
    _check_prediction_lifecycle,
    _check_rollup_parent_weight,
)
from hooks.scripts.invlang_checks_authorization import (
    _check_affirmative_true_positive,
    _check_attribute_updates_target_shape,
    _check_authorization_contract_edge_ref,
    _check_authorization_gated_disposition,
    _check_authorization_resolution_backrefs,
)
from hooks.scripts.invlang_checks_impact import (
    _check_conclude_two_axis,
    _check_impact_closure,
    _check_impact_prediction_structure,
    _check_impact_resolution_backrefs,
)
from hooks.scripts.invlang_checks_hypothesis import (
    _check_attribute_prediction_structure,
    _check_classification_evaluation_prefix,
    _check_compound_prediction_claim,
    _check_hypothesis_fork_distinctness,
    _check_hypothesis_persistence,
    _check_integrity_peer_discipline,
    _check_prediction_id_hypothesis_scope,
    _check_prediction_subject_scope,
    _check_predictions_leanness,
    _check_refutation_prediction_links,
    _check_sibling_prediction_divergence,
)

# Re-exports required by consumers importing from this module path
# (validate_report_precheck.py, scripts/handlers/*.py, tests/*.py).
__all__ = [
    "YAML_BLOCK_RE",
    "COMPANION_TOP_LEVEL",
    "_merge_blocks",
    "_parse_blocks",
    "_check_append_only",
    "_check_lead_required_fields",
    "_check_id_formats",
    "_check_id_references",
    "_check_edge_authority",
    "_check_refutation_ids",
    "_check_screen_result_scope",
    "_check_lead_predictions",
    "_check_route_compliance",
    "_check_prediction_coverage",
    "_check_partial_authority_cap",
    "_check_prediction_closure",
    "_check_prediction_lifecycle",
    "_check_rollup_parent_weight",
    "_check_authorization_contract_edge_ref",
    "_check_authorization_resolution_backrefs",
    "_check_authorization_gated_disposition",
    "_check_affirmative_true_positive",
    "_check_attribute_updates_target_shape",
    "_check_authorization_resolution_provenance",
    "_check_anchor_consultation_provenance",
    "_check_impact_prediction_structure",
    "_check_impact_resolution_backrefs",
    "_check_impact_closure",
    "_check_conclude_two_axis",
    "_check_integrity_peer_discipline",
    "_check_hypothesis_fork_distinctness",
    "_check_hypothesis_persistence",
    "_check_prediction_id_hypothesis_scope",
    "_check_compound_prediction_claim",
    "_check_classification_evaluation_prefix",
    "_check_predictions_leanness",
    "_check_prediction_subject_scope",
    "_check_refutation_prediction_links",
    "_check_sibling_prediction_divergence",
    "_check_attribute_prediction_structure",
    "_check_lead_dedup_warnings",
    "_check_silent_empty_result_warnings",
    "_check_tool_audit_cross_ref_warnings",
    "validate_companion",
    "collect_warnings",
]


# ---------------------------------------------------------------------------
# Block-level append-only (diffing current vs proposed)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------

def _check_route_compliance(merged: dict[str, Any]) -> list[str]:
    """Warn when a lead's predictions don't cover the actually-next lead.

    For each lead with `predictions`:
      - if there's a following lead in the same companion, its `name` should
        appear in at least one `advance_to`.
      - if there's no following lead (this is the last lead in `gather`),
        `REPORT` should appear in at least one `advance_to`.
    """
    warnings: list[str] = []
    leads = merged.get("findings", []) or []
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
            if "REPORT" not in advance_tos:
                warnings.append(
                    f"lead {lid}: terminal lead with predictions but no advance_to names "
                    f"REPORT (declared: {sorted(a for a in advance_tos if a)})"
                )
            continue

        next_name = next_lead.get("name") if isinstance(next_lead, dict) else None
        if not isinstance(next_name, str):
            continue
        if next_name not in advance_tos:
            warnings.append(
                f"lead {lid}: next lead {next_name!r} does not match any advance_to "
                f"(declared: {sorted(a for a in advance_tos if a)}). "
                f"If the fork space was incomplete, PREDICT to extend it."
            )

    return warnings


def _check_lead_dedup_warnings(merged: dict[str, Any]) -> list[str]:
    """Warn when two leads share the same template + query + substitutions."""
    warnings: list[str] = []
    seen: dict[tuple[str, str, tuple[tuple[str, Any], ...]], str] = {}
    for lead in merged.get("findings", []) or []:
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

    v2.11: The former `trust_anchor_result` surface is gone. Silent-empty
    is now fine when the lead produced any of: observations,
    attribute_updates, anchor_consultations, or failure_reason.
    """
    warnings: list[str] = []
    for lead in merged.get("findings", []) or []:
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
        if outcome.get("anchor_consultations"):
            continue
        if outcome.get("failure_reason"):
            continue
        lid = lead.get("id", "?")
        warnings.append(
            f"lead {lid}: declares tests {list(tests)!r} but outcome has no "
            f"observations, no attribute_updates, no anchor_consultations, and "
            f"no failure_reason. If the query genuinely returned nothing, "
            f"record it explicitly via anchor_consultations (result: no-data) "
            f"or failure_reason — silent empty results are indistinguishable "
            f"from a broken query."
        )
    return warnings


def _load_tool_audit_entries(run_dir: Path) -> list[dict[str, Any]] | None:
    """Load all tool_audit.jsonl entries from the runs directory."""
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
    """Warn when a lead's query_details has no corresponding tool_audit entry."""
    if run_dir is None:
        return []
    entries = _load_tool_audit_entries(run_dir)
    if entries is None:
        return []
    blobs = [_audit_blob(e) for e in entries]

    MATCH_PREFIX_LEN = 500
    MIN_QUERY_LEN = 12

    warnings: list[str] = []
    for lead in merged.get("findings", []) or []:
        if not isinstance(lead, dict):
            continue
        qd = lead.get("query_details") or {}
        if not isinstance(qd, dict):
            continue
        query = qd.get("query")
        if not isinstance(query, str) or len(query.strip()) < MIN_QUERY_LEN:
            continue
        needle = query[:MATCH_PREFIX_LEN]
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
    """Extract and parse all companion blocks from `text`.

    Three surfaces are walked, in this order:
      1. Every ```yaml fenced block (legacy + non-cutover phases).
      2. Every ```invlang fenced block (dense surface; Foundation-onward).
         Parsed via `scripts/handlers/_dense_parser` and projected to the
         canonical companion dict shape so `_merge_blocks` and the 29
         validator rules remain untouched.
      3. The legacy bare `:T conclude` block (no fence) authored by REPORT
         pre-Foundation. Synthesized as a `{"conclude": <dict>}` document
         and appended last so it wins over any conflicting YAML/dense
         conclude (mirrors the on-disk write order).

    Returns (parsed_dicts, parse_errors). Non-dict YAML documents,
    malformed YAML, and malformed dense blocks are surfaced via the error
    list.
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

    # ```invlang fences — walk via the unified dense parser. Track whether
    # the dense surface emitted a `conclude` so the legacy bare-conclude
    # fallback (next step) only fires for pre-Foundation files.
    dense_emitted_conclude = False
    if INVLANG_BLOCK_RE.search(text):
        try:
            from scripts.handlers._dense_parser import (  # type: ignore
                parse_dense_companion,
                DenseParseError,
            )
            dense_doc = parse_dense_companion(text)
            if dense_doc:
                blocks.append(dense_doc)
                if "conclude" in dense_doc:
                    dense_emitted_conclude = True
        except DenseParseError as e:
            errors.append(f"dense ```invlang block malformed: {e}")

    # Legacy bare `:T conclude` (pre-Foundation; old on-disk files only).
    # Skipped only if a ```invlang fence already produced a conclude — a
    # YAML-fence conclude is intentionally still overridden by the legacy
    # bare block so behavior matches the pre-Foundation last-wins order.
    if not dense_emitted_conclude:
        dense_conclude = _parse_dense_conclude(text, errors)
        if dense_conclude is not None:
            for b in blocks:
                b.pop("conclude", None)
            blocks.append({"conclude": dense_conclude})

    return blocks, errors


def _parse_dense_conclude(
    text: str, errors: list[str]
) -> dict[str, Any] | None:
    """Parse the REPORT-phase dense `:T conclude` block (if present) into
    the canonical conclude dict shape.

    Malformed dense blocks append a parse error and return None so the
    validator surfaces a precise message rather than silently falling back.

    SOC_AGENT_ROOT is on sys.path from this module's top — no local
    sys.path manipulation needed.
    """
    from scripts.handlers._conclude_dense import (  # type: ignore
        ConcludeOutputError,
        parse_conclude_dense,
    )
    try:
        return parse_conclude_dense(text)
    except ConcludeOutputError as e:
        errors.append(f"dense :T conclude block malformed: {e}")
        return None


def validate_companion(proposed_text: str, current_text: str | None) -> list[str]:
    """Parse and validate all YAML companion blocks from proposed_text.

    current_text is the pre-write on-disk content (for append-only check
    and prediction-lifecycle diff). Returns a list of error strings;
    empty = pass.
    """
    blocks, errors = _parse_blocks(proposed_text)

    if current_text is not None:
        errors.extend(_check_append_only(proposed_text, current_text))

    if not blocks:
        return errors

    merged = _merge_blocks(blocks)

    # Structural
    errors.extend(_check_lead_required_fields(merged))
    errors.extend(_check_id_formats(merged))
    errors.extend(_check_id_references(merged))
    errors.extend(_check_edge_authority(merged))
    errors.extend(_check_refutation_ids(merged))
    errors.extend(_check_screen_result_scope(merged))
    errors.extend(_check_lead_predictions(merged))

    # Rule #11 provenance (split by surface)
    errors.extend(_check_authorization_resolution_provenance(merged))
    errors.extend(_check_anchor_consultation_provenance(merged))

    # Authorization (post-v2.14: contract edge_ref + back-refs +
    # attribute_updates target are sub-cases of rule #7; gated
    # disposition stays as rule #21)
    errors.extend(_check_authorization_contract_edge_ref(merged))
    errors.extend(_check_authorization_resolution_backrefs(merged))
    errors.extend(_check_authorization_gated_disposition(merged))
    errors.extend(_check_affirmative_true_positive(merged))
    errors.extend(_check_attribute_updates_target_shape(merged))

    # Impact (rules #29–#31) + CONCLUDE two-axis
    errors.extend(_check_impact_prediction_structure(merged))
    errors.extend(_check_impact_resolution_backrefs(merged))
    errors.extend(_check_impact_closure(merged))
    errors.extend(_check_conclude_two_axis(merged))

    # Hypothesis (rules #23–#32 minus impact closure)
    errors.extend(_check_hypothesis_fork_distinctness(merged))
    errors.extend(_check_hypothesis_persistence(merged))
    errors.extend(_check_prediction_id_hypothesis_scope(merged))
    errors.extend(_check_compound_prediction_claim(merged))
    errors.extend(_check_classification_evaluation_prefix(merged))
    errors.extend(_check_predictions_leanness(merged))
    errors.extend(_check_prediction_subject_scope(merged))
    errors.extend(_check_refutation_prediction_links(merged))
    errors.extend(_check_sibling_prediction_divergence(merged))
    errors.extend(_check_integrity_peer_discipline(merged))
    errors.extend(_check_attribute_prediction_structure(merged))

    # Predictions / weight coverage
    errors.extend(_check_prediction_coverage(merged))
    errors.extend(_check_partial_authority_cap(merged))
    errors.extend(_check_rollup_parent_weight(merged))
    errors.extend(_check_prediction_closure(merged))

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
    """Non-blocking checks that emit warnings rather than errors."""
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
