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
  authority, refutation IDs, trust anchor, screen scope, lead predictions)
- `invlang_checks_predictions.py` — prediction discipline (coverage, partial
  authority cap, prediction lifecycle, rollup parent weight)
- `invlang_checks_legitimacy.py` — legitimacy-as-edge-attribute rules
  (contract, resolution back-refs, gated disposition, asks/verdict, supersede
  chain, target shape, consultation requirement)
- `invlang_checks_hypothesis.py` — hypothesis-discipline rules (fork
  distinctness, persistence, prediction-id scope, compound claims, evaluation-
  prefixed classifications, leanness, subject scope, refutation link)

This file orchestrates them and owns the block-level append-only check plus
the warning pipeline (route compliance, dedup, silent empty, tool audit
cross-ref).

Warnings (non-blocking, printed to stderr with exit 0):
- Route compliance: when a lead with `predictions` is followed by another lead
  in the same companion, the follower's `name` should match at least one
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
    YAML_BLOCK_RE,
    _merge_blocks,
)
from hooks.scripts.invlang_checks_structural import (
    _check_edge_authority,
    _check_id_formats,
    _check_id_references,
    _check_lead_predictions,
    _check_lead_required_fields,
    _check_refutation_ids,
    _check_screen_result_scope,
    _check_trust_anchor_completeness,
)
from hooks.scripts.invlang_checks_predictions import (
    _check_partial_authority_cap,
    _check_prediction_coverage,
    _check_prediction_lifecycle,
    _check_rollup_parent_weight,
)
from hooks.scripts.invlang_checks_legitimacy import (
    _check_asks_verdict_shape,
    _check_attribute_updates_target_shape,
    _check_kind_asks_coherence,
    _check_legitimacy_contract_edge_ref,
    _check_legitimacy_gated_disposition,
    _check_legitimacy_resolution_backrefs,
    _check_legitimacy_resolution_target_shape,
    _check_legitimacy_supersede_chain,
    _check_resolution_requires_authorization_asks,
)
from hooks.scripts.invlang_checks_hypothesis import (
    _check_classification_evaluation_prefix,
    _check_compound_prediction_claim,
    _check_hypothesis_fork_distinctness,
    _check_hypothesis_persistence,
    _check_prediction_id_hypothesis_scope,
    _check_prediction_subject_scope,
    _check_predictions_leanness,
    _check_refutation_prediction_links,
)

# Re-exports required by consumers importing from this module path
# (validate_conclude.py, scripts/handlers/*.py, tests/test_invlang_validate.py).
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
    "_check_trust_anchor_completeness",
    "_check_screen_result_scope",
    "_check_lead_predictions",
    "_check_route_compliance",
    "_check_prediction_coverage",
    "_check_partial_authority_cap",
    "_check_prediction_lifecycle",
    "_check_rollup_parent_weight",
    "_check_legitimacy_contract_edge_ref",
    "_check_legitimacy_resolution_backrefs",
    "_check_legitimacy_gated_disposition",
    "_check_attribute_updates_target_shape",
    "_check_asks_verdict_shape",
    "_check_kind_asks_coherence",
    "_check_legitimacy_resolution_target_shape",
    "_check_legitimacy_supersede_chain",
    "_check_resolution_requires_authorization_asks",
    "_check_hypothesis_fork_distinctness",
    "_check_hypothesis_persistence",
    "_check_prediction_id_hypothesis_scope",
    "_check_compound_prediction_claim",
    "_check_classification_evaluation_prefix",
    "_check_predictions_leanness",
    "_check_prediction_subject_scope",
    "_check_refutation_prediction_links",
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
                f"If the fork space was incomplete, PREDICT to extend it."
            )

    return warnings


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
    errors.extend(_check_asks_verdict_shape(merged))
    errors.extend(_check_kind_asks_coherence(merged))
    errors.extend(_check_legitimacy_resolution_target_shape(merged))
    errors.extend(_check_legitimacy_supersede_chain(merged))
    errors.extend(_check_resolution_requires_authorization_asks(merged))
    errors.extend(_check_hypothesis_fork_distinctness(merged))
    errors.extend(_check_hypothesis_persistence(merged))
    errors.extend(_check_prediction_id_hypothesis_scope(merged))
    errors.extend(_check_compound_prediction_claim(merged))
    errors.extend(_check_classification_evaluation_prefix(merged))
    errors.extend(_check_predictions_leanness(merged))
    errors.extend(_check_prediction_subject_scope(merged))
    errors.extend(_check_refutation_prediction_links(merged))

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
