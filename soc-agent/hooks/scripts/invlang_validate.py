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

Exit codes:
    0 - Passed (or not applicable)
    2 - Validation failed (message fed back to agent, blocks the write)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.run_context import extract_run_dir_from_path

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


# ---------------------------------------------------------------------------
# Proposed-content resolution (mirrors validate_conclude.py)
# ---------------------------------------------------------------------------

def resolve_proposed_text(hook_data: dict) -> tuple[Path | None, str | None]:
    """Return (run_dir, proposed_text) for a PreToolUse targeting investigation.md."""
    tool_name = hook_data.get("tool_name", "")
    tool_input = hook_data.get("tool_input", {})
    file_path = tool_input.get("file_path", "")

    run_dir = extract_run_dir_from_path(file_path)
    if run_dir is None:
        return None, None

    if tool_name == "Write":
        content = tool_input.get("content", "")
        return run_dir, content if isinstance(content, str) else ""

    if tool_name == "Edit":
        inv_path = run_dir / "investigation.md"
        if not inv_path.exists():
            return None, None
        try:
            current = inv_path.read_text()
        except OSError:
            return None, None
        old = tool_input.get("old_string", "")
        new = tool_input.get("new_string", "")
        if not isinstance(old, str) or not isinstance(new, str):
            return None, None
        proposed = current.replace(old, new) if tool_input.get("replace_all") else current.replace(old, new, 1)
        return run_dir, proposed

    return None, None


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
    for entry in merged.get("gather", []):
        lead = entry.get("lead", {})
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
    for i, entry in enumerate(merged.get("gather", [])):
        if not isinstance(entry, dict) or "lead" not in entry:
            errors.append(f"gather[{i}]: entry missing 'lead' key")
            continue
        lead = entry["lead"]
        if not isinstance(lead, dict):
            errors.append(f"gather[{i}].lead: must be a mapping")
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
    for entry in merged.get("gather", []):
        lead = entry.get("lead", {})
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

    for entry in merged.get("gather", []):
        lead = entry.get("lead", {})
        lid = lead.get("id", "?")
        _ref(lead.get("target"), f"lead {lid} target")
        for tid in lead.get("tests", []) or []:
            _ref(tid, f"lead {lid} tests")
        for obs in lead.get("observes", []) or []:
            _ref(obs.get("hypothesis"), f"lead {lid} observes.hypothesis")
        for attr_upd in lead.get("outcome", {}).get("attribute_updates", []) or []:
            _ref(attr_upd.get("vertex"), f"lead {lid} attribute_updates.vertex")
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
    for entry in merged.get("gather", []):
        lead = entry.get("lead", {})
        obs = lead.get("outcome", {}).get("observations", {})
        for e in obs.get("edges", []):
            eid = e.get("id")
            kind = e.get("authority", {}).get("kind", "")
            if eid:
                edge_authority[eid] = kind

    for entry in merged.get("gather", []):
        lead = entry.get("lead", {})
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
    for entry in merged.get("gather", []):
        lead = entry.get("lead", {})
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
    for entry in merged.get("gather", []):
        lead = entry.get("lead", {})
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
    for entry in merged.get("gather", []):
        lead = entry.get("lead", {})
        lid = lead.get("id", "?")
        outcome = lead.get("outcome", {})
        if "screen_result" in outcome and lead.get("mode") != "screen":
            errors.append(
                f"lead {lid}: outcome.screen_result is set but lead.mode is not "
                f"'screen' — screen_result is only valid on SCREEN-dispatched leads"
            )
    return errors


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
# Main validation entry
# ---------------------------------------------------------------------------

def validate_companion(proposed_text: str, current_text: str | None) -> list[str]:
    """Parse and validate all YAML companion blocks from proposed_text.

    current_text is the pre-write on-disk content (for append-only check).
    Returns a list of error strings; empty = pass.
    """
    errors: list[str] = []

    # Extract and parse YAML blocks
    blocks: list[dict[str, Any]] = []
    for match in YAML_BLOCK_RE.finditer(proposed_text):
        raw = match.group(1)
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            errors.append(f"YAML parse error in block: {e}")
            continue
        if isinstance(doc, dict):
            blocks.append(doc)

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

    return errors


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
    if not errors:
        sys.exit(0)

    print("invlang validation failed:", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    print(
        "Next action: fix the YAML block(s) and retry the write.",
        file=sys.stderr,
    )
    sys.exit(2)


if __name__ == "__main__":
    main()
