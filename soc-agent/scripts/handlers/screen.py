"""SCREEN phase handler.

Replaces the SCREEN section of `skills/investigate/SKILL.md` with a Python
orchestration that dispatches one merged Sonnet subagent (`screen`). The
subagent emits a single terminal YAML block carrying both the pattern-match
verdict and the invlang `gather:` transcription — replacing the previous
Haiku screen + Haiku screen-invlang split.

The handler runs a Python structural verifier on the match claim:
matched_pattern must name a loaded Screen row, and every lead in that row's
Leads column must appear in `leads_run`. Failures downgrade the result to
`error` and route to PREDICT.

Input (Context):
    ctx.run_dir, ctx.signature_id, ctx.ticket_id, ctx.alert

Output:
    PhaseResult
      - match → Phase.REPORT, payload carrying the match summary
      - no_match | error | structural-downgraded → Phase.PREDICT
      - empty Screen section → Phase.PREDICT without any subagent call

Files written:
    {run_dir}/investigation.md — appends a `## SCREEN` markdown block + the
    fenced `gather:` YAML. Append is pre-validated via
    `hooks/scripts/invlang_validate.validate_companion()` lazy-imported as a
    library call; the PreToolUse hook is the write-time backstop.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional

import yaml

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._markdown import (
    iter_yaml_fences,
    parse_markdown,
    table_rows_after_heading,
)
from scripts.handlers._subagent import (
    extract_terminal_yaml,
    invoke_subagent as _shared_invoke,
)


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_SCREEN_TIMEOUT_SECONDS", "300")
)


# ---------------------------------------------------------------------------
# Subagent invocation (mockable)
# ---------------------------------------------------------------------------


def _invoke_screen(prompt: str, *, timeout: int = SUBAGENT_TIMEOUT_SECONDS) -> str:
    """Module-level wrapper over the shared subagent dispatcher.

    Kept as a module-level function so tests can monkeypatch it with
    `monkeypatch.setattr(screen_handler, "_invoke_screen", stub)`.
    """
    return _shared_invoke("screen", prompt, timeout=timeout)


# ---------------------------------------------------------------------------
# Playbook Screen table parsing
# ---------------------------------------------------------------------------


def _load_screen_rows(signature_id: str) -> list[dict[str, str]]:
    """Parse the `## Screen` table of a signature's playbook.

    Returns a list of row dicts keyed by the table's header names, lowercased
    and stripped. Empty list when the section is absent OR present-but-empty
    (no data rows after the header separator). Missing playbook file raises
    OrchestrationError — that's a signature-config bug, not a silent skip.
    """
    playbook_path = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "playbook.md"
    )
    if not playbook_path.exists():
        raise OrchestrationError(
            f"playbook not found for {signature_id}: {playbook_path}"
        )
    tokens = parse_markdown(playbook_path.read_text())
    rows = table_rows_after_heading(tokens, "Screen")
    if len(rows) < 1:
        return []
    header = [c.strip().lower() for c in rows[0]]
    data_rows: list[dict[str, str]] = []
    for row in rows[1:]:
        cells = [c.strip() for c in row]
        if len(cells) != len(header):
            continue
        data_rows.append({header[i]: cells[i] for i in range(len(cells))})
    return data_rows


def _parse_leads_column(leads_cell: str) -> list[str]:
    """Split the playbook's Leads column into a list of lead names.

    The column is comma-separated. Names may carry a trailing ` anchor`
    annotation (e.g. `approved-monitoring-sources anchor`) — strip it.
    """
    names = []
    for token in leads_cell.split(","):
        t = token.strip()
        if not t:
            continue
        # Strip trailing " anchor" (with or without hyphenation markers).
        t = re.sub(r"\s+anchor\s*$", "", t).strip()
        if t:
            names.append(t)
    return names


# ---------------------------------------------------------------------------
# Prologue extraction
# ---------------------------------------------------------------------------


def _extract_prologue_yaml(run_dir: Path) -> str:
    """Return the fenced `prologue:` YAML block from `investigation.md` as a
    YAML string (no fence markers).

    Raises OrchestrationError if `investigation.md` is missing or has no
    prologue — the SCREEN handler cannot run before CONTEXTUALIZE has written
    one.
    """
    inv_path = run_dir / "investigation.md"
    if not inv_path.exists():
        raise OrchestrationError(
            f"investigation.md not found at {inv_path}; CONTEXTUALIZE must run first"
        )
    for body in iter_yaml_fences(inv_path.read_text()):
        try:
            parsed = yaml.safe_load(body)
        except yaml.YAMLError:
            continue
        if isinstance(parsed, dict) and "prologue" in parsed:
            return body
    raise OrchestrationError(
        f"investigation.md at {inv_path} has no `prologue:` YAML block"
    )


# ---------------------------------------------------------------------------
# Screen subagent dispatch + validation
# ---------------------------------------------------------------------------


_VALID_SCREEN_RESULTS = {"match", "no_match", "error"}


def _assemble_screen_prompt(ctx: Context, prologue_yaml: str) -> str:
    return (
        f"run_dir={ctx.run_dir}\n"
        f"signature_id={ctx.signature_id}\n\n"
        "prologue_yaml:\n"
        "```yaml\n"
        f"{prologue_yaml.rstrip()}\n"
        "```\n"
    )


def _validate_screen_result(parsed: dict) -> dict:
    screen_result = parsed.get("screen_result")
    if screen_result not in _VALID_SCREEN_RESULTS:
        raise OrchestrationError(
            f"screen subagent returned unknown screen_result {screen_result!r}; "
            f"expected one of {sorted(_VALID_SCREEN_RESULTS)}"
        )
    return parsed


def _structural_verify(
    parsed: dict, screen_rows: list[dict[str, str]],
) -> tuple[dict, Optional[str]]:
    """Verify a `screen_result: match` claim against the playbook Screen table.

    Returns (parsed, downgrade_reason). When downgrade_reason is non-None the
    caller must treat the result as `error` with that reason. On pass-through
    (no downgrade), returns the parsed dict unchanged.

    Check 1: `matched_pattern` names a row loaded from the Screen table.
    Check 2: every lead named in that row's `leads` column appears in
             `leads_run` with a non-null `observation`.
    """
    if parsed.get("screen_result") != "match":
        return parsed, None
    matched_pattern = parsed.get("matched_pattern")
    row = next(
        (r for r in screen_rows if r.get("pattern") == matched_pattern), None,
    )
    if row is None:
        return parsed, (
            f"matched_pattern {matched_pattern!r} does not name any row in the "
            f"Screen table (rows: {[r.get('pattern') for r in screen_rows]})"
        )
    required_leads = _parse_leads_column(row.get("leads", "") or "")
    leads_run = parsed.get("leads_run") or []
    ran_names = {
        (entry or {}).get("lead") for entry in leads_run
        if (entry or {}).get("observation") not in (None, "")
    }
    missing = [lead for lead in required_leads if lead not in ran_names]
    if missing:
        return parsed, (
            f"matched_pattern {matched_pattern!r} requires leads {required_leads} "
            f"but leads_run missing: {missing}"
        )
    return parsed, None


# ---------------------------------------------------------------------------
# Markdown + YAML composition
# ---------------------------------------------------------------------------


def _compose_markdown(
    screen_result: dict, downgrade_reason: Optional[str],
) -> str:
    """Append a `## SCREEN` human-readable section.

    Template mirrors `skills/investigate/SKILL.md:322-329`.
    """
    result_tag = screen_result.get("screen_result", "error")
    if downgrade_reason:
        result_tag = f"error (structural downgrade)"

    leads_run = screen_result.get("leads_run") or []
    if leads_run:
        leads_lines = "\n".join(
            f"- {(entry or {}).get('lead', '?')}: "
            f"{(entry or {}).get('observation', '')}"
            for entry in leads_run
        )
    else:
        leads_lines = "- (none — screen subagent ran no leads)"

    outcome_parts: list[str] = []
    if downgrade_reason:
        outcome_parts.append(f"structural-verification downgrade: {downgrade_reason}")
        outcome_parts.append("falling through to PREDICT")
    elif screen_result.get("screen_result") == "match":
        matched = screen_result.get("matched_pattern", "?")
        archetype = screen_result.get("matched_archetype") or "?"
        ticket = screen_result.get("matched_ticket_id") or "?"
        outcome_parts.append(
            f"matched pattern={matched}, archetype={archetype}, "
            f"precedent={ticket} — proceeding to REPORT"
        )
    elif screen_result.get("screen_result") == "no_match":
        reason = screen_result.get("reason") or "(no reason given)"
        outcome_parts.append(f"no_match: {reason} — falling through to PREDICT")
    else:  # error
        reason = screen_result.get("reason") or "(no reason given)"
        outcome_parts.append(f"error: {reason} — falling through to PREDICT")
    outcome_line = " | ".join(outcome_parts)

    return (
        f"## SCREEN\n\n"
        f"**Result:** {result_tag}\n"
        f"**Leads run:**\n{leads_lines}\n"
        f"**Outcome:** {outcome_line}\n"
    )


def _extract_gather_yaml_from_parsed(parsed: dict) -> str:
    """Re-serialize the `gather` key from the merged screen subagent's
    parsed dict back to a YAML string (without fence markers) for inlining
    into investigation.md.

    Returns an empty string when `gather` is absent — the handler still
    writes the markdown section but skips the invlang block (consistent
    with the empty-Screen short-circuit).
    """
    gather = parsed.get("gather")
    if not gather:
        return ""
    return yaml.safe_dump({"gather": gather}, sort_keys=False)


# ---------------------------------------------------------------------------
# Validate + append
# ---------------------------------------------------------------------------


def _validate_and_write(ctx: Context, new_section: str) -> None:
    """Append `new_section` to investigation.md after running
    `validate_companion` as a library check."""
    hooks_scripts = str(SOC_AGENT_ROOT / "hooks")
    if hooks_scripts not in sys.path:
        sys.path.insert(0, hooks_scripts)
    from scripts.invlang_validate import validate_companion  # type: ignore

    inv_path = ctx.run_dir / "investigation.md"
    current = inv_path.read_text() if inv_path.exists() else ""
    proposed = current + ("\n" if current and not current.endswith("\n") else "") + new_section

    errors = validate_companion(proposed, current if current else None)
    if errors:
        raise OrchestrationError(
            "SCREEN invlang validation failed:\n" + "\n".join(errors)
        )

    inv_path.write_text(proposed)


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def _match_payload(parsed: dict) -> dict:
    return {
        "screen_result": "match",
        "matched_pattern": parsed.get("matched_pattern"),
        "matched_archetype": parsed.get("matched_archetype"),
        "matched_ticket_id": parsed.get("matched_ticket_id"),
        "disposition": parsed.get("disposition"),
        "confidence": parsed.get("confidence"),
        "leads_run": parsed.get("leads_run") or [],
        "evidence_summary": parsed.get("evidence_summary"),
        # Preserve the invlang gather block so the REPORT handler can
        # compose trust_anchors_consulted mechanically without re-reading
        # investigation.md.
        "gather": parsed.get("gather") or [],
    }


def _fallthrough_payload(parsed: dict, override_reason: Optional[str] = None) -> dict:
    return {
        "screen_result": "error" if override_reason else parsed.get("screen_result"),
        "leads_run": parsed.get("leads_run") or [],
        "evidence_summary": parsed.get("evidence_summary"),
        "reason": override_reason or parsed.get("reason"),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def handle(ctx: Context) -> PhaseResult:
    # Step 0: preflight — empty Screen section short-circuits.
    screen_rows = _load_screen_rows(ctx.signature_id)
    if not screen_rows:
        return PhaseResult(
            next_phase=Phase.PREDICT,
            payload={
                "screen_result": "skipped",
                "reason": "empty_screen_section",
            },
        )

    # Step 1: dispatch the merged screen subagent. Prologue is inlined so the
    # subagent can pick `target: v-*` / `e-*` for each lead without reading
    # investigation.md.
    prologue_yaml = _extract_prologue_yaml(ctx.run_dir)
    screen_prompt = _assemble_screen_prompt(ctx, prologue_yaml)
    screen_raw = _invoke_screen(screen_prompt)
    parsed = _validate_screen_result(extract_terminal_yaml(screen_raw))

    # Step 2: structural verifier on match claim.
    parsed, downgrade_reason = _structural_verify(parsed, screen_rows)
    if downgrade_reason is not None:
        parsed["screen_result"] = "error"
        parsed["reason"] = downgrade_reason
        # Downgrade invalidates the gather block — drop it so we don't write
        # an invlang audit trail claiming a match that the verifier rejected.
        parsed.pop("gather", None)

    # Step 3: compose + validate + append to investigation.md.
    gather_yaml = _extract_gather_yaml_from_parsed(parsed)
    markdown = _compose_markdown(parsed, downgrade_reason)
    new_section = markdown
    if gather_yaml:
        new_section = markdown + "\n```yaml\n" + gather_yaml + "```\n"
    _validate_and_write(ctx, new_section)

    # Step 4: route.
    if parsed.get("screen_result") == "match" and downgrade_reason is None:
        return PhaseResult(
            next_phase=Phase.REPORT, payload=_match_payload(parsed),
        )
    return PhaseResult(
        next_phase=Phase.PREDICT,
        payload=_fallthrough_payload(parsed, downgrade_reason),
    )
