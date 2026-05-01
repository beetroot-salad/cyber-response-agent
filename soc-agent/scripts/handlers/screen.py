"""SCREEN phase handler.

Replaces the SCREEN section of `skills/investigate/SKILL.md` with a Python
orchestration that dispatches one merged Sonnet subagent (`screen`). The
subagent emits a single terminal YAML block carrying both the pattern-match
verdict and the invlang `findings:` transcription — replacing the previous
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
    fenced `findings:` YAML. Append is pre-validated via
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

from scripts.handlers._investigation_io import append_and_validate
from scripts.handlers._markdown import iter_companion_dicts
from scripts.handlers._playbook import load_screen_rows
from scripts.handlers._screen_dense import emit_screen_findings_dense
from scripts.handlers._subagent import (
    extract_terminal_yaml,
    make_invoker,
)


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_SCREEN_TIMEOUT_SECONDS", "300")
)


# ---------------------------------------------------------------------------
# Subagent invocation (mockable)
# ---------------------------------------------------------------------------


_invoke_screen = make_invoker("screen", default_timeout=SUBAGENT_TIMEOUT_SECONDS)


# ---------------------------------------------------------------------------
# Playbook Screen table parsing
# ---------------------------------------------------------------------------


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
    """Return the prologue block from `investigation.md` as a YAML string.

    Walks both ```yaml and ```invlang fences so the SCREEN handler can run
    against the post-foundation on-disk surface. The screen subagent prompt
    still embeds YAML, so the parsed prologue is re-serialized.

    Raises OrchestrationError if `investigation.md` is missing or has no
    prologue — the SCREEN handler cannot run before CONTEXTUALIZE has written
    one.
    """
    inv_path = run_dir / "investigation.md"
    if not inv_path.exists():
        raise OrchestrationError(
            f"investigation.md not found at {inv_path}; CONTEXTUALIZE must run first"
        )
    for parsed in iter_companion_dicts(inv_path.read_text()):
        prologue = parsed.get("prologue")
        if isinstance(prologue, dict):
            return yaml.safe_dump({"prologue": prologue}, sort_keys=False)
    raise OrchestrationError(
        f"investigation.md at {inv_path} has no prologue block"
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


def _extract_findings_dense_from_parsed(parsed: dict) -> str:
    """Render the merged screen subagent's `findings` list as a dense
    invlang block body (no fence markers) for inlining into investigation.md.

    Returns an empty string when `findings` is absent — the handler still
    writes the markdown section but skips the invlang block (consistent
    with the empty-Screen short-circuit).
    """
    findings = parsed.get("findings")
    if not findings:
        return ""
    return emit_screen_findings_dense(findings)


# ---------------------------------------------------------------------------
# Validate + append
# ---------------------------------------------------------------------------


def _validate_and_write(ctx: Context, new_section: str) -> None:
    append_and_validate(ctx.run_dir, new_section, phase="SCREEN")


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
        # Preserve the invlang findings block so the REPORT handler can
        # compose trust_anchors_consulted mechanically without re-reading
        # investigation.md.
        "findings": parsed.get("findings") or [],
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
    screen_rows = load_screen_rows(ctx.signature_id)
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
        # Downgrade invalidates the findings block — drop it so we don't write
        # an invlang audit trail claiming a match that the verifier rejected.
        parsed.pop("findings", None)

    # Step 3: compose + validate + append to investigation.md.
    findings_dense = _extract_findings_dense_from_parsed(parsed)
    markdown = _compose_markdown(parsed, downgrade_reason)
    new_section = markdown
    if findings_dense:
        new_section = markdown + "\n```invlang\n" + findings_dense + "\n```\n"
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
