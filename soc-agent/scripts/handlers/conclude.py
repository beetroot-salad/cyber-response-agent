"""CONCLUDE phase handler.

Three-level compose gradient:

  **Level 1 — mechanical, fully grounded.** SCREEN match with all grounding
    satisfied (required_anchors confirmed, OR precedent file present).
    `status: resolved`, disposition + confidence from SCREEN. No LLM call.

  **Level 2 — mechanical, partial grounding.** SCREEN match but grounding
    incomplete (anchor unconfirmed, precedent missing, etc.). Status flipped
    to `escalated`, disposition preserved from SCREEN, confidence clamped to
    `medium`. No LLM call. Termination rationale names which leg failed.

  **Level 3 — subagent fallback.** Used when mechanical composition cannot
    proceed (archetype directory missing, Tier-1 validation fails on the
    mechanical output, or the SCREEN payload is not match-shaped).
    Dispatches the `conclude` subagent. Any partial mechanical writes are
    rolled back before fallback so the subagent starts from a clean state.

  Also handles: analyze-routed + forced-exhaustion (both always Level 3).

Payload carries `compose_mode` for telemetry:
  `screen_mechanical_grounded` (L1) | `screen_mechanical_partial` (L2) | `subagent` (L3).

Input:
    ctx.ticket_id                               — resolved at Context construction
    ctx.forced_conclude                         — true on MAX_LOOPS path
    ctx.outputs[Phase.ANALYZE]  OR
    ctx.outputs[Phase.SCREEN]

Output:
    PhaseResult(
        next_phase=Phase.CONCLUDE,  # terminal; orchestrator returns summary
        payload={
            "status": "written" | "gate_failed" | "error",
            "report_path": "...",              # on written
            "disposition": "...",              # on written
            "confidence": "...",               # on written
            "matched_archetype": "..." | None, # on written
            "status_frontmatter": "...",       # on written
            "compose_mode": "screen_mechanical" | "subagent",  # telemetry
            "failure": {...},                  # on gate_failed
            "reason": "...",                   # on error
        },
    )
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._context_loader import (
    format_alert_block,
    format_archetype_shapes_block,
    format_investigation_block,
    load_alert,
    load_archetype_shapes,
    load_investigation_md,
)
from scripts.handlers._subagent import (
    extract_terminal_yaml,
    invoke_subagent as _shared_invoke,
)


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_MODEL = os.environ.get("SOC_AGENT_CONCLUDE_MODEL", "haiku")
SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_CONCLUDE_TIMEOUT_SECONDS", "300")
)


def _invoke_subagent(prompt: str, *, timeout: int = SUBAGENT_TIMEOUT_SECONDS) -> str:
    """Thin per-handler binding over the shared wrapper.

    Kept as a module-level function so tests can monkeypatch it with
    `monkeypatch.setattr(conclude_handler, "_invoke_subagent", stub)`.
    """
    return _shared_invoke("conclude", prompt, timeout=timeout)


_VALID_STATUSES = {"written", "gate_failed", "error"}


def _select_routing_source(ctx: Context) -> tuple[str, bool]:
    """Return (routing_source, forced_exhaustion).

    forced_exhaustion is True when the orchestrator reached CONCLUDE via the
    MAX_LOOPS path (`ctx.forced_conclude`). Otherwise the routing source is
    whichever upstream phase routed here:
    - ANALYZE present → analyze
    - SCREEN present → screen

    Dedup fast-path (CONTEXTUALIZE→CONCLUDE on dedup_candidate) is retired —
    see handlers/contextualize.py module docstring + tasks/dedup-fast-path.md.
    """
    if ctx.forced_conclude:
        return "forced_exhaustion", True
    if Phase.ANALYZE in ctx.outputs:
        return "analyze", False
    if Phase.SCREEN in ctx.outputs:
        return "screen", False
    return "forced_exhaustion", True


def _assemble_prompt(ctx: Context) -> str:
    """Build the conclude subagent prompt with all deterministic context inline.

    The subagent receives alert.json, investigation.md, and every archetype's
    story.md + trust-anchors.md + precedent snapshots preloaded — no Read/Glob
    tool calls required. On the forced-exhaustion path archetype shapes are
    omitted (the subagent is instructed to emit `matched_archetype: null`
    regardless of investigation state, so carrying archetypes wastes tokens).

    The subagent's remaining job: pick `matched_ticket_id` from the inlined
    precedents, synthesize report.md's narrative prose, and emit the terminal
    YAML status block.
    """
    if not ctx.ticket_id:
        raise OrchestrationError(
            "CONCLUDE handler: ctx.ticket_id is empty — must be set at Context "
            "construction by the /investigate entrypoint"
        )
    routing_source, forced = _select_routing_source(ctx)
    header_lines = [
        f"run_dir={ctx.run_dir}",
        f"signature_id={ctx.signature_id}",
        f"identifier={ctx.ticket_id}",
        f"routing_source={routing_source}",
    ]
    if forced:
        header_lines.append("forced_exhaustion=true")

    alert = load_alert(ctx.run_dir)
    investigation_md = load_investigation_md(ctx.run_dir)

    blocks = [
        "\n".join(header_lines),
        format_alert_block(alert),
        format_investigation_block(investigation_md),
    ]

    # Forced-exhaustion is archetype-null by contract — skip archetype load.
    if not forced:
        shapes = load_archetype_shapes(
            ctx.signature_id, SOC_AGENT_ROOT, include_precedents=True,
        )
        blocks.append(format_archetype_shapes_block(shapes, with_precedents=True))

    return "\n\n".join(blocks)


def _validate_status(parsed: dict) -> dict:
    status = parsed.get("status")
    if status not in _VALID_STATUSES:
        raise OrchestrationError(
            f"conclude subagent returned unknown status {status!r}; "
            f"expected one of {sorted(_VALID_STATUSES)}"
        )
    return parsed


class _MechanicalFallback(Exception):
    """Raised by the mechanical composer when it can't produce a valid report
    and wants the handler to fall through to the conclude subagent. Carries
    a reason string for telemetry. Any partial writes have already been
    rolled back when this is raised."""


def handle(ctx: Context) -> PhaseResult:
    screen_payload = ctx.outputs.get(Phase.SCREEN) or {}
    fallback_reason: str | None = None
    if (
        not ctx.forced_conclude
        and screen_payload.get("screen_result") == "match"
        and screen_payload.get("matched_archetype")
        and screen_payload.get("gather")
    ):
        try:
            payload = _compose_screen_match(ctx, screen_payload)
            return PhaseResult(next_phase=Phase.CONCLUDE, payload=payload)
        except _MechanicalFallback as exc:
            fallback_reason = str(exc)

    prompt = _assemble_prompt(ctx)
    raw = _invoke_subagent(prompt)
    payload = _validate_status(extract_terminal_yaml(raw))
    payload["compose_mode"] = "subagent"
    if fallback_reason:
        payload["mechanical_fallback_reason"] = fallback_reason
    return PhaseResult(next_phase=Phase.CONCLUDE, payload=payload)


# ---------------------------------------------------------------------------
# Mechanical CONCLUDE composer (SCREEN-match fast-path)
# ---------------------------------------------------------------------------


def _compose_screen_match(ctx: Context, screen_payload: dict) -> dict:
    """Compose the CONCLUDE artifacts mechanically from the SCREEN payload.

    Returns the handler payload on success. Raises `_MechanicalFallback`
    when mechanical composition cannot produce a valid report (Level 3);
    any partial writes are rolled back before raising so the caller can
    dispatch the subagent cleanly.

    Level selection:
      Level 1 (grounded)  — archetype resolves on disk AND
                            (required_anchors fully confirmed OR precedent file exists).
                            status=resolved, disposition+confidence from SCREEN.
      Level 2 (partial)   — archetype resolves but grounding incomplete.
                            status=escalated, disposition preserved from SCREEN,
                            confidence clamped to medium. Rationale names the gap.
      Level 3 (fallback)  — archetype missing, or Tier-1 validation rejects
                            the mechanical output (indicates a schema bug).

    Writes to disk (only after all invariants decided):
      - {run_dir}/investigation.md — appends ## CONCLUDE + conclude: YAML
      - {run_dir}/report.md        — full frontmatter + body
    Runs `validate_tier1(report_path)` post-write. On validation failure,
    rolls both writes back and raises `_MechanicalFallback`.
    """
    archetype = screen_payload["matched_archetype"]
    disposition = screen_payload.get("disposition") or "benign"
    screen_confidence = screen_payload.get("confidence") or "high"
    evidence_summary = screen_payload.get("evidence_summary") or ""
    leads_run = screen_payload.get("leads_run") or []
    gather = screen_payload.get("gather") or []
    matched_pattern = screen_payload.get("matched_pattern") or archetype

    archetype_dir = (
        SOC_AGENT_ROOT
        / "knowledge" / "signatures" / ctx.signature_id
        / "archetypes" / archetype
    )
    if not archetype_dir.exists():
        raise _MechanicalFallback(
            f"archetype dir missing: {archetype_dir} (matched_archetype={archetype!r})"
        )

    required_anchors = _load_required_anchors(archetype_dir)
    matched_ticket_id = screen_payload.get("matched_ticket_id")
    precedent_path = (
        archetype_dir / f"{matched_ticket_id}.json" if matched_ticket_id else None
    )
    precedent_missing = bool(matched_ticket_id) and not (precedent_path and precedent_path.exists())
    if precedent_missing:
        matched_ticket_id = None  # drop from frontmatter; note in rationale

    trust_anchors = _derive_trust_anchors(gather)
    confirmed_anchor_ids = {
        ta["anchor"] for ta in trust_anchors if ta.get("result") == "confirmed"
    }
    missing_anchors = [a for a in required_anchors if a not in confirmed_anchor_ids]

    anchor_leg_grounded = bool(required_anchors) and not missing_anchors
    precedent_leg_grounded = bool(matched_ticket_id)

    # Level selection.
    if anchor_leg_grounded or precedent_leg_grounded:
        compose_mode = "screen_mechanical_grounded"
        status = "resolved"
        confidence = screen_confidence
        termination_category = "trust-root"
        rationale_parts = [
            f"SCREEN fast-path matched {matched_pattern}",
        ]
        if anchor_leg_grounded:
            rationale_parts.append(
                f"confirmed {len(confirmed_anchor_ids)}/{len(required_anchors)} required anchor(s)"
            )
        if precedent_leg_grounded:
            rationale_parts.append(f"cited precedent {screen_payload.get('matched_ticket_id')}")
    else:
        compose_mode = "screen_mechanical_partial"
        status = "escalated"
        # Preserve SCREEN's disposition — we still believe the mechanism call,
        # we just can't ground it. Downgrade confidence to medium so the
        # analyst sees mechanical-without-grounding signal.
        confidence = "medium"
        termination_category = "exhaustion-escalation"
        gap_notes = []
        if missing_anchors:
            gap_notes.append(f"required anchors unconfirmed: {missing_anchors}")
        if precedent_missing:
            gap_notes.append(
                f"precedent '{screen_payload.get('matched_ticket_id')}' not found under "
                f"{archetype_dir.name}/"
            )
        if not required_anchors and not screen_payload.get("matched_ticket_id"):
            gap_notes.append(
                f"archetype '{archetype}' declares no required_anchors and SCREEN "
                f"named no precedent — no grounding leg available"
            )
        rationale_parts = [
            f"SCREEN matched {matched_pattern} but grounding incomplete",
            *gap_notes,
        ]

    trace = _compose_trace(matched_pattern, leads_run, disposition)
    summary = evidence_summary or (
        f"SCREEN matched {archetype} via {matched_pattern}; "
        f"grounded by {len(trust_anchors)} anchor(s)."
    )

    conclude_yaml_block = {
        "conclude": {
            "termination": {
                "category": termination_category,
                "rationale": "; ".join(rationale_parts) + ".",
            },
            "disposition": disposition,
            "confidence": confidence,
            "matched_archetype": archetype,
            "summary": summary,
        }
    }
    conclude_yaml_text = yaml.safe_dump(conclude_yaml_block, sort_keys=False).rstrip()

    md_lines = [
        "## CONCLUDE",
        "",
        f"**Verdict:** {status} / {disposition} / {confidence}",
        f"**Confirmed hypothesis:** ?{archetype} via SCREEN fast-path",
        f"**Trace:** {trace}",
        "",
        "```yaml",
        conclude_yaml_text,
        "```",
        "",
    ]

    report_text = _compose_report_md(
        ctx=ctx,
        status=status,
        disposition=disposition,
        confidence=confidence,
        matched_archetype=archetype,
        matched_ticket_id=matched_ticket_id,
        trust_anchors=trust_anchors,
        leads_run=leads_run,
        trace=trace,
        summary=summary,
        matched_pattern=matched_pattern,
    )

    # Snapshot for rollback: Tier-1 can still reject a mechanically-composed
    # report if a schema assumption is violated. We want the subagent fallback
    # to see a clean run dir, so capture pre-write state before touching disk.
    inv_path = ctx.run_dir / "investigation.md"
    report_path = ctx.run_dir / "report.md"
    inv_before = inv_path.read_text() if inv_path.exists() else None

    _append_to_investigation(ctx.run_dir, "\n".join(md_lines))
    report_path.write_text(report_text)

    try:
        _run_tier1_validation(report_path)
    except OrchestrationError as exc:
        # Rollback both writes so the subagent starts from a clean state.
        if inv_before is None:
            inv_path.unlink(missing_ok=True)
        else:
            inv_path.write_text(inv_before)
        report_path.unlink(missing_ok=True)
        raise _MechanicalFallback(
            f"Tier-1 validation rejected mechanical report: {exc}"
        ) from None

    return {
        "status": "written",
        "report_path": str(report_path),
        "disposition": disposition,
        "confidence": confidence,
        "matched_archetype": archetype,
        "matched_ticket_id": matched_ticket_id,
        "status_frontmatter": status,
        "compose_mode": compose_mode,
    }


def _load_required_anchors(archetype_dir: Path) -> list[str]:
    trust_anchors_path = archetype_dir / "trust-anchors.md"
    if not trust_anchors_path.exists():
        return []
    hooks_dir = str(SOC_AGENT_ROOT / "hooks")
    if hooks_dir not in sys.path:
        sys.path.insert(0, hooks_dir)
    from scripts.frontmatter import parse_yaml_frontmatter  # type: ignore

    fm = parse_yaml_frontmatter(trust_anchors_path.read_text())
    required = fm.get("required_anchors") or []
    return [str(r) for r in required if r]


def _derive_trust_anchors(gather: list[dict]) -> list[dict]:
    """Extract trust_anchors_consulted records from the invlang gather block.

    Each gather lead whose `outcome.trust_anchor_result` is set becomes one
    `{anchor, kind, result, citation}` entry. Citation is the lead's
    observation when the outer SCREEN payload provides it; we synthesize a
    short description otherwise.
    """
    out: list[dict] = []
    for lead in gather:
        outcome = (lead or {}).get("outcome") or {}
        tar = outcome.get("trust_anchor_result")
        if not tar:
            continue
        out.append({
            "anchor": tar.get("anchor_id") or lead.get("name"),
            "kind": tar.get("kind") or "org-authority",
            "result": tar.get("result") or "unavailable",
            "citation": (
                f"{lead.get('name')}: verdict={tar.get('verdict','?')}, "
                f"as_of={tar.get('as_of','?')}"
            ),
        })
    return out


def _compose_trace(matched_pattern: str, leads_run: list[dict], disposition: str) -> str:
    lead_names = [
        (entry or {}).get("lead", "?") for entry in leads_run
    ]
    if lead_names:
        return f"screen({matched_pattern}, [{', '.join(lead_names)}]) → disposition:{disposition}"
    return f"screen({matched_pattern}) → disposition:{disposition}"


def _append_to_investigation(run_dir: Path, new_section: str) -> None:
    inv_path = run_dir / "investigation.md"
    current = inv_path.read_text() if inv_path.exists() else ""
    sep = "\n" if current and not current.endswith("\n") else ""
    inv_path.write_text(current + sep + new_section)


def _run_tier1_validation(report_path: Path) -> None:
    """Library-mode call of validate_report.validate_tier1.

    Tier 1 is deterministic — same checks a Write PostToolUse hook would run,
    just invoked directly here since we bypassed the subagent. Tier 2
    (Haiku judge) is skipped because the report is mechanically composed
    from verified SCREEN subagent output; there's no model drift to catch.
    """
    hooks_dir = str(SOC_AGENT_ROOT / "hooks")
    if hooks_dir not in sys.path:
        sys.path.insert(0, hooks_dir)
    from scripts.validate_report import validate_tier1  # type: ignore

    passed, errors, _ = validate_tier1(report_path)
    if not passed:
        raise OrchestrationError(
            "mechanical CONCLUDE report failed Tier-1 validation:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


def _compose_report_md(
    *,
    ctx: Context,
    status: str,
    disposition: str,
    confidence: str,
    matched_archetype: str,
    matched_ticket_id: str | None,
    trust_anchors: list[dict],
    leads_run: list[dict],
    trace: str,
    summary: str,
    matched_pattern: str,
) -> str:
    fm = {
        "ticket_id": ctx.ticket_id,
        "signature_id": ctx.signature_id,
        "status": status,
        "disposition": disposition,
        "confidence": confidence,
        "matched_archetype": matched_archetype,
        "matched_ticket_id": matched_ticket_id,
        "trust_anchors_consulted": trust_anchors,
        "leads_pursued": len(leads_run),
        "trace": trace,
    }
    # yaml.safe_dump quotes strings that would otherwise parse as another
    # YAML scalar type (e.g. Wazuh ids like "1776748918.3300232" get single
    # quotes because the dot would make them look like floats).
    frontmatter_yaml = yaml.safe_dump(fm, sort_keys=False).rstrip()

    trace_table_rows = []
    for entry in leads_run:
        lead = (entry or {}).get("lead", "?")
        obs = (entry or {}).get("observation", "")
        trace_table_rows.append(f"| SCREEN | {lead} | {obs} |")
    trace_table = "\n".join(trace_table_rows) if trace_table_rows else "| SCREEN | (no leads recorded) | |"

    evidence_lines = []
    for entry in leads_run:
        lead = (entry or {}).get("lead", "?")
        obs = (entry or {}).get("observation", "")
        evidence_lines.append(f"- **{lead}:** {obs}")
    evidence_block = "\n".join(evidence_lines) if evidence_lines else "- (no leads recorded)"

    precedent_line = (
        f"Precedent: `{matched_ticket_id}`"
        if matched_ticket_id
        else "Precedent: none cited (anchor-leg grounding only)"
    )

    return (
        "---\n"
        + frontmatter_yaml
        + "\n---\n"
        + "\n"
        + "## Summary\n\n"
        + f"{summary}\n\n"
        + f"Fast-path match: `{matched_pattern}` → archetype `{matched_archetype}`. {precedent_line}.\n\n"
        + "## Investigation Trace\n\n"
        + "| Phase | Action | Result |\n"
        + "|-------|--------|--------|\n"
        + trace_table
        + "\n\n"
        + "## Hypothesis Outcomes\n\n"
        + f"- **?{matched_archetype}:** confirmed via SCREEN fast-path — "
        + f"all {len(leads_run)} indicator(s) satisfied.\n\n"
        + "## Key Evidence\n\n"
        + evidence_block
        + "\n\n"
        + "## Verdict\n\n"
        + f"**Status:** {status.capitalize()}  \n"
        + f"**Disposition:** {disposition.capitalize()}  \n"
        + f"**Confidence:** {confidence.capitalize()}  \n"
        + f"**Matched Archetype:** {matched_archetype}  \n\n"
        + ("" if status == "resolved" else
           "## For Analyst\n\n"
           "SCREEN matched a known pattern but grounding requirements for a resolved "
           "status are not fully met. Review the Investigation Trace and confirm "
           "whether anchor confirmation or a precedent cite can be produced manually.\n")
    )
