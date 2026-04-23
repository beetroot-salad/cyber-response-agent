"""REPORT phase handler.

Compose gradient with mechanical fast-paths for both SCREEN-matched and
ANALYZE-routed investigations. LLM dispatch is reserved for (a) authoring the
free-text narrative sections (Summary / For Analyst) on the ANALYZE mechanical
path, and (b) the full-context fallback when mechanical composition cannot
proceed.

SCREEN path:
  **Level 1 — mechanical, fully grounded.** SCREEN match with all grounding
    satisfied (required_anchors confirmed, OR precedent file present).
    `status: resolved`, disposition + confidence from SCREEN. No LLM call.

  **Level 2 — mechanical, partial grounding.** SCREEN match but grounding
    incomplete (anchor unconfirmed, precedent missing, etc.). Status flipped
    to `escalated`, disposition preserved from SCREEN, confidence clamped to
    `medium`. No LLM call. Termination rationale names which leg failed.

ANALYZE path:
  **Mechanical + narrative subagent.** Handler composes every structured
    field (frontmatter, conclude: YAML, Hypothesis Outcomes, Key Evidence,
    Verdict, trace) from the ANALYZE payload + invlang `gather:` blocks in
    investigation.md. A narrow `report_narrative` subagent (Haiku, no
    tools) authors only `## Summary` and optionally `## For Analyst`. Its
    preload is ~5-8 KB (trimmed investigation + optional single archetype)
    vs. ~50 KB for the full-context fallback.

Fallback:
  **Full-context subagent.** Used when mechanical composition cannot
    proceed (archetype directory missing, Tier-1 validation fails on the
    mechanical output, narrative subagent fails to emit the expected tagged
    blocks, SCREEN payload not match-shaped, or forced-exhaustion). Any
    partial mechanical writes are rolled back before fallback so the
    subagent starts from a clean state. Uses agents/report.md.

Payload carries `compose_mode` for telemetry:
  `screen_mechanical_grounded` | `screen_mechanical_partial` |
  `analyze_mechanical` | `subagent`.

Input:
    ctx.ticket_id                               — resolved at Context construction
    ctx.forced_report                         — true on MAX_LOOPS path
    ctx.outputs[Phase.ANALYZE]  OR
    ctx.outputs[Phase.SCREEN]

Output:
    PhaseResult(
        next_phase=Phase.REPORT,  # terminal; orchestrator returns summary
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
    load_run_salt,
)
from scripts.handlers._subagent import (
    extract_terminal_yaml,
    invoke_subagent as _shared_invoke,
)


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_MODEL = os.environ.get("SOC_AGENT_REPORT_MODEL", "haiku")
SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_REPORT_TIMEOUT_SECONDS", "300")
)


def _invoke_subagent(prompt: str, *, timeout: int = SUBAGENT_TIMEOUT_SECONDS) -> str:
    """Thin per-handler binding over the shared wrapper.

    Kept as a module-level function so tests can monkeypatch it with
    `monkeypatch.setattr(report_handler, "_invoke_subagent", stub)`.
    """
    return _shared_invoke("report", prompt, timeout=timeout)


ARCHETYPE_MATCH_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_ARCHETYPE_MATCH_TIMEOUT_SECONDS", "120")
)


def _invoke_archetype_match(prompt: str) -> str:
    """Module-level binding for archetype-match subagent so tests can stub it."""
    return _shared_invoke(
        "archetype-match", prompt, timeout=ARCHETYPE_MATCH_TIMEOUT_SECONDS,
    )


_VALID_STATUSES = {"written", "gate_failed", "error"}


def _select_routing_source(ctx: Context) -> tuple[str, bool]:
    """Return (routing_source, forced_exhaustion).

    forced_exhaustion is True when the orchestrator reached REPORT via the
    MAX_LOOPS path (`ctx.forced_report`). Otherwise the routing source is
    whichever upstream phase routed here:
    - ANALYZE present → analyze
    - SCREEN present → screen

    Dedup fast-path (CONTEXTUALIZE→REPORT on dedup_candidate) is retired —
    see handlers/contextualize.py module docstring + tasks/dedup-fast-path.md.
    """
    if ctx.forced_report:
        return "forced_exhaustion", True
    if Phase.ANALYZE in ctx.outputs:
        return "analyze", False
    if Phase.SCREEN in ctx.outputs:
        return "screen", False
    return "forced_exhaustion", True


def _assemble_prompt(ctx: Context, *, matched_archetype: str | None = None) -> str:
    """Build the report subagent prompt with all deterministic context inline.

    The subagent receives alert.json, investigation.md, and every archetype's
    story.md + trust-anchors.md + precedent snapshots preloaded — no Read/Glob
    tool calls required. On the forced-exhaustion path archetype shapes are
    omitted (the subagent is instructed to emit `matched_archetype: null`
    regardless of investigation state, so carrying archetypes wastes tokens).

    `matched_archetype` is the already-resolved archetype label (from the
    handler's earlier `archetype-match` dispatch on the analyze path, from
    the SCREEN payload on the screen path, or `None` on forced-exhaustion).
    It is passed as a caller input rather than re-derived by the subagent
    because ANALYZE no longer carries the field.

    The subagent's remaining job: pick `matched_ticket_id` from the inlined
    precedents, synthesize report.md's narrative prose, and emit the terminal
    YAML status block.
    """
    if not ctx.ticket_id:
        raise OrchestrationError(
            "REPORT handler: ctx.ticket_id is empty — must be set at Context "
            "construction by the /investigate entrypoint"
        )
    routing_source, forced = _select_routing_source(ctx)
    archetype_input = matched_archetype if matched_archetype else "null"
    header_lines = [
        f"run_dir={ctx.run_dir}",
        f"signature_id={ctx.signature_id}",
        f"identifier={ctx.ticket_id}",
        f"routing_source={routing_source}",
        f"matched_archetype={archetype_input}",
    ]
    if forced:
        header_lines.append("forced_exhaustion=true")

    alert = load_alert(ctx.run_dir)
    salt = load_run_salt(ctx.run_dir)
    investigation_md = load_investigation_md(ctx.run_dir)

    blocks = [
        "\n".join(header_lines),
        format_alert_block(alert, salt),
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
            f"report subagent returned unknown status {status!r}; "
            f"expected one of {sorted(_VALID_STATUSES)}"
        )
    return parsed


class _MechanicalFallback(Exception):
    """Raised by the mechanical composer when it can't produce a valid report
    and wants the handler to fall through to the report subagent. Carries
    a reason string for telemetry. Any partial writes have already been
    rolled back when this is raised."""


def _resolve_matched_archetype(
    ctx: Context,
    *,
    analyze_payload: dict,
    screen_payload: dict,
) -> tuple[str | None, str | None]:
    """Resolve the archetype label authoritatively at REPORT-time.

    Called once in `handle()` and threaded into every downstream
    composition path (mechanical SCREEN uses its own payload archetype
    instead; mechanical ANALYZE and the fallback subagent both receive
    this value as caller input).

    Returns `(matched_archetype, dispatch_failure_reason)`. When
    `dispatch_failure_reason` is non-None, archetype-match could not
    be invoked — operator should investigate. A legitimate null match
    (the catalog doesn't cover this outcome) returns `(None, None)`.
    """
    if ctx.forced_report:
        return None, None

    # SCREEN fast-path already names the archetype; don't re-run matcher.
    if (
        screen_payload.get("screen_result") == "match"
        and screen_payload.get("matched_archetype")
    ):
        return screen_payload["matched_archetype"], None

    if not (analyze_payload and analyze_payload.get("disposition")):
        return None, None

    raw_disposition = analyze_payload.get("disposition")
    disposition = "inconclusive" if raw_disposition == "escalated" else raw_disposition
    confidence = analyze_payload.get("confidence") or "low"
    surviving_hypotheses = analyze_payload.get("surviving_hypotheses") or []

    investigation_md = load_investigation_md(ctx.run_dir)
    gather = _extract_gather_blocks(investigation_md)
    trust_anchors = _derive_trust_anchors(gather)

    matched, _reason, dispatch_failed = _run_archetype_match(
        ctx,
        disposition=disposition,
        confidence=confidence,
        mechanism_summary=_derive_mechanism_summary(
            surviving_hypotheses, analyze_payload,
        ),
        legitimacy_verdicts=_derive_legitimacy_verdicts(gather),
        trust_anchors_confirmed=[
            (a.get("anchor") or "") for a in trust_anchors
            if a.get("result") == "confirmed"
        ],
    )
    return matched, (_reason if dispatch_failed else None)


def handle(ctx: Context) -> PhaseResult:
    screen_payload = ctx.outputs.get(Phase.SCREEN) or {}
    analyze_payload = ctx.outputs.get(Phase.ANALYZE) or {}
    fallback_reason: str | None = None

    # Resolve the archetype label once up-front. All three downstream
    # paths (mechanical SCREEN, mechanical ANALYZE, fallback subagent)
    # consume this value — keeps the contract uniform and ensures the
    # fallback subagent doesn't try to re-derive archetype from an
    # ANALYZE block that no longer carries it.
    matched_archetype, archetype_dispatch_failure = _resolve_matched_archetype(
        ctx,
        analyze_payload=analyze_payload,
        screen_payload=screen_payload,
    )

    if (
        not ctx.forced_report
        and screen_payload.get("screen_result") == "match"
        and screen_payload.get("matched_archetype")
        and screen_payload.get("gather")
    ):
        try:
            payload = _compose_screen_match(ctx, screen_payload)
            _annotate_archetype_failure(payload, archetype_dispatch_failure)
            return PhaseResult(next_phase=Phase.REPORT, payload=payload)
        except _MechanicalFallback as exc:
            fallback_reason = str(exc)

    # ANALYZE-routed mechanical path: handler composes every structured field;
    # dispatches the narrative subagent only for Summary / For Analyst prose.
    # Gated on a non-empty ANALYZE payload; forced-exhaustion skips this path
    # (ANALYZE never ran).
    if (
        fallback_reason is None
        and not ctx.forced_report
        and analyze_payload
        and analyze_payload.get("disposition")
    ):
        try:
            payload = _compose_analyze_routed(
                ctx, analyze_payload, matched_archetype=matched_archetype,
            )
            _annotate_archetype_failure(payload, archetype_dispatch_failure)
            return PhaseResult(next_phase=Phase.REPORT, payload=payload)
        except _MechanicalFallback as exc:
            fallback_reason = str(exc)

    prompt = _assemble_prompt(ctx, matched_archetype=matched_archetype)
    raw = _invoke_subagent(prompt)
    payload = _validate_status(extract_terminal_yaml(raw))
    payload["compose_mode"] = "subagent"
    if fallback_reason:
        payload["mechanical_fallback_reason"] = fallback_reason
    _annotate_archetype_failure(payload, archetype_dispatch_failure)
    return PhaseResult(next_phase=Phase.REPORT, payload=payload)


def _annotate_archetype_failure(payload: dict, failure_reason: str | None) -> None:
    """Surface archetype-match dispatch failures on the result payload.

    A legitimate null match is silent; only subprocess/parse failures
    are flagged so operators can triage why a report landed unlabeled.
    """
    if failure_reason:
        payload["archetype_match_failure_reason"] = failure_reason


# ---------------------------------------------------------------------------
# Mechanical REPORT composer (SCREEN-match fast-path)
# ---------------------------------------------------------------------------


def _compose_screen_match(ctx: Context, screen_payload: dict) -> dict:
    """Compose the REPORT artifacts mechanically from the SCREEN payload.

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
      - {run_dir}/investigation.md — appends ## REPORT + conclude: YAML
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
        "## REPORT",
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

    report_text = _compose_report_md_screen(
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


def _derive_legitimacy_verdicts(gather: list[dict]) -> list[dict]:
    """Pull `legitimacy_resolutions[]` entries from every gather outcome.

    Each entry becomes `{contract, result}` — the shape archetype-match expects
    in its `legitimacy_verdicts` input.
    """
    out: list[dict] = []
    for lead in gather:
        outcome = (lead or {}).get("outcome") or {}
        resolutions = outcome.get("legitimacy_resolutions") or []
        for r in resolutions:
            contract = r.get("contract")
            result = r.get("result")
            if contract and result:
                out.append({"contract": contract, "result": result})
    return out


def _archetype_story_paths(signature_id: str) -> list[Path]:
    """List every `story.md` path under this signature's archetype catalog."""
    base = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "archetypes"
    )
    if not base.is_dir():
        return []
    return sorted(
        d / "story.md" for d in base.iterdir()
        if d.is_dir() and (d / "story.md").exists()
    )


def _derive_mechanism_summary(
    surviving_hypotheses: list[str],
    analyze_payload: dict,
) -> str:
    """One-line mechanism description for archetype-match input.

    Prefer ANALYZE's own `rationale` field if present; otherwise stitch the
    surviving-hypothesis IDs together.
    """
    rationale = (analyze_payload.get("rationale") or "").strip()
    if rationale:
        return rationale.splitlines()[0][:200]
    if surviving_hypotheses:
        return "surviving: " + ", ".join(surviving_hypotheses)
    return "all hypotheses refuted"


def _run_archetype_match(
    ctx: Context,
    *,
    disposition: str,
    confidence: str,
    mechanism_summary: str,
    legitimacy_verdicts: list[dict],
    trust_anchors_confirmed: list[str],
) -> tuple[str | None, str, bool]:
    """Dispatch archetype-match and parse its terminal YAML.

    Returns `(matched_archetype, reason, dispatch_failed)`:
      - `matched_archetype` is the archetype name, or `None` (both for
        "no archetype fits" and for dispatch/parse failures).
      - `reason` is the subagent's justification on a clean match/null,
        or the failure description on dispatch/parse errors.
      - `dispatch_failed` is `True` when the subagent couldn't be invoked
        or its output couldn't be parsed — distinguishes operator-visible
        failures from legitimate null-match outcomes. Missing catalogs
        are treated as legitimate (dispatch_failed=False) because some
        signatures ship without archetypes by design.
    """
    story_paths = _archetype_story_paths(ctx.signature_id)
    if not story_paths:
        return None, "no archetype catalog for this signature", False

    alert_path = ctx.run_dir / "alert.json"
    field_quirks_path = (
        SOC_AGENT_ROOT / "knowledge" / "signatures"
        / ctx.signature_id / "field-quirks.md"
    )
    prompt_lines = [
        f"alert_path={alert_path}",
        f"field_quirks_path={field_quirks_path}",
        f"story_paths={','.join(str(p) for p in story_paths)}",
        f"disposition={disposition}",
        f"confidence={confidence}",
        f"mechanism_summary={mechanism_summary}",
        "legitimacy_verdicts:",
    ]
    if legitimacy_verdicts:
        for v in legitimacy_verdicts:
            prompt_lines.append(f"  - contract: {v['contract']}")
            prompt_lines.append(f"    result: {v['result']}")
    else:
        prompt_lines[-1] = "legitimacy_verdicts: []"
    if trust_anchors_confirmed:
        prompt_lines.append("trust_anchors_confirmed:")
        for a in trust_anchors_confirmed:
            prompt_lines.append(f"  - {a}")
    else:
        prompt_lines.append("trust_anchors_confirmed: []")

    prompt = "\n".join(prompt_lines)
    try:
        raw = _invoke_archetype_match(prompt)
    except OrchestrationError as exc:
        return None, f"archetype-match dispatch failed: {exc}", True
    try:
        parsed = extract_terminal_yaml(raw)
    except Exception as exc:
        return None, f"archetype-match YAML parse failed: {exc}", True
    matched = parsed.get("matched_archetype")
    justification = parsed.get("justification", "")
    if isinstance(matched, str) and matched.strip() and matched != "null":
        return matched.strip(), justification, False
    return None, justification or "archetype-match returned null", False


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
            "mechanical REPORT report failed Tier-1 validation:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


def _compose_report_md_screen(
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


# ---------------------------------------------------------------------------
# Mechanical REPORT composer (ANALYZE-routed path)
# ---------------------------------------------------------------------------


def _extract_gather_blocks(investigation_md: str) -> list[dict]:
    """Extract gather lead entries from investigation.md.

    Preference order:
      1. Invlang `gather: [...]` YAML fences (structured form — carries
         full outcome shape including trust_anchor_result, resolutions,
         attribute_updates).
      2. Prose-form `## GATHER (loop N)` sections with `**Lead:**` /
         `**Status:**` bold-prefix lines (what ANALYZE currently produces).
         Yields `{name, status, loop}` entries — enough for lead counts
         and trace composition, but no structured outcome fields.

    Returns an empty list if neither form is present.
    """
    from scripts.handlers._markdown import iter_yaml_fences  # local import

    merged: list[dict] = []
    for body in iter_yaml_fences(investigation_md):
        try:
            parsed = yaml.safe_load(body)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        gather = parsed.get("gather")
        if not isinstance(gather, list):
            continue
        for entry in gather:
            if isinstance(entry, dict):
                merged.append(entry)
    if merged:
        return merged

    # Fallback: parse prose-form GATHER sections.
    return _extract_gather_blocks_prose(investigation_md)


_GATHER_HEADER_RE = None
_LEAD_FIELD_RE = None


def _extract_gather_blocks_prose(investigation_md: str) -> list[dict]:
    """Parse prose-form `## GATHER (loop N)` sections into lead entries.

    Each GATHER section is assumed to have a `**Lead:** <name>` line and
    optional `**Status:** <status>` line. Multiple Lead entries within a
    single GATHER (composite dispatch) are each returned as separate
    entries.
    """
    import re  # local
    global _GATHER_HEADER_RE, _LEAD_FIELD_RE
    if _GATHER_HEADER_RE is None:
        _GATHER_HEADER_RE = re.compile(
            r"^## GATHER(?:\s*\(loop\s*(\d+)\))?\s*$", re.MULTILINE,
        )
        _LEAD_FIELD_RE = re.compile(
            r"^\*\*(?P<key>Lead|Status|Query):\*\*\s*(?P<value>.+?)\s*$",
            re.MULTILINE,
        )

    entries: list[dict] = []
    lines = investigation_md.splitlines()
    in_fence = False
    # Collect (start_line, loop_n, end_line) for each GATHER section.
    section_ranges: list[tuple[int, int | None, int]] = []
    cur_start: int | None = None
    cur_loop: int | None = None
    for i, line in enumerate(lines):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.startswith("## "):
            if cur_start is not None:
                section_ranges.append((cur_start, cur_loop, i))
                cur_start = None
                cur_loop = None
            m = _GATHER_HEADER_RE.match(line)
            if m:
                cur_start = i
                cur_loop = int(m.group(1)) if m.group(1) else None
    if cur_start is not None:
        section_ranges.append((cur_start, cur_loop, len(lines)))

    for start, loop, end in section_ranges:
        body = "\n".join(lines[start + 1:end])
        current: dict | None = None
        for fm in _LEAD_FIELD_RE.finditer(body):
            key = fm.group("key")
            value = fm.group("value").strip()
            if key == "Lead":
                if current is not None:
                    entries.append(current)
                current = {"name": value, "loop": loop}
            elif current is not None:
                current[key.lower()] = value
        if current is not None:
            entries.append(current)
    return entries


def _extract_final_analyze_section(investigation_md: str) -> str:
    """Return the raw markdown text of the final `## ANALYZE (loop N)`
    section, header line included. Returns empty string if no ANALYZE
    section is present. Fence-aware (a `## ` line inside a code block is
    not a section boundary).
    """
    lines = investigation_md.splitlines()
    in_fence = False
    section_starts: list[int] = []
    next_section_after: dict[int, int] = {}
    for i, line in enumerate(lines):
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if line.startswith("## "):
            for s in section_starts:
                if s not in next_section_after:
                    next_section_after[s] = i
            header = line[3:].strip().lower()
            if header.startswith("analyze"):
                section_starts.append(i)
    if not section_starts:
        return ""
    last = section_starts[-1]
    end = next_section_after.get(last, len(lines))
    return "\n".join(lines[last:end]).rstrip()


def _compose_trace_analyze(
    gather: list[dict],
    disposition: str,
    surviving_hypotheses: list[str] | None,
    matched_archetype: str | None,
) -> str:
    """Build the trace line for an ANALYZE-routed investigation:

        lead1(outcome) -> lead2(outcome) -> ... -> disposition:{tail}

    `tail` is `matched_archetype` if set, else the first surviving
    hypothesis, else the disposition itself (so "escalated" still lands).
    """
    parts: list[str] = []
    for entry in gather:
        name = entry.get("name") or entry.get("id") or "?"
        outcome_obj = entry.get("outcome") or {}
        tar = outcome_obj.get("trust_anchor_result")
        if isinstance(tar, dict) and tar.get("verdict"):
            summary = str(tar.get("verdict"))
        elif isinstance(tar, dict) and tar.get("result"):
            summary = str(tar.get("result"))
        elif outcome_obj.get("resolutions"):
            res = outcome_obj["resolutions"]
            if isinstance(res, list) and res:
                first = res[0] if isinstance(res[0], dict) else {}
                summary = str(first.get("weight") or "resolved")
            else:
                summary = "resolved"
        elif outcome_obj.get("attribute_updates"):
            summary = "classified"
        else:
            summary = "observed"
        parts.append(f"{name}({summary})")
    if matched_archetype:
        tail = f"{disposition}:{matched_archetype}"
    elif surviving_hypotheses:
        tail = f"{disposition}:{surviving_hypotheses[0]}"
    else:
        tail = disposition
    if parts:
        return " → ".join(parts) + f" → {tail}"
    return tail


def _derive_termination_category(
    analyze_payload: dict,
    gather: list[dict],
    final_analyze_text: str,
) -> str:
    """Decide `conclude.termination.category` from the available signals.

    Order of precedence:
      1. `trust-root` — a gather lead carries `legitimacy_resolutions[]` with
         at least one entry where `verdict: authorized`, OR a
         `trust_anchor_result` with `verdict: authorized`. An authority
         closed the question.
      2. `adversarial-refuted` — the final ANALYZE text grades an
         adversarial-named hypothesis (`?adversary-*`, `?post-exploit-*`,
         or the word "adversarial") at `--`.
      3. `severity-ceiling` — the final ANALYZE text or an investigation
         narrative mentions a composition rule (`composition rule`,
         `severity ceiling`, `co-fir`), indicating the structural severity
         forces escalation regardless of mechanism.
      4. `exhaustion-escalation` — default.

    This mirrors the discipline in agents/report.md §3 without requiring
    the subagent to author it. Over-triggering `exhaustion-escalation` is
    the safe fallback — escalated dispositions land there.
    """
    for entry in gather:
        outcome = entry.get("outcome") or {}
        tar = outcome.get("trust_anchor_result")
        if isinstance(tar, dict) and tar.get("verdict") == "authorized":
            return "trust-root"
        resolutions = outcome.get("legitimacy_resolutions")
        if isinstance(resolutions, list):
            for r in resolutions:
                if isinstance(r, dict) and r.get("verdict") == "authorized":
                    return "trust-root"

    lower = final_analyze_text.lower()
    # Adversarial-refuted: look for ?adversary-* / ?post-exploit-* /
    # adversarial keyword paired with a `--` grade.
    adversarial_markers = ("?adversary-", "?post-exploit-", "adversarial")
    if any(m in lower for m in adversarial_markers) and "`--`" in final_analyze_text:
        return "adversarial-refuted"

    if (
        "composition rule" in lower
        or "severity ceiling" in lower
        or "co-fir" in lower  # matches "co-fire", "co-firing", "co-fires"
    ):
        return "severity-ceiling"

    return "exhaustion-escalation"


def _compose_hypothesis_outcomes_md(
    gather: list[dict],
    surviving_hypotheses: list[str] | None,
) -> str:
    """Render `## Hypothesis Outcomes` from invlang gather resolutions.

    Walks gather blocks for `outcome.resolutions[]` entries, collecting
    the final weight per hypothesis ID. Output is a bulleted list:

        - **?hypothesis-id (h-NNN):** final-weight — source lead(s).

    If no resolutions are found, falls back to listing surviving
    hypotheses (if any) with status `(live weight)`; if that too is empty,
    emits a neutral `(no hypothesis records found)` placeholder. The
    handler will still pass Tier-1 since the section exists.
    """
    # hypothesis_id -> (latest_weight, lead_names_that_resolved_it)
    resolved: dict[str, tuple[str, list[str]]] = {}
    for entry in gather:
        outcome = entry.get("outcome") or {}
        resolutions = outcome.get("resolutions")
        if not isinstance(resolutions, list):
            continue
        lead_name = entry.get("name") or entry.get("id") or "?"
        for r in resolutions:
            if not isinstance(r, dict):
                continue
            hyp = r.get("hypothesis") or r.get("hypothesis_id")
            weight = r.get("weight") or r.get("to_weight")
            if not hyp or not weight:
                continue
            prev = resolved.get(str(hyp))
            if prev is None:
                resolved[str(hyp)] = (str(weight), [lead_name])
            else:
                # Keep the latest weight; append the lead.
                resolved[str(hyp)] = (str(weight), prev[1] + [lead_name])

    if resolved:
        lines = []
        for hyp_id, (weight, leads) in resolved.items():
            leads_str = ", ".join(dict.fromkeys(leads))  # dedupe preserving order
            lines.append(f"- **{hyp_id}:** `{weight}` — via {leads_str}")
        return "\n".join(lines)

    if surviving_hypotheses:
        return "\n".join(
            f"- **{h}:** live weight (not resolved to `++`/`--`)"
            for h in surviving_hypotheses
        )

    return "- (no hypothesis records found in gather blocks)"


def _compose_key_evidence_md(gather: list[dict]) -> str:
    """Render `## Key Evidence` from invlang gather outcomes.

    One bullet per lead. Preference order for what to cite:
      1. trust_anchor_result — anchor verdict + as_of.
      2. attribute_updates — first updates entry compactly.
      3. resolutions — count + leads they touch.
      4. fallback — lead name + status string.
    """
    lines: list[str] = []
    for entry in gather:
        name = entry.get("name") or entry.get("id") or "?"
        outcome = entry.get("outcome") or {}
        citation: str
        tar = outcome.get("trust_anchor_result")
        if isinstance(tar, dict) and (tar.get("verdict") or tar.get("result")):
            verdict = tar.get("verdict") or tar.get("result")
            anchor = tar.get("anchor_id") or name
            as_of = tar.get("as_of")
            suffix = f" (as of {as_of})" if as_of else ""
            citation = f"anchor `{anchor}` → `{verdict}`{suffix}"
        elif outcome.get("attribute_updates"):
            updates = outcome["attribute_updates"]
            if isinstance(updates, list) and updates:
                first = updates[0] if isinstance(updates[0], dict) else {}
                target = first.get("target", "?")
                up = first.get("updates") or {}
                if isinstance(up, dict) and up:
                    key, val = next(iter(up.items()))
                    citation = f"`{target}.{key}` = `{val}`"
                else:
                    citation = f"attribute update on `{target}`"
            else:
                citation = "attribute update recorded"
        elif outcome.get("resolutions"):
            res = outcome["resolutions"]
            count = len(res) if isinstance(res, list) else 0
            citation = f"{count} hypothesis resolution(s) recorded"
        else:
            status = entry.get("status") or "observed"
            citation = f"lead completed (status: `{status}`)"
        lines.append(f"- **{name}:** {citation}")
    if not lines:
        return "- (no gather leads recorded)"
    return "\n".join(lines)


_SUMMARY_TAG_RE = None
_ANALYST_TAG_RE = None


def _parse_narrative_tags(raw: str) -> tuple[str, str | None]:
    """Extract `<summary>` (required) and `<for-analyst>` (optional) body
    text from the narrative subagent's stdout. Returns `(summary_md,
    analyst_md_or_None)`. Raises `_MechanicalFallback` if `<summary>` is
    missing — the mechanical path cannot proceed without it.
    """
    import re  # local; narrow scope
    global _SUMMARY_TAG_RE, _ANALYST_TAG_RE
    if _SUMMARY_TAG_RE is None:
        _SUMMARY_TAG_RE = re.compile(r"<summary>\s*(.*?)\s*</summary>", re.DOTALL)
        _ANALYST_TAG_RE = re.compile(
            r"<for-analyst>\s*(.*?)\s*</for-analyst>", re.DOTALL,
        )
    m = _SUMMARY_TAG_RE.search(raw)
    if not m:
        raise _MechanicalFallback(
            "narrative subagent produced no <summary> block"
        )
    summary = m.group(1).strip()
    if not summary or summary.startswith("(insufficient-context"):
        raise _MechanicalFallback(
            f"narrative subagent flagged insufficient context: {summary!r}"
        )
    analyst_m = _ANALYST_TAG_RE.search(raw)
    analyst = analyst_m.group(1).strip() if analyst_m else None
    return summary, (analyst or None)


def _dispatch_narrative_subagent(
    ctx: Context,
    *,
    status: str,
    disposition: str,
    confidence: str,
    matched_archetype: str | None,
) -> tuple[str, str | None]:
    """Invoke `report_narrative` subagent with a trimmed preload.

    Preload shape (target ≤ 8 KB):
      - One-line alert summary
      - <investigation-summary> via `format_investigation_block(mode="report-narrative")`
      - <archetype> block only when `matched_archetype` is non-null
      - Header metadata: status, disposition, confidence, matched_archetype

    Returns (summary_md, analyst_md_or_None). Raises `_MechanicalFallback`
    on any failure (subagent error, missing <summary> tag, insufficient-
    context sentinel).
    """
    alert = load_alert(ctx.run_dir)
    salt = load_run_salt(ctx.run_dir)
    investigation_md = load_investigation_md(ctx.run_dir)

    header_lines = [
        f"status={status}",
        f"disposition={disposition}",
        f"confidence={confidence}",
        f"matched_archetype={matched_archetype or 'null'}",
    ]
    blocks = [
        "\n".join(header_lines),
        format_alert_block(alert, salt),
        format_investigation_block(investigation_md, mode="report-narrative"),
    ]
    if matched_archetype:
        shapes = load_archetype_shapes(
            ctx.signature_id, SOC_AGENT_ROOT,
            archetype_names=[matched_archetype],
            include_precedents=False,
        )
        if shapes:
            blocks.append(format_archetype_shapes_block(
                shapes, with_precedents=False,
            ))

    prompt = "\n\n".join(blocks)
    try:
        raw = _shared_invoke("report_narrative", prompt, timeout=120)
    except OrchestrationError as exc:
        raise _MechanicalFallback(
            f"narrative subagent invocation failed: {exc}"
        ) from None
    return _parse_narrative_tags(raw)


def _compose_report_md_analyze(
    *,
    ctx: Context,
    status: str,
    disposition: str,
    confidence: str,
    matched_archetype: str | None,
    matched_ticket_id: str | None,
    trust_anchors: list[dict],
    leads_pursued: int,
    trace: str,
    hypothesis_outcomes_md: str,
    key_evidence_md: str,
    summary_md: str,
    analyst_md: str | None,
) -> str:
    """Assemble report.md for the ANALYZE-routed mechanical path.

    Structural fields come from the ANALYZE payload + parsed gather blocks.
    `summary_md` and `analyst_md` come from the narrative subagent. Section
    order is fixed to match agents/report.md §6 exactly so Tier-1 passes.
    """
    fm = {
        "ticket_id": ctx.ticket_id,
        "signature_id": ctx.signature_id,
        "status": status,
        "disposition": disposition,
        "confidence": confidence,
        "matched_archetype": matched_archetype,
        "matched_ticket_id": matched_ticket_id,
        "trust_anchors_consulted": trust_anchors,
        "leads_pursued": leads_pursued,
        "trace": trace,
    }
    frontmatter_yaml = yaml.safe_dump(fm, sort_keys=False).rstrip()

    sections: list[str] = [
        "---",
        frontmatter_yaml,
        "---",
        "",
        "## Summary",
        "",
        summary_md.strip(),
        "",
        "## Investigation Trace",
        "",
        trace,
        "",
        "## Hypothesis Outcomes",
        "",
        hypothesis_outcomes_md.strip(),
        "",
        "## Key Evidence",
        "",
        key_evidence_md.strip(),
        "",
        "## Verdict",
        "",
        f"**Status:** {status.capitalize()}  ",
        f"**Disposition:** {disposition.capitalize()}  ",
        f"**Confidence:** {confidence.capitalize()}  ",
        f"**Matched Archetype:** {matched_archetype or 'null'}  ",
    ]

    if status == "escalated":
        sections.append("")
        sections.append("## For Analyst")
        sections.append("")
        if analyst_md:
            sections.append(analyst_md.strip())
        else:
            sections.append(
                "Investigation escalated without grounding. Review the "
                "Hypothesis Outcomes and Key Evidence sections above, and "
                "confirm whether additional telemetry or authority "
                "consultation can resolve the open uncertainty."
            )

    return "\n".join(sections) + "\n"


def _compose_analyze_routed(
    ctx: Context,
    analyze_payload: dict,
    *,
    matched_archetype: str | None,
) -> dict:
    """Mechanical REPORT composer for the ANALYZE-routed path.

    Extracts structured fields from the ANALYZE payload + invlang gather
    blocks in investigation.md, dispatches the narrative subagent for the
    free-text sections, assembles report.md, appends the REPORT section
    to investigation.md, and runs Tier-1 validation.

    `matched_archetype` is resolved upstream by `_resolve_matched_archetype`
    (which dispatches the `archetype-match` subagent against the confirmed
    investigation outcome). Passed in rather than re-derived here so the
    mechanical and subagent-fallback paths share one source of truth.

    On any failure (narrative subagent miss, Tier-1 reject, mandatory-
    grounding violation on resolved status), rolls back partial writes and
    raises `_MechanicalFallback` so handle() falls through to the
    full-context subagent.
    """
    raw_disposition = analyze_payload.get("disposition")
    confidence = analyze_payload.get("confidence")
    surviving_hypotheses = analyze_payload.get("surviving_hypotheses") or []

    if not raw_disposition or not confidence:
        raise _MechanicalFallback(
            f"ANALYZE payload missing disposition/confidence: "
            f"{list(analyze_payload.keys())}"
        )

    # ANALYZE's routing schema (agents/analyze.md) uses
    # disposition ∈ {benign, false_positive, true_positive, escalated}
    # but the report frontmatter schema (schemas/enums.py VALID_DISPOSITIONS)
    # uses {benign, false_positive, true_positive, inconclusive}. When ANALYZE
    # routes `escalated`, that maps to report-frontmatter
    # `disposition: inconclusive` + `status: escalated`. The report
    # subagent does this remapping implicitly per agents/report.md; the
    # mechanical path does it explicitly.
    force_escalated_from_disposition = False
    if raw_disposition == "escalated":
        disposition = "inconclusive"
        force_escalated_from_disposition = True
    else:
        disposition = raw_disposition

    investigation_md = load_investigation_md(ctx.run_dir)
    gather = _extract_gather_blocks(investigation_md)
    final_analyze_text = _extract_final_analyze_section(investigation_md)

    trust_anchors = _derive_trust_anchors(gather)
    leads_pursued = len(gather)

    trace = _compose_trace_analyze(
        gather, disposition, surviving_hypotheses, matched_archetype,
    )
    termination_category = _derive_termination_category(
        analyze_payload, gather, final_analyze_text,
    )
    hypothesis_outcomes_md = _compose_hypothesis_outcomes_md(
        gather, surviving_hypotheses,
    )
    key_evidence_md = _compose_key_evidence_md(gather)

    # Resolve grounding status. The ANALYZE disposition steers, but
    # `resolved` requires either (a) required_anchors all confirmed or
    # (b) a matched_ticket_id pointing at an on-disk precedent.
    matched_ticket_id = analyze_payload.get("matched_ticket_id")
    status = "escalated"
    if disposition in ("benign", "false_positive") and matched_archetype:
        archetype_dir = (
            SOC_AGENT_ROOT
            / "knowledge" / "signatures" / ctx.signature_id
            / "archetypes" / matched_archetype
        )
        if archetype_dir.exists():
            required = _load_required_anchors(archetype_dir)
            confirmed = {
                (a.get("anchor") or "") for a in trust_anchors
                if a.get("result") == "confirmed"
            }
            anchor_grounded = bool(required) and all(
                r in confirmed for r in required
            )
            precedent_grounded = False
            if matched_ticket_id:
                precedent_path = archetype_dir / f"{matched_ticket_id}.json"
                precedent_grounded = precedent_path.exists()
            if anchor_grounded or precedent_grounded:
                status = "resolved"
            elif matched_ticket_id and not precedent_grounded:
                # SCREEN-style recovery: drop the invalid cite, keep trying.
                matched_ticket_id = None
        # If archetype dir missing, fall through to escalated with
        # matched_archetype preserved for the report body. Tier-1 will
        # catch this if it's incompatible with status=resolved.

    # If the ANALYZE disposition is adversarial (true_positive / inconclusive
    # with adversarial termination) we always escalate — matches the
    # legitimacy-gated-disposition rule in invlang v2.9. Also applies when
    # ANALYZE explicitly routed `disposition: escalated`.
    if disposition in ("true_positive", "inconclusive") or force_escalated_from_disposition:
        status = "escalated"

    # Dispatch narrative subagent (BEFORE writing anything — on failure we
    # haven't touched disk yet, no rollback needed).
    summary_md, analyst_md = _dispatch_narrative_subagent(
        ctx,
        status=status,
        disposition=disposition,
        confidence=confidence,
        matched_archetype=matched_archetype,
    )

    conclude_yaml_block = {
        "conclude": {
            "termination": {
                "category": termination_category,
                "rationale": _compose_termination_rationale(
                    termination_category, matched_archetype,
                    matched_ticket_id, surviving_hypotheses,
                ),
            },
            "disposition": disposition,
            "confidence": confidence,
            "matched_archetype": matched_archetype,
            "summary": _truncate_summary(summary_md),
        }
    }
    conclude_yaml_text = yaml.safe_dump(
        conclude_yaml_block, sort_keys=False,
    ).rstrip()

    verdict_line = (
        f"**Verdict:** {status} / {disposition} / {confidence}"
    )
    confirmed_hyp = (
        f"?{matched_archetype} (via ANALYZE routing)"
        if matched_archetype
        else (surviving_hypotheses[0] if surviving_hypotheses else "null")
    )
    md_lines = [
        "## REPORT",
        "",
        verdict_line,
        f"**Confirmed hypothesis:** {confirmed_hyp}",
        f"**Trace:** {trace}",
        "",
        "```yaml",
        conclude_yaml_text,
        "```",
        "",
    ]

    report_text = _compose_report_md_analyze(
        ctx=ctx,
        status=status,
        disposition=disposition,
        confidence=confidence,
        matched_archetype=matched_archetype,
        matched_ticket_id=matched_ticket_id,
        trust_anchors=trust_anchors,
        leads_pursued=leads_pursued,
        trace=trace,
        hypothesis_outcomes_md=hypothesis_outcomes_md,
        key_evidence_md=key_evidence_md,
        summary_md=summary_md,
        analyst_md=analyst_md,
    )

    # Snapshot before touching disk so Tier-1 failure rolls back cleanly.
    inv_path = ctx.run_dir / "investigation.md"
    report_path = ctx.run_dir / "report.md"
    inv_before = inv_path.read_text() if inv_path.exists() else None

    _append_to_investigation(ctx.run_dir, "\n".join(md_lines))
    report_path.write_text(report_text)

    try:
        _run_tier1_validation(report_path)
    except OrchestrationError as exc:
        if inv_before is None:
            inv_path.unlink(missing_ok=True)
        else:
            inv_path.write_text(inv_before)
        report_path.unlink(missing_ok=True)
        raise _MechanicalFallback(
            f"Tier-1 validation rejected mechanical analyze report: {exc}"
        ) from None

    return {
        "status": "written",
        "report_path": str(report_path),
        "disposition": disposition,
        "confidence": confidence,
        "matched_archetype": matched_archetype,
        "matched_ticket_id": matched_ticket_id,
        "status_frontmatter": status,
        "compose_mode": "analyze_mechanical",
    }


def _compose_termination_rationale(
    category: str,
    matched_archetype: str | None,
    matched_ticket_id: str | None,
    surviving_hypotheses: list[str],
) -> str:
    """One-sentence rationale for the `termination.category`. Mechanical —
    no narrative judgment."""
    if category == "trust-root":
        return (
            f"Authority verdict closed the question"
            + (f" for archetype {matched_archetype}" if matched_archetype else "")
            + "."
        )
    if category == "adversarial-refuted":
        return (
            "Adversarial mechanism hypothesis refuted with a named matched "
            "refutation shape."
        )
    if category == "severity-ceiling":
        return (
            "Signature's structural severity forces escalation regardless of "
            "mechanism (composition rule triggered)."
        )
    # exhaustion-escalation
    if matched_archetype and matched_ticket_id is None:
        return (
            f"Archetype {matched_archetype} could not be grounded — required "
            f"anchor(s) unconfirmed and no matching precedent."
        )
    if surviving_hypotheses:
        return (
            f"Further leads not runnable; "
            f"{surviving_hypotheses[0]} held at live weight."
        )
    return "Further leads not runnable; investigation escalated for analyst review."


def _truncate_summary(summary_md: str, *, max_chars: int = 300) -> str:
    """Collapse a multi-paragraph narrative summary into a 1-2 sentence
    summary field for the conclude: YAML block. Takes the first paragraph,
    strips newlines, clamps to max_chars.
    """
    first_para = summary_md.strip().split("\n\n", 1)[0]
    collapsed = " ".join(first_para.split())
    if len(collapsed) <= max_chars:
        return collapsed
    return collapsed[: max_chars - 1].rstrip() + "…"
