"""ANALYZE phase handler.

Interprets gather observations against the scaffolding PREDICT set up
(hypotheses, predictions, authz contracts) and decides whether the
investigation is terminal. Does NOT decide what to investigate next — that is
PREDICT's job. ANALYZE's routing decision is binary: `continue` → PREDICT |
`halt` → REPORT.

The ANALYZE subagent (agents/analyze.md, model=sonnet) emits three sections:
    1. `## ANALYZE (loop {n})` — human-readable assessment
    2. `## Self-report`        — data wishes, uncertain claims, anomalies
    3. terminal fenced `yaml`  — machine-parsed routing decision

Terminal YAML trailer:
    route: continue | halt
    # halt path:
    termination_category: trust-root | adversarial-refuted | severity-ceiling | exhaustion-escalation
    disposition: benign | false_positive | true_positive | escalated
    confidence: high | medium | low
    matched_archetype: <name> | null
    surviving_hypotheses: [...]
    # continue path:
    unresolved_prescribed_set: [...]  # optional; prescribed leads that gather
                                      # didn't resolve. Handler back-fills from
                                      # GATHER payload when the subagent omits.

Handler responsibilities:
    - computes `loop_n` from ctx.history (count of PREDICT entries)
    - invokes the subagent via the shared `_subagent.invoke_subagent` wrapper
    - extracts the terminal routing YAML via `extract_terminal_yaml`
    - validates the routing payload shape
    - back-fills `unresolved_prescribed_set` from `ctx.outputs[Phase.GATHER]`
      when the subagent didn't compute it
    - strips only the *last* YAML fence (the terminal routing trailer) before
      appending; non-terminal YAML survives. This is future-proofing for when
      the subagent starts emitting `resolutions:` sub-blocks — the invlang
      infrastructure for three-phase co-ownership isn't landed yet, but the
      handler should not drop signal when it does.
    - appends the two markdown sections to investigation.md, pre-validated via
      `validate_companion()` as a library call
    - returns PhaseResult(next_phase, payload)

Input (Context):
    ctx.run_dir, ctx.signature_id, ctx.history, ctx.alert,
    ctx.outputs[Phase.GATHER] (carries prescribed_leads + executed_leads)

Output:
    PhaseResult
      - route=halt      → Phase.REPORT
      - route=continue  → Phase.PREDICT
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._context_loader import (
    format_alert_block,
    format_investigation_block,
    load_alert,
    load_investigation_md,
    load_run_salt,
)
from scripts.handlers._subagent import (
    extract_terminal_yaml,
    invoke_subagent as _shared_invoke,
)


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_ANALYZE_TIMEOUT_SECONDS", "300")
)

_VALID_ROUTES = {"continue", "halt"}
_VALID_TERMINATION_CATEGORIES = {
    "trust-root",
    "adversarial-refuted",
    "severity-ceiling",
    "exhaustion-escalation",
}
_VALID_DISPOSITIONS = {"benign", "false_positive", "true_positive", "escalated"}
_VALID_CONFIDENCES = {"high", "medium", "low"}


# ---------------------------------------------------------------------------
# Subagent invocation (mockable)
# ---------------------------------------------------------------------------


def _invoke_subagent(prompt: str, *, timeout: int = SUBAGENT_TIMEOUT_SECONDS) -> str:
    """Module-level wrapper over the shared subagent dispatcher.

    Kept as a module-level function so tests can monkeypatch it with
    `monkeypatch.setattr(analyze_handler, "_invoke_subagent", stub)`.
    """
    return _shared_invoke("analyze", prompt, timeout=timeout)


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


def _compute_loop_n(ctx: Context) -> int:
    """Infer the current loop number from ctx.history.

    loop_n is the count of PREDICT entries observed — every loop begins
    with PREDICT, so the most recent PREDICT closes the current loop.
    Fallback to 1 for safety (shouldn't happen — ANALYZE should always
    follow at least one PREDICT in a well-formed run).
    """
    return sum(1 for p in ctx.history if p == Phase.PREDICT.value) or 1


def _assemble_prompt(ctx: Context) -> str:
    """Build the analyze subagent prompt with all deterministic context inline.

    The subagent receives alert.json and investigation.md preloaded — no Read
    tool calls required. Archetype context is not preloaded; archetype
    labeling moved to the REPORT phase.
    """
    loop_n = _compute_loop_n(ctx)
    alert = load_alert(ctx.run_dir)
    salt = load_run_salt(ctx.run_dir)
    investigation_md = load_investigation_md(ctx.run_dir)
    return "\n\n".join([
        f"run_dir={ctx.run_dir}\nloop_n={loop_n}\nsignature_id={ctx.signature_id}",
        format_alert_block(alert, salt),
        format_investigation_block(investigation_md, mode="analyze"),
    ])


# ---------------------------------------------------------------------------
# Terminal YAML validation
# ---------------------------------------------------------------------------


def _validate_routing(payload: dict) -> dict:
    """Verify the terminal YAML conforms to the subagent contract."""
    route = payload.get("route")
    if route not in _VALID_ROUTES:
        raise OrchestrationError(
            f"analyze subagent: invalid route {route!r} "
            f"(expected one of {sorted(_VALID_ROUTES)})"
        )

    if route == "halt":
        category = payload.get("termination_category")
        if category not in _VALID_TERMINATION_CATEGORIES:
            raise OrchestrationError(
                f"analyze subagent: route=halt requires termination_category "
                f"∈ {sorted(_VALID_TERMINATION_CATEGORIES)}, got {category!r}"
            )
        disposition = payload.get("disposition")
        if disposition not in _VALID_DISPOSITIONS:
            raise OrchestrationError(
                f"analyze subagent: route=halt requires disposition "
                f"∈ {sorted(_VALID_DISPOSITIONS)}, got {disposition!r}"
            )
        confidence = payload.get("confidence")
        if confidence not in _VALID_CONFIDENCES:
            raise OrchestrationError(
                f"analyze subagent: route=halt requires confidence "
                f"∈ {sorted(_VALID_CONFIDENCES)}, got {confidence!r}"
            )
        surviving = payload.get("surviving_hypotheses")
        if not isinstance(surviving, list):
            raise OrchestrationError(
                "analyze subagent: route=halt requires surviving_hypotheses[] "
                "(empty list if every hypothesis is refuted) — got "
                f"{type(surviving).__name__}"
            )
    else:  # continue
        # PREDICT owns lead selection and fork evolution; ANALYZE's continue
        # routing only needs a structural signal. unresolved_prescribed_set is
        # optional — handler back-fills from GATHER payload when absent.
        ups = payload.get("unresolved_prescribed_set")
        if ups is not None:
            if not isinstance(ups, list) or not all(
                isinstance(x, str) and x.strip() for x in ups
            ):
                raise OrchestrationError(
                    f"analyze subagent: unresolved_prescribed_set must be "
                    f"list[str] of non-empty slugs when present "
                    f"(got {ups!r})"
                )

    return payload


def _backfill_unresolved_prescribed_set(payload: dict, ctx: Context) -> dict:
    """On continue, compute unresolved_prescribed_set from GATHER payload if
    the subagent didn't emit it. Backstop for Bug A: even if gather-composite's
    scope-check is bypassed, ANALYZE still surfaces the gap so PREDICT can
    re-prescribe.
    """
    if payload.get("route") != "continue":
        return payload
    if payload.get("unresolved_prescribed_set") is not None:
        return payload
    gather_out = ctx.outputs.get(Phase.GATHER)
    if not isinstance(gather_out, dict):
        # No GATHER payload (shouldn't happen in a well-formed loop); leave absent.
        return payload
    prescribed = gather_out.get("prescribed_leads")
    executed = gather_out.get("executed_leads")
    if not isinstance(prescribed, list) or not isinstance(executed, list):
        return payload
    executed_set = set(executed)
    unresolved = [lead for lead in prescribed if lead not in executed_set]
    if unresolved:
        payload["unresolved_prescribed_set"] = unresolved
    return payload


# ---------------------------------------------------------------------------
# Markdown section extraction
# ---------------------------------------------------------------------------


def _strip_terminal_routing(raw: str) -> str:
    """Return `raw` with the last ```yaml``` fence removed.

    The terminal routing YAML is consumed out-of-band and must not land in
    investigation.md — invlang validators would reject its routing keys as
    unknown. Drop only the last yaml fence; preserve all preceding fences.
    Matches `predict.py:_strip_terminal_routing` so both phase outputs
    follow the same lead-block-preserving convention.

    This deliberately does not strip earlier fences — future ANALYZE
    subagent versions will emit `resolutions:` sub-blocks that must survive
    the strip. When that lands alongside a merge-by-lead-id invlang
    validator extension, the handler here needs no further change.
    """
    last_start = raw.rfind("```yaml")
    if last_start == -1:
        return raw.rstrip() + "\n"
    end_marker_start = raw.find("```", last_start + len("```yaml"))
    if end_marker_start == -1:
        return raw[:last_start].rstrip() + "\n"
    after = raw[end_marker_start + len("```"):]
    return (raw[:last_start].rstrip() + "\n" + after.lstrip()).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Validate + append
# ---------------------------------------------------------------------------


def _validate_and_write(ctx: Context, new_section: str) -> None:
    """Append `new_section` to investigation.md after running
    `validate_companion` as a library check.

    `validate_companion` is a pure function that walks any YAML blocks
    present in the text; appending markdown-only prose leaves the YAML set
    unchanged so the validator is effectively idempotent on this path, but
    we run it anyway to catch any drift in the accumulated document.

    Note: validation runs *after* the subagent has been spawned, so a
    failure here sinks the subagent's cost — there's no pre-spawn path
    that could catch it, since the text being validated is the subagent's
    own output. On failure, `OrchestrationError` bubbles up and the
    orchestrator halts the run.
    """
    hooks_scripts = str(SOC_AGENT_ROOT / "hooks")
    if hooks_scripts not in sys.path:
        sys.path.insert(0, hooks_scripts)
    from scripts.invlang_validate import validate_companion  # type: ignore

    inv_path = ctx.run_dir / "investigation.md"
    current = inv_path.read_text() if inv_path.exists() else ""
    proposed = (
        current
        + ("\n" if current and not current.endswith("\n") else "")
        + new_section
    )

    errors = validate_companion(proposed, current if current else None)
    if errors:
        raise OrchestrationError(
            "ANALYZE invlang validation failed:\n" + "\n".join(errors)
        )

    inv_path.write_text(proposed)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def handle(ctx: Context) -> PhaseResult:
    prompt = _assemble_prompt(ctx)
    raw = _invoke_subagent(prompt)

    payload = _validate_routing(extract_terminal_yaml(raw))
    payload = _backfill_unresolved_prescribed_set(payload, ctx)

    sections = _strip_terminal_routing(raw)
    _validate_and_write(ctx, sections)

    next_phase = (
        Phase.REPORT if payload["route"] == "halt"
        else Phase.PREDICT
    )
    return PhaseResult(next_phase=next_phase, payload=payload)
