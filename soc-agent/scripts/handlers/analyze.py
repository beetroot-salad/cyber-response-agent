"""ANALYZE phase handler.

Replaces the ANALYZE section of `skills/investigate/SKILL.md` with a Python
orchestration that dispatches the `analyze` subagent and parses its terminal
routing YAML to decide the next phase.

The ANALYZE subagent (agents/analyze.md, model=sonnet) emits three sections:
    1. `## ANALYZE (loop {n})` — human-readable assessment
    2. `## Self-report`        — data wishes, uncertain claims, anomalies
    3. terminal fenced `yaml`  — machine-parsed routing decision

This handler:
    - computes `loop_n` from ctx.history (count of HYPOTHESIZE entries)
    - invokes the subagent via the shared `_subagent.invoke_subagent` wrapper
    - extracts the terminal routing YAML via `extract_terminal_yaml`
    - validates the routing payload (next_action, disposition, etc.)
    - appends the two markdown sections (stripping the terminal YAML) to
      investigation.md, pre-validated via `validate_companion()` as a library call
    - returns PhaseResult(next_phase, payload)

It does NOT compose the invlang `gather[].resolutions[]` block — that belongs
to a future GATHER-cutover handler where observations + resolutions are
naturally composed together. Until then, resolutions are written by whatever
drives the loop in the skill-based flow.

Input (Context):
    ctx.run_dir, ctx.signature_id, ctx.history, ctx.alert

Output:
    PhaseResult
      - next_action=CONCLUDE    → Phase.CONCLUDE
      - next_action=HYPOTHESIZE → Phase.HYPOTHESIZE

Files written:
    {run_dir}/investigation.md — appends `## ANALYZE (loop N)` + `## Self-report`
    markdown sections (no invlang YAML).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

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


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_ANALYZE_TIMEOUT_SECONDS", "300")
)

_VALID_NEXT_ACTIONS = {"CONCLUDE", "HYPOTHESIZE"}
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

    loop_n is the count of HYPOTHESIZE entries observed — every loop begins
    with HYPOTHESIZE, so the most recent HYPOTHESIZE closes the current loop.
    Fallback to 1 for safety (shouldn't happen — ANALYZE should always
    follow at least one HYPOTHESIZE in a well-formed run).
    """
    return sum(1 for p in ctx.history if p == Phase.HYPOTHESIZE.value) or 1


def _assemble_prompt(ctx: Context) -> str:
    """Build the analyze subagent prompt with all deterministic context inline.

    The subagent receives alert.json, investigation.md, and every archetype's
    story.md + trust-anchors.md preloaded — no Read tool calls required.
    Only the narrative synthesis (ANALYZE + Self-report + terminal YAML)
    remains as the subagent's work.
    """
    loop_n = _compute_loop_n(ctx)
    alert = load_alert(ctx.run_dir)
    salt = load_run_salt(ctx.run_dir)
    investigation_md = load_investigation_md(ctx.run_dir)
    archetype_shapes = load_archetype_shapes(
        ctx.signature_id, SOC_AGENT_ROOT, include_precedents=False,
    )
    return "\n\n".join([
        f"run_dir={ctx.run_dir}\nloop_n={loop_n}\nsignature_id={ctx.signature_id}",
        format_alert_block(alert, salt),
        format_investigation_block(investigation_md, mode="analyze"),
        format_archetype_shapes_block(archetype_shapes, with_precedents=False),
    ])


# ---------------------------------------------------------------------------
# Terminal YAML validation
# ---------------------------------------------------------------------------


def _validate_routing(payload: dict) -> dict:
    """Verify the terminal YAML conforms to the subagent contract."""
    next_action = payload.get("next_action")
    if next_action not in _VALID_NEXT_ACTIONS:
        raise OrchestrationError(
            f"analyze subagent: invalid next_action {next_action!r} "
            f"(expected one of {sorted(_VALID_NEXT_ACTIONS)})"
        )

    if next_action == "CONCLUDE":
        disposition = payload.get("disposition")
        if disposition not in _VALID_DISPOSITIONS:
            raise OrchestrationError(
                f"analyze subagent: routing CONCLUDE requires disposition "
                f"∈ {sorted(_VALID_DISPOSITIONS)}, got {disposition!r}"
            )
        confidence = payload.get("confidence")
        if confidence not in _VALID_CONFIDENCES:
            raise OrchestrationError(
                f"analyze subagent: routing CONCLUDE requires confidence "
                f"∈ {sorted(_VALID_CONFIDENCES)}, got {confidence!r}"
            )
        if "matched_archetype" not in payload:
            raise OrchestrationError(
                "analyze subagent: routing CONCLUDE requires matched_archetype "
                "(use null for no-archetype outcomes)"
            )
        surviving = payload.get("surviving_hypotheses")
        if not isinstance(surviving, list):
            raise OrchestrationError(
                "analyze subagent: routing CONCLUDE requires "
                "surviving_hypotheses[] (empty list if every hypothesis is "
                f"refuted) — got {type(surviving).__name__}"
            )
    else:  # HYPOTHESIZE
        discriminator = payload.get("discriminator")
        if not isinstance(discriminator, str) or not discriminator.strip():
            raise OrchestrationError(
                "analyze subagent: routing HYPOTHESIZE requires a non-empty "
                "discriminator field (one-line question the next lead must answer)"
            )

    return payload


# ---------------------------------------------------------------------------
# Markdown section extraction
# ---------------------------------------------------------------------------


def _strip_yaml_fences(raw: str) -> str:
    """Return `raw` with every ```yaml...``` fenced block removed.

    The subagent contract forbids companion-YAML emission from ANALYZE
    (the main agent composes `gather[].resolutions[]` downstream) and the
    routing YAML is consumed out-of-band before this strip runs. So any
    `yaml` fence in the appended text is either the terminal routing block
    or an out-of-contract emission — in both cases, it must not land in
    `investigation.md` where the invlang validator would merge it into
    the companion graph. Strip all of them.
    """
    fence = "```yaml"
    end_marker = "```"
    out: list[str] = []
    i = 0
    while True:
        start = raw.find(fence, i)
        if start == -1:
            out.append(raw[i:])
            break
        out.append(raw[i:start])
        body_start = start + len(fence)
        stop = raw.find(end_marker, body_start)
        if stop == -1:
            # Unterminated fence — drop the remainder and stop.
            break
        i = stop + len(end_marker)
    return "".join(out).rstrip() + "\n"


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

    sections = _strip_yaml_fences(raw)
    _validate_and_write(ctx, sections)

    next_phase = (
        Phase.CONCLUDE if payload["next_action"] == "CONCLUDE"
        else Phase.HYPOTHESIZE
    )
    return PhaseResult(next_phase=next_phase, payload=payload)
