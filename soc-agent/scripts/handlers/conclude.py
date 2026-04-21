"""CONCLUDE phase handler — dispatches the `conclude` subagent and parses its
terminal status.

Input:
    ctx.ticket_id                               — resolved at Context construction
    ctx.forced_conclude                         — true on MAX_LOOPS path
    ctx.outputs[Phase.ANALYZE]  OR
    ctx.outputs[Phase.SCREEN]   OR
    ctx.outputs[Phase.CONTEXTUALIZE].dedup      (fast-path)

Work:
    1. Choose routing source (analyze / screen / forced_exhaustion).
    2. Assemble the subagent prompt and invoke via the shared wrapper.
    3. Parse the single terminal YAML block the subagent emits.

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
            "failure": {...},                  # on gate_failed
            "reason": "...",                   # on error
        },
    )

The subagent does the actual Edit on investigation.md and Write on report.md;
hook-based validators fire during those writes. The handler's retry loop lives
inside the subagent (classifier-gated, cap 1).
"""

from __future__ import annotations

import os

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._subagent import (
    extract_terminal_yaml,
    invoke_subagent as _shared_invoke,
)


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
    - CONTEXTUALIZE with `dedup=True` → screen-shaped fast-path
    - SCREEN present → screen
    - ANALYZE present → analyze
    """
    if ctx.forced_conclude:
        return "forced_exhaustion", True
    if Phase.CONTEXTUALIZE in ctx.outputs:
        ctx_payload = ctx.outputs[Phase.CONTEXTUALIZE]
        if ctx_payload.get("dedup"):
            return "screen", False
    if Phase.ANALYZE in ctx.outputs:
        return "analyze", False
    if Phase.SCREEN in ctx.outputs:
        return "screen", False
    return "forced_exhaustion", True


def _assemble_prompt(ctx: Context) -> str:
    if not ctx.ticket_id:
        raise OrchestrationError(
            "CONCLUDE handler: ctx.ticket_id is empty — must be set at Context "
            "construction by the /investigate entrypoint"
        )
    routing_source, forced = _select_routing_source(ctx)
    lines = [
        f"run_dir={ctx.run_dir}",
        f"signature_id={ctx.signature_id}",
        f"identifier={ctx.ticket_id}",
        f"routing_source={routing_source}",
    ]
    if forced:
        lines.append("forced_exhaustion=true")
    return "\n".join(lines)


def _validate_status(parsed: dict) -> dict:
    status = parsed.get("status")
    if status not in _VALID_STATUSES:
        raise OrchestrationError(
            f"conclude subagent returned unknown status {status!r}; "
            f"expected one of {sorted(_VALID_STATUSES)}"
        )
    return parsed


def handle(ctx: Context) -> PhaseResult:
    prompt = _assemble_prompt(ctx)
    raw = _invoke_subagent(prompt)
    payload = _validate_status(extract_terminal_yaml(raw))
    return PhaseResult(next_phase=Phase.CONCLUDE, payload=payload)
