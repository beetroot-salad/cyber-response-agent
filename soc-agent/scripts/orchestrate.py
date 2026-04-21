"""Investigation orchestrator — Python state machine that drives phase transitions.

Replaces the main-LLM-agent loop in skills/investigate/SKILL.md. Each phase is a
pure function: it receives the accumulated context, returns a next-phase decision
and an opaque payload. The orchestrator validates transitions against
schemas/state.py, persists state.json, enforces the loop cap, and loops until a
terminal phase (CONCLUDE) or an error.

At this skeleton stage, phase handlers are stub functions passed in by the caller
(typically a test). Real handlers that shell out to `claude --print` subagents
come later, one phase at a time.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import (  # noqa: E402
    MAX_LOOPS,
    Phase,
    count_loops,
    make_state,
    validate_transition,
)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class PhaseResult:
    """What a phase handler returns.

    next_phase: the phase to transition to after this one completes.
    payload:    opaque per-phase output, stashed on the context for downstream
                phases to consume. The orchestrator does not interpret it.
    """

    next_phase: Phase
    payload: dict = field(default_factory=dict)


@dataclass
class Context:
    """Accumulated runtime state passed to every phase handler.

    `ticket_id` is resolved once at Context construction (by the /investigate
    entrypoint or `setup_run.py`) — handlers never reach into `alert` to
    re-derive it. That keeps alert-schema coupling confined to one place.
    """

    run_dir: Path
    signature_id: str
    ticket_id: str
    alert: dict
    outputs: dict[Phase, dict] = field(default_factory=dict)
    history: list[str] = field(default_factory=list)
    current_phase: Optional[Phase] = None
    forced_conclude: bool = False


PhaseHandler = Callable[[Context], PhaseResult]


class OrchestrationError(Exception):
    """Raised when the orchestrator cannot continue (illegal transition, missing
    handler, handler failure, etc.)."""


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run(ctx: Context, handlers: dict[Phase, PhaseHandler]) -> dict:
    """Drive the state machine to a terminal phase.

    Returns a summary dict: {status, history, outputs}. Raises
    OrchestrationError if an illegal transition or missing handler is hit.
    """
    proposed = Phase.CONTEXTUALIZE
    forced = False

    while True:
        current_name = ctx.current_phase.value if ctx.current_phase else None
        ok, err = validate_transition(current_name, proposed.value)
        if not ok:
            raise OrchestrationError(err)

        ctx.current_phase = proposed
        ctx.history.append(proposed.value)
        _persist_state(ctx)

        if proposed == Phase.CONCLUDE:
            # CONCLUDE is terminal, but a registered handler still runs once
            # to compose report.md and persist the conclude: YAML. Tests can
            # omit the handler to exercise pure-transition behaviour.
            handler = handlers.get(Phase.CONCLUDE)
            if handler is not None:
                result = handler(ctx)
                ctx.outputs[Phase.CONCLUDE] = result.payload
            return _summary("forced_conclude" if forced else "complete", ctx)

        if count_loops(ctx.history) >= MAX_LOOPS:
            # Next legal move from the current phase must include CONCLUDE for
            # the forced path to land. Every non-terminal phase in the schema
            # already allows CONCLUDE either directly (C, SCREEN, ANALYZE) or
            # one hop away (GATHER, HYPOTHESIZE) — if the current phase can't
            # reach CONCLUDE directly, raise rather than silently extend.
            from schemas.state import TRANSITIONS

            if Phase.CONCLUDE not in TRANSITIONS[proposed]:
                raise OrchestrationError(
                    f"loop cap hit in {proposed.value} but CONCLUDE is not reachable "
                    f"in one hop; handler must route there itself"
                )
            proposed = Phase.CONCLUDE
            forced = True
            ctx.forced_conclude = True
            continue

        handler = handlers.get(proposed)
        if handler is None:
            raise OrchestrationError(f"no handler registered for phase {proposed.value}")

        result = handler(ctx)
        ctx.outputs[proposed] = result.payload
        proposed = result.next_phase


def _persist_state(ctx: Context) -> None:
    state = make_state(
        phase=ctx.current_phase.value,
        run_id=ctx.run_dir.name,
        signature_id=ctx.signature_id,
        history=list(ctx.history),
    )
    (ctx.run_dir / "state.json").write_text(json.dumps(state, indent=2))


def _summary(status: str, ctx: Context) -> dict:
    return {
        "status": status,
        "history": list(ctx.history),
        "outputs": {p.value: v for p, v in ctx.outputs.items()},
    }
