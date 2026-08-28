"""The spend ceiling: what a call costs, when the run stops, and who records it.

Split out of `driver.py` at 1221 lines. The hooks assembled here are the only place a
request is accounted, which is why a harness dispatch that bypasses them has to account
itself.
"""
from __future__ import annotations

import sys
import time
from typing import Any

from pydantic_ai.capabilities.hooks import Hooks


from . import observe
from .tools import (
    AgentDeps,
)

from defender.hooks.budget_enforcer import (
    BUDGET_EXEMPT_TOOLS,
    DEFAULT_LIMITS,
    BudgetKill,
    account_call,
    check_budgets,
    read_budget,
    refusal_message,
    should_refuse,
    tail_exhausted,
    tier,
    update_budget_locked,
)


def _budget_state_for_enforcement(state: dict, deps: AgentDeps) -> dict:
    return {**state, "started_monotonic": deps.budget_started_monotonic}


def _budget_short_circuit(
    deps: AgentDeps, tool_name: str, limits: dict,
    logger: observe.RequestLogger, agent_id: str,
) -> str | None:
    # RS16: the exemption sits AHEAD of the tail kill, not only inside `should_refuse` — the
    # tail kill is unconditional, so an exemption expressed only in the refusal check still
    # ends the run at the close. The gate's own forced turns are what push a run past the tail
    # to begin with, so closing must stay possible under exactly that pressure.
    if tool_name in BUDGET_EXEMPT_TOOLS:
        return None
    state = _budget_state_for_enforcement(read_budget(deps.run_dir), deps)
    if tail_exhausted(state, limits):
        raise BudgetKill(f"budget tail exhausted at {tool_name}")
    if should_refuse(state, tool_name, tier(tool_name, deps.role), limits):
        logger.log_budget_refusal(tool_name=tool_name, agent_id=agent_id)
        return refusal_message(state, tool_name, limits)
    return None


def _account_executed_call(deps: AgentDeps, tool_name: str, *, active: bool, limits: dict) -> None:
    try:
        call_tier = tier(tool_name, deps.role)
        if active:
            state = account_call(deps.run_dir, deps.run_id, tool_name, limits=limits, tier=call_tier)
        else:
            state = update_budget_locked(deps.run_dir, deps.run_id, tool_name, limits=limits)
        state = _budget_state_for_enforcement(state, deps)
        for w in check_budgets(state, limits):
            print(f"[run.py] {w}", file=sys.stderr)
    except BudgetKill:
        raise
    except Exception as e:  # noqa: BLE001 — budget accounting must never break the run
        print(f"[run.py] budget accounting skipped: {e!r}", file=sys.stderr)


def _stamp_duration(store: Any, session_id: str | None, duration_ms: float) -> None:
    """Write the MEASURED latency into the render's pending stamp.

    `selection.render` opens the stamp for the request it is preparing, but that request's
    duration only exists once the model has answered — here. The next round's `ingest`
    consumes the stamp, so patching it in place is what puts a real number in
    `message.duration_ms` instead of the renderer's placeholder."""
    if store is None or session_id is None:
        return
    pending = getattr(store, "pending_stamps", None)
    if not pending or session_id not in pending:
        return
    run_step, _placeholder, wire_sha = pending[session_id]
    pending[session_id] = (run_step, duration_ms, wire_sha)


def _make_hooks(  # noqa: PLR0913 — the hook set's full wiring: logging, budget, and the store stamp
    logger: observe.RequestLogger, agent_id: str, *, enforce: bool, limits: dict = DEFAULT_LIMITS,
    session_id: str | None = None, store: Any = None, toon_gate: Any = None,
) -> Hooks[Any]:
    hooks = Hooks()

    @hooks.on.tool_execute
    async def _budget(ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        deps: AgentDeps = ctx.deps
        tool_name = call.tool_name
        if enforce:
            refusal = _budget_short_circuit(deps, tool_name, limits, logger, agent_id)
            if refusal is not None:
                return refusal
        result = await handler(args)
        _account_executed_call(deps, tool_name, active=enforce, limits=limits)
        return result

    @hooks.on.model_request
    async def _log_request(ctx, *, request_context, handler):  # noqa: ANN001
        t0 = time.time()
        resp = await handler(request_context)
        duration_ms = (time.time() - t0) * 1000.0
        try:
            _stamp_duration(store, session_id, duration_ms)
            logger.log(
                request_messages=request_context.messages,
                response=resp,
                run_step=int(getattr(ctx, "run_step", 0) or 0),
                duration_ms=duration_ms,
                agent_id=agent_id,
                session_id=session_id,
                toon_gate=toon_gate.snapshot() if toon_gate is not None else None,
            )
        except Exception as e:  # noqa: BLE001
            print(f"[run.py] request logging skipped: {e!r}", file=sys.stderr)
        return resp

    return hooks
