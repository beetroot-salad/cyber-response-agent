"""The spend ceiling: what a call costs, when the run stops, and who records it.

These hooks are the only place a request is accounted; a harness dispatch that bypasses them
must account itself. They count on the run's `RunState` the deps carry (#1235). An enforced role
(`budget_enforced`: MAIN and gather) needs one: deps that carry none are a wiring fault, and its
first tool call raises (`run_state_of`) rather than run with no budget at all. A role that is
not enforced may carry none — a learning stage, a review role — and then nothing is counted.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from pydantic_ai.capabilities.hooks import Hooks


from .. import observe
from ..run_state import RunState, run_state_of
from ..verbs import ServingAbort
from ..tools import (
    AgentDeps,
)

from defender.hooks.budget_enforcer import (
    BUDGET_EXEMPT_TOOLS,
    DEFAULT_LIMITS,
    BudgetKill,
    account_call,
    check_budgets,
    count_call,
    enforcement_state,
    refusal_message,
    should_refuse,
    tail_exhausted,
    tier,
)

_logger = logging.getLogger(__name__)


def _budget_short_circuit(
    deps: AgentDeps, tool_name: str, limits: dict,
    logger: observe.RequestLogger, agent_id: str,
) -> str | None:
    """The enforced posture's check ahead of a call: `BudgetKill` past the tail, the refusal
    text at a cap, else `None`. Deps with no run state raise (`run_state_of`)."""
    # Exemption before the unconditional tail kill: the review gate's forced turns can push a
    # run past the tail, and closing must stay possible then.
    if tool_name in BUDGET_EXEMPT_TOOLS:
        return None
    state = enforcement_state(run_state_of(deps))
    if tail_exhausted(state, limits):
        raise BudgetKill(f"budget tail exhausted at {tool_name}")
    if should_refuse(state, tool_name, tier(tool_name, deps.role), limits):
        logger.log_budget_refusal(tool_name=tool_name, agent_id=agent_id)
        return refusal_message(state, tool_name, limits)
    return None


def _account_executed_call(deps: AgentDeps, tool_name: str, *, active: bool, limits: dict) -> None:
    """Count one executed call on the run's state: against the cap when `active` (the enforced
    posture, whose deps must carry a state — `run_state_of` raises otherwise), with no cap check
    when not (deps carrying no state then count nothing). Logs the budget warnings after."""
    run_state: RunState | None = run_state_of(deps) if active else deps.run_state
    if run_state is None:
        return
    if active:
        account_call(run_state, tool_name, limits=limits, tier=tier(tool_name, deps.role))
    else:
        count_call(run_state, tool_name)
    for w in check_budgets(enforcement_state(run_state), limits):
        _logger.warning(f"{w}")


def _stamp_duration(store: Any, session_id: str | None, duration_ms: float) -> None:
    """Write the measured latency into the render's pending stamp, replacing the placeholder
    before the next round's `ingest` consumes it."""
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
        try:
            result = await handler(args)
        except ServingAbort:
            # The call was made, and its world gave up under it (#1224): it still counts as
            # the one investigator call it was, as on a run whose world served it.
            _account_executed_call(deps, tool_name, active=enforce, limits=limits)
            raise
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
            _logger.warning(f"request logging skipped: {e!r}")
        return resp

    return hooks
