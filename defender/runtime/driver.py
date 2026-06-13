"""The PydanticAI main-agent driver — one investigation, owning the loop.

SKILL.md is the system prompt (`instructions`, verbatim — never "Read the
skill"); the four generic tools are the surface; the permission gate lives in
the tools; budget is an in-process `after_tool_execute` hook; observability is a
`wrap_model_request` hook logging every API request live to `llm_requests.jsonl`
(observe.py projects `tool_trace.jsonl` from it). The loop is `agent.iter()` over
nodes — the exact seam Phase B's `ProcessHistory` compaction plugs into (this
slice passes history through unmodified).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.capabilities.hooks import Hooks
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models.anthropic import AnthropicModel, AnthropicModelSettings
from pydantic_ai.usage import UsageLimits

from . import observe
from .tools import GatherDeps, RunDeps, register_gather_tool, register_tools

# permission.py put defender/hooks on sys.path on import; reuse the budget logic.
from . import permission  # noqa: F401  (import for its sys.path bootstrap)
from budget_enforcer import (  # noqa: E402
    DEFAULT_LIMITS,
    check_budgets,
    update_budget_locked,
)

DEFAULT_MODEL = "claude-sonnet-4-6"
GATHER_MODEL = "claude-haiku-4-5"
DEFAULT_REQUEST_LIMIT = 60
GATHER_REQUEST_LIMIT = 20  # gather is a short, mechanical loop per lead
# The permission gate denies disallowed tool calls via ModelRetry — control-flow
# feedback ("pick another command"), the in-process twin of the claude -p hook's
# exit-2, not a hard error. pydantic-ai resets a tool's retry counter on success,
# so this budget bounds only *consecutive* denials/errors; the request limit caps
# total work. max_retries=1 (the default) would abort the run on the 2nd back-to-
# back gate denial — far too brittle for a gate used as feedback.
DEFAULT_TOOL_RETRIES = 10

# Cache the byte-stable preamble — the SKILL system prompt (~9K tokens, re-sent
# every request) and the tool schemas — so only the growing message tail is
# uncached. Message-level caching is Phase B; instructions/tools are stable per
# run, so this is a safe, immediate win on the slice-1 cache=0 baseline.
_CACHE_SETTINGS = AnthropicModelSettings(
    anthropic_cache_instructions="1h",
    anthropic_cache_tool_definitions="1h",
)


def _main_instructions(defender_dir: Path) -> str:
    return (defender_dir / "SKILL.md").read_text()


def _gather_instructions(defender_dir: Path) -> str:
    return (defender_dir / "skills" / "gather" / "SKILL.md").read_text()


def _user_prompt(run_dir: Path, alert_path: Path) -> str:
    # Run context only. The procedure — artifacts to write, the stop condition,
    # case_id (= the run-dir basename) — all lives in SKILL.md, the system
    # prompt; don't restate it, and don't say "Read SKILL.md" (it IS the prompt).
    return (
        "Begin the investigation.\n\n"
        f"run_dir: {run_dir}\n"
        f"alert: {alert_path}\n"
    )


def _make_hooks(logger: observe.RequestLogger, agent_id: str) -> Hooks:
    """The budget + observability hooks, shared by the main and gather agents.
    `agent_id` tags this instance's logged requests ("main" / "gather:{lead_id}")
    and binds the same run-scoped budget (keyed by run_dir, locked)."""
    hooks = Hooks()

    @hooks.on.after_tool_execute
    async def _budget(ctx, *, call, tool_def, args, result):  # noqa: ANN001
        # Warning-only budget accounting, same caps as the claude -p enforcer.
        try:
            deps: RunDeps = ctx.deps
            state = update_budget_locked(deps.run_dir, deps.run_id, call.tool_name)
            for w in check_budgets(state, DEFAULT_LIMITS):
                print(f"[run_pai] {w}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — budget must never break the run
            print(f"[run_pai] budget accounting skipped: {e!r}", file=sys.stderr)
        return result

    @hooks.on.model_request  # the wrap-style model-request hook
    async def _log_request(ctx, *, request_context, handler):  # noqa: ANN001
        # The single observability site: log every API request's full input,
        # output, usage, and timing at the boundary, tagged by agent instance
        # (observe.py projects the main-only trace from these). Never break the run.
        t0 = time.time()
        resp = await handler(request_context)
        try:
            logger.log(
                request_messages=request_context.messages,
                response=resp,
                run_step=int(getattr(ctx, "run_step", 0) or 0),
                duration_ms=(time.time() - t0) * 1000.0,
                agent_id=agent_id,
            )
        except Exception as e:  # noqa: BLE001
            print(f"[run_pai] request logging skipped: {e!r}", file=sys.stderr)
        return resp

    return hooks


def build_gather_agent(defender_dir: Path, logger: observe.RequestLogger, agent_id: str) -> Agent:
    """A nested gather subagent: Haiku, the gather SKILL as its system prompt, the
    same generic tools (the bash tool auto-captures adapter calls under
    `is_main_session=False`). One per dispatch so `agent_id` binds to the lead."""
    agent = Agent(
        AnthropicModel(GATHER_MODEL),
        deps_type=GatherDeps,
        instructions=_gather_instructions(defender_dir),
        capabilities=[_make_hooks(logger, agent_id)],
        model_settings=_CACHE_SETTINGS,
        retries=DEFAULT_TOOL_RETRIES,
    )
    register_tools(agent)
    return agent


def build_agent(model_name: str, defender_dir: Path, logger: observe.RequestLogger) -> Agent:
    agent = Agent(
        AnthropicModel(model_name),
        deps_type=RunDeps,
        instructions=_main_instructions(defender_dir),
        capabilities=[_make_hooks(logger, "main")],
        model_settings=_CACHE_SETTINGS,
        retries=DEFAULT_TOOL_RETRIES,
    )
    register_tools(agent)
    # The gather dispatch tool builds a fresh nested gather agent per lead.
    register_gather_tool(
        agent,
        lambda agent_id: build_gather_agent(defender_dir, logger, agent_id),
        GATHER_REQUEST_LIMIT,
    )
    return agent


def _log_node(node: Any) -> None:
    if Agent.is_model_request_node(node):
        print("[run_pai] · model request", file=sys.stderr)
    elif Agent.is_call_tools_node(node):
        print("[run_pai] · tool calls", file=sys.stderr)
    elif Agent.is_end_node(node):
        print("[run_pai] · end", file=sys.stderr)


async def run_investigation(
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
    defender_dir: Path,
    salt: str,
    model_name: str | None = None,
) -> dict:
    """Run one investigation end-to-end; emit the trace; return a small summary."""
    model_name = model_name or os.environ.get("DEFENDER_MODEL") or DEFAULT_MODEL
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    agent = build_agent(model_name, defender_dir, logger)
    deps = RunDeps(
        run_dir=run_dir, defender_dir=defender_dir, run_id=run_id,
        salt=salt, is_main_session=True,
    )
    prompt = _user_prompt(run_dir, alert_path)

    t0 = time.time()
    # Hitting request_limit is an expected loop terminator, not a crash:
    # UsageLimitExceeded propagates out of `agent.iter`. Catch it so the
    # post-steps run; every request up to the limit is already in the live
    # request log either way. Let any other error stay loud.
    try:
        async with agent.iter(
            prompt, deps=deps,
            usage_limits=UsageLimits(request_limit=DEFAULT_REQUEST_LIMIT),
        ) as run:
            async for node in run:
                _log_node(node)
    except UsageLimitExceeded as e:
        print(f"[run_pai] request limit reached ({e}); writing partial trace",
              file=sys.stderr)
    wall_ms = (time.time() - t0) * 1000.0

    # result is None when the run ends without an End node (e.g. the request-limit
    # path above). The trace is projected from the live request log, not the run
    # object, so it survives that case (and a crash) unchanged.
    result = run.result
    observe.write_trace(run_dir, logger.records, model=model_name, wall_ms=wall_ms)
    logger.close()
    output = result.output if result is not None else None
    return {"output": output, "model": model_name, "requests": len(logger.records)}
