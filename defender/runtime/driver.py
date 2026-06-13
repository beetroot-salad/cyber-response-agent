"""The PydanticAI main-agent driver — one investigation, owning the loop.

SKILL.md is the system prompt (`instructions`, verbatim — never "Read the
skill"); the four generic tools are the surface; the permission gate lives in
the tools; budget is an in-process `after_tool_execute` hook; observability is
the captured message stream. The loop is `agent.iter()` over nodes — live
observability now, and the exact seam Phase B's `ProcessHistory` compaction
plugs into (this slice passes history through unmodified).
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
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.usage import UsageLimits

from . import observe
from .tools import RunDeps, register_tools

# permission.py put defender/hooks on sys.path on import; reuse the budget logic.
from . import permission  # noqa: F401  (import for its sys.path bootstrap)
from budget_enforcer import (  # noqa: E402
    DEFAULT_LIMITS,
    check_budgets,
    update_budget_locked,
)

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_REQUEST_LIMIT = 60

# TEMPORARY (slice 1): the gather subagent / Task dispatch is not wired yet.
# Remove this note when gather lands in slice 2 — at which point the agent works
# the full ORIENT→PLAN→GATHER→ANALYZE→REPORT loop.
_SLICE1_SCAFFOLD = """
---
## Build note (temporary — this runtime is mid-migration)

The gather subagent and its `Task` dispatch are **not available in this build**.
Do not attempt to dispatch gather, run any `defender-<system>` data-source
adapter, or read `gather_raw/`. Work the loop ORIENT → PLAN → ANALYZE → REPORT
using only the alert itself plus the read-only shims (`defender-invlang`,
`defender-lessons`). If reaching a confident disposition would require gathering
data you cannot obtain, conclude `disposition: inconclusive` and say so. Always
produce both `investigation.md` (valid invlang) and `report.md`.
"""


def _build_instructions(defender_dir: Path) -> str:
    return (defender_dir / "SKILL.md").read_text() + "\n" + _SLICE1_SCAFFOLD


def _user_prompt(run_id: str, run_dir: Path, alert_path: Path) -> str:
    # Run context only — no "Read SKILL.md" (it's the system prompt).
    return (
        "Begin the investigation.\n\n"
        f"case_id: {run_id}\n"
        f"run_dir: {run_dir}\n"
        f"alert: {alert_path}\n\n"
        "The run dir already contains alert.json. Write all artifacts "
        "(investigation.md, report.md) into the run dir. Stop when both exist."
    )


def build_agent(model_name: str, defender_dir: Path) -> Agent:
    model = AnthropicModel(model_name)
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

    agent = Agent(
        model,
        deps_type=RunDeps,
        instructions=_build_instructions(defender_dir),
        capabilities=[hooks],
    )
    register_tools(agent)
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
    agent = build_agent(model_name, defender_dir)
    deps = RunDeps(
        run_dir=run_dir, defender_dir=defender_dir, run_id=run_id,
        salt=salt, is_main_session=True,
    )
    prompt = _user_prompt(run_id, run_dir, alert_path)

    t0 = time.time()
    # Hitting request_limit is an expected loop terminator, not a crash:
    # UsageLimitExceeded propagates out of `agent.iter`, but the partial
    # messages/usage stay accessible on the run object. Catch it so the trace
    # is still written and the post-steps run; let any other error stay loud.
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

    # Source messages/usage from the run, not run.result: result is None when
    # the run ends without an End node (e.g. the request-limit path above).
    result = run.result
    messages = run.all_messages()
    usage = run.usage  # property (not a method) in pydantic-ai 1.x
    observe.write_trace(
        run_dir, messages, usage,
        model=model_name, wall_ms=wall_ms,
        num_turns=int(getattr(usage, "requests", 0) or 0),
    )
    output = result.output if result is not None else None
    return {"output": output, "model": model_name, "requests": getattr(usage, "requests", 0)}
