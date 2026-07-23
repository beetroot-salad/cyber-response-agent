from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from typing import Any

from defender.learning.core.config import (
    SUBAGENT_TIMEOUT,
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    _log,
)
from defender.runtime import observe, providers
from defender.runtime.driver import MakeModel, build_agent_core
from defender.runtime.tools import AgentDeps

from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import UsageLimits


def build_stage_agent(  # noqa: PLR0913 — the stage-build seam plus the make_model/tools/verbs DI seams; every param is load-bearing
    deps_type: type[AgentDeps],
    prompt_path: Path,
    model: str,
    effort: str | None,
    logger: observe.RequestLogger,
    label: str,
    *,
    make_model: MakeModel = providers.build_for_effort,
    tools: Any = None,
    verbs: Any = None,
) -> Agent[Any, str]:
    from defender.agents import AGENTS

    overrides: dict[str, Any] = {"model": lambda: model, "effort": effort}
    if tools is not None:
        overrides["tools"] = tools
    defn = replace(AGENTS[deps_type.role], **overrides)
    return build_agent_core(
        defn,
        deps_type=deps_type,
        instructions=prompt_path.read_text(encoding="utf-8"),
        logger=logger,
        agent_id=label,
        make_model=make_model,
        verbs=verbs,
    )


async def _drive(
    agent: Agent[Any, str], user: str, deps: AgentDeps, request_limit: int, timeout: int
):
    return await asyncio.wait_for(
        agent.run(user, deps=deps, usage_limits=UsageLimits(request_limit=request_limit)),
        timeout=timeout,
    )

def _last_response_is_empty_text(messages: list[dict]) -> bool:
    """Whether the latest model response contains only empty text parts."""
    for record in reversed(messages):
        if record.get("kind") != "response":
            continue
        message = record.get("message") or {}
        parts = message.get("parts") or []
        return bool(parts) and all(
            part.get("part_kind") == "text"
            and not str(part.get("content") or "").strip()
            for part in parts
        )
    return False



def run_stage(  # noqa: PLR0913 — every param is load-bearing per-call transport state
    *,
    stage: str,
    prompt_path: Path,
    model: str,
    effort: str | None,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    deps: AgentDeps,
    request_limit: int,
    make_model: MakeModel = providers.build_for_effort,
    require_output: bool = True,
    wall_clock_timeout: int = SUBAGENT_TIMEOUT,
    tools: Any = None,
    verbs: Any = None,
) -> str:
    logger = observe.RequestLogger(learning_run_dir / trace_name)
    _log(f"step={label} engine=pydantic_ai model={model} effort={effort}")
    try:
        try:
            agent = build_stage_agent(
                type(deps), prompt_path, model, effort, logger, label,
                make_model=make_model, tools=tools, verbs=verbs,
            )
        except ValueError as e:
            raise FatalConfigError(f"{stage} ({label}) misconfigured: {e}") from e
        result = asyncio.run(
            _drive(agent, user, deps, request_limit, wall_clock_timeout)
        )
    except (TimeoutError, UsageLimitExceeded) as e:
        if require_output and _last_response_is_empty_text(logger.messages):
            raise RunUnprocessable(f"{stage} ({label}) returned empty output") from e
        raise RunUnprocessable(f"{stage} ({label}) did not complete: {e!r}") from e
    except (StageAbort, FatalConfigError):
        raise
    except Exception as e:
        if require_output and _last_response_is_empty_text(logger.messages):
            raise RunUnprocessable(f"{stage} ({label}) returned empty output") from e
        raise RunUnprocessable(f"{stage} ({label}) failed: {e!r}") from e
    finally:
        logger.close()
    out = str(result.output or "")
    if require_output and not out.strip():
        raise RunUnprocessable(f"{stage} ({label}) returned empty output")
    return out
