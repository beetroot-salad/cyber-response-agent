from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from typing import Any, ClassVar, Protocol

from defender._text import is_content_less
from defender.learning.core.config import (
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    StageContext,
    StageWiring,
)
from defender.runtime import observe, providers
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel, build_agent_core

from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import UsageLimits

_logger = logging.getLogger(__name__)


class RoleDeps(Protocol):
    """What this module needs of a deps object: a type that names its role.

    Not `AgentDeps`: that is the run scope (run dir, policy, box executor), which the deny-all
    roles (questioner, judge) deliberately do not carry. `build_stage_agent` reads only
    `deps_type.role`; every `AgentDeps` subclass declares it too.
    """

    role: ClassVar[AgentRole]


def build_stage_agent(
    deps_type: type[RoleDeps],
    wiring: StageWiring,
    logger: observe.RequestLogger,
    *,
    make_model: MakeModel = providers.build_for_effort,
    tools: Any = None,
    verbs: Any = None,
) -> Agent[Any, str]:
    from defender.agents import AGENTS

    overrides: dict[str, Any] = {"model": lambda: wiring.model, "effort": wiring.effort}
    if tools is not None:
        overrides["tools"] = tools
    defn = replace(AGENTS[deps_type.role], **overrides)
    return build_agent_core(
        defn,
        deps_type=deps_type,
        instructions=wiring.prompt_path.read_text(encoding="utf-8"),  # lint-whole-read: ok — repo-shipped stage prompt; operator-controlled, not on any box-writable mount
        logger=logger,
        agent_id=wiring.label,
        make_model=make_model,
        verbs=verbs,
    )


async def _drive(
    agent: Agent[Any, str], user: str, deps: RoleDeps, request_limit: int, timeout: int
):
    return await asyncio.wait_for(
        agent.run(user, deps=deps, usage_limits=UsageLimits(request_limit=request_limit)),
        timeout=timeout,
    )


def _last_response_is_empty_text(messages: list[dict]) -> bool:
    """Whether the latest model response contains only content-less text parts."""
    for record in reversed(messages):
        if record.get("kind") != "response":
            continue
        message = record.get("message") or {}
        parts = message.get("parts") or []
        return bool(parts) and all(
            part.get("part_kind") == "text"
            and is_content_less(str(part.get("content") or ""))
            for part in parts
        )
    return False



def run_stage(
    *,
    stage: str,
    wiring: StageWiring,
    ctx: StageContext,
    deps: RoleDeps,
    make_model: MakeModel = providers.build_for_effort,
    require_output: bool = True,
    tools: Any = None,
    verbs: Any = None,
) -> str:
    """Drive one in-process stage. `wiring` is how the stage is configured, `ctx` is what
    this spawn is about."""
    label = wiring.label
    # Under `wire_logs/`, never the run dir root: the trace is the stage's whole context
    # verbatim, learning run dirs are shared, and readers of the root are not shape-filtered.
    # The wire-log policy denial (`files.names_wire_log_dir`) only covers this subdirectory.
    logger = observe.RequestLogger(
        observe.stage_trace_path(ctx.learning_run_dir, wiring.trace_name)
    )
    _logger.info(f"step={label} engine=pydantic_ai model={wiring.model} effort={wiring.effort}")
    try:
        try:
            agent = build_stage_agent(
                type(deps), wiring, logger,
                make_model=make_model, tools=tools, verbs=verbs,
            )
        except ValueError as e:
            raise FatalConfigError(f"{stage} ({label}) misconfigured: {e}") from e
        result = asyncio.run(
            _drive(agent, ctx.user, deps, ctx.request_limit, ctx.wall_clock_timeout)
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
    if require_output and is_content_less(out):
        raise RunUnprocessable(f"{stage} ({label}) returned empty output")
    return out
