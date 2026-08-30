from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any, ClassVar, Protocol

from defender._text import is_content_less
from defender.learning.core.config import (
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    StageContext,
    StageWiring,
    _log,
)
from defender.runtime import observe, providers
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel, build_agent_core

from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import UsageLimits


class RoleDeps(Protocol):
    """What this module actually needs of a deps object: a TYPE that names its role.

    `AgentDeps` was the annotation, and it is too narrow by exactly one role. `AgentDeps` IS the
    run scope — run dir, compiled policy, box executor, cwd anchor — and #947's questioner
    deliberately carries none of it: its whole input is inlined in one user message by the host,
    so a deps object with eleven handles on a tree it may not touch is the thing that class
    exists not to be. Nothing below reads any of those fields. `build_stage_agent` reads
    `deps_type.role` to find the definition, and `agent.run` hands the object to tools this role
    does not have.

    So the annotation says that and no more. Every existing caller still satisfies it — each
    `AgentDeps` subclass declares `role` — and a deps class that names no role is refused at the
    type level rather than at `AGENTS[...]` with a `KeyError`.
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
        instructions=wiring.prompt_path.read_text(encoding="utf-8"),
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
    # `<root>/wire_logs/<trace>`, never the root itself: this stream is the stage's whole
    # context verbatim, and learning run dirs are SHARED — both legs of an `inconclusive` case
    # run concurrently against one dir, and a re-LEARN reopens it. The gray-box actor reads
    # that root with NO shape filter, so a judge trace at the root would hand it the
    # UNREDACTED payload exemplars (`judge/compare.unredacted_exemplar`) that `decide_read`'s
    # gather_raw deny withholds. `files.names_wire_log_dir` refuses the read; this puts the
    # file where it can.
    logger = observe.RequestLogger(
        observe.stage_trace_path(ctx.learning_run_dir, wiring.trace_name)
    )
    _log(f"step={label} engine=pydantic_ai model={wiring.model} effort={wiring.effort}")
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
