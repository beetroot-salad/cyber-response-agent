from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import (
    StageContext,
    StageWiring,
    oracle_effort,
    oracle_model,
    subagent_timeout,
)
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.tools import AgentDeps

ORACLE_REQUEST_LIMIT = 1

_ORACLE_DENY_REASON = (
    "Blocked: the oracle is a pure per-lead projection — its entire input is inlined in the user "
    "prompt and its entire output is one YAML document. It runs no tools: no data-source adapters, "
    "no gather_raw reads, no writes, no shell. Emit the events YAML directly."
)


@dataclass(frozen=True)
class OracleDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.ORACLE


ORACLE_DEF = AgentDefinition(
    role=AgentRole.ORACLE,
    model=oracle_model,
    effort=oracle_effort(),
    tools=ToolSet(),
    deps_cls=OracleDeps,
    deny_reason=_ORACLE_DENY_REASON,
)


def _run_oracle_pydantic(
    wiring: StageWiring,
    *,
    user: str,
    learning_run_dir: Path,
    salt: str | None = None,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """The oracle's limits are stage-fixed, so the context is built HERE rather than taken
    from the caller — `subagent_timeout()` is read at spawn, never frozen at import (#717).

    The context is built FIRST and `bind` reads the salt off it, so `ctx.salt` is what the
    agent was actually bound with rather than a second copy nothing reads."""
    ctx = StageContext(
        learning_run_dir=learning_run_dir, user=user,
        request_limit=ORACLE_REQUEST_LIMIT,
        wall_clock_timeout=subagent_timeout(),
        salt=salt,
    )
    deps = bind(ORACLE_DEF, ctx.learning_run_dir, salt=ctx.salt)
    return run_stage(stage="oracle", wiring=wiring, ctx=ctx, deps=deps, make_model=make_model)
