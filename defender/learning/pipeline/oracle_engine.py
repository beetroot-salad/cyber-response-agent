from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import ORACLE_EFFORT, ORACLE_MODEL
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
    model=lambda: ORACLE_MODEL,
    effort=ORACLE_EFFORT,
    tools=ToolSet(),
    deps_cls=OracleDeps,
    deny_reason=_ORACLE_DENY_REASON,
)


def _run_oracle_pydantic(  # noqa: PLR0913 — the oracle_fn protocol signature plus the make_model test seam; every param is load-bearing per-call state
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    *,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    deps = bind(ORACLE_DEF, learning_run_dir)
    return run_stage(
        stage="oracle",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=ORACLE_REQUEST_LIMIT, make_model=make_model,
    )
