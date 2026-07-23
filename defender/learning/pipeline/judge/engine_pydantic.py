from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from defender.learning.core.config import JUDGE_EFFORT, JUDGE_MODEL
from defender.learning.pipeline._pydantic_stage import build_stage_agent, run_stage
from defender.runtime import observe, providers
from defender.runtime.agent_definition import (
    AgentDefinition,
    ResolvedRoots,
    RunScope,
    ToolSet,
    bind,
)
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission.command_shape import SQL_SHIM
from defender.runtime.permission.grant import (
    TREE,
    Grant,
    PathShapes,
    program_shape,
    under,
)
from defender.runtime.tools import AgentDeps

from pydantic_ai import Agent

if TYPE_CHECKING:
    from .run import _ToolScope

JUDGE_REQUEST_LIMIT = 45

_JUDGE_DENY_REASON = (
    "Blocked: the judge is read-only over the grounded evidence — `cat <payload> | "
    "defender-sql '<SQL>'` to aggregate a gather_raw payload (cat's operands must resolve "
    "inside the read roots; the SQL runs in a sealed sandbox), and read_file (with an "
    "optional substring pattern) for everything else. Nothing else in bash: no data-source "
    "adapters, no writes, no arbitrary shell. You never need to list a directory: every "
    "payload's absolute path is named in the comparison files."
)


@dataclass(frozen=True)
class JudgeDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.JUDGE


def _judge_bash_shapes(roots: ResolvedRoots) -> tuple[Grant, ...]:
    scope = PathShapes(
        under(r.resolve(), TREE)
        for r in (roots.run_dir, roots.defender_dir, *roots.read_roots)
    )
    return (
        Grant(program="cat", pattern=program_shape("cat"), scope=scope),
        Grant(program=SQL_SHIM, pattern=program_shape(SQL_SHIM)),
    )


JUDGE_DEF = AgentDefinition(
    role=AgentRole.JUDGE,
    model=lambda: JUDGE_MODEL,
    effort=JUDGE_EFFORT,
    tools=ToolSet(read=True, bash=True),
    bash_shapes=(_judge_bash_shapes,),
    deps_cls=JudgeDeps,
    deny_reason=_JUDGE_DENY_REASON,
)


def build_judge_agent(
    prompt_path: Path, model: str, effort: str,
    logger: observe.RequestLogger, agent_id: str,
    *, make_model: MakeModel = providers.build_for_effort,
) -> Agent[JudgeDeps, str]:
    return build_stage_agent(
        JudgeDeps, prompt_path, model, effort, logger, agent_id, make_model=make_model,
    )


def _run_judge_pydantic(  # noqa: PLR0913 — the judge_fn protocol signature plus the make_model/verbs test seams; every param is load-bearing per-call state
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    *,
    scope: _ToolScope,
    salt: str | None = None,
    make_model: MakeModel = providers.build_for_effort,
    verbs: Any = None,
) -> str:
    read_roots = tuple(scope.add_dir) if isinstance(scope.add_dir, list) else ()
    deps = bind(
        JUDGE_DEF, learning_run_dir, scope=RunScope(add_dirs=read_roots), salt=salt
    )
    tools = replace(JUDGE_DEF.tools, closed_tickets=scope.closed_ticket_read)
    if verbs is None and scope.closed_ticket_read:
        from defender.runtime.verbs import ModuleVerbRegistry
        verbs = ModuleVerbRegistry(deps.defender_dir / "scripts" / "adapters")
    return run_stage(
        stage="judge",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=JUDGE_REQUEST_LIMIT, make_model=make_model,
        tools=tools, verbs=verbs,
    )
