from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from defender.learning.core.config import ACTOR_EFFORT, ACTOR_MODEL, REPO_ROOT
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import (
    AgentDefinition,
    ResolvedRoots,
    RunScope,
    ToolSet,
    bind,
)
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission.grant import Grant
from defender.runtime.tools import AgentDeps

ACTOR_REQUEST_LIMIT = 30

_ACTOR_DENY_REASON = (
    "Blocked: the actor is read-only over the lessons corpora — it may run only the pinned "
    "read-only lesson scripts (lessons_env_retrieve.py; the adversarial actor also "
    "lessons_actor_index.py) plus read_file (with an optional substring pattern) under "
    "defender/. No data-source adapters, no writes, no arbitrary shell."
)


@dataclass(frozen=True)
class _ActorScope:

    scripts: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = field(kw_only=True)


@dataclass(frozen=True)
class ActorDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.ACTOR


def _script_grant(script: Path) -> Grant:
    script_abs = script.resolve()
    rel = script_abs.relative_to(REPO_ROOT.resolve())
    spellings = "|".join(re.escape(s) for s in (str(rel), str(script_abs)))
    return Grant(
        program="python3",
        pattern=re.compile(rf"^(?:[^ ]*/)?python3? (?:{spellings})(?: .*)?$"),
        pins_path=True,
    )


def _actor_bash_shapes(roots: ResolvedRoots) -> tuple[Grant, ...]:
    return tuple(_script_grant(s) for s in roots.scripts)


ACTOR_DEF = AgentDefinition(
    role=AgentRole.ACTOR,
    model=lambda: ACTOR_MODEL,
    effort=ACTOR_EFFORT,
    tools=ToolSet(read=True, bash=True),
    bash_shapes=(_actor_bash_shapes,),
    deps_cls=ActorDeps,
    requires_confine=True,
    deny_reason=_ACTOR_DENY_REASON,
)


def _run_actor_pydantic(  # noqa: PLR0913 — the actor_fn protocol signature plus the make_model test seam; every param is load-bearing per-call state
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    *,
    scope: _ActorScope,
    salt: str | None = None,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    deps = bind(
        ACTOR_DEF, learning_run_dir,
        scope=RunScope(scripts=scope.scripts, read_confine=scope.read_confine),
        salt=salt,
    )
    return run_stage(
        stage="actor",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=ACTOR_REQUEST_LIMIT, make_model=make_model,
    )
