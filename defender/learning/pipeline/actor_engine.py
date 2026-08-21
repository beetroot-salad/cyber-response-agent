from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from defender.learning.core.config import (
    REPO_ROOT,
    StageContext,
    StageWiring,
    actor_effort,
    actor_model,
    subagent_timeout,
)
from defender.learning._pydantic_stage import run_stage
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
    model=actor_model,
    effort=actor_effort(),
    tools=ToolSet(read=True, bash=True),
    bash_shapes=(_actor_bash_shapes,),
    deps_cls=ActorDeps,
    requires_confine=True,
    # cwd_anchor is repo_root (defender_dir.parent): the box's `--workdir` is the auto-created
    # ro PARENT of the defender infra mount, so a relative `python3 defender/...` operand
    # resolves there instead of at learning_run_dir, where no `defender/` exists.
    anchors_on_tree=True,
    deny_reason=_ACTOR_DENY_REASON,
)


def _run_actor_pydantic(
    wiring: StageWiring,
    *,
    user: str,
    learning_run_dir: Path,
    scope: _ActorScope,
    salt: str | None = None,
    box: Any = None,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """The actor's limits are stage-fixed, so the context is built HERE rather than taken
    from the caller — `subagent_timeout()` is read at spawn, never frozen at import.

    The context is built FIRST and `bind` reads the transport off it; binding off the flat
    parameters would leave `ctx.box` a second copy nothing reads, free to diverge from what the
    agent was actually bound with. `ctx.salt` is NOT bound: it scopes this stage's PROMPT
    frames, while a tool return is framed by `wrap_fresh`, which mints its own."""
    ctx = StageContext(
        learning_run_dir=learning_run_dir, user=user,
        request_limit=ACTOR_REQUEST_LIMIT,
        wall_clock_timeout=subagent_timeout(),
        box=box, salt=salt,
    )
    deps = bind(
        ACTOR_DEF, ctx.learning_run_dir,
        scope=RunScope(scripts=scope.scripts, read_confine=scope.read_confine),
        box=ctx.box,
    )
    return run_stage(stage="actor", wiring=wiring, ctx=ctx, deps=deps, make_model=make_model)
