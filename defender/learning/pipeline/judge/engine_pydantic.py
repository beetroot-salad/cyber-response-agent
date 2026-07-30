from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from defender.learning.core.config import (
    StageContext,
    StageWiring,
    judge_effort,
    judge_model,
    subagent_timeout,
)
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
from defender.runtime.verb_grant import DENY_ALL, VerbGrant

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


#: The benign judge's read-only ticket grant (#632, c18) — the two verbs the runtime's own
#: `query` tool never uses (`get-ticket`, `key-pattern`), plus `list-tickets`. The adversarial
#: stage never reads the closed-ticket store; see `_run_judge_pydantic`'s scoping for how the
#: same definition builds with this grant EMPTIED when that stage switches its capability off.
JUDGE_TICKET_PAIRS: tuple[tuple[str, str], ...] = (
    ("ticket", "get-ticket"), ("ticket", "key-pattern"), ("ticket", "list-tickets"),
)

JUDGE_DEF = AgentDefinition(
    role=AgentRole.JUDGE,
    model=judge_model,
    effort=judge_effort(),
    # closed_tickets stays False here — every ToolSet bit on JUDGE_DEF defaults False, so a
    # generic build (build_judge_agent with no verbs=, a permission-gate probe) never demands
    # a registry it wasn't handed. `_run_judge_pydantic` is the ONLY site that turns this bit
    # on, via a runtime replace() that scopes the verb_grant beside it in the SAME step (d73) —
    # so the real per-leg build never sees this static default at all, agreeing or not.
    tools=ToolSet(read=True, bash=True),
    bash_shapes=(_judge_bash_shapes,),
    deps_cls=JudgeDeps,
    deny_reason=_JUDGE_DENY_REASON,
    verb_grant=VerbGrant(
        role=AgentRole.JUDGE.value,
        entries=tuple((s, v, "r") for s, v in JUDGE_TICKET_PAIRS),
    ),
)


def build_judge_agent(
    wiring: StageWiring, logger: observe.RequestLogger,
    *, make_model: MakeModel = providers.build_for_effort,
) -> Agent[JudgeDeps, str]:
    return build_stage_agent(JudgeDeps, wiring, logger, make_model=make_model)


def _run_judge_pydantic(
    wiring: StageWiring,
    *,
    user: str,
    learning_run_dir: Path,
    scope: _ToolScope,
    salt: str | None = None,
    box: Any = None,
    make_model: MakeModel = providers.build_for_effort,
    verbs: Any = None,
) -> str:
    """The judge's limits are stage-fixed, so the context is built HERE rather than taken
    from the caller — `subagent_timeout()` is read at spawn, never frozen at import (#717).

    The context is built FIRST and `bind` reads the transport off it, so `ctx.box`/`ctx.salt`
    are what the agent was actually bound with rather than a second copy nothing reads."""
    read_roots = tuple(scope.add_dir) if isinstance(scope.add_dir, list) else ()
    ctx = StageContext(
        learning_run_dir=learning_run_dir, user=user,
        request_limit=JUDGE_REQUEST_LIMIT,
        wall_clock_timeout=subagent_timeout(),
        box=box, salt=salt,
    )
    tools = replace(JUDGE_DEF.tools, closed_tickets=scope.closed_ticket_read)
    # d73: the SAME runtime replace() that sets the capability bit scopes the grant beside
    # it — a build with the tool off is handed the empty deny-all, so the disagreement §7 R7
    # forbids cannot arise at a stage whose grant lives on a definition it shares with a
    # capability-ON sibling (the adversarial judge shares JUDGE_DEF with the benign one).
    effective_grant = JUDGE_DEF.verb_grant if tools.closed_tickets else DENY_ALL
    scoped_def = replace(JUDGE_DEF, tools=tools, verb_grant=effective_grant)
    deps = bind(
        scoped_def, ctx.learning_run_dir, scope=RunScope(add_dirs=read_roots),
        salt=ctx.salt, box=ctx.box,
    )
    if tools.closed_tickets:
        if verbs is None:
            from defender.runtime.verbs import ModuleVerbRegistry
            verbs = ModuleVerbRegistry(deps.defender_dir / "scripts" / "adapters", effective_grant)
        from defender.runtime.verb_grant import GrantError
        from defender.runtime.verbs import VerbRegistry
        if not isinstance(verbs, VerbRegistry):
            raise TypeError(
                f"the closed-ticket tools need a real VerbRegistry, got {type(verbs).__name__}"
            )
        if not verbs.grant.entries:
            raise GrantError(
                "the judge's closed-ticket capability is on but the verb registry handed to "
                "the stage carries an empty grant — a capability with nothing behind it"
            )
    return run_stage(
        stage="judge", wiring=wiring, ctx=ctx,
        deps=deps, make_model=make_model, tools=tools, verbs=verbs,
    )
