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
from defender.learning._pydantic_stage import build_stage_agent, run_stage
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


def _judge_grant() -> VerbGrant:
    """The benign judge's read-only ticket grant, projected from the verb-disposition table.

    It used to be a second hand-written tuple of pairs, in this package, with the gather grant
    a third in another one — so the only file where the whole census appeared together was a
    test. Both roles now read the one table (#995); the adversarial stage still never reaches
    the closed-ticket store, because `_run_judge_pydantic` replaces this grant with `DENY_ALL`
    when it switches that capability off.

    `shipped_dispositions`, not a `load_dispositions` of its own: the driver's gather
    projection reads the same rows at the same startup, and a second load here is a second
    read of a file both halves must agree about — one table, one loader.
    """
    from defender.runtime.verb_dispositions import grant_for, shipped_dispositions

    return grant_for(AgentRole.JUDGE.value, shipped_dispositions())


JUDGE_DEF = AgentDefinition(
    role=AgentRole.JUDGE,
    model=judge_model,
    effort=judge_effort(),
    # closed_tickets stays False here, so a generic build (build_judge_agent with no verbs=, a
    # permission-gate probe) never demands a registry it wasn't handed. `_run_judge_pydantic`
    # is the ONLY site that turns the bit on, via a replace() that scopes the verb_grant beside
    # it in the SAME step.
    tools=ToolSet(read=True, bash=True),
    bash_shapes=(_judge_bash_shapes,),
    deps_cls=JudgeDeps,
    deny_reason=_JUDGE_DENY_REASON,
    verb_grant=_judge_grant(),
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
    from the caller — `subagent_timeout()` is read at spawn, never frozen at import.

    The context is built FIRST and `bind` reads the transport off it, so `ctx.box` is what the
    agent was actually bound with rather than a second copy nothing reads. `ctx.salt` is NOT
    bound: it scopes this stage's PROMPT frames — the set `stage_user_message` announces as one
    message — and a tool return is framed by `wrap_fresh`, which mints its own."""
    read_roots = tuple(scope.add_dir) if isinstance(scope.add_dir, list) else ()
    ctx = StageContext(
        learning_run_dir=learning_run_dir, user=user,
        request_limit=JUDGE_REQUEST_LIMIT,
        wall_clock_timeout=subagent_timeout(),
        box=box, salt=salt,
    )
    tools = replace(JUDGE_DEF.tools, closed_tickets=scope.closed_ticket_read)
    # The SAME replace() that sets the capability bit scopes the grant beside it — a build with
    # the tool off is handed the empty deny-all, so bit and grant cannot disagree at a stage
    # whose definition it shares with a capability-ON sibling (adversarial shares JUDGE_DEF
    # with benign).
    effective_grant = JUDGE_DEF.verb_grant if tools.closed_tickets else DENY_ALL
    scoped_def = replace(JUDGE_DEF, tools=tools, verb_grant=effective_grant)
    deps = bind(
        scoped_def, ctx.learning_run_dir, scope=RunScope(add_dirs=read_roots),
        box=ctx.box,
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
