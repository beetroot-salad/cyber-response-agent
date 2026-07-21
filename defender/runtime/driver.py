
from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import ProcessHistory
from pydantic_ai.capabilities.hooks import Hooks
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelMessagesTypeAdapter
from pydantic_ai.usage import UsageLimits

from . import compaction
from . import observe
from . import orient
from . import permission
from . import providers
from .agent_definition import AgentDefinition, ResolvedRoots, ToolSet, bind
from .agent_role import AgentRole
from .circuit_breaker import RunAborted
from .permission.policies import _common
from .providers import BuiltModel
from .tools import (
    AgentDeps,
    GatherDeps,
    register_gather_tool,
    register_tools,
)
from .verbs import ModuleVerbRegistry

from defender._env import env_bool
from defender._run_paths import RunPaths
from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    BudgetKill,
    account_call,
    check_budgets,
    open_budget,
    read_budget,
    refusal_message,
    should_refuse,
    tail_exhausted,
    tier,
    update_budget_locked,
)

BUDGET_ENFORCE_FLAG = "DEFENDER_BUDGET_ENFORCE"


def enforcement_enabled() -> bool:
    return env_bool(BUDGET_ENFORCE_FLAG, False)

DEFAULT_MODEL = "glm-5.2"
DEFAULT_GATHER_MODEL = "kimi-k2.6"
DEFAULT_REQUEST_LIMIT = 60
GATHER_REQUEST_LIMIT = 40
DEFAULT_TOOL_RETRIES = 10



def _main_instructions(defender_dir: Path) -> str:
    return (defender_dir / "SKILL.md").read_text(encoding="utf-8")


def _user_prompt(run_dir: Path, alert_path: Path, defender_dir: Path, salt: str) -> str:
    orientation = orient.orientation(run_dir, defender_dir, alert_path, salt)
    return (
        "Begin the investigation.\n\n"
        f"run_dir: {run_dir}\n"
        f"alert: {alert_path}\n\n"
        f"{orientation}"
    )


def _budget_short_circuit(
    deps: AgentDeps, tool_name: str, limits: dict,
    logger: observe.RequestLogger, agent_id: str,
) -> str | None:
    state = read_budget(deps.run_dir)
    if tail_exhausted(state, limits):
        raise BudgetKill(f"budget tail exhausted at {tool_name}")
    if should_refuse(state, tool_name, tier(tool_name, deps.role), limits):
        logger.log_budget_refusal(tool_name=tool_name, agent_id=agent_id)
        return refusal_message(state, tool_name, limits)
    return None


def _account_executed_call(deps: AgentDeps, tool_name: str, *, active: bool, limits: dict) -> None:
    try:
        call_tier = tier(tool_name, deps.role)
        if active:
            state = account_call(deps.run_dir, deps.run_id, tool_name, limits=limits, tier=call_tier)
        else:
            state = update_budget_locked(deps.run_dir, deps.run_id, tool_name, limits=limits)
        for w in check_budgets(state, limits):
            print(f"[run.py] {w}", file=sys.stderr)
    except BudgetKill:
        raise
    except Exception as e:  # noqa: BLE001 — budget accounting must never break the run
        print(f"[run.py] budget accounting skipped: {e!r}", file=sys.stderr)


def _make_hooks(
    logger: observe.RequestLogger, agent_id: str, *, enforce: bool, limits: dict = DEFAULT_LIMITS,
) -> Hooks[Any]:
    hooks = Hooks()

    @hooks.on.tool_execute
    async def _budget(ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        deps: AgentDeps = ctx.deps
        tool_name = call.tool_name
        if enforce:
            refusal = _budget_short_circuit(deps, tool_name, limits, logger, agent_id)
            if refusal is not None:
                return refusal
        result = await handler(args)
        _account_executed_call(deps, tool_name, active=enforce, limits=limits)
        return result

    @hooks.on.model_request
    async def _log_request(ctx, *, request_context, handler):  # noqa: ANN001
        t0 = time.time()
        resp = await handler(request_context)
        try:
            logger.log(
                request_messages=request_context.messages,
                response=resp,
                run_step=int(getattr(ctx, "run_step", 0) or 0),
                duration_ms=(time.time() - t0) * 1000.0,
                agent_id=agent_id,
            )
        except Exception as e:  # noqa: BLE001
            print(f"[run.py] request logging skipped: {e!r}", file=sys.stderr)
        return resp

    return hooks


def gather_model() -> str:
    return os.environ.get("DEFENDER_GATHER_MODEL") or DEFAULT_GATHER_MODEL




MakeModel = Callable[[str, str | None], BuiltModel]


def build_agent_core(  # noqa: PLR0913 — the single build site's config + 3 DI seams (make_model/verbs/limits); every param is load-bearing per-build
    defn: AgentDefinition,
    *,
    deps_type: type,
    instructions: str,
    logger: observe.RequestLogger,
    agent_id: str,
    extra_capabilities: Sequence[Any] = (),
    make_model: MakeModel = providers.build_for_effort,
    verbs: Any = None,
    limits: dict = DEFAULT_LIMITS,
) -> Agent[Any, str]:
    built = make_model(defn.model(), defn.effort)
    capabilities: list[Any] = [
        _make_hooks(logger, agent_id, enforce=defn.budget_enforced, limits=limits),
        *extra_capabilities,
    ]
    if defn.tools.query:
        from defender._paths import PATHS

        from .query_tool import QueryCapture

        if verbs is None:
            verbs = ModuleVerbRegistry(PATHS.defender_dir / "scripts" / "adapters")
        capabilities.append(QueryCapture(verbs))
    agent: Agent[Any, str] = Agent(
        built.model,
        deps_type=deps_type,
        instructions=instructions,
        capabilities=capabilities,
        model_settings=built.settings,
        retries=DEFAULT_TOOL_RETRIES,
    )
    register_tools(agent, defn.tools, verbs)
    return agent


def resolve_main_model(explicit: str | None = None) -> str:
    return explicit or os.environ.get("DEFENDER_MODEL") or DEFAULT_MODEL


_CORPUS_DIRS = ("lessons", "skills", "examples")


def _main_bash_shapes(roots: ResolvedRoots) -> tuple[Any, ...]:
    return _common.reader_grants(roots.run_dir, roots.defender_dir, raw=False)


def _gather_bash_shapes(roots: ResolvedRoots) -> tuple[Any, ...]:
    return _common.reader_grants(roots.run_dir, roots.defender_dir, raw=True)


def _main_write_shape(roots: ResolvedRoots) -> tuple[Any, ...]:
    return permission.build_named_write_allow(roots.run_dir, ("investigation.md", "report.md"))


MAIN_DEF = AgentDefinition(
    role=AgentRole.MAIN,
    model=resolve_main_model,
    effort="low",
    tools=ToolSet(read=True, bash=True, write=True),
    corpus_dirs=_CORPUS_DIRS,
    bash_shapes=(_main_bash_shapes,),
    write_shapes=(_main_write_shape,),
    deps_cls=AgentDeps,
    deny_reason=permission.FALLTHROUGH_DENY_REASON,
    budget_enforced=True,
)

GATHER_DEF = AgentDefinition(
    role=AgentRole.GATHER,
    model=gather_model,
    effort="none",
    tools=ToolSet(read=True, bash=True, template_search=True, query=True),
    corpus_dirs=_CORPUS_DIRS,
    bash_shapes=(_gather_bash_shapes,),
    deps_cls=GatherDeps,
    deny_reason=permission.GATHER_FALLTHROUGH_DENY_REASON,
    budget_enforced=True,
)


def _gather_instructions(defender_dir: Path) -> str:
    return (defender_dir / "skills" / "gather" / "SKILL.md").read_text(encoding="utf-8")


def build_gather_agent(
    defender_dir: Path, logger: observe.RequestLogger, agent_id: str,
    make_model: MakeModel = providers.build_for_effort,
    verbs: Any = None,
    limits: dict = DEFAULT_LIMITS,
) -> Agent[GatherDeps, str]:
    name = gather_model()
    return build_agent_core(
        replace(
            GATHER_DEF, model=lambda: name,
            effort=providers.effort_for_role(name, AgentRole.GATHER),
            budget_enforced=GATHER_DEF.budget_enforced and enforcement_enabled(),
        ),
        deps_type=GatherDeps,
        instructions=_gather_instructions(defender_dir),
        logger=logger,
        agent_id=agent_id,
        make_model=make_model,
        verbs=verbs,
        limits=limits,
    )




def _compaction_enabled() -> bool:
    return env_bool("DEFENDER_COMPACTION", False)


def _summary_pointers(run_dir: Path) -> dict[str, str]:
    d = run_dir / "gather_summaries"
    if not d.is_dir():
        return {}
    return {p.stem: str(p) for p in sorted(d.glob("*.md"))}


def _frontier_index(messages: list) -> int | None:
    for i in range(len(messages) - 1, -1, -1):
        for part in getattr(messages[i], "parts", []):
            if getattr(part, "part_kind", None) == "user-prompt":
                content = getattr(part, "content", "")
                if isinstance(content, str) and compaction.FRONTIER_SENTINEL in content:
                    return i
    return None


def _compact_messages(messages: list, run_dir: Path) -> list:
    inv = RunPaths(run_dir).investigation
    inv_text = inv.read_text(encoding="utf-8") if inv.is_file() else ""
    fold = compaction.fold_boundary(inv_text)
    marker = _frontier_index(messages)
    if fold <= 0:
        return messages

    frontier_md = compaction._frontier_through(inv_text, fold)
    frontier_dict = compaction.render_frontier_message(frontier_md)
    frontier_obj = ModelMessagesTypeAdapter.validate_python([frontier_dict])[0]

    orientation = messages[0]
    tail = messages[marker + 1:] if marker is not None else []
    rewritten = [orientation, frontier_obj] + tail
    if marker is None and len(rewritten) >= len(messages):
        return messages
    return rewritten


def _make_compaction_processor():
    async def process(ctx: RunContext[AgentDeps], messages: list) -> list:
        try:
            return _compact_messages(messages, ctx.deps.run_dir)
        except Exception as e:  # noqa: BLE001 — compaction must never break the run
            print(f"[run.py] compaction skipped: {e!r}", file=sys.stderr)
            return messages

    return process


def _main_extra_capabilities() -> list[ProcessHistory[Any]]:
    if not _compaction_enabled():
        return []
    print("[run.py] per-loop compaction ENABLED (DEFENDER_COMPACTION)", file=sys.stderr)
    return [ProcessHistory(_make_compaction_processor())]


def build_agent(
    defender_dir: Path, logger: observe.RequestLogger,
    make_model: MakeModel = providers.build_for_effort,
    *, main_model: str | None = None, verbs: Any = None, limits: dict = DEFAULT_LIMITS,
) -> Agent[AgentDeps, str]:
    extra = _main_extra_capabilities()
    _override = " (DEFENDER_GATHER_MODEL override)" if os.environ.get("DEFENDER_GATHER_MODEL") else ""
    print(f"[run.py] gather model: {gather_model()}{_override}", file=sys.stderr)
    name = resolve_main_model(main_model)
    agent = build_agent_core(
        replace(
            MAIN_DEF, model=lambda: name,
            effort=providers.effort_for_role(name, AgentRole.MAIN),
            budget_enforced=MAIN_DEF.budget_enforced and enforcement_enabled(),
        ),
        deps_type=AgentDeps,
        instructions=_main_instructions(defender_dir),
        logger=logger,
        agent_id="main",
        extra_capabilities=extra,
        make_model=make_model,
        limits=limits,
    )
    register_gather_tool(
        agent,
        lambda agent_id: build_gather_agent(
            defender_dir, logger, agent_id, make_model, verbs, limits,
        ),
        GATHER_REQUEST_LIMIT,
    )
    return agent


def _log_node(node: Any) -> None:
    if Agent.is_model_request_node(node):
        print("[run.py] · model request", file=sys.stderr)
    elif Agent.is_call_tools_node(node):
        print("[run.py] · tool calls", file=sys.stderr)
    elif Agent.is_end_node(node):
        print("[run.py] · end", file=sys.stderr)


async def run_investigation(  # noqa: PLR0913 — a composition root: every parameter is a
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
    defender_dir: Path,
    salt: str,
    model_name: str | None = None,
    make_model: MakeModel | None = None,
    verbs: Any = None,
    limits: dict | None = None,
    box: Any = None,
) -> dict:
    model_name = resolve_main_model(model_name)
    make_model = make_model or providers.build_for_effort
    adapters = defender_dir / "scripts" / "adapters"
    verbs = verbs if verbs is not None else ModuleVerbRegistry(adapters)  # lint-default: ok — DI seam owning its default (tree-derived; no signature default possible)
    limits = limits if limits is not None else DEFAULT_LIMITS  # lint-default: ok — DI seam owning its default (the cap table, threaded inward)
    open_budget(run_dir, run_id)
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    agent = build_agent(
        defender_dir, logger, make_model, main_model=model_name, verbs=verbs, limits=limits,
    )
    deps = replace(
        bind(MAIN_DEF, run_dir, salt=salt, defender_dir=defender_dir, box=box), run_id=run_id,
    )
    prompt = _user_prompt(run_dir, alert_path, defender_dir, salt)

    t0 = time.time()
    truncated_by: str | None = None
    try:
        async with agent.iter(
            prompt, deps=deps,
            usage_limits=UsageLimits(request_limit=DEFAULT_REQUEST_LIMIT),
        ) as run:
            async for node in run:
                _log_node(node)
    except UsageLimitExceeded as e:
        print(f"[run.py] request limit reached ({e}); writing partial trace",
              file=sys.stderr)
    except RunAborted as e:
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
    except BudgetKill as e:
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
        truncated_by = "budget"
    wall_ms = (time.time() - t0) * 1000.0

    result = run.result
    observe.write_trace(run_dir, logger.messages, wall_ms=wall_ms)
    logger.close()
    output = result.output if result is not None else None
    return {
        "output": output, "model": model_name, "requests": logger.n_requests,
        "truncated_by": truncated_by,
    }
