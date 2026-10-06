"""The composition roots: which model, which grants, which tools each role gets.

Parameter counts are wide because a build is where configuration and injection seams meet.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import ProcessHistory

if TYPE_CHECKING:
    from pydantic_ai.settings import ModelSettings


from .. import compaction
from .. import lessons_push
from .. import observe
from .. import permission
from .. import providers
from .. import selection
from ..request_ceiling import RequestCeiling, requests_so_far
from .. import toon_gate as toon_gate_mod
from ..agent_definition import AgentDefinition, ResolvedRoots, ToolSet
from ..agent_role import GATHER_AGENT_ID_PREFIX, AgentRole
from .. import challenge_gate
from .. import review_roles
from ..close_tool import register_close_tool
from ..circuit_breaker import RunAborted
from ..permission.policies import _common
from ..providers import BuiltModel
from ..tools import (
    AgentDeps,
    GatherDeps,
    register_gather_tool,
    register_tools,
)
from ..verb_grant import VerbGrant
from ..verbs import ModuleVerbRegistry

from defender._frontmatter import strip_frontmatter
from defender.run_repository import RUN_LAYOUT, RunPaths
from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    BudgetKill,
)
from ._prompts import DEFAULT_GATHER_MODEL, DEFAULT_MODEL, DEFAULT_TOOL_RETRIES, GATHER_REQUEST_LIMIT, _main_instructions, enforcement_enabled
from ._budget import _make_hooks

_logger = logging.getLogger(__name__)


def gather_model() -> str:
    return os.environ.get("DEFENDER_GATHER_MODEL") or DEFAULT_GATHER_MODEL




MakeModel = Callable[[str, str | None], BuiltModel]


def _affinity_key(agent_id: str, session_id: str | None, cache_key: str | None) -> str:
    """The prompt-cache affinity key for every role: which prefix this agent shares, and with whom.

    1. An explicit `cache_key` wins (gather: sibling leads share SKILL.md and the system's
       catalog across leads and runs, which a per-lead key would scatter across replicas).
    2. With a session, the conversation's key: one growing prefix.
    3. Without one (one-shot review lenses), the bare `agent_id`, stable across runs.
    """
    if cache_key is not None:
        return cache_key
    return f"{session_id}:{agent_id}" if session_id is not None else agent_id


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
    session_id: str | None = None,
    store: Any = None,
    cache_key: str | None = None,
    toolset: Any = None,
    toon_encoder: Any = None,
) -> Agent[Any, str]:
    model_name = defn.model()
    built = make_model(model_name, defn.effort)
    # Applied here, not in `make_model`, whose two-argument shape many callers depend on.
    # `built.settings` is typed as a plain dict so provider extension keys survive; cast for
    # the call.
    settings = providers.cache_affinity(
        model_name, cast("ModelSettings | None", built.settings),
        _affinity_key(agent_id, session_id, cache_key),
    )
    # The TOON view gate is always installed here, where every build path passes. A gate
    # already in `extra_capabilities` is reused so a foreign result is framed exactly once.
    reused_gate = next(
        (c for c in extra_capabilities if isinstance(c, toon_gate_mod.ToonGateCapability)), None,
    )
    toon_gate = (
        toon_gate_mod.ToonGateCapability(encoder=toon_encoder)
        if reused_gate is None else reused_gate
    )
    capabilities: list[Any] = [
        _make_hooks(logger, agent_id, enforce=defn.budget_enforced, limits=limits,
                    session_id=session_id, store=store, toon_gate=toon_gate),
        *extra_capabilities,
    ]
    if reused_gate is None:
        capabilities.append(toon_gate)
    # Both verb-bearing tools need a real registry: a stand-in that grants everything would
    # expose the whole verb surface through `list_verbs`. `QueryCapture` wraps `query` only.
    if defn.tools.query or defn.tools.list_verbs:
        from defender._paths import PATHS

        from ..verbs import VerbRegistry, read_roster

        if verbs is None:
            verbs = ModuleVerbRegistry(read_roster(PATHS.adapters_dir), defn.verb_grant)
        if not isinstance(verbs, VerbRegistry):
            raise TypeError(
                f"a verb-bearing tool needs a real VerbRegistry, got {type(verbs).__name__} — a "
                "registry-shaped stand-in that never went through the constructor is refused"
            )
        if defn.tools.query:
            from ..query_tool import QueryCapture

            capabilities.append(QueryCapture(verbs, defn.role.value))
    agent: Agent[Any, str] = Agent(
        built.model,
        deps_type=deps_type,
        instructions=instructions,
        capabilities=capabilities,
        model_settings=settings,
        retries={"tools": DEFAULT_TOOL_RETRIES, "output": 0},
        toolsets=[toolset] if toolset is not None else [],
    )
    # The gate identifies owned tools by this toolset object, which every later registration
    # onto this agent shares, so binding once covers them all.
    toon_gate.bind_native_toolset(agent._function_toolset)  # noqa: SLF001 — the identity IS the contract; see toon_gate.py
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
    # report.md is not on the allow-list; the close tool is its only writer.
    return permission.build_named_write_allow(
        roots.run_dir, (RUN_LAYOUT.investigation.name,))


MAIN_DEF = AgentDefinition(
    role=AgentRole.MAIN,
    model=resolve_main_model,
    effort="low",
    # `append`, not `write`: investigation.md is append-only.
    tools=ToolSet(read=True, bash=True, append=True, close=True),
    corpus_dirs=_CORPUS_DIRS,
    bash_shapes=(_main_bash_shapes,),
    write_shapes=(_main_write_shape,),
    deps_cls=AgentDeps,
    deny_reason=permission.FALLTHROUGH_DENY_REASON,
    budget_enforced=True,
)


#: Gather's definition carries no grant: grants are per tenant, so each run binds gather via
#: `gather_def_for(grants.gather)`. `compile_policy` refuses to bind this empty grant with
#: verb-bearing tools on, so a forgotten grant fails loudly.
GATHER_DEF = AgentDefinition(
    role=AgentRole.GATHER,
    model=gather_model,
    effort="none",
    tools=ToolSet(read=True, bash=True, template_search=True, query=True, list_verbs=True),
    corpus_dirs=_CORPUS_DIRS,
    bash_shapes=(_gather_bash_shapes,),
    deps_cls=GatherDeps,
    deny_reason=permission.GATHER_FALLTHROUGH_DENY_REASON,
    budget_enforced=True,
    verb_grant=VerbGrant(role=AgentRole.GATHER.value),
)


def gather_def_for(verb_grant: VerbGrant) -> AgentDefinition:
    """Gather's definition carrying one run's grant — the only form gather is ever bound in.
    @owns gather verb_grant"""
    return replace(GATHER_DEF, verb_grant=verb_grant)


def _gather_instructions(defender_dir: Path) -> str:
    """Gather's system prompt, frontmatter stripped like MAIN's."""
    return strip_frontmatter(
        (defender_dir / "skills" / "gather" / "SKILL.md").read_text(encoding="utf-8")  # lint-whole-read: ok — repo-shipped gather SKILL.md; operator-controlled, not on any box-writable mount
    )


def build_gather_agent(  # noqa: PLR0913 — composition root, same shape as build_agent
    defender_dir: Path, logger: observe.RequestLogger, agent_id: str,
    make_model: MakeModel = providers.build_for_effort,
    verbs: Any = None,
    limits: dict = DEFAULT_LIMITS,
    extra_capabilities: Sequence[Any] = (),
    session_id: str | None = None,
    cache_key: str | None = None,
    *,
    verb_grant: VerbGrant,
) -> Agent[GatherDeps, str]:
    name = gather_model()
    # The run's gather grant, or item 3's narrower correlation grant. Required.
    defn = gather_def_for(verb_grant)
    return build_agent_core(
        replace(
            defn, model=lambda: name,
            effort=providers.effort_for_role(name, AgentRole.GATHER),
            budget_enforced=defn.budget_enforced and enforcement_enabled(),
        ),
        deps_type=GatherDeps,
        instructions=_gather_instructions(defender_dir),
        logger=logger,
        agent_id=agent_id,
        # The ceiling's round marker on every gather agent, ahead of the extras so a recorder
        # commits the request as actually sent. No-op without a ceiling.
        extra_capabilities=[RequestCeiling(), *extra_capabilities],
        make_model=make_model,
        verbs=verbs,
        limits=limits,
        session_id=session_id,
        cache_key=cache_key,
    )




def _compaction_enabled() -> bool:
    return compaction.enabled()


def _summary_pointers(run_dir: Path) -> dict[str, str]:
    d = RunPaths(run_dir).gather_summaries
    if not d.is_dir():
        return {}
    return {p.stem: str(p) for p in sorted(d.glob("*.md"))}


class _FoldDecision(NamedTuple):
    #: The loop number (see `_fold_decision`) and the whole document at decision time; the
    #: frontier row's text is composed by `_fold_composer` at mint only.
    boundary: int
    document: str


def _fold_decision(run_dir: Path) -> _FoldDecision | None:
    """When to fold — `None` for "not yet".

    The boundary is `compaction.fold_boundary`: the highest contiguous closed loop with a
    resolved lead. Without this gate every round would mint a fresh frontier and lose the
    model's tool results. A loop number, not a row count, so it is stable within a loop and the
    same frontier is reused until the next loop closes.
    """
    inv = RunPaths(run_dir).investigation
    inv_text = inv.read_text(encoding="utf-8") if inv.is_file() else ""  # lint-whole-read: ok — investigation.md: host writers go through validate_artifact (64 KiB cap, INVESTIGATION_FILE_MAX); box-writable in the rw run dir, bounded by the box fsize limit; per-run driver
    fold_through = compaction.fold_boundary(inv_text)
    if fold_through <= 0:
        return None
    return _FoldDecision(fold_through, inv_text)


def _fold_composer(deps: AgentDeps, decision: _FoldDecision) -> selection.Composer:
    """The frontier row's text, composed only at mint (never on reuse rounds).

    Carries the record (`compaction.frontier_text`) plus the lessons block for the full
    document: the fold displaces the write returns that carried earlier blocks, and the record
    may be cut before the slot a lesson keys on."""
    def compose():
        record = compaction.frontier_text(decision.document, decision.boundary)
        return lessons_push.compose_fold(deps, record, decision.document)
    return compose


def _make_store_render_processor(  # noqa: PLR0913 — the correlation injector rides this seam
    store: Any, session_id: str, *, fold: bool, request_limit: int,
    correlation_task: Any = None,
):
    injected = [False]

    async def _inject_correlation() -> None:
        """Await item 3 before MAIN's second request (never the first) and write its summary
        into MAIN's session. Written to the store, not `messages`: the render rebuilds the list
        from the store."""
        if correlation_task is None or injected[0]:
            return
        injected[0] = True
        try:
            summary = await correlation_task
        except (BudgetKill, RunAborted):
            raise
        except Exception as e:  # noqa: BLE001 — item 3's own dispatch must never break the run
            summary = None
            _logger.warning(f"correlation lead injection skipped: {e!r}")
        if not summary:
            return
        from datetime import UTC, datetime as _dt

        from pydantic_ai.messages import ModelRequest as _MR, UserPromptPart as _UPP

        from .. import lead_zero as _lz
        from ..session_store import path_row_ids as _path_row_ids

        ids = _path_row_ids(store, session_id)
        parent = ids[-1] if ids else None
        row = _MR(
            parts=[_UPP(content=(
                f"## Correlation lead ({_lz.L3}) — dispatched automatically at ORIENT time, "
                "off the ancestors lead-0 resolved\n\n"
                f"{summary}"
            ))],
            timestamp=_dt.now(UTC),
        )
        store.append(session_id, [row], agent_id="main", parent_id=parent, synthesized=True)

    async def process(ctx: RunContext[AgentDeps], messages: list) -> list:
        # The framework appends this round's request before checking the request limit, so on
        # the doomed round withhold it from the store; otherwise a round that never happens is
        # committed. `request_limit` is the run's raised ceiling, not the base.
        requests = requests_so_far(ctx)
        if requests >= request_limit:
            selection.ingest(store, session_id, messages[:-1], agent_id="main")
            return messages
        selection.ingest(store, session_id, messages, agent_id="main")
        if requests >= 1:
            await _inject_correlation()
        decision = _fold_decision(ctx.deps.run_dir) if fold else None
        return selection.render(
            store, session_id, messages, agent_id="main", fold=decision is not None,
            boundary=decision.boundary if decision else None,
            text=_fold_composer(ctx.deps, decision) if decision else None,
            run_step=int(getattr(ctx, "run_step", 0) or 0),
            # Unknown yet; `_stamp_duration` patches it after the request completes.
            duration_ms=None,
            run_id=getattr(ctx, "run_id", None), conversation_id=getattr(ctx, "conversation_id", None),
        )

    return process


def _make_gather_recorder(store: Any, session_id: str, agent_id: str, *, request_limit: int):
    """`request_limit` is this dispatch's own ceiling, required because MAIN's leads and the
    correlation lead use different ceilings."""
    async def process(ctx: RunContext[GatherDeps], messages: list) -> list:
        # Same withholding rule as the main processor; gather has no run-end flush to repair a
        # phantom round.
        requests = requests_so_far(ctx)
        if requests >= request_limit:
            selection.ingest(store, session_id, messages[:-1], agent_id=agent_id)
            return messages
        selection.ingest(store, session_id, messages, agent_id=agent_id)
        return messages

    return process


def _main_extra_capabilities(
    store: Any, session_id: str, *, request_limit: int | None = None,
    correlation_task: Any = None,
) -> list[ProcessHistory[Any]]:
    """`request_limit` is the run's raised ceiling (base plus the gate's forced turns). The
    default is the raised ceiling of the shipped bounds, never the base, which would withhold
    the extra rounds from compaction. Production always passes it."""
    # lint-default: ok — derived from the bounds object, so it cannot be a signature default.
    limit = (
        request_limit if request_limit is not None
        else challenge_gate.raised_request_limit(challenge_gate.default_bounds())
    )
    return [ProcessHistory(_make_store_render_processor(
        store, session_id, fold=_compaction_enabled(), request_limit=limit,
        correlation_task=correlation_task))]


def _gather_extra_capabilities(
    store: Any, session_id: str, agent_id: str, *, request_limit: int,
) -> list[ProcessHistory[Any]]:
    """`request_limit` has no default: two dispatches use different ceilings."""
    return [ProcessHistory(
        _make_gather_recorder(store, session_id, agent_id, request_limit=request_limit)
    )]


def build_agent(  # noqa: PLR0913 — composition root: config + DI seams + the store's identity
    defender_dir: Path, logger: observe.RequestLogger,
    make_model: MakeModel = providers.build_for_effort,
    *, main_model: str | None = None, verbs: Any = None, limits: dict = DEFAULT_LIMITS,
    store: Any = None, session_id: str | None = None, review_stages: Any = None,
    bounds: challenge_gate.Bounds,
    correlation_task: Any = None,
    toolset: Any = None,
    catalog: str | None,
    gather_grant: VerbGrant,
) -> Agent[AgentDeps, str]:
    # `gather_grant` is the run's; every dispatched lead is bound over it. Pass
    # `GATHER_DEF.verb_grant` (empty) for "no grant", and dispatch refuses at `bind`.
    # `bounds` arrives resolved so there is one value, not a default at every depth.
    extra: list[ProcessHistory[Any]] = []
    if store is not None:
        assert session_id is not None, "a store requires its session_id (build_agent's own contract)"
        extra = _main_extra_capabilities(
            store, session_id, request_limit=challenge_gate.raised_request_limit(bounds),
            correlation_task=correlation_task,
        )
    _override = " (DEFENDER_GATHER_MODEL override)" if os.environ.get("DEFENDER_GATHER_MODEL") else ""
    _logger.info(f"gather model: {gather_model()}{_override}")
    name = resolve_main_model(main_model)
    # The effective definition, not `MAIN_DEF`, decides below whether the close tool registers.
    main_defn = replace(
        MAIN_DEF, model=lambda: name,
        effort=providers.effort_for_role(name, AgentRole.MAIN),
        budget_enforced=MAIN_DEF.budget_enforced and enforcement_enabled(),
    )
    agent = build_agent_core(
        main_defn,
        deps_type=AgentDeps,
        instructions=_main_instructions(defender_dir),
        logger=logger,
        agent_id="main",
        extra_capabilities=extra,
        make_model=make_model,
        limits=limits,
        session_id=session_id,
        store=store,
        toolset=toolset,
    )

    # agent_id → its gather session. Leads run concurrently, so there is no "current" one;
    # `agent_id` is unique per run because `claim_lead` refuses a reused lead id.
    gather_sessions: dict[str, str] = {}

    def _build_gather(agent_id: str, system: str, request_limit: int) -> Agent[GatherDeps, str]:
        gather_extra: Sequence[Any] = ()
        gather_session_id: str | None = None
        if store is not None:
            gather_session_id = store.new_session(agent_id=agent_id)
            gather_sessions[agent_id] = gather_session_id
            # The dispatch's own limit, so the recorder and `UsageLimits` use the same number.
            gather_extra = _gather_extra_capabilities(
                store, gather_session_id, agent_id, request_limit=request_limit,
            )
        return build_gather_agent(
            defender_dir, logger, agent_id, make_model, verbs, limits,
            extra_capabilities=gather_extra, session_id=gather_session_id,
            verb_grant=gather_grant,
            # Keyed on the system: the prompt prefix is identical for every lead to it across
            # runs. `agent_id` stays `gather:{lead_id}` for logs and the store.
            cache_key=f"{GATHER_AGENT_ID_PREFIX}{system}",
        )

    def _stamp_gather_terminator(agent_id: str, reason: str) -> None:
        """`_flush_run_end`'s stamp for a gather session, best-effort (the store may be what
        ended the lead). No flush is needed: the recorder commits every round as it goes."""
        gather_session_id = gather_sessions.get(agent_id)
        if store is None or gather_session_id is None:
            return
        try:
            store.set_truncated_by(gather_session_id, reason)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            _logger.warning(f"gather truncated_by write skipped for {agent_id}: {e!r}")

    # Always the run's gather grant, never the injected `verbs=` registry's, so a narrower
    # registry does not narrow what the catalog advertises. `catalog` is built at run start.
    register_gather_tool(
        agent, _build_gather, GATHER_REQUEST_LIMIT, gather_grant,
        _stamp_gather_terminator, catalog=catalog,
    )
    # No `run_dir` here to build a live bundle; `run_investigation` passes one. The fallback is
    # an unbound bundle that fails the review closed, never one anchored on the source tree.
    stages = (
        review_stages if review_stages is not None
        else review_roles.ReviewStages()  # lint-default: ok — DI seam owning its default (the UNBOUND bundle: no run dir here, so `stage()` raises UnboundReviewStage and the gate fails the close closed)
    )
    if main_defn.tools.close:
        register_close_tool(agent, stages=stages, bounds=bounds)
    return agent
