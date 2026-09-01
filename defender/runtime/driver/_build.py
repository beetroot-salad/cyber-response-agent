"""The composition roots: which model, which grants, which tools each role gets.

Split out of `driver.py` at 1221 lines. Every function here is a build site — the
parameter counts are wide on purpose, because a build is where the configuration and the
injection seams meet.
"""
from __future__ import annotations

import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import ProcessHistory


from .. import compaction
from .. import observe
from .. import permission
from .. import providers
from .. import selection
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
from ..verb_dispositions import Disposition, dispositions_path, grant_for, load_dispositions
from ..verb_grant import VerbGrant
from ..verbs import ModuleVerbRegistry

from defender._env import env_bool
from defender._frontmatter import strip_frontmatter
from defender._run_paths import RunPaths
from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    BudgetKill,
)
from ._prompts import DEFAULT_GATHER_MODEL, DEFAULT_MODEL, DEFAULT_TOOL_RETRIES, GATHER_REQUEST_LIMIT, _main_instructions, enforcement_enabled
from ._budget import _make_hooks


def gather_model() -> str:
    return os.environ.get("DEFENDER_GATHER_MODEL") or DEFAULT_GATHER_MODEL




MakeModel = Callable[[str, str | None], BuiltModel]


def _affinity_key(agent_id: str, session_id: str | None, cache_key: str | None) -> str:
    """THE prompt-cache affinity key, for every role — the whole policy, in one place.

    Three arms, each answering "what prefix does this agent share, and with whom":

    1. An explicit `cache_key` wins. Gather is its whole population: a gather session HAS a
       conversation, but its `agent_id` is `gather:{lead_id}`, so arm 2 would route every
       sibling lead to a different replica and none could share the prefix they have in common
       — gather's SKILL.md and the dispatched system's catalog, byte-identical across leads AND
       across runs. Only the caller knows what that prefix is keyed on.
    2. WITH a session, the key is that conversation's: one growing prefix, every turn wanting
       the replica that already holds the previous one.
    3. WITHOUT one the agent is a one-shot (the review lenses), so there is no within-run
       prefix to keep warm; the bare `agent_id` is stable ACROSS runs, which is the only reuse
       a single-call role can have — its role instructions, identical every run.

    Threading a resolved key inward would make all four callers compute one; this is the ONE
    site that knows the policy.
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
    # Applied HERE and not inside `make_model`: the seam is a two-positional-argument callable
    # every engine in the tree (and a dozen test doubles) passes by that shape, and the key is
    # not a property of the model anyway.
    settings = providers.cache_affinity(
        model_name, built.settings, _affinity_key(agent_id, session_id, cache_key),
    )
    # The TOON view gate is installed UNCONDITIONALLY, at the single `Agent(...)` every one of
    # the five build paths reaches, so no build path can miss it. A gate already present in
    # `extra_capabilities` is REUSED rather than shadowed by a second one, which is what keeps
    # a foreign result framed exactly once however many times the gate is handed to a build.
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
    # EVERY verb-bearing bit this builder registers, not `query` alone: `list_verbs` reads the
    # grant to decide what it may name, so it needs the same production registry default AND
    # the same nominal type check — a registry-shaped stand-in that answers GRANTED to
    # everything would otherwise publish the whole verb surface through it. `QueryCapture`
    # stays behind `query`: it wraps the dispatch tool, which `list_verbs` is not.
    if defn.tools.query or defn.tools.list_verbs:
        from defender._paths import PATHS

        from ..verbs import VerbRegistry

        if verbs is None:
            verbs = ModuleVerbRegistry(PATHS.defender_dir / "scripts" / "adapters", defn.verb_grant)
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
    # The gate's identity check for "is this an owned tool". Every registration onto this agent
    # (this call's `register_tools`, plus `build_agent`'s gather and close tools) shares this
    # ONE toolset object, so binding once here covers all of them whatever the order.
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
    # report.md is not on the model's write allow-list at all — the close tool is its ONLY
    # writer, rendering it host-side through validate_artifact.
    return permission.build_named_write_allow(roots.run_dir, ("investigation.md",))


MAIN_DEF = AgentDefinition(
    role=AgentRole.MAIN,
    model=resolve_main_model,
    effort="low",
    # `append`, not `write`: main's write allowlist is exactly investigation.md, and that
    # document is append-only by construction — the general verbs offered an anchored replace
    # the artifact never admitted.
    tools=ToolSet(read=True, bash=True, append=True, close=True),
    corpus_dirs=_CORPUS_DIRS,
    bash_shapes=(_main_bash_shapes,),
    write_shapes=(_main_write_shape,),
    deps_cls=AgentDeps,
    deny_reason=permission.FALLTHROUGH_DENY_REASON,
    budget_enforced=True,
)


@lru_cache(maxsize=1)
def _dispositions() -> tuple[Disposition, ...]:
    """The shipped verb-disposition table, read ONCE for this process.

    Read at import, and a missing or malformed table raises here rather than yielding an empty
    grant. That is deliberate: an empty grant reports every verb as unknown, which is this
    issue's own symptom applied to the whole product.

    Cached because three module-scope readers want the same rows — `GATHER_PAIRS`,
    `_gather_verb_grant`, and the judge's own projection — and each uncached call is a file
    read plus two full YAML passes (the duplicate-key compose, then the load) over a file that
    cannot change under a running process.
    """
    from defender._paths import PATHS

    return load_dispositions(dispositions_path(PATHS.defender_dir))


#: The gather grant, projected from the verb-disposition table (#995). It used to be a tuple
#: of pairs written here, which made this a shared file every new system had to edit while
#: `/connect`'s lane rules forbade touching it — so a connected system was silently
#: unreachable. The table is still AUTHORED, not derived from the adapters on disk; what moved
#: is only where a human writes it. See `runtime/verb_dispositions.py` for why that
#: distinction is the entire design.
#:
#: `GATHER_PAIRS` is the grant's non-`health-check` half, kept as a module export for the same
#: reason it always was — it is the driver's published name for the census. It has no reader
#: in the tree today: `tests/_verb_authorization_632.py` holds its OWN independently written
#: copy and `test_verb_grant_632` compares that copy against `GATHER_DEF.verb_grant`, which is
#: the check that matters now that this side is derived rather than authored.
GATHER_PAIRS: tuple[tuple[str, str], ...] = tuple(
    (s, v) for s, v, _ in grant_for(AgentRole.GATHER.value, _dispositions()).entries
    if v != "health-check"
)


def _gather_verb_grant() -> VerbGrant:
    return grant_for(AgentRole.GATHER.value, _dispositions())


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
    verb_grant=_gather_verb_grant(),
)


def _gather_instructions(defender_dir: Path) -> str:
    """Gather's system prompt, frontmatter stripped for the same reason MAIN's is. Gather's
    carries no `allowed-tools` today, but a loader that keeps metadata for one role and drops
    it for the other is the asymmetry the next such line slips through."""
    return strip_frontmatter(
        (defender_dir / "skills" / "gather" / "SKILL.md").read_text(encoding="utf-8")
    )


def build_gather_agent(  # noqa: PLR0913 — composition root, same shape as build_agent
    defender_dir: Path, logger: observe.RequestLogger, agent_id: str,
    make_model: MakeModel = providers.build_for_effort,
    verbs: Any = None,
    limits: dict = DEFAULT_LIMITS,
    extra_capabilities: Sequence[Any] = (),
    session_id: str | None = None,
    cache_key: str | None = None,
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
        extra_capabilities=extra_capabilities,
        make_model=make_model,
        verbs=verbs,
        limits=limits,
        session_id=session_id,
        cache_key=cache_key,
    )




def _compaction_enabled() -> bool:
    return env_bool("DEFENDER_COMPACTION", False)


def _summary_pointers(run_dir: Path) -> dict[str, str]:
    d = run_dir / "gather_summaries"
    if not d.is_dir():
        return {}
    return {p.stem: str(p) for p in sorted(d.glob("*.md"))}


def _fold_decision(run_dir: Path) -> tuple[int, str] | None:
    """WHEN to fold, and what the frontier carries — `None` for "not yet".

    `compaction.fold_boundary` is the highest CONTIGUOUS closed investigation loop that
    produced a resolved lead, and `0` until one closes. That gate is the whole policy —
    without it a fold fires on every round, and each one mints a FRESH frontier and orphans
    the turns before it, so the model re-enters every round having lost its own tool results.

    The loop number, not a row count, is the boundary: it is stable across the rounds WITHIN
    a loop, so `_fold_impl`'s reuse lookup hits and the same frontier is reused until the next
    loop closes.
    """
    inv = RunPaths(run_dir).investigation
    inv_text = inv.read_text(encoding="utf-8") if inv.is_file() else ""
    fold_through = compaction.fold_boundary(inv_text)
    if fold_through <= 0:
        return None
    return fold_through, compaction.frontier_text(inv_text, fold_through)


def _make_store_render_processor(  # noqa: PLR0913 — #808's correlation injector rides this seam
    store: Any, session_id: str, *, fold: bool, request_limit: int,
    correlation_task: Any = None,
):
    injected = [False]

    async def _inject_correlation() -> None:
        """Item 3's async frame, awaited right before MAIN's SECOND request is prepared
        (`requests == 1`), never before the first — the marker must not be in message 0.
        Writes the summary DIRECTLY into MAIN's session so the store-hydrated list the next
        render produces carries it: `ProcessHistory` returns a list rebuilt FROM the store,
        so a plain append to `messages` would be discarded."""
        if correlation_task is None or injected[0]:
            return
        injected[0] = True
        try:
            summary = await correlation_task
        except (BudgetKill, RunAborted):
            raise
        except Exception as e:  # noqa: BLE001 — item 3's own dispatch must never break the run
            summary = None
            print(f"[run.py] correlation lead injection skipped: {e!r}", file=sys.stderr)
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
        # The framework appends this round's own request to state history and only THEN
        # checks the request limit (pydantic_ai's `_prepare_request`), so by the time this
        # processor runs the doomed round's continuation is already in `messages`. Mirror the
        # check and withhold it from the store — otherwise a round that never happens gets
        # committed anyway, and the run-end flush can never recover the true terminal response.
        #
        # RS7: the ceiling is the one the RUN was handed, not the un-raised base. Pinned to the
        # base, this mirror withheld the extra rounds the raise exists to buy — rounds that
        # genuinely execute — so they skipped history compaction and the model was handed raw,
        # unrendered history for them.
        usage = getattr(ctx, "usage", None)
        requests = int(getattr(usage, "requests", 0) or 0)
        if requests >= request_limit:
            selection.ingest(store, session_id, messages[:-1], agent_id="main")
            return messages
        selection.ingest(store, session_id, messages, agent_id="main")
        if requests >= 1:
            await _inject_correlation()
        decision = _fold_decision(ctx.deps.run_dir) if fold else None
        return selection.render(
            store, session_id, messages, agent_id="main", fold=decision is not None,
            boundary=decision[0] if decision else None,
            text=decision[1] if decision else None,
            run_step=int(getattr(ctx, "run_step", 0) or 0),
            # The latency of the request this render is PREPARING cannot be known here;
            # `_log_request` measures it and patches this same pending stamp before the
            # next round's ingest consumes it (`_stamp_duration`).
            duration_ms=None,
            run_id=getattr(ctx, "run_id", None), conversation_id=getattr(ctx, "conversation_id", None),
        )

    return process


def _make_gather_recorder(store: Any, session_id: str, agent_id: str, *, request_limit: int):
    """`request_limit` is the ceiling THIS dispatch will hand `_run_gather`, required rather
    than defaulted to the module constant: the constant is only MAIN's own leads' ceiling, and
    the correlation lead runs the same recorder under `CORRELATION_REQUEST_LIMIT`. Measured
    against the constant, the check below was `8 >= 40` on every correlation round — never
    true, so the doomed round was committed and the session ended on an unanswered request."""
    async def process(ctx: RunContext[GatherDeps], messages: list) -> list:
        # Same withholding rule as the main processor: pydantic_ai appends the round's own
        # continuation to history BEFORE checking the request limit, so on the doomed round
        # `messages` already ends with a request that will never be sent. Committing it would
        # leave a phantom round in this gather's session — and unlike main there is no run-end
        # flush on this side to reconcile it afterwards.
        usage = getattr(ctx, "usage", None)
        requests = int(getattr(usage, "requests", 0) or 0)
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
    """`request_limit` is the ceiling the RUN was handed — base plus the gate's forced-turn
    bound — and the default is the RAISED ceiling of the shipped bounds, never the un-raised
    base: defaulting to the base would have this reader withhold from the compaction path the
    very rounds the raise buys (the staleness RS7 exists to prevent). The sole production
    caller passes the run's own value; the default serves tests that pin the capability COUNT
    and have no ceiling to hand it."""
    # lint-default: ok — resolved once into a fresh name; the honest default is derived from
    # the bounds object and cannot be a signature default without an import-time read of it.
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
    """`request_limit` has no default for the reason `_make_gather_recorder`'s docstring
    gives: this factory serves two dispatches with two different ceilings."""
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
) -> Agent[AgentDeps, str]:
    # The bounds arrive RESOLVED, non-`Optional`. Re-coalescing here would give the gate's ONE
    # bounds object a default at four depths, and the entry point could then resolve one value
    # while a direct build resolved another from its own environment read.
    extra: list[ProcessHistory[Any]] = []
    if store is not None:
        assert session_id is not None, "a store requires its session_id (build_agent's own contract)"
        extra = _main_extra_capabilities(
            store, session_id, request_limit=challenge_gate.raised_request_limit(bounds),
            correlation_task=correlation_task,
        )
    _override = " (DEFENDER_GATHER_MODEL override)" if os.environ.get("DEFENDER_GATHER_MODEL") else ""
    print(f"[run.py] gather model: {gather_model()}{_override}", file=sys.stderr)
    name = resolve_main_model(main_model)
    # Named rather than inlined into the build call: the EFFECTIVE definition — not `MAIN_DEF`
    # — is what decides below whether this root registers the close tool, the same way
    # `register_tools` reads the effective ToolSet for every other capability bit.
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

    # agent_id → the gather session opened for it. Keyed by agent_id and not "the last one
    # built" because sibling leads are dispatched CONCURRENTLY (one `gather` call per lead in a
    # single main turn), so "the current gather session" does not exist. `agent_id` is
    # `gather:{lead_id}` and `claim_lead` refuses a reused `lead_id`, so it is unique per run.
    gather_sessions: dict[str, str] = {}

    def _build_gather(agent_id: str, system: str, request_limit: int) -> Agent[GatherDeps, str]:
        gather_extra: Sequence[Any] = ()
        gather_session_id: str | None = None
        if store is not None:
            gather_session_id = store.new_session(agent_id=agent_id)
            gather_sessions[agent_id] = gather_session_id
            # `request_limit` is THE DISPATCH'S OWN, handed down by `_run_gather` — not
            # `GATHER_REQUEST_LIMIT` read again here. The recorder's withholding check and the
            # `UsageLimits` that stops the loop are the same number by construction.
            gather_extra = _gather_extra_capabilities(
                store, gather_session_id, agent_id, request_limit=request_limit,
            )
        return build_gather_agent(
            defender_dir, logger, agent_id, make_model, verbs, limits,
            extra_capabilities=gather_extra, session_id=gather_session_id,
            # Keyed on the SYSTEM, not this lead and not this run. What the dispatch prompt
            # puts in front of the lead's question — gather's SKILL.md, the descriptor index,
            # this system's catalog — is identical for every lead dispatched here, in this run
            # and the next, and the key is what routes them to one replica. `agent_id` stays
            # `gather:{lead_id}`: the wire log, session store and terminator stamp key on it.
            cache_key=f"{GATHER_AGENT_ID_PREFIX}{system}",
        )

    def _stamp_gather_terminator(agent_id: str, reason: str) -> None:
        """`_flush_run_end`'s stamp, for a GATHER session. Best-effort for the same reason:
        the store may be exactly what ended this lead, and losing the terminator must not also
        lose the lead's summary. No terminal-exchange flush pairs with it — gather's recorder
        commits every round as it goes and withholds the doomed round's continuation, so only
        the stamp is missing."""
        gather_session_id = gather_sessions.get(agent_id)
        if store is None or gather_session_id is None:
            return
        try:
            store.set_truncated_by(gather_session_id, reason)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            print(f"[run.py] gather truncated_by write skipped for {agent_id}: {e!r}",
                  file=sys.stderr)

    # ALWAYS the role's own committed grant — never the per-call `verbs=` registry's. The
    # dispatch catalog/template index is a ROLE-LEVEL surface (the one verb_roster.py scores
    # against), not a per-run one; a test injecting a registry scoped narrower than
    # GATHER_DEF's real grant must not narrow what the catalog advertises.
    register_gather_tool(
        agent, _build_gather, GATHER_REQUEST_LIMIT, GATHER_DEF.verb_grant,
        _stamp_gather_terminator,
    )
    # `build_agent` has no `run_dir` of its own, so it cannot BUILD a live bundle — one
    # carrying live stages is assembled by `run_investigation` and arrives here already bound.
    # The fallback must never substitute the SOURCE TREE for the missing run dir: that anchors
    # each review role's compiled policy on the repo checkout and has every stage append its
    # trace inside it. An empty bundle fails the review closed at call time instead.
    stages = (
        review_stages if review_stages is not None
        else review_roles.ReviewStages()  # lint-default: ok — DI seam owning its default (the UNBOUND bundle: no run dir here, so `stage()` raises UnboundReviewStage and the gate fails the close closed)
    )
    if main_defn.tools.close:
        register_close_tool(agent, stages=stages, bounds=bounds)
    return agent
