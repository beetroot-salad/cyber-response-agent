
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import ProcessHistory
from pydantic_ai.capabilities.hooks import Hooks
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.messages import ModelResponse
from pydantic_ai.usage import UsageLimits

from defender._io import write_guarded

from . import branch
from . import compaction
from . import observe
from . import orient
from . import permission
from . import providers
from . import selection
from . import session_store
from . import toon_gate as toon_gate_mod
from .agent_definition import AgentDefinition, ResolvedRoots, ToolSet, bind
from .agent_role import GATHER_AGENT_ID_PREFIX, AgentRole
from . import challenge_gate
from . import review_roles
from .close_tool import register_close_tool
from .circuit_breaker import RunAborted
from .permission.policies import _common
from .providers import BuiltModel
from .tools import (
    AgentDeps,
    GatherDeps,
    register_gather_tool,
    register_tools,
)
from .verb_grant import VerbGrant
from .verbs import ModuleVerbRegistry

from defender._env import env_bool
from defender._frontmatter import strip_frontmatter
from defender._run_paths import RunPaths
from defender.hooks.budget_enforcer import (
    BUDGET_EXEMPT_TOOLS,
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
    """MAIN's system prompt: the SKILL's BODY, without its frontmatter.

    The frontmatter is file metadata nothing here parses, and it can carry an `allowed-tools:`
    line naming verbs the `ToolSet` does not register. The roster has exactly one enforced
    owner (`MAIN_DEF.tools` → `register_tools`); a second copy in prose can only drift, and
    drifting it teaches the model to call a tool it does not have."""
    return strip_frontmatter((defender_dir / "SKILL.md").read_text(encoding="utf-8"))


def _user_prompt(  # noqa: PLR0913 — the harness's own pre-turn seams (#808)
    run_dir: Path, alert_path: Path, defender_dir: Path,
    *, verbs: Any = None, limits: dict = DEFAULT_LIMITS, run_id: str | None = None,
) -> tuple[str, str, str]:
    """Lead-0's call site, with its OWN exception handler: a `BudgetKill` or
    `circuit_breaker.RunAborted` raised inside `resolve_lead_zero` is caught HERE so it cannot
    end the run before MAIN's first prompt — the section degrades instead.

    Returns `(prompt, ancestor_block, status)`; the block/status feed item 3's dispatch gate,
    computed once here rather than re-resolved by a second lead_zero call."""
    from . import lead_zero as lead_zero_mod
    from .circuit_breaker import RunAborted

    ancestor_block = ""
    status = lead_zero_mod.STATUS_FAILED
    try:
        result = lead_zero_mod.resolve_lead_zero(
            run_dir=run_dir, defender_dir=defender_dir, alert_path=alert_path,
            verbs=verbs, limits=limits, run_id=run_id,
        )
        lead_zero_text = lead_zero_mod.render_orient_section(result)
        ancestor_block = result.text
        status = result.status
    except (BudgetKill, RunAborted) as e:
        print(f"[run.py] lead-0 degraded ({e!r}); continuing without it", file=sys.stderr)
        degraded = lead_zero_mod.LeadZeroResult(
            text=lead_zero_mod._render_section(
                lead_zero_mod._unavailable(f"a run-level fault interrupted resolution: {e!r}"),
            ),
            status=lead_zero_mod.STATUS_FAILED,
        )
        lead_zero_text = lead_zero_mod.render_orient_section(degraded)

    orientation = orient.orientation(
        run_dir, defender_dir, alert_path, lead_zero_section=lead_zero_text,
    )
    prompt = (
        "Begin the investigation.\n\n"
        f"run_dir: {run_dir}\n"
        f"alert: {alert_path}\n\n"
        f"{orientation}"
    )
    return prompt, ancestor_block, status


def _opening_prompt(  # noqa: PLR0913 — `_user_prompt`'s parameters plus the resume it chooses between
    resume: Any, run_dir: Path, alert_path: Path, defender_dir: Path,
    *, verbs: Any, limits: dict, run_id: str | None,
) -> tuple[str, str, str]:
    """MAIN's first message — for a fresh run or a resumed one.

    A RESUMED run does not orient. Lead-0 and the correlation dispatch are turn-0 work: they
    read the alert cold and resolve its ancestors, and a branch point is by construction past
    that — the defender already holds the payloads. Re-running them would put a second
    orientation section in front of a history that already contains the first, and dispatch a
    lead the source run already ran. `run_investigation` gates that dispatch on `resume is None`
    directly, so the skip is stated where it happens rather than smuggled through a registry
    this function nulls.

    THE COORDINATE HEADER RIDES ALONG, even though the wording of the continuation itself is
    the caller's (the 2026-08-16 experiment's own caveat was that its continuation wording
    biased the run toward closing). It has to: a sibling gets its OWN run dir, while every path
    in the inherited prefix names the SOURCE run's — and `permission.decide_read` resolves its
    roots from `deps.run_dir`, so a model re-reading `<source>/investigation.md` off its own
    history is denied with no correct path to substitute. The two lines are the same scaffold
    `_user_prompt` emits; they are coordinates, not instruction.
    """
    if resume is None:
        return _user_prompt(
            run_dir, alert_path, defender_dir, verbs=verbs, limits=limits, run_id=run_id,
        )
    prompt = (
        f"{resume.continuation_prompt}\n\n"
        f"run_dir: {run_dir}\n"
        f"alert: {alert_path}\n"
    )
    return prompt, "", ""


def _budget_state_for_enforcement(state: dict, deps: AgentDeps) -> dict:
    return {**state, "started_monotonic": deps.budget_started_monotonic}


def _budget_short_circuit(
    deps: AgentDeps, tool_name: str, limits: dict,
    logger: observe.RequestLogger, agent_id: str,
) -> str | None:
    # RS16: the exemption sits AHEAD of the tail kill, not only inside `should_refuse` — the
    # tail kill is unconditional, so an exemption expressed only in the refusal check still
    # ends the run at the close. The gate's own forced turns are what push a run past the tail
    # to begin with, so closing must stay possible under exactly that pressure.
    if tool_name in BUDGET_EXEMPT_TOOLS:
        return None
    state = _budget_state_for_enforcement(read_budget(deps.run_dir), deps)
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
        state = _budget_state_for_enforcement(state, deps)
        for w in check_budgets(state, limits):
            print(f"[run.py] {w}", file=sys.stderr)
    except BudgetKill:
        raise
    except Exception as e:  # noqa: BLE001 — budget accounting must never break the run
        print(f"[run.py] budget accounting skipped: {e!r}", file=sys.stderr)


def _stamp_duration(store: Any, session_id: str | None, duration_ms: float) -> None:
    """Write the MEASURED latency into the render's pending stamp.

    `selection.render` opens the stamp for the request it is preparing, but that request's
    duration only exists once the model has answered — here. The next round's `ingest`
    consumes the stamp, so patching it in place is what puts a real number in
    `message.duration_ms` instead of the renderer's placeholder."""
    if store is None or session_id is None:
        return
    pending = getattr(store, "pending_stamps", None)
    if not pending or session_id not in pending:
        return
    run_step, _placeholder, wire_sha = pending[session_id]
    pending[session_id] = (run_step, duration_ms, wire_sha)


def _make_hooks(  # noqa: PLR0913 — the hook set's full wiring: logging, budget, and the store stamp
    logger: observe.RequestLogger, agent_id: str, *, enforce: bool, limits: dict = DEFAULT_LIMITS,
    session_id: str | None = None, store: Any = None, toon_gate: Any = None,
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
        duration_ms = (time.time() - t0) * 1000.0
        try:
            _stamp_duration(store, session_id, duration_ms)
            logger.log(
                request_messages=request_context.messages,
                response=resp,
                run_step=int(getattr(ctx, "run_step", 0) or 0),
                duration_ms=duration_ms,
                agent_id=agent_id,
                session_id=session_id,
                toon_gate=toon_gate.snapshot() if toon_gate is not None else None,
            )
        except Exception as e:  # noqa: BLE001
            print(f"[run.py] request logging skipped: {e!r}", file=sys.stderr)
        return resp

    return hooks


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

        from .verbs import VerbRegistry

        if verbs is None:
            verbs = ModuleVerbRegistry(PATHS.defender_dir / "scripts" / "adapters", defn.verb_grant)
        if not isinstance(verbs, VerbRegistry):
            raise TypeError(
                f"a verb-bearing tool needs a real VerbRegistry, got {type(verbs).__name__} — a "
                "registry-shaped stand-in that never went through the constructor is refused"
            )
        if defn.tools.query:
            from .query_tool import QueryCapture

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

#: The gather grant: 21 read verbs across 7 systems, plus `health-check` granted uniformly per
#: system rather than per verb (the split carries no security content). `cmdb.list-roles` and
#: `identity.list-authorized-hosts` are granted to nobody: in the registry, exercised by no
#: template and no run.
GATHER_PAIRS: tuple[tuple[str, str], ...] = (
    ("change-mgmt", "active-changes"), ("change-mgmt", "get-change"),
    ("change-mgmt", "list-changes"),
    ("cmdb", "get-host"), ("cmdb", "list-hosts"),
    ("elastic", "alerts"), ("elastic", "esql"), ("elastic", "query"),
    ("host-state", "authorized-keys"), ("host-state", "container-inspect"),
    ("host-state", "fim-checksum"), ("host-state", "package-list"),
    ("host-state", "passwd"), ("host-state", "proc-tree"),
    ("identity", "can-access"), ("identity", "get-user"), ("identity", "list-roles"),
    ("identity", "list-users"),
    ("threat-intel", "list-indicators"), ("threat-intel", "lookup"),
    ("ticket", "list-tickets"),
)


def _gather_verb_grant() -> VerbGrant:
    systems = sorted({s for s, _ in GATHER_PAIRS})
    entries = tuple((s, v, "r") for s, v in GATHER_PAIRS)
    entries += tuple((s, "health-check", "r") for s in systems)
    return VerbGrant(role=AgentRole.GATHER.value, entries=entries)


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

        from . import lead_zero as _lz
        from .session_store import path_row_ids as _path_row_ids

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


def _log_node(node: Any) -> None:
    if Agent.is_model_request_node(node):
        print("[run.py] · model request", file=sys.stderr)
    elif Agent.is_call_tools_node(node):
        print("[run.py] · tool calls", file=sys.stderr)
    elif Agent.is_end_node(node):
        print("[run.py] · end", file=sys.stderr)


StoreFactory = Callable[[str, Path], Any]


def _default_store_factory(case_id: str, run_dir: Path) -> Any:
    return session_store.open_store(case_id=case_id, runs_base=run_dir.parent)


def _resolve_store_factory(resume: Any, store_factory: StoreFactory | None) -> StoreFactory:
    """Which store this run opens, DERIVED from whether it is a resume.

    A fresh run mints its own (or takes the injected seam's); a resume joins the source run's,
    because that is where the prefix rows live and `fork` walks parents inside one connection.

    THE RESUME WINS, and that ordering is the whole point. Deciding it here rather than letting
    the caller supply both a `resume=` and a matching `store_factory=` is what stops the two
    from disagreeing — a spec pointing at run X beside a factory opening run Y's store forks
    against a database that does not hold the branch point, and `_walk_parents` terminates
    cleanly on an id it cannot resolve, so the result is a silently truncated prefix rather
    than an error. Asking the caller and then preferring the caller's answer would leave that
    disagreement reachable, which is exactly what this function claims to close.
    """
    if resume is not None:
        return branch.store_factory_for(resume)
    if store_factory is not None:
        return store_factory
    return _default_store_factory


def _run_summary(  # noqa: PLR0913 — one dict literal's full field set, named once
    *, output: Any, model_name: str | None, requests: int, truncated_by: str | None,
    exit_reason: str | None, case_id: str, store_path: Any,
) -> dict:
    """The one shape `run_investigation` returns through, on every exit — setup-failure
    and the normal end alike — so the two exits cannot drift apart on a field name."""
    return {
        "output": output, "model": model_name, "requests": requests,
        "truncated_by": truncated_by, "exit_reason": exit_reason,
        "case_id": case_id, "store_path": store_path,
    }


def _flush_run_end(run: Any, store: Any, session_id: str, truncated_by: str | None) -> None:
    """Capture the terminal exchange (whatever `run` holds on ANY exit, clean or not) and
    stamp `truncated_by`, both best-effort so a broken store cannot mask the exit that got us
    here."""
    if run is not None:
        try:
            live = run.ctx.state.message_history
            confirmed_len = store.last_render_len(session_id) or 0
            if len(live) <= confirmed_len:
                # A prior round's processor already committed everything `live` holds, or more
                # — the request-limit check withholds a doomed round's continuation, so `live`
                # can be SHORTER than what is confirmed. Either way there is nothing to add,
                # and truncating here would re-add content the store correctly declined.
                pass
            else:
                # New content past the last confirmed round: drop a trailing incomplete
                # continuation (built but never confirmed by a processor call) so the tail
                # ends on a confirmed response.
                for i in range(len(live) - 1, -1, -1):
                    if isinstance(live[i], ModelResponse):
                        live = live[: i + 1]
                        break
                if len(live) > confirmed_len:
                    selection.ingest(store, session_id, live, agent_id="main")
        except Exception as e:  # noqa: BLE001 — the run-end flush is best-effort
            print(f"[run.py] run-end flush skipped: {e!r}", file=sys.stderr)
    if truncated_by is not None:
        try:
            store.set_truncated_by(session_id, truncated_by)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            print(f"[run.py] truncated_by write skipped: {e!r}", file=sys.stderr)


async def _reap_correlation_task(task: Any) -> None:
    """`correlation_task` (item 3's fire-and-forget dispatch) is only ever awaited by
    `_inject_correlation`, itself only reached when MAIN prepares a SECOND model request. A run
    that closes after one request — or exits `_drive_agent` through any other handled exception
    first — would otherwise leave the task running past `run_investigation`'s return: still
    issuing backend/model calls and writing the run dir (queries table, `gather_raw/l-00c/*`,
    `budget.json`, the session store) concurrently with `run.py`'s post-run steps on that same
    tree, with any exception it raises never retrieved. Called unconditionally after
    `_drive_agent` returns; a no-op if `_inject_correlation` already consumed it."""
    if task is None:
        return
    if not task.done():
        task.cancel()
    try:
        await task
    except Exception as e:  # noqa: BLE001 — this cleanup step must not itself break the run
        print(f"[run.py] correlation task reaped with an unretrieved fault: {e!r}",
              file=sys.stderr)
    except asyncio.CancelledError:
        pass


async def _drive_agent(  # noqa: PLR0913 — the loop's own inputs: agent, prompt, deps, store, bounds
    agent: Agent[AgentDeps, str], prompt: str, deps: AgentDeps, store: Any, session_id: str,
    bounds: challenge_gate.Bounds, message_history: list | None = None,
) -> tuple[Any, str | None, str | None]:
    """Runs the `async for node in run` loop and classifies its caught exits into
    `(truncated_by, exit_reason)`; returns the (possibly unfinished) `run` alongside them so
    the caller can still read `run.result`/`run.ctx` on a clean exit."""
    truncated_by: str | None = None
    exit_reason: str | None = None
    run: Any = None
    try:
        async with agent.iter(
            prompt, deps=deps,
            # A RESUMED run's inherited prefix, or None for a fresh one. The store's render
            # processor rebuilds history from the store on every request and `selection.ingest`
            # compares the live list against `last_render_len` — which a fork has ALREADY
            # seeded to its inherited prefix. So a fresh `agent.iter`, whose list starts empty,
            # underflows against a store that is correct. Handing the prefix back here is what
            # closes that, and it is exact rather than approximate: `fork` and
            # `hydrate(role="send")` both truncate through `_complete_prefix_len`.
            message_history=message_history,
            # RS7: the ceiling that terminates a run is raised by the gate's own forced-turn
            # cap, read FROM the bound rather than restated as a literal. Every run pays it
            # whether or not the gate ever fires — a property of the run, not of a review.
            usage_limits=UsageLimits(request_limit=challenge_gate.raised_request_limit(bounds)),
        ) as run:
            async for node in run:
                _log_node(node)
    except UsageLimitExceeded as e:
        print(f"[run.py] request limit reached ({e}); writing partial trace",
              file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_REQUEST_LIMIT
        exit_reason = "UsageLimitExceeded"
    except UnexpectedModelBehavior as e:
        # RS6: a stubborn model that keeps retrying a call the gate refuses (e.g. a write of
        # report.md) exhausts the framework's shared tool-retry budget (`DEFAULT_TOOL_RETRIES`)
        # and pydantic_ai raises this; no other handler here catches it, so uncaught it takes
        # the process down. Force the unresolved close directly, bypassing the model — which
        # is exactly what got stuck — rather than end with no disposition at all.
        print(f"[run.py] {e}; forcing an unresolved close (retry budget exhausted)",
              file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_RETRY_EXHAUSTED
        exit_reason = "UnexpectedModelBehavior"
        # R4: this handler bypasses the gate and commits through the same path, so on a run
        # whose disposition ALREADY committed it would replace a confident finding with the
        # unresolved one it forces and destroy that close's review record. A run that errors
        # AFTER closing keeps what it decided; the error survives in the logs above.
        if challenge_gate.ReviewState.of(deps).closed:
            print("[run.py] the investigation already closed; keeping its disposition",
                  file=sys.stderr)
        else:
            try:
                from .close_tool import _close_investigation_async

                # `inconclusive` short-circuits ahead of the gate, so no stage and no bound
                # is ever consumed here; the run's own bounds are threaded anyway rather
                # than re-resolved, so this limb cannot end up acting on a different value
                # from the one the rest of the run was built with.
                #: `forced=True`: the framework's own close is exempt from the flagged-row
                #: gate. No model is left to repair the row, and refusing here would end the
                #: run with NO report.md — dead-lettering it at persist for the wrong reason.
                #: Every close the MODEL invokes is still gated.
                await _close_investigation_async(
                    deps, "inconclusive", stages=None, bounds=bounds, forced=True,
                )
            except Exception as close_err:  # noqa: BLE001 — this exit must not itself raise
                # ...but it must not SWALLOW it either: logging alone left a forced close that
                # failed indistinguishable downstream from one that committed (same
                # truncated_by, same exit_reason), and the run dead-lettered at persist for a
                # missing artifact, invisibly. The exit reason carries the failure.
                print(f"[run.py] forced close after retry exhaustion also failed "
                      f"({close_err!r})", file=sys.stderr)
                exit_reason = "ForcedCloseFailed"
    except RunAborted as e:
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_ABORTED
        exit_reason = "RunAborted"
    except BudgetKill as e:
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_BUDGET
        exit_reason = "BudgetKill"
    except (sqlite3.Error, session_store.StoreError) as e:
        # StoreError, not StoreAppendError: PayloadNotRepresentable / IngestTailUnderflow /
        # CyclicParentChain / UnknownSchemaVersion all reach here from inside the
        # ProcessHistory hook, and any one escaping takes the whole run.py process down
        # instead of writing the partial trace this handler exists for.
        print(f"[run.py] store append failed ({e!r}); stopping the run", file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_STORE
        exit_reason = "StoreAppendError"
    finally:
        _flush_run_end(run, store, session_id, truncated_by)
    return run, truncated_by, exit_reason


async def run_investigation(  # noqa: PLR0913 — a composition root: every parameter is a
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
    defender_dir: Path,
    model_name: str | None = None,
    make_model: MakeModel | None = None,
    verbs: Any = None,
    limits: dict | None = None,
    box: Any = None,
    store_factory: StoreFactory | None = None,
    review_stages: Any = None,
    bounds: challenge_gate.Bounds | None = None,
    model_override: str | None = None,
    toolset: Any = None,
    resume: Any = None,
) -> dict:
    model_name = resolve_main_model(model_name)
    # Lead-0's OWN registry seam: a scenario that injected no `verbs=` at all must not have
    # lead-0 acquire one via the MAIN-gather default resolved below. Captured before it.
    lead_zero_verbs = verbs
    # lint-default: ok — DI seam owning its default (the gate's bounds, carrying the request
    # ceiling's BASE), resolved once at the entry point and threaded inward as a concrete value.
    gate_bounds = bounds if bounds is not None else challenge_gate.default_bounds()
    make_model = make_model or providers.build_for_effort
    adapters = defender_dir / "scripts" / "adapters"
    verbs = verbs if verbs is not None else ModuleVerbRegistry(adapters, GATHER_DEF.verb_grant)  # lint-default: ok — DI seam owning its default (tree-derived; no signature default possible)
    limits = limits if limits is not None else DEFAULT_LIMITS  # lint-default: ok — DI seam owning its default (the cap table, threaded inward)
    budget_started_monotonic = time.monotonic()
    open_budget(run_dir, run_id)
    # `<run_dir>/wire_logs/llm_requests.jsonl`, one level down and NOT at the run root: the
    # subdirectory is what keeps this log out of every reader agent's `under(run, SEG)` read
    # shape, MAIN's and GATHER's alike. `observe.wire_log_path` owns the location.
    logger = observe.RequestLogger(observe.wire_log_path(run_dir))

    # THE one place a live review bundle can honestly be built, and it sits BELOW the logger:
    # the entry point is the only frame holding all three things a live stage needs — the run
    # dir it anchors its policies on, the operator's model choice, and the run's own
    # `RequestLogger`. Built above the logger, every stage mints a private one and writes to a
    # file no reader opens, so the review's model calls charge a provider and land in no
    # accounted total.
    #
    # `model_override` is the operator's RAW `--model`, deliberately not `model_name` above,
    # which is already resolved against the investigator's default. Handing the resolved one
    # over would give the review a non-`None` explicit model on every run, making its own
    # pinned default unreachable in production.
    #
    # Guarded, because this sits BELOW the open: `live_review_stages` reads three prompt assets
    # off the tree and `role_prompt` raises `FileNotFoundError` on a missing one, which would
    # leave `llm_requests.jsonl` open AND permanently registered in `observe._ACTIVE_PATHS`, so
    # a second `run_investigation` in the same process could never reopen that path. Its own
    # handler rather than the store-setup one below: a missing prompt asset is not a store
    # fault and must not be reported as one.
    try:
        stages = (
            review_stages if review_stages is not None
            else review_roles.live_review_stages(  # lint-default: ok — DI seam owning its default (the live bundle, buildable only where the run dir and the run's logger are)
                run_dir, defender_dir, logger=logger, model_override=model_override,
            )
        )
    except BaseException:
        logger.close()
        raise

    case_id = uuid.uuid4().hex
    factory = _resolve_store_factory(resume, store_factory)  # lint-default: ok — DI seam owning its default (R12's fifth seam; a resume derives its own, and outranks it)
    store = None
    try:
        store = factory(case_id, run_dir)
        session_store.write_case_pointer(run_dir, case_id=case_id, store_path=store.path)
        # A resume JOINS a case rather than minting one: the store the factory hands back is
        # the SOURCE run's, and the prefix rows live in it.
        #
        # KNOWN GAP, not a claim of correctness. `case_id` above is a fresh uuid, and the
        # pointer therefore pairs it with a store named after the SOURCE's case — a store that
        # holds no session under this id, because `fork` inherits its parent row's `case_id`.
        # Two things follow, and both are live: `branch.open_source_store` on a sibling run dir
        # can never match its derived path against the recorded one, so a branch cannot be
        # taken from a branch; and any reader resolving a run dir to a store and then to
        # `main_session_id` — `scripts/visualize/visualize_run.py` does exactly this — lands on
        # the ROOT of the lineage, i.e. the source run's transcript rather than the sibling's.
        # Closing it means deciding what a sibling's case identity IS, which is #920 PR 2's
        # call, not a line to change here.
        session_id, resume_history = branch.open_main_session(store, resume)
    # `branch.BranchError` rides here with the store faults: a refused branch point (message 0,
    # no captured evidence, an empty or snapped frontier, a pointer that names another store)
    # is a SETUP failure, and without it the raise escapes `run_investigation` entirely —
    # leaving the sqlite connection open AND `llm_requests.jsonl` permanently registered in
    # `observe._ACTIVE_PATHS`, so the next sibling in an in-process sweep can never reopen it.
    except (sqlite3.Error, session_store.StoreError, branch.BranchError, OSError) as e:
        # The store is opened during SETUP, outside `_drive_agent`'s handler — so without
        # this, a stale-version file (or a plain filesystem fault: an unwritable
        # run_dir/runs_base for the pointer write or the store's own mkdir) takes the whole
        # process down instead of ending the run through the handled `truncated_by="store"`
        # exit. Not one model turn is driven.
        print(f"[run.py] store setup failed ({e!r}); ending the run", file=sys.stderr)
        if store is not None:
            # `factory()` can succeed — a live connection, DDL already run — and a LATER
            # call in this same try (`write_case_pointer`, `new_session`) still fail;
            # without this the connection (and its WAL/-shm sidecars) is never closed.
            try:
                store.close()
            except Exception as close_err:  # noqa: BLE001 — best-effort on an already-failing path
                print(f"[run.py] store close after setup failure also failed "
                      f"({close_err!r})", file=sys.stderr)
        logger.close()
        return _run_summary(
            output=None, model_name=model_name, requests=logger.n_requests,
            truncated_by="store", exit_reason=type(e).__name__,
            case_id=case_id, store_path=None,
        )

    prompt, lead_zero_block, lead_zero_status = _opening_prompt(
        resume, run_dir, alert_path, defender_dir,
        verbs=lead_zero_verbs, limits=limits, run_id=run_id,
    )

    # Item 3's async frame: scheduled here (after item 1 has resolved synchronously) and
    # awaited later, inside the store's render processor, right before MAIN's SECOND request.
    # A scenario with no injected registry dispatches nothing.
    correlation_task: Any = None
    # `resume is None` is stated here rather than carried by a nulled `lead_zero_verbs`: a
    # resume skipping turn-0 work is a fact about the run, and a reader at this line must be
    # able to see it without tracing where the registry was set to `None` and why.
    if resume is None and lead_zero_verbs is not None:
        from . import lead_zero as lead_zero_mod

        try:
            alert_doc = json.loads(alert_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            alert_doc = {}
        contract = lead_zero_mod.prepare_correlation_lead(
            run_dir, alert_doc, lead_zero_block, lead_zero_status,
        )
        if contract is not None:
            goal, what_to_summarize = contract
            # Chain the budget hooks around lead-0's OWN dispatch: routing through
            # QueryCapture/the gather machinery does not by itself move `budget.json` —
            # `subagent_spawns` is gated on the literal tool name "gather", which a harness
            # dispatch never emits.
            lead_zero_mod._budget_account(run_dir, run_id, "gather", limits)
            correlation_task = asyncio.ensure_future(lead_zero_mod.dispatch_correlation(
                run_dir=run_dir, defender_dir=defender_dir, run_id=run_id,
                goal=goal, what_to_summarize=what_to_summarize, verbs=lead_zero_verbs,
                limits=limits, make_model=make_model, logger=logger, box=box, store=store,
                # Share the RUN's own budget-clock origin rather than letting it default to a
                # fresh `time.monotonic()` stamp taken whenever this task happens to start.
                budget_started_monotonic=budget_started_monotonic,
            ))

    agent = build_agent(
        defender_dir, logger, make_model, main_model=model_name, verbs=verbs, limits=limits,
        store=store, session_id=session_id, review_stages=stages, bounds=gate_bounds,
        correlation_task=correlation_task, toolset=toolset,
    )
    deps = replace(
        bind(MAIN_DEF, run_dir, defender_dir=defender_dir, box=box),
        run_id=run_id,
        budget_started_monotonic=budget_started_monotonic,
    )

    t0 = time.time()
    run, truncated_by, exit_reason = await _drive_agent(
        agent, prompt, deps, store, session_id, gate_bounds, resume_history,
    )
    wall_ms = (time.time() - t0) * 1000.0
    await _reap_correlation_task(correlation_task)

    result = run.result if run is not None else None
    try:
        observe.write_trace(run_dir, store=store, session_id=session_id, wall_ms=wall_ms)
    except Exception as e:  # noqa: BLE001 — a broken store must not swallow the artifact entirely
        print(f"[run.py] write_trace failed ({e!r}); writing an empty trace", file=sys.stderr)
        try:
            write_guarded(run_dir / "tool_trace.jsonl", "")
        except OSError as fallback_err:
            # The fallback runs while an exception is already being handled, and its target is
            # a name the box can plant an alias at — unguarded, one planted entry converts "the
            # trace could not be built" into an uncaught OSError that ends the run at its last
            # step, discarding the summary and every artifact already written. The trace is
            # observability; the run's result is not.
            print(f"[run.py] the empty-trace fallback also failed ({fallback_err!r}); "
                  f"{run_dir} has no tool_trace.jsonl", file=sys.stderr)
    logger.close()
    output = result.output if result is not None else None
    return _run_summary(
        output=output, model_name=model_name, requests=logger.n_requests,
        truncated_by=truncated_by, exit_reason=exit_reason,
        case_id=case_id, store_path=store.path,
    )
