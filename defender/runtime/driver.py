
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

from . import compaction
from . import observe
from . import orient
from . import permission
from . import providers
from . import selection
from . import session_store
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
    """MAIN's system prompt: the SKILL's BODY, without its frontmatter (#810).

    The frontmatter is file metadata — `name`, `description` — that nothing in this runtime
    parses; it used to ride into the prompt verbatim, and with it an `allowed-tools:` line
    naming verbs the `ToolSet` does not register. The roster has exactly one enforced owner
    (`MAIN_DEF.tools` → `register_tools`), so a second copy in prose could only ever drift,
    and drifting it teaches the model to call a tool it does not have."""
    return strip_frontmatter((defender_dir / "SKILL.md").read_text(encoding="utf-8"))


def _user_prompt(  # noqa: PLR0913 — the harness's own pre-turn seams (#808)
    run_dir: Path, alert_path: Path, defender_dir: Path, salt: str,
    *, verbs: Any = None, limits: dict = DEFAULT_LIMITS, run_id: str | None = None,
) -> tuple[str, Any, str]:
    """#808 — lead-0's own call site. It takes its OWN exception handler (K8/N3): a
    `BudgetKill` or `circuit_breaker.RunAborted` raised inside `resolve_lead_zero` (its
    QueryCapture path inherits both) is caught HERE, so it never escapes `_user_prompt` and
    ends the run before MAIN's first prompt — the run degrades the section instead.

    Returns `(prompt, entities, status)`: the entities/status feed item 3's dispatch gate
    (`d22`), computed once here rather than re-resolved by a second lead_zero call."""
    from . import lead_zero as lead_zero_mod
    from .circuit_breaker import RunAborted

    entities: Any = lead_zero_mod.Entities()
    status = lead_zero_mod.STATUS_FAILED
    try:
        result = lead_zero_mod.resolve_lead_zero(
            run_dir=run_dir, defender_dir=defender_dir, alert_path=alert_path, salt=salt,
            verbs=verbs, limits=limits, run_id=run_id,
        )
        lead_zero_text = lead_zero_mod.render_orient_section(result)
        entities = result.entities
        status = result.status
    except (BudgetKill, RunAborted) as e:
        print(f"[run.py] lead-0 degraded ({e!r}); continuing without it", file=sys.stderr)
        degraded = lead_zero_mod.LeadZeroResult(
            text=lead_zero_mod._render_section(
                lead_zero_mod._unavailable(f"a run-level fault interrupted resolution: {e!r}"),
                salt,
            ),
            entities=lead_zero_mod.Entities(), status=lead_zero_mod.STATUS_FAILED,
        )
        lead_zero_text = lead_zero_mod.render_orient_section(degraded)

    orientation = orient.orientation(
        run_dir, defender_dir, alert_path, salt, lead_zero_section=lead_zero_text,
    )
    prompt = (
        "Begin the investigation.\n\n"
        f"run_dir: {run_dir}\n"
        f"alert: {alert_path}\n\n"
        f"{orientation}"
    )
    return prompt, entities, status


def _budget_state_for_enforcement(state: dict, deps: AgentDeps) -> dict:
    return {**state, "started_monotonic": deps.budget_started_monotonic}


def _budget_short_circuit(
    deps: AgentDeps, tool_name: str, limits: dict,
    logger: observe.RequestLogger, agent_id: str,
) -> str | None:
    # RS16: the exemption has to sit AHEAD of the tail kill, not only inside `should_refuse`.
    # The tail kill is unconditional, so an exemption expressed only in the refusal check
    # still ends the run at the close — and the gate's own forced turns (extra tool calls,
    # up to four stage deadlines of wall clock inside ONE close) are what push a run past the
    # tail to begin with. Closing must remain possible under exactly the pressure the gate
    # creates, which is also what the budget refusal message now tells the model to do.
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

    `selection.render` opens the stamp for the request it is preparing, but that
    request's duration only exists once the model has answered — here. The stamp is
    consumed by the next round's `ingest`, which runs after this hook, so patching it
    in place is what puts a real number in `message.duration_ms` instead of the
    placeholder the renderer had to leave."""
    if store is None or session_id is None:
        return
    pending = getattr(store, "pending_stamps", None)
    if not pending or session_id not in pending:
        return
    run_step, _placeholder, wire_sha = pending[session_id]
    pending[session_id] = (run_step, duration_ms, wire_sha)


def _make_hooks(  # noqa: PLR0913 — the hook set's full wiring: logging, budget, and the store stamp
    logger: observe.RequestLogger, agent_id: str, *, enforce: bool, limits: dict = DEFAULT_LIMITS,
    session_id: str | None = None, store: Any = None,
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

    A named function and not three nested conditionals at the call site because there are three
    arms now, each answering "what prefix does this agent share, and with whom":

    1. An explicit `cache_key` wins. Gather is its whole population (#835): a gather session HAS
       a conversation, but its `agent_id` is `gather:{lead_id}`, so arm 2 would route every
       sibling lead to a different replica and none of them could share the prefix they have in
       common — gather's SKILL.md and the dispatched system's catalog, byte-identical across
       leads AND across runs. Only the caller knows what that prefix is keyed on, so it says.
    2. WITH a session, the key is that conversation's: one growing prefix, and every turn of it
       wants the replica already holding the previous turn.
    3. WITHOUT one the agent is a one-shot (the review lenses are the whole of this class), so
       there is no within-run prefix to keep warm and the bare `agent_id` is better: it is
       stable ACROSS runs, the only reuse a single-call role can have — its role instructions,
       identical every run, warm on the replica this key routes to.

    `defender/CLAUDE.md`'s anchor-a-default rule is satisfied by this being the ONE site that
    knows the policy; threading a resolved key inward would make all four callers compute one.
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
) -> Agent[Any, str]:
    model_name = defn.model()
    built = make_model(model_name, defn.effort)
    # Applied HERE and not inside `make_model`: the seam is a two-positional-argument callable
    # every engine in the tree (and a dozen test doubles) passes by that shape, and the key is
    # not a property of the model anyway.
    settings = providers.cache_affinity(
        model_name, built.settings, _affinity_key(agent_id, session_id, cache_key),
    )
    capabilities: list[Any] = [
        _make_hooks(logger, agent_id, enforce=defn.budget_enforced, limits=limits,
                    session_id=session_id, store=store),
        *extra_capabilities,
    ]
    if defn.tools.query:
        from defender._paths import PATHS

        from .query_tool import QueryCapture
        from .verbs import VerbRegistry

        if verbs is None:
            verbs = ModuleVerbRegistry(PATHS.defender_dir / "scripts" / "adapters", defn.verb_grant)
        if not isinstance(verbs, VerbRegistry):
            raise TypeError(
                f"the query tool needs a real VerbRegistry, got {type(verbs).__name__} — a "
                "registry-shaped stand-in that never went through the constructor is refused"
            )
        capabilities.append(QueryCapture(verbs, defn.role.value))
    agent: Agent[Any, str] = Agent(
        built.model,
        deps_type=deps_type,
        instructions=instructions,
        capabilities=capabilities,
        model_settings=settings,
        retries={"tools": DEFAULT_TOOL_RETRIES, "output": 0},
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
    # R1 (#774): report.md leaves the model's own write allow-list entirely — the close
    # tool is now its ONLY writer, rendering it host-side through validate_artifact rather
    # than accepting a model-supplied write/edit of it.
    return permission.build_named_write_allow(roots.run_dir, ("investigation.md",))


MAIN_DEF = AgentDefinition(
    role=AgentRole.MAIN,
    model=resolve_main_model,
    effort="low",
    # `append`, not `write` (#810): main's write allowlist is exactly investigation.md, and
    # that document is append-only by construction. The general verbs offered an anchored
    # replace the artifact never admitted — seven of the eight non-append edit_file calls
    # measured across three runs failed. Same move #774 made for report.md, one artifact later.
    tools=ToolSet(read=True, bash=True, append=True, close=True),
    corpus_dirs=_CORPUS_DIRS,
    bash_shapes=(_main_bash_shapes,),
    write_shapes=(_main_write_shape,),
    deps_cls=AgentDeps,
    deny_reason=permission.FALLTHROUGH_DENY_REASON,
    budget_enforced=True,
)

#: The gather grant (#632, c18): the census over the 14 committed query templates plus 20
#: past runs' history — 21 read verbs across 7 systems, plus `health-check` granted uniformly
#: per system rather than per verb (the split carries no security content). `cmdb.list-roles`
#: and `identity.list-authorized-hosts` are granted to nobody: in the registry, exercised by
#: no template and no run.
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
    tools=ToolSet(read=True, bash=True, template_search=True, query=True),
    corpus_dirs=_CORPUS_DIRS,
    bash_shapes=(_gather_bash_shapes,),
    deps_cls=GatherDeps,
    deny_reason=permission.GATHER_FALLTHROUGH_DENY_REASON,
    budget_enforced=True,
    verb_grant=_gather_verb_grant(),
)


def _gather_instructions(defender_dir: Path) -> str:
    """Gather's system prompt, frontmatter stripped for the same reason MAIN's is. Gather's
    carries no `allowed-tools`, so nothing was being mis-taught here — but a prompt loader
    that keeps metadata for one role and drops it for the other is the asymmetry the next
    `allowed-tools` line slips through."""
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

    `compaction.fold_boundary` is the same trigger the retired in-driver glue used: the
    highest CONTIGUOUS closed investigation loop that produced a resolved lead, and `0`
    until one closes. That gate is the whole policy — without it a fold fires on every
    round, and since the boundary it keys on advances every round too, each one mints a
    FRESH frontier and orphans the turns before it. The model would then re-enter every
    round having lost its own tool results (#705's port dropped this trigger and nothing
    replaced it; `fold_boundary` is FK10's open decision, settled here on the loop
    number so one closed loop maps to exactly one frontier row).

    The loop number, not a row count, is the boundary: it is stable across the rounds
    WITHIN a loop, so `_fold_impl`'s reuse lookup hits and the same frontier is reused
    until the next loop closes.
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
        """#808/K10/F2 — item 3's async frame, awaited HERE: right before MAIN's SECOND
        request is prepared (`requests == 1`, i.e. round 1 already completed), never before
        the first (the marker must not be in message 0). Writes the summary DIRECTLY into
        MAIN's own session so the store-hydrated list the next render produces carries it —
        `ProcessHistory` returns `hydrate(...)`, a list rebuilt FROM the store, so a plain
        append to `messages` would be discarded."""
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
        # The framework appends this round's own request to state history and only
        # THEN checks the request limit (pydantic_ai's `_prepare_request`), so by the
        # time this processor runs the doomed round's continuation is already in
        # `messages`. Mirror the same check here and withhold it from the store —
        # otherwise a round that never actually happens gets committed anyway, and the
        # run-end flush can never recover the true terminal response.
        #
        # RS7: the ceiling is the one the RUN was handed, not the un-raised base. Pinned to
        # the base, this mirror withheld the extra rounds the raise exists to buy — rounds
        # that genuinely execute — so they skipped the history-compaction path entirely and
        # the model was handed raw, unrendered history for them.
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


def _make_gather_recorder(store: Any, session_id: str, agent_id: str):
    async def process(ctx: RunContext[GatherDeps], messages: list) -> list:
        # Same withholding rule as the main processor: pydantic_ai appends the round's own
        # continuation to history BEFORE it checks the request limit, so on the doomed
        # round `messages` already ends with a request that will never be sent. Committing
        # it would leave a phantom, never-executed round in this gather's session — and
        # unlike main there is no run-end flush on this side to reconcile it afterwards.
        usage = getattr(ctx, "usage", None)
        requests = int(getattr(usage, "requests", 0) or 0)
        if requests >= GATHER_REQUEST_LIMIT:
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
    base.

    The base was the default here, mirroring at one call frame's remove the exact staleness
    RS7 exists to prevent: the composition root honoured the raised ceiling while an omitted
    argument would have had this reader withhold from the compaction path the very rounds the
    raise buys. Sole production caller passes the run's own value; the default exists because
    the assembly seam is constructed directly by tests that pin the capability COUNT and have
    no ceiling to hand it."""
    # lint-default: ok — resolved once into a fresh name; the honest default is derived from
    # the bounds object and cannot be a signature default without an import-time read of it.
    limit = (
        request_limit if request_limit is not None
        else challenge_gate.raised_request_limit(challenge_gate.default_bounds())
    )
    return [ProcessHistory(_make_store_render_processor(
        store, session_id, fold=_compaction_enabled(), request_limit=limit,
        correlation_task=correlation_task))]


def _gather_extra_capabilities(store: Any, session_id: str, agent_id: str) -> list[ProcessHistory[Any]]:
    return [ProcessHistory(_make_gather_recorder(store, session_id, agent_id))]


def build_agent(  # noqa: PLR0913 — composition root: config + DI seams + the store's identity
    defender_dir: Path, logger: observe.RequestLogger,
    make_model: MakeModel = providers.build_for_effort,
    *, main_model: str | None = None, verbs: Any = None, limits: dict = DEFAULT_LIMITS,
    store: Any = None, session_id: str | None = None, review_stages: Any = None,
    bounds: challenge_gate.Bounds,
    correlation_task: Any = None,
) -> Agent[AgentDeps, str]:
    # The bounds arrive RESOLVED, non-`Optional`, and are used under their own name. They
    # used to be re-coalesced here, which gave the gate's ONE bounds object a default at four
    # depths — against the anchor-a-default-in-one-place convention, and with that
    # convention's usual cost: the entry point could resolve one value while a direct build
    # resolved another from its own environment read.
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
    # Named rather than inlined into the build call because the EFFECTIVE definition — not
    # `MAIN_DEF` — is what decides below whether this root registers the close tool, the same
    # way `register_tools` reads the effective ToolSet for every other capability bit.
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
    )

    # agent_id → the gather session opened for it. Keyed by agent_id and not "the last one
    # built" because sibling leads are dispatched CONCURRENTLY (one `gather` tool call per
    # lead in a single main turn), so "the current gather session" is not a thing that
    # exists. `agent_id` is `gather:{lead_id}` and `_run_gather`'s `claim_lead` refuses a
    # reused `lead_id`, so it is unique within a run.
    gather_sessions: dict[str, str] = {}

    def _build_gather(agent_id: str, system: str) -> Agent[GatherDeps, str]:
        gather_extra: Sequence[Any] = ()
        gather_session_id: str | None = None
        if store is not None:
            gather_session_id = store.new_session(agent_id=agent_id)
            gather_sessions[agent_id] = gather_session_id
            gather_extra = _gather_extra_capabilities(store, gather_session_id, agent_id)
        return build_gather_agent(
            defender_dir, logger, agent_id, make_model, verbs, limits,
            extra_capabilities=gather_extra, session_id=gather_session_id,
            # Keyed on the SYSTEM, not this lead and not this run (#835). What the dispatch
            # prompt puts in front of the lead's question — gather's SKILL.md, the descriptor
            # index, this system's catalog — is identical for every lead dispatched here, in
            # this run and the next; the key is the only thing that routes them to one replica
            # so the second lead reads that prefix instead of re-paying it. `agent_id` stays
            # `gather:{lead_id}`: the wire log, the session store and the terminator stamp all
            # key on it, and none of them wants a system.
            cache_key=f"{GATHER_AGENT_ID_PREFIX}{system}",
        )

    def _stamp_gather_terminator(agent_id: str, reason: str) -> None:
        """`_flush_run_end`'s stamp, for a GATHER session (#826 item 1). Best-effort for the
        same reason: the store may be exactly what ended this lead, and losing the terminator
        must not also lose the lead's summary. There is no flush of a terminal exchange to
        pair with it — gather's recorder commits every round as it goes and deliberately
        withholds the doomed round's own continuation, so there is nothing left to reconcile
        at the end; only the stamp is missing, and only the stamp is added."""
        gather_session_id = gather_sessions.get(agent_id)
        if store is None or gather_session_id is None:
            return
        try:
            store.set_truncated_by(gather_session_id, reason)
        except Exception as e:  # noqa: BLE001 — the store may already be the reason we're here
            print(f"[run.py] gather truncated_by write skipped for {agent_id}: {e!r}",
                  file=sys.stderr)

    # ALWAYS the role's own committed grant (#632) — never the per-call `verbs=` registry's
    # own grant. The dispatch catalog/template index is a ROLE-LEVEL surface (the same one
    # the generated roster and its audit are scored against, verb_roster.py), not a per-run
    # one; a test injecting a registry scoped narrower (or differently) than GATHER_DEF's
    # real grant, for reasons that have nothing to do with catalog content, must not narrow
    # what the catalog advertises.
    register_gather_tool(
        agent, _build_gather, GATHER_REQUEST_LIMIT, GATHER_DEF.verb_grant,
        _stamp_gather_terminator,
    )
    # `build_agent` has no `run_dir` of its own, so it cannot BUILD a live bundle — a bundle
    # carrying live stages is assembled by `run_investigation`, the entry point that holds the
    # real run dir, and arrives here already bound to it. The fallback below must never
    # substitute the SOURCE TREE for the missing run dir: doing that anchored each review
    # role's compiled policy on the repo checkout and had every stage call append its trace
    # to a file inside it. An empty bundle fails the review closed at call time, through the
    # gate's own fault arm, instead of quietly acting on the wrong tree.
    stages = (
        review_stages if review_stages is not None
        else review_roles.ReviewStages()  # lint-default: ok — DI seam owning its default (the UNBOUND bundle: this root holds no run dir, so `stage()` raises UnboundReviewStage and the gate fails the close closed)
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
    """R11's true `finally`: capture the terminal exchange (whatever `run` actually holds
    on ANY exit, clean or not) and stamp `truncated_by`, both best-effort so a broken
    store cannot mask the exit that got us here."""
    if run is not None:
        try:
            live = run.ctx.state.message_history
            confirmed_len = store.last_render_len(session_id) or 0
            if len(live) <= confirmed_len:
                # A prior round's processor already committed everything `live` holds
                # (or more — `_make_store_render_processor`'s request-limit check
                # withholds a doomed round's own continuation, so `live` can be one
                # message SHORTER than what is already confirmed). Either way there is
                # nothing new to add, and truncating `live` here would try to re-add
                # content the store has already, correctly, chosen not to hold.
                pass
            else:
                # New content past the last confirmed round: drop a trailing incomplete
                # continuation (one built but never itself confirmed by a processor
                # call — the request-limit / uncaught-mid-round shapes) so the tail
                # ends on the response that IS confirmed, never on an unconfirmed one.
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
    """#808 review fix — `correlation_task` (item 3's fire-and-forget dispatch, scheduled via
    `asyncio.ensure_future` in `run_investigation`) is only ever awaited by
    `_inject_correlation`, itself only reached when MAIN prepares a SECOND model request. A
    run that closes after exactly one request — or that exits `_drive_agent` through any of
    its OTHER handled exceptions before a second request is ever prepared — would otherwise
    leave this task running, unawaited and uncancelled, past `run_investigation`'s own
    return: it keeps issuing real backend/model calls and writing to the run dir (queries
    table, `gather_raw/l-00c/*`, `budget.json`, the session store) concurrently with
    `run.py`'s post-run steps on that same tree, and any exception it raises is never
    retrieved. Called unconditionally right after `_drive_agent` returns: a no-op if
    `_inject_correlation` already consumed it."""
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
    bounds: challenge_gate.Bounds,
) -> tuple[Any, str | None, str | None]:
    """Runs the bare `async for node in run` loop and classifies the four caught exits
    into `(truncated_by, exit_reason)`; returns the (possibly unfinished) `run` alongside
    them so the caller can still read `run.result`/`run.ctx` on a clean exit."""
    truncated_by: str | None = None
    exit_reason: str | None = None
    run: Any = None
    try:
        async with agent.iter(
            prompt, deps=deps,
            # RS7 (#774): the ceiling that terminates a run is raised by the gate's own
            # forced-turn cap, read FROM the bound rather than restated as a literal —
            # every run pays it whether or not the gate ever fires (a property of the
            # run, not of a review that happened).
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
        # RS6 (#774): a stubborn model that keeps retrying a call the gate refuses (e.g. a
        # write of report.md, narrowed off the allow-list by R1) exhausts the framework's
        # shared tool-retry budget (`DEFAULT_TOOL_RETRIES`) and pydantic_ai raises this —
        # none of the OTHER handlers here catch it, so uncaught it takes the whole process
        # down. Force the unresolved close directly (bypassing the model, which is exactly
        # what got stuck) rather than let the run end with no disposition at all.
        print(f"[run.py] {e}; forcing an unresolved close (retry budget exhausted)",
              file=sys.stderr)
        truncated_by = session_store.TRUNCATED_BY_RETRY_EXHAUSTED
        exit_reason = "UnexpectedModelBehavior"
        # R4, the limb terminality has to answer separately: this handler bypasses the gate
        # and commits through the same path, so on a run whose disposition ALREADY committed
        # it silently replaced a confident finding with the unresolved one it forces — and
        # destroyed that close's review record with it. The handler is not withdrawn (it is
        # the only thing between a stuck model and no disposition at all); it is made aware
        # of the close it is about to overwrite. A run that errors AFTER closing keeps what
        # it decided, and the error survives in the logs above rather than in the case record.
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
                #: `forced=True` (#836/H1): the framework's own close is exempt from the
                #: flagged-row gate. There is no model left to repair the row with, and
                #: refusing here would end the run with NO report.md at all — which
                #: dead-letters it at persist before investigation.md is ever validated,
                #: for the wrong reason. Every close the MODEL invokes is still gated.
                await _close_investigation_async(
                    deps, "inconclusive", stages=None, bounds=bounds, forced=True,
                )
            except Exception as close_err:  # noqa: BLE001 — this exit must not itself raise
                # ...but it must not SWALLOW it either. Until #836 this handler only logged,
                # so a forced close that failed and one that committed were indistinguishable
                # downstream — same truncated_by, same exit_reason, and the only difference a
                # report.md nobody checks. The run then dead-lettered at persist for a missing
                # artifact, invisibly. The exit reason now carries the failure.
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
        # StoreError, not StoreAppendError: PayloadNotRepresentable / IngestTailUnderflow
        # / CyclicParentChain / UnknownSchemaVersion all reach here from inside the
        # ProcessHistory hook, and any one of them escaping takes the whole run.py
        # process down instead of writing the partial trace this handler exists for.
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
    salt: str,
    model_name: str | None = None,
    make_model: MakeModel | None = None,
    verbs: Any = None,
    limits: dict | None = None,
    box: Any = None,
    store_factory: StoreFactory | None = None,
    review_stages: Any = None,
    bounds: challenge_gate.Bounds | None = None,
    model_override: str | None = None,
) -> dict:
    model_name = resolve_main_model(model_name)
    # #808/K12/d49 — lead-0's OWN registry seam: a scenario that injected no `verbs=` at all
    # must not have lead-0 acquire one by way of the ordinary MAIN-gather default resolved
    # a few lines below. Captured before that default is applied.
    lead_zero_verbs = verbs
    # lint-default: ok — DI seam owning its default (the #774 repair's seventh seam: the
    # gate's bounds, carrying the request ceiling's own BASE), resolved once at the entry
    # point and threaded inward as a concrete value.
    gate_bounds = bounds if bounds is not None else challenge_gate.default_bounds()
    make_model = make_model or providers.build_for_effort
    adapters = defender_dir / "scripts" / "adapters"
    verbs = verbs if verbs is not None else ModuleVerbRegistry(adapters, GATHER_DEF.verb_grant)  # lint-default: ok — DI seam owning its default (tree-derived; no signature default possible)
    limits = limits if limits is not None else DEFAULT_LIMITS  # lint-default: ok — DI seam owning its default (the cap table, threaded inward)
    budget_started_monotonic = time.monotonic()
    open_budget(run_dir, run_id)
    # `<run_dir>/observe/llm_requests.jsonl`, one level down and NOT at the run root: the
    # subdirectory is what keeps this log out of every reader agent's `under(run, SEG)` read
    # shape, MAIN's and GATHER's alike. See `observe.wire_log_path`, which owns the location.
    logger = observe.RequestLogger(observe.wire_log_path(run_dir))

    # THE one place a live review bundle can honestly be built, and it sits HERE — below the
    # logger, not above it. The entry point is the only frame holding all three things a live
    # stage needs: the run dir it anchors its policies on, the operator's model choice, and
    # the run's own `RequestLogger`. It used to be resolved ten lines further up, where the
    # logger did not yet exist, so every stage minted a private one and wrote to a file no
    # reader ever opened — the review's model calls charged a provider and landed in no
    # accounted total (#787). `build_agent`, which sees none of the three, used to substitute
    # the source tree for the run dir here.
    #
    # `model_override` is the operator's RAW `--model` and is deliberately a different value
    # from `model_name` above, which has already been resolved against the investigator's
    # default. Handing the resolved one to the review would give it a non-`None` explicit
    # model on every run, and the review's own pinned default would be unreachable in
    # production while a unit test calling the resolver with `None` still proved it was the
    # default.
    #
    # Guarded, because this resolution now happens BELOW the open: `live_review_stages` reads
    # three prompt assets off the tree and `role_prompt` raises `FileNotFoundError` on a
    # missing one. Above the logger that raise cost nothing; here it would leave
    # `llm_requests.jsonl` open AND permanently registered in `observe._ACTIVE_PATHS`, so a
    # second `run_investigation` in the same process could never reopen that path. The
    # store-setup handler below closes the logger for exactly this reason; this window needs
    # its own because a missing prompt asset is not a store fault and must not be reported
    # as one.
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
    factory = store_factory if store_factory is not None else _default_store_factory  # lint-default: ok — DI seam owning its default (R12's fifth seam)
    store = None
    try:
        store = factory(case_id, run_dir)
        session_store.write_case_pointer(run_dir, case_id=case_id, store_path=store.path)
        session_id = store.new_session(agent_id="main")
    except (sqlite3.Error, session_store.StoreError, OSError) as e:
        # FK-G: the store is opened during SETUP, outside `_drive_agent`'s own handler —
        # so without this, a stale-version file (or a plain filesystem fault: an unwritable
        # run_dir/runs_base for the pointer write or the store's own mkdir) takes the whole
        # process down instead of ending the run through the same handled
        # `truncated_by="store"` exit. Not one model turn is driven.
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

    prompt, lead_zero_entities, lead_zero_status = _user_prompt(
        run_dir, alert_path, defender_dir, salt,
        verbs=lead_zero_verbs, limits=limits, run_id=run_id,
    )

    # #808/F2 — item 3's async frame: scheduled here (right after `_user_prompt` returns,
    # i.e. after item 1 has resolved synchronously) and awaited later, inside the store's
    # own render processor, right before MAIN's SECOND request. A scenario with no injected
    # registry (`lead_zero_verbs is None`) dispatches nothing (K12).
    correlation_task: Any = None
    if lead_zero_verbs is not None:
        from . import lead_zero as lead_zero_mod

        try:
            alert_doc = json.loads(alert_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            alert_doc = {}
        contract = lead_zero_mod.prepare_correlation_lead(
            run_dir, alert_doc, lead_zero_entities, lead_zero_status,
        )
        if contract is not None:
            goal, what_to_summarize = contract
            # K23 — chain the budget hooks around lead-0's OWN dispatch: routing through
            # QueryCapture/the gather machinery does not, by itself, move `budget.json`
            # (P7, executed) — `subagent_spawns` is gated on the literal tool name "gather",
            # which a harness dispatch never emits.
            lead_zero_mod._budget_account(run_dir, run_id, "gather", limits)
            correlation_task = asyncio.ensure_future(lead_zero_mod.dispatch_correlation(
                run_dir=run_dir, defender_dir=defender_dir, salt=salt, run_id=run_id,
                goal=goal, what_to_summarize=what_to_summarize, verbs=lead_zero_verbs,
                limits=limits, make_model=make_model, logger=logger, box=box, store=store,
                # #808 review fix — share the RUN's own budget-clock origin (see
                # lead_zero.dispatch_correlation's docstring note) rather than letting it
                # default to a fresh `time.monotonic()` stamp taken whenever this task
                # happens to start.
                budget_started_monotonic=budget_started_monotonic,
            ))

    agent = build_agent(
        defender_dir, logger, make_model, main_model=model_name, verbs=verbs, limits=limits,
        store=store, session_id=session_id, review_stages=stages, bounds=gate_bounds,
        correlation_task=correlation_task,
    )
    deps = replace(
        bind(MAIN_DEF, run_dir, salt=salt, defender_dir=defender_dir, box=box),
        run_id=run_id,
        budget_started_monotonic=budget_started_monotonic,
    )

    t0 = time.time()
    run, truncated_by, exit_reason = await _drive_agent(
        agent, prompt, deps, store, session_id, gate_bounds,
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
            # a name the box can plant an alias at — so an unguarded call here lets one planted
            # entry convert "the trace could not be built" into an uncaught OSError that ends
            # the run at its last step, discarding the summary and every artifact already
            # written. The trace is observability; the run's result is not.
            print(f"[run.py] the empty-trace fallback also failed ({fallback_err!r}); "
                  f"{run_dir} has no tool_trace.jsonl", file=sys.stderr)
    logger.close()
    output = result.output if result is not None else None
    return _run_summary(
        output=output, model_name=model_name, requests=logger.n_requests,
        truncated_by=truncated_by, exit_reason=exit_reason,
        case_id=case_id, store_path=store.path,
    )
