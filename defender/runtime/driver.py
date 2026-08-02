
from __future__ import annotations

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
from pydantic_ai.exceptions import UsageLimitExceeded
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
from .verb_grant import VerbGrant
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


def _budget_state_for_enforcement(state: dict, deps: AgentDeps) -> dict:
    return {**state, "started_monotonic": deps.budget_started_monotonic}


def _budget_short_circuit(
    deps: AgentDeps, tool_name: str, limits: dict,
    logger: observe.RequestLogger, agent_id: str,
) -> str | None:
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
) -> Agent[Any, str]:
    built = make_model(defn.model(), defn.effort)
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
        model_settings=built.settings,
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
    return (defender_dir / "skills" / "gather" / "SKILL.md").read_text(encoding="utf-8")


def build_gather_agent(  # noqa: PLR0913 — composition root, same shape as build_agent
    defender_dir: Path, logger: observe.RequestLogger, agent_id: str,
    make_model: MakeModel = providers.build_for_effort,
    verbs: Any = None,
    limits: dict = DEFAULT_LIMITS,
    extra_capabilities: Sequence[Any] = (),
    session_id: str | None = None,
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


def _make_store_render_processor(store: Any, session_id: str, *, fold: bool):
    async def process(ctx: RunContext[AgentDeps], messages: list) -> list:
        # The framework appends this round's own request to state history and only
        # THEN checks the request limit (pydantic_ai's `_prepare_request`), so by the
        # time this processor runs the doomed round's continuation is already in
        # `messages`. Mirror the same check here and withhold it from the store —
        # otherwise a round that never actually happens gets committed anyway, and the
        # run-end flush can never recover the true terminal response.
        usage = getattr(ctx, "usage", None)
        requests = int(getattr(usage, "requests", 0) or 0)
        if requests >= DEFAULT_REQUEST_LIMIT:
            selection.ingest(store, session_id, messages[:-1], agent_id="main")
            return messages
        selection.ingest(store, session_id, messages, agent_id="main")
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


def _main_extra_capabilities(store: Any, session_id: str) -> list[ProcessHistory[Any]]:
    return [ProcessHistory(
        _make_store_render_processor(store, session_id, fold=_compaction_enabled()))]


def _gather_extra_capabilities(store: Any, session_id: str, agent_id: str) -> list[ProcessHistory[Any]]:
    return [ProcessHistory(_make_gather_recorder(store, session_id, agent_id))]


def build_agent(  # noqa: PLR0913 — composition root: config + DI seams + the store's identity
    defender_dir: Path, logger: observe.RequestLogger,
    make_model: MakeModel = providers.build_for_effort,
    *, main_model: str | None = None, verbs: Any = None, limits: dict = DEFAULT_LIMITS,
    store: Any = None, session_id: str | None = None,
) -> Agent[AgentDeps, str]:
    extra: list[ProcessHistory[Any]] = []
    if store is not None:
        assert session_id is not None, "a store requires its session_id (build_agent's own contract)"
        extra = _main_extra_capabilities(store, session_id)
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
        session_id=session_id,
        store=store,
    )

    def _build_gather(agent_id: str) -> Agent[GatherDeps, str]:
        gather_extra: Sequence[Any] = ()
        gather_session_id: str | None = None
        if store is not None:
            gather_session_id = store.new_session(agent_id=agent_id)
            gather_extra = _gather_extra_capabilities(store, gather_session_id, agent_id)
        return build_gather_agent(
            defender_dir, logger, agent_id, make_model, verbs, limits,
            extra_capabilities=gather_extra, session_id=gather_session_id,
        )

    # ALWAYS the role's own committed grant (#632) — never the per-call `verbs=` registry's
    # own grant. The dispatch catalog/template index is a ROLE-LEVEL surface (the same one
    # the generated roster and its audit are scored against, verb_roster.py), not a per-run
    # one; a test injecting a registry scoped narrower (or differently) than GATHER_DEF's
    # real grant, for reasons that have nothing to do with catalog content, must not narrow
    # what the catalog advertises.
    register_gather_tool(agent, _build_gather, GATHER_REQUEST_LIMIT, GATHER_DEF.verb_grant)
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


async def _drive_agent(
    agent: Agent[AgentDeps, str], prompt: str, deps: AgentDeps, store: Any, session_id: str,
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
            usage_limits=UsageLimits(request_limit=DEFAULT_REQUEST_LIMIT),
        ) as run:
            async for node in run:
                _log_node(node)
    except UsageLimitExceeded as e:
        print(f"[run.py] request limit reached ({e}); writing partial trace",
              file=sys.stderr)
        truncated_by = "request-limit"
        exit_reason = "UsageLimitExceeded"
    except RunAborted as e:
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
        truncated_by = "aborted"
        exit_reason = "RunAborted"
    except BudgetKill as e:
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
        truncated_by = "budget"
        exit_reason = "BudgetKill"
    except (sqlite3.Error, session_store.StoreError) as e:
        # StoreError, not StoreAppendError: PayloadNotRepresentable / IngestTailUnderflow
        # / CyclicParentChain / UnknownSchemaVersion all reach here from inside the
        # ProcessHistory hook, and any one of them escaping takes the whole run.py
        # process down instead of writing the partial trace this handler exists for.
        print(f"[run.py] store append failed ({e!r}); stopping the run", file=sys.stderr)
        truncated_by = "store"
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
) -> dict:
    model_name = resolve_main_model(model_name)
    make_model = make_model or providers.build_for_effort
    adapters = defender_dir / "scripts" / "adapters"
    verbs = verbs if verbs is not None else ModuleVerbRegistry(adapters, GATHER_DEF.verb_grant)  # lint-default: ok — DI seam owning its default (tree-derived; no signature default possible)
    limits = limits if limits is not None else DEFAULT_LIMITS  # lint-default: ok — DI seam owning its default (the cap table, threaded inward)
    budget_started_monotonic = time.monotonic()
    open_budget(run_dir, run_id)
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")

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

    agent = build_agent(
        defender_dir, logger, make_model, main_model=model_name, verbs=verbs, limits=limits,
        store=store, session_id=session_id,
    )
    deps = replace(
        bind(MAIN_DEF, run_dir, salt=salt, defender_dir=defender_dir, box=box),
        run_id=run_id,
        budget_started_monotonic=budget_started_monotonic,
    )
    prompt = _user_prompt(run_dir, alert_path, defender_dir, salt)

    t0 = time.time()
    run, truncated_by, exit_reason = await _drive_agent(agent, prompt, deps, store, session_id)
    wall_ms = (time.time() - t0) * 1000.0

    result = run.result if run is not None else None
    try:
        observe.write_trace(run_dir, store=store, session_id=session_id, wall_ms=wall_ms)
    except Exception as e:  # noqa: BLE001 — a broken store must not swallow the artifact entirely
        print(f"[run.py] write_trace failed ({e!r}); writing an empty trace", file=sys.stderr)
        write_guarded(run_dir / "tool_trace.jsonl", "")
    logger.close()
    output = result.output if result is not None else None
    return _run_summary(
        output=output, model_name=model_name, requests=logger.n_requests,
        truncated_by=truncated_by, exit_reason=exit_reason,
        case_id=case_id, store_path=store.path,
    )
