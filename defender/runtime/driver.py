"""The PydanticAI main-agent driver — one investigation, owning the loop.

SKILL.md is the system prompt (`instructions`, verbatim — never "Read the
skill"); the four generic tools are the surface; the permission gate lives in
the tools; budget is an in-process `after_tool_execute` hook; observability is a
`wrap_model_request` hook logging every API request live to `llm_requests.jsonl`
(observe.py projects `tool_trace.jsonl` from it). The loop is `agent.iter()` over
nodes — the exact seam Phase B's `ProcessHistory` compaction plugs into (this
slice passes history through unmodified).
"""

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
from .agent_definition import AgentDefinition, BashGrammar, ToolSet
from .agent_role import AgentRole
from .circuit_breaker import RunAborted
from .providers import BuiltModel
from .tools import (
    AgentDeps,
    GatherDeps,
    register_gather_tool,
    register_tools,
)

from defender._env import env_bool
from defender._run_paths import RunPaths
from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS
from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    check_budgets,
    update_budget_locked,
)

# The MAIN-loop default model — Fireworks GLM 5.2 (flagship) unless overridden by
# --model / $DEFENDER_MODEL. Production is single-provider (Fireworks), no Anthropic
# dependency; a `claude-*` id is still reachable via the override.
DEFAULT_MODEL = "glm-5.2"
# The GATHER-subagent default — a CHEAPER Fireworks model than MAIN, since the ES|QL
# find→execute→verify loop is mechanical and flagship reasoning is overkill. Kimi K2.6
# (~$0.60/$3.00 vs GLM 5.2's $1.40/$4.40) generates correct ES|QL + reliable
# tool-calls, run with reasoning off (see `runtime/providers/openai_compat.py`). Override via
# $DEFENDER_GATHER_MODEL (e.g. `glm-5.2` to match MAIN, or `claude-sonnet-4-6` for #340).
DEFAULT_GATHER_MODEL = "kimi-k2.6"
DEFAULT_REQUEST_LIMIT = 60
GATHER_REQUEST_LIMIT = 40  # the gather's per-lead loop; large multi-dimension
# leads need well over 20 turns (#304: a 6-dimension large-dump lead needed ~26).
# (The finder/executor split's two-budget tuning — a finder cap + a per-assay cap —
# was removed with the split (#339 never merged; the gather #340 superseded it).)
# The permission gate denies disallowed tool calls via ModelRetry — control-flow
# feedback ("pick another command"), the in-process twin of the claude -p hook's
# exit-2, not a hard error. pydantic-ai resets a tool's retry counter on success,
# so this budget bounds only *consecutive* denials/errors; the request limit caps
# total work. max_retries=1 (the default) would abort the run on the 2nd back-to-
# back gate denial — far too brittle for a gate used as feedback.
DEFAULT_TOOL_RETRIES = 10

# Per-provider model construction + per-role ModelSettings (Anthropic prompt cache /
# Fireworks reasoning_effort) live in `runtime/providers/`. The driver stays
# provider-neutral: `build_agent_core` resolves a model via the `(name, effort)`
# `make_model` seam (`providers.build_for_effort`) → a BuiltModel.


def _main_instructions(defender_dir: Path) -> str:
    return (defender_dir / "SKILL.md").read_text()


def _user_prompt(run_dir: Path, alert_path: Path, defender_dir: Path, salt: str) -> str:
    # Run context + the precomputed ORIENT pack. The procedure — artifacts to
    # write, the stop condition, case_id (= the run-dir basename) — all lives in
    # SKILL.md, the system prompt; don't restate it, and don't say "Read SKILL.md"
    # (it IS the prompt). The orientation block hands the agent the deterministic
    # context it used to spend ~18 round-trips fetching (catalog, system map,
    # this signature's lessons/corpus, plus the raw alert + invlang grammar) so
    # ORIENT reasons over given material — and, because message 0 survives a
    # compaction fold verbatim, that material can't be dropped and re-read.
    # Built fail-safe: a degraded pack just means the agent fetches a piece live.
    orientation = orient.orientation(run_dir, defender_dir, alert_path, salt)
    return (
        "Begin the investigation.\n\n"
        f"run_dir: {run_dir}\n"
        f"alert: {alert_path}\n\n"
        f"{orientation}"
    )


def _make_hooks(logger: observe.RequestLogger, agent_id: str) -> Hooks[Any]:
    """The budget + observability hooks, shared by the main and gather agents.
    `agent_id` tags this instance's logged requests ("main" / "gather:{lead_id}")
    and binds the same run-scoped budget (keyed by run_dir, locked)."""
    hooks = Hooks()

    @hooks.on.after_tool_execute
    async def _budget(ctx, *, call, result, **_):  # noqa: ANN001 — **_ absorbs the unused tool_def/args framework kwargs
        # Warning-only budget accounting, same caps as the claude -p enforcer.
        try:
            deps: AgentDeps = ctx.deps
            state = update_budget_locked(deps.run_dir, deps.run_id, call.tool_name)
            for w in check_budgets(state, DEFAULT_LIMITS):
                print(f"[run.py] {w}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — budget must never break the run
            print(f"[run.py] budget accounting skipped: {e!r}", file=sys.stderr)
        return result

    @hooks.on.model_request  # the wrap-style model-request hook
    async def _log_request(ctx, *, request_context, handler):  # noqa: ANN001
        # The single observability site: log every API request's full input,
        # output, usage, and timing at the boundary, tagged by agent instance
        # (observe.py projects the main-only trace from these). Never break the run.
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
    """The production gather model — **Kimi K2.6** by default (`DEFAULT_GATHER_MODEL`),
    a cheaper Fireworks model than the MAIN GLM (still single-provider). The gather's
    ES|QL find→execute→verify loop is mechanical, so a flagship is overkill; Kimi
    generates correct ES|QL + reliable tool-calls at ~40% of GLM 5.2's price, run with
    reasoning off (see `runtime/providers/openai_compat.py`). `DEFENDER_GATHER_MODEL`
    overrides — e.g. `glm-5.2` to match the main model, or `claude-sonnet-4-6` (#340)."""
    return os.environ.get("DEFENDER_GATHER_MODEL") or DEFAULT_GATHER_MODEL


# The single agent-construction unit + site (#493, generalized by #538). Each agent's
# CONFIG is now its `AgentDefinition` (`agent_definition.py`) — the model thunk + effort
# + the `ToolSet` that drives registration; `build_agent_core` is the ONE `Agent(...)`
# site every caller funnels through (MAIN, GATHER, and — via `_pydantic_stage` — the
# learning stages). `logger` / `agent_id` stay separate params, NOT def fields: they're
# per-run / per-dispatch observability wiring (one shared RequestLogger fans across
# main + N gathers, keyed by agent_id), not static config.


# The model-construction seam: `(name, effort) -> BuiltModel`. Tests inject a fake (a
# pydantic-ai FunctionModel wrapped in a BuiltModel) instead of patching a model symbol;
# production passes `providers.build_for_effort`, which routes the name to its serving
# infra (Anthropic for `claude-*`; Fireworks for a `fireworks:`/glm/kimi id) and pairs
# the model with its effort settings. (Was role-keyed; #493 re-keyed it on (name, effort)
# so the one build site never re-derives a model's provider from a role.)
MakeModel = Callable[[str, str | None], BuiltModel]


def build_agent_core(
    defn: AgentDefinition,
    *,
    deps_type: type,
    instructions: str,
    logger: observe.RequestLogger,
    agent_id: str,
    extra_capabilities: Sequence[Any] = (),
    make_model: MakeModel = providers.build_for_effort,
) -> Agent[Any, str]:
    """Construct one agent + register EXACTLY its `AgentDefinition`'s toolset — the
    single build site.

    Resolves the model via `make_model(defn.model(), defn.effort)` — `defn.model` is a
    zero-arg thunk, so a late `--model` / `$DEFENDER_MODEL` override is honored here, not
    frozen at import; wires the shared budget/observability hooks FIRST (so observability
    wraps any capability-rewritten request) then `extra_capabilities` (MAIN's compaction
    ProcessHistory; the empty default keeps a no-capability build byte-identical); and
    registers the tools `defn.tools` declares present (a pure-prediction `ToolSet()`
    registers NOTHING). Layered per-caller extras (MAIN's `gather` dispatch tool) stay at
    the call site — they are not construction. No defensive catch: a `make_model` fault
    (unroutable name / missing key / bad effort) surfaces at the build, not as a
    half-built agent that 401s mid-run."""
    built = make_model(defn.model(), defn.effort)
    agent: Agent[Any, str] = Agent(
        built.model,
        deps_type=deps_type,
        instructions=instructions,
        capabilities=[_make_hooks(logger, agent_id), *extra_capabilities],
        model_settings=built.settings,
        retries=DEFAULT_TOOL_RETRIES,
    )
    register_tools(agent, defn.tools)
    return agent


def resolve_main_model(explicit: str | None = None) -> str:
    """The MAIN-agent model name: an explicit override (run.py's ``--model``), else
    ``$DEFENDER_MODEL``, else ``DEFAULT_MODEL``. The single read of ``DEFENDER_MODEL`` —
    every entry point (run.py, ``build_agent``, ``run_investigation``, and ``MAIN_DEF``'s
    model thunk) routes through here so the env var and its default don't get re-read with
    drifting fallbacks."""
    return explicit or os.environ.get("DEFENDER_MODEL") or DEFAULT_MODEL


# The two runtime agents' definitions (#538). The reader-lane program set below is the
# DECLARATIVE signal that main/gather are reader agents; `compile_policy` delegates the
# actual per-run anchored allowlist to `permission.policies._common.reader_patterns`
# (the #535 anchoring), so this content documents intent and only its non-emptiness is
# load-bearing at step one (the #535 end-state compiles the grammar directly). The
# corpus dirs are the tight `.md` roots under `defender_dir` a reader may open.
_READER_VIEWERS = ("cat", "grep", "tail", "head", "wc", "ls", "cd", "jq")
_CORPUS_DIRS = ("lessons", "skills", "examples")

# MAIN — the orchestrator: reader lane + the file writers (it authors investigation.md /
# report.md), no data-source adapters (it dispatches gather). `model` is the live thunk
# so a `--model` / `$DEFENDER_MODEL` override resolves at build; `effort` is the Fireworks
# GLM default (production re-binds both per invocation in `build_agent`, preserving the
# model-dependent effort for the claude escape hatch).
MAIN_DEF = AgentDefinition(
    role=AgentRole.MAIN,
    model=resolve_main_model,
    effort="low",
    tools=ToolSet(
        read=True,
        bash=BashGrammar(shims=tuple(NON_ADAPTER_SHIMS), viewers=_READER_VIEWERS),
        write=True,
    ),
    corpus_dirs=_CORPUS_DIRS,
    deny_reason=permission.FALLTHROUGH_DENY_REASON,
)

# GATHER — the data-access subagent: reader lane + adapters + the `adapter | defender-sql`
# pipe, read-only (no writers). Runs its own cheaper `gather_model()`, reasoning off.
GATHER_DEF = AgentDefinition(
    role=AgentRole.GATHER,
    model=gather_model,
    effort="none",
    tools=ToolSet(
        read=True,
        bash=BashGrammar(viewers=_READER_VIEWERS, adapters=True, adapter_sql_pipe=True),
    ),
    corpus_dirs=_CORPUS_DIRS,
    deny_reason=permission.GATHER_FALLTHROUGH_DENY_REASON,
)


def _gather_instructions(defender_dir: Path) -> str:
    return (defender_dir / "skills" / "gather" / "SKILL.md").read_text()


def build_gather_agent(
    defender_dir: Path, logger: observe.RequestLogger, agent_id: str,
    make_model: MakeModel = providers.build_for_effort,
) -> Agent[GatherDeps, str]:
    """The single-agent gather (#340) — the production gather for the PydanticAI
    engine. One agent runs find→execute(one server-side ES|QL aggregation)→verify and
    auto-captures its own adapter calls (no finder/executor split). Built through the
    single `build_agent_core` site from `GATHER_DEF`: the read-only reader lane + adapters
    (no file writers — it measures and returns a summary, never authors
    investigation.md/report.md), its own cheaper `gather_model()`, and NO layered `gather`
    dispatch tool (a gather must not dispatch itself). Loads `skills/gather/SKILL.md`. One
    per dispatch so `agent_id` binds to the lead/measurement. The per-invocation effort is
    re-bound from the resolved model (so a `DEFENDER_GATHER_MODEL=claude-*` override omits
    the Fireworks-only `none` knob, exactly as today), while the static def carries the
    Fireworks default."""
    name = gather_model()
    return build_agent_core(
        replace(GATHER_DEF, effort=providers.effort_for_role(name, AgentRole.GATHER)),
        deps_type=GatherDeps,
        instructions=_gather_instructions(defender_dir),
        logger=logger,
        agent_id=agent_id,
        make_model=make_model,
    )


# --- Phase B: per-loop, invlang-based compaction --------------------------
# The live adapter for the pure rewrite in `compaction.py`. It plugs into the
# `agent.iter()` seam via PydanticAI's `ProcessHistory` capability (a
# `before_model_request` history rewrite) — added to the MAIN agent only, and
# only when `DEFENDER_COMPACTION` is enabled, so Phase A stays byte-identical
# when off (this is the A/B toggle). Design: docs/runtime-per-loop-compaction-
# design.md. The processor sees PydanticAI's canonical (append-only) history
# each request; it dumps to the dict form `compaction` operates on, and
# re-validates a rewritten result back to message objects.


def _compaction_enabled() -> bool:
    # An unrecognized DEFENDER_COMPACTION token fails loud (FatalConfigError) rather
    # than silently disabling — an operator typo on the toggle should surface.
    return env_bool("DEFENDER_COMPACTION", False)


def _summary_pointers(run_dir: Path) -> dict[str, str]:
    """{lead_id: path} for persisted gather summaries (tools._persist_gather_summary).

    No longer fed into the frontier message — advertising these paths invited the
    agent to re-read folded context (4th-A/B finding); see `_compact_messages`. The
    summaries still persist on disk (debug / genuine last resort); this helper maps
    them for that and is exercised by the test suite."""
    d = run_dir / "gather_summaries"
    if not d.is_dir():
        return {}
    return {p.stem: str(p) for p in sorted(d.glob("*.md"))}


def _frontier_index(messages: list) -> int | None:
    """Index of the synthetic frontier message we previously injected, else None.

    PydanticAI **accumulates** the history processor's output — each call receives
    `[what we returned last time] + [turns appended since]`, not the full
    append-only canonical. So a stateful index into a growing canonical is invalid
    (it was the 2nd-A/B bug: tail always empty → agent loses memory → loops). We
    instead find our frontier sentinel in the received history; everything after
    it is the live tail to preserve."""
    for i in range(len(messages) - 1, -1, -1):
        for part in getattr(messages[i], "parts", []):
            if getattr(part, "part_kind", None) == "user-prompt":
                content = getattr(part, "content", "")
                if isinstance(content, str) and compaction.FRONTIER_SENTINEL in content:
                    return i
    return None


def _compact_messages(messages: list, run_dir: Path) -> list:
    """Stateless, marker-based per-loop compaction (see `_frontier_index` for why
    stateless). Each call: re-render the *settled* frontier from investigation.md
    (loops ≤ `fold_boundary`) and keep the live tail (turns after our last frontier
    marker). The trimmed frontier is byte-stable while the active loop runs — its
    growing rows are excluded — so the prefix caches within a loop. Returns the
    original objects on passthrough; never raises (the caller guards too)."""
    inv = RunPaths(run_dir).investigation
    inv_text = inv.read_text() if inv.is_file() else ""
    fold = compaction.fold_boundary(inv_text)
    marker = _frontier_index(messages)
    if fold <= 0:
        return messages  # nothing settled yet (or undetermined) → never regress

    frontier_md = compaction._frontier_through(inv_text, fold)
    # The frontier is a continuation, not a pointer dump: we deliberately do NOT
    # hand the agent the per-lead on-disk summary paths. Advertising them read as
    # a to-do list and the agent re-read the folded detail back into context,
    # undoing the fold (4th-A/B finding). The inlined invlang record is
    # authoritative; the summaries persist on disk, just unadvertised.
    frontier_dict = compaction.render_frontier_message(frontier_md)
    frontier_obj = ModelMessagesTypeAdapter.validate_python([frontier_dict])[0]

    orientation = messages[0]
    tail = messages[marker + 1:] if marker is not None else []
    rewritten = [orientation, frontier_obj] + tail
    if marker is None and len(rewritten) >= len(messages):
        return messages  # first freeze wouldn't shrink a tiny history → wait
    return rewritten


def _make_compaction_processor():
    """A stateless history processor — robust to PydanticAI's output accumulation.
    Never raises into the run: any failure falls back to the full history."""
    # The first param MUST be annotated `RunContext[...]` — pydantic-ai's
    # `takes_run_context` detects the ctx-taking variant by the annotation, not
    # the name; an unannotated `ctx` is silently called as a no-ctx processor.
    async def process(ctx: RunContext[AgentDeps], messages: list) -> list:
        try:
            return _compact_messages(messages, ctx.deps.run_dir)
        except Exception as e:  # noqa: BLE001 — compaction must never break the run
            print(f"[run.py] compaction skipped: {e!r}", file=sys.stderr)
            return messages

    return process


def _main_extra_capabilities() -> list[ProcessHistory[Any]]:
    """MAIN's compaction assembly seam — the observable compaction toggle. Returns one
    `ProcessHistory` (the per-loop invlang compaction) when `DEFENDER_COMPACTION` is on,
    else `[]`, which `build_agent` passes to `build_agent_core` as `extra_capabilities`:
    off → `()`, byte-identical to a no-capability build (the A/B invariant). MAIN only —
    gather sub-runs are short single leads, nothing to compact. Listed AFTER the hooks in
    `build_agent_core` so observability wraps the rewritten request (recorded usage then
    reflects the compacted token cost). (That `[hooks, *extra]` ordering + the live wiring
    is pinned by the e2e replay suite — pydantic-ai exposes no public capabilities surface
    to assert against here.)"""
    if not _compaction_enabled():
        return []
    print("[run.py] per-loop compaction ENABLED (DEFENDER_COMPACTION)", file=sys.stderr)
    return [ProcessHistory(_make_compaction_processor())]


def build_agent(
    defender_dir: Path, logger: observe.RequestLogger,
    make_model: MakeModel = providers.build_for_effort,
    *, main_model: str | None = None,
) -> Agent[AgentDeps, str]:
    """The MAIN loop agent — built through the single `build_agent_core` site from
    `MAIN_DEF` (the reader lane + file writers + MAIN's compaction capability), then the
    `gather` dispatch tool layered on (MAIN-only; construction stays generic).
    `main_model` resolves via `resolve_main_model` (run.py's `--model` /
    `$DEFENDER_MODEL` / `DEFAULT_MODEL`) and is bound onto the def's model thunk, with the
    effort re-derived for that model (so the claude-* override stays uncapped, exactly as
    today)."""
    extra = _main_extra_capabilities()
    _override = " (DEFENDER_GATHER_MODEL override)" if os.environ.get("DEFENDER_GATHER_MODEL") else ""
    print(f"[run.py] gather model: {gather_model()}{_override}", file=sys.stderr)
    name = resolve_main_model(main_model)
    agent = build_agent_core(
        replace(MAIN_DEF, model=lambda: name, effort=providers.effort_for_role(name, AgentRole.MAIN)),
        deps_type=AgentDeps,
        instructions=_main_instructions(defender_dir),
        logger=logger,
        agent_id="main",
        extra_capabilities=extra,
        make_model=make_model,
    )
    # The gather dispatch tool builds a fresh nested gather agent per lead
    # (#340): one agent runs find→execute(one server-side ES|QL aggregation)→verify
    # and auto-captures its own adapter calls. The finder/executor split (#339) was
    # superseded by this before it ever merged.
    register_gather_tool(
        agent,
        lambda agent_id: build_gather_agent(defender_dir, logger, agent_id, make_model),
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


async def run_investigation(
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
    defender_dir: Path,
    salt: str,
    model_name: str | None = None,
    make_model: MakeModel | None = None,
) -> dict:
    """Run one investigation end-to-end; emit the trace; return a small summary."""
    model_name = resolve_main_model(model_name)
    make_model = make_model or providers.build_for_effort
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    agent = build_agent(defender_dir, logger, make_model, main_model=model_name)
    deps = AgentDeps(
        run_dir=run_dir, defender_dir=defender_dir, run_id=run_id,
        salt=salt,
        policy=permission.policy_for("main", run_dir=run_dir, defender_dir=defender_dir),
    )
    prompt = _user_prompt(run_dir, alert_path, defender_dir, salt)

    t0 = time.time()
    # Hitting request_limit is an expected loop terminator, not a crash:
    # UsageLimitExceeded propagates out of `agent.iter`. Catch it so the
    # post-steps run; every request up to the limit is already in the live
    # request log either way. Let any other error stay loud.
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
        # Run-wide circuit breaker: the environment is broadly unreachable. Stop
        # the loop and write the partial trace, same as the request-limit path —
        # every request up to here is already in the live request log.
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
    wall_ms = (time.time() - t0) * 1000.0

    # result is None when the run ends without an End node (e.g. the request-limit
    # path above). The trace is projected from the live request log, not the run
    # object, so it survives that case (and a crash) unchanged.
    result = run.result
    observe.write_trace(run_dir, logger.messages, wall_ms=wall_ms)
    logger.close()
    output = result.output if result is not None else None
    return {"output": output, "model": model_name, "requests": logger.n_requests}
