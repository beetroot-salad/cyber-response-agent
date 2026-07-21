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

# The #631 enforcement flag: OFF for interactive dev, ON in CI/eval. Read through the
# closed-token `env_bool`, so a typo fails loud rather than silently shipping unenforced.
BUDGET_ENFORCE_FLAG = "DEFENDER_BUDGET_ENFORCE"


def enforcement_enabled() -> bool:
    """Whether the blocking budget posture is on for this process (`DEFENDER_BUDGET_ENFORCE`,
    default False). The single read of the flag; an unrecognized token raises
    FatalConfigError at startup rather than being coerced to a silently-unenforced run."""
    return env_bool(BUDGET_ENFORCE_FLAG, False)

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
    return (defender_dir / "SKILL.md").read_text(encoding="utf-8")


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


def _budget_short_circuit(
    deps: AgentDeps, tool_name: str, limits: dict,
    logger: observe.RequestLogger, agent_id: str,
) -> str | None:
    """The enforced pre-execute decision (#631): raise `BudgetKill` when the report tail is
    exhausted, return the refusal message (and mint its own record) when the pool is tripped
    for this tool's tier, else None (proceed). Read OFF the flock-consistent budget state; a
    refusal is NOT an executed call, so it neither increments nor calls check_budgets (NF2)."""
    state = read_budget(deps.run_dir)
    if tail_exhausted(state, limits):
        # Raised OUTSIDE any accounting guard (FF11), so the "budget must never break the
        # run" catch cannot swallow it — it ENDS the run.
        raise BudgetKill(f"budget tail exhausted at {tool_name}")
    if should_refuse(state, tool_name, tier(tool_name, deps.role), limits):
        logger.log_budget_refusal(tool_name=tool_name, agent_id=agent_id)
        return refusal_message(state, tool_name, limits)
    return None


def _account_executed_call(deps: AgentDeps, tool_name: str, *, active: bool, limits: dict) -> None:
    """Account one EXECUTED call and emit stderr warnings, under BOTH postures. Enforced →
    `account_call` (commit-time re-checked, accounting-failure aware, may `BudgetKill`);
    unenforced → the plain unconditional increment. The kill escapes the guard like the tail
    kill; every other accounting fault is swallowed (budget must never break the run)."""
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
    """The budget + observability hooks, shared by the main and gather agents.
    `agent_id` tags this instance's logged requests ("main" / "gather:{lead_id}") and
    binds the same run-scoped budget (keyed by run_dir, locked).

    `enforce` is the agent's budget POSTURE bit (#631, M2) — REQUIRED, keyword-only, no
    default: a caller that states nothing would run unenforced (the fail-open M2 exists
    to prevent), so omitting it is a `TypeError` at the one call site CI never collects
    (`experiments/.../run_arms.py`) rather than a silent unenforced run. `limits` is the
    cap table threaded from the boundary (`no_operator_config`). `enforce` already folds in
    the flag (the production boundary ANDs `defn.budget_enforced` with `enforcement_enabled()`),
    so a direct `build_agent_core` build enforces on the bit alone."""
    hooks = Hooks()

    @hooks.on.tool_execute
    async def _budget(ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        # The budget SHORT-CIRCUIT + accounting, in one wrap-style seam ahead of QueryCapture
        # (M11): when the pool is tripped the tool is refused here WITHOUT awaiting the handler
        # — so a refused `query` never enters QueryCapture and writes no phantom row, and the
        # model reads a permanent-withdrawal ToolReturnPart rather than a framework retry.
        # Accounting runs for every EXECUTED call under either posture; only refusal/kill gate.
        deps: AgentDeps = ctx.deps
        tool_name = call.tool_name
        if enforce:
            refusal = _budget_short_circuit(deps, tool_name, limits, logger, agent_id)
            if refusal is not None:
                return refusal
        result = await handler(args)
        _account_executed_call(deps, tool_name, active=enforce, limits=limits)
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
    half-built agent that 401s mid-run.

    `verbs` is the data-source verb registry (#611), threaded from `run_investigation` like
    `make_model`. Declaring `ToolSet(query=True)` is what CONSTRUCTS the capture capability here
    — that is the whole inseparability property: an agent cannot be built holding the `query`
    tool and not writing its queries row, because there is no seam between them to unpick."""
    built = make_model(defn.model(), defn.effort)
    capabilities: list[Any] = [
        _make_hooks(logger, agent_id, enforce=defn.budget_enforced, limits=limits),
        *extra_capabilities,
    ]
    if defn.tools.query:
        from defender._paths import PATHS

        from .query_tool import QueryCapture

        # A query-declaring def with no registry threaded in resolves the PRODUCTION
        # registry off the main-checkout adapters (still an allowlist, never fail-open):
        # run_investigation always threads the run's tree, so this default only fires for
        # a direct `build_agent_core` build (the gate/tier tests, which never call query).
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
    """The MAIN-agent model name: an explicit override (run.py's ``--model``), else
    ``$DEFENDER_MODEL``, else ``DEFAULT_MODEL``. The single read of ``DEFENDER_MODEL`` —
    every entry point (run.py, ``build_agent``, ``run_investigation``, and ``MAIN_DEF``'s
    model thunk) routes through here so the env var and its default don't get re-read with
    drifting fallbacks."""
    return explicit or os.environ.get("DEFENDER_MODEL") or DEFAULT_MODEL


# The two runtime agents' definitions (#538). Each hangs its OWN grant builder on its OWN def
# (#575): `compile_policy` composes what the defs bring — it never reaches up to ask an agent
# what it wants. The reader lane is the shared `_common.reader_grants` (one `cat` opener + the
# stdin-only viewers + the non-adapter shims), and the `cat` grant's SCOPE is also this agent's
# read surface (`read_allow`), so the two surfaces are one object. The corpus dirs are the `.md`
# roots under `defender_dir` a reader may open.
_CORPUS_DIRS = ("lessons", "skills", "examples")


def _main_bash_shapes(roots: ResolvedRoots) -> tuple[Any, ...]:
    """MAIN's bash lane: the reader grants WITHOUT the gather_raw shape. Main's denial of the raw
    payload channel is the ABSENCE of that address from its grant list — not a clamp on a wider
    grant, which is what the deleted `RAW_MARKER in cmd` substring scan was (it also denied
    `… | grep gather_raw`, where the marker is a search pattern and no such file is ever
    opened)."""
    return _common.reader_grants(roots.run_dir, roots.defender_dir, raw=False)


def _gather_bash_shapes(roots: ResolvedRoots) -> tuple[Any, ...]:
    """GATHER's bash lane: the reader grants PLUS the machine-tight `gather_raw/{lead}/{seq}.json`
    shape (it owns the payloads its queries capture).

    There are no adapter grants any more (#611): a data source is reached through the `query`
    tool, and gather's bash lane keeps only local computation. The sanctioned aggregation pipe
    survives split in two — `query(...)`, then `cat <ABSOLUTE payload path> | defender-sql
    '<SQL>'`, which this very shape is what admits."""
    return _common.reader_grants(roots.run_dir, roots.defender_dir, raw=True)


def _main_write_shape(roots: ResolvedRoots) -> tuple[Any, ...]:
    """MAIN's write scope: a POSITIVE ALLOW-LIST of exactly `investigation.md` and
    `report.md` under `run_dir` (#631, S2) — NOT the whole run-dir subtree. The bound on
    spend is only a bound if the RECORD of spend is unforgeable, so every other path under
    the run dir (budget.json, circuit_breaker.json, the two tables, gather_summaries, …)
    is refused, and so are the `gather_raw/evil.md` / `sub/report.md` a `.md`-suffix filter
    would have admitted (`decide_write` applies no path shapes). Anchored on `run_dir` — NOT
    `defender_dir` — so MAIN can never author the corpus. `_main_write_shape`'s "+ any case
    artifact it authors" enumerates to the empty set (Q2d), so nothing legitimate is lost;
    a future MAIN-authored artifact needs an explicit allow-list edit (accepted cost)."""
    return permission.build_named_write_allow(roots.run_dir, ("investigation.md", "report.md"))


# MAIN — the orchestrator: reader lane + the file writers (it authors investigation.md /
# report.md), no data-source adapters (it dispatches gather). `model` is the live thunk so a
# `--model` / `$DEFENDER_MODEL` override resolves at build; `effort` is the Fireworks GLM default
# (production re-binds both per invocation in `build_agent`, preserving the model-dependent effort
# for the claude escape hatch).
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

# GATHER — the data-access subagent: the reader lane + its own gather_raw + the typed `query`
# tool (#611 — the adapter routes off its bash lane are gone; a data source is reached through
# the registry, never through a program the model names),
# read-only (no writers). Runs its own cheaper `gather_model()`, reasoning off. `template_search`
# is its query-catalog discovery route (#585): every bash route it had into that corpus is dead
# (`find` was never granted, `grep -r` denies since #581, a glob reaches grep as a literal filename
# under `shell=False`, and #575 took the last one, `ls`), so the grep comes back as a gated tool
# with a harness-owned root. MAIN does not get it — `defender/SKILL.md` forbids main the corpus.
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
    """The single-agent gather (#340) — the production gather for the PydanticAI
    engine. One agent runs find→execute(one server-side ES|QL aggregation)→verify and
    auto-captures its own adapter calls (no finder/executor split). Built through the
    single `build_agent_core` site from `GATHER_DEF`: the read-only reader lane + adapters
    (no file writers — it measures and returns a summary, never authors
    investigation.md/report.md), its own cheaper `gather_model()`, and NO layered `gather`
    dispatch tool (a gather must not dispatch itself). Loads `skills/gather/SKILL.md`. One
    per dispatch so `agent_id` binds to the lead/measurement. The resolved model name is read
    ONCE and both `model` + `effort` are re-bound onto the def from it (mirroring `build_agent`),
    so the built model and its effort can't disagree on a mid-build env change — a
    `DEFENDER_GATHER_MODEL=claude-*` override omits the Fireworks-only `none` knob, exactly as
    today, while the static def carries the Fireworks default."""
    name = gather_model()
    return build_agent_core(
        replace(
            GATHER_DEF, model=lambda: name,
            effort=providers.effort_for_role(name, AgentRole.GATHER),
            # Fold the flag into the posture at the production boundary (#631, M9): the
            # def carries the static bit; the run enforces only when the flag is also on.
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
    inv_text = inv.read_text(encoding="utf-8") if inv.is_file() else ""
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
    *, main_model: str | None = None, verbs: Any = None, limits: dict = DEFAULT_LIMITS,
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
        replace(
            MAIN_DEF, model=lambda: name,
            effort=providers.effort_for_role(name, AgentRole.MAIN),
            # Fold the flag into the posture at the production boundary (#631, M9).
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
    # The gather dispatch tool builds a fresh nested gather agent per lead
    # (#340): one agent runs find→execute(one server-side ES|QL aggregation)→verify
    # and auto-captures its own adapter calls. The finder/executor split (#339) was
    # superseded by this before it ever merged. The SAME threaded `limits` reach the
    # nested gather so MAIN and GATHER share the one enforced pool (M8).
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
    # keyword-only injection seam (the run's identity, then `make_model`/`verbs`/`limits`/`box`).
    # Bundling them into a config object would hide exactly the seams the e2e replay suite
    # enters through, which is the opposite of what this signature is for.
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
    """Run one investigation end-to-end; emit the trace; return a small summary.

    `verbs` is the data-source registry the gather subagent's `query` tool dispatches against
    (#611) — the SECOND injection seam below the model, alongside `make_model`. Production
    resolves the real `ModuleVerbRegistry` off the RUN's `defender_dir`, which is the whole
    point: the tree is a per-run value (a worktree in a learning drain, an eval's tmp tree), so
    a verb reads THAT tree's `config.env`, not the one the driver happened to import under.

    `limits` is the THIRD injection seam (#631): the cap table resolved ONCE here at the
    boundary and threaded inward (there is no operator-facing config — N1). Production resolves
    `DEFAULT_LIMITS`; a test injects low caps so a run crosses a real cap in a few turns.

    `box` is the FOURTH such seam (#540): the run's execution boundary for the bash lane, built by
    `run.py` before the investigation starts and torn down after it ends. `None` leaves the deps
    carrying the inert default executor, so a driver run that never invokes bash needs no
    container — but one that does invoke it fails closed rather than running on the host."""
    model_name = resolve_main_model(model_name)
    make_model = make_model or providers.build_for_effort
    # The registry is derived from a PARAMETER (the run's tree), so it cannot be a signature
    # default — this is the endorsed "single DI/test seam that owns its default" shape, the same
    # one `make_model` uses on the line above.
    adapters = defender_dir / "scripts" / "adapters"
    verbs = verbs if verbs is not None else ModuleVerbRegistry(adapters)  # lint-default: ok — DI seam owning its default (tree-derived; no signature default possible)
    limits = limits if limits is not None else DEFAULT_LIMITS  # lint-default: ok — DI seam owning its default (the cap table, threaded inward)
    # Open the run's budget with its cross-process wall-clock origin BEFORE the first tool
    # call, so the enforcing read never mistakes an un-opened run for a cold start (#631, D2).
    open_budget(run_dir, run_id)
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    agent = build_agent(
        defender_dir, logger, make_model, main_model=model_name, verbs=verbs, limits=limits,
    )
    # MAIN deps via the single bind() seam (#545): compile_policy reproduces the authored
    # main policy field-for-field AND adds the read↔bash filename filter (read_shapes), and
    # the run's PERSISTED salt is carried in (never a fresh uuid4) so the deps' tool-output
    # wrapper and orient's alert wrapper tag with the ONE salt the agent is told to distrust —
    # a split salt would fail the injection defence open. `defender_dir` is threaded into bind
    # (#551) so the gate anchors reads/writes on the SAME tree the prompt describes — prod passes
    # a PATHS-equal value (behaviour-preserving), but a worktree/temp-tree run no longer validates
    # against PATHS while the prompt names tree X. `run_id` is the caller's identity (run.py mints
    # run_dir=base/run_id, so it equals run_dir.name in production; the replay harness passes a
    # distinct label), re-stamped over bind's run_dir-basename default.
    deps = replace(
        bind(MAIN_DEF, run_dir, salt=salt, defender_dir=defender_dir, box=box), run_id=run_id,
    )
    prompt = _user_prompt(run_dir, alert_path, defender_dir, salt)

    t0 = time.time()
    truncated_by: str | None = None
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
    except BudgetKill as e:
        # The budget tail is exhausted (or the accounting write is standing-failed): the
        # SAME shutdown as the request-limit path — write the partial trace from the live
        # log — but MARKED, so the post-run pipeline can tell an enforced stop from a
        # clean conclusion. Its own exception type (not RunAborted), caught by a plain
        # `except BudgetKill` (P6: concurrent kills collapse to one, unwrapped).
        print(f"[run.py] {e}; writing partial trace", file=sys.stderr)
        truncated_by = "budget"
    wall_ms = (time.time() - t0) * 1000.0

    # result is None when the run ends without an End node (e.g. the request-limit
    # path above). The trace is projected from the live request log, not the run
    # object, so it survives that case (and a crash) unchanged.
    result = run.result
    observe.write_trace(run_dir, logger.messages, wall_ms=wall_ms)
    logger.close()
    output = result.output if result is not None else None
    return {
        "output": output, "model": model_name, "requests": logger.n_requests,
        "truncated_by": truncated_by,
    }
