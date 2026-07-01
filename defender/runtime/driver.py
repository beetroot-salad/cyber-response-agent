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
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import ProcessHistory
from pydantic_ai.capabilities.hooks import Hooks
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelMessagesTypeAdapter
from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModel, AnthropicModelSettings
from pydantic_ai.settings import ModelSettings
from pydantic_ai.usage import UsageLimits

from . import compaction
from . import observe
from . import orient
from .agent_role import AgentRole
from .circuit_breaker import RunAborted
from .tools import (
    GatherDeps,
    RunDeps,
    register_gather_tool,
    register_tools,
)

from defender._env import env_bool, env_str
from defender._run_paths import RunPaths
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
# find→execute→verify loop is mechanical and flagship reasoning is overkill. Kimi K2.5
# (~$0.60/$3.00 vs GLM 5.2's $1.40/$4.40) generates correct ES|QL + reliable
# tool-calls, run with reasoning off (see `_settings_for`). Override via
# $DEFENDER_GATHER_MODEL (e.g. `glm-5.2` to match MAIN, or `claude-sonnet-4-6` for #340).
DEFAULT_GATHER_MODEL = "kimi-k2.5"
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

# Three-part caching. The byte-stable preamble — the SKILL system prompt (~9K
# tokens, re-sent every request) and the tool schemas — is cached at 1h: it's
# written ~once and must survive the one gap that can exceed 5m (a long gather
# sub-run blocks the main loop while no main request refreshes its cache). The
# growing message tail uses `anthropic_cache` — a top-level breakpoint the server
# moves forward as the conversation grows — at 5m: the tail is re-read on the very
# next turn (max main-loop gap is bash's 120s timeout, always < 5m, and each read
# slides the TTL), and each turn writes only the new delta, so 5m's 1.25x write
# beats 1h's 2x on every one of up to DEFAULT_REQUEST_LIMIT turns. Budget: the
# automatic breakpoint claims one of Anthropic's 4 cache-point slots, leaving 3
# for explicit ones; instructions(1) + tools(1) = 2, within budget (pydantic-ai
# trims excess newest-first if it's ever exceeded). Verify via the per-response
# cache_read/creation token counts already logged in observe.py.
_CACHE_SETTINGS = AnthropicModelSettings(
    anthropic_cache_instructions="1h",
    anthropic_cache_tool_definitions="1h",
    anthropic_cache="5m",
)


# Fireworks reasoning models (GLM, Kimi, …) reason by default and bill that thinking
# as output tokens — a big cost/latency driver — so the runtime caps effort by ROLE.
# The MAIN loop (GLM 5.2) gets `low` (measured ~−50% cost / −75% wall vs full reasoning,
# disposition unchanged); the GATHER subagent (Kimi K2.5) gets `none` — its ES|QL
# find→execute→verify loop is mechanical, so reasoning bought only extra tokens.
# Override per role via DEFENDER_MAIN_REASONING_EFFORT / DEFENDER_GATHER_REASONING_EFFORT
# ∈ {low, medium, high, none}, or the sentinel `default` to omit reasoning_effort
# (the provider's own full-reasoning default). Verified honored by both GLM and Kimi.
_DEFAULT_MAIN_REASONING_EFFORT = "low"       # MAIN loop
_DEFAULT_GATHER_REASONING_EFFORT = "none"    # GATHER subagent — mechanical ES|QL
# reasoning_effort is a closed enum; the sentinel `default` omits the param (falls
# back to the provider's own full-reasoning default). Read via env_str(choices=…) so
# a typo'd or empty operator value fails loud at startup, not silently forwarded.
_REASONING_EFFORT_CHOICES = ("low", "medium", "high", "none", "default")


def _settings_for(model: Model, role: AgentRole) -> ModelSettings | None:
    """Per-provider, per-role model settings. The AnthropicModel gets the three-part
    `anthropic_cache_*` prompt-cache settings (meaningless on any other provider). A
    Fireworks model (OpenAIChatModel — GLM, Kimi, …) gets `reasoning_effort`, defaulting
    by role — `low` for MAIN, `none` for GATHER — each overridable via
    `DEFENDER_MAIN_REASONING_EFFORT` / `DEFENDER_GATHER_REASONING_EFFORT`
    (`low`|`medium`|`high`|`none`, or `default` to omit the param). Fireworks
    auto-caches its prefix, so no explicit cache breakpoints are needed here. Any other
    model — a test FunctionModel, or an Anthropic-only install lacking the openai
    extra — → None."""
    if isinstance(model, AnthropicModel):
        return _CACHE_SETTINGS
    try:
        from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
    except ImportError:
        return None  # openai extra absent → no Fireworks model can be live here
    if not isinstance(model, OpenAIChatModel):
        return None  # e.g. a test FunctionModel — reasoning_effort is Fireworks-only
    if role is AgentRole.GATHER:
        env, default = "DEFENDER_GATHER_REASONING_EFFORT", _DEFAULT_GATHER_REASONING_EFFORT
    else:
        env, default = "DEFENDER_MAIN_REASONING_EFFORT", _DEFAULT_MAIN_REASONING_EFFORT
    # env_str fails loud (FatalConfigError) on a typo'd or empty value: an operator
    # knob misconfig should surface at startup, not silently forward a bad
    # reasoning_effort to the API — nor, on an empty string, drop the cost cap.
    effort = env_str(env, default, choices=_REASONING_EFFORT_CHOICES)
    if effort == "default":
        return None
    # Fireworks honors the OpenAI-standard `reasoning_effort` (verified it scales
    # thinking length for GLM and Kimi); sent via extra_body so it round-trips as a raw
    # request param regardless of the profile pydantic-ai infers for the model id.
    return OpenAIChatModelSettings(extra_body={"reasoning_effort": effort})


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
            deps: RunDeps = ctx.deps
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
    """The production gather model — **Kimi K2.5** by default (`DEFAULT_GATHER_MODEL`),
    a cheaper Fireworks model than the MAIN GLM (still single-provider). The gather's
    ES|QL find→execute→verify loop is mechanical, so a flagship is overkill; Kimi
    generates correct ES|QL + reliable tool-calls at ~40% of GLM 5.2's price, run with
    reasoning off (see `_settings_for`). `DEFENDER_GATHER_MODEL` overrides — e.g.
    `glm-5.2` to match the main model, or `claude-sonnet-4-6` for the #340 tier."""
    return os.environ.get("DEFENDER_GATHER_MODEL") or DEFAULT_GATHER_MODEL


# --- Model construction: routes by model name. The name is the provider
# discriminator, so the selectors (`--model` / `$DEFENDER_MODEL` /
# `$DEFENDER_GATHER_MODEL`) reach either provider: a `claude-*` id builds an
# AnthropicModel; a `fireworks:<id>` name — or a `glm-*` convenience alias — builds
# an OpenAIChatModel on Fireworks' OpenAI-compatible endpoint, keyed off
# FIREWORKS_API_KEY, which is now the default (`DEFAULT_MODEL = "glm-5.2"`).
_FIREWORKS_PREFIX = "fireworks:"
_FIREWORKS_BASE_URL = "https://api.fireworks.ai/inference/v1"

# Friendly aliases → the canonical `fireworks:<model-id>` form (human spelling and
# Fireworks' own id spelling both accepted). GLM 5.2 is the MAIN default (flagship);
# Kimi K2.5 is the GATHER default (cheaper). Any other Fireworks model works too via
# an explicit `fireworks:<id>`.
_MODEL_ALIASES = {
    "glm-5.2": _FIREWORKS_PREFIX + "accounts/fireworks/models/glm-5p2",
    "glm-5p2": _FIREWORKS_PREFIX + "accounts/fireworks/models/glm-5p2",
    "kimi-k2.5": _FIREWORKS_PREFIX + "accounts/fireworks/models/kimi-k2p5",
    "kimi-k2p5": _FIREWORKS_PREFIX + "accounts/fireworks/models/kimi-k2p5",
}


def _resolve_alias(name: str) -> str:
    # Case-insensitive on the alias key only (a mis-cased `GLM-5.2` should still
    # reach Fireworks, matching pricing.model_key's case-insensitive match); a
    # non-alias name passes through unchanged so real model ids keep their case.
    return _MODEL_ALIASES.get(name.lower(), name)


def model_provider(name: str) -> str:
    """`"fireworks"` if `name` selects the Fireworks (OpenAI-compatible) path, else
    `"anthropic"`. The single classifier — run.py reads it to require the matching
    API key before a run, so a Fireworks model never 401s mid-investigation."""
    return "fireworks" if _resolve_alias(name).startswith(_FIREWORKS_PREFIX) else "anthropic"


def build_model(name: str) -> Model:
    """Construct the pydantic-ai model for a resolved model name. A `fireworks:`
    prefix (or a `glm-*` alias) builds an OpenAIChatModel on Fireworks' OpenAI-
    compatible endpoint (GLM 5.2 et al.), keyed off `FIREWORKS_API_KEY`; anything
    else is an AnthropicModel — the prior, byte-identical default. The openai extra
    is imported lazily, so the Anthropic path never requires it installed."""
    name = _resolve_alias(name)
    if not name.startswith(_FIREWORKS_PREFIX):
        return AnthropicModel(name)
    model_id = name[len(_FIREWORKS_PREFIX):]
    api_key = os.environ.get("FIREWORKS_API_KEY")
    if not api_key:
        raise RuntimeError(
            f"model {name!r} needs FIREWORKS_API_KEY — set it in <repo>/.env or "
            "$DEFENDER_ENV_FILE (Fireworks bills its OpenAI-compatible API)."
        )
    try:
        from pydantic_ai.models.openai import OpenAIChatModel
        from pydantic_ai.providers.openai import OpenAIProvider
    except ImportError as e:  # the openai extra isn't installed
        raise RuntimeError(
            "the Fireworks/GLM path needs the openai extra — reinstall defender with "
            "`uv pip install --python .venv/bin/python -e '.[openai]'`."
        ) from e
    return OpenAIChatModel(
        model_id,
        provider=OpenAIProvider(base_url=_FIREWORKS_BASE_URL, api_key=api_key),
    )


# Model-construction seam: tests inject fake models (pydantic-ai's FunctionModel)
# by passing `make_model` instead of patching the AnthropicModel symbol. The
# factory is keyed on `AgentRole` ALONE — the role is the single discriminator,
# sourced from each deps type's `role` ClassVar (the same value the permission
# gate reads, so model and gate dispatch can't drift) — and it owns the
# role->model policy, so build sites never thread a model name. A new subagent
# role adds a branch here, not a name parameter through four signatures.
ModelFactory = Callable[[AgentRole], Model]


def _make_default_factory(main_model_name: str) -> ModelFactory:
    """The production model factory: MAIN runs `main_model_name` (run.py's
    `--model` / `$DEFENDER_MODEL` / `DEFAULT_MODEL`), every other role runs the
    gather model (`gather_model()`; GLM, `$DEFENDER_GATHER_MODEL` overrides).
    `build_model` picks the provider from the name (Anthropic, or Fireworks for a
    `fireworks:`/`glm-*` id); tests replace the whole factory."""
    def make(role: AgentRole) -> Model:
        name = main_model_name if role is AgentRole.MAIN else gather_model()
        return build_model(name)
    return make


def resolve_main_model(explicit: str | None = None) -> str:
    """The MAIN-agent model name: an explicit override (run.py's ``--model``), else
    ``$DEFENDER_MODEL``, else ``DEFAULT_MODEL``. The single read of ``DEFENDER_MODEL`` —
    every entry point (run.py, ``_env_make_model``, ``run_investigation``) routes through
    here so the env var and its default don't get re-read with drifting fallbacks."""
    return explicit or os.environ.get("DEFENDER_MODEL") or DEFAULT_MODEL


# Default for direct `build_*` callers without an explicit main-model override:
# resolve the main model from the environment (run.py's flagless path).
def _env_make_model(role: AgentRole) -> Model:
    return _make_default_factory(resolve_main_model())(role)


def _build_subagent(
    defender_dir: Path, logger: observe.RequestLogger, agent_id: str,
    instructions: str, make_model: ModelFactory = _env_make_model,
) -> Agent[GatherDeps, str]:
    """A nested subagent with the read-only slice of the generic tools (bash +
    read_file; the bash tool auto-captures the gather's adapter calls under the
    `GATHER` role). `writers=False`: this subagent measures and returns a
    summary — it never authors investigation.md/report.md, so denying it
    write_file/edit_file keeps it in lane. One per dispatch so `agent_id` binds to
    the lead/measurement. The system prompt (`instructions`) + the factory's
    GATHER-role model specialize the instance into the gather (GLM by default)."""
    model = make_model(GatherDeps.role)
    agent = Agent(
        model,
        deps_type=GatherDeps,
        instructions=instructions,
        capabilities=[_make_hooks(logger, agent_id)],
        model_settings=_settings_for(model, GatherDeps.role),
        retries=DEFAULT_TOOL_RETRIES,
    )
    register_tools(agent, writers=False)
    return agent


def _gather_instructions(defender_dir: Path) -> str:
    return (defender_dir / "skills" / "gather" / "SKILL.md").read_text()


def build_gather_agent(
    defender_dir: Path, logger: observe.RequestLogger, agent_id: str,
    make_model: ModelFactory = _env_make_model,
) -> Agent[GatherDeps, str]:
    """The single-agent gather (#340) — the production gather for the
    PydanticAI engine. One agent runs find→execute(one server-side ES|QL
    aggregation)→verify and auto-captures its own adapter calls (no finder/executor
    split). Loads `skills/gather/SKILL.md`. The factory resolves the GATHER-role
    model (`gather_model()`; GLM, `DEFENDER_GATHER_MODEL` overrides)."""
    return _build_subagent(
        defender_dir, logger, agent_id, _gather_instructions(defender_dir),
        make_model,
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
    async def process(ctx: RunContext[RunDeps], messages: list) -> list:
        try:
            return _compact_messages(messages, ctx.deps.run_dir)
        except Exception as e:  # noqa: BLE001 — compaction must never break the run
            print(f"[run.py] compaction skipped: {e!r}", file=sys.stderr)
            return messages

    return process


def build_agent(
    defender_dir: Path, logger: observe.RequestLogger,
    make_model: ModelFactory = _env_make_model,
) -> Agent[RunDeps, str]:
    capabilities: list[Hooks[Any] | ProcessHistory[Any]] = [_make_hooks(logger, "main")]
    if _compaction_enabled():
        # Main agent only — gather sub-runs are short single leads, nothing to
        # compact. Listed after the hooks so observability wraps the rewritten
        # request (the recorded usage then reflects the compacted token cost).
        capabilities.append(ProcessHistory(_make_compaction_processor()))
        print("[run.py] per-loop compaction ENABLED (DEFENDER_COMPACTION)", file=sys.stderr)
    _override = " (DEFENDER_GATHER_MODEL override)" if os.environ.get("DEFENDER_GATHER_MODEL") else ""
    print(f"[run.py] gather model: {gather_model()}{_override}", file=sys.stderr)
    model = make_model(RunDeps.role)
    agent = Agent(
        model,
        deps_type=RunDeps,
        instructions=_main_instructions(defender_dir),
        capabilities=capabilities,
        model_settings=_settings_for(model, RunDeps.role),
        retries=DEFAULT_TOOL_RETRIES,
    )
    register_tools(agent)
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
    make_model: ModelFactory | None = None,
) -> dict:
    """Run one investigation end-to-end; emit the trace; return a small summary."""
    model_name = resolve_main_model(model_name)
    make_model = make_model or _make_default_factory(model_name)
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    agent = build_agent(defender_dir, logger, make_model)
    deps = RunDeps(
        run_dir=run_dir, defender_dir=defender_dir, run_id=run_id,
        salt=salt,
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
