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
import re
import sys
import time
from pathlib import Path
from typing import Any

from pydantic_ai import Agent, RunContext
from pydantic_ai.capabilities import ProcessHistory
from pydantic_ai.capabilities.hooks import Hooks
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelMessagesTypeAdapter
from pydantic_ai.models.anthropic import AnthropicModel, AnthropicModelSettings
from pydantic_ai.usage import UsageLimits

from . import compaction
from . import observe
from . import orient
from .circuit_breaker import RunAborted
from .tools import (
    GatherDeps,
    RunDeps,
    register_gather_tool,
    register_tools,
)

from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    check_budgets,
    update_budget_locked,
)

DEFAULT_MODEL = "claude-sonnet-4-6"
GATHER_MODEL = "claude-haiku-4-5"
DEFAULT_REQUEST_LIMIT = 60
GATHER_REQUEST_LIMIT = 40  # the lean gather's per-lead loop; large multi-dimension
# leads need well over 20 turns (#304: a 6-dimension large-dump lead needed ~26).
# (The finder/executor split's two-budget tuning — a finder cap + a per-assay cap —
# was removed with the split (#339 never merged; the lean gather #340 superseded it).)
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


def _main_instructions(defender_dir: Path) -> str:
    return (defender_dir / "SKILL.md").read_text()


# --- TEMPORARY gather engine seam (remove when the engines stop sharing one SKILL) ---
# defender/skills/gather/SKILL.md is the gather subagent's instructions for BOTH
# runtime engines: run.py's `claude -p` (via dispatch.py, which points the
# subagent at the file) and this PydanticAI driver (which loads it as the agent's
# system prompt). A span there tells gather to Read the full {system}/SKILL.md +
# execution.md up front on every dispatch. This engine instead injects the target
# system's FRONTMATTER (the descriptor catalog — progressive disclosure) and lets
# gather pull the body on demand, so that unconditional double-read is pure
# redundancy here (measured: the same system SKILL re-read once per sibling lead).
# The SKILL marks such spans with GATHER-PAI-TRIM:BEGIN/END comments; we strip
# them for this engine and leave them intact for `claude -p`, which still needs
# them. This is TEMPORARY: once the engines no longer share one SKILL, delete this
# seam and the markers, and the trim becomes a plain SKILL edit.
_PAI_TRIM_RE = re.compile(
    r"[ \t]*<!--\s*GATHER-PAI-TRIM:BEGIN.*?GATHER-PAI-TRIM:END\s*-->\n?",
    re.DOTALL,
)


def _strip_temporary_pai_trims(skill_text: str) -> str:
    """Strip GATHER-PAI-TRIM spans from the gather SKILL for this engine (see the
    banner above). Fail-safe: with no markers present the text passes through
    unchanged, and we log a one-line note so a SKILL refactor that drops the
    markers is noticed rather than silently reinstating the redundant read."""
    out, n = _PAI_TRIM_RE.subn("", skill_text)
    if n == 0:
        print("[run_pai] note: gather SKILL carries no GATHER-PAI-TRIM markers; "
              "progressive-disclosure trim seam was a no-op", file=sys.stderr)
    return out


def _gather_instructions(defender_dir: Path) -> str:
    return _strip_temporary_pai_trims(
        (defender_dir / "skills" / "gather" / "SKILL.md").read_text()
    )


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


def _make_hooks(logger: observe.RequestLogger, agent_id: str) -> Hooks:
    """The budget + observability hooks, shared by the main and gather agents.
    `agent_id` tags this instance's logged requests ("main" / "gather:{lead_id}")
    and binds the same run-scoped budget (keyed by run_dir, locked)."""
    hooks = Hooks()

    @hooks.on.after_tool_execute
    async def _budget(ctx, *, call, tool_def, args, result):  # noqa: ANN001
        # Warning-only budget accounting, same caps as the claude -p enforcer.
        try:
            deps: RunDeps = ctx.deps
            state = update_budget_locked(deps.run_dir, deps.run_id, call.tool_name)
            for w in check_budgets(state, DEFAULT_LIMITS):
                print(f"[run_pai] {w}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — budget must never break the run
            print(f"[run_pai] budget accounting skipped: {e!r}", file=sys.stderr)
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
            print(f"[run_pai] request logging skipped: {e!r}", file=sys.stderr)
        return resp

    return hooks


def _gather_model() -> str:
    """The gather subagent model — Haiku by default; `DEFENDER_GATHER_MODEL`
    overrides it. The override exists for the instruction-following A/B: Haiku
    under-adopts the §4 `--batch` form and flails the on-disk filter loop into the
    request cap, so a Sonnet gather is worth testing. It's affordable *because* the
    always-sampled passthrough (record_query) keeps the multi-MB raw dump out of
    gather's context — a pricier gather pays only for the small sampled context +
    summaries, not the dump it re-sends every request."""
    return os.environ.get("DEFENDER_GATHER_MODEL") or GATHER_MODEL


def _build_subagent(
    defender_dir: Path, logger: observe.RequestLogger, agent_id: str,
    instructions: str, model_name: str,
) -> Agent:
    """A nested subagent with the read-only slice of the generic tools (bash +
    read_file; the bash tool auto-captures adapter calls for an executor under
    `is_main_session=False`, and denies them for a finder via the role gate).
    `writers=False`: these subagents measure and return a summary — they never
    author investigation.md/report.md, so denying them write_file/edit_file keeps
    them in lane. One per dispatch so `agent_id` binds to the lead/measurement. The
    system prompt (`instructions`) + `model_name` specialize the instance into the
    legacy gather, the finder (Sonnet), or the executor (Haiku)."""
    agent = Agent(
        AnthropicModel(model_name),
        deps_type=GatherDeps,
        instructions=instructions,
        capabilities=[_make_hooks(logger, agent_id)],
        model_settings=_CACHE_SETTINGS,
        retries=DEFAULT_TOOL_RETRIES,
    )
    register_tools(agent, writers=False)
    return agent


def build_gather_agent(defender_dir: Path, logger: observe.RequestLogger, agent_id: str) -> Agent:
    """The LEGACY single-agent gather (shared `skills/gather/SKILL.md`). Kept for the
    `claude -p` engine + the hermetic llm tests; the PydanticAI runtime uses the
    finder/executor pair below. Behaves as an executor (runs queries, auto-captures)
    when given executor-role deps. Haiku."""
    return _build_subagent(
        defender_dir, logger, agent_id, _gather_instructions(defender_dir), _gather_model()
    )


def _lean_gather_instructions(defender_dir: Path) -> str:
    return (defender_dir / "skills" / "gather" / "SKILL.lean.md").read_text()


def build_lean_gather_agent(defender_dir: Path, logger: observe.RequestLogger, agent_id: str) -> Agent:
    """The lean single-agent gather (#340) — the production gather for the
    PydanticAI engine. One agent runs find→execute(one server-side ES|QL
    aggregation)→verify and auto-captures its own adapter calls (no finder/executor
    split). Loads `skills/gather/SKILL.lean.md`. Model is `_gather_model()` (Haiku;
    `DEFENDER_GATHER_MODEL` overrides to A/B at Sonnet)."""
    return _build_subagent(
        defender_dir, logger, agent_id, _lean_gather_instructions(defender_dir),
        _gather_model(),
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
    return os.environ.get("DEFENDER_COMPACTION", "").strip().lower() in (
        "1", "on", "true", "yes")


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
    inv = run_dir / "investigation.md"
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
            print(f"[run_pai] compaction skipped: {e!r}", file=sys.stderr)
            return messages

    return process


def build_agent(model_name: str, defender_dir: Path, logger: observe.RequestLogger) -> Agent:
    capabilities = [_make_hooks(logger, "main")]
    if _compaction_enabled():
        # Main agent only — gather sub-runs are short single leads, nothing to
        # compact. Listed after the hooks so observability wraps the rewritten
        # request (the recorded usage then reflects the compacted token cost).
        capabilities.append(ProcessHistory(_make_compaction_processor()))
        print("[run_pai] per-loop compaction ENABLED (DEFENDER_COMPACTION)", file=sys.stderr)
    print(f"[run_pai] gather model: {_gather_model()}", file=sys.stderr)
    if os.environ.get("DEFENDER_GATHER_MODEL"):
        print(f"[run_pai] gather model OVERRIDE: {_gather_model()} "
              "(DEFENDER_GATHER_MODEL)", file=sys.stderr)
    agent = Agent(
        AnthropicModel(model_name),
        deps_type=RunDeps,
        instructions=_main_instructions(defender_dir),
        capabilities=capabilities,
        model_settings=_CACHE_SETTINGS,
        retries=DEFAULT_TOOL_RETRIES,
    )
    register_tools(agent)
    # The gather dispatch tool builds a fresh nested LEAN gather agent per lead
    # (#340): one agent runs find→execute(one server-side ES|QL aggregation)→verify
    # and auto-captures its own adapter calls. The finder/executor split (#339) was
    # superseded by this before it ever merged.
    register_gather_tool(
        agent,
        lambda agent_id: build_lean_gather_agent(defender_dir, logger, agent_id),
        GATHER_REQUEST_LIMIT,
    )
    return agent


def _log_node(node: Any) -> None:
    if Agent.is_model_request_node(node):
        print("[run_pai] · model request", file=sys.stderr)
    elif Agent.is_call_tools_node(node):
        print("[run_pai] · tool calls", file=sys.stderr)
    elif Agent.is_end_node(node):
        print("[run_pai] · end", file=sys.stderr)


async def run_investigation(
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
    defender_dir: Path,
    salt: str,
    model_name: str | None = None,
) -> dict:
    """Run one investigation end-to-end; emit the trace; return a small summary."""
    model_name = model_name or os.environ.get("DEFENDER_MODEL") or DEFAULT_MODEL
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    agent = build_agent(model_name, defender_dir, logger)
    deps = RunDeps(
        run_dir=run_dir, defender_dir=defender_dir, run_id=run_id,
        salt=salt, is_main_session=True,
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
        print(f"[run_pai] request limit reached ({e}); writing partial trace",
              file=sys.stderr)
    except RunAborted as e:
        # Run-wide circuit breaker: the environment is broadly unreachable. Stop
        # the loop and write the partial trace, same as the request-limit path —
        # every request up to here is already in the live request log.
        print(f"[run_pai] {e}; writing partial trace", file=sys.stderr)
    wall_ms = (time.time() - t0) * 1000.0

    # result is None when the run ends without an End node (e.g. the request-limit
    # path above). The trace is projected from the live request log, not the run
    # object, so it survives that case (and a crash) unchanged.
    result = run.result
    observe.write_trace(run_dir, logger.messages, wall_ms=wall_ms)
    logger.close()
    output = result.output if result is not None else None
    return {"output": output, "model": model_name, "requests": logger.n_requests}
