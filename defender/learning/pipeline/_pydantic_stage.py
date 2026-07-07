"""The in-process PydanticAI transport shared by every learning-loop stage that runs
in-process — the twin of ``core/runner.py::_run_claude`` (the ``claude -p`` transport).

The judge was the first in-process stage, so this generic transport was born inline in
``pipeline/judge/engine_pydantic.py``: the ``RequestLogger`` setup, the ``build_agent_core``
wrapper, the one-shot ``_drive`` (wall-clock ceiling + tool-loop request cap), and the
error-mapping ladder (config faults → ``FatalConfigError`` exit-2, per-run model/timeout
faults → ``RunUnprocessable`` dead-letter, systemic faults re-raised). A SECOND in-process
stage (the actor) would have cloned all of it, so it lives here once and both stages
(``judge/engine_pydantic.py``, ``actor_engine.py``) compose it. Each stage module keeps only
what is genuinely stage-specific — its ``AgentDeps`` subclass, its ``AgentPolicy`` (matchers),
its request cap, its labels — and builds its own fully-scoped ``deps`` before delegating.

This module imports the pydantic-ai graph, so it is imported LAZILY — only by the two engine
modules, which are themselves imported lazily (when a stage actually runs), never at loop
import.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from defender.learning.core.config import (
    SUBAGENT_TIMEOUT,
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    _log,
)
from defender.runtime import observe, providers
from defender.runtime.driver import AgentSpec, MakeModel, build_agent_core
from defender.runtime.tools import AgentDeps

from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import UsageLimits


def build_stage_agent(
    deps_type: type,
    prompt_path: Path,
    model: str,
    effort: str | None,
    logger: observe.RequestLogger,
    label: str,
    *,
    make_model: MakeModel = providers.build_for_effort,
    writers: bool = False,
) -> Agent[Any, str]:
    """Build one in-process stage agent — a THIN WRAPPER over the shared ``build_agent_core``
    (the single agent-construction site, #493). Every in-process learning stage is just
    another read-only PydanticAI agent: an ``AgentSpec`` (``writers`` gates the file writers;
    the model by name + its per-leg ``effort``), the stage's system prompt, and the shared
    budget/observability hooks ``build_agent_core`` wires. ``effort`` is per-call config (not
    role-keyed), so two legs of a stage can run concurrently at different efforts. ``make_model``
    is the DI seam tests use to inject a FunctionModel; production uses
    ``providers.build_for_effort`` (Anthropic ``anthropic_effort`` / Fireworks
    ``reasoning_effort``)."""
    return build_agent_core(
        AgentSpec(model=model, effort=effort, writers=writers),
        deps_type=deps_type,
        instructions=prompt_path.read_text(),
        logger=logger,
        agent_id=label,
        make_model=make_model,
    )


async def _drive(
    agent: Agent[Any, str], user: str, deps: AgentDeps, request_limit: int, timeout: int
):
    """One-shot stage run with a wall-clock ceiling (the in-process twin of the ``claude -p``
    subprocess timeout) and a request cap on the tool loop."""
    return await asyncio.wait_for(
        agent.run(user, deps=deps, usage_limits=UsageLimits(request_limit=request_limit)),
        timeout=timeout,
    )


def run_stage(  # noqa: PLR0913 — every param is load-bearing per-call transport state
    *,
    stage: str,
    prompt_path: Path,
    model: str,
    effort: str | None,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    deps: AgentDeps,
    request_limit: int,
    make_model: MakeModel = providers.build_for_effort,
    writers: bool = False,
    require_output: bool = True,
    wall_clock_timeout: int = SUBAGENT_TIMEOUT,
) -> str:
    """Run one in-process stage to completion and return its model's final text VERBATIM.

    The caller supplies a fully-built ``deps`` (its identity + ``AgentPolicy``); this owns the
    rest — build the agent (``deps_type`` = ``type(deps)``), log every request to
    ``learning_run_dir/{trace_name}`` via ``RequestLogger``, run once (async bridged via
    ``asyncio.run`` — safe in the loop's per-direction worker thread, which has no running
    event loop), and map faults: an unroutable model / unsupported effort raised at build is a
    run-independent CONFIG fault (``FatalConfigError`` → exit 2, never dead-lettering every run
    for it); a timeout / usage-limit / model error after retries quarantines the single run
    (``RunUnprocessable``), the same per-run disposition the sibling ``claude -p`` stages get
    from a non-zero exit; ``StageAbort`` / ``FatalConfigError`` from the run are systemic and
    re-raised. ``stage`` is the human stage name in those messages (``judge`` / ``actor``);
    ``label`` is the per-leg observability id (``agent_id`` + the ``step=`` log line).

    ``wall_clock_timeout`` (seconds) is the per-run wall-clock ceiling — the author-time
    forward-check passes its own ``VERIFIER_TIMEOUT`` here; the default anchors to the pipeline
    ``SUBAGENT_TIMEOUT`` (unchanged for the judge/actor/oracle stages, which omit the arg). Anchored
    in the signature rather than coalesced with ``or`` in the body so a deliberately-set ``0`` is
    honored, not silently swapped for the 450s default."""
    logger = observe.RequestLogger(learning_run_dir / trace_name)
    _log(f"step={label} engine=pydantic_ai model={model} effort={effort}")
    try:
        try:
            agent = build_stage_agent(
                type(deps), prompt_path, model, effort, logger, label,
                make_model=make_model, writers=writers,
            )
        except ValueError as e:
            raise FatalConfigError(f"{stage} ({label}) misconfigured: {e}") from e
        result = asyncio.run(
            _drive(agent, user, deps, request_limit, wall_clock_timeout)
        )
    except (TimeoutError, UsageLimitExceeded) as e:
        raise RunUnprocessable(f"{stage} ({label}) did not complete: {e!r}") from e
    except (StageAbort, FatalConfigError):
        raise  # systemic faults doom the whole stage (exit 2) — never per-run dead-letter
    except Exception as e:  # a model/API error after retries — quarantine the run
        raise RunUnprocessable(f"{stage} ({label}) failed: {e!r}") from e
    finally:
        logger.close()
    out = str(result.output or "")
    if require_output and not out.strip():
        # A reasoning model (GLM@low, the shipped default) can burn its whole budget in the
        # thinking channel and emit an EMPTY final text part without tripping the request /
        # usage cap. An empty story or verdict is never valid; quarantine this run (the same
        # per-run disposition a claude -p stage gets from an empty/failed exit) rather than
        # letting ``""`` flow on to the oracle/judge — for the actor, is_skip_story("") is
        # False, so an empty story would otherwise be graded as a real (empty) one.
        #
        # A WRITER stage opts OUT (``require_output=False``): the lead author's output is the
        # committed tree, not the returned text — it does its work through write_file/edit_file/rm
        # tool calls and legitimately ends with an empty final part.
        raise RunUnprocessable(f"{stage} ({label}) returned empty output")
    return out
