from __future__ import annotations

import asyncio
import unicodedata
from dataclasses import replace
from pathlib import Path
from typing import Any

from defender.learning.core.config import (
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    _log,
)
from defender.runtime import observe, providers
from defender.runtime.driver import MakeModel, build_agent_core
from defender.runtime.tools import AgentDeps

from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import UsageLimits


def build_stage_agent(  # noqa: PLR0913 — the stage-build seam plus the make_model/tools/verbs DI seams; every param is load-bearing
    deps_type: type[AgentDeps],
    prompt_path: Path,
    model: str,
    effort: str | None,
    logger: observe.RequestLogger,
    label: str,
    *,
    make_model: MakeModel = providers.build_for_effort,
    tools: Any = None,
    verbs: Any = None,
) -> Agent[Any, str]:
    from defender.agents import AGENTS

    overrides: dict[str, Any] = {"model": lambda: model, "effort": effort}
    if tools is not None:
        overrides["tools"] = tools
    defn = replace(AGENTS[deps_type.role], **overrides)
    return build_agent_core(
        defn,
        deps_type=deps_type,
        instructions=prompt_path.read_text(encoding="utf-8"),
        logger=logger,
        agent_id=label,
        make_model=make_model,
        verbs=verbs,
    )


async def _drive(
    agent: Agent[Any, str], user: str, deps: AgentDeps, request_limit: int, timeout: int
):
    return await asyncio.wait_for(
        agent.run(user, deps=deps, usage_limits=UsageLimits(request_limit=request_limit)),
        timeout=timeout,
    )


# Unicode categories whose members occupy no visual space: Cc (controls, incl. NUL),
# Cf (formats — U+200B ZERO WIDTH SPACE, U+FEFF, U+00AD SOFT HYPHEN, the tag block),
# Cs (lone surrogates). Deliberately excludes Co/Cn — private-use and codepoints this
# CPython's UCD has not seen yet can carry a glyph, and "empty" must not depend on the
# interpreter's Unicode version.
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})


def _is_content_less(text: str) -> bool:
    """Whether `text` carries no visible character — this pipeline's "empty output" test.

    NOT ``not text.strip()``. strip() keys off ``str.isspace()``, which splits the
    invisible characters the wrong way in both directions: True for the visible-width
    separators (U+00A0, U+3000, U+2028, U+0085, U+001C-1F), False for the zero-width
    ones (U+200B, U+FEFF, U+00AD, U+2060) and for NUL. So a response rendering as
    nothing at all passed the guard as real stage output, while one carrying only
    spacing did not — and a stage's own text is steerable by the attacker-influenced
    alert/gather text it was asked to analyze, which made the "did this stage produce
    output" decision steerable with it (#722). One visible character is content.
    """
    return all(
        ch.isspace() or unicodedata.category(ch) in _INVISIBLE_CATEGORIES for ch in text
    )


def _last_response_is_empty_text(messages: list[dict]) -> bool:
    """Whether the latest model response contains only content-less text parts."""
    for record in reversed(messages):
        if record.get("kind") != "response":
            continue
        message = record.get("message") or {}
        parts = message.get("parts") or []
        return bool(parts) and all(
            part.get("part_kind") == "text"
            and _is_content_less(str(part.get("content") or ""))
            for part in parts
        )
    return False



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
    require_output: bool = True,
    # No signature default: the knob is env-backed, and a default evaluated at import
    # would freeze it (#717). Each stage passes `subagent_timeout()` or its own knob.
    wall_clock_timeout: int,
    tools: Any = None,
    verbs: Any = None,
) -> str:
    logger = observe.RequestLogger(learning_run_dir / trace_name)
    _log(f"step={label} engine=pydantic_ai model={model} effort={effort}")
    try:
        try:
            agent = build_stage_agent(
                type(deps), prompt_path, model, effort, logger, label,
                make_model=make_model, tools=tools, verbs=verbs,
            )
        except ValueError as e:
            raise FatalConfigError(f"{stage} ({label}) misconfigured: {e}") from e
        result = asyncio.run(
            _drive(agent, user, deps, request_limit, wall_clock_timeout)
        )
    except (TimeoutError, UsageLimitExceeded) as e:
        if require_output and _last_response_is_empty_text(logger.messages):
            raise RunUnprocessable(f"{stage} ({label}) returned empty output") from e
        raise RunUnprocessable(f"{stage} ({label}) did not complete: {e!r}") from e
    except (StageAbort, FatalConfigError):
        raise
    except Exception as e:
        if require_output and _last_response_is_empty_text(logger.messages):
            raise RunUnprocessable(f"{stage} ({label}) returned empty output") from e
        raise RunUnprocessable(f"{stage} ({label}) failed: {e!r}") from e
    finally:
        logger.close()
    out = str(result.output or "")
    if require_output and _is_content_less(out):
        raise RunUnprocessable(f"{stage} ({label}) returned empty output")
    return out
