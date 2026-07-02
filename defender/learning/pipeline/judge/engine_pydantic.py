"""The judge on the in-process PydanticAI engine — a drop-in ``judge_fn``.

This is the FIRST learning-loop agent to run in-process on PydanticAI rather than
the shared ``claude -p`` transport. Everything judge-specific lives HERE, in the
judge's own directory: its deps identity, its permission policy (data), its one bit
of custom logic (the benign closed-ticket matcher), and its agent builder. It only
*composes* shared engine machinery from ``defender.runtime`` — the policy-driven
gate, ``register_tools``, ``providers.build_for_effort``, ``_make_hooks``, ``observe``
— so nothing judge-specific leaks into ``runtime/`` (the shared, agent-neutral layer).

This module imports the pydantic-ai graph, so it is imported LAZILY (only when
``LEARNING_JUDGE_ENGINE=pydantic_ai``); the default ``claude_print`` path never
touches it. Selection happens in ``core/subagents.ClaudePrintSubagents.judge``.
"""
from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from defender.learning.core.config import (
    REPO_ROOT,
    SUBAGENT_TIMEOUT,
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    _log,
)
from defender.runtime import observe, providers
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import DEFAULT_TOOL_RETRIES, _make_hooks
from defender.runtime.permission import AgentPolicy, BashDecision, command_shape
from defender.runtime.providers import BuiltModel
from defender.runtime.tools import RunDeps, register_tools

from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.usage import UsageLimits

if TYPE_CHECKING:
    from defender.runtime.bash_exec import Pipeline

    from .run import _ToolScope

# The judge does a handful of jq/grep tool calls then emits its YAML verdict; a small
# request cap bounds a runaway tool loop (the twin of the gather's per-lead cap).
JUDGE_REQUEST_LIMIT = 30

# The model-construction seam (DI): (model_name, effort) -> BuiltModel. Defaults to the
# provider abstraction; tests inject BuiltModel(FunctionModel, None) to run hermetically
# — the judge's twin of the runtime driver's `make_model` factory.
JudgeModelFactory = Callable[[str, str], BuiltModel]

# A reasoning model on the in-process engine sometimes prepends prose to its final
# text turn before the YAML verdict (observed: Sonnet emitting 2 paragraphs of analysis
# above `outcome:`), which downstream `strip_yaml_fence` (fences/<thinking> only)
# doesn't remove, so yaml.safe_load fails. The judge doc's first top-level key is always
# `outcome:` at column 0 (the prompt mandates "first character is o"); a citation's inner
# `outcome:` is indented, so this anchor finds the doc start without matching those.
_YAML_DOC_START = re.compile(r"^outcome:", re.MULTILINE)


def _extract_yaml_doc(text: str) -> str:
    """Trim any leading prose preamble before the YAML verdict. Falls back to the full
    text when there's no top-level `outcome:` line (a genuinely malformed output — it
    then fails validation downstream, exactly as it should)."""
    m = _YAML_DOC_START.search(text)
    return text[m.start():] if m else text


_JUDGE_DENY_REASON = (
    "Blocked: the judge is read-only over the grounded evidence — jq/grep/cat/ls over "
    "the comparison files and the gather_raw payloads (plus, benign only, the pinned "
    "closed-ticket read). No data-source adapters, no writes, no arbitrary shell."
)


@dataclass(frozen=True)
class JudgeDeps(RunDeps):
    """The judge's per-run deps. Identical shape to ``RunDeps`` (run_dir, defender_dir,
    run_id, salt, policy) — the judge's read roots and its custom matcher ride in
    ``policy`` (data), not in extra deps fields. ``run_dir`` is the *learning* run dir
    (the judge's own output dir), so budget/lesson-load side effects land there and the
    judge can only reach gather_raw via its policy read roots, never roam the whole
    investigation run dir. ``role`` is a JUDGE identity label — the gate keys on
    ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.JUDGE


def _make_ticket_matcher(py: Path, ticket_cli: Path):
    """The benign judge's one bit of custom logic (issue #338): allow the scoped,
    CLOSED-ONLY case-history read that confirms a cited past case. Claims exactly a
    single-stage ``<py> <ticket_cli> {list-tickets|get-ticket} … --require-closed …``
    invocation — `py`/`ticket_cli` pinned, and ``--require-closed`` REQUIRED (the
    security property that the open in-flight ticket stays unreachable rides on that
    flag). Anything else declines (`None`) and falls through to the generic gate,
    which denies it (``<py> <ticket_cli> …`` is not a read-only viewer). The
    adversarial judge is built with no matchers, so it can never reach the store."""
    py_s, cli_s = str(py), str(ticket_cli)

    def _match(pipelines: list[Pipeline]) -> BashDecision | None:
        stages = command_shape.flat_stages(pipelines)
        if len(stages) != 1:  # a single command, never a pipe/compound
            return None
        argv = stages[0]
        if len(argv) < 3 or argv[0] != py_s or argv[1] != cli_s:
            return None
        if argv[2] not in ("list-tickets", "get-ticket"):
            return None
        if "--require-closed" not in argv:
            return None
        return BashDecision(True, pipelines=tuple(pipelines))

    return _match


def _judge_policy(read_roots: tuple[Path, ...], ticket_cli: tuple[Path, Path] | None) -> AgentPolicy:
    """The judge's declarative gate policy: read-only, may `jq`/read gather_raw
    (raw_reads) + its comparison dir (read_roots), never runs a data-source adapter,
    and — benign only — carries the pinned closed-ticket matcher as its custom logic."""
    matchers = (_make_ticket_matcher(*ticket_cli),) if ticket_cli is not None else ()
    return AgentPolicy(
        adapters=False,
        adapter_sql_pipe=False,
        raw_reads=True,
        read_roots=read_roots,
        custom_matchers=matchers,
        deny_reason=_JUDGE_DENY_REASON,
    )


def build_judge_agent(
    prompt_path: Path, model: str, effort: str,
    logger: observe.RequestLogger, agent_id: str,
    *, make_model: JudgeModelFactory = providers.build_for_effort,
) -> Agent[JudgeDeps, str]:
    """The in-process judge agent: the read-only tool pair (bash + read_file, via
    ``register_tools(writers=False)`` — no writers, no gather dispatch), the direction's
    system prompt, the model chosen by name + its effort settings
    (``providers.build_for_effort`` → Anthropic ``anthropic_effort`` / Fireworks
    ``reasoning_effort``), and the shared budget/observability hooks. Parallels the
    runtime's ``_build_subagent`` — the judge is just another read-only PydanticAI
    agent, specialized by prompt + policy + model. ``make_model`` is the DI seam tests
    use to inject a FunctionModel."""
    built = make_model(model, effort)
    agent: Agent[JudgeDeps, str] = Agent(
        built.model,
        deps_type=JudgeDeps,
        instructions=prompt_path.read_text(),
        capabilities=[_make_hooks(logger, agent_id)],
        model_settings=built.settings,
        retries=DEFAULT_TOOL_RETRIES,
    )
    register_tools(agent, writers=False)
    return agent


async def _drive(agent: Agent[JudgeDeps, str], user: str, deps: JudgeDeps):
    """One-shot judge run with a wall-clock ceiling (the in-process twin of the
    ``claude -p`` subprocess timeout) and a request cap on the tool loop."""
    return await asyncio.wait_for(
        agent.run(
            user, deps=deps,
            usage_limits=UsageLimits(request_limit=JUDGE_REQUEST_LIMIT),
        ),
        timeout=SUBAGENT_TIMEOUT,
    )


def _run_judge_pydantic(
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    *,
    scope: _ToolScope,
    make_model: JudgeModelFactory = providers.build_for_effort,
) -> str:
    """The PydanticAI ``judge_fn`` — same signature as ``_run_judge_claude`` so it drops
    into ``invoke_judge(..., judge_fn=_run_judge_pydantic)``.

    Builds the judge agent + its ``JudgeDeps`` from the tool ``scope`` (read roots =
    the comparison + gather_raw add-dirs; the benign closed-ticket paths), runs it once
    (async bridged via ``asyncio.run`` — safe in the loop's per-direction worker
    thread, which has no running event loop), logs every request to
    ``learning_run_dir/{trace_name}``, and returns the final YAML text (downstream
    ``_validate_judge_yaml`` parses it unchanged). A timeout / usage-limit / model error
    raises ``RunUnprocessable`` — the same per-run failure disposition as the
    ``claude -p`` path's non-zero exit."""
    add_dirs = scope.add_dir or []
    read_roots = tuple(add_dirs if isinstance(add_dirs, list) else [add_dirs])
    deps = JudgeDeps(
        run_dir=learning_run_dir,
        defender_dir=REPO_ROOT / "defender",
        run_id=learning_run_dir.name,
        salt=uuid.uuid4().hex,
        policy=_judge_policy(read_roots, scope.ticket_cli),
    )
    logger = observe.RequestLogger(learning_run_dir / trace_name)
    _log(f"step={label} engine=pydantic_ai model={model} effort={effort}")
    try:
        agent = build_judge_agent(prompt_path, model, effort, logger, label, make_model=make_model)
        result = asyncio.run(_drive(agent, user, deps))
    except (asyncio.TimeoutError, UsageLimitExceeded) as e:
        raise RunUnprocessable(f"judge ({label}) did not complete: {e!r}") from e
    except (StageAbort, FatalConfigError):
        raise  # systemic faults doom the whole stage (exit 2) — never per-run dead-letter
    except Exception as e:  # a model/API error after retries — quarantine the run
        raise RunUnprocessable(f"judge ({label}) failed: {e!r}") from e
    finally:
        logger.close()
    return _extract_yaml_doc(str(result.output or ""))
