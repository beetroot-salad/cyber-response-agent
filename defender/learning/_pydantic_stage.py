from __future__ import annotations

import asyncio
import logging
import functools
from collections.abc import Callable
from dataclasses import replace
from typing import Any, ClassVar, NamedTuple, Protocol

from defender._text import is_content_less
from defender.box import BoxOutputLimitExceeded
from defender._exception_groups import carried
from defender.learning.core.config import (
    FatalConfigError,
    ReplyUnusable,
    RunUnprocessable,
    StageAbort,
    StageContext,
    StageWiring,
)
from defender.investigation import observe
from defender import providers
from defender._agent_role import AgentRole
from defender._model_view import ModelView
from defender.investigation.driver import MakeModel, build_agent_core

from pydantic_ai import Agent
from pydantic_ai import ModelRetry, TextOutput, ToolOutput, capture_run_messages
from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded
from pydantic_ai.messages import ModelRequest, ModelResponse, RetryPromptPart
from pydantic_ai.usage import UsageLimits
from defender._io import read_text_utf8

_logger = logging.getLogger(__name__)


class RoleDeps(Protocol):
    """What this module needs of a deps object: a type that names its role.

    Not `AgentDeps`: that is the run scope (run dir, policy, box executor), which the deny-all
    roles (questioner, judge) deliberately do not carry. `build_stage_agent` reads only
    `deps_type.role`; every `AgentDeps` subclass declares it too.
    """

    role: ClassVar[AgentRole]


def with_make_model(runner: Callable[..., str], make_model: MakeModel | None) -> Callable[..., str]:
    """`runner` (a stage's `run_author`) over `make_model`; `None` keeps the stage's own default model."""
    if make_model is None:
        return runner
    return functools.partial(runner, make_model=make_model)


def build_stage_agent(
    deps_type: type[RoleDeps],
    wiring: StageWiring,
    logger: observe.RequestLogger,
    *,
    make_model: MakeModel = providers.build_for_effort,
    tools: Any = None,
    verbs: Any = None,
    workspace: ModelView | None = None,
) -> Agent[Any, str]:
    from defender.learning.roles import LEARNING_AGENTS

    overrides: dict[str, Any] = {"model": lambda: wiring.model, "effort": wiring.effort}
    if tools is not None:
        overrides["tools"] = tools
    defn = replace(LEARNING_AGENTS[deps_type.role], **overrides)
    instructions = read_text_utf8(wiring.prompt_path)
    if workspace is not None:
        instructions += (
            "\n\nYou are part of the defender learning loop.\n"
            f"Working directory: {workspace.cwd}\n"
            f"Workspace roots: {workspace.roots_text()}\n"
            "These paths name your workspace; your declared tool permissions still apply.\n"
        )
    return build_agent_core(
        defn,
        deps_type=deps_type,
        instructions=instructions,
        logger=logger,
        agent_id=wiring.label,
        make_model=make_model,
        verbs=verbs,
    )


class TypedOutput(NamedTuple):
    """One typed call (#1579): the model answers through an output tool named `name` whose
    arguments are described by `schema` (the shape only; `check` is the owner of validity).

    `check(mapping)` returns to accept the tool's arguments, raises `pydantic_ai.ModelRetry(reason)`
    to refuse them (the reason goes back to the model, inside the same call), and any other
    exception is a host error. At most `retries` re-asks: the call sends at most 1 + `retries`
    requests."""

    name: str
    description: str
    schema: dict
    check: Callable[[Any], None]
    retries: int


class Accepted(NamedTuple):
    """A typed call's accepted reply and how many requests it took."""

    mapping: dict
    requests: int


_CALL_THE_TOOL = "Plain text is not an answer: call the tool to give it."


async def _drive(
    agent: Agent[Any, Any], user: str, deps: RoleDeps, request_limit: int, timeout: int,
    **extra: Any,
):
    return await asyncio.wait_for(
        agent.run(user, deps=deps, usage_limits=UsageLimits(request_limit=request_limit), **extra),
        timeout=timeout,
    )


class _Typed:
    """The state of one typed call: whether the check failed on the host, and the call's history."""

    def __init__(self, spec: TypedOutput) -> None:
        self.spec = spec
        self.host_fault = False
        self.history: list[Any] = []

    def output_type(self) -> list[Any]:
        from pydantic_ai import StructuredDict

        args_type = StructuredDict(dict(self.spec.schema))

        def answer(args):
            try:
                self.spec.check(args)
            except ModelRetry:
                raise
            except BaseException:
                self.host_fault = True
                raise
            return dict(args)

        answer.__annotations__ = {"args": args_type, "return": dict}

        def no_text(_text: str) -> dict:
            raise ModelRetry(_CALL_THE_TOOL)

        return [ToolOutput(answer, name=self.spec.name, description=self.spec.description),
                TextOutput(no_text)]

    async def drive(self, agent: Any, user: str, deps: Any, timeout: int):
        bound = 1 + self.spec.retries
        # The retry budgets are only a backstop: the request limit is the one bound, so every
        # order of refusals ends the same way and the history ends with the last refusal.
        budget = bound + 1
        with capture_run_messages() as messages:
            self.history = messages
            return await _drive(
                agent, user, deps, bound, timeout * bound,
                output_type=self.output_type(),
                retries={"tools": budget, "output": budget},
            )

    def responses(self) -> int:
        return sum(1 for m in self.history if isinstance(m, ModelResponse))

    def last_reason(self) -> str:
        for message in reversed(self.history):
            if isinstance(message, ModelRequest):
                for part in message.parts:
                    if isinstance(part, RetryPromptPart):
                        return _bare(part.model_response())
        return "no reason recorded"


def _bare(reason: str) -> str:
    """A retry prompt's reason without the framework's wrapper lines."""
    return reason.removeprefix("Validation feedback:\n").removesuffix(
        "\n\nFix the errors and try again.").strip()


def _typed_ending(typed: _Typed, stage: str, label: str, e: BaseException) -> Exception:
    responses = typed.responses()
    if isinstance(e, (UsageLimitExceeded, UnexpectedModelBehavior)) and not typed.host_fault:
        reason = typed.last_reason()
        return ReplyUnusable(
            f"{stage} ({label}) reply unusable after {responses} requests: {reason}",
            reason=reason, requests=responses)
    # A host fault in the check came after its request's response; any other failure (transport,
    # provider, the wall clock) cut a request that was sent and has no response.
    raised = RunUnprocessable(f"{stage} ({label}) failed: {e!r}")
    raised.requests = responses if typed.host_fault else responses + 1
    return raised


def _last_response_is_empty_text(messages: list[dict]) -> bool:
    """Whether the latest model response contains only content-less text parts."""
    for record in reversed(messages):
        if record.get("kind") != "response":
            continue
        message = record.get("message") or {}
        parts = message.get("parts") or []
        return bool(parts) and all(
            part.get("part_kind") == "text"
            and is_content_less(str(part.get("content") or ""))
            for part in parts
        )
    return False



def _text_ending(stage: str, label: str, e: Exception, *, empty: bool) -> RunUnprocessable:
    if empty:
        return RunUnprocessable(f"{stage} ({label}) returned empty output")
    if isinstance(e, (TimeoutError, UsageLimitExceeded)):
        return RunUnprocessable(f"{stage} ({label}) did not complete: {e!r}")
    return RunUnprocessable(f"{stage} ({label}) failed: {e!r}")


def run_stage(  # noqa: PLR0913 — the stage's own keyword set plus the typed output
    *,
    stage: str,
    wiring: StageWiring,
    ctx: StageContext,
    deps: RoleDeps,
    make_model: MakeModel = providers.build_for_effort,
    require_output: bool = True,
    tools: Any = None,
    verbs: Any = None,
    output: TypedOutput | None = None,
) -> str | Accepted:
    """Drive one in-process stage. `wiring` is how the stage is configured, `ctx` is what
    this spawn is about.

    With `output`, the call is typed (#1579) and the runner alone owns its ending: it returns
    `Accepted(mapping, requests)`, raises `ReplyUnusable` when the model's attempts ran out, or
    `RunUnprocessable` for any other failure (transport, provider, timeout, a host error in
    the check). Both carry `requests`."""
    label = wiring.label
    from defender.investigation.tools import AgentDeps

    # Under `wire_logs/`, never the run dir root: the trace is the stage's whole context
    # verbatim, learning run dirs are shared, and readers of the root are not shape-filtered.
    # The wire-log policy denial (`files.names_wire_log_dir`) only covers this subdirectory.
    logger = observe.RequestLogger(
        observe.stage_trace_path(ctx.learning_run_dir, wiring.trace_name)
    )
    logger.bind_ledger(observe.NO_LEDGER)  # a learning stage has its own charge and no spend ledger (#1377)
    _logger.info(f"step={label} engine=pydantic_ai model={wiring.model} effort={wiring.effort}")
    typed = _Typed(output) if output is not None else None
    try:
        try:
            agent = build_stage_agent(
                type(deps), wiring, logger,
                make_model=make_model, tools=tools, verbs=verbs,
                workspace=deps.view if isinstance(deps, AgentDeps) else None,
            )
        except ValueError as e:
            raise FatalConfigError(f"{stage} ({label}) misconfigured: {e}") from e
        if typed is not None:
            result = asyncio.run(typed.drive(agent, ctx.user, deps, ctx.wall_clock_timeout))
        else:
            result = asyncio.run(
                _drive(agent, ctx.user, deps, ctx.request_limit, ctx.wall_clock_timeout)
            )
    except (StageAbort, FatalConfigError):
        raise
    except Exception as e:
        if carried(e, BoxOutputLimitExceeded) is not None:
            raise
        if typed is not None:
            raise _typed_ending(typed, stage, label, e) from e
        raise _text_ending(stage, label, e, empty=require_output and _last_response_is_empty_text(logger.messages)) from e
    finally:
        logger.close()
    if typed is not None:
        return Accepted(dict(result.output), typed.responses())
    out = str(result.output or "")
    if require_output and is_content_less(out):
        raise RunUnprocessable(f"{stage} ({label}) returned empty output")
    return out
