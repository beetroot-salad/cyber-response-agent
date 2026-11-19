"""#1579: a scripted model for typed (output-tool) stage calls, and the spellings the contract
imposes on the typed runner and the two seams.

`ScriptedCalls` is a `make_model(name, effort)`: each agent built through it takes the next
script, and each model request of that call the next reply in it. A reply is one of:

- a `dict`: a call to the output tool the request offered (its name read off the request);
- a `str`: a plain text answer (`""` is an empty one);
- `BadJSON(text)`: a call to the offered output tool whose arguments are not valid JSON;
- `UnknownTool(args)`: a call to a tool the request never offered;
- an exception instance: raised from the model (a transport or provider fault).

Every request's messages are kept, so a case reads the reason the framework sent back as the
model read it. Production symbols that do not exist before #1579 are resolved lazily, so a
missing one fails the test that reaches it, never collection.
"""
from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    RetryPromptPart,
    TextPart,
    ToolCallPart,
    UserPromptPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel

from defender.providers import BuiltModel

#: Design r3's per-call retry limit N ("N: proposed 2").
N = 2
#: O2: at most 1 + N model requests per call.
MAX_REQUESTS = 1 + N


@dataclass(frozen=True)
class BadJSON:
    """An output-tool call whose arguments do not parse as JSON."""

    text: str = '{"story": "unterminated'


@dataclass(frozen=True)
class UnknownTool:
    """A call to a tool the request did not offer."""

    args: Any = None
    name: str = "submit_answer_v0"


class ScriptedCalls:
    """`make_model(name, effort)` for a sequence of calls; see the module docstring."""

    def __init__(self, *calls: list[Any]) -> None:
        self._scripts = [list(c) for c in calls]
        #: Per call, the messages each of its requests sent.
        self.requests: list[list[list[Any]]] = []
        #: Per call, the output tools its first request offered.
        self.offered: list[list[Any]] = []

    def __call__(self, name: str, effort: str | None) -> BuiltModel:  # noqa: ARG002 — the wiring's choice, not this script's
        if not self._scripts:
            raise AssertionError(f"no scripted call left for call {len(self.requests) + 1}")
        script = self._scripts.pop(0)
        seen: list[list[Any]] = []
        self.requests.append(seen)
        index = len(self.requests) - 1

        def fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
            seen.append(list(messages))
            if len(seen) == 1:
                self.offered.append(list(info.output_tools))
            if not script:
                raise AssertionError(f"call {index + 1} sent a request its script does not hold")
            return _respond(script.pop(0), info, index)

        return BuiltModel(FunctionModel(fn), None)

    def request_counts(self) -> list[int]:
        return [len(r) for r in self.requests]

    def reasons_sent(self, call: int) -> list[str]:
        """Every retry prompt the framework sent back within call `call`, as the model read it."""
        out: list[str] = []
        for messages in self.requests[call][1:]:
            last = messages[-1]
            if isinstance(last, ModelRequest):
                out += [p.model_response() for p in last.parts if isinstance(p, RetryPromptPart)]
        return out

    def user_prompt(self, call: int) -> str:
        first = self.requests[call][0]
        return "\n".join(str(p.content) for m in first if isinstance(m, ModelRequest)
                         for p in m.parts if isinstance(p, UserPromptPart))

    def exhausted(self) -> bool:
        """Every scripted call was made and every scripted reply consumed."""
        return not self._scripts


def _respond(reply: Any, info: AgentInfo, index: int) -> ModelResponse:
    if isinstance(reply, BaseException):
        raise reply
    if isinstance(reply, str):
        return ModelResponse(parts=[TextPart(content=reply)])
    if isinstance(reply, UnknownTool):
        return ModelResponse(parts=[ToolCallPart(tool_name=reply.name, args=reply.args or {})])
    if not info.output_tools:
        raise AssertionError(f"call {index + 1} offered no output tool to answer through")
    tool = info.output_tools[0].name
    if isinstance(reply, BadJSON):
        return ModelResponse(parts=[ToolCallPart(tool_name=tool, args=reply.text)])
    return ModelResponse(parts=[ToolCallPart(tool_name=tool, args=dict(reply))])


def response_records(trace: Path) -> int:
    """How many model responses a `RequestLogger` trace holds (O5: one per request)."""
    if not trace.is_file():
        return 0
    return sum(1 for line in trace.read_text(encoding="utf-8").splitlines()
               if line.strip() and json.loads(line).get("kind") == "response")


def http_413() -> BaseException:
    """The provider's answer to an over-long prompt, as `pydantic_ai` raises it."""
    from pydantic_ai.exceptions import ModelHTTPError

    return ModelHTTPError(status_code=413, model_name="scripted",
                          body={"error": {"type": "request_too_large"}})


# ------------------------------------------------------------------------------------------
# Spellings the contract imposes where design r3 names none (one place each).
# ------------------------------------------------------------------------------------------

#: Module holding `run_stage`, `TypedOutput` and `Accepted`.
STAGE = "defender.learning._pydantic_stage"
#: Module holding `RunUnprocessable` and `ReplyUnusable`.
CONFIG = "defender.learning.core.config"


def _sym(module: str, name: str) -> Any:
    return getattr(importlib.import_module(module), name)


def typed_output(check: Any, *, name: str = "answer", schema: dict | None = None,
                 retries: int = N) -> Any:
    """`run_stage(output=...)`: the call's output tool and its in-call check.

    `TypedOutput(name, description, schema, check, retries)`. `check(mapping)` returns nothing
    to accept the tool's arguments, raises `pydantic_ai.ModelRetry(reason)` to refuse them
    (the reason goes back to the model), and any other exception is a host error (P5).
    """
    return _sym(STAGE, "TypedOutput")(
        name=name, description="Submit your answer.",
        schema=schema if schema is not None else {"type": "object"},
        check=check, retries=retries)


def accepted() -> type:
    """`Accepted(mapping, requests)`: a typed `run_stage` call's (and a seam's) return; a
    2-tuple, so a fake may return a plain `(mapping, requests)`."""
    return _sym(STAGE, "Accepted")


def reply_unusable() -> type[BaseException]:
    """`ReplyUnusable(reason, requests)`: not a `RunUnprocessable` (P5)."""
    return _sym(CONFIG, "ReplyUnusable")


def run_unprocessable() -> type[BaseException]:
    return _sym(CONFIG, "RunUnprocessable")


def unusable(reason: str, *, requests: int = MAX_REQUESTS, label: str = "scripted") -> BaseException:
    """A seam fake's exhausted call: what the runner raises when retries run out."""
    return reply_unusable()(f"{label}: {reason}", reason=reason, requests=requests)


def unprocessable(message: str, *, requests: int = 1,
                  cause: BaseException | None = None) -> BaseException:
    """A seam fake's transport/provider failure, carrying the call's request count (P5)."""
    raised = run_unprocessable()(message)
    raised.requests = requests
    if cause is not None:
        raised.__cause__ = cause
    return raised


#: The keyword both production seam factories take for the model builder they hand
#: `run_stage` (`branch.seams.model_seam(ep, make_model=)`, `judge._default_judge_seam(ep,
#: make_model=)`), and the keyword `invoke` takes for the call's `TypedOutput`.
SEAM_MAKE_MODEL = "make_model"
INVOKE_OUTPUT = "output"
