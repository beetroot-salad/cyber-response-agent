"""The request ceiling, enforced at the round.

A gather lead runs under `UsageLimits(request_limit=L)`, and its summary is the text of its
last answered request. So the model must be told which request is its last, whatever tool the
round used. Two hooks around every model request share one predicate, `is_final_request`,
comparing the request count to `ctx.usage_limits`.

Before the final request, the closing sentence is appended to its user turn and it is sent
with `tool_choice: none` (tool definitions stay on the wire: a history with tool blocks must
define tools). After the response, any tool call the provider let through is dropped, so the
run ends on the model's text like a finished lead.

The ceiling is recorded on the lead's `LeadStop` when the sentence goes out, so main's notice
reads a recorded fact rather than an inferred count. These sentences are gather's vocabulary;
main's "treat this lead as incomplete" idiom lives in `tools_gather`.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from pydantic_ai.capabilities.abstract import AbstractCapability
from pydantic_ai.messages import ModelRequest, ToolCallPart, UserPromptPart

#: What every closing sentence ends on: write the summary now, naming its gaps.
WRITE_SUMMARY_NOW = (
    "Write the summary now, from what you already retrieved: address each item you were asked "
    "to summarize, and name plainly which of them you could not establish."
)
#: Added to the last request the ceiling allows, after that round's tool results.
FINAL_REQUEST = (
    "This is the last request this lead's budget allows; no tool can be called on it. "
    + WRITE_SUMMARY_NOW
)


def requests_so_far(ctx: Any) -> int:
    """The framework's request count: N-1 while request N is prepared, N once its response
    arrives. `0` for a context with no usage (lead zero uses a bare namespace). The recorder's
    final-round withholding must use this same read."""
    usage = getattr(ctx, "usage", None)
    requests = getattr(usage, "requests", None)
    return int(requests) if requests is not None else 0


def request_limit(ctx: Any) -> int | None:
    """The run's `UsageLimits.request_limit` from the hook context, or `None` (no ceiling, or
    a bare context)."""
    return getattr(getattr(ctx, "usage_limits", None), "request_limit", None)


def is_final_request(ctx: Any, *, answered: bool) -> bool:
    """Whether the request in hand (being prepared, or just `answered`) is the last the
    ceiling allows. Shared by both hooks so the marked request is the one whose calls are
    dropped."""
    limit = request_limit(ctx)
    if limit is None:
        return False
    number = requests_so_far(ctx) + (0 if answered else 1)
    return number == limit


class RequestCeiling(AbstractCapability[Any]):
    """Installed on every gather agent by `build_gather_agent`; a no-op on a run with no
    request ceiling."""

    async def before_model_request(self, ctx, request_context):  # noqa: ANN001
        if not is_final_request(ctx, answered=False):
            return request_context
        last = request_context.messages[-1]
        # If the history doesn't end with a `ModelRequest`, let the framework raise its own
        # error. Appending matches its tool-returns-then-user-parts ordering.
        if isinstance(last, ModelRequest):
            last.parts = [*last.parts, UserPromptPart(content=FINAL_REQUEST)]
        request_context.model_settings = {
            **(request_context.model_settings or {}), "tool_choice": "none",
        }
        stop = getattr(ctx.deps, "stop", None)
        if stop is not None:
            stop.mark_ceiling(request_limit(ctx))
        return request_context

    async def after_model_request(self, ctx, *, request_context, response):  # noqa: ANN001
        """Drop any tool calls from the final response (a provider may ignore
        `tool_choice: none`), so the run ends on the model's summary text. A response with no
        text becomes the framework's empty-response fault, reported by `_run_gather`."""
        if not is_final_request(ctx, answered=True):
            return response
        kept = [p for p in response.parts if not isinstance(p, ToolCallPart)]
        if len(kept) == len(response.parts):
            return response
        return replace(response, parts=kept)
