"""#987 — the request ceiling, enforced at the ROUND.

A gather lead runs under `UsageLimits(request_limit=L)`: the framework answers L model
requests and refuses the (L+1)th. The lead's summary is whatever text its LAST answered
request produces, so the harness owes the model one fact — "this request is your last, and
the summary is what it is for" — and owes main one true account of how the lead ended.

Both are properties of the round, not of any one tool. The model can spend a round on
`query`, on `bash`, on `read_file`, on a refused call or on a validation retry, and the fact
is the same. So the sentence is added to request L itself, in the user turn that carries the
previous round's results, by a hook that runs before EVERY model request and reads one
number: the run's request count against the ceiling the dispatch was handed. The same
comparison, one step later, says that round L's tool calls belong to a request the framework
will never send — so they are not run.

What the model reads here is gather's own vocabulary. MAIN's idiom ("Treat this lead as
incomplete…") lives in `tools_gather` and is never among these sentences (#807 G19).
"""
from __future__ import annotations

from typing import Any

from pydantic_ai.capabilities.abstract import AbstractCapability
from pydantic_ai.exceptions import ToolFailed
from pydantic_ai.messages import ModelRequest, UserPromptPart

#: What every closing sentence ends on: the summary is owed NOW, and it must name its gaps.
WRITE_SUMMARY_NOW = (
    "Write the summary now, from what you already retrieved: address each item you were asked "
    "to summarize, and name plainly which of them you could not establish."
)
#: Added to the LAST request the ceiling allows, after that round's tool results.
FINAL_REQUEST = (
    "This is the last request this lead's budget allows; no tool call made now will be "
    "answered. " + WRITE_SUMMARY_NOW
)
#: A tool call made ON the final request. The model was told; the result would go into a
#: request the framework refuses; nothing runs.
TOOL_NOT_RUN_BUDGET_SPENT = (
    "This call was not executed: the lead's request budget is spent, and no result could be "
    "shown to you."
)


def requests_so_far(ctx: Any) -> int:
    """The run's request count as the framework keeps it: bumped when a response ARRIVES, so
    it reads N-1 while request N is being prepared and N while round N's tool calls run. `0`
    for a context with no usage at all (lead zero drives tool hooks with a bare namespace).
    The one spelling of this read — the recorder's doomed-round withholding and this module's
    two checks must be counting the same thing."""
    usage = getattr(ctx, "usage", None)
    requests = getattr(usage, "requests", None)
    return int(requests) if requests is not None else 0


def _ceiling(ctx: Any) -> int | None:
    return getattr(ctx.deps, "request_limit", None)


class RequestCeiling(AbstractCapability[Any]):
    """Installed on every gather agent by `build_gather_agent`; a no-op on deps that carry no
    `request_limit` (bound outside a dispatch)."""

    async def before_model_request(self, ctx, request_context):  # noqa: ANN001
        limit = _ceiling(ctx)
        if limit is None or requests_so_far(ctx) != limit - 1:
            return request_context
        last = request_context.messages[-1]
        # The processed history must end with a `ModelRequest` (the framework asserts it), and
        # the framework itself orders a request's parts tool-returns-first, user-parts-after —
        # so appending here is the canonical shape, and the store records the request as sent.
        assert isinstance(last, ModelRequest)
        last.parts = [*last.parts, UserPromptPart(content=FINAL_REQUEST)]
        return request_context

    async def wrap_tool_execute(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        limit = _ceiling(ctx)
        if limit is not None and requests_so_far(ctx) >= limit:
            raise ToolFailed(TOOL_NOT_RUN_BUDGET_SPENT)
        return await handler(args)
