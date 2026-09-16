"""#987 — the request ceiling, enforced at the ROUND.

A gather lead runs under `UsageLimits(request_limit=L)`: the framework answers L model
requests and refuses the (L+1)th. The lead's summary is whatever text its LAST answered
request produces, so the harness owes the model one fact — "this request is your last, and
the summary is what it is for" — and owes main one true account of how the lead ended.

Both are properties of the round, not of any one tool. The model can spend a round on
`query`, on `bash`, on `read_file`, on a refused call or on a validation retry, and the fact
is the same. So the final request is handled by two hooks that run around EVERY model request
and share one predicate, `is_final_request`: the run's request count against the ceiling the
run was handed (`ctx.usage_limits`, the same object `_run_gather` gave `agent.run`).

BEFORE the final request goes out, the sentence is added to it — in the user turn that
carries the previous round's results — and the request is sent with `tool_choice: none`: the
tool definitions stay on the wire (a history carrying `tool_use`/`tool_result` blocks must
define tools — Anthropic's Messages API refuses one that does not), but the model is told it
may not call any. AFTER the final response arrives, any function tool call the provider let
through anyway is dropped from it before the framework sees it, so what remains is the text
the model wrote — and the run ends on that text the way a finished lead's does. There is no
"budget spent" tool result, no refused round, and no summary lost beside a stray call: on the
final request a tool call is not a thing that happens.

The ceiling is recorded on the lead's `LeadStop` at the moment the sentence goes out, so the
frame composing main's notice reads a fact that was written, never a count it infers.

What the model reads here is gather's own vocabulary. MAIN's idiom ("Treat this lead as
incomplete…") lives in `tools_gather` and is never among these sentences (#807 G19).
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from pydantic_ai.capabilities.abstract import AbstractCapability
from pydantic_ai.messages import ModelRequest, ToolCallPart, UserPromptPart

#: What every closing sentence ends on: the summary is owed NOW, and it must name its gaps.
WRITE_SUMMARY_NOW = (
    "Write the summary now, from what you already retrieved: address each item you were asked "
    "to summarize, and name plainly which of them you could not establish."
)
#: Added to the LAST request the ceiling allows, after that round's tool results.
FINAL_REQUEST = (
    "This is the last request this lead's budget allows; no tool can be called on it. "
    + WRITE_SUMMARY_NOW
)


def requests_so_far(ctx: Any) -> int:
    """The run's request count as the framework keeps it: bumped when request N's response
    ARRIVES, before the after-request hook sees it — so it reads N-1 while request N is being
    prepared, and N from the moment its response is in hand through round N's tool calls.
    `0` for a context with no usage at all (lead zero drives tool hooks with a bare
    namespace). The one spelling of this read — the recorder's doomed-round withholding and
    this module's predicate must be counting the same thing."""
    usage = getattr(ctx, "usage", None)
    requests = getattr(usage, "requests", None)
    return int(requests) if requests is not None else 0


def request_limit(ctx: Any) -> int | None:
    """The ceiling the RUN was handed — `UsageLimits.request_limit` as `agent.run` received
    it, which the framework puts on every hook's context. `None` for a run with no ceiling
    (an agent bound outside a dispatch), and for a bare context."""
    return getattr(getattr(ctx, "usage_limits", None), "request_limit", None)


def is_final_request(ctx: Any, *, answered: bool) -> bool:
    """Whether the request in hand is the last the ceiling allows: the one being PREPARED
    (`answered=False`, the count reads one less than its number) or the one whose response
    just arrived (`answered=True`, the count reads its number). One predicate for both hooks,
    so the request that is marked is the request whose calls are dropped."""
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
        # The processed history must end with a `ModelRequest` — the framework raises one
        # line after this hook if it does not, and that is its error to raise, not one to
        # pre-empt by appending a user part to whatever is there. The framework itself
        # orders a request's parts tool-returns-first, user-parts-after, so appending is the
        # canonical shape, and the store records the request as sent.
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
        """The response to the final request carries no function tool calls into the
        framework: a provider that honoured `tool_choice: none` sent none, and one that did
        not has them dropped here. What remains is the model's text — its summary — and the
        run ends on it. A response left with no text at all is the framework's ordinary
        empty-response case (an output retry the ceiling then refuses), which `_run_gather`
        reports as the fault it is."""
        if not is_final_request(ctx, answered=True):
            return response
        kept = [p for p in response.parts if not isinstance(p, ToolCallPart)]
        if len(kept) == len(response.parts):
            return response
        return replace(response, parts=kept)
