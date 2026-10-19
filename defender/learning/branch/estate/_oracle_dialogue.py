"""Conversation settlement and the oracle capability guard."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from defender.learning.branch.estate.oracle import Oracle



import json





from typing import Any













from defender.learning.branch.estate._oracle_attempt import _Run as _Run






class _AttemptOver(Exception):
    """An oracle attempt that ends before its next model request goes out: its deadline passed,
    its request failed, or a tool already ended it. `told`: the oracle was handed `text` as that
    tool's own result, so nothing more is appended to the conversation."""

    def __init__(self, text: str, *, told: bool = False) -> None:
        super().__init__(text)
        self.text = text
        self.told = told




class _VerifierGaveUp(Exception):
    """The verifier's pass ends without a verdict: its model failed on the re-ask too."""




class _BudgetSpent(Exception):
    """The world's oracle budget is spent; the call ends unservable (reason `budget`)."""




def _settled(messages: list[Any]) -> list[Any]:
    """The conversation as far as its last request. A run cut off after a model reply never
    answered that reply's tool calls, and a provider refuses a conversation holding one."""
    from pydantic_ai.messages import ModelResponse

    out = list(messages)
    while out and isinstance(out[-1], ModelResponse):
        out.pop()
    return out




def _answered(messages: list[Any], call_id: str | None, answer: str) -> list[Any]:
    """`messages` with the `submit` call's result reading `answer` (what became of the
    submission) in place of the agent loop's stock acknowledgement."""
    from dataclasses import replace

    from pydantic_ai.messages import ModelRequest, ToolReturnPart

    out = list(messages)
    if call_id is None or not out or not isinstance(out[-1], ModelRequest):
        return out
    out[-1] = replace(out[-1], parts=[
        replace(part, content=answer)
        if isinstance(part, ToolReturnPart) and part.tool_call_id == call_id else part
        for part in out[-1].parts])
    return out




def _conversation_size(parts: list[Any]) -> int:
    """The characters `parts` carry, as `_PROMPT_BUDGET` counts them: every text a part holds
    (a prompt, a tool's result, a reply's text) and every tool call's arguments, measured as
    the text it is — the same count every cap here makes."""
    size = 0
    for part in parts:
        for value in (getattr(part, "content", None), getattr(part, "args", None)):
            if isinstance(value, str):
                size += len(value)
            elif value is not None:
                size += len(json.dumps(value, sort_keys=True, default=str))
    return size




def _guard(oracle: Oracle, actor: str) -> Any:
    """The one gate every model request of `actor`'s runs passes: the world's budget is checked
    before it goes out, a provider failure ends the attempt (the verifier re-asks once), and its
    spend is charged to the world. The deadline is the attempt's (`_within_deadline`)."""
    from pydantic_ai.capabilities import AbstractCapability

    class _Guard(AbstractCapability[_Run]):
        async def wrap_model_request(self, ctx: Any, *, request_context: Any,
                                     handler: Any) -> Any:
            run: _Run = ctx.deps
            if oracle.store.spent >= oracle.budget:
                raise _BudgetSpent(f"the oracle spent its budget ({oracle.store.spent:.6f} of "
                                   f"{oracle.budget} USD)")
            if run.ended is not None:
                raise _AttemptOver(run.ended, told=True)
            try:
                response = await handler(request_context)
            except (_BudgetSpent, _AttemptOver):
                raise
            except Exception as exc:  # noqa: BLE001 — a provider failure ends the attempt
                if actor == "verifier" and not run.reasked:  # the verifier re-asks once (M03=A)
                    run.reasked = True
                    return await self.wrap_model_request(
                        ctx, request_context=request_context, handler=handler)
                name = type(exc).__name__
                if actor == "verifier":
                    raise _VerifierGaveUp(f"the verifier's model request failed ({name})") from None
                raise _AttemptOver(f"the model request failed ({name})") from None
            # Outside the provider-failure handling: the request succeeded and was paid for.
            oracle.charge(actor, response)
            return response

    return _Guard()
