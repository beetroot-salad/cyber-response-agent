"""Shared `FunctionModel` replay plumbing for the engine/tool test modules.

Every hermetic engine test drives a real stage through its `make_model` DI seam with
a scripted `FunctionModel` under `override_allow_model_requests(False)`. That needs
the same three pieces every time — a `BuiltModel` wrapper, a scripted response fn,
and (for the tool-calling stages) a way to see what the model was shown. They lived
as private copies in ten modules; the copies' own comments recorded the copy chain
(`mirrors _replay_harness` / `mirrors the verify engine test` / `mirrors the
lead-author test`), which is what a drifting hand-copy looks like.

Import AFTER the module's `pytest.importorskip("pydantic_ai")` — this module imports
pydantic_ai at module level, so a tree without the runtime extra must skip first.

`e2e/_replay_harness.py` stays separate on purpose: it replays whole golden runs
against the driver, not a single stage.
"""
from __future__ import annotations

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models.function import FunctionModel

from defender.runtime.providers import BuiltModel


def fake_model(fn):
    """A `make_model` stand-in returning `fn` as the model.

    settings=None — a FunctionModel needs no provider settings.
    """
    return lambda model, effort: BuiltModel(FunctionModel(fn), None)


def flatten_messages(messages) -> str:
    """Every str-valued part content across `messages`, newline-joined.

    What a test asserts against when it wants "did the model see the tool's return".
    """
    out = []
    for msg in messages:
        for part in getattr(msg, "parts", []):
            c = getattr(part, "content", None)
            if isinstance(c, str):
                out.append(c)
    return "\n".join(out)


def replay_once(text: str, *, calls=()):
    """A FunctionModel fn returning ONE scripted turn: optional tool calls + a text part.

    The text part is always appended, including when `text` is empty — an empty final
    is a real case some stages must reject, so it must survive to the model response.
    """
    def fn(messages, info):
        parts = [ToolCallPart(tool_name=n, args=a) for n, a in calls]
        parts.append(TextPart(content=text))
        return ModelResponse(parts=parts)
    return fn


def replay_turns(turns, *, seen=None, capture=flatten_messages):
    """A FunctionModel fn replaying scripted turns, one per call.

    Each turn is ``{"calls": [(tool, args), ...], "text": str}``; both keys optional.
    A turn's text part is appended only when non-empty (a tool-call-only turn carries
    no text) — the difference from `replay_once`, which always appends one.

    Once the script is exhausted the LAST turn repeats, so a stage that loops longer
    than the script does not fall off the end.

    When `seen` is a list, each call appends what the model was shown, through
    `capture` (default: flattened text; pass `capture=None` for the raw messages).
    """
    state = {"i": 0}

    def fn(messages, info):
        if seen is not None:
            seen.append(capture(messages) if capture is not None else messages)
        turn = turns[min(state["i"], len(turns) - 1)]
        state["i"] += 1
        parts = [ToolCallPart(tool_name=n, args=a) for n, a in turn.get("calls", [])]
        if turn.get("text"):
            parts.append(TextPart(content=turn["text"]))
        return ModelResponse(parts=parts)

    return fn
