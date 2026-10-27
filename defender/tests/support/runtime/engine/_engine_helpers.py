"""Shared `FunctionModel` replay plumbing for the engine/tool test modules."""
from __future__ import annotations

from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel

from defender.providers import BuiltModel


def fake_model(fn):
    """A `make_model` stand-in returning `fn` as the model (no settings: a FunctionModel needs none)."""
    return lambda model, effort: BuiltModel(FunctionModel(fn), None)


def replay_once(text: str):
    """A FunctionModel fn answering every request with one text part, even an empty one: an empty
    final is a real case some stages must reject, so it must survive to the model response."""
    def fn(messages, info):
        return ModelResponse(parts=[TextPart(content=text)])
    return fn
