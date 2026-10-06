"""The TOON view gate: a provenance-gated, cost-bounded substitution of a foreign tool's
dict/list result with a smaller TOON view, framed like every other untrusted span.

Installed at the single `Agent(...)` composition root (`driver.build_agent_core`), so it is
on every build path. Defender's own tools are identified by toolset identity (the agent's
`_function_toolset`), not by name, so a same-named foreign tool cannot pass. Any other toolset
is foreign and gated unless marked with `mark_owned()`.

`_prevalidate` runs before the encoder: `toons.dumps` segfaults (rather than raising) on
self-referential or very deep containers. Encoder/decoder calls are guarded against
`BaseException` (the encoder's panic is one), re-raising only control-flow exceptions.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
from defender._model import model
from typing import Any, cast

import pydantic.dataclasses as _pydantic_dataclasses
from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.exceptions import ModelRetry, ToolRetryError
from pydantic_ai.messages import ToolReturn, ToolReturnPart, is_multi_modal_content
from pydantic_ai.toolsets import SetMetadataToolset, WrapperToolset

from defender._env import env_int
from defender.run_repository import GATE_METADATA_KEY
from defender._untrusted import wrap_fresh as _frame
from defender.hooks.budget_enforcer import BudgetKill

#: `GATE_METADATA_KEY` (the reserved key the original JSON rides on) lives in
#: `defender.run_repository._layout` because its reader, the visualizer, runs without pydantic-ai.
__all__ = ["GATE_METADATA_KEY", "ToonGateCapability", "mark_owned"]

_OWNED_METADATA_KEY = "_defender_toon_gate_owned"
_CANDIDATE_METADATA_KEY = "_defender_toon_gate_candidate"

#: The value `mark_owned` writes and `_is_owned` checks by identity. Not `True`: foreign
#: toolsets fill `ToolDefinition.metadata` too (e.g. from an MCP server's `meta`), and a
#: definition built from JSON can spell the key but never hold this object.
_OWNED_SENTINEL = object()

MAX_DEPTH_ENV = "DEFENDER_TOON_GATE_MAX_DEPTH"
MAX_NODES_ENV = "DEFENDER_TOON_GATE_MAX_NODES"
MAX_PERCENT_ENV = "DEFENDER_TOON_GATE_MAX_PERCENT"

#: Bound a hostile or huge payload's cost before the encoder sees it.
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_NODES = 100_000
#: An operator default (the value corpus measurements were taken at), not a contract.
DEFAULT_MAX_PERCENT = 85

#: The ceiling on in-flight `after_tool_execute` hand-offs. See `ToonGateCapability._pending`.
_MAX_PENDING = 64

#: Control-flow exceptions the encoder/decoder guard must never swallow.
_REPROPAGATE: tuple[type[BaseException], ...] = (
    BudgetKill, KeyboardInterrupt, GeneratorExit, SystemExit, asyncio.CancelledError,
)

#: The fixed byte cost `wrap_fresh` adds; constant because the salt is always 16 hex chars.
_FRAME_OVERHEAD = len(_frame("", "untrusted"))


def mark_owned(toolset: Any) -> Any:
    """Label a toolset as defender's own, opting it out of the gate. For the composition
    root only, never model-facing. Toolset metadata so it survives wrapping and combination."""
    return SetMetadataToolset(toolset, {_OWNED_METADATA_KEY: _OWNED_SENTINEL})


class _Refused(Exception):
    """Internal control-flow signal from `_prevalidate` — never escapes this module."""


def _check_key(k: Any) -> None:
    if not isinstance(k, str):
        raise _Refused("non-str mapping key")
    if "\x00" in k:
        raise _Refused("raw NUL in key")
    try:
        k.encode("utf-8")
    except UnicodeEncodeError:
        raise _Refused("unencodable mapping key") from None


class _Walker:
    """The pre-validator's recursive walk over `dict`/`list` (subclasses included):
      - charges the node budget for every value visited, bounding the walk's own cost;
      - refuses past the depth cap (deep but acyclic payloads);
      - refuses a container reachable from itself on the current path (path-scoped, so shared
        structure is still admitted);
      - refuses a raw NUL in any key or string.
    """

    def __init__(self, *, max_depth: int, max_nodes: int) -> None:
        self.max_depth = max_depth
        self.budget = max_nodes

    def _charge(self, depth: int) -> None:
        self.budget -= 1
        if self.budget < 0:
            raise _Refused("node budget exceeded")
        if depth > self.max_depth:
            raise _Refused("depth cap exceeded")

    @staticmethod
    def _enter(v: dict | list, ancestors: frozenset) -> frozenset:
        if id(v) in ancestors:
            raise _Refused("container reachable from itself")
        return ancestors | {id(v)}

    def walk(self, v: Any, depth: int, ancestors: frozenset) -> None:
        self._charge(depth)
        if isinstance(v, str):
            if "\x00" in v:
                raise _Refused("raw NUL in value")
        elif isinstance(v, dict):
            nxt = self._enter(v, ancestors)
            for k, item in v.items():
                _check_key(k)
                self.walk(item, depth + 1, nxt)
        elif isinstance(v, list):
            nxt = self._enter(v, ancestors)
            for item in v:
                self.walk(item, depth + 1, nxt)


def _prevalidate(value: Any, *, max_depth: int, max_nodes: int) -> None:
    """Raise `_Refused` before the encoder ever sees a hazardous payload. See `_Walker`."""
    _Walker(max_depth=max_depth, max_nodes=max_nodes).walk(value, 1, frozenset())


class _RealEncoder:
    """The production encoder, `toons`, imported lazily so a missing wheel degrades the gate to
    passthrough instead of breaking every agent build."""

    @staticmethod
    def dumps(value: Any) -> str:
        import toons
        return toons.dumps(value)

    @staticmethod
    def loads(text: str) -> Any:
        import toons
        return toons.loads(text)


_REAL_ENCODER = _RealEncoder()


def _wire_text(call_tool_name: str, tool_call_id: str, value: Any) -> str:
    """The text the model is charged for on a passthrough, via the same serializer
    (`ToolReturnPart.model_response_str`), so serialization errors match the ungated path."""
    return ToolReturnPart(
        tool_name=call_tool_name, content=value, tool_call_id=tool_call_id,
    ).model_response_str()


def _unwrap(result: Any) -> tuple[Any, dict | None, Any]:
    """Split a possibly `ToolReturn`-wrapped result into `(return_value, metadata, content)`.
    `content` is a separate model-facing channel (e.g. images) and must be preserved."""
    if isinstance(result, ToolReturn):
        return result.return_value, result.metadata, result.content
    return result, None, None


def _split_files(value: Any) -> tuple[Any, list[Any]]:
    """Split a foreign return into (data, multimodal files), mirroring pydantic-ai's own
    `BaseToolReturnPart._unwrap_data`.

    Without this, files in e.g. `[BinaryContent(...), {...}]` would be lost when the gate
    returns a framed `str`. The files go to `ToolReturn.content` instead, as pydantic-ai does
    for text-only tool-result APIs. A non-multimodal value is returned unchanged."""
    if is_multi_modal_content(value):
        return None, [value]
    if not isinstance(value, list) or not any(is_multi_modal_content(v) for v in value):
        return value, []
    files = [v for v in value if is_multi_modal_content(v)]
    data = [v for v in value if not is_multi_modal_content(v)]
    if not data:
        return None, files
    # Single-item unwrapping, matching `_unwrap_data`: with files extracted, a one-element
    # remainder is delivered as that element, not as a one-element list.
    return (data[0] if len(data) == 1 else data), files


def _merge_content(body_content: Any, files: list[Any]) -> Any:
    """Append the split-off file parts to the tool body's own `ToolReturn.content` channel."""
    if not files:
        return body_content
    if body_content is None:
        return list(files)
    if isinstance(body_content, str):
        return [body_content, *files]
    return [*body_content, *files]


def _framed_retry(part: Any) -> Any:
    """Frame the model-facing text of a foreign tool's `ModelRetry`, which otherwise reaches
    main's context verbatim.

    Only `str` content is framed; the list shape is pydantic's own argument-validation text.
    Other exceptions from a foreign body fail the run and are never shown to the model."""
    if not isinstance(part.content, str):
        return part
    return replace(part, content=_frame(part.content, "untrusted"))


def _merge_metadata(body_metadata: dict | None, original_value: Any) -> dict:
    """Merge `{GATE_METADATA_KEY: original}` into the body's metadata. On a key collision both
    values are kept, nested under the key."""
    merged = dict(body_metadata or {})
    if GATE_METADATA_KEY in merged:
        merged[GATE_METADATA_KEY] = {
            "gate_value": original_value, "collided_with": merged[GATE_METADATA_KEY],
        }
    else:
        merged[GATE_METADATA_KEY] = original_value
    return merged


@model
class _GateWrapperToolset(WrapperToolset[Any]):
    """Stamps every foreign tool's `ToolDefinition.metadata` with the candidate marker, since
    `wrap_tool_execute` sees only the `ToolDefinition`, not its toolset. Provenance is
    `ToolsetTool.toolset` compared by identity against the agent's native toolset."""

    #: Required: a `None` default would be re-passed, and refused by strict validation, on
    #: every `dataclasses.replace(self, ...)` that `WrapperToolset` performs.
    gate: ToonGateCapability

    async def get_tools(self, ctx):  # noqa: ANN001
        tools = await self.wrapped.get_tools(ctx)
        out = {}
        for name, tool in tools.items():
            if self.gate._is_owned(tool):
                out[name] = tool
                continue
            meta = {**(tool.tool_def.metadata or {}), _CANDIDATE_METADATA_KEY: True}
            out[name] = replace(tool, tool_def=replace(tool.tool_def, metadata=meta))
        return out


class ToonGateCapability(AbstractCapability[Any]):
    """The TOON view gate capability."""

    def __init__(self, *, encoder: Any = None) -> None:
        self._encoder = encoder if encoder is not None else _REAL_ENCODER
        #: Every native toolset ever bound: one gate instance can serve two builds (the
        #: `extra_capabilities` reuse path), and the first agent's tools must stay owned.
        self._native_toolsets: list[Any] = []
        self._examined = 0
        self._refused = 0
        self._substituted = 0
        self._bytes_saved = 0
        #: `wrap_tool_execute` returns a bare framed string so outer capabilities see an
        #: ordinary tool value; the body's `metadata`/`content` is reattached by call id in
        #: `after_tool_execute`, only if the value is still ours.
        #:
        #: Bounded (oldest evicted first): an outer capability may raise after this gate
        #: returned, so `after_tool_execute` never runs and the entry, which pins the original
        #: payload, would otherwise leak.
        self._pending: dict[str, tuple[str, dict | None, Any]] = {}

    def bind_native_toolset(self, toolset: Any) -> None:
        """Bind the agent's native function toolset right after `Agent(...)` construction;
        every later `agent.tool` registration adds to that same object."""
        if not any(t is toolset for t in self._native_toolsets):
            self._native_toolsets.append(toolset)

    def snapshot(self) -> dict:
        return {
            "examined": self._examined, "refused": self._refused,
            "substituted": self._substituted, "bytes_saved": self._bytes_saved,
        }

    def _is_owned(self, tool: Any) -> bool:
        if any(tool.toolset is native for native in self._native_toolsets):
            return True
        meta = tool.tool_def.metadata or {}
        return meta.get(_OWNED_METADATA_KEY) is _OWNED_SENTINEL

    def get_wrapper_toolset(self, toolset: Any) -> Any:
        return _GateWrapperToolset(wrapped=toolset, gate=self)

    async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler, **_):  # noqa: ANN001, ANN003
        meta = tool_def.metadata or {}
        if not meta.get(_CANDIDATE_METADATA_KEY):
            return await handler(args)
        try:
            result = await handler(args)
        except ToolRetryError as e:
            # The error exit is model-facing too.
            raise ToolRetryError(_framed_retry(e.tool_retry)) from e
        except ModelRetry as e:
            # The raw shape, reached when the caller asked for unwrapped errors
            # (`wrap_validation_errors=False` — the sandboxed-dispatch path).
            raise ModelRetry(_frame(e.message, "untrusted")) from e
        text, metadata, content = self._gate(call.tool_name, call.tool_call_id, result)
        if metadata is not None or content is not None:
            while len(self._pending) >= _MAX_PENDING:
                self._pending.pop(next(iter(self._pending)))
            self._pending[call.tool_call_id] = (text, metadata, content)
        return text

    async def after_tool_execute(self, ctx, *, call, tool_def, args, result, **_):  # noqa: ANN001, ANN003
        pending = self._pending.pop(call.tool_call_id, None)
        if pending is None:
            return result
        text, metadata, content = pending
        if result != text:
            # An outer capability replaced our output; respect that and drop the metadata.
            return result
        return ToolReturn(return_value=result, metadata=metadata, content=content)

    def _gate(
        self, tool_name: str, tool_call_id: str, result: Any,
    ) -> tuple[str, dict | None, Any]:
        body_value, body_metadata, body_content = _unwrap(result)
        body_value, files = _split_files(body_value)
        body_content = _merge_content(body_content, files)
        args = (tool_name, tool_call_id, body_value, body_metadata, body_content)

        if not isinstance(body_value, (dict, list)):
            return self._passthrough(*args)

        max_depth = env_int(MAX_DEPTH_ENV, DEFAULT_MAX_DEPTH)
        max_nodes = env_int(MAX_NODES_ENV, DEFAULT_MAX_NODES)
        try:
            _prevalidate(body_value, max_depth=max_depth, max_nodes=max_nodes)
        except (_Refused, RecursionError):
            # The walk is recursive Python; hitting the interpreter's limit means the same
            # "too deep to inspect" as the depth cap.
            self._refused += 1
            return self._passthrough(*args)

        try:
            toon_view = self._encoder.dumps(body_value)
        except _REPROPAGATE:
            raise
        except BaseException:  # noqa: BLE001 — the encoder's own panic is a BaseException
            return self._passthrough(*args)

        if not isinstance(toon_view, str) or not toon_view:
            # Non-`str` would fail the unguarded code below; empty (e.g. from `{}`) would
            # substitute nothing for a real value.
            return self._passthrough(*args)

        # Outside the guard: an unserializable payload must raise exactly as it would ungated.
        wire_text_value = _wire_text(tool_name, tool_call_id, body_value)
        wire_bytes_value = len(wire_text_value.encode("utf-8"))
        toon_bytes_value = len(toon_view.encode("utf-8"))
        bar = env_int(MAX_PERCENT_ENV, DEFAULT_MAX_PERCENT)
        clears = (
            100 * (toon_bytes_value + _FRAME_OVERHEAD)
            <= bar * (wire_bytes_value + _FRAME_OVERHEAD)
        )
        if not clears:
            return self._passthrough(*args, wire_text_value=wire_text_value)

        try:
            recovered = self._encoder.loads(toon_view)
            recovered_wire = _wire_text(tool_name, tool_call_id, recovered)
        except _REPROPAGATE:
            raise
        except BaseException:  # noqa: BLE001 — the decoder's own fault is a BaseException too
            return self._passthrough(*args, wire_text_value=wire_text_value)

        if recovered_wire != wire_text_value:
            return self._passthrough(*args, wire_text_value=wire_text_value)

        self._examined += 1
        self._substituted += 1
        self._bytes_saved += max(0, wire_bytes_value - toon_bytes_value)
        framed = _frame(toon_view, "untrusted")
        return framed, _merge_metadata(body_metadata, body_value), body_content

    def _passthrough(  # noqa: PLR0913 — the gate's own call shape, threaded whole
        self, tool_name: str, tool_call_id: str, body_value: Any,
        body_metadata: dict | None, body_content: Any = None, *,
        wire_text_value: str | None = None,
    ) -> tuple[str, dict | None, Any]:
        self._examined += 1
        text = (
            wire_text_value if wire_text_value is not None
            else _wire_text(tool_name, tool_call_id, body_value)
        )
        framed = _frame(text, "untrusted")
        metadata = dict(body_metadata) if body_metadata else None
        return framed, metadata, body_content


# `_GateWrapperToolset.gate` forward-references `ToonGateCapability`, so the pydantic dataclass
# is incomplete at decoration; rebuild it now that both classes exist. The cast is typing-only:
# mypy doesn't see `@model`'s return as a `PydanticDataclass`.
_pydantic_dataclasses.rebuild_dataclass(cast("type[Any]", _GateWrapperToolset))
