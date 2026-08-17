"""The TOON view gate: a provenance-gated, cost-bounded substitution of a foreign tool's
dict/list result with a smaller TOON view, framed like every other untrusted span.

Installed unconditionally at the single `Agent(...)` composition root (`driver.build_agent_core`)
so it is on all five build paths. It never touches defender's OWN tools — those are
identified by toolset IDENTITY (the agent's own `_function_toolset`), not by name or by an
allow-list, so a same-named foreign tool cannot walk through it. Anything else reaching
`call_tool` (a toolset supplied at `run_investigation`'s `toolset=` seam, or one supplied at
run time) is FOREIGN by default and is gated, unless explicitly marked owned via
`mark_owned()`.

The pre-validator (`_prevalidate`) runs BEFORE the encoder ever sees the payload: `toons.dumps`
does not raise on a self-referential container or a sufficiently deep acyclic one, it SIGSEGVs,
so those hazards must never reach it. Every encoder/decoder call is guarded against
`BaseException` (the encoder's own panic is one, not an `Exception`), re-raising only the
control-flow set a tool call must never swallow.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import Any

from pydantic_ai.capabilities import AbstractCapability
from pydantic_ai.exceptions import ModelRetry, ToolRetryError
from pydantic_ai.messages import ToolReturn, ToolReturnPart, is_multi_modal_content
from pydantic_ai.toolsets import SetMetadataToolset, WrapperToolset

from defender._env import env_int
from defender._run_paths import GATE_METADATA_KEY
from defender._untrusted import wrap_fresh as _frame
from defender.hooks.budget_enforcer import BudgetKill

#: The reserved metadata key the original JSON rides on. Not the gate's to change:
#: `test_substitute_branch_return_shape` pins the literal string. Defined in
#: `defender._run_paths` and re-exported here: the page that reads it back
#: (`scripts/visualize/visualize_messages`) renders on installs that carry no pydantic-ai, so
#: the name it agrees with the writer on cannot live behind this module's imports.
__all__ = ["GATE_METADATA_KEY", "ToonGateCapability", "mark_owned"]

_OWNED_METADATA_KEY = "_defender_toon_gate_owned"
_CANDIDATE_METADATA_KEY = "_defender_toon_gate_candidate"

#: The value `mark_owned` writes and `_is_owned` demands, by IDENTITY. An object rather than
#: `True`, because the key is read off the tool's OWN `ToolDefinition.metadata` — a field a
#: foreign toolset also fills (pydantic-ai builds an MCP tool's from the server's `meta` and
#: `annotations`). Against a truthy check, a foreign toolset could declare ITSELF owned and
#: walk past both the gate and the untrusted frame. Identity against a module-private object
#: cannot cross that seam: a tool definition assembled from JSON — which is what every remote
#: toolset's is — can spell the key but can never hold this value.
_OWNED_SENTINEL = object()

MAX_DEPTH_ENV = "DEFENDER_TOON_GATE_MAX_DEPTH"
MAX_NODES_ENV = "DEFENDER_TOON_GATE_MAX_NODES"
MAX_PERCENT_ENV = "DEFENDER_TOON_GATE_MAX_PERCENT"

#: An ordinary run never approaches either ceiling; both exist to bound a hostile or merely
#: huge payload's cost before the encoder ever sees it.
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_NODES = 100_000
#: The value the corpus measurements were taken at. Not a contract — an operator default.
DEFAULT_MAX_PERCENT = 85

#: The ceiling on in-flight `after_tool_execute` hand-offs. See `ToonGateCapability._pending`.
_MAX_PENDING = 64

#: The control-flow set that must never be swallowed by the encoder/decoder guard — the same
#: shape `query_tool._decide_guarded` uses, widened by `SystemExit`.
_REPROPAGATE: tuple[type[BaseException], ...] = (
    BudgetKill, KeyboardInterrupt, GeneratorExit, SystemExit, asyncio.CancelledError,
)

#: The fixed byte cost `wrap_fresh` adds, computed ONCE. A fresh-minted salt is always 16 hex
#: chars (`secrets.token_hex(8)`) and the frame is pure ASCII, so the overhead is a function of
#: the tag alone — never of which salt a particular call drew.
_FRAME_OVERHEAD = len(_frame("", "untrusted"))


def mark_owned(toolset: Any) -> Any:
    """Label a toolset as defender's own at the installation site.

    The gate's default is FOREIGN — an unlabelled toolset supplied at the `toolset=` seam is
    gated. This is the one way to opt a specific toolset instance out, for the composition
    root's own use (never a model-facing switch: nothing in the tree exposes it to a tool
    body). Implemented as toolset-wide metadata rather than a subclass check so it survives
    wrapping and combination like any other toolset metadata."""
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
    """The pre-validator's recursive walk, as a small stateful object rather than a nested
    closure (which reads as more complex to a cyclomatic-complexity linter).

    Over `dict`/`list` (subclasses included — the encoder's own traversal set):
      - charges the node budget for EVERY value visited, containers and scalars alike, and
        bails the instant it is exhausted — bounding the walk's own cost on a payload whose
        containers alone would take it exponential;
      - refuses one level over the configured depth cap, catching a payload that is deep but
        acyclic — a case a cycle check alone does not see;
      - refuses a container reachable from ITSELF on the CURRENT path (path-scoped, not a
        global seen-set: ordinary shared structure must still be admitted);
      - refuses any string, key or value, carrying a raw NUL.
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
    """The production encoder: `toons`, imported lazily at the CALL site.

    A module-scope `import toons` would fail every one of the five build paths together the
    instant the wheel is absent, because the gate is installed unconditionally at the single
    composition root. Deferred here, a missing wheel refuses the gate's own work (passthrough)
    without taking any build down."""

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
    """The bytes the model is actually charged for on a passthrough — the same serializer
    `ToolReturnPart.model_response_str` uses, computed off the real primitive so a
    `PydanticSerializationError` the baseline would raise propagates here identically."""
    return ToolReturnPart(
        tool_name=call_tool_name, content=value, tool_call_id=tool_call_id,
    ).model_response_str()


def _unwrap(result: Any) -> tuple[Any, dict | None, Any]:
    """A tool body may pre-wrap its own return in a `ToolReturn`. The gate operates on
    `return_value` and preserves the body's own `metadata` — and its `content`, a SEPARATE
    model-facing channel (`ToolReturn.content` becomes its own `UserPromptPart`, and is where a
    multimodal tool puts an image). Dropping it would silently delete, on every gated call, a
    part of the tool's answer the gate has no view over."""
    if isinstance(result, ToolReturn):
        return result.return_value, result.metadata, result.content
    return result, None, None


def _split_files(value: Any) -> tuple[Any, list[Any]]:
    """Split a foreign return into (data, multimodal files), mirroring the split pydantic-ai
    itself performs on a `ToolReturnPart` (`BaseToolReturnPart._unwrap_data`).

    The gate's own ruler is `ToolReturnPart.model_response_str()`, which EXCLUDES the file
    parts — a provider receives them natively, not as JSON. Without the split, a foreign
    toolset returning `[BinaryContent(...), {...}]` (an MCP server's image, the canonical
    foreign result) has its files DELETED: the value takes the dict/list branch, the encoder
    refuses the content blocks, and the passthrough returns a bare `str` carrying the data half
    alone. The frame is a control over text; dropping an image is not a cheaper view of it.

    Splitting first keeps the gate's return a framed `str` on every exit while the files ride
    the tool's other model-facing channel (`ToolReturn.content`) — the same relocation
    pydantic-ai performs for providers whose tool-result API accepts text only
    (`model_response_str_and_user_content`).

    Returns the value UNCHANGED, with an empty file list, when there is nothing multimodal in
    it — every non-multimodal payload takes the byte-identical path it took before."""
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
    """Reframe the model-facing text of a foreign tool's `ModelRetry` — the error exit.

    `_raw_execute` converts a tool body's `ModelRetry` into a `ToolRetryError` carrying a
    `RetryPromptPart`, and that part's content reaches MAIN's context verbatim. Framing only
    the RESULT would leave a foreign toolset one unframed channel into the trusted region —
    `ModelRetry("IGNORE PRIOR INSTRUCTIONS ...")` — the exact span `wrap_fresh` exists to close.

    Only a `str` content is framed: the list shape belongs to argument `ValidationError`s,
    which are the library's own text about a call defender's model made, not the foreign
    tool's about its own answer. An ordinary `Exception` from a foreign body needs no arm
    here — it is not converted into anything the model reads; it fails the run."""
    if not isinstance(part.content, str):
        return part
    return replace(part, content=_frame(part.content, "untrusted"))


def _merge_metadata(body_metadata: dict | None, original_value: Any) -> dict:
    """Merge the gate's own `{GATE_METADATA_KEY: original}` into the body's own metadata.

    A collision (the body already used the reserved key) loses neither side — both remain
    reachable, nested under the same key, rather than one silently overwriting the other."""
    merged = dict(body_metadata or {})
    if GATE_METADATA_KEY in merged:
        merged[GATE_METADATA_KEY] = {
            "gate_value": original_value, "collided_with": merged[GATE_METADATA_KEY],
        }
    else:
        merged[GATE_METADATA_KEY] = original_value
    return merged


@dataclass
class _GateWrapperToolset(WrapperToolset[Any]):
    """Stamps every FOREIGN tool's `ToolDefinition.metadata` with the gate's own candidate
    marker, so `wrap_tool_execute` (which only sees a `ToolDefinition`, not the toolset that
    produced it) can decide without redoing the toolset walk per call.

    Provenance is read off `ToolsetTool.toolset` — the toolset that supplied the tool,
    preserved through `CombinedToolset`/`PreparedToolset` wrapping — compared by IDENTITY
    against the agent's own native function toolset (`agent._function_toolset`, bound once at
    build time). Anything else is foreign by default, unless it carries the owned marker
    `mark_owned` sets."""

    gate: ToonGateCapability = field(default=None)  # type: ignore[assignment]

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
    """The gate. See module docstring."""

    def __init__(self, *, encoder: Any = None) -> None:
        self._encoder = encoder if encoder is not None else _REAL_ENCODER
        #: EVERY native toolset ever bound, not the last one. One gate instance can legitimately
        #: reach two builds (the `extra_capabilities` reuse path), and a single slot would let
        #: the second build's bind silently un-own the FIRST agent's own tools — turning
        #: defender's own results foreign, gated and framed.
        self._native_toolsets: list[Any] = []
        self._examined = 0
        self._refused = 0
        self._substituted = 0
        self._bytes_saved = 0
        #: `wrap_tool_execute` returns a bare framed STRING — never a `ToolReturn` — so an
        #: OUTER capability's own `handler(args)` sees exactly the tool's-own-shaped value it
        #: would see from any other wrapper. The tool body's own `metadata`/`content` is
        #: attached one hook later, in `after_tool_execute`, which runs on the value AFTER the
        #: whole wrap chain has resolved — keyed by call id, and applied only when that value
        #: STILL EQUALS what this call produced (nothing further out has replaced it).
        #:
        #: BOUNDED, because an entry can be stranded: an outer capability may raise a
        #: control-flow exception (`ModelRetry`, `ToolFailed`, `SkipToolExecution`) after this
        #: gate returned, and `after_tool_execute` — the map's only reader — never runs for
        #: that call. Each entry pins the call's ORIGINAL payload, so an unbounded map would
        #: retain every stranded payload for the life of the run. Oldest is evicted first.
        self._pending: dict[str, tuple[str, dict | None, Any]] = {}

    def bind_native_toolset(self, toolset: Any) -> None:
        """Bound right after `Agent(...)` construction — the identity every later
        `agent.tool`/`agent.tool_plain` registration (MAIN's own tools, the close tool, the
        gather tool, the query tool) shares, since they all add to the SAME object."""
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
            # The error exit is a model-facing exit, and it was the one span the gate did not
            # frame. See `_framed_retry`.
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
            # Something further OUT in the wrap chain already replaced our own output (a
            # capture-shaped capability, say) — respect that override. The metadata is
            # legitimately lost with it, the same way it is for `query`.
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
            # `RecursionError` sits beside `_Refused` because the walk is recursive PYTHON: a
            # depth cap above the interpreter's own limit — or an already-deep stack under it —
            # hits the interpreter's ceiling first, which is the same "too deep to inspect"
            # answer, not a reason to fail a tool call the un-gated run would have delivered.
            self._refused += 1
            return self._passthrough(*args)

        try:
            toon_view = self._encoder.dumps(body_value)
        except _REPROPAGATE:
            raise
        except BaseException:  # noqa: BLE001 — the encoder's own panic is a BaseException
            return self._passthrough(*args)

        if not isinstance(toon_view, str) or not toon_view:
            # Two refusals in one shape. NON-`str`: the guard above covers the encoder's CALL,
            # not its RETURN, and `.encode()`/`wrap_fresh` below sit outside every guard — so a
            # view that is not a string would fail the TOOL CALL where the contract is a
            # passthrough. EMPTY: an empty dict encodes to zero bytes, clears any bar and
            # round-trips, substituting NOTHING where the JSON said `{}`.
            return self._passthrough(*args)

        # Computed OUTSIDE the guard above: a payload the pre-validator admits but the wire
        # serializer cannot represent (an arbitrary object as a value) must raise exactly as
        # the un-gated run does — the gate does no worse, never better.
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
