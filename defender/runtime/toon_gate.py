"""#872 — the TOON view gate: a provenance-gated, cost-bounded substitution of a foreign
tool's dict/list result with a smaller TOON view, framed like every other untrusted span.

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
from pydantic_ai.messages import ToolReturn, ToolReturnPart
from pydantic_ai.toolsets import SetMetadataToolset, WrapperToolset

from defender._env import env_int
from defender._untrusted import wrap as _frame
from defender.hooks.budget_enforcer import BudgetKill

#: §7 r1's spelling — the reserved metadata key the original JSON rides on. Not the gate's
#: to change: `test_substitute_branch_return_shape` pins the literal string.
GATE_METADATA_KEY = "json"

_OWNED_METADATA_KEY = "_defender_toon_gate_owned"
_CANDIDATE_METADATA_KEY = "_defender_toon_gate_candidate"

MAX_DEPTH_ENV = "DEFENDER_TOON_GATE_MAX_DEPTH"
MAX_NODES_ENV = "DEFENDER_TOON_GATE_MAX_NODES"
MAX_PERCENT_ENV = "DEFENDER_TOON_GATE_MAX_PERCENT"

#: §7 r6's operator judgment — an ordinary run never approaches either ceiling; both exist to
#: bound a hostile or merely huge payload's cost before the encoder ever sees it.
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_NODES = 100_000
#: The value the corpus measurements were taken at. Not a contract — an operator default.
DEFAULT_MAX_PERCENT = 85

#: The control-flow set that must never be swallowed by the encoder/decoder guard — the same
#: shape `query_tool._decide_guarded` already uses, widened by `SystemExit` (`d56`).
_REPROPAGATE: tuple[type[BaseException], ...] = (
    BudgetKill, KeyboardInterrupt, GeneratorExit, SystemExit, asyncio.CancelledError,
)


def mark_owned(toolset: Any) -> Any:
    """Label a toolset as defender's own at the installation site (§7 r2, P1 = B).

    The gate's default is FOREIGN — an unlabelled toolset supplied at the `toolset=` seam is
    gated. This is the one way to opt a specific toolset instance out, for the composition
    root's own use (never a model-facing switch: nothing in the tree exposes it to a tool
    body). Implemented as toolset-wide metadata rather than a subclass check so it survives
    wrapping and combination like any other toolset metadata."""
    return SetMetadataToolset(toolset, {_OWNED_METADATA_KEY: True})


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
    """M7's recursive walk, as a small stateful object rather than a nested closure — split
    out from `_prevalidate` because a nested-closure version of the same logic reads as MORE
    complex to a cyclomatic-complexity linter than the identical logic split across methods.

    Over `dict`/`list` (subclasses included — the encoder's own traversal set, `d51`):
      - charges the node budget for EVERY value visited, containers and scalars alike, and
        bails the instant it is exhausted — bounding the walk's own cost on a payload whose
        containers alone would take it exponential (`S7`);
      - refuses one level over the configured depth cap, catching a payload that is deep but
        acyclic (`S3`) — a case a cycle check alone does not see;
      - refuses a container reachable from ITSELF on the CURRENT path (path-scoped, not a
        global seen-set — `d49`'s own anti-vacuity control is ordinary shared structure,
        which must still be admitted);
      - refuses any string, key or value, carrying a raw NUL (`d64`).
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
    """M7: raise `_Refused` before the encoder ever sees a hazardous payload. See `_Walker`."""
    _Walker(max_depth=max_depth, max_nodes=max_nodes).walk(value, 1, frozenset())


class _RealEncoder:
    """The production encoder: `toons`, imported lazily at the CALL site (`d75`).

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


def _unwrap(result: Any) -> tuple[Any, dict | None]:
    """A tool body may pre-wrap its own return in a `ToolReturn` (§7's `cN7`/`cN8`). The gate
    operates on `return_value` and preserves the body's own `metadata` alongside its own."""
    if isinstance(result, ToolReturn):
        return result.return_value, result.metadata
    return result, None


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
        self._native_toolset: Any = None
        self._examined = 0
        self._refused = 0
        self._substituted = 0
        self._bytes_saved = 0
        #: `wrap_tool_execute` returns a bare framed STRING — never a `ToolReturn` — so that
        #: an OUTER capability's own `handler(args)` sees exactly the tool's-own-shaped value
        #: it would see from any other wrapper (`d69`'s discriminator:
        #: `test_call_tool_receives_the_tools_own_return_with_a_capture_shaped_capability_installed`).
        #: Metadata is attached one hook later, in `after_tool_execute`, which runs on the
        #: value AFTER the whole wrap chain has resolved — keyed by call id, and applied only
        #: when that value is STILL what this call produced (`is`), i.e. nothing further out
        #: in the chain (like a capture-shaped capability) has already replaced it.
        self._pending: dict[str, tuple[str, dict | None]] = {}

    def bind_native_toolset(self, toolset: Any) -> None:
        """Bound once, right after `Agent(...)` construction — the identity every later
        `agent.tool`/`agent.tool_plain` registration (MAIN's own tools, the close tool, the
        gather tool, the query tool) shares, since they all add to the SAME object."""
        self._native_toolset = toolset

    def snapshot(self) -> dict:
        return {
            "examined": self._examined, "refused": self._refused,
            "substituted": self._substituted, "bytes_saved": self._bytes_saved,
        }

    def _is_owned(self, tool: Any) -> bool:
        if self._native_toolset is not None and tool.toolset is self._native_toolset:
            return True
        meta = tool.tool_def.metadata or {}
        return bool(meta.get(_OWNED_METADATA_KEY))

    def get_wrapper_toolset(self, toolset: Any) -> Any:
        return _GateWrapperToolset(wrapped=toolset, gate=self)

    async def wrap_tool_execute(self, ctx, *, call, tool_def, args, handler, **_):  # noqa: ANN001, ANN003
        meta = tool_def.metadata or {}
        if not meta.get(_CANDIDATE_METADATA_KEY):
            return await handler(args)
        result = await handler(args)
        text, metadata = self._gate(ctx, call.tool_name, call.tool_call_id, result)
        if metadata is not None:
            self._pending[call.tool_call_id] = (text, metadata)
        return text

    async def after_tool_execute(self, ctx, *, call, tool_def, args, result):  # noqa: ANN001, ANN003
        pending = self._pending.pop(call.tool_call_id, None)
        if pending is None:
            return result
        text, metadata = pending
        if result != text:
            # Something further OUT in the wrap chain already replaced our own output (a
            # capture-shaped capability, say) — respect that override. The metadata is
            # legitimately lost with it, the same way it is for `query` today (`d69`).
            return result
        return ToolReturn(return_value=result, metadata=metadata)

    def _gate(self, ctx, tool_name: str, tool_call_id: str, result: Any) -> tuple[str, dict | None]:
        body_value, body_metadata = _unwrap(result)

        if not isinstance(body_value, (dict, list)):
            return self._passthrough(ctx, tool_name, tool_call_id, body_value, body_metadata)

        max_depth = env_int(MAX_DEPTH_ENV, DEFAULT_MAX_DEPTH)
        max_nodes = env_int(MAX_NODES_ENV, DEFAULT_MAX_NODES)
        try:
            _prevalidate(body_value, max_depth=max_depth, max_nodes=max_nodes)
        except _Refused:
            self._refused += 1
            return self._passthrough(ctx, tool_name, tool_call_id, body_value, body_metadata)

        try:
            toon_view = self._encoder.dumps(body_value)
        except _REPROPAGATE:
            raise
        except BaseException:  # noqa: BLE001 — the encoder's own panic is a BaseException
            return self._passthrough(ctx, tool_name, tool_call_id, body_value, body_metadata)

        if not toon_view:
            # The empty-view floor (`d18`): an empty dict encodes to zero bytes and would
            # otherwise clear any bar and round-trip, substituting NOTHING where the JSON
            # said `{}`.
            return self._passthrough(ctx, tool_name, tool_call_id, body_value, body_metadata)

        # Computed OUTSIDE the guard above: a payload the pre-validator admits but the wire
        # serializer cannot represent (an arbitrary object as a value) must raise exactly as
        # the un-gated run does (`d47`) — the gate does no worse, never better.
        wire_text_value = _wire_text(tool_name, tool_call_id, body_value)
        wire_bytes_value = len(wire_text_value.encode("utf-8"))
        toon_bytes_value = len(toon_view.encode("utf-8"))
        overhead = len(_frame("", "untrusted", ctx.deps.salt))
        bar = env_int(MAX_PERCENT_ENV, DEFAULT_MAX_PERCENT)
        clears = 100 * (toon_bytes_value + overhead) <= bar * (wire_bytes_value + overhead)
        if not clears:
            return self._passthrough(
                ctx, tool_name, tool_call_id, body_value, body_metadata,
                wire_text_value=wire_text_value,
            )

        try:
            recovered = self._encoder.loads(toon_view)
            recovered_wire = _wire_text(tool_name, tool_call_id, recovered)
        except _REPROPAGATE:
            raise
        except BaseException:  # noqa: BLE001 — the decoder's own fault is a BaseException too
            return self._passthrough(
                ctx, tool_name, tool_call_id, body_value, body_metadata,
                wire_text_value=wire_text_value,
            )

        if recovered_wire != wire_text_value:
            return self._passthrough(
                ctx, tool_name, tool_call_id, body_value, body_metadata,
                wire_text_value=wire_text_value,
            )

        self._examined += 1
        self._substituted += 1
        self._bytes_saved += max(0, wire_bytes_value - toon_bytes_value)
        framed = _frame(toon_view, "untrusted", ctx.deps.salt)
        return framed, _merge_metadata(body_metadata, body_value)

    def _passthrough(
        self, ctx, tool_name: str, tool_call_id: str, body_value: Any,
        body_metadata: dict | None, *, wire_text_value: str | None = None,
    ) -> tuple[str, dict | None]:
        self._examined += 1
        text = (
            wire_text_value if wire_text_value is not None
            else _wire_text(tool_name, tool_call_id, body_value)
        )
        framed = _frame(text, "untrusted", ctx.deps.salt)
        metadata = dict(body_metadata) if body_metadata else None
        return framed, metadata
