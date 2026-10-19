"""#872 — the return contract at the seam (`d0`, `d0b`, `d16`, `d61`, `d71`, `d72`)."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

toons = pytest.importorskip("toons")  # noqa: E402

from pydantic_ai.messages import ToolReturn  # noqa: E402
from pydantic_ai.toolsets import FunctionToolset  # noqa: E402

from defender.tests.e2e._toon872 import (  # noqa: E402
    gate_metadata_key,
    agent_run,
    corpus,
    delivered_percent,
    foreign_toolset,
    framed_content,
    toon_rows,
    wire_roundtrip_equal,
    wire_text,
)

pytestmark = pytest.mark.e2e

FIXTURE = "fx-33"


def _under_bar() -> dict:
    value = toon_rows(corpus()[FIXTURE])
    assert delivered_percent(value) < 80.0, (
        "the substitution fixture no longer clears the shipped DELIVERED-bytes bar (`d3`)"
    )
    return value


def _over_bar() -> dict:
    value = corpus()[FIXTURE]
    assert delivered_percent(value) > 95.0, (
        "the passthrough fixture no longer fails the shipped DELIVERED-bytes bar (`d3`)"
    )
    return value


def test_passthrough_carries_the_tools_own_json_unchanged_inside_the_frame() -> None:
    for value in (_over_bar(), "a plain string", 7, None):
        out = agent_run(toolset=foreign_toolset(value))
        delivered = out.dispatched.text()
        assert framed_content(delivered) == wire_text(value), (
            f"passthrough content diverged from the no-gate wire bytes for {type(value).__name__}"
        )
        assert out.encoder.loads_calls == 0, "a passthrough decoded a view it did not deliver"


def test_substitute_branch_return_shape() -> None:
    """The substitute branch returns `ToolReturn(return_value=<framed TOON>,
    metadata={"json": <the tool's own return>})` — §7 r1's decision, spelled."""
    value = _under_bar()
    out = agent_run(toolset=foreign_toolset(value))
    part = out.dispatched.part("fetch_rows")

    assert gate_metadata_key() == "json", "§7 r1 spelled the metadata key; it is not the gate's to pick"
    assert framed_content(part.content) == toons.dumps(value), (
        "the model was handed something other than the framed TOON view"
    )
    assert isinstance(part.metadata, dict)
    assert gate_metadata_key() in part.metadata
    assert part.metadata[gate_metadata_key()] == value


def test_the_byte_gate_and_the_stringify_step_measure_the_bytes_the_model_receives() -> None:
    for value in ({"x": float("nan")}, {"x": b"ab"}, [], {"x": float("-inf")}):
        out = agent_run(toolset=foreign_toolset(value))
        assert framed_content(out.dispatched.text()) == wire_text(value), (
            f"the gate measured {value!r} with the wrong serializer"
        )

    oracle = {"rows": [{"a": float("nan"), "b": i} for i in range(40)]}
    assert wire_roundtrip_equal(oracle), (
        "the wire serializer no longer renders both sides of this round trip identically, so "
        "the two oracles no longer disagree here and this arm has stopped discriminating"
    )
    assert delivered_percent(oracle) <= 85, (
        "the oracle fixture no longer clears the delivered-bytes bar, so the byte gate would "
        "decide it and M3 would never be consulted"
    )
    out = agent_run(toolset=foreign_toolset(oracle))
    assert framed_content(out.dispatched.text()) == toons.dumps(oracle), (
        "a payload M3's oracle blesses under the WIRE serializer passed through — the oracle "
        "is spelled with `pydantic_core.to_json`, the site `d71` left unruled"
    )


def test_a_tool_body_that_returns_its_own_toolreturn_is_unwrapped_framed_and_loses_nothing() -> None:
    value = {"rows": [{"a": i, "b": f"row-{i}"} for i in range(40)]}
    ts = FunctionToolset()

    def fetch_rows() -> ToolReturn:
        return ToolReturn(return_value=value, metadata={"body_private": "kept"})

    ts.tool_plain(fetch_rows)
    part = agent_run(toolset=ts).dispatched.part("fetch_rows")

    assert isinstance(part.content, str), "the ToolReturn dataclass reached the model"
    assert "body_private" not in part.content, "the tool body's private metadata leaked to the model"
    assert "tool-return" not in part.content
    assert "return_value" not in part.content
    assert framed_content(part.content) == toons.dumps(value), (
        "a pre-wrapped ToolReturn opted out of the gate"
    )
    assert part.metadata["body_private"] == "kept", "the gate destroyed application data"
    assert part.metadata[gate_metadata_key()] == value

    collide = FunctionToolset()

    def fetch_rows_collide() -> ToolReturn:
        return ToolReturn(return_value=value, metadata={gate_metadata_key(): "the body's own"})

    fetch_rows_collide.__name__ = "fetch_rows"
    collide.tool_plain(fetch_rows_collide)
    hit = agent_run(toolset=collide).dispatched.part("fetch_rows")
    reachable = _flatten(hit.metadata)
    assert "the body's own" in reachable, "the gate overwrote the body's value on the reserved key"
    assert value in reachable, "the body overwrote the gate's original JSON on the reserved key"


def _flatten(meta: dict) -> list:
    """Every value reachable in a metadata mapping — the shape assertion, so neither merge
    order can be spelled into the test as the expected one."""
    out: list = []
    for v in meta.values():
        out.append(v)
        if isinstance(v, dict):
            out.extend(_flatten(v))
    return out
