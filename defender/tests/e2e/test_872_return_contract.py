"""#872 — the return contract at the seam: what each branch hands the model."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

toons = pytest.importorskip("toons")  # noqa: E402

from pydantic_ai.messages import ToolReturn  # noqa: E402
from pydantic_ai.toolsets import FunctionToolset  # noqa: E402

from defender.investigation.toon_gate import GATE_METADATA_KEY  # noqa: E402
from defender.tests.e2e._toon872 import (  # noqa: E402
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
        "the substitution fixture no longer clears the delivered-bytes bar"
    )
    return value


def test_substitute_branch_return_shape() -> None:
    """The substitute branch returns `ToolReturn(return_value=<framed TOON>,
    metadata={"json": <the tool's own return>})`."""
    value = _under_bar()
    out = agent_run(toolset=foreign_toolset(value))
    part = out.dispatched.part("fetch_rows")

    assert GATE_METADATA_KEY == "json", "the gate's metadata key is no longer `json`"
    assert framed_content(part.content) == toons.dumps(value), (
        "the model was handed something other than the framed TOON view"
    )
    assert isinstance(part.metadata, dict)
    assert GATE_METADATA_KEY in part.metadata
    assert part.metadata[GATE_METADATA_KEY] == value


def test_the_byte_gate_and_the_stringify_step_measure_the_bytes_the_model_receives() -> None:
    for value in ({"x": float("nan")}, {"x": b"ab"}, [], {"x": float("-inf")}):
        out = agent_run(toolset=foreign_toolset(value))
        assert framed_content(out.dispatched.text()) == wire_text(value), (
            f"the gate measured {value!r} with the wrong serializer"
        )

    oracle = {"rows": [{"a": float("nan"), "b": i} for i in range(40)]}
    assert wire_roundtrip_equal(oracle), (
        "the wire serializer no longer renders both sides of this round trip identically"
    )
    assert delivered_percent(oracle) <= 85, (
        "the oracle fixture no longer clears the delivered-bytes bar"
    )
    out = agent_run(toolset=foreign_toolset(oracle))
    assert framed_content(out.dispatched.text()) == toons.dumps(oracle), (
        "a payload the round-trip oracle accepts under the wire serializer passed through"
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
    assert part.metadata[GATE_METADATA_KEY] == value

    collide = FunctionToolset()

    def fetch_rows_collide() -> ToolReturn:
        return ToolReturn(return_value=value, metadata={GATE_METADATA_KEY: "the body's own"})

    fetch_rows_collide.__name__ = "fetch_rows"
    collide.tool_plain(fetch_rows_collide)
    hit = agent_run(toolset=collide).dispatched.part("fetch_rows")
    reachable = _flatten(hit.metadata)
    assert "the body's own" in reachable, "the gate overwrote the body's value on the reserved key"
    assert value in reachable, "the body overwrote the gate's original JSON on the reserved key"


def _flatten(meta: dict) -> list:
    """Every value reachable in a metadata mapping, so the test fixes no merge order."""
    out: list = []
    for v in meta.values():
        out.append(v)
        if isinstance(v, dict):
            out.extend(_flatten(v))
    return out
