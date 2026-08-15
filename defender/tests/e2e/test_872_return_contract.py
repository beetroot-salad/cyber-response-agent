"""#872 — the return contract at the seam (`d0`, `d0b`, `d16`, `d61`, `d71`, `d72`).

What the wrapper hands back, and what the model consequently reads. Every oracle here is the
`ToolReturnPart` the model received, read off the dispatched request messages (§7 r8), never
the wrapper's own return value — except the two demands that ARE about the return object.

The re-reading §7 r3 (f2 = B) forced is what most of this module is about: `result is
original` is VOID, and O2's byte-identity is now "the JSON content is unchanged INSIDE the
frame". A test still asserting `is` would pin a contract §7 rejected.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

import toons  # noqa: E402

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

#: `fx-33`'s two arms. The dict-row arm is 37.6% of the wire JSON and the columnar arm is
#: 101.3% — TOON larger — so one fixture supplies both a substitution and a passthrough
#: without any test naming a bar. Re-derived at call time, so a regenerated corpus fails the
#: selection loudly instead of silently turning the passthrough case into a second
#: substitution case.
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
    """A foreign result the gate does NOT substitute reaches the model as the tool's own wire
    JSON, byte for byte, between the frame's delimiters — on the byte-gate arm and on each
    type-admission arm alike.

    O2's oracle as §7 r3 re-read it. The identity assertion this replaces (`result is
    original`) is void by construction under f2 = B: the passthrough branch must stringify and
    frame, so it cannot return the object it was handed. What survives is the CONTENT — the
    bytes inside the frame equal the bytes the model would have received with no gate at all,
    which is `ToolReturnPart.model_response_str()`, the real serializer, computed here rather
    than recorded so the comparison re-probes reality on every run.

    The delivered string is deliberately NOT compared: it differs from the no-gate run by
    exactly the frame, and a test asserting the whole delivered string passes over a gate that
    never framed anything.
    """
    for value in (_over_bar(), "a plain string", 7, None):
        out = agent_run(toolset=foreign_toolset(value))
        delivered = out.dispatched.text()
        assert framed_content(delivered) == wire_text(value), (
            f"passthrough content diverged from the no-gate wire bytes for {type(value).__name__}"
        )
        assert out.encoder.loads_calls == 0, "a passthrough decoded a view it did not deliver"


def test_substitute_branch_return_shape() -> None:
    """The substitute branch returns `ToolReturn(return_value=<framed TOON>,
    metadata={"json": <the tool's own return>})` — §7 r1's decision, spelled.

    Reading C with reading B's frame applied to `return_value`, taken as one decision with
    f5 = B and P6 = B. Three things the resolution names, each asserted: the model reads the
    FRAMED TOON — not a bare `toons.dumps`, which would drop every framing demand at this seam
    — the original rides in `metadata` under the key §7 spelled, and the metadata half is what
    the tool returned rather than anything the gate derived.

    `metadata` is off both provider wires and is the application's copy, which is exactly what
    f5 = B then recovers from the wire log (`d15b`).
    """
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


def test_the_recovered_json_equals_the_value_the_tool_returned() -> None:
    """The JSON recovered from a substituted call equals the OBJECT the tool returned, never a
    re-encode of the view the gate produced.

    `tool_return_part`'s `roles-disjoint-sources` invariant is the formal statement of this:
    its two roles are `return_value` (derived from the view) and `metadata_json` (the tool's
    own return). If the metadata half were derived from the view, O5 would be vacuous while
    looking identical — every recoverability assertion downstream would pass over a gate that
    had already lost the original.

    Driven with a payload the encoder is LOSSY on in one field, so a re-encode is
    distinguishable from the original rather than merely equal to it: `toons` nulls a `set`
    silently (`r10`), so a metadata half round-tripped through the view could not carry it
    back.
    """
    value = {"rows": [{"a": i, "b": f"row-{i}"} for i in range(40)], "tag": {"a", "b"}}
    out = agent_run(toolset=foreign_toolset(value))
    part = out.dispatched.part("fetch_rows")
    unmet = ("the substituted call carries no metadata under the reserved key, so there is "
             "nothing to recover and O5 is unmet")
    assert isinstance(part.metadata, dict), unmet
    assert gate_metadata_key() in part.metadata, unmet
    recovered = part.metadata[gate_metadata_key()]
    assert recovered == value
    assert recovered["tag"] == {"a", "b"}, "the recovered half is a re-encode of the view"


def test_a_dict_an_int_and_none_are_stringified_before_the_frame_and_the_frame_never_raises() -> None:
    """A dict, an int and `None` each reach the model FRAMED, with the tool's own wire bytes
    between the delimiters, and nothing on the path raises.

    The step f2 reading B requires and no design sentence supplied. `_untrusted.wrap` raises
    `TypeError('content must be a string')` on exactly those three shapes (`r12`, executed),
    and under B the passthrough branch is framed too — so a value that is not already a `str`
    has to become one first, on every branch.

    THE TRAP THIS PINS: an implementation that stringifies with `str(value)` produces Python
    `repr` text — single quotes, `None`, `True` — which is neither the wire JSON nor
    recoverable, and it would satisfy a naive "is it framed?" check. The stringification is
    the TOOL-RETURN serializer (`d71`), so `{"a": 1}` arrives as `{"a":1}` and `None` arrives
    as the empty string, not as `None`.
    """
    for value in ({"a": 1}, 7, None):
        out = agent_run(toolset=foreign_toolset(value))
        assert out.error is None, f"the frame raised on {value!r}"
        delivered = out.dispatched.text()
        assert framed_content(delivered) == wire_text(value)
        if repr(value) != wire_text(value):
            assert repr(value) not in delivered, (
                f"{value!r} was stringified with str()/repr(), not with the wire serializer"
            )


def test_the_byte_gate_and_the_stringify_step_measure_the_bytes_the_model_receives() -> None:
    """ALL THREE of the gate's `to_json` sites — the byte gate's denominator, f2 = B's
    stringify step, and M3's ROUND-TRIP ORACLE — are
    `ToolReturnPart.model_response_str`'s serializer, not `pydantic_core.to_json`.

    THE CORRECTION, NOT TODAY'S BEHAVIOUR. `design-872-r3.md` M2 states the two are "byte for
    byte" the same. They are not, in 7 of 22 probed value classes (`cN2`), by three
    independent mechanisms — non-finite floats (`NaN`/`Infinity` constants against `null`),
    `bytes` values (utf-8 text against base64: `{"x":"ab"}` against `{"x":"YWI="}`), and the
    empty list (`[]`, 2 bytes, against the empty string, 0 bytes). O2 is a byte-identity
    obligation, so a gate ruling the bytes with `to_json` makes the ruler and the thing it
    rules agree with each other while both differ from what the model receives.

    THE THIRD SITE IS NAMED HERE BECAUSE LEAVING IT UNRULED DECIDES AN ARM BY ACCIDENT
    (`92-reconciliation.md` F2, resolved at §7: M3's oracle takes the same ruler). The first
    two sites are measured on the PASSTHROUGH arm — under `to_json` a bytes-valued payload
    would arrive as utf-8 text where the un-gated run sent base64, which is where O2 is
    strongest. The oracle is not visible there at all: it only ever decides whether a payload
    the byte gate ALREADY cleared substitutes. So the third site is driven with a payload that
    clears the delivered-bytes bar and on which the two serializers disagree — a 40-row
    non-finite float form, 59.9% delivered — where the wire serializer renders `null` on both
    sides of the round trip (EQUAL, substitute) and `pydantic_core.to_json` renders `NaN`
    against `null` (unequal, passthrough). One assertion, opposite outcomes.
    """
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
    """A foreign tool body that pre-wraps its own value in a `ToolReturn` is unwrapped, its
    `return_value` gated and framed like any other foreign result, and the metadata the gate
    returns carries BOTH the body's own keys and the gate's original JSON.

    A CONSEQUENCE OF DECISIONS ALREADY TAKEN, not a new one. Five readings were executed
    (`cN7`, `cN8`) and four fail: passing the `ToolReturn` through returns a foreign result
    UNFRAMED, which f2 = B forbids; nesting it as `return_value` serializes the dataclass to
    the model and LEAKS the body's private metadata, documented as accessible to the
    application and not sent to the LLM; mutating `return_value` in place loses the gate's own
    `{"json": original}`, so O5 is silently unmet; re-wrapping while dropping the inner
    metadata destroys application data the gate did not author, which nothing decided licenses
    — `d69` accepts metadata loss caused by an OUTER hook, it does not license the gate to
    cause it.

    The reserved-key arm is pinned as a SHAPE, not a string: when the body's metadata already
    carries the gate's key, BOTH merge orders lose data (`cN9`), so what is asserted is that
    neither value is silently overwritten.
    """
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
