"""#872 — passthrough arms: every non-substituting branch hands the JSON through byte-identical to the un-gated run (`wire_text`), with the encoder called no more than the ordering allows."""
from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("pydantic_ai")

# `toons` ships in the `runtime` EXTRA, so an install without it is a supported one —
# and a bare module-scope import there is a COLLECTION error, which pytest answers by
# interrupting the whole session. Guarded like `pydantic_ai` above it.
toons = pytest.importorskip("toons")  # noqa: E402

from pydantic_ai.messages import BinaryContent  # noqa: E402

from defender.hooks.budget_enforcer import BudgetKill  # noqa: E402
from defender.tests.e2e._toon872 import (  # noqa: E402
    PANIC,
    EncoderFault,
    SpyEncoder,
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


def _substituting() -> dict:
    """A foreign dict-row payload comfortably under the shipped bar — the positive control
    every "and it did not substitute" assertion in this module needs to be non-vacuous."""
    return toon_rows(corpus()["fx-33"])


def test_str_scalar_none_and_content_block_returns_never_reach_the_encoder() -> None:
    """A `str`, a scalar, `None`, `bytes` and a content-block return never reach the encoder: the
    type admission examines the top-level shape and precedes both the byte gate and the round
    trip."""
    for value in ("a plain string", 7, None, b"ab"):
        out = agent_run(toolset=foreign_toolset(value))
        assert out.encoder.dumps_calls == 0, f"{type(value).__name__} reached the encoder"
        assert out.encoder.loads_calls == 0
        assert framed_content(out.dispatched.text()) == wire_text(value), (
            f"{type(value).__name__} reached the model as something other than its own wire bytes"
        )

    block = agent_run(toolset=foreign_toolset(
        BinaryContent(data=b"hello", media_type="text/plain")))
    assert block.encoder.dumps_calls == 0, "a content-block return reached the encoder"
    assert block.encoder.loads_calls == 0

    control = agent_run(toolset=foreign_toolset(_substituting()))
    assert control.encoder.dumps_calls == 1, "the spy cannot see an encode at all"
    assert framed_content(control.dispatched.text()) == toons.dumps(_substituting()), (
        "nothing substituted, so the model-visible assertions above hold over a gate that "
        "never encodes anything"
    )


def test_a_raising_toon_encoder_emits_json() -> None:
    """When the encoder raises on a payload the pre-validator ADMITTED, the model gets the tool's
    own JSON inside the frame and the gate raises nothing of its own."""
    value = _substituting()
    spy = SpyEncoder(EncoderFault(dumps_raises=PANIC("simulated encoder panic (S5's class)")))
    out = agent_run(toolset=foreign_toolset(value), encoder=spy)

    assert out.error is None, "an encoder fault escaped the gate"
    assert spy.dumps_calls == 1
    assert framed_content(out.dispatched.text()) == wire_text(value)


def test_a_pydantic_serialization_error_on_the_baseline_emits_json() -> None:
    """A payload the wire serializer cannot serialize leaves the run exactly as it is without the
    gate: the gate substitutes nothing, decodes nothing and changes no outcome."""
    class Arbitrary:
        def __repr__(self) -> str:
            return "<Arbitrary>"

    value = {"rows": [{"a": Arbitrary(), "b": 1}]}
    assert isinstance(toons.dumps(value), str), (
        "the encoder now raises on this fixture, so the ordering assertion below is about a "
        "different arm than the one this demand names"
    )
    gated = agent_run(toolset=foreign_toolset(value))
    ungated = agent_run(toolset=foreign_toolset(value), capabilities=False)

    assert gated.encoder.dumps_calls == 1, (
        "the gate never reached the encoder, so both differentials below are satisfied by a "
        "gate that does nothing — the key flow puts `dumps` before the baseline serialization"
    )
    assert gated.encoder.loads_calls == 0, "the gate decoded a view whose baseline never serialized"
    assert type(gated.error).__name__ == type(ungated.error).__name__, (
        "the gate changed the class of a pre-existing serialization failure"
    )


def test_a_nested_payload_and_one_toon_enlarges_pass_through() -> None:
    """A nested payload and a non-uniform list — the two shapes TOON does not make cheaper —
    reach the model as their own JSON inside the frame."""
    nested = corpus()["fx-33"]
    non_uniform = {"rows": [{"a": 1, "b": 2}, {"c": 3}, {"a": 4, "b": 5, "d": 6}] * 20}
    for value in (nested, non_uniform):
        out = agent_run(toolset=foreign_toolset(value))
        assert framed_content(out.dispatched.text()) == wire_text(value), (
            "a payload TOON does not shrink was substituted anyway"
        )


def test_a_silently_coerced_value_fails_the_round_trip_and_emits_json() -> None:
    """A payload whose TOON view does not carry the JSON's content back reaches the model as JSON
    — with the oracle §7 r4 (f8 = B) decided: `to_json(loads(toon)) == to_json(value)`,
    compared SERIALIZED, not with Python `==`."""
    big = {"rows": [{"a": 2 ** 63, "b": f"pad-{i}"} for i in range(40)]}
    assert toons.loads(toons.dumps(big)) == big, (
        "the `==` oracle no longer blesses the big-integer view, so this case has stopped "
        "discriminating between the two oracles"
    )
    out = agent_run(toolset=foreign_toolset(big))
    assert framed_content(out.dispatched.text()) == wire_text(big), (
        "an integer >= 2**63 reached the model in float notation — the `==` oracle, not f8 = B's"
    )

    coerced = {"rows": [{"a": {i, i + 1}, "b": f"pad-{i}"} for i in range(40)]}
    out = agent_run(toolset=foreign_toolset(coerced))
    assert framed_content(out.dispatched.text()) == wire_text(coerced), (
        "a silently nulled `set` substituted"
    )

    surrogate = {"rows": [{"a": "\ud800", "b": f"pad-{i}"} for i in range(40)]}
    gated = agent_run(toolset=foreign_toolset(surrogate))
    ungated = agent_run(toolset=foreign_toolset(surrogate), capabilities=False)
    assert type(gated.error).__name__ == type(ungated.error).__name__, (
        "a raising comparison escaped the guard instead of taking the passthrough arm"
    )


def test_every_passthrough_arm_is_byte_identical_with_and_without_the_gate() -> None:
    """On EVERY passthrough arm — type admission, encoder fault, baseline serialization, the byte
    gate, the round trip, and the guard's refusal — the JSON content inside the frame is byte-
    identical to the no-gate run's model-visible text."""
    arms = {
        "type-admission": ("a plain string", None),
        "byte-gate": (corpus()["fx-33"], None),
        "round-trip": ({"rows": [{"a": {i}, "b": i} for i in range(40)]}, None),
        "encoder-fault": (_substituting(), EncoderFault(dumps_raises=PANIC("S5"))),
        "decoder-fault": ({"rows": [{"}": i, "z": i} for i in range(20)]}, None),
        "guard-refusal": ({"rows": [{"a": "x\x00y", "b": 1}]}, None),
    }
    for arm, (value, fault) in arms.items():
        out = agent_run(toolset=foreign_toolset(value),
                        encoder=SpyEncoder(fault) if fault else None)
        assert out.error is None, f"the {arm} arm raised"
        assert framed_content(out.dispatched.text()) == wire_text(value), (
            f"the {arm} arm's content is not the no-gate run's bytes"
        )

    control = agent_run(toolset=foreign_toolset(_substituting()))
    assert framed_content(control.dispatched.text()) != wire_text(_substituting()), (
        "the comparison cannot see a substitution, so every arm above passed vacuously"
    )


def test_a_payload_failing_the_byte_gate_is_never_decoded() -> None:
    """The round trip runs only AFTER the byte gate, and the pre-validator runs before the
    encoder: a payload that fails the bar is encoded once and decoded zero times, and a
    payload the guard refuses is encoded zero times."""
    over_value = corpus()["fx-33"]
    over = agent_run(toolset=foreign_toolset(over_value))
    assert (over.encoder.dumps_calls, over.encoder.loads_calls) == (1, 0)
    assert framed_content(over.dispatched.text()) == wire_text(over_value)

    refused_value = {"rows": [{"a": "x\x00y"}]}
    refused = agent_run(toolset=foreign_toolset(refused_value))
    assert (refused.encoder.dumps_calls, refused.encoder.loads_calls) == (0, 0)
    assert framed_content(refused.dispatched.text()) == wire_text(refused_value)

    under_value = _substituting()
    under = agent_run(toolset=foreign_toolset(under_value))
    assert (under.encoder.dumps_calls, under.encoder.loads_calls) == (1, 1)
    assert framed_content(under.dispatched.text()) == toons.dumps(under_value)


def test_a_payload_whose_toon_form_is_empty_is_not_substituted() -> None:
    """An empty dict is not substituted, and an empty list is not substituted — and the two are
    OPPOSITE cases, not one."""
    empty_moved = "the empty-dict mechanism has moved: it no longer encodes to zero bytes " \
        "and round-trips, so this floor is guarding a case that no longer exists"
    assert toons.dumps({}) == "", empty_moved
    assert toons.loads("") == {}, empty_moved
    assert wire_text([]) == "", "the empty list's wire denominator is no longer zero"

    for value in ({}, []):
        out = agent_run(toolset=foreign_toolset(value))
        assert out.error is None
        assert framed_content(out.dispatched.text()) == wire_text(value), (
            f"{value!r} was substituted"
        )


def test_a_baseexception_from_the_encoder_passes_through_and_a_control_flow_exception_is_reraised() -> None:
    """Two assertions, and the second is the one a naive widening breaks."""
    value = _substituting()
    caught = agent_run(
        toolset=foreign_toolset(value),
        encoder=SpyEncoder(EncoderFault(dumps_raises=PANIC("S5's class, captured"))),
    )
    assert caught.error is None
    assert framed_content(caught.dispatched.text()) == wire_text(value)

    for exc in (asyncio.CancelledError(), KeyboardInterrupt(), GeneratorExit(),
                SystemExit(1), BudgetKill("budget tail exhausted")):
        out = agent_run(
            toolset=foreign_toolset(value),
            encoder=SpyEncoder(EncoderFault(dumps_raises=exc)),
        )
        assert out.error is not None, f"{type(exc).__name__} was swallowed by the guard"
        assert isinstance(out.error, type(exc)) or type(exc).__name__ in repr(out.error), (
            f"{type(exc).__name__} was replaced rather than re-raised"
        )
        assert not out.dispatched.parts or out.dispatched.texts() == [], (
            f"the run continued after {type(exc).__name__}"
        )


def test_a_view_the_encoder_produced_that_the_decoder_cannot_read_passes_through() -> None:
    """A view the encoder itself produced that the decoder cannot read is a passthrough, not an
    escaped fault — the box r2's diagram does not have."""
    value = {"rows": [{"}": i, "z": f"pad-{i}"} for i in range(20)]}
    view = toons.dumps(value)
    with pytest.raises(BaseException) as caught:  # noqa: B017, PT011 — the class IS the probe
        toons.loads(view)
    assert not isinstance(caught.value, Exception), (
        "the decoder's fault is now an Exception subclass; the guard's breadth demand (d55) "
        "and this arm no longer describe the same encoder"
    )

    out = agent_run(toolset=foreign_toolset(value))
    assert out.error is None, "a decoder fault escaped the gate"
    assert out.encoder.dumps_calls == 1
    assert out.encoder.loads_calls == 1
    assert framed_content(out.dispatched.text()) == wire_text(value)


def test_a_nan_or_infinite_float_reaches_the_model_identically_with_and_without_the_gate() -> None:
    """A payload carrying NaN or ±infinity reaches the model with the same information gated and
    un-gated — and where the gate substitutes, it substitutes because M3's oracle BLESSES the
    round trip under the wire serializer."""
    substituted_at_least_once = False
    for f in (float("nan"), float("inf"), float("-inf")):
        for value in ({"x": f}, {"rows": [{"a": f, "b": i} for i in range(40)]}):
            assert wire_roundtrip_equal(value), (
                f"M3's oracle no longer blesses {f!r} under the wire serializer, so the arm "
                "this demand asserts is decided by the fidelity check rather than by the bar"
            )
            out = agent_run(toolset=foreign_toolset(value))
            assert out.error is None
            view = framed_content(out.dispatched.text())

            clears = delivered_percent(value) <= 85
            expected = toons.dumps(value) if clears else wire_text(value)
            assert view == expected, (
                f"{f!r} in {'row' if 'rows' in value else 'scalar'} position took the wrong "
                f"arm: the delivered-bytes ratio is {delivered_percent(value):.1f}%"
            )
            substituted_at_least_once |= clears

            # The obligation itself, on whichever arm was taken: what the model can read back
            # out of the delivered text is what the un-gated run would have sent.
            recovered = toons.loads(view) if clears else json.loads(view)
            assert wire_text(recovered) == wire_text(value), (
                f"the gate introduced a divergence on {f!r} that the un-gated run does not have"
            )

    assert substituted_at_least_once, (
        "no non-finite payload substituted, so every assertion above is the passthrough arm "
        "and the oracle correction this demand pins is untested"
    )
