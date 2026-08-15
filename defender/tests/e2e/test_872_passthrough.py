"""#872 — the passthrough arms and the fidelity oracle
(`d4`, `d5`, `d6`, `d7`, `d8`, `d9`, `d10`, `d11`, `d55`, `d56`, `d70`).

Every branch of the key flow but the last hands the JSON through. This module drives each of
them and asserts the same thing each time: what the model reads inside the frame is what the
un-gated run would have sent, byte for byte, and the encoder was called exactly as many times
as the ordering allows and no more.

THE NO-GATE ARM IS `wire_text(value)` — `ToolReturnPart.model_response_str()`, the real
serializer, recomputed on every run. It is not a recorded string and it is not a switch: §7
r5 installed the gate unconditionally, so there is no production configuration in which it is
absent, and inventing one would be a fail-open knob a test asked for.
"""
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
    """A `str`, a scalar, `None`, `bytes` and a content-block return never reach the encoder:
    the type admission examines the top-level shape and precedes both the byte gate and the
    round trip.

    Load-bearing rather than tidy: `toons.dumps("a string")` returns the string unchanged and
    round-trips (`x8`, `r10`), so the round trip cannot serve as the type gate — a gate that
    admitted a `str` would substitute it and the round trip would agree.

    The five members are enumerated because the fault surface is not the same for each —
    `bytes` is neither a dict nor a list and so is the type admission's rule rather than the
    list's (settled #26), and a content-block is an object the wrapped toolset produced
    (settled #1). The encoder's call count is ONE of the two observables, because "the encoder
    was not called" cannot be inferred from a return value that looks the same either way —
    but a count on its own is an internal, so each member is also read at the MODEL: the text
    inside the frame is the tool's own wire bytes.

    THE CONTENT BLOCK IS THE ONE MEMBER WITH NO MODEL-VISIBLE ASSERTION, and the reason is
    that no resolution supplies one. `d4`'s note has this arm returning "the wrapped toolset's
    object itself" while f2 = B stringifies and frames every foreign exit; the two readings
    give different delivered shapes and §7 answered neither, so this test claims only what is
    settled for it. `bytes` is asserted, and it is the sharpest of the four: the wire
    serializer sends BASE64 (`"YWI="`) where `pydantic_core.to_json` would send utf-8 text, so
    a gate stringifying with the wrong serializer diverges here on the passthrough arm.
    """
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
    """When the encoder raises on a payload the pre-validator ADMITTED, the model gets the
    tool's own JSON inside the frame and the gate raises nothing of its own.

    THE REACHABILITY OF THIS ARM NARROWED WITH M7, and the narrowing is what the fault choice
    here is about: a non-`str` key no longer reaches the encoder at all (`d48`), so a test that
    drove this arm with `{1: "x"}` would be testing the pre-validator and going green for the
    wrong reason. The fault is injected at the encoder seam instead, and its class is not
    authored: it is `pyo3_runtime.PanicException`, captured from the real encoder at import
    (`S5`), whose MRO is (PanicException, BaseException, object) — the exact class r2's
    `except Exception` arm walked through.
    """
    value = _substituting()
    spy = SpyEncoder(EncoderFault(dumps_raises=PANIC("simulated encoder panic (S5's class)")))
    out = agent_run(toolset=foreign_toolset(value), encoder=spy)

    assert out.error is None, "an encoder fault escaped the gate"
    assert spy.dumps_calls == 1
    assert framed_content(out.dispatched.text()) == wire_text(value)


def test_a_pydantic_serialization_error_on_the_baseline_emits_json() -> None:
    """A payload the wire serializer cannot serialize leaves the run exactly as it is without
    the gate: the gate substitutes nothing, decodes nothing and changes no outcome.

    The fault is REAL and induced through the real primitive: an arbitrary object as a VALUE
    is the only input `to_json` raises on — not a `datetime`, a `set` or `bytes`, which it
    ISO-formats or base64s (`r10`). M7 admits it (it is not a bad key, not a cycle, not deep),
    `toons.dumps` nulls it silently, and the serializer then raises.

    The assertion is a DIFFERENTIAL, not an outcome, because the un-gated run raises here too:
    `ToolReturnPart.model_response_str` calls the same serializer, so this is the pre-existing
    wire baseline failing, and O2 pins the gate to never doing worse rather than to doing
    better (`d47`). What the gate must not do is substitute, decode, or change the class of
    the failure.

    THE THIRD ASSERTION IS THE ANTI-VACUITY ONE AND IT IS A DESIGN CONSEQUENCE, NOT A GUESS
    (`92-reconciliation.md` F7). Two pure differentials are satisfied by a gate that does
    nothing at all, which is what made this the one null-stub pass with no control. The key
    flow fixes the order — pre-validate → `dumps` → `to_json` → bar — and `d10` pins that chain
    with its own test, so the encoder is reached BEFORE the baseline serialization is
    attempted. Executed on this fixture: `toons.dumps` succeeds, returning
    `'rows[1]{a,b}:\\n  null,1'` (the arbitrary object silently nulled), and the wire
    serializer then raises. `dumps_calls == 1` is therefore fixed by the design and is `0` for
    a gate that never ran — the discrimination the other two assertions cannot supply.
    """
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
    reach the model as their own JSON inside the frame.

    The columnar arm of the committed corpus is the executed instance of "TOON enlarges":
    across all 40 fixtures the wire-ruler ratio never drops below 86.2% and the worst is
    108.3%, so this is the population the gate is inert on and it is inert on it by
    MEASUREMENT, not by a type rule. The non-uniform list is the second shape: TOON's tabular
    form needs an array of objects with identical key sets, so a list whose rows disagree
    cannot reach it.
    """
    nested = corpus()["fx-33"]
    non_uniform = {"rows": [{"a": 1, "b": 2}, {"c": 3}, {"a": 4, "b": 5, "d": 6}] * 20}
    for value in (nested, non_uniform):
        out = agent_run(toolset=foreign_toolset(value))
        assert framed_content(out.dispatched.text()) == wire_text(value), (
            "a payload TOON does not shrink was substituted anyway"
        )


def test_a_silently_coerced_value_fails_the_round_trip_and_emits_json() -> None:
    """A payload whose TOON view does not carry the JSON's content back reaches the model as
    JSON — with the oracle §7 r4 (f8 = B) decided: `to_json(loads(toon)) == to_json(value)`,
    compared SERIALIZED, not with Python `==`.

    THE CORRECTION, PINNED — the ORACLE `==` GAVE IS REFUTED. Two probed classes were green
    under `==` with the view lossy: an integer >= 2**63 renders in float notation, so the model
    reads 9223372036854776000 where the JSON says 9223372036854775808 (`S6`), and `==` blesses
    it because Python compares the decoded float equal; and a value with a lying `__eq__`
    substituted over a view that had lost its data (`S10`). Both are driven here, and the
    integer case is the one a test written against `==` would still pass.

    The third arm is the oracle's OWN fault: under f8 = B there is no `__eq__` call at all, so
    the probed fault is `to_json` RAISING. A lone surrogate in a VALUE is the instance M7
    admits — its NUL scan and its key checks do not reach it — and it is a passthrough inside
    the `BaseException` guard like every other arm.
    """
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
    """On EVERY passthrough arm — type admission, encoder fault, baseline serialization,
    the byte gate, the round trip, and the guard's refusal — the JSON content inside the frame
    is byte-identical to the no-gate run's model-visible text.

    O2's oracle stated once over all SIX arms; the sixth is M7's refusal, which did not exist
    when O2 was written and which a reader will assume returns something synthesized.

    RE-READ AT §7 r3 (f2 = B), AND THE RE-READING IS THE WHOLE DEMAND. "Byte identical with
    the gate and without it" cannot survive a change that frames every foreign result, so the
    parity is over the FRAMED CONTENT — the bytes between the delimiters — and not over the
    delivered string, which differs by exactly the frame. A test written against the
    un-re-read sentence fails on a correct implementation; one written against the delivered
    string passes over a gate that never framed anything.

    ANTI-VACUITY: the comparison is only meaningful over calls that actually reach
    `call_tool`. Defender's outermost hook may answer a call WITHOUT calling the handler, so a
    budget-refused call is parity-preserving for a reason that has nothing to do with the gate
    and would pass this test over a gate nothing installed. The substituting control at the end
    is what proves the comparison can see a difference at all.
    """
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
    payload the guard refuses is encoded zero times.

    The full order is pre-validate -> dumps -> to_json -> bar -> loads -> to_json both sides ->
    compare; f8 = B added the second serialization AFTER the bar, so the ordering claim covers
    the re-serialization too and the decode cost is still not paid on the payloads that fail
    the byte gate.

    Counted at the seam, never inferred from source order: a spy encoder's call counts are the
    only instrument that distinguishes "refused before the encoder" from "encoded and then
    discarded".

    AND EACH COUNT IS PAIRED WITH WHAT THE MODEL GOT, because a call count on its own is an
    internal variable and O1 forbids reading one as the oracle. A suite that regressed to
    "encoded / not encoded" while delivering the wrong text would pass the counts and fail the
    three assertions beside them.
    """
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
    """An empty dict is not substituted, and an empty list is not substituted — and the two
    are OPPOSITE cases, not one.

    The empty DICT encodes to ZERO BYTES, clears any bar and round-trips (`toons.loads("")`
    returns `{}`), so the round trip cannot see it: it is the empty-view floor, the one hard
    floor f6 keeps under every reading, and substituting it would hand the model nothing at
    all where the JSON said `{}`.

    The empty LIST is the opposite: it encodes to `[0]:`, four bytes, and its WIRE denominator
    is ZERO — `model_response_str` renders `[]` as the empty string (`cN3`) — so it can never
    clear the bar and passes through ON THE BAR, not on the empty-view rule. A test asserting
    one outcome over "an empty payload" pins a false symmetry, and the empty list's
    passthrough is not evidence that the empty-view floor works.
    """
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
    """Two assertions, and the second is the one a naive widening breaks. A `BaseException`
    out of the encoder is a passthrough; a CONTROL-FLOW exception is RE-RAISED, not swallowed.

    `pyo3_runtime.PanicException` is not an `Exception` — its MRO is (PanicException,
    BaseException, object) and `issubclass(PanicException, Exception)` is False — which is
    precisely how r2's arm shipped unimplementable, so the guard's breadth is `BaseException`.
    Widening to a bare `except BaseException` WITHOUT the re-raise turns a cancelled run into a
    silently-substituted one, so `CancelledError`, `KeyboardInterrupt`, `GeneratorExit`,
    `SystemExit` and the house's `BudgetKill` each escape. The shape is
    `query_tool._decide_guarded`'s, which already does exactly this in this tree.

    `S5` also established the arm is DURABLE rather than one-shot: after 200 consecutive caught
    panics `dumps` still encodes and round-trips, so one spy is reused across the cases here.
    """
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
    """A view the encoder itself produced that the decoder cannot read is a passthrough, not
    an escaped fault — the box r2's diagram does not have.

    r2 has `loads(dumps(x)) != x`, an INEQUALITY; it has no "`loads` raises" branch, and
    `loads` raises on views `dumps` ITSELF produced. Driven here through the REAL encoder and
    the REAL decoder with a real input: a `}` in a mapping key in ROW position makes `dumps`
    emit `rows[N]{"}",z}:` and `loads` raise a `PanicException` ("begin > end when slicing") on
    the view it just produced (`R7`, reproduced at `S5`).

    PRE-VALIDATION CANNOT COVER THIS and the demand exists because it cannot: a `}` key is a
    perfectly legal, UTF-8-encodable `str` that M7 ADMITS by design, so the guard is the only
    thing between it and an escaped fault. The probed BOUND is what makes a guard sufficient —
    across the hazard alphabet `loads` never crashes the process, its worst outcome is a
    catchable panic, so unlike the encoder's cycle case there is no signal to survive.
    """
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
    """A payload carrying NaN or ±infinity reaches the model with the same information gated
    and un-gated — and where the gate substitutes, it substitutes because M3's oracle BLESSES
    the round trip under the wire serializer.

    THE ARM IS ASSERTED NOW, AND THAT IS THE §7 CORRECTION (`92-reconciliation.md` F2). The
    earlier reading of this demand forbade asserting an arm, on the ground that the arm was
    contingent on a serializer the design misidentifies (`d71`) — and then asserted the
    passthrough arm anyway, which is the arm the un-corrected serializer produces. §7 spelled
    M3's oracle with the same wire tool-return serializer `d71` pins for the other two sites,
    so the contingency is gone: `wire(loads(dumps(x)))` and `wire(x)` both render every
    non-finite float as `null`, the round trip compares EQUAL, and M3 does not veto.

    THE PARITY IS STILL THE OBLIGATION, and it survives the arm change because the loss is
    pydantic-ai's rather than the gate's: `tool_return_ta.dump_json` nulls every non-finite
    float BEFORE any gate exists and `toons` nulls it identically, so the information the model
    receives is the same on either arm. That is asserted here as decoded-content parity, which
    holds on BOTH arms and is what "the same information gated and un-gated" means — a
    delivered-string comparison would only ever restate which arm was taken.

    WHICH arm each payload takes is left to the two rulers that decide it and re-derived by
    measurement, not spelled: M3 blesses all six, so the delivered-bytes bar (`d3`) is the only
    thing left, and it splits them. The 40-row forms are 59.9% delivered and SUBSTITUTE; the
    scalar forms are 7 bytes of view against 10 of JSON but 74 against 77 once the frame is
    counted on both sides — 96.1%, over any bar the tree would configure — so they pass through
    ON THE BAR. Both are asserted against the measured verdict, so a gate that took the other
    ruler on either fails here.

    The committed corpus contains ZERO floats of any kind (`cN6`), so neither hazard is
    exercised by it and this is the only place either is driven.
    """
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
