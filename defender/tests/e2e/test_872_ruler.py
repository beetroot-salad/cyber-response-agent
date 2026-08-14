"""#872 — the ruler and the bar (`d1`, `d3`, `d24`, `d25`, `d45`, `d58`).

`85` is the value the measurements were taken at. IT IS NOT A CONTRACT AND NO DEMAND ASSERTS
IT. The threshold demand that did (`d2`) is dead: the 1.5pp owned/unowned window it pinned is
measured between two ENCODINGS OF ONE POPULATION — the corpus's `unowned` arm is the same 40
owned payloads re-zipped — so it bears on no foreign source at all.

What the suite pins instead is the gate's behavior RELATIVE TO THE BAR IT IS GIVEN, run at
more than one configured bar, and the ruler that bar is applied with.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("pydantic_ai")

import toons  # noqa: E402

from defender.tests.e2e._toon872 import (  # noqa: E402
    SALT,
    agent_run,
    corpus,
    delivered_percent,
    foreign_sequence,
    foreign_toolset,
    frame_overhead,
    framed_content,
    toon_bytes,
    toon_rows,
    wire_bytes,
    wire_text,
)

pytestmark = pytest.mark.e2e

MAX_PERCENT_ENV = "DEFENDER_TOON_GATE_MAX_PERCENT"


def _pick(bar: int, *, clearing: bool):
    """A committed fixture arm on the requested side of a CONFIGURED bar.

    The selection is what makes these demands parameterized rather than pinned: nothing here
    names 85, and running at a second bar re-selects rather than re-spelling.

    SELECTED ON THE DELIVERED RATIO, NOT THE ENCODER ONE, and the distinction is `d3`: three
    committed arms clear on encoder bytes and fail once the frame is counted, so a selection
    made on `percent` can hand a caller a payload it then asserts substitutes while the gate
    `d3` demands passes it through — a test no correct implementation makes green."""
    for name, columnar in sorted(corpus().items()):
        for arm, value in (("dict-rows", toon_rows(columnar)), ("columnar", columnar)):
            if (delivered_percent(value) <= bar) is clearing:
                return f"{name}/{arm}", value
    raise AssertionError(f"no committed fixture is {'under' if clearing else 'over'} bar {bar}")


def test_foreign_dict_row_clearing_the_bar_reaches_the_model_as_toon() -> None:
    """A dict-row result from a toolset defender does not own, whose TOON form clears the
    CONFIGURED bar, arrives at the model as TOON — read off the `ToolReturnPart` the model
    received, not off an internal variable.

    O1's oracle, and the oracle names the bar the gate was configured with rather than a
    constant. The view is not merely "different from the JSON": it is the encoder's own output
    for that value, and it decodes back to it, so a gate that shipped a truncated or
    placeholder view would fail here rather than passing on inequality.

    This is also the positive control `d28` names: a gate that emitted no TOON anywhere would
    satisfy that negative and fail this.
    """
    for bar in (85, 90):
        label, value = _pick(bar, clearing=True)
        out = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(bar)})
        view = framed_content(out.dispatched.text(), salt=SALT)
        assert view == toons.dumps(value), f"{label} did not reach the model as TOON at bar {bar}"
        assert toons.loads(view) == value


def test_the_bytes_the_model_receives_clear_the_bar_the_gate_measured() -> None:
    """The bar is applied to the bytes the model RECEIVES, not to the encoder's output: a
    payload that clears on encoder bytes and fails once the frame is counted passes through.

    Under f2 = B the frame is on every exit, so the comparison the code must carry is a
    DELIVERED-bytes one. `r20` measured the consequence on the committed corpus: 8 of the 40
    unowned arms clear the bar on encoder bytes and fail it on delivered bytes, and below about
    447 bytes of wire JSON the framed view can EXCEED the JSON it replaced — inverting O1,
    which is a cost obligation.

    The fixture is selected by measurement rather than named, and the selection asserts the
    discriminator still exists: if no committed arm sits in that window any more, this test
    fails loudly instead of quietly testing an ordinary passthrough.
    """
    bar = 85
    overhead = frame_overhead(SALT)
    window = [
        (f"{name}/{arm}", value)
        for name, columnar in sorted(corpus().items())
        for arm, value in (("dict-rows", toon_rows(columnar)), ("columnar", columnar))
        if 100 * toon_bytes(value) <= bar * wire_bytes(value)
        and 100 * (toon_bytes(value) + overhead) > bar * (wire_bytes(value) + overhead)
    ]
    assert window, (
        "no committed fixture clears on encoder bytes and fails on delivered bytes any more, "
        "so this demand's discriminator is gone and the assertion below would be vacuous"
    )
    label, value = window[0]
    out = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(bar)})
    assert framed_content(out.dispatched.text(), salt=SALT) == wire_text(value), (
        f"{label} was substituted: the gate measured the encoder's bytes, not the delivered ones"
    )

    _, clears = _pick(bar, clearing=True)
    assert 100 * (toon_bytes(clears) + overhead) <= bar * (wire_bytes(clears) + overhead)
    control = agent_run(toolset=foreign_toolset(clears), env={MAX_PERCENT_ENV: str(bar)})
    assert framed_content(control.dispatched.text(), salt=SALT) == toons.dumps(clears), (
        "nothing clears the delivered-bytes bar either, so the assertion above is not about "
        "the frame"
    )


def test_a_fixture_whose_verdict_differs_between_rulers_takes_the_wire_rulers_verdict() -> None:
    """At the bar the gate is configured with, a fixture whose verdict differs between
    `json.dumps` and the wire serializer takes the WIRE ruler's verdict.

    O8: the gate's JSON baseline is the serialization the model is actually charged for.
    Measuring against `json.dumps` defaults inflates the baseline with `ensure_ascii` escapes
    and two-byte separators and books a win that does not exist on the wire — at the shipped
    bar exactly one committed arm discriminates the two rulers, `fx-01` columnar, which clears
    at 81.7% under `json.dumps` and fails at 86.2% under the wire ruler.

    PARAMETERIZED ON THE CONFIGURED BAR, because WHICH fixture discriminates is a function of
    the bar: the discriminators are re-derived at each bar rather than hard-coded at one, and
    the assertion is a drive rather than a restatement of the formula.

    SCOPED TO dict/list, deliberately: the two serializers diverge on `str` and `None` as well,
    which the type admission excludes anyway — unscoped, the demand would pin a false
    universal.
    """
    overhead = frame_overhead(SALT)

    def _verdict(value, denominator: int, bar: int) -> bool:
        """The gate's own comparison against a candidate baseline — delivered bytes on both
        sides (`d3`), so the only thing that varies between the two rulers below is WHICH
        serializer supplies the JSON side."""
        return 100 * (toon_bytes(value) + overhead) <= bar * (denominator + overhead)

    for bar in (85, 90):
        discriminators = [
            (f"{name}/{arm}", value)
            for name, columnar in sorted(corpus().items())
            for arm, value in (("dict-rows", toon_rows(columnar)), ("columnar", columnar))
            if _verdict(value, len(json.dumps(value).encode()), bar)
            != _verdict(value, wire_bytes(value), bar)
        ]
        assert discriminators, f"no committed arm discriminates the two rulers at bar {bar}"
        label, value = discriminators[0]
        out = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(bar)})
        substituted = framed_content(out.dispatched.text(), salt=SALT) != wire_text(value)
        assert substituted == _verdict(value, wire_bytes(value), bar), (
            f"{label} took the json.dumps ruler's verdict at bar {bar}"
        )


def test_a_cjk_payload_is_measured_in_bytes_not_characters() -> None:
    """Both sides of the comparison are measured in UTF-8 BYTES, not characters.

    A nested CJK payload is a different fraction of the wire JSON in characters than in bytes,
    because TOON emits raw UTF-8 while the wire serializer does too but the two differ in
    structural overhead — so a `len(str)` implementation reaches a different verdict on the
    same value. The fixture is chosen by measurement so that the two rulers straddle the
    configured bar, and the assertion is that the BYTE verdict is the one the model gets.

    A pure-ASCII fixture cannot tell the two apart, which is why this demand exists as its own
    domain member rather than riding on the corpus.

    THE STRADDLE IS COMPUTED ON THE DELIVERED RATIO (`d3`) AND THE FIXTURE IS SEARCHED FOR,
    NOT SPELLED. The frame is 67 ASCII bytes on both sides, and adding a constant to both
    numerator and denominator drags every ratio toward 100% — which is enough to collapse a
    straddle that exists on encoder bytes. The three-key fixture this test used to name does
    exactly that: 84.4% in characters and 91.4% in bytes bare, but 96.0% and 96.0% delivered,
    so a `len(str)` implementation reached the SAME verdict as a byte one and the assertion
    held over the implementation it exists to reject. The family below is searched at the
    configured bar and the search asserts it found a straddle, so a frame-width change fails
    the selection loudly rather than quietly emptying the demand.
    """
    bar = 85
    overhead = frame_overhead(SALT)

    def _straddles(value) -> tuple[bool, bool]:
        view, wire = toons.dumps(value), wire_text(value)
        by_bytes = 100 * (len(view.encode()) + overhead) <= bar * (len(wire.encode()) + overhead)
        by_chars = 100 * (len(view) + overhead) <= bar * (len(wire) + overhead)
        return by_bytes, by_chars

    candidates = [
        {"rows": [{"件": "あ" * width, "詳": "説明", "備": "補"} for _ in range(rows)]}
        for rows in range(1, 13)
        for width in range(1, 40)
    ]
    straddling = [v for v in candidates if _straddles(v)[0] != _straddles(v)[1]]
    assert straddling, (
        "no CJK payload in the searched family straddles the bar on the DELIVERED ratio any "
        "more, so a len(str) implementation would pass this test"
    )
    value = straddling[len(straddling) // 2]
    by_bytes, by_chars = _straddles(value)

    out = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(bar)})
    substituted = framed_content(out.dispatched.text(), salt=SALT) != wire_text(value)
    assert substituted == by_bytes, (
        f"the CJK payload was measured in characters (verdict {by_chars}), not in UTF-8 bytes"
    )


def test_each_call_is_gated_independently_with_no_cross_call_or_run_position_state() -> None:
    """Every call is gated on its own value: the first tool call of a run behaves as a later
    one, two byte-identical payloads get identical verdicts, and the second of two differing
    payloads is unaffected by the first call's decision.

    M1-M3 are a pure function of one call's own value, and no doc sentence introduces
    run-position-dependent behaviour. Four consequences the phase-C readers converged on are
    driven together, in one run, because the failure this forbids is state that survives
    BETWEEN calls — a cached verdict, a first-call special case, a counter that changes the
    bar.

    AND THE ONE THAT IS NOT COMFORTABLE: because each call is gated independently, a RETRIED
    call may legitimately land on the other side of the bar, so idempotence is not guaranteed
    and O1's saving is non-deterministic across retries. That is a consequence of the design,
    not a defect this demand asks to be repaired, so nothing here asserts stability across
    differing values.
    """
    under = toon_rows(corpus()["fx-33"])
    over = corpus()["fx-33"]
    values = [under, over, under, over, under]
    out = agent_run(
        toolset=foreign_sequence(values),
        calls=[("fetch_rows", {})],
        turns=len(values),
    )
    texts = out.dispatched.texts("fetch_rows")
    assert len(texts) == len(values), f"expected {len(values)} returns, got {len(texts)}"
    for i, (value, text) in enumerate(zip(values, texts, strict=True)):
        expected = toons.dumps(value) if value is under else wire_text(value)
        assert framed_content(text, salt=SALT) == expected, (
            f"call {i + 1} took a verdict that depends on its position or on an earlier call"
        )


def test_a_payload_just_under_the_configured_bar_substitutes_and_one_just_over_it_passes_through() -> None:
    """At a configured bar, a payload just under it substitutes and one just over it passes
    through — at MORE THAN ONE configured bar, and asserting NO CONSTANT.

    This replaces both dead threshold demands. `d2` pinned the 1.5pp owned/unowned window and
    `0.85` as a contract; the window is measured between two encodings of ONE population, so
    it bears on no foreign source. `d26` recorded that `0.90`'s crossing verdict flipped under
    the wire ruler; with no pinned bar there is no constant for an alternative to cross FROM,
    so `90` is simply one more value this demand is run at.

    What survives from both is the MECHANISM, and it is asserted here: `<=` is inclusive, so a
    payload exactly at the bar substitutes and one byte over passes through. §7 r7 (f7 = B)
    settled the spelling — an integer percent through the existing `env_int` — which is why
    the two bars below are integers and why no float appears anywhere in this demand.
    """
    for bar in (85, 90):
        env = {MAX_PERCENT_ENV: str(bar)}
        under_label, under = _pick(bar, clearing=True)
        over_label, over = _pick(bar, clearing=False)

        subbed = agent_run(toolset=foreign_toolset(under), env=env)
        assert framed_content(subbed.dispatched.text(), salt=SALT) == toons.dumps(under), (
            f"{under_label} did not substitute at bar {bar}"
        )

        passed = agent_run(toolset=foreign_toolset(over), env=env)
        assert framed_content(passed.dispatched.text(), salt=SALT) == wire_text(over), (
            f"{over_label} substituted at bar {bar}"
        )

    # The boundary at the finest granularity the integer knob admits: ONE payload, two bars
    # one percentage point apart, straddling its own measured ratio. This is what makes the
    # demand about the RELATION rather than about either fixture — a gate keying on a
    # hard-coded constant passes both loops above and fails here.
    #
    # THE RATIO IS THE DELIVERED ONE (`d3`), and at this granularity the difference decides the
    # sub-case. `fx-00/dict-rows` measures 46.63% on encoder bytes and 47.19% once the frame is
    # counted on both sides, so floors and ceils taken on the encoder ratio ask for
    # substitution at a configured bar of 47 — which the delivered-bytes gate `d3`'s resolution
    # requires must pass through. Derived from `delivered_percent`, the two demands agree
    # (`92-reconciliation.md` F1, resolved at §7: the delivered-bytes gate stands and this
    # sub-case moves).
    import math
    _, value = _pick(85, clearing=True)
    ratio = delivered_percent(value)
    low, high = math.floor(ratio), math.ceil(ratio)
    assert low != high, "the boundary fixture's ratio is exactly integral; pick another arm"
    passed = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(low)})
    assert framed_content(passed.dispatched.text(), salt=SALT) == wire_text(value), (
        f"a payload at {ratio:.2f}% substituted at a configured bar of {low}"
    )
    subbed = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(high)})
    assert framed_content(subbed.dispatched.text(), salt=SALT) == toons.dumps(value), (
        f"a payload at {ratio:.2f}% passed through at a configured bar of {high}"
    )
