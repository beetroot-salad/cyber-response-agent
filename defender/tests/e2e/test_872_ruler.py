"""#872 — the ruler and the bar (`d1`, `d3`, `d24`, `d25`, `d45`, `d58`)."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("pydantic_ai")

# `toons` ships in the `runtime` EXTRA, so an install without it is a supported one —
# and a bare module-scope import there is a COLLECTION error, which pytest answers by
# interrupting the whole session. Guarded like `pydantic_ai` above it.
toons = pytest.importorskip("toons")  # noqa: E402

from defender.tests.e2e._toon872 import (  # noqa: E402
    agent_run,
    corpus,
    delivered_percent,
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
    """A committed fixture arm on the requested side of a CONFIGURED bar."""
    for name, columnar in sorted(corpus().items()):
        for arm, value in (("dict-rows", toon_rows(columnar)), ("columnar", columnar)):
            if (delivered_percent(value) <= bar) is clearing:
                return f"{name}/{arm}", value
    raise AssertionError(f"no committed fixture is {'under' if clearing else 'over'} bar {bar}")


def test_foreign_dict_row_clearing_the_bar_reaches_the_model_as_toon() -> None:
    """A dict-row result from a toolset defender does not own, whose TOON form clears the
    CONFIGURED bar, arrives at the model as TOON — read off the `ToolReturnPart` the model
    received, not off an internal variable."""
    for bar in (85, 90):
        label, value = _pick(bar, clearing=True)
        out = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(bar)})
        view = framed_content(out.dispatched.text())
        assert view == toons.dumps(value), f"{label} did not reach the model as TOON at bar {bar}"
        assert toons.loads(view) == value


def test_a_fixture_whose_verdict_differs_between_rulers_takes_the_wire_rulers_verdict() -> None:
    """At the bar the gate is configured with, a fixture whose verdict differs between
    `json.dumps` and the wire serializer takes the WIRE ruler's verdict."""
    overhead = frame_overhead()

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
        substituted = framed_content(out.dispatched.text()) != wire_text(value)
        assert substituted == _verdict(value, wire_bytes(value), bar), (
            f"{label} took the json.dumps ruler's verdict at bar {bar}"
        )


def test_a_cjk_payload_is_measured_in_bytes_not_characters() -> None:
    """Both sides of the comparison are measured in UTF-8 BYTES, not characters."""
    bar = 85
    overhead = frame_overhead()

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
    substituted = framed_content(out.dispatched.text()) != wire_text(value)
    assert substituted == by_bytes, (
        f"the CJK payload was measured in characters (verdict {by_chars}), not in UTF-8 bytes"
    )


def test_a_payload_just_under_the_configured_bar_substitutes_and_one_just_over_it_passes_through() -> None:
    """At a configured bar, a payload just under it substitutes and one just over it passes
    through — at MORE THAN ONE configured bar, and asserting NO CONSTANT."""
    for bar in (85, 90):
        env = {MAX_PERCENT_ENV: str(bar)}
        under_label, under = _pick(bar, clearing=True)
        over_label, over = _pick(bar, clearing=False)

        subbed = agent_run(toolset=foreign_toolset(under), env=env)
        assert framed_content(subbed.dispatched.text()) == toons.dumps(under), (
            f"{under_label} did not substitute at bar {bar}"
        )

        passed = agent_run(toolset=foreign_toolset(over), env=env)
        assert framed_content(passed.dispatched.text()) == wire_text(over), (
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
    assert framed_content(passed.dispatched.text()) == wire_text(value), (
        f"a payload at {ratio:.2f}% substituted at a configured bar of {low}"
    )
    subbed = agent_run(toolset=foreign_toolset(value), env={MAX_PERCENT_ENV: str(high)})
    assert framed_content(subbed.dispatched.text()) == toons.dumps(value), (
        f"a payload at {ratio:.2f}% passed through at a configured bar of {high}"
    )
