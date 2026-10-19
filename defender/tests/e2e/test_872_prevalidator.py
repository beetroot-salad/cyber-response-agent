"""#872 — M7 pre-validator: hostile payloads (bad keys, cycles, depth/node-budget bombs, NUL) are refused before the encoder runs (observed by a spy encoder call count); real-encoder cases run in a child interpreter."""
from __future__ import annotations

import collections
import json
from collections.abc import Mapping

import pytest

pytest.importorskip("pydantic_ai")

toons = pytest.importorskip("toons")  # noqa: E402

from defender.tests.e2e._toon872 import (  # noqa: E402
    DOOMED_CHILD_MEM_LIMIT_MB,
    EncoderFault,
    SpyEncoder,
    agent_run,
    corpus,
    delivered_percent,
    foreign_toolset,
    framed_content,
    run_isolated,
    toon_rows,
    wire_text,
)

pytestmark = pytest.mark.e2e

MAX_DEPTH_ENV = "DEFENDER_TOON_GATE_MAX_DEPTH"
MAX_NODES_ENV = "DEFENDER_TOON_GATE_MAX_NODES"
MAX_PERCENT_ENV = "DEFENDER_TOON_GATE_MAX_PERCENT"

def _sealed() -> SpyEncoder:
    return SpyEncoder(EncoderFault(dumps_returns="<the encoder must not have been called>"))


def _refused_and_unchanged(label: str, value, *, encoder: SpyEncoder | None = None) -> SpyEncoder:
    """Drive a refusal and assert BOTH observables — the count AND what the model got."""
    spy = encoder if encoder is not None else _sealed()
    gated = agent_run(toolset=foreign_toolset(value), encoder=spy)
    assert spy.dumps_calls == 0, f"{label} reached the encoder"
    assert spy.loads_calls == 0, f"{label} was decoded"
    if gated.error is None:
        assert framed_content(gated.dispatched.text()) == wire_text(value), (
            f"{label} was refused, but the model did not get the tool's own wire bytes"
        )
    else:
        ungated = agent_run(toolset=foreign_toolset(value), capabilities=False)
        assert type(gated.error).__name__ == type(ungated.error).__name__, (
            f"{label}: the gate changed the class of a pre-existing serialization failure"
        )
    return spy


class _Mapping(Mapping):
    """A `collections.abc.Mapping` the encoder does not enter (`S2`)."""

    def __init__(self, data: dict) -> None:
        self._data = data

    def __getitem__(self, key):  # noqa: ANN001, ANN204
        return self._data[key]

    def __iter__(self):  # noqa: ANN204
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


class _Dict(dict):
    """A `dict` SUBCLASS. `toons.dumps` recurses into it — an implementation keying on
    `type(v) is dict` passes every other case here and fails this one."""


class _List(list):
    """A `list` SUBCLASS, for the same reason."""


def _nest(depth: int) -> dict:
    value: dict = {"leaf": 1}
    for _ in range(depth - 1):
        value = {"n": value}
    return value


def test_a_non_str_or_non_utf8_mapping_key_is_refused_and_the_encoder_is_never_called() -> None:
    """A mapping key that is not a `str`, and a `str` key that is not UTF-8 encodable, are
    refused before the encoder is called — in EVERY structural position."""
    class StrKey(str):
        pass

    surrogate = "\ud800"
    refused = {
        "non-str, mapping position": {1: "x"},
        "non-str, row position": {"rows": [{1: "x", "z": 2}]},
        "surrogate, mapping position": {surrogate: "x"},
        "surrogate, row position": {"rows": [{surrogate: "x", "z": 2}]},
    }
    for label, value in refused.items():
        try:
            baseline = wire_text(value)
        except BaseException as e:  # noqa: BLE001 — the un-gated run's own fault, whatever it is
            baseline = None
            baseline_error: BaseException | None = e
        else:
            baseline_error = None

        spy = _sealed()
        out = agent_run(toolset=foreign_toolset(value), encoder=spy)
        assert spy.dumps_calls == 0, f"{label} reached the encoder"
        if baseline_error is None:
            assert out.error is None, f"{label} escaped the guard"
            assert framed_content(out.dispatched.text()) == baseline
        else:
            assert out.error is not None, (
                f"{label}: the un-gated run cannot serialize this payload "
                f"({type(baseline_error).__name__}), so a gated run that DELIVERS it is the "
                "gate doing better than the baseline, which d47 forbids"
            )

    admitted = {"rows": [{StrKey("a"): i, "b": f"pad-{i}"} for i in range(40)]}
    out = agent_run(toolset=foreign_toolset(admitted))
    assert out.encoder.dumps_calls == 1, (
        "a `str` SUBCLASS key was refused — the predicate is `isinstance`, not `type(k) is str`"
    )


def test_a_container_reachable_from_itself_is_refused_and_the_encoder_is_never_called() -> None:
    """A container reachable from itself is refused before the encoder, in every dict/list
    placement the hazard is reachable through."""
    placements = {}
    a: dict = {"self": None}
    a["self"] = a
    placements["direct dict self-reference"] = a

    b: list = []
    b.append(b)
    placements["direct list self-reference"] = {"rows": b}

    c: dict = {"x": {}}
    c["x"]["back"] = c
    placements["indirect dict cycle"] = c

    d: dict = {"rows": [{"a": 1}]}
    d["rows"].append(d)
    placements["cycle through a row list"] = d

    e: dict = {"outer": {"inner": []}}
    e["outer"]["inner"].append(e["outer"])
    placements["cycle inside a nested list"] = e

    f: list = [{"k": None}]
    f[0]["k"] = f
    placements["cycle from a row back to its list"] = f

    g: dict = {"a": {"b": {"c": None}}}
    g["a"]["b"]["c"] = g["a"]
    placements["cycle to a mid-path container"] = g

    for label, value in placements.items():
        _refused_and_unchanged(label, value)


def test_the_validators_container_set_equals_the_encoders() -> None:
    """The walk recurses into exactly `dict` and `list`, SUBCLASSES INCLUDED, and enters nothing
    else — the totality argument, made executable."""
    Point = collections.namedtuple("Point", "k")
    hazard = {1: "not a str key"}

    not_entered = {
        "tuple": {"x": (hazard,)},
        "abc.Mapping": {"x": _Mapping(hazard)},
        "deque": {"x": collections.deque([hazard])},
        "namedtuple": {"x": Point(k=hazard)},
        "object attribute": {"x": type("Holder", (), {"k": hazard})()},
    }
    for label, value in not_entered.items():
        assert isinstance(toons.dumps(value), str), (
            f"the encoder now ENTERS a {label}; M7's traversal set has moved under this demand"
        )
        out = agent_run(toolset=foreign_toolset(value))
        assert out.encoder.dumps_calls == 1, (
            f"a hazard inside a {label} was refused, but the encoder never enters one"
        )
        if out.error is None:
            assert framed_content(out.dispatched.text()) == wire_text(value), (
                f"a hazard inside a {label} was ADMITTED and then substituted over a view "
                "that lost it"
            )

    entered = {
        "dict subclass": {"rows": [_Dict(hazard)]},
        "list subclass": {"rows": _List([hazard])},
    }
    for label, value in entered.items():
        _refused_and_unchanged(f"a hazard inside a {label}", value)


def test_a_payload_one_level_over_the_configured_depth_cap_is_refused_and_one_under_it_is_admitted() -> None:
    """One level over the configured depth cap is refused before the encoder; one level under it
    is admitted."""
    for cap in (8, 16):
        env = {MAX_DEPTH_ENV: str(cap)}
        over = _nest(cap + 1)
        spy = _sealed()
        out = agent_run(toolset=foreign_toolset(over), encoder=spy, env=env)
        assert spy.dumps_calls == 0, f"depth {cap + 1} reached the encoder at a cap of {cap}"
        assert framed_content(out.dispatched.text()) == wire_text(over)

        under = _nest(cap - 1)
        admitted = agent_run(toolset=foreign_toolset(under), env=env)
        assert admitted.encoder.dumps_calls == 1, (
            f"depth {cap - 1} was refused at a cap of {cap} — the cap is not the configured value"
        )


def test_a_shallow_acyclic_payload_whose_node_count_exceeds_the_budget_is_refused() -> None:
    """A shallow, acyclic payload whose node count exceeds the configured budget is refused
    before the encoder, and the WALK'S OWN COST is bounded by the same budget."""
    gated_child = f'''
import json
from defender.tests.e2e import _toon872 as T

value = {{"leaf": 1}}
for _ in range(16):
    value = {{"a": value, "b": value}}

spy = T.SpyEncoder(T.EncoderFault(dumps_returns="<must not be called>"))
out = T.agent_run(toolset=T.foreign_toolset(value), encoder=spy,
                  env={{"{MAX_NODES_ENV}": "1000", "{MAX_DEPTH_ENV}": "64"}})
print(json.dumps({{
    "dumps_calls": spy.dumps_calls,
    "raised": out.error is not None,
    "content_is_wire": T.framed_content(out.dispatched.text()) == T.wire_text(value),
}}), flush=True)
del value, spy, out

value = {{"leaf": 1}}
for _ in range(28):
    value = {{"a": value, "b": value}}
T.agent_run(toolset=T.foreign_toolset(value), capabilities=True)
'''
    gated_bomb = run_isolated(gated_child, timeout=90.0, mem_limit_mb=DOOMED_CHILD_MEM_LIMIT_MB)
    assert not gated_bomb.timed_out, (
        "the walk did not terminate on the expansion bomb — a validator with no node budget "
        "visits 2**16 nodes before it decides anything, and 2**28 at the k=28 arm"
    )
    first = [ln for ln in gated_bomb.stdout.splitlines() if ln.startswith("{")]
    assert first, f"the k=16 probe never reported: {gated_bomb.stderr[-800:]}"
    result = json.loads(first[0])
    assert result["dumps_calls"] == 0, "the expansion bomb reached the encoder"
    assert result["raised"] is False
    assert result["content_is_wire"] is True

    plain_child = (
        "from defender.tests.e2e import _toon872 as T\n"
        'value = {"leaf": 1}\n'
        "for _ in range(28):\n"
        '    value = {"a": value, "b": value}\n'
        "T.agent_run(toolset=T.foreign_toolset(value), capabilities=False)\n"
    )
    plain_bomb = run_isolated(plain_child, timeout=90.0, mem_limit_mb=DOOMED_CHILD_MEM_LIMIT_MB)
    assert not plain_bomb.timed_out, "the un-gated arm hung, so the comparison below is unsound"
    assert (gated_bomb.returncode == 0) == (plain_bomb.returncode == 0), (
        "the gate changed whether a 2**28-node payload takes the process down; it is "
        "undeliverable either way, and the gate may not be worse OR better than the baseline"
    )


def _shared_leaf_dag(*, width: int, share: int) -> dict:
    """One leaf dict of `width` SCALAR entries, shared pairwise `share` levels deep."""
    value: dict = {f"k{i}": i for i in range(width)}
    for _ in range(share):
        value = {"a": value, "b": value}
    return value


def test_a_payload_under_the_budget_in_containers_and_over_it_in_values_is_refused() -> None:
    """The budget charges EVERY VALUE the walk visits, scalars included — not only the dict/list
    containers it recurses into."""
    for budget, over_width, under_width in ((1000, 400, 20), (5000, 1000, 100)):
        env = {MAX_NODES_ENV: str(budget), MAX_DEPTH_ENV: "64"}

        over = _shared_leaf_dag(width=over_width, share=5)
        spy = _sealed()
        out = agent_run(toolset=foreign_toolset(over), encoder=spy, env=env)
        assert spy.dumps_calls == 0, (
            f"a payload holding 63 containers and {32 * over_width} scalar values reached the "
            f"encoder at a budget of {budget} — the budget is counting containers, not values"
        )
        assert framed_content(out.dispatched.text()) == wire_text(over), (
            "the over-budget payload was refused, but the model did not get the tool's own "
            "wire bytes"
        )

        under = _shared_leaf_dag(width=under_width, share=5)
        admitted = agent_run(toolset=foreign_toolset(under), env=env)
        assert admitted.encoder.dumps_calls == 1, (
            f"a payload of 63 containers and {32 * under_width} scalar values was refused at a "
            f"budget of {budget} — the budget is not the configured value"
        )


def test_one_leaf_object_referenced_three_times_encodes_round_trips_and_substitutes() -> None:
    """One leaf dict referenced three times in a row list encodes, round-trips and SUBSTITUTES —
    it is not refused."""
    leaf = {"x": 1, "y": 2}
    value = {"values": [leaf, leaf, leaf]}
    assert toons.loads(toons.dumps(value)) == value, (
        "shared structure no longer round-trips; this control has stopped controlling"
    )
    out = agent_run(toolset=foreign_toolset(value))
    assert out.encoder.dumps_calls == 1, "benign shared structure was refused before the encoder"
    assert framed_content(out.dispatched.text()) == toons.dumps(value), (
        "benign shared structure was not substituted"
    )


def test_the_guard_refuses_no_committed_fixture_and_changes_no_verdict() -> None:
    """Across both arms of all 40 committed fixtures the guard refuses NOTHING, and the gate's
    verdict with the guard installed is identical to the un-guarded bar's on 40 of 40."""
    fixtures = corpus()
    assert len(fixtures) == 40, "the vendored corpus is no longer the 40 committed fixtures"
    bar = 85
    for name, columnar in sorted(fixtures.items()):
        for arm, value in (("columnar", columnar), ("dict-rows", toon_rows(columnar))):
            out = agent_run(toolset=foreign_toolset(value),
                            env={MAX_PERCENT_ENV: str(bar)})
            assert out.encoder.dumps_calls == 1, f"{name} {arm} was refused by the guard"
            substituted = framed_content(out.dispatched.text()) != wire_text(value)
            assert substituted == (delivered_percent(value) <= bar), (
                f"{name} {arm}: the guarded verdict differs from the un-guarded bar's"
            )


def test_every_input_class_kills_or_survives_the_run_identically_with_and_without_the_gate() -> None:
    """For every input class in the probed battery the PROCESS outcome — survives or dies, and
    how — is identical with the gate installed and with it absent."""
    battery = {
        "brace in key, row position": 'value = {"rows": [{"}": i, "z": i} for i in range(20)]}',
        "benign dict rows": 'value = {"rows": [{"a": i, "b": "pad-%d" % i} for i in range(40)]}',
        "plain string": 'value = "a plain string"',
        "non-str mapping key": 'value = {1: "x"}',
        "surrogate mapping key": 'value = {"\\ud800": "x"}',
        "circular container": 'value = {"self": None}\nvalue["self"] = value',
        "deep acyclic container": (
            'value = {"leaf": 1}\n'
            "for _ in range(50000):\n"
            '    value = {"n": value}'
        ),
    }
    def child_for(gated: bool) -> str:
        return (
            "import json, sys\n"
            "sys.setrecursionlimit(100000)\n"
            "from defender.tests.e2e import _toon872 as T\n"
            f"BATTERY = {battery!r}\n"
            "for label, build in BATTERY.items():\n"
            "    ns = {}\n"
            "    exec(build, ns)\n"
            "    value = ns['value']\n"
            f"    out = T.agent_run(toolset=T.foreign_toolset(value), capabilities={gated})\n"
            "    try:\n"
            "        text, text_raised = (out.dispatched.texts() or [None])[0], False\n"
            "    except BaseException:\n"
            "        text, text_raised = None, True\n"
            "    print(json.dumps({'label': label, 'raised': out.error is not None,\n"
            "                      'type': type(out.error).__name__ if out.error else None,\n"
            "                      'text_raised': text_raised,\n"
            "                      'text': text}), flush=True)\n"
        )

    arms = {gated: run_isolated(child_for(gated), timeout=240.0) for gated in (True, False)}
    gated_out, plain_out = arms[True], arms[False]
    assert not gated_out.timed_out, "the battery hung with the gate"
    assert not plain_out.timed_out, "the battery hung without the gate"
    assert gated_out.signalled == plain_out.signalled, (
        "the gate changed whether the process was killed by a signal"
    )
    assert (gated_out.returncode == 0) == (plain_out.returncode == 0), (
        "the gate changed whether the battery survived"
    )

    def results(outcome) -> dict:
        rows = (json.loads(line) for line in outcome.stdout.splitlines() if line.startswith("{"))
        return {r["label"]: r for r in rows}

    g_res, p_res = results(gated_out), results(plain_out)
    for label in battery:
        assert (label in g_res) == (label in p_res), (
            f"{label}: the gate changed whether the run survived"
        )
        if label in g_res:
            g, p = g_res[label], p_res[label]
            assert g["raised"] == p["raised"], f"{label}: the gate changed whether it raised"
            assert g["type"] == p["type"], f"{label}: the gate changed the class of the failure"
    brace = "brace in key, row position"
    assert brace in g_res, "a `}`-in-key payload stopped delivering with the gate"
    assert brace in p_res, "a `}`-in-key payload stopped delivering without the gate"

    assert ("panicked at" in gated_out.stderr) == ("panicked at" in plain_out.stderr), (
        "a Rust panic line became gate-attributable — it is ambient to this harness today, so "
        "an asymmetry here is a real change in what the gate does to the process"
    )
    # The gate ALWAYS frames, so raw stdout differs by construction (and by run id). What must
    # match is the framed CONTENT against the un-gated text — the bytes the model reads.
    g_text, p_text = g_res[brace], p_res[brace]
    assert not g_text["text_raised"], "harvesting the gated arm's text raised"
    assert not p_text["text_raised"], "harvesting the un-gated arm's text raised"
    assert framed_content(g_text["text"]) == p_text["text"], (
        "the gate changed the model-visible text on a `}`-in-key payload"
    )


def test_a_payload_carrying_a_raw_nul_is_refused_and_the_encoder_is_never_called() -> None:
    """A payload carrying a raw NUL in any string is refused before the encoder, and the model-
    visible text is byte-identical to the un-gated run's."""
    nul = chr(0)
    value = {"rows": [{"a": "x" + nul + "y", "b": i} for i in range(20)]}
    assert nul in toons.dumps(value), (
        "the encoder no longer emits the NUL raw and unquoted, so the model-visible "
        "divergence this refusal exists for has changed shape"
    )
    assert delivered_percent(value) <= 85, (
        "the NUL payload no longer clears the shipped bar, so it would pass through anyway "
        "and this refusal would be untested"
    )

    spy = _sealed()
    out = agent_run(toolset=foreign_toolset(value), encoder=spy)
    assert spy.dumps_calls == 0, "a raw NUL reached the encoder"
    delivered = out.dispatched.text()
    assert framed_content(delivered) == wire_text(value)
    assert nul not in delivered, "a raw U+0000 reached the model"
    assert "\\u0000" in delivered, "the escaped form the un-gated run sends is missing"
