"""#872 — M7, the pre-validator, and O9's three-part oracle
(`d48`, `d49`, `d50`, `d51`, `d52`, `d53`, `d54`, `d57`, `d64`, `d81`).

O9 replaces r2's fail-safe sentence, which was REFUTED END TO END: a real capability ->
WrapperToolset -> Agent with a foreign tool returning `{1: 'alpha'}` exited 1 with a
`PanicException` that walked straight through `except Exception`, and one returning a
self-referential dict was KILLED BY SIGNAL 11.

THE OBSERVABLE IS THE SPY ENCODER'S CALL COUNT, and it is not a convenience. "The gate
returned the original" is satisfied by an implementation that crashed the encoder in a
subprocess and recovered, which is not what M7 says; a refusal and a fault look identical
from outside the gate, which is exactly how r2's arm shipped unimplementable.

AND THE SPY IS THE CONTAINMENT. Every case here whose real encoding would end the process
hands the gate a spy with a CANNED return, so the Rust encoder is unreachable from the
assertion even if the implementation under test walks the value wrongly. The two demands that
mean nothing without the real thing — `d57`'s process parity and `d52`'s expansion bomb —
run in a child interpreter with a wall clock.
"""
from __future__ import annotations

import collections
import json
from collections.abc import Mapping

import pytest

pytest.importorskip("pydantic_ai")

# `toons` ships in the `runtime` EXTRA, so an install without it is a supported one —
# and a bare module-scope import there is a COLLECTION error, which pytest answers by
# interrupting the whole session. Guarded like `pydantic_ai` above it.
toons = pytest.importorskip("toons")  # noqa: E402

from defender.tests.e2e._toon872 import (  # noqa: E402
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

#: A spy that CANNOT reach the real encoder. Every refusal case uses it, because the whole
#: point of those cases is that the encoder must not be called — and if the implementation
#: calls it anyway, the failure must be a red assertion rather than SIGSEGV.
def _sealed() -> SpyEncoder:
    return SpyEncoder(EncoderFault(dumps_returns="<the encoder must not have been called>"))


def _refused_and_unchanged(label: str, value, *, encoder: SpyEncoder | None = None) -> SpyEncoder:
    """Drive a refusal and assert BOTH observables — the count AND what the model got.

    A spy's call count is an internal variable, and `rules.md` is explicit that an oracle
    reading an internal is not an oracle (`91-blind.md` red flag 1: several refusal tests
    asserted the count alone, so a suite that regressed to "encoder called / not called" while
    delivering the wrong text would still have passed them). The count is still necessary —
    a refusal and a fault are indistinguishable from outside the gate — so it is kept and
    PAIRED with the model-visible half.

    The model-visible half is stated as a differential because a refused payload is not always
    deliverable: three of the classes here (`abc.Mapping`, `deque`, an object attribute) carry
    a non-`str` key the WIRE serializer itself raises on, so the un-gated run dies too and O2's
    pin is that the gate does no worse (`d47`). Where the baseline serializes, the delivered
    content is its bytes; where it raises, the failure class is the same one."""
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
    refused before the encoder is called — in EVERY structural position.

    The admission rule has two halves and both are pinned. `isinstance(k, str)`, SUBCLASSES
    INCLUDED — `type(k) is str` is the wrong predicate and a `str` subclass key must still be
    ADMITTED — and `k.encode('utf-8')` succeeding, which a lone surrogate fails.

    FOUR STRUCTURAL POSITIONS, because the fault class is not stable across them (`S1`, 21 key
    types x 4 positions): a non-`str` key raises `PanicException` in mapping position and a
    plain `TypeError` in row position, and a surrogate raises `PanicException` /
    `UnicodeEncodeError` the same way. A test that placed the hazard at one position only would
    pass over an implementation that guards one encoder path.

    WHAT REFUSAL MEANS HERE, CORRECTED. This asserted `out.error is None` for all four, i.e.
    that every refused payload still delivers. That is unachievable for the surrogate pair and
    demanding it would require the gate to do BETTER than the un-gated run, which `d47` forbids
    in as many words. Executed against the shipped serializer: a non-`str` key serializes fine
    (pydantic-core coerces `{1: "x"}` to `{"1":"x"}`), while a lone surrogate raises
    `PydanticSerializationError` from `ToolReturnPart.model_response_str` — the ruler the gate
    and the baseline share. So a surrogate payload is undeliverable by ANY path, gate or no
    gate, and the gate's job is to reach that failure without having called the encoder.

    The demand this test exists for is untouched and is the one asserted in every position:
    the encoder is NEVER reached. What is now derived rather than assumed is whether the run
    then survives — read off the baseline serializer, so the gate is pinned to parity with it
    instead of to a constant that happened to hold for two of the four cases.
    """
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
    placement the hazard is reachable through.

    THE ONE REFUSAL THAT IS NOT AN OPTIMISATION. `toons.dumps` does not raise on a
    self-referential container: it SIGSEGVs, and no `except` clause of any breadth catches a
    signal (`R11`, four shapes, all killed by signal 11). That is why the encoder here is
    sealed — a canned return, unable to reach the real Rust encoder — so a wrong implementation
    fails this test rather than ending the process running it.

    The encoder call count is one of the two observables: "the gate returned the original" is
    satisfied by an implementation that crashed the encoder in a subprocess and recovered,
    which is not what M7 says. It is PAIRED with what the model got, because a count alone is
    an internal — for a cycle the wire serializer raises too, so the model-visible half is the
    differential `d47` states (`_refused_and_unchanged`). `d53` is this demand's anti-vacuity
    control — a gate that refuses everything passes this and fails that one.
    """
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
    """The walk recurses into exactly `dict` and `list`, SUBCLASSES INCLUDED, and enters
    nothing else — the totality argument, made executable.

    TWO-SIDED, and that is what stops M7 being a guess about someone else's recursion. A
    hazard inside a tuple, a `collections.abc.Mapping`, a `deque`, a dataclass, a namedtuple,
    a generator or an object attribute is NOT refused, because the encoder never enters those
    containers — it emits them as `null` — and refusing them would be a false positive over an
    input the encoder handles fine. A hazard inside a `dict` or `list` SUBCLASS IS refused,
    because the encoder does enter those: executed here, `dumps` raises `PanicException` on a
    dict subclass carrying a non-`str` key and a plain `TypeError` on a list subclass.

    An implementation keying on `type(v) is dict` passes the first half and fails the second,
    which is exactly the drift this demand exists to catch. Both halves are driven and observed
    at the SEAM AND AT THE MODEL, never enumerated off a type registry: the admitted half is
    read as an encode plus the delivered text, the refused half through
    `_refused_and_unchanged`, so neither half rests on a call count alone.
    """
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
        # The admitted half read at the model as well: the container the encoder emits as
        # `null` cannot carry the payload back, so M3 rejects and the JSON arm is what the
        # model reads — where the baseline serializes it at all.
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
    """One level over the configured depth cap is refused before the encoder; one level under
    it is admitted. NO DEPTH CONSTANT IS ASSERTED.

    That is the load-bearing half. `S4` executed the reason: the crash depth scales with the
    thread's stack — 8 MB dies at 12 000, 1 MB at 2 000, 512 KB at 900 — and
    `threading.stack_size()` reports 0 in this runtime, so a test pinning a specific safe depth
    would be pinning a property of the machine it happens to run on. §7 r6 chose 64 as an
    operator judgment; the suite is parameterized on whatever cap is configured and is run at
    more than one, so an operator moving the number breaks nothing here.

    `S3` is why the cap exists at all: the payload is ACYCLIC, so `d49`'s predicate does not
    see it, and a deep acyclic payload segfaults the encoder exactly as a cycle does.
    """
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
    before the encoder, and the WALK'S OWN COST is bounded by the same budget.

    THE BUDGET IS NOT THE DEPTH CAP, and the fixture is what proves it: `S7`'s expansion bomb
    is 29 objects sharing children pairwise at depth 28, so a depth cap admits it, it is
    neither a cycle nor a bad key nor deep, and `d48`, `d49` and `d51` all pass it through —
    while the encoder reaches 132 MB at k=20 and takes the process at k=24.

    A validator WITHOUT a node budget cannot even terminate on it: it would visit 2**k nodes
    itself. That is why this runs in a child interpreter with a wall clock AND an address-space
    ceiling — a hang is not a test result, and neither is the OOM killer, which is what an
    unbounded walk here reaches: it is a machine-wide event that can take a process other than
    this child. `run_isolated` caps the child so the same input fails as a bounded
    `MemoryError` the parent can read. An implementation with no budget hangs or exhausts its
    ceiling here rather than failing quietly. The budget is configured low, so a correct walk
    stops after a bounded number of visits whatever k is, which is the second reason M7
    precedes the encoder rather than wrapping it.

    TWO ARMS, BECAUSE ONE k CANNOT CARRY BOTH HALVES. This drove k=28 and then asserted the
    child exits 0. It cannot: a 2**28-node payload is UNDELIVERABLE, and not by the gate's
    doing — the passthrough has to serialize what it declined to encode, and so does the
    un-gated run, and both need >2 GiB. Executed both ways at k=28: `returncode -6`, SIGABRT,
    identically with the capability installed and absent. Demanding survival there asked the
    gate to beat the baseline, which `d47` forbids.

    So the refusal is observed at k=16 — 65_536 containers against a budget of 1_000, far
    enough over to prove the walk stopped early, small enough that the passthrough's own
    serialization is trivial — and k=28 is kept for the half only it can prove: that the walk
    TERMINATES instead of visiting 2**k nodes, plus parity of the death that follows.
    """
    child = f'''
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
}}))
'''
    outcome = run_isolated(child, timeout=90.0)
    assert not outcome.timed_out, (
        "the walk did not terminate on the expansion bomb — a validator with no node budget "
        "visits 2**16 nodes before it decides anything"
    )
    assert outcome.returncode == 0, f"the child died: {outcome.stderr[-800:]}"
    result = json.loads(outcome.stdout.strip().splitlines()[-1])
    assert result["dumps_calls"] == 0, "the expansion bomb reached the encoder"
    assert result["raised"] is False
    assert result["content_is_wire"] is True

    # The k=28 arm: the walk must TERMINATE rather than visit 2**28 nodes. The process then
    # dies serializing a payload no serializer can hold — so what is asserted is termination
    # (not a hang) and PARITY of that death, never survival.
    bomb = (
        "from defender.tests.e2e import _toon872 as T\n"
        'value = {"leaf": 1}\n'
        "for _ in range(28):\n"
        '    value = {"a": value, "b": value}\n'
        "T.agent_run(toolset=T.foreign_toolset(value), capabilities=%s)\n"
    )
    gated_bomb = run_isolated(bomb % "True", timeout=90.0)
    plain_bomb = run_isolated(bomb % "False", timeout=90.0)
    assert not gated_bomb.timed_out, (
        "the guarded walk did not terminate on a 2**28-node payload — the node budget is not "
        "bounding the walk's own cost, which is the half a smaller k cannot prove"
    )
    assert not plain_bomb.timed_out, "the un-gated arm hung, so the comparison below is unsound"
    assert (gated_bomb.returncode == 0) == (plain_bomb.returncode == 0), (
        "the gate changed whether a 2**28-node payload takes the process down; it is "
        "undeliverable either way, and the gate may not be worse OR better than the baseline"
    )


def _shared_leaf_dag(*, width: int, share: int) -> dict:
    """One leaf dict of `width` SCALAR entries, shared pairwise `share` levels deep.

    CONTAINERS: `2**(share+1) - 1`, and it does not move with `width`.
    VALUES:     the containers plus `2**share * width` scalars, and it moves with nothing else.

    That separation is the whole fixture: two payloads built from it can carry an identical
    container count and differ by orders of magnitude in what the encoder emits.
    """
    value: dict = {f"k{i}": i for i in range(width)}
    for _ in range(share):
        value = {"a": value, "b": value}
    return value


def test_a_payload_under_the_budget_in_containers_and_over_it_in_values_is_refused() -> None:
    """The budget charges EVERY VALUE the walk visits, scalars included — not only the
    dict/list containers it recurses into. NO NODE CONSTANT IS ASSERTED.

    THE TWO PAYLOADS IN EACH PASS CARRY THE SAME 63 CONTAINERS and differ only in a count a
    container-only budget never charges, so an implementation that counts containers admits
    the first and this test is the only thing in the suite that sees it. `d52`'s bomb does
    not: at its configured budget of 1000 both readings refuse it, because that fixture's
    containers are the thing that expands.

    WHY IT MATTERS, MEASURED. `toons` emits one line per value with the full indent on it —
    at depth 64 that is 136 bytes for a scalar entry against ~9 in JSON — so the output is
    proportional to VALUES, not containers. A payload of 64 objects (a 300-entry leaf shared
    15 levels deep, sunk to depth 64) is admitted by a container-counting walk at 65 583
    containers and then aborts the process inside the Rust encoder: `memory allocation of
    2147483648 bytes failed`, SIGABRT, rc 134. It is an ABORT, not a Python exception, so
    `d55`'s `BaseException` arm never runs. The un-gated arm of the same payload returns
    CLEANLY under the identical 2 GB ceiling (121 MB dispatched, 1520 MB peak), so a
    container-only budget breaks `O9(a)`'s parity outright.

    That process death is a CLAIM (`cE2`) and not a case here, for the reason the expansion
    bomb is not in `d57`'s battery: reaching it needs >130 MB of wire text on the refusal
    path, which is a risk to the test host rather than a test result. What is driven here is
    the predicate that keeps the encoder from ever seeing it.

    `r3_validator.prevalidate` — the instrument behind `S8`, `S9` and §7 r6's 100 000 —
    already counts this way: its `budget -= 1` sits ABOVE the container check, which is why
    `S9` reports 517 nodes on a corpus whose deepest fixture holds 108 containers.
    """
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

        # The anti-vacuity control, and it is the half that makes the assertion above mean
        # what it says: the SAME 63 containers with the values under the budget is ADMITTED,
        # so the refusal is charged to the value count and not to the shape.
        under = _shared_leaf_dag(width=under_width, share=5)
        admitted = agent_run(toolset=foreign_toolset(under), env=env)
        assert admitted.encoder.dumps_calls == 1, (
            f"a payload of 63 containers and {32 * under_width} scalar values was refused at a "
            f"budget of {budget} — the budget is not the configured value"
        )


def test_one_leaf_object_referenced_three_times_encodes_round_trips_and_substitutes() -> None:
    """One leaf dict referenced three times in a row list encodes, round-trips and
    SUBSTITUTES — it is not refused.

    THE ANTI-VACUITY CONTROL FOR `d49`, and the demand that fails the cheap wrong
    implementation. M7's cycle check is PATH-SCOPED: a container is refused when it is
    reachable from ITSELF on the current path, not when it has been seen before. A global
    seen-set passes `d49` and refuses this payload, which encodes to `values[3]{x,y}:` and
    round-trips exactly (`S7`, executed).

    Ordinary foreign data shares structure. A gate that refuses it is a gate that refuses
    everything interesting while passing its own safety demand.
    """
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
    verdict with the guard installed is identical to the un-guarded bar's on 40 of 40.

    O9(c) IS THE CLAUSE THAT STOPS THE OTHER TWO BEING BOUGHT BY REFUSING EVERYTHING, and the
    second half is what makes it a survival demand rather than a smoke test: a guard that
    refused a fixture would not merely cost a saving, it would change what the model reads on
    real data.

    The fixtures are VENDORED into the suite (§7 r10, P5 = A): no import from `experiments/`,
    no `sys.path` mutation, and the re-zip that builds the dict-row arm is the eight-line
    helper copied with them, because keeping the full `columns` dicts is what every published
    ratio depends on.

    THE UN-GUARDED BAR IS THE DELIVERED-BYTES ONE (`d3`), because that is the bar this gate
    has: three of the eighty arms (`fx-19`, `fx-23`, `fx-24`, dict-rows) clear on encoder bytes
    and fail once the frame is counted, so spelling the comparison on encoder bytes would make
    this demand assert a verdict `d3` forbids on three fixtures — the guard would be blamed for
    a difference the ruler made.
    """
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
    how — is identical with the gate installed and with it absent.

    THE DEMAND THAT KEEPS O9 HONEST INSTEAD OF OVER-PROMISING, and it is a PARITY demand
    precisely because it is not an immortality one. Three probed classes still kill the run:
    a circular container and a very deep container die in `PydanticSerializationError` inside
    pydantic-ai's own tool-return serialization, and a lone surrogate in a mapping key does the
    same — IDENTICALLY with the gate installed and with no capability at all. r2's failure was
    the over-promise "fails safe by construction"; the replacement is stated as a differential.

    ONE PROBED DIVERGENCE, AND IT IS ASSERTED RATHER THAN ASSERTED AWAY: on a `}`-in-key
    payload the guarded run prints a Rust panic line to STDERR that the un-gated run does not.
    Model-visible text is identical; process stderr is not.

    THE PROBE MUST NOT CREATE THE DIVERGENCE IT MEASURES. The child used to harvest its result
    with a bare `out.dispatched.texts()`, and that call SERIALIZES the tool return — so on an
    unserializable payload (a lone surrogate in a mapping key, a circular container) the probe
    itself raised, killing the un-gated child while the gated one exited cleanly, because the
    gated arm's text is already a plain framed `str` with nothing left to serialize. The
    measurement, not the gate, was the asymmetry: executed both ways, the two arms reach the
    SAME outcome (neither delivers) whenever the harvest is not the thing that dies. The
    harvest is now guarded and its own failure is reported as `text_raised`, so a real change
    in what the gate does to a process still fails this test while a probe artefact cannot.

    Each arm runs in its own child interpreter, because the point of the demand is what a
    PROCESS does and because a SIGSEGV in the test process is not a test result.
    """
    battery = {
        "benign dict rows": 'value = {"rows": [{"a": i, "b": "pad-%d" % i} for i in range(40)]}',
        "plain string": 'value = "a plain string"',
        "non-str mapping key": 'value = {1: "x"}',
        "surrogate mapping key": 'value = {"\\ud800": "x"}',
        "brace in key, row position": 'value = {"rows": [{"}": i, "z": i} for i in range(20)]}',
        "circular container": 'value = {"self": None}\nvalue["self"] = value',
        "deep acyclic container": (
            'value = {"leaf": 1}\n'
            "for _ in range(50000):\n"
            '    value = {"n": value}'
        ),
    }
    for label, build in battery.items():
        arms = {}
        for gated in (True, False):
            child = (
                "import json, sys\n"
                "sys.setrecursionlimit(100000)\n"
                "from defender.tests.e2e import _toon872 as T\n"
                f"{build}\n"
                f"out = T.agent_run(toolset=T.foreign_toolset(value), capabilities={gated})\n"
                # HARVESTED DEFENSIVELY, and this is load-bearing: `texts()` SERIALIZES the
                # tool return, so on an unserializable payload the probe itself raises — in
                # the un-gated arm only, because the gated arm's text is already a plain
                # framed `str` with nothing left to serialize. Harvesting it bare made this
                # test report a divergence it had created: the RUN reached the same outcome in
                # both arms (neither delivers), and only the measurement died.
                "try:\n"
                "    text, text_raised = (out.dispatched.texts() or [None])[0], False\n"
                "except BaseException:\n"
                "    text, text_raised = None, True\n"
                "print(json.dumps({'raised': out.error is not None,\n"
                "                  'type': type(out.error).__name__ if out.error else None,\n"
                "                  'text_raised': text_raised,\n"
                "                  'text': text}))\n"
            )
            arms[gated] = run_isolated(child, timeout=120.0)

        gated_out, plain_out = arms[True], arms[False]
        assert not gated_out.timed_out, f"{label} hung with the gate"
        assert not plain_out.timed_out, f"{label} hung without the gate"

        assert gated_out.signalled == plain_out.signalled, (
            f"{label}: the gate changed whether the process was killed by a signal"
        )
        assert (gated_out.returncode == 0) == (plain_out.returncode == 0), (
            f"{label}: the gate changed whether the run survived"
        )
        if gated_out.returncode == 0 and plain_out.returncode == 0:
            g = json.loads(gated_out.stdout.strip().splitlines()[-1])
            p = json.loads(plain_out.stdout.strip().splitlines()[-1])
            assert g["raised"] == p["raised"], f"{label}: the gate changed whether it raised"
            assert g["type"] == p["type"], (
                f"{label}: the gate changed the class of the failure"
            )

    # THE PROBED STDERR DIVERGENCE DOES NOT EXIST, and asserting it made this test depend on a
    # panic being ABSENT from an arm that also emits it. Executed over a 2x2 — {benign,
    # `}`-in-key} x {gated, un-gated} — the `serialization.rs` panic line appears in ALL FOUR,
    # including a benign dict-row payload with no capability installed at all. It is ambient to
    # driving an agent in this harness, not something the gate does and not something the
    # `}` key provokes: a bare `toons.dumps({"rows": [{"a": 1}]})` in a child prints nothing.
    #
    # So the honest statement is the ABSENCE of a gate-attributable stderr difference, and the
    # demand that actually carries O9 is the model-visible one: the text is identical.
    brace = '{"rows": [{"}": i, "z": i} for i in range(20)]}'
    harvest = (
        "from defender.tests.e2e import _toon872 as T\n"
        f"out = T.agent_run(toolset=T.foreign_toolset({brace}), capabilities=%s)\n"
        "print((out.dispatched.texts() or [None])[0])\n"
    )
    gated = run_isolated(harvest % "True", timeout=120.0)
    plain = run_isolated(harvest % "False", timeout=120.0)
    assert gated.returncode == 0, "a `}`-in-key payload stopped delivering with the gate"
    assert plain.returncode == 0, "a `}`-in-key payload stopped delivering without the gate"
    assert ("panicked at" in gated.stderr) == ("panicked at" in plain.stderr), (
        "a Rust panic line became gate-attributable — it is ambient to this harness today, so "
        "an asymmetry here is a real change in what the gate does to the process"
    )
    # The gate ALWAYS frames, so raw stdout differs by construction (and by run id). What must
    # match is the framed CONTENT against the un-gated text — the bytes the model reads.
    assert framed_content(gated.stdout.strip()) == plain.stdout.strip(), (
        "the gate changed the model-visible text on a `}`-in-key payload"
    )


def test_a_payload_carrying_a_raw_nul_is_refused_and_the_encoder_is_never_called() -> None:
    """A payload carrying a raw NUL in any string is refused before the encoder, and the
    model-visible text is byte-identical to the un-gated run's.

    A FIFTH REFUSAL REASON IN M7, AND THE ONLY SECURITY-SHAPED ONE IN AN AVAILABILITY CONTROL.
    What it buys is O2 back for this class: measured, the encoder emits the NUL RAW AND
    UNQUOTED, `loads` returns the original exactly, the byte gate clears and the gate
    SUBSTITUTES — so the model would read a bare U+0000 on the substitute arm where the
    passthrough arm shows the six printable characters that spell it. That is a model-visible
    difference between gated and un-gated text, which is the one thing O2 was written to
    forbid. #851's NUL refusal does not reach this seam: all three callers of `decide_bash`
    take a model-authored bash command, never a tool return.

    TWO OBSERVABLES, and the second is what makes it a refusal rather than a round-trip
    failure: the spy encoder's call count is 0, and the delivered content is the wire bytes.
    The NUL is spelled as a Python escape here and never as a raw byte, which is the defect
    four files in this run's history acquired in exactly this sentence's slot.
    """
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
