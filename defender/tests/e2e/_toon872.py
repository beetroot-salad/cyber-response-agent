"""Machinery for the #872 TOON view-gate spec — NO test scripts.

The suite this serves is the executable form of `spec-flow/specs/spec_graph_872.yaml`.
It is RED against HEAD by construction: `defender.runtime.toon_gate` does not exist yet,
`build_agent_core` has no `toolset=` / `toon_encoder=` seam and `run_investigation` has no
`toolset=` seam. Those three are demands (`d20`, `d44`, `d78`), not incidental imports.

TWO ALTITUDES, BOTH REAL, AND THE CHOICE IS THE ORACLE'S NOT CONVENIENCE'S (§7 r8):

  * `agent_run(...)` builds the agent through **defender's own composition root**
    (`driver.build_agent_core`) and drives it with a `FunctionModel`. The oracle is the
    **dispatched request messages** — the `ToolReturnPart` the model received — which is
    where §7 r8 put O1/O2/O3/O8. It is not an internal variable and it is not the wrapper's
    own return value, which O1 forbids reading.
  * `_replay_harness.drive(..., toolset=...)` drives the whole `run_investigation` loop.
    That is the only altitude where the session store, the send-history rebuild, the wire
    log, the queries table and the run dir exist at all, so every demand about those is
    driven there and nowhere else.

THE ENCODER IS A SEAM (`d78`), AND THAT IS NOT A TEST CONVENIENCE. O9's own oracle is "for a
payload the validator refuses, the encoder is **never called** — observable on a spy encoder's
call count, not inferred from the return value" (design-872-r3.md, O9(b)). A refusal and a
fault are indistinguishable from outside the gate, which is exactly how r2's arm shipped
unimplementable. The project profile forbids `monkeypatch.setattr`, so the seam is the demand.

AND IT IS ALSO THE SEGFAULT CONTAINMENT. `toons.dumps` does not raise on a self-referential
container, it **SIGSEGVs** (`R11`, four shapes, all killed by signal 11), and a deep acyclic
payload does the same (`S3`). Every test that hands the gate one of those hands it a
`SpyEncoder`, so the real Rust encoder is never reachable from the assertion even if the
implementation under test walks the value wrongly. The two cases that must use the REAL
encoder to mean anything — `d57`'s process parity and `d52`'s expansion bomb — run in a
child process with a wall clock (`run_isolated`), because a crash or a hang in the test
process is not a test result.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")
#: Guarded like `pydantic_ai` beside it, and for the same reason: `toons` ships in the
#: `runtime` EXTRA (`defender/pyproject.toml`), so an install without it is a supported one.
#: A bare `import toons` there is not "these seven modules fail" — it is seven COLLECTION
#: errors, and pytest answers a collection error by interrupting the whole session, so the
#: entire suite stops running over a missing optional wheel.
toons = pytest.importorskip("toons")  # noqa: E402

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.messages import (  # noqa: E402
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.toolsets import FunctionToolset  # noqa: E402

from defender.runtime import driver  # noqa: E402
from defender.runtime.agent_definition import AgentDefinition  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER, ReplayFn  # noqa: E402

REPO_ROOT = DEFENDER.parent

#: #875 retired the run's one standing salt: every frame now mints its OWN (`_untrusted.
#: wrap_fresh`), 16 hex chars, after its content is in hand. `d3`'s delivered-bytes measure
#: still rests on that WIDTH (`frame_overhead`), never on a value a test could inject or
#: predict — `framed_content`/`frame_count` below match the frame's SHAPE, not a known salt.
RUN_ID = "toon-872"

#: Address-space ceiling for every `run_isolated` child, in MiB. A measured `agent_run`
#: child peaks at ~96 MB RSS, so this is ~20x headroom: no honest payload reaches it, and
#: the expansion bomb (`S7`) hits it long before the kernel's OOM killer would fire.
CHILD_MEM_LIMIT_MB = 2048

#: The six printable characters a JSON escape of U+0000 spells, written as an escape of an
#: escape so no artifact in this run can carry the raw byte itself. Four files in this run's
#: history were corrupted in exactly this slot; `d64` is the demand about it.
NUL_ESCAPE = "\\u0000"
NUL = "\x00"


# The vendored evidence corpus (§7 r10, P5 = A)

#: The 40 committed fixture payloads, copied into the suite at §7 r10 (P5 = A). VENDORED, not
#: imported: `experiments/toon-vs-columnar-kimi/build_fixtures.py:15` does
#: `sys.path.insert(0, "/workspace")`, so importing it prepends a sibling checkout to the
#: suite's path (hole H2). The experiment file is deliberately left untouched, so its cited
#: numbers stand unre-run.
_CORPUS_PATH = Path(__file__).with_name("_toon872_corpus.json")


def corpus() -> dict[str, dict]:
    """`{fixture id: payload}` for the 40 committed fixtures, columnar as recorded."""
    return json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))


# lint-dup: ok — §7 r10 (fork P5 = A) vendors this eight-line re-zip into the suite rather
# than importing `build_fixtures.toon_input`, whose module prepends a sibling checkout to
# sys.path. The duplication is the cost the human took with P5 = A; the drift risk (a
# regenerated corpus) is recorded in the same resolution.
def toon_rows(payload: dict) -> dict:
    """The dict-row arm of a columnar payload — `build_fixtures.toon_input`, vendored.

    TOON's tabular form needs an array of OBJECTS with identical key sets; the production
    payload is array-of-arrays, so the dicts #842 deleted are materialized again transiently
    as encoder input. Keeping the FULL `columns` dicts is load-bearing: `G7` recorded that a
    hand-rolled re-zip reducing `columns` to names moves every published ratio.
    """
    names = [c.get("name") for c in payload["columns"]]
    return {**payload, "values": [dict(zip(names, row, strict=False)) for row in payload["values"]]}


def wire_bytes(value: Any) -> int:
    """The bytes the model is charged for — `d71`'s ruler, not `pydantic_core.to_json`.

    `ToolReturnPart.model_response_str` calls `tool_return_ta.dump_json`, and the two
    serializers differ in 7 of 22 probed value classes (`cN2`): non-finite floats, `bytes`
    and the empty list. O2 is a byte-identity obligation, so measuring it with `to_json`
    makes the ruler and the thing it rules agree with each other while both differ from the
    wire."""
    return len(wire_text(value).encode("utf-8"))


def wire_text(value: Any) -> str:
    return ToolReturnPart(
        tool_name="probe", content=value, tool_call_id="probe",
    ).model_response_str()


def toon_bytes(value: Any) -> int:
    return len(toons.dumps(value).encode("utf-8"))


def percent(value: Any) -> float:
    """`100 * bytes(toon) / bytes(wire_json)` — the ENCODER-bytes ratio, which is NOT the ruler
    the gate applies.

    Kept because `d3` is stated as the difference between this and the delivered one: three
    committed arms clear on encoder bytes and fail once the frame is counted. Anything that
    selects a fixture by which side of the bar it lands on must use `delivered_percent`.
    Returned as a float so a test can pick a fixture either side of a bar; no test asserts a
    percentage."""
    return 100.0 * toon_bytes(value) / wire_bytes(value)


def delivered_percent(value: Any) -> float:
    """`d3`'s ruler, spelled ONCE: the bytes the model receives on each arm, frame included.

    Under f2 = B every exit is framed, so both arms of the comparison carry the same fixed
    frame cost and the ratio the gate decides on is
    `100 * (bytes(toon) + frame) / (bytes(wire_json) + frame)`. This is the spelling `d3`'s own
    test drives, and it is the one every fixture selection and every anti-vacuity guard in this
    suite reads — a selection made on `percent` can hand a test a payload the delivered-bytes
    gate decides the other way, which is a test no correct implementation makes green
    (`92-reconciliation.md` F1). `design-872-r3.md` M2 carries the frame after the same
    correction."""
    overhead = frame_overhead()
    return 100.0 * (toon_bytes(value) + overhead) / (wire_bytes(value) + overhead)


def wire_roundtrip_equal(value: Any) -> bool:
    """M3's oracle, spelled with the WIRE tool-return serializer — `d71`'s third `to_json` site.

    `d71` corrects two sites (the byte gate's denominator and f2 = B's stringify step) and §7
    rules the third the same way: the fidelity oracle is
    `wire(loads(dumps(x))) == wire(x)`, not `pydantic_core.to_json` on either side. The two
    disagree on the classes `cN2` measured, and the disagreement decides an ARM: a non-finite
    float compares EQUAL under the wire serializer (both sides render `null`) and unequal under
    `pydantic_core.to_json` (`NaN` against `null`), so `d70`'s payloads substitute under the
    ruler the rest of this suite already uses."""
    return wire_text(toons.loads(toons.dumps(value))) == wire_text(value)


def frame_overhead() -> int:
    """The fixed byte cost `_untrusted.wrap_fresh` adds (`r20`), measured off the real
    primitive rather than recalled as 67. A fresh-minted salt is always 16 hex chars
    (`secrets.token_hex(8)`), so the overhead is a function of the tag alone, never of which
    salt a particular call happened to draw."""
    from defender import _untrusted
    return len(_untrusted.wrap_fresh("", "untrusted").encode("utf-8"))


_FRAME_RE_CACHE: dict[str, re.Pattern] = {}


def _frame_re(tag: str) -> re.Pattern:
    """A frame's SHAPE, salt unpinned — #875 mints one per call (`wrap_fresh`), so no test can
    know it ahead of time. The open and close delimiters' salts are tied by backreference:
    that they MATCH is exactly what makes the span one frame rather than two independent
    stray tags."""
    pat = _FRAME_RE_CACHE.get(tag)
    if pat is None:
        tag_re = re.escape(tag)
        pat = re.compile(rf"<run-([0-9a-f]+)-{tag_re}>\n(.*)\n</run-\1-{tag_re}>", re.DOTALL)
        _FRAME_RE_CACHE[tag] = pat
    return pat


def framed_content(text: str, *, tag: str = "untrusted") -> str:
    """The bytes BETWEEN the frame's delimiters — O2's re-read oracle after §7 r3 (f2 = B).

    Raises rather than returning the input when the text is not framed: a helper that
    silently passed unframed text through would make every `d0`/`d9` assertion pass over a
    gate that never framed anything.

    A NON-`str` INPUT IS REFUSED HERE RATHER THAN LEFT TO `startswith`. Under f2 = B every
    foreign exit is stringified before it is framed, so a `dict` arriving at this helper is
    the demand failing — and an `AttributeError: 'dict' object has no attribute 'startswith'`
    reads as a broken test rather than as a discriminating one, which is exactly the
    distinction the null-stub check turns on."""
    if not isinstance(text, str):
        raise AssertionError(
            f"a {type(text).__name__} reached the frame unstringified — under f2 = B every "
            f"foreign exit is a `str` before it is framed: {text!r:.120}"
        )
    m = _frame_re(tag).fullmatch(text)
    if not m:
        raise AssertionError(f"not framed (tag={tag!r}): {text[:120]!r}")
    return m.group(2)


def frame_count(text: str, *, tag: str = "untrusted") -> int:
    return len(re.findall(rf"<run-[0-9a-f]+-{re.escape(tag)}>", text))


# The declarative fault-injection fake for the encoder seam

def _panic_class() -> type[BaseException]:
    """The REAL `pyo3_runtime.PanicException` class, captured from the real primitive.

    It is not importable — `pyo3_runtime` is a module PyO3 synthesizes, and there is no
    `import pyo3_runtime` in this venv — so the only honest way to hold the class is to make
    the encoder raise one. `S5` established the fact this suite rests on and it is re-probed
    here on every run rather than pinned: `issubclass(PanicException, Exception)` is False and
    its MRO is (PanicException, BaseException, object), which is precisely how r2's `except
    Exception` arm shipped unimplementable. The Rust panic line this prints to stderr is the
    same one `d57` asserts is a real difference between the gated and un-gated runs."""
    try:
        toons.dumps({1: "not a str key"})
    except BaseException as exc:  # noqa: BLE001 — capturing the class IS the probe
        return type(exc)
    raise AssertionError(
        "toons.dumps({1: 'x'}) no longer raises — S1's fault taxonomy has moved under this "
        "suite and every fake citing it is now asserting a fault the encoder does not produce"
    )


PANIC: type[BaseException] = _panic_class()

assert not issubclass(PANIC, Exception), (
    "S5's load-bearing fact has changed: the encoder's panic is now an Exception subclass, "
    "so `except Exception` would catch it and d55's breadth demand no longer discriminates"
)


@dataclass
class EncoderFault:
    """A data fault-spec for `SpyEncoder`. Every fault class here is probe-derived; none is
    authored belief.

    `dumps_raises` / `loads_raises` — the exception INSTANCE to raise. The classes the suite
    uses are `PANIC` (`S5`/`R11`: the encoder's real panic, a `BaseException` and not an
    `Exception`) and the control-flow set `d55` requires re-raised.
    `dumps_returns` — a canned view, for the cases where the gate must be shown a value the
    real encoder would take the process to produce (`R11`'s cycle, `S3`'s depth).
    `raise_after` — let N calls through, then fault. `S5` established the arm is durable
    rather than one-shot: after 200 consecutive caught panics `dumps` still encodes.
    """

    dumps_raises: BaseException | None = None
    loads_raises: BaseException | None = None
    dumps_returns: str | None = None
    loads_returns: Any = None
    raise_after: int = 0


class SpyEncoder:
    """The encoder seam's fake: it INJECTS FAULTS AND COUNTS CALLS, and decides nothing.

    It classifies nothing and makes no policy decision — it does not know what a bar is, what
    foreign means or what a refusal is. The call counts are the observation channel O9(b) is
    stated over: `dumps_calls == 0` is what distinguishes "refused before the encoder" from
    "encoded and then discarded", and no property of the returned value can tell those apart.
    """

    def __init__(self, fault: EncoderFault | None = None) -> None:
        self.fault = fault or EncoderFault()
        self.dumps_calls = 0
        self.loads_calls = 0
        self.dumps_args: list[Any] = []

    def dumps(self, value: Any, **kwargs: Any) -> str:
        self.dumps_calls += 1
        self.dumps_args.append(value)
        if self.fault.dumps_raises is not None and self.dumps_calls > self.fault.raise_after:
            raise self.fault.dumps_raises
        if self.fault.dumps_returns is not None:
            return self.fault.dumps_returns
        return toons.dumps(value, **kwargs)

    def loads(self, text: str, **kwargs: Any) -> Any:
        self.loads_calls += 1
        if self.fault.loads_raises is not None and self.loads_calls > self.fault.raise_after:
            raise self.fault.loads_raises
        if self.fault.loads_returns is not None:
            return self.fault.loads_returns
        return toons.loads(text, **kwargs)


# Foreign and owned toolsets

def foreign_toolset(returns: Any, *, name: str = "fetch_rows") -> FunctionToolset:
    """A toolset defender does not own, carrying one dict/list-returning tool.

    UNLABELLED, which is the point: §7 r2 (P1 = B) made the default *foreign unless installed
    by defender's own composition root*, so an unlabelled source must be gated and framed
    rather than silently exempt. `mark_owned` is the only thing that moves it."""
    ts = FunctionToolset()
    fn = _returner(returns)
    fn.__name__ = name
    ts.tool_plain(fn)
    return ts


def foreign_sequence(values: list[Any], *, name: str = "fetch_rows") -> FunctionToolset:
    """A foreign tool whose successive calls return successive values — the instrument
    `d45` (each call gated independently) and `d44` (the seam holds for every call) need."""
    ts = FunctionToolset()
    box = {"i": 0}

    def fn() -> Any:
        v = values[min(box["i"], len(values) - 1)]
        box["i"] += 1
        return v

    fn.__name__ = name
    ts.tool_plain(fn)
    return ts


def _returner(value: Any):
    def fn() -> Any:
        return value
    return fn


def gate_metadata_key() -> str:
    """The reserved key §7 r1 spelled, imported PER CALL rather than at a module head.

    `defender.runtime.toon_gate` does not exist at the base this spec forks from, and a
    module-head import turns that into one collection error per file instead of one failure per
    test — which is exactly what the null-stub check cannot read: an import error proves the
    file is broken, never that the test discriminates. The #705 spec suite established this
    shape for the same reason."""
    from defender.runtime.toon_gate import GATE_METADATA_KEY
    return GATE_METADATA_KEY


def owned_toolset(returns: Any, *, name: str = "fetch_rows") -> Any:
    """The same toolset carrying defender's OWNED label.

    The label is applied through the production marker, never by spelling a metadata key in
    the test: `d59` pins what the label IS, and a test that hand-wrote the key would go green
    over an implementation that read a different one."""
    from defender.runtime.toon_gate import mark_owned
    return mark_owned(foreign_toolset(returns, name=name))


# Driving the composition root

class Dispatched:
    """What the model received, and nothing the gate says about itself.

    `parts` is read off the LAST request's message list — the dispatched request messages,
    which §7 r8 made the artifact for O1/O2/O3/O8. `returns` is the wrapper's own return
    value and is deliberately NOT the oracle for any encoding demand; it exists only for the
    two demands stated over the return contract itself (`d0b`, `d72`).

    `text()` RENDERS THE PART THE WAY A PROVIDER DOES — `model_response_str()`, which is
    `wire_text`'s own serializer — and NOT with `str()`. The design says why in as many words
    (M5): "`str()` produces Python `repr` text (single quotes, `None`, `True`), which is
    neither the wire JSON nor recoverable". Under `str()` an UN-GATED `dict` return rendered
    as `{'a': 1}` while `wire_text` gave `{"a":1}`, so every O2 assertion of the form
    "the owned/ungated text is unchanged == `wire_text(value)`" compared repr to JSON and
    could not pass whatever the gate did. A framed `str` renders identically under both, so
    the substitute arms never saw it."""

    def __init__(self, requests: list[list[Any]], returns: list[Any]) -> None:
        self.requests = requests
        self.returns = returns

    @property
    def parts(self) -> list[ToolReturnPart]:
        if not self.requests:
            return []
        return [
            p for msg in self.requests[-1]
            for p in getattr(msg, "parts", [])
            if isinstance(p, ToolReturnPart)
        ]

    def part(self, tool_name: str) -> ToolReturnPart:
        hits = [p for p in self.parts if p.tool_name == tool_name]
        assert len(hits) == 1, f"expected one {tool_name!r} return, got {len(hits)}"
        return hits[0]

    def text(self, tool_name: str = "fetch_rows") -> str:
        return self.part(tool_name).model_response_str()

    def texts(self, tool_name: str = "fetch_rows") -> list[str]:
        return [p.model_response_str() for p in self.parts if p.tool_name == tool_name]

    def metadata(self, tool_name: str = "fetch_rows") -> Any:
        return self.part(tool_name).metadata


class _Recorder:
    """A `FunctionModel` callable that keeps the RAW request messages.

    `_replay_harness.messages_text` flattens every part to one string, which loses
    `ToolReturnPart.metadata` entirely — the field `d15b`, `d16`, `d65` and `d66` are stated
    over. Everything in this suite that reads a part reads it through here."""

    __name__ = "ToonRecorder"

    def __init__(self, calls: list[tuple[str, dict]], turns: int = 1) -> None:
        self._calls = calls
        self._turns = turns
        self.requests: list[list[Any]] = []
        self.n = 0

    def __call__(self, messages, info) -> ModelResponse:
        self.requests.append(list(messages))
        self.n += 1
        if self.n <= self._turns:
            return ModelResponse(parts=[
                ToolCallPart(tool_name=name, args=args) for name, args in self._calls
            ])
        return ModelResponse(parts=[TextPart(content="(done)")])


class PartRecorder(ReplayFn):
    """`ReplayFn` + the raw request messages, for the whole-run altitude.

    The harness's own `ReplayFn` records `messages_text(messages)`, which cannot see
    `metadata`; `ToolRoster` records the tool roster. This records the message objects, which
    is what the send-history and store round-trip demands are stated over."""

    __name__ = "ToonPartRecorder"

    def __init__(self, turns) -> None:
        super().__init__(turns)
        self.requests: list[list[Any]] = []

    def __call__(self, messages, info) -> ModelResponse:
        self.requests.append(list(messages))
        return super().__call__(messages, info)

    @property
    def dispatched(self) -> Dispatched:
        return Dispatched(self.requests, [])


@dataclass
class GateBuild:
    """One agent built through defender's own composition root, plus its observation channels."""

    dispatched: Dispatched
    encoder: SpyEncoder
    record: Any
    error: BaseException | None = None
    stderr: str = ""
    seen_returns: list[Any] = field(default_factory=list)
    agent: Any = None


def installed_gate_capability(build: GateBuild) -> Any:
    """The gate capability the composition root installed, recovered off the built agent.

    `d80` drives a SECOND install through `build_agent_core`'s `extra_capabilities` seam, so
    the test needs an object to install — and it is RECOVERED RATHER THAN CONSTRUCTED BY NAME.
    No resolution ever spelled a public constructor for the capability: `d78` pins two seams
    and neither is a capability factory, so a test that spelled `ToonGateCapability()` would
    mint a production symbol and a signature §7 never decided, at the last authoring step.
    What the demand is about is a second INSTALL, not a new public name.

    The identification is defender-vs-library rather than a class name or a module path:
    `cR3` measured that the three capabilities pydantic-ai installs by itself on this build
    (`ToolSearch`, `PendingMessageDrainCapability`, `Hooks`) are all defined under
    `pydantic_ai.*`, and the stripped definition this suite builds registers no `query` tool,
    so `QueryCapture` is absent and defender's own capability is the one left.
    `Agent.root_capability` is the library's own public accessor and `apply` its documented
    visitor, so nothing here reaches into a private attribute.
    """
    caps: list[Any] = []
    build.agent.root_capability.apply(caps.append)
    mine = [c for c in caps if type(c).__module__.split(".", 1)[0] == "defender"]
    assert len(mine) == 1, (
        "expected exactly ONE capability defined in defender's own code on an agent built "
        "through the composition root — the gate — and found "
        f"{[type(c).__module__ + '.' + type(c).__name__ for c in mine]} among "
        f"{[type(c).__name__ for c in caps]}"
    )
    return mine[0]


def agent_run(  # noqa: PLR0913 — one parameter per seam this drive threads
    *,
    toolset: Any = None,
    encoder: SpyEncoder | None = None,
    calls: list[tuple[str, dict]] | None = None,
    own_tool: Any = None,
    env: dict[str, str] | None = None,
    turns: int = 1,
    capabilities: bool = True,
    defn: Any = None,
    extra: tuple = (),
) -> GateBuild:
    """Build an agent at `build_agent_core` and drive one turn against a `FunctionModel`.

    THE COMPOSITION ROOT IS THE SUBJECT, not a convenience: §7 r5 (P2 = A) put the gate's
    construction at the single `Agent(...)` in `build_agent_core`, which serves all five build
    paths. A test that constructed the wrapper toolset by hand would certify a class, never
    that the composition root installs it.

    `capabilities=False` is `S11`'s OWN CONTROL — a bare `Agent(..., capabilities=[])` over
    the identical toolset and the identical model, which is what "with the gate absent" means
    at the process altitude (`d57`). It is deliberately NOT a production off-switch: nothing
    in the shipped tree can disable the gate, because §7 r5 installed it unconditionally, and
    a `install=False` parameter would be a fail-open knob invented by a test. Every BYTE-level
    parity demand (`d0`, `d9`, `d70`) uses a cheaper and stricter no-gate arm instead —
    `wire_text(value)`, the real serializer pydantic-ai would have sent, computed from the
    real primitive on every run rather than recorded once.
    """
    # The seam owns its default and the default must be a FRESH object per call: every test
    # reads this spy's own call counts, so a shared signature default would carry one test's
    # encode count into the next and make O9(b)'s observable meaningless.
    encoder = encoder if encoder is not None else SpyEncoder()  # lint-default: ok — per-call spy
    calls = calls if calls is not None else [("fetch_rows", {})]
    model = _Recorder(calls, turns=turns)
    logger = _NullLogger()
    deps = _deps(defn)
    old = {k: os.environ.get(k) for k in (env or {})}
    for k, v in (env or {}).items():
        os.environ[k] = v
    try:
        agent = _build(toolset=toolset, encoder=encoder, own_tool=own_tool,
                       model=model, capabilities=capabilities, logger=logger,
                       deps=deps, defn=defn, extra=extra)
        error: BaseException | None = None
        with override_allow_model_requests(False):
            import asyncio
            try:
                asyncio.run(agent.run("go", deps=deps))
            except BaseException as exc:  # noqa: BLE001 — the arm d6/d57 are stated over
                error = exc
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return GateBuild(
        dispatched=Dispatched(model.requests, []),
        encoder=encoder,
        record=logger,
        error=error,
        agent=agent,
    )


def _deps(defn: Any = None, run_dir: Path | None = None):
    """A real `AgentDeps`, bound the way the composition root binds one.

    The frame demands (`d17a`, `d61`, `d67`) are stated over the gate's use of
    `_untrusted.wrap_fresh` — #875 retired `AgentDeps.salt` and `bind`'s `salt=` parameter
    entirely, so there is no standing value left to inject here; every frame mints its own.

    THE SCOPE IS PART OF THE STRIP. `ACTOR_DEF` sets `requires_confine`, so `bind` refuses it
    against the default empty `RunScope` ("an empty confine widens the agent's reads to the
    whole defender_dir"). The confine is the run dir itself, which is the narrowest honest
    answer for an agent whose tools are stripped: it reads nothing."""
    import tempfile

    from defender.runtime.agent_definition import RunScope, bind
    resolved = _defn(defn)
    if run_dir is None:
        run_dir = Path(tempfile.mkdtemp(prefix="toon872-"))
        (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    scope = RunScope(read_confine=(run_dir,)) if resolved.requires_confine else RunScope()
    return bind(resolved, run_dir, scope=scope, defender_dir=DEFENDER)


def _build(  # noqa: PLR0913 — one parameter per seam this build threads, plus the two the
           # composition root already takes; every one is load-bearing per-build
        *, toolset, encoder, own_tool, model, capabilities, logger, deps,
           defn=None, extra=()) -> Agent:
    """The real `build_agent_core`, with the gate's two build-time seams supplied.

    `toolset=` is the foreign-toolset seam `d20` mints and `run_investigation` threads;
    `toon_encoder=` is the encoder seam `d78` mints, which exists because O9(b)'s observable
    is a call count and the profile forbids monkeypatching one in.

    `capabilities=False` bypasses the composition root entirely and builds `S11`'s control —
    a bare `Agent` with `capabilities=[]` over the same toolset. It is the only construction
    in this suite that does not go through `build_agent_core`, and that is the point of it."""
    if not capabilities:
        agent: Agent = Agent(
            _built(model).model, deps_type=type(deps), instructions="spec-872",
            capabilities=[], toolsets=[toolset] if toolset is not None else [],
        )
    else:
        agent = driver.build_agent_core(
            _defn(defn),
            deps_type=type(deps),
            instructions="spec-872",
            logger=logger,
            agent_id="toon-872",
            make_model=lambda name, effort: _built(model),
            extra_capabilities=extra,
            toolset=toolset,
            toon_encoder=encoder,
        )
    if own_tool is not None:
        agent.tool_plain(own_tool)
    return agent


def _defn(defn: Any = None) -> AgentDefinition:
    """A definition with NO defender tools and NO query capability — the gate's own surface,
    isolated from the fourteen registrations, so a foreign result is the only thing crossing
    the seam. The whole-run altitude is where the fourteen are exercised.

    `defn=` lets `d35` drive each of the five build paths' OWN definitions through the single
    `Agent(...)` site they all reach, which is the drive the census demand needs — enumerating
    `AGENTS` picks the subjects, it is not what is asserted about them."""
    from dataclasses import replace

    from defender.runtime.agent_definition import DENY_ALL, ToolSet
    from defender.runtime.driver import MAIN_DEF
    base = defn if defn is not None else MAIN_DEF
    # `write_shapes`/`bash_shapes`/`verb_grant`/`corpus_dirs` go with the grants they scope:
    # `agent_definition` refuses a definition that declares shapes no ToolSet grants a writer
    # for ("dead scope") AND one whose verb-bearing tool bit is off while its `verb_grant` is
    # non-empty, which is the tree telling us that stripping the tools means stripping their
    # scope too. Three of the five registry roles (GATHER, ACTOR, JUDGE) carry a non-empty
    # `verb_grant` or a corpus, so a strip that stopped at `tools` made `bind` raise before the
    # gate was reached — a red that is not the test's own assertion, on three of `d35`'s five
    # paths.
    return replace(base, tools=ToolSet(), write_shapes=(), bash_shapes=(),
                   budget_enforced=False, verb_grant=DENY_ALL, corpus_dirs=(),
                   requires_corpus=False)


class _NullLogger:
    """The `RequestLogger` shape `build_agent_core` needs, recording what it is handed.

    A run-dir-backed logger would make every agent-altitude test write a tree it does not
    assert on; the whole-run altitude uses the real one, which is where `d15b` and `d38`
    are stated."""

    def __init__(self) -> None:
        self.records: list[dict] = []

    def log(self, **kw: Any) -> None:
        self.records.append(kw)

    def log_budget_refusal(self, **kw: Any) -> None:
        self.records.append({"budget_refusal": kw})


def _built(model):
    from defender.runtime.providers import BuiltModel
    return BuiltModel(FunctionModel(model), None)


# Driving an agent one of the FIVE BUILD FUNCTIONS produced (`d35`, `d74`)

def probe_model(calls: list[tuple[str, dict]] | None = None, turns: int = 1):
    """A `make_model` seam and the recorder behind it — `(make_model, recorder)`.

    Every one of the five build functions takes `make_model` as a declared DI seam
    (`providers.build_for_effort` is its default), so this is how a real build path is driven
    without a provider. The recorder is the same `_Recorder` the composition-root altitude
    uses, so the oracle is the dispatched request messages there too (§7 r8)."""
    rec = _Recorder(calls if calls is not None else [("fetch_rows", {})], turns=turns)
    return (lambda name, effort: _built(rec)), rec


def run_with_foreign_toolset(agent: Agent, deps: Any, recorder: _Recorder, value: Any,
                             *, name: str = "fetch_rows") -> Dispatched:
    """Run an ALREADY-BUILT agent one turn with a foreign toolset supplied at RUN time.

    THE RUN-LEVEL TOOLSET IS THE POINT, AND IT IS AN EXECUTED FACT RATHER THAN AN ASSUMPTION:
    pydantic-ai applies a capability's `get_wrapper_toolset` to the toolsets handed to
    `Agent.run(toolsets=[...])`, not only to the ones the agent was constructed with (probed
    against 1.107.0 with a marking `WrapperToolset` — the wrapper saw the call and rewrote the
    return). That is what lets `d35` drive each of the five build FUNCTIONS as itself: none of
    them takes the `toolset=` seam (§7 r5 gave that to `run_investigation` alone), so a
    build-path census that had to thread one could only ever re-drive `build_agent_core`."""
    import asyncio
    with override_allow_model_requests(False):
        asyncio.run(agent.run("go", deps=deps, toolsets=[foreign_toolset(value, name=name)]))
    return Dispatched(recorder.requests, [])


# Child-process isolation — hazard containment, not tidiness

@dataclass(frozen=True)
class ChildOutcome:
    """A process-level outcome: what `d57`'s parity is stated over."""

    returncode: int
    signalled: bool
    timed_out: bool
    stdout: str
    stderr: str

    @property
    def survived(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _child_limits() -> None:
    """Bound the child's address space and forbid core dumps. Runs in the forked child.

    `RLIMIT_AS` is the containment, not tidiness. Without it the expansion bomb's failure
    mode is the OOM killer, which is a MACHINE-wide event: the child grows until the kernel
    picks a victim, and the victim is not reliably the child — a developer running this
    module can lose their editor, and CI can lose the runner. A wall clock does not help,
    because allocation outruns it. With the limit the same input fails as a bounded
    allocation failure inside the child, which IS a test result: the parent still reads a
    non-zero return code and the same parity assertions hold, because both arms of `d57`
    inherit the identical limit.

    The ceiling is deliberately far above legitimate use — a measured `agent_run` child
    peaks at ~96 MB RSS, so 2 GB is ~20x headroom and no honest payload can reach it.
    `RLIMIT_CORE = 0` stops a multi-GB core file per SIGSEGV; this suite drives four
    segfaulting input classes and a probe in this issue's own history was nearly lost to a
    core dump."""
    try:
        import resource
    except ImportError:  # pragma: no cover — POSIX-only; CI and the devcontainer are Linux
        return
    limit = CHILD_MEM_LIMIT_MB * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_isolated(
    source: str,
    *,
    timeout: float = 60.0,
    pythonpath: bool = True,
    mem_limit: bool = True,
) -> ChildOutcome:
    """Run a snippet in a child interpreter with a wall clock AND a memory ceiling.

    Three of the input classes this suite drives can end a process rather than raise: a
    self-referential container SIGSEGVs inside `toons.dumps` (`R11`, 4 of 4 shapes), a deep
    acyclic one does the same (`S3`), and the expansion bomb exhausts memory (`S7`) — which
    without a ceiling means the OOM killer, a machine-wide event rather than a test result
    (see `_child_limits`). A fourth can HANG: a validator with no node budget visits 2**28
    nodes on that bomb before it decides anything. None of those is a test result in the test
    process, and `PYTHONPATH` is pinned to the repo root because the shared venv's editable
    install points at the main checkout — a child that resolved `defender` by cwd would
    measure the wrong tree."""
    env = dict(os.environ)
    if pythonpath:
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    else:
        # `d75`'s condition: the child must reach the gate WITHOUT an inherited path, the way
        # the golden-case generator's re-executed `run.py` child does.
        env.pop("PYTHONPATH", None)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", source],
            capture_output=True, text=True, timeout=timeout, env=env, check=False,
            preexec_fn=_child_limits if mem_limit else None,  # noqa: PLW1509 — see _child_limits
        )
    except subprocess.TimeoutExpired as exc:
        return ChildOutcome(
            returncode=-1, signalled=False, timed_out=True,
            stdout=(exc.stdout or b"").decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=(exc.stderr or b"").decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
        )
    return ChildOutcome(
        returncode=proc.returncode, signalled=proc.returncode < 0,
        timed_out=False, stdout=proc.stdout, stderr=proc.stderr,
    )


#: The child-side preamble every isolated case shares: build the gate over a foreign toolset
#: at the composition root and drive one turn, or drive the identical build with the gate
#: suppressed. Kept here rather than inlined so the two arms of a parity demand are provably
#: the same program apart from the flag they differ on.
CHILD_PRELUDE = '''
import asyncio, json, sys
from defender.tests.e2e import _toon872 as T

def drive(value, *, gated):
    try:
        out = T.agent_run(toolset=T.foreign_toolset(value), capabilities=gated,
                          encoder=None)
    except BaseException as exc:
        print(json.dumps({"outcome": "raised", "type": type(exc).__name__}))
        return
    err = out.error
    print(json.dumps({
        "outcome": "raised" if err is not None else "returned",
        "type": type(err).__name__ if err is not None else None,
        "text": out.dispatched.texts()[0] if (err is None and out.dispatched.parts) else None,
    }))
'''


# Hazard corpora — every value below is an `r11` / `R7` / `S1` probe value, not an invention

#: `r11`/`c4`'s fifteen-value hazard corpus: the characters TOON's SPEC 7.1 escaping is about.
#: Each is a value that, unescaped, could close a row, open a field or forge a delimiter.
HAZARD_VALUES: tuple[str, ...] = (
    "line\nbreak",
    "carriage\rreturn",
    "tab\there",
    'double"quote',
    "back\\slash",
    "comma,separated",
    "colon:separated",
    "open[bracket",
    "close]bracket",
    "brace{here",
    "brace}here",
    "rows[2]{a,b}:",
    "  leading spaces",
    "trailing spaces  ",
    "- dash leader",
)


def hazard_rows() -> dict:
    """A foreign dict-row payload carrying every `r11` hazard in a VALUE position."""
    return {"rows": [{"id": i, "text": v} for i, v in enumerate(HAZARD_VALUES)]}


def hazard_free_rows() -> dict:
    """`d13`'s positive control — the SAME shape with every hazard removed, so the difference
    between the two runs is the hazard and nothing else."""
    return {"rows": [{"id": i, "text": f"benign-{i}"} for i in range(len(HAZARD_VALUES))]}


def hazard_key_rows() -> dict:
    """`R7`'s key-position corpus: the same hazards in the FIELD NAME, which in TOON becomes
    the header line — the one line that declares how many fields each row has."""
    keys = ["id", 'q"uote', "com,ma", "col:on", "br}ace"]
    return {"rows": [{k: f"v{i}{j}" for j, k in enumerate(keys)} for i in range(3)]}


def declared_and_emitted(view: str) -> list[tuple[int, int]]:
    """`(rows declared, row lines emitted)` per tabular block in a TOON view — O4's oracle
    read off the view itself rather than off the encoder's return code.

    A block header is `<name>[N]{f1,f2}:` and its rows are the indented lines that follow.
    An encoder that emitted a literal newline inside a row would round-trip symmetrically
    while the view the model reads has forged rows (settled #24), which is exactly what
    counting the emitted lines catches and what comparing decoded objects does not."""
    import re
    out: list[tuple[int, int]] = []
    lines = view.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)\S*\[(\d+)\]\{[^}]*\}:\s*$", line)
        if not m:
            continue
        indent = len(m.group(1))
        emitted = 0
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                break
            if len(nxt) - len(nxt.lstrip()) <= indent:
                break
            emitted += 1
        out.append((int(m.group(2)), emitted))
    return out
