"""Shared machinery for the #872 TOON view-gate tests.

Tags such as `d3`, `S1` or `r11` name demands and probes in
`docs/archive/spec-graphs/spec_graph_872.yaml`."""
from __future__ import annotations

import functools
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
#: `toons` ships in the optional `runtime` extra; a bare import would be a collection error,
#: which interrupts the whole pytest session.
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

from defender.investigation import driver  # noqa: E402
from defender.investigation.agent_definition import AgentDefinition  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER, ReplayFn  # noqa: E402

REPO_ROOT = DEFENDER.parent

#: Every frame mints its own 16-hex salt (`_untrusted.wrap_fresh`, #875), so the helpers below
#: rely on the salt's width and the frame's shape, never on a known salt value.
RUN_ID = "toon-872"

#: Address-space ceiling for `run_isolated` children, in MiB: ~20x a measured `agent_run`
#: child's ~96 MB RSS, so only the expansion bomb (`S7`) reaches it, well before the OOM killer.
CHILD_MEM_LIMIT_MB = 2048

#: A lower ceiling for children expected to die of allocation (the 2**28-node bomb), which
#: otherwise spend ~13 s per arm reaching 2 GB. A benign child peaks at ~310 MB of address
#: space; both arms of a parity test get the same ceiling.
DOOMED_CHILD_MEM_LIMIT_MB = 768

#: The six printable characters of a JSON-escaped U+0000, written as an escape of an escape so
#: no file here carries the raw byte.
NUL_ESCAPE = "\\u0000"
NUL = "\x00"


# The vendored evidence corpus

#: The 40 committed fixture payloads, vendored rather than imported: the experiment's
#: `build_fixtures.py` runs `sys.path.insert(0, "/workspace")` on import.
_CORPUS_PATH = Path(__file__).with_name("_toon872_corpus.json")


def corpus() -> dict[str, dict]:
    """`{fixture id: payload}` for the 40 committed fixtures, columnar as recorded."""
    return json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))


# lint-dup: ok — §7 r10 (fork P5 = A) vendors this eight-line re-zip into the suite rather
# than importing `build_fixtures.toon_input`, whose module prepends a sibling checkout to
# sys.path. The duplication is the cost the human took with P5 = A; the drift risk (a
# regenerated corpus) is recorded in the same resolution.
def toon_rows(payload: dict) -> dict:
    """The dict-row arm of a columnar payload (`build_fixtures.toon_input`, vendored): TOON's
    tabular form needs objects with identical keys. Keep the full `columns` dicts: reducing them
    to names moves every published ratio."""
    names = [c.get("name") for c in payload["columns"]]
    return {**payload, "values": [dict(zip(names, row, strict=False)) for row in payload["values"]]}


def wire_bytes(value: Any) -> int:
    """The bytes the model is charged for, via the wire serializer (`model_response_str`), not
    `pydantic_core.to_json`: the two differ on non-finite floats, `bytes` and the empty list."""
    return len(wire_text(value).encode("utf-8"))


def wire_text(value: Any) -> str:
    return ToolReturnPart(
        tool_name="probe", content=value, tool_call_id="probe",
    ).model_response_str()


def toon_bytes(value: Any) -> int:
    return len(toons.dumps(value).encode("utf-8"))


def percent(value: Any) -> float:
    """The ENCODER-bytes ratio, NOT the gate's ruler: some arms clear it and fail once the frame
    is counted, so pick fixtures by bar side with `delivered_percent`."""
    return 100.0 * toon_bytes(value) / wire_bytes(value)


def delivered_percent(value: Any) -> float:
    """The gate's ruler: the bytes the model receives on each arm, frame included."""
    overhead = frame_overhead()
    return 100.0 * (toon_bytes(value) + overhead) / (wire_bytes(value) + overhead)


def wire_roundtrip_equal(value: Any) -> bool:
    """The round-trip fidelity oracle, spelled with the wire serializer."""
    return wire_text(toons.loads(toons.dumps(value))) == wire_text(value)


def frame_overhead() -> int:
    """The fixed byte cost `_untrusted.wrap_fresh` adds, measured off the real primitive; salts
    are always 16 hex chars, so it depends on the tag alone."""
    from defender import _untrusted
    return len(_untrusted.wrap_fresh("", "untrusted").encode("utf-8"))


_FRAME_RE_CACHE: dict[str, re.Pattern] = {}


def _frame_re(tag: str) -> re.Pattern:
    """A frame's shape with the salt unpinned; a backreference ties the open and close salts,
    so the span is one frame, not two stray tags."""
    pat = _FRAME_RE_CACHE.get(tag)
    if pat is None:
        tag_re = re.escape(tag)
        pat = re.compile(rf"<run-([0-9a-f]+)-{tag_re}>\n(.*)\n</run-\1-{tag_re}>", re.DOTALL)
        _FRAME_RE_CACHE[tag] = pat
    return pat


def framed_content(text: str, *, tag: str = "untrusted") -> str:
    """The bytes between the frame's delimiters."""
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
    """The REAL `pyo3_runtime.PanicException` class, captured from the real primitive."""
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
    """A data fault-spec for `SpyEncoder`; every fault class here is probe-derived."""

    dumps_raises: BaseException | None = None
    loads_raises: BaseException | None = None
    dumps_returns: str | None = None
    loads_returns: Any = None
    raise_after: int = 0


class SpyEncoder:
    """The encoder seam's fake: injects faults and counts calls, decides nothing.

    `dumps_calls == 0` is what tells "refused before the encoder" from "encoded, then
    discarded"; the returned value cannot."""

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
    """A toolset defender does not own, carrying one tool. Unlabelled on purpose: anything not
    installed by defender's composition root is foreign; only `mark_owned` changes that."""
    ts = FunctionToolset()
    fn = _returner(returns)
    fn.__name__ = name
    ts.tool_plain(fn)
    return ts


def foreign_sequence(values: list[Any], *, name: str = "fetch_rows") -> FunctionToolset:
    """A foreign tool whose successive calls return successive values."""
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
    """`toon_gate.GATE_METADATA_KEY`, the reserved metadata key carrying the original JSON."""
    from defender.investigation.toon_gate import GATE_METADATA_KEY
    return GATE_METADATA_KEY


def owned_toolset(returns: Any, *, name: str = "fetch_rows") -> Any:
    """The same toolset with defender's owned label, applied by the production `mark_owned`
    (a hand-written key would pass over an implementation reading a different one)."""
    from defender.investigation.toon_gate import mark_owned
    return mark_owned(foreign_toolset(returns, name=name))


# Driving the composition root

class Dispatched:
    """What the model received, and nothing the gate says about itself."""

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
    """A `FunctionModel` callable that keeps the raw request messages
    (`_replay_harness.messages_text` would lose `ToolReturnPart.metadata`)."""

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
    """`ReplayFn` plus the raw request messages (with `metadata`), for whole-run tests."""

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
    """The gate capability the composition root installed, recovered off the built agent."""
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
    """Build an agent at `build_agent_core` and drive one turn against a `FunctionModel`."""
    # A fresh spy per call: a shared default would carry one test's call counts into the next.
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
    """A real `AgentDeps`, bound the way the composition root binds one."""
    import tempfile

    from defender.investigation.agent_definition import RunScope, bind
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
    """The real `build_agent_core` with the gate's two build-time seams: `toolset=` (foreign
    tools) and `toon_encoder=` (call counts observable without monkeypatching).

    `capabilities=False` builds the un-gated control instead: a bare `Agent` with
    `capabilities=[]` over the same toolset."""
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
    """A definition with no defender tools and no query capability, so a foreign result is the
    only thing crossing the gate; `defn=` strips another role's definition the same way."""
    from dataclasses import replace

    from defender.investigation.agent_definition import DENY_ALL, ToolSet
    from defender.investigation.driver import MAIN_DEF
    base = defn if defn is not None else MAIN_DEF
    # Stripping the tools strips their scope too: `agent_definition` refuses shapes or a
    # `verb_grant` no granted tool uses, so `bind` would raise before the gate is reached.
    return replace(base, tools=ToolSet(), write_shapes=(), bash_shapes=(),
                   budget_enforced=False, verb_grant=DENY_ALL, corpus_dirs=(),
                   requires_corpus=False)


class _NullLogger:
    """The `RequestLogger` shape `build_agent_core` needs, recording what it is handed (whole-run
    tests use the real, run-dir-backed one)."""

    def __init__(self) -> None:
        self.records: list[dict] = []

    def log(self, **kw: Any) -> None:
        self.records.append(kw)

    def log_budget_refusal(self, **kw: Any) -> None:
        self.records.append({"budget_refusal": kw})


def _built(model):
    from defender.providers import BuiltModel
    return BuiltModel(FunctionModel(model), None)


# Driving an agent one of the five build functions produced

def probe_model(calls: list[tuple[str, dict]] | None = None, turns: int = 1):
    """`(make_model, recorder)`: every build function takes `make_model`, so this drives a real
    build path without a provider."""
    rec = _Recorder(calls if calls is not None else [("fetch_rows", {})], turns=turns)
    return (lambda name, effort: _built(rec)), rec


def run_with_foreign_toolset(agent: Agent, deps: Any, recorder: _Recorder, value: Any,
                             *, name: str = "fetch_rows") -> Dispatched:
    """Run an ALREADY-BUILT agent one turn with a foreign toolset supplied at RUN time."""
    import asyncio
    with override_allow_model_requests(False):
        asyncio.run(agent.run("go", deps=deps, toolsets=[foreign_toolset(value, name=name)]))
    return Dispatched(recorder.requests, [])


# Child-process isolation — hazard containment, not tidiness

@dataclass(frozen=True)
class ChildOutcome:
    """A process-level outcome, for with/without-gate parity."""

    returncode: int
    signalled: bool
    timed_out: bool
    stdout: str
    stderr: str

    @property
    def survived(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _child_limits(mem_limit_mb: int) -> None:
    """Bound the child's address space and forbid core dumps. Runs in the forked child."""
    try:
        import resource
    except ImportError:  # pragma: no cover — POSIX-only; CI and the devcontainer are Linux
        return
    limit = mem_limit_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_isolated(
    source: str,
    *,
    timeout: float = 60.0,
    pythonpath: bool = True,
    mem_limit_mb: int = CHILD_MEM_LIMIT_MB,
) -> ChildOutcome:
    """Run a snippet in a child interpreter with a wall clock AND a memory ceiling."""
    env = dict(os.environ)
    if pythonpath:
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    else:
        # The child must reach the gate without an inherited path, like a re-executed `run.py`.
        env.pop("PYTHONPATH", None)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", source],
            capture_output=True, text=True, timeout=timeout, env=env, check=False,
            preexec_fn=functools.partial(_child_limits, mem_limit_mb),  # noqa: PLW1509 — see _child_limits
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


#: Shared child preamble: drive one turn gated or un-gated, so both arms of a parity test are
#: one program apart from that flag.
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


# Hazard corpora (probe-derived values)

#: Values that, unescaped, could close a row, open a field or forge a delimiter (the characters
#: TOON's SPEC 7.1 escaping is about).
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
    """The positive control: the same shape with every hazard removed."""
    return {"rows": [{"id": i, "text": f"benign-{i}"} for i in range(len(HAZARD_VALUES))]}


def hazard_key_rows() -> dict:
    """The hazards in field-name position, which TOON puts in the header line that declares
    each row's fields."""
    keys = ["id", 'q"uote', "com,ma", "col:on", "br}ace"]
    return {"rows": [{k: f"v{i}{j}" for j, k in enumerate(keys)} for i in range(3)]}


def declared_and_emitted(view: str) -> list[tuple[int, int]]:
    """`(rows declared, row lines emitted)` per tabular block (`<name>[N]{f1,f2}:` plus indented
    rows) of a TOON view. A literal newline inside a row can round-trip cleanly yet forge rows
    in the view: counting lines catches it, comparing decoded objects does not."""
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
