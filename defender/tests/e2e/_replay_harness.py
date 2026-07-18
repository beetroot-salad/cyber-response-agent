"""Reusable machinery for the hermetic e2e replay tests — NO test scripts.

The runtime e2e tests drive the REAL `driver.run_investigation` loop with a
`FunctionModel` that replays a scripted sequence of model turns — no API key, no
network, no dollars (`override_allow_model_requests(False)` makes any real
provider call raise). This module holds the *machinery* the test scripts share:

    FunctionModel(replay) -> driver.agent.iter loop -> real generic tools
      -> real permission gate (incl. invlang validation) -> real observe
      projection (tool_trace.jsonl) + budget hook -> run-dir artifacts

The *scripts* (the turn sequences + their assertions) live in the `test_*`
modules that import this one: `test_replay_skeleton.py` (happy-path golden
replays + the deny-tail) and `test_replay_error_paths.py` (the driver's error
handling + the gate-as-feedback recovery loop). Keeping the two apart means a new
scenario is a few lines of `Turn(...)` against this harness, not a fresh copy of
the plumbing.

This is NOT a test module (the leading underscore keeps pytest from collecting
it). Drive a run with `drive(run_dir, run_id=…, salt=…, main=<callable>)`, where
the callable is a `ReplayFn` / `DenyProbe` / `NeverEndsModel` — `drive` wraps it
in `FunctionModel`, so scripts never touch the pydantic plumbing.

Below the model there are exactly THREE fakeable boundaries, and all are INJECTED
(never monkeypatched): the model itself (`make_model`), the data-source verb
registry (`verbs=` → `run_investigation(verbs=…)`, #611), and the box executor
(`box=` → `run_investigation(box=…)`, #540). A scenario hands `drive` a `FakeVerbs`
table of plain annotated functions; the real query tool validates against their real
signatures, the real capture capability writes the real rows. The `box` seam is the
same shape one layer lower: the bash tool's execution boundary is a container the
test process cannot start hermetically, so a scenario hands in a `BoxExecutor` built
over a fake transport and the REAL framing codec still runs on both sides.
"""
from __future__ import annotations

import asyncio
import json
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402

DEFENDER = Path(__file__).resolve().parents[2]  # tests/e2e/ -> tests/ -> defender/
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-v2sshd"
GOLDEN_AB3 = DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3"
# The run dir the vendored ab3 trace was recorded under; rewritten to the temp
# run dir on replay (the context-reproduction step).
AB3_ORIG_RUN_DIR = "/tmp/defender-runs/ab3-B"


# --- scripted turns + replay models ----------------------------------------

@dataclass
class Turn:
    """One scripted assistant turn. `tool_calls` is [(tool_name, args), ...]; a
    turn with no tool_calls is text-only and ENDS the agent loop."""
    tool_calls: list[tuple[str, dict]] = field(default_factory=list)
    text: str = ""


def messages_text(messages) -> str:
    """Flatten every message part's content to one string — used to assert a deny
    reason bounced back to the model as retry feedback."""
    out: list[str] = []
    for msg in messages:
        for part in getattr(msg, "parts", []):
            content = getattr(part, "content", None)
            if content is not None:
                out.append(content if isinstance(content, str) else str(content))
    return "\n".join(out)


class ReplayFn:
    """Stateful FunctionModel callable: emits the next scripted turn per model
    request. Past the script it returns a text-only turn so the loop terminates
    rather than hanging (mirrors a real run hitting its stop condition)."""

    __name__ = "ReplayFn"  # FunctionModel derives its model_name from this

    def __init__(self, turns: list[Turn]):
        self._turns = turns
        self.calls = 0
        # Flattened message history per request, so error-path scripts can assert
        # a gate's deny reason bounced back as retry feedback (the same trick
        # DenyProbe uses). Purely additive — the golden-replay scripts ignore it.
        self.seen: list[str] = []

    def __call__(self, messages, info) -> ModelResponse:
        self.seen.append(messages_text(messages))
        if self.calls < len(self._turns):
            t = self._turns[self.calls]
            self.calls += 1
            parts: list = []
            if t.text:
                parts.append(TextPart(content=t.text))
            for name, args in t.tool_calls:
                parts.append(ToolCallPart(tool_name=name, args=args))
            return ModelResponse(parts=parts or [TextPart(content="(done)")])
        return ModelResponse(parts=[TextPart(content="(replay exhausted)")])


class DenyProbe:
    """A model that emits one offending tool call, then text. Records the message
    history of each request so a script can assert the deny reason came back."""

    __name__ = "DenyProbe"

    def __init__(self, tool_name: str, args: dict):
        self._offending = (tool_name, args)
        self.calls = 0
        self.seen: list[str] = []

    def __call__(self, messages, info) -> ModelResponse:
        self.calls += 1
        self.seen.append(messages_text(messages))
        if self.calls == 1:
            name, args = self._offending
            return ModelResponse(parts=[ToolCallPart(tool_name=name, args=args)])
        return ModelResponse(parts=[TextPart(content="Acknowledged; stopping.")])


class NeverEndsModel:
    """A model that ALWAYS emits one benign, allowed tool call (read the alert),
    so the loop never reaches a text-only stop turn and instead runs straight
    into the request limit. Records `calls` for the limit assertion."""

    __name__ = "NeverEnds"

    def __init__(self, run_dir: Path):
        self.calls = 0
        self._alert = str(run_dir / "alert.json")

    def __call__(self, messages, info) -> ModelResponse:
        self.calls += 1
        return ModelResponse(parts=[ToolCallPart(tool_name="read_file", args={"path": self._alert})])


# --- the injected verb-registry seam (#611) --------------------------------
# The data-source transports are the one boundary below the model with no in-process
# twin, so a hermetic run fakes them. They enter through an INJECTION seam — the same
# shape as `make_model` — not by monkeypatching a module attribute: a registry is a
# VALUE the run is handed, and a fake registry has to satisfy the very signature the
# real validator reads.
#
# A fake verb is a plain annotated function: `def q(ctx, *, index: str) -> dict`. Its
# keyword-only params ARE its declared param surface, so the real query tool validates
# a model's `params` against the fake exactly as it would against `elastic_cli.VERBS`.
# A fake never classifies and never decides policy: it RECORDS what it was handed and
# then returns its payload or raises its fault. The exit code, the error class, the
# payload status, the breaker outcome are all the production code's job.


@dataclass(frozen=True)
class VerbCall:
    """One invocation a fake verb received: the harness-supplied `ctx` (the
    `VerbContext` — the run's tree + its scrubbed env) and the bound `params`."""

    verb: str
    ctx: Any
    params: dict


class VerbRecorder:
    """The observation channel for the injected registry: what each verb was HANDED.

    A fake that only returns a canned value proves nothing about the payload the tool
    built for it, so every scenario asserts against these records as well as against
    the row on disk."""

    def __init__(self) -> None:
        self.calls: list[VerbCall] = []

    def record(self, verb: str, ctx: Any, params: dict) -> None:
        self.calls.append(VerbCall(verb=verb, ctx=ctx, params=dict(params)))

    @property
    def verbs(self) -> list[str]:
        return [c.verb for c in self.calls]

    def only(self) -> VerbCall:
        assert len(self.calls) == 1, f"expected exactly 1 verb call, got {self.verbs}"
        return self.calls[0]


class FakeVerbs:
    """An injected verb registry — the drop-in for the production `ModuleVerbRegistry`.

    Dumb data: `{system: {verb: fn}}`. It declares the systems it was built with (a system
    mapped to an EMPTY dict is a DECLARED system with no verbs — the fail-closed case, and
    the reason this is a plain table rather than a defaultdict), and hands back the mapping
    for one. It makes no admission decision: an unknown system raises `KeyError`, and what
    the tool does about that is the tool's contract, not the fake's."""

    def __init__(self, table: Mapping[str, Mapping[str, Callable[..., Any]]]):
        self._table = {s: dict(v) for s, v in table.items()}

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

    def verbs(self, system: str) -> Mapping[str, Callable[..., Any]]:
        return self._table[system]


# --- trace mining (Layer 2): real tool_trace.jsonl -> scripted Turns -------

def _rewrite_paths(v, old: str | None, new: str | None):
    """Recursively rewrite `old`->`new` in string leaves of a tool-args value."""
    if isinstance(v, str):
        return v.replace(old, new) if old and new else v
    if isinstance(v, dict):
        return {k: _rewrite_paths(x, old, new) for k, x in v.items()}
    if isinstance(v, list):
        return [_rewrite_paths(x, old, new) for x in v]
    return v


def _turn_from_record(rec: dict, old_run_dir: str | None, new_run_dir: str | None) -> Turn:
    calls: list[tuple[str, dict]] = []
    text = ""
    for part in rec.get("message", {}).get("content", []):
        if part.get("type") == "tool_use":
            calls.append((part["name"], _rewrite_paths(part.get("input", {}), old_run_dir, new_run_dir)))
        elif part.get("type") == "text":
            text = part.get("text", "")
    return Turn(tool_calls=calls, text=text)


def load_turns_from_trace(
    trace_path: Path, *, old_run_dir: str | None = None, new_run_dir: str | None = None,
) -> list[Turn]:
    """Parse a real `tool_trace.jsonl` into scripted Turns.

    Rewrites `old_run_dir`->`new_run_dir` in string args — the context-repro step
    (a recorded write/read names an absolute path into the ORIGINAL run dir). Full
    replay of the nested gather subagent additionally needs stubbed adapter deps.
    """
    turns: list[Turn] = []
    for rec in read_jsonl_rows(Path(trace_path)):
        if rec.get("type") == "assistant":
            turns.append(_turn_from_record(rec, old_run_dir, new_run_dir))
    return turns


# --- fixture materialization, golden diffing, and the drive seam -----------

def materialize(tmp_path: Path, golden: Path, *, run_id: str, salt: str) -> Path:
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(golden / "alert.json", run_dir / "alert.json")
    (run_dir / "meta.json").write_text(json.dumps({"run_id": run_id, "salt": salt}))
    return run_dir


def normalize(text: str, *, run_dir: Path, salt: str, run_id: str) -> str:
    """Strip nondeterministic substrings so a replayed artifact diffs cleanly
    against a golden (the VCR/snapshot discipline: timestamps, salt, run id)."""
    return (text.replace(str(run_dir), "<RUN_DIR>")
                .replace(salt, "<SALT>")
                .replace(run_id, "<RUN_ID>"))


def drive(run_dir: Path, *, run_id: str, salt: str, main, gather=None, verbs=None, box=None):
    """Run the real driver with injected fake models — no monkeypatching of the
    model symbol. `main`/`gather` are plain replay callables (ReplayFn / DenyProbe
    / NeverEndsModel); this wraps each in `FunctionModel`, so scripts stay
    plumbing-free.

    `verbs` is the SECOND injection seam (#611): a `FakeVerbs` registry handed straight
    to `run_investigation(verbs=…)`, which threads it to the gather agent's query tool.
    Omit it and the run resolves the production `ModuleVerbRegistry` off `defender_dir`
    — a scenario that never calls `query` needs no registry, and one that does never
    reaches a real transport. It is passed only when supplied, so the seam stays optional
    at the boundary rather than making every replay name a registry it does not use.

    `make_model` is the driver's DI seam — now keyed on `(name, effort)`
    (#493): it dispatches on the model NAME (`driver.gather_model()` marks the nested
    gather; anything else is the main loop) so the main loop and a nested gather get
    distinct fakes, each returned as a `BuiltModel` (settings=None — a FunctionModel
    needs no provider settings). `override_allow_model_requests(False)` makes any real
    provider call raise, so the run is provably hermetic.

    `box` is the THIRD injection seam (#540): a `BoxExecutor` handed straight to
    `run_investigation(box=…)`, which threads it through `bind` onto `AgentDeps.box`, so
    every bash tool call in the replay executes through THAT executor. Omit it and the run
    builds the production box from `BoxSpec` — which needs a real daemon, so any scenario
    whose script contains a bash turn must supply one. Passed only when supplied, for the
    same reason `verbs` is: a bash-free replay should not have to name an executor it never
    reaches."""
    main_built = BuiltModel(FunctionModel(main), None)
    gather_built = BuiltModel(FunctionModel(gather), None) if gather is not None else None

    # The (name, effort) seam (#493) can only tell the two fakes apart by model NAME, so a
    # two-fake replay REQUIRES the MAIN and GATHER models to resolve to distinct names. They
    # do for the defaults (glm-5.2 vs kimi-k2.6); fail loud rather than silently route the
    # MAIN loop to the gather fake if a fixture/env ever collapses them onto one name (e.g.
    # DEFENDER_GATHER_MODEL set to match MAIN).
    if gather_built is not None and driver.resolve_main_model() == driver.gather_model():
        raise ValueError(
            "replay harness can't inject distinct main/gather fakes when both resolve to "
            f"the same model name ({driver.gather_model()!r}); the (name, effort) make_model "
            "seam keys on the name — set DEFENDER_MODEL / DEFENDER_GATHER_MODEL to differ."
        )

    def make_model(name, effort):
        if gather_built is not None and name == driver.gather_model():
            return gather_built
        return main_built

    seams: dict[str, Any] = {}
    if verbs is not None:
        seams["verbs"] = verbs
    if box is not None:
        seams["box"] = box
    with override_allow_model_requests(False):
        return asyncio.run(driver.run_investigation(
            alert_path=run_dir / "alert.json", run_dir=run_dir, run_id=run_id,
            defender_dir=DEFENDER, salt=salt, make_model=make_model, **seams,
        ))
