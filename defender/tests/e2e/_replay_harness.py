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

Below the model there are exactly SEVEN injected seams, and every one is a VALUE the run
is handed (never a monkeypatched module attribute): the model itself (`make_model`), the
data-source verb registry (`verbs=` → `run_investigation(verbs=…)`, #611), the budget cap
table (`limits=` → `run_investigation(limits=…)`, #631), the box executor (`box=` →
`run_investigation(box=…)`, #540), the per-case session store (`store_factory=` →
`run_investigation(store_factory=…)`, #705), and the review-stage bundle (`review_stages=`
→ `run_investigation(review_stages=…)`, #774) the close tool's live write-time gate drives
its three model-backed stages through, and the gate's bounds object (`bounds=` →
`run_investigation(bounds=…)`, the #774 repair) carrying the request ceiling's own base. The fifth exists because environment steering
cannot express contention or corruption — it can only express "the store is missing", one
third of O19's stated domain, while reading as covered — and the project profile forbids
the `monkeypatch.setattr` that would express the rest (R12). The sixth exists because the
gate's three review-stage calls have no injection point in the design at all — without a
value the run is handed they are live provider calls, and no hermetic scenario could drive
a single arm of the gate. A scenario hands `drive` a
`FakeVerbs` table of plain
annotated functions; the real query tool validates against their real signatures, the real
capture capability writes the real rows. A scenario hands `drive` a `limits` dict; the real
accounting hook and the real enforcing seam read it, so a run crosses a real cap in a few
`Turn(...)` lines. The `box` seam is the same shape one layer lower: the bash tool's
execution boundary is a container the test process cannot start hermetically, so a scenario
hands in a `BoxExecutor` built over a fake transport and the REAL framing codec still runs
on both sides.
"""
from __future__ import annotations

import asyncio
import re
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender._io import read_jsonl_rows  # noqa: E402
from defender import run_common  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import VerbRegistry  # noqa: E402
from defender.tests import _review_bundle  # noqa: E402

DEFENDER = Path(__file__).resolve().parents[2]
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-v2sshd"
GOLDEN_AB3 = DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3"
AB3_ORIG_RUN_DIR = "/tmp/defender-runs/ab3-B"



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

    __name__ = "ReplayFn"

    def __init__(self, turns: list[Turn]):
        self._turns = turns
        self.calls = 0
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


class FakeVerbs(VerbRegistry):
    """An injected verb registry — the drop-in for the production `ModuleVerbRegistry`.

    Dumb data: `{system: {verb: fn}}`. It declares the systems it was built with (a system
    mapped to an EMPTY dict is a DECLARED system with no verbs — the fail-closed case, and
    the reason this is a plain table rather than a defaultdict), and hands back the mapping
    for one. It makes no admission decision beyond a real, everything-it-declares `VerbGrant`
    built from its own table (#632 — pre-dating the per-role grant, this pre-authorization-era
    fake grants itself full access rather than making every #611-era scenario author one)."""

    def __init__(self, table: Mapping[str, Mapping[str, Callable[..., Any]]]):
        self._table = {s: dict(v) for s, v in table.items()}
        super().__init__(VerbGrant(
            role="fake",
            entries=tuple((s, v, "r") for s, verbs in self._table.items() for v in verbs),
        ))

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

    def verbs(self, system: str) -> Mapping[str, Callable[..., Any]]:
        return self._table[system]



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


def _is_investigation_write(name: str, args: Mapping[str, Any]) -> bool:
    return (name in ("write_file", "edit_file")
            and str(args.get("path", "")).endswith("investigation.md"))


def _split_at_fences(text: str, n: int) -> list[str]:
    """Cut `text` into `n` pieces on ```invlang fence boundaries, so every running
    concatenation is a valid prefix document rather than a half-open block."""
    if n <= 1:
        return [text]
    starts = [m.start() for m in re.finditer(r"(?m)^```invlang", text)]
    if len(starts) < n:
        return [text] + [""] * (n - 1)
    picks = ([0] + [starts[round(i * len(starts) / n)] for i in range(1, n)] + [len(text)])
    return [text[a:b] for a, b in zip(picks, picks[1:], strict=False)]


def _retarget_writes_as_appends(turns: list[Turn]) -> list[Turn]:
    """Re-express a golden's recorded investigation.md writes as `append_block` calls (#810).

    The goldens were recorded when main held `write_file`/`edit_file`, and at least one of
    them (sshpivot-ab3) used `write_file` as a whole-document REWRITER — its four recorded
    contents share a 176-character common prefix and then diverge, because the model kept
    restating vertex rows instead of refining them. Main cannot express that any more, and
    should not: the artifact is append-only.

    So the recorded writes are not translated one-for-one — there is no delta to translate.
    The LAST recorded content is the document the run actually produced, and it is split
    across the same number of turns, on fence boundaries. Turn count, gather dispatches, bash
    and read calls are all untouched, and the final artifact is byte-identical to the golden,
    which is what the replays assert. What is lost is the intermediate states, which were
    never asserted and which the surface no longer admits."""
    sites = [
        (t_i, c_i)
        for t_i, turn in enumerate(turns)
        for c_i, (name, args) in enumerate(turn.tool_calls)
        if _is_investigation_write(name, args)
    ]
    if not sites:
        return turns
    _, last_args = turns[sites[-1][0]].tool_calls[sites[-1][1]]
    target = last_args.get("content") or last_args.get("new_string") or ""
    for (t_i, c_i), chunk in zip(sites, _split_at_fences(target, len(sites)), strict=True):
        turns[t_i].tool_calls[c_i] = ("append_block", {"text": chunk})
    return turns


def load_turns_from_trace(
    trace_path: Path, *, old_run_dir: str | None = None, new_run_dir: str | None = None,
    as_appends: bool = False,
) -> list[Turn]:
    """Parse a real `tool_trace.jsonl` into scripted Turns.

    Rewrites `old_run_dir`->`new_run_dir` in string args — the context-repro step
    (a recorded write/read names an absolute path into the ORIGINAL run dir). Full
    replay of the nested gather subagent additionally needs stubbed adapter deps.

    Parsing is FAITHFUL by default: a recorded `write_file` comes back as a `write_file`
    turn. `test_projection_move_705` reads this function as a frozen consumer of the
    projection's format and would not be able to tell a format regression from a
    translation if the translation were unconditional.

    `as_appends=True` re-expresses recorded investigation.md writes as `append_block` —
    what a script needs to DRIVE a golden through MAIN, whose write grant is `append`
    since #810. See `_retarget_writes_as_appends` for why that is a re-split rather than
    a rename.
    """
    turns: list[Turn] = []
    for rec in read_jsonl_rows(Path(trace_path)):
        if rec.get("type") == "assistant":
            turns.append(_turn_from_record(rec, old_run_dir, new_run_dir))
    return _retarget_writes_as_appends(turns) if as_appends else turns



def materialize(tmp_path: Path, golden: Path) -> Path:
    """The on-disk run dir a driven run starts from: `gather_raw/` plus the copied alert.

    Takes no `run_id`/`salt`: it seeds NOTHING salted. Both were parameters only because this
    used to write the run's retired metadata file (#647); the trust token is now minted in
    process by `run_common.materialize_run_dir` and threaded as a value, so there is nothing
    on disk for this to seed. Keeping the parameters would let a test pass `salt=` and believe
    it had set up a salted run dir — setup a test can silently pass without."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(golden / "alert.json", run_dir / "alert.json")
    return run_dir


def normalize(text: str, *, run_dir: Path, salt: str, run_id: str) -> str:
    """Strip nondeterministic substrings so a replayed artifact diffs cleanly
    against a golden (the VCR/snapshot discipline: timestamps, salt, run id)."""
    return (text.replace(str(run_dir), "<RUN_DIR>")
                .replace(salt, "<SALT>")
                .replace(run_id, "<RUN_ID>"))


def drive(  # noqa: PLR0913 — the harness entry point: one parameter per INJECTION SEAM
        run_dir: Path, *, run_id: str, salt: str, main, gather=None, verbs=None,
        limits=None, box=None, store_factory=None, review_stages=None, bounds=None):
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
    every bash tool call in the replay executes through THAT executor. A scenario that wants
    to ASSERT on what crossed the boundary passes its own recording executor.

    Omitted, it defaults to `box.unboxed_executor()` — host execution, no container. That is
    the honest default for a HERMETIC replay: these runs have no daemon, and the alternative
    (the inert production default) makes every bash turn fail closed on infrastructure rather
    than exercising the lane the scenario is about. It does not weaken the boundary claim,
    which is pinned directly in the #540 suite — `test_no_box_failure_path_executes_in_process`
    and `test_tool_bash_executes_through_the_injected_box_seam` assert that production has no
    unboxed path, and this default is reachable only from a test.

    `review_stages` is the SIXTH injection seam (#774), demanded rather than described: the
    live write-time gate drives three lenses and a composer from inside the close tool, and
    without a value the run is handed they are real provider calls that no hermetic scenario
    can drive.

    Omitted, it defaults to a bundle whose four stages answer without a provider and whose
    composer finds `holds` — the same reasoning as the `box` default above, one layer up.
    It was passed through ONLY when supplied while #797 left the bundle empty, which was
    harmless exactly as long as there was no reviewer to build: once #796 bound one,
    `run_investigation`'s own default became `live_review_stages`, and every replay that
    drafted a confident disposition built three live provider clients, wrote their empty
    `review_*_live_trace.jsonl` files into the run dir, and had the review fail on the
    unreachable provider. The scripts still passed — `override_allow_model_requests(False)`
    keeps that hermetic — but they were asserting the SHAPE OF A FAULT while believing they
    asserted the interim posture, and #796's reviewer had no end-to-end coverage at all. A
    scenario about a gate arm still hands in its own bundle; `holds` is the default because
    a replay of a real run is a happy-path script.

    `bounds` is the SEVENTH injection seam (#774 repair): the gate's bounds object, carrying
    the request ceiling's own BASE alongside the forced-turn cap. Without it the base is a
    module constant with no environment backing and no path through the entry point, so
    "the raised ceiling is READ FROM the cap rather than restated as a literal" cannot be
    discriminated at all — the shipped base and a hardcoded copy of it are the same number.
    Reaching it any other way means the technique this project ratchets in CI, which is why
    the seam is the demand. Passed through only when supplied. RED until
    `run_investigation` accepts it."""
    main_built = BuiltModel(FunctionModel(main), None)
    gather_built = BuiltModel(FunctionModel(gather), None) if gather is not None else None

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
    if limits is not None:
        seams["limits"] = limits
    if store_factory is not None:
        seams["store_factory"] = store_factory
    seams["review_stages"] = review_stages if review_stages is not None else (
        _review_bundle.bundle(composer=_review_bundle.composer_reply("holds"))
    )
    if bounds is not None:
        seams["bounds"] = bounds
    seams["box"] = box if box is not None else box_mod.unboxed_executor(
        env=run_common.run_env(DEFENDER, run_dir),
    )
    with override_allow_model_requests(False):
        return asyncio.run(driver.run_investigation(
            alert_path=run_dir / "alert.json", run_dir=run_dir, run_id=run_id,
            defender_dir=DEFENDER, salt=salt, make_model=make_model, **seams,
        ))
