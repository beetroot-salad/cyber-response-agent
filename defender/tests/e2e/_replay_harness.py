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
it). Drive a run with `drive(run_dir, run_id=…, main=<callable>)`, where
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
import contextlib
import functools
import inspect
import os
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.records import _provenance  # noqa: E402
from defender import run_common  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender.run_repository import Run, RunPaths  # noqa: E402
from defender import box as box_mod  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import RosterRead, VerbRegistry  # noqa: E402
from defender.tests.support.runtime.permissions import _review_bundle
from defender.tests.support.tenancy import _tenants1106

DEFENDER = Path(__file__).resolve().parents[2]
GOLDEN = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd"
GOLDEN_AB3 = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-sshpivot-ab3"
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


class ToolRoster(ReplayFn):
    """`ReplayFn` + capture of the model-visible tool roster.

    `AgentInfo.function_tools` — the second argument every `FunctionModel` callable receives
    — is the tool definitions as the MODEL is offered them, which is the only honest place to
    read a registration or an advertised schema from: a registry entry, or the annotation
    re-inspected off the function object, would both pass while the wire carried something
    else. Lives here rather than in each suite that wants it: three suites had grown the same
    six-line subclass."""

    __name__ = "ToolRoster"

    def __init__(self, turns: list[Turn]):
        super().__init__(turns)
        self.tool_defs: list | None = None

    def __call__(self, messages, info) -> ModelResponse:
        if self.tool_defs is None:
            self.tool_defs = list(info.function_tools)
        return super().__call__(messages, info)


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
        # #1255 P1/C9: the model names the alert by its model path; a host path is refused.
        from defender.tests.support.runtime.state._1255_view import model_path

        self._alert = model_path(RunPaths(run_dir).alert, run_dir=run_dir)

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

    def _cold_verb_names(self, system: str) -> frozenset[str]:
        return frozenset(self._table.get(system, {}))

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


#: The verbs BOUND to investigation.md, which therefore carry no path to filter on — the name
#: is the whole predicate. `append_block` has been one since #810 and `fix_row` since #836.
_PATHLESS_INVESTIGATION_WRITES = ("append_block", "fix_row")


def _is_investigation_write(name: str, args: Mapping[str, Any]) -> bool:
    if name in _PATHLESS_INVESTIGATION_WRITES:
        return True
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
    last_name, last_args = turns[sites[-1][0]].tool_calls[sites[-1][1]]
    # The re-split rests on the LAST recorded write being the whole document. An `edit_file`
    # carries only the replacement FRAGMENT in `new_string`, so reading a target out of one
    # would silently replay a few lines as if they were the finished artifact — and the
    # byte-identity assertion downstream would then be comparing the golden against a stub.
    # Fail loudly on a golden shaped that way instead.
    target = last_args.get("content")
    if last_name != "write_file" or not isinstance(target, str):
        raise AssertionError(
            "the golden's last investigation.md write is a "
            f"{last_name} — `_retarget_writes_as_appends` needs a whole-document "
            "`write_file` there to re-split, not an anchored fragment"
        )
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



def materialize(tmp_path: Path, golden: Path, *, run_id: str = "run") -> Path:
    """The on-disk run dir a driven run starts from: `gather_raw/`, the copied alert, and the
    provenance stamp.

    Takes no `run_id`/`salt`: it seeds NOTHING salted. Both were parameters only because this
    used to write the run's retired metadata file (#647); the trust token is now minted in
    process by `run_common.materialize_run` and threaded as a value, so there is nothing
    on disk for this to seed. Keeping the parameters would let a test pass `salt=` and believe
    it had set up a salted run dir — setup a test can silently pass without.

    THE STAMP IS WRITTEN HERE BECAUSE PRODUCTION WRITES IT (#976). What that buys is FILE-SET
    parity with `run_common.materialize_run` — `test_salt_origin_647`'s parity arm, the
    same trap #647's was built to catch pointing the other way. It is NOT message 0's listing:
    `workspace_map._unlisted()` suppresses the stamp, so a replayed message 0 is byte-identical
    either way, and a reader deciding whether the other hand-built run-dir fixtures need one
    should weigh the parity arm rather than the prompt.

    Captured against `run_common.REPO_ROOT` — production's own constant, not a second path
    derived by counting `parents[...]` here — so "like production's" is a fact rather than a
    coincidence of where this file sits in the tree."""
    run_dir = tmp_path / run_id
    paths = RunPaths(run_dir)
    paths.gather_raw.mkdir(parents=True)
    plant_alert(run_dir, (golden / "alert.json").read_bytes())
    _provenance.write(paths.provenance, _harness_provenance())
    return run_dir


def plant_alert(run_dir: Path, raw: bytes) -> None:
    """The alert and its record in the run's input directory, as `materialize_run` leaves them
    (the committed tenants' mapping derives the facts)."""
    from defender.tests.support.storage import _alert_plant

    _alert_plant.plant_alert(run_dir, raw)


@functools.cache
def _harness_provenance() -> _provenance.RunProvenance:
    """The capture, taken ONCE per test session rather than once per fixture.

    `capture_tree` shells out to `git rev-parse` and to a whole-repo `git status
    --untracked-files=all`, and this builder runs in ~120 places across the suite. What the
    parity arm needs is that the harness writes the same FILE production writes; it does not
    need a fresh interrogation of an unchanging checkout per test, and paying for one turns a
    hermetic fixture into a per-test subprocess pair."""
    return _provenance.capture_tree(run_common.REPO_ROOT)


#: Every frame delimiter, whatever salt it carries. Since #875 a run has no single salt to
#: substitute: `wrap_fresh` mints one per frame, after the content is in hand, so normalizing
#: has to match the SHAPE rather than a known value. Strictly better for a golden diff — it
#: also normalizes frames the old single-substitution missed (a stage salt, a nested frame).
_FRAME_TAG_RE = re.compile(r"<(/?)run-[0-9a-f]+-([a-z_-]+)>")


def normalize(text: str, *, run_dir: Path, run_id: str) -> str:
    """Strip nondeterministic substrings so a replayed artifact diffs cleanly
    against a golden (the VCR/snapshot discipline: timestamps, frame salts, run id)."""
    return (_FRAME_TAG_RE.sub(r"<\1run-<SALT>-\2>", text)
                .replace(str(run_dir), "<RUN_DIR>")
                .replace(run_id, "<RUN_ID>"))


def no_orient_shims(argv: list[str], env: dict[str, str]) -> None:
    """`drive`'s default ORIENT shim runner: every shim-backed section is absent."""
    return None


#: What the correlation lead (`l-00c`) says under a replay that does not script it (#1222 C01): a
#: usable summary from a lead that issued no call (C38), so an incidental replay's lead draws
#: none of the turns scripted for MAIN's own leads.
DEFAULT_CORRELATION_SUMMARY = (
    "Window bound 2026-05-25T13:00:00Z..2026-05-25T17:00:00Z, anchored on the alert's "
    "timestamp field; no call issued, so no counts to report.")
_DISPATCHED_LEAD = re.compile(r"\n## Dispatch\n```yaml\n(?:.*\n)*?lead_id: (\S+)\n")


def _awaiting(fn):
    """`fn` as an async model function: a double that answers late hands back an awaitable (a
    delay or a hang that must be awaited ON THE EVENT LOOP, so a deadline can cut it), which a
    sync `FunctionModel` function would be handed back unawaited."""
    async def call(messages, info):
        # The double runs on a worker thread, as a sync `FunctionModel` function always has: a
        # double that blocks (waits on another lead) must not stall the event loop.
        out = await asyncio.to_thread(fn, messages, info)
        return await out if inspect.isawaitable(out) else out

    call.__name__ = getattr(fn, "__name__", type(fn).__name__)
    return call


def _with_default_correlation(gather, main):
    """`gather` (or `main`, when none is given) as the gather model, except that the
    correlation lead's conversation is answered by its own default fake. A `gather` that routes
    leads itself (`by_lead`, the #1222 `LeadRouter`) or is marked `serves_correlation` (the
    #808 scenario builder's, whose script is `l-00c`'s) is already that."""
    if gather is not None and (hasattr(gather, "by_lead") or getattr(gather, "serves_correlation", False)):
        return gather
    inner = gather if gather is not None else main

    def fn(messages, info):
        found = _DISPATCHED_LEAD.search(messages_text(messages))
        if found is not None and found.group(1) == "l-00c":
            return ModelResponse(parts=[TextPart(content=DEFAULT_CORRELATION_SUMMARY)])
        return inner(messages, info)

    fn.__name__ = getattr(inner, "__name__", "gather")
    return fn


def _fake_make_model(main, gather, *, dispatches_correlation: bool, wrap_model: Any = None):
    """The driver's `make_model` seam over the replay doubles: the gather model NAME gets
    `gather` (the correlation lead drawing its own default fake when the run dispatches it,
    C01), every other name gets `main`. `wrap_model(kind, model)` (#1243), when given, wraps
    each scripted model (`kind` "main" or "gather") before it is handed out."""
    def wrap(kind: str, model: Any) -> Any:
        return wrap_model(kind, model) if wrap_model is not None else model

    main_built = BuiltModel(wrap("main", FunctionModel(_awaiting(main))), None)
    gather_fn = (
        _with_default_correlation(gather, main)
        if dispatches_correlation and driver.resolve_main_model() != driver.gather_model()
        else gather)
    gather_built = (
        BuiltModel(wrap("gather", FunctionModel(_awaiting(gather_fn))), None)
        if gather_fn is not None else None)

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

    return make_model


def investigate_as_handed(main, gather=None, *, review_stages=None, orient_shim=None):
    """A production `investigate` for `run._drive_investigation(investigate=…)`: the REAL driver
    run with EXACTLY the keywords production composed for it — the `run`, the `RunTenant`, the
    roster, the verb registry, the box, and whatever else run.py hands its driver — plus only
    what no hermetic run can build: the fake models (`main` / `gather`, wired as `drive` wires
    them), the review bundle (`drive`'s `holds` default) and the ORIENT shims (none).

    For a scenario about what run.py HANDS the run (#1256: its one judgement of the systems):
    `drive` / `_spec1222.run_alert` re-resolve the tenant and build a fresh `Run`, so anything
    run.py attached to either, or passed as a further lifecycle keyword, never reaches their
    driver. Composed with production's own `_run_investigation_lifecycle` and
    `_drive_investigation`, this keeps the whole chain production's."""
    def investigate(**handed: Any) -> dict:
        make_model = _fake_make_model(
            main, gather,
            dispatches_correlation=handed.get("resume") is None and handed.get("verbs") is not None)
        with override_allow_model_requests(False):
            return asyncio.run(driver.run_investigation(
                **handed, make_model=make_model,
                review_stages=review_stages if review_stages is not None else (
                    _review_bundle.bundle(composer=_review_bundle.composer_reply("holds"))),
                orient_shim=orient_shim if orient_shim is not None else no_orient_shims))

    return investigate


def _refuse_conflicting_store_seams(resume, store_factory) -> None:
    """`resume=` and `store_factory=` name the same thing and cannot both be honoured.

    `driver._resolve_store_factory` lets the resume win, which is right for the driver — the
    two can disagree about which database holds the branch point — but silent here. Every
    neighbouring scenario injects `store_factory=` to capture the store handle it later asserts
    over, so a #920 script written to that shape would get an empty sink and die on `sink[0]`
    with an `IndexError` naming nothing. A resume already forks INTO the source run's store;
    that handle is the one to assert over.
    """
    if resume is not None and store_factory is not None:
        raise ValueError(
            "drive(resume=…) derives its store from the spec's source run, so a store_factory= "
            "beside it is silently discarded — assert over the source run's own handle instead")


def _default_tenant() -> Any:
    """The tenant a replay that names none runs as: the committed fixture, set up under the
    current data root (#1120 H2) — the test's own, or, for a module-scoped drive that runs
    before it, the session's (conftest's `session_data_root`)."""
    return _tenants1106.fixture_tenant()


def _no_docker_daemon(argv: list[str], **_kw: Any) -> Any:
    """The docker a hermetic replay has: none. `start_box` turns the failed call into its
    startup `BoxFault`, which the operator's opt-out turns into production's unboxed mode."""
    raise FileNotFoundError("docker: a hermetic replay has no daemon")


@contextlib.contextmanager
def _unsandboxed_allowed() -> Iterator[None]:
    """`DEFENDER_ALLOW_UNSANDBOXED=1` for the length of the block, the prior value (or its
    absence) restored after — scoped to one `start_box` call, never left set for the test."""
    prior = os.environ.get(box_mod._ALLOW_UNSANDBOXED)
    os.environ[box_mod._ALLOW_UNSANDBOXED] = "1"
    try:
        yield
    finally:
        if prior is None:
            os.environ.pop(box_mod._ALLOW_UNSANDBOXED, None)
        else:
            os.environ[box_mod._ALLOW_UNSANDBOXED] = prior


def production_unboxed_box(run_dir: Path, defender_dir: Path, run_tenant: Any) -> Any:
    """The box a hermetic replay runs its bash lane in: production's unboxed mode, reached the
    way `run.py` reaches it (`start_box(run_dir, defender_dir, tenant_agent=…, tenant_id=…)`)
    with no daemon and the opt-out set for this call alone (#1255 C6). Nothing it writes or logs
    is hidden: the opt-out's "running UNSANDBOXED" warning and the startup fault's did-not-run
    scrub marker beside the run folder (`RunPaths.scrub_verdict`) are production's, and land in
    every replay that takes this default."""
    with _unsandboxed_allowed():
        return box_mod.start_box(run_dir, defender_dir, docker=_no_docker_daemon,
                                 tenant_agent=run_tenant.agent, tenant_id=run_tenant.tenant_id)


def drive(  # noqa: PLR0913 — the harness entry point: one parameter per INJECTION SEAM
        run_dir: Path, *, run_id: str, main, gather=None, verbs=None,
        limits=None, box=None, store_factory=None, review_stages=None, bounds=None,
        toolset=None, resume=None, source_run: Run | None = None, defender_dir: Path | None = None,
        tenant: Any = None, orient_shim: Any = None, run_state: RunState | None = None,
        clock: Callable[[], Any] | None = None, roster: Any = None, systems: Any = None, wrap_model: Any = None) -> dict:
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

    `tenant` (#1106) is the run's accepted `Tenant`; omitted, the committed fixture tenant set
    up under this test's own data root and accepted through the real `accept_tenant` (#1120
    H2). A scenario's grants are its tenant folder's `verb-grants.yaml`: it plants a tenant
    whose table says what it needs (#1107). The tenant is handed to the driver as one
    `RunTenant` (`_tenants1106.run_tenant`, i.e. `resolve_run_tenant`).

    `box` is the THIRD injection seam (#540): a `BoxExecutor` handed straight to
    `run_investigation(box=…)`, which threads it through `bind` onto `AgentDeps.box`, so
    every bash tool call in the replay executes through THAT executor. A scenario that wants
    to ASSERT on what crossed the boundary passes its own recording executor.

    Omitted, it defaults to PRODUCTION'S unboxed mode (#1255 C6: "every mode includes the
    hermetic harness"): `box.start_box` over a docker that has no daemon (`_no_docker_daemon`),
    with `DEFENDER_ALLOW_UNSANDBOXED=1` set for that one call and restored after
    (`_unsandboxed_allowed`) — the operator's opt-out, taken the way `run.py` takes it, with the
    run's tenant half and identity. So whatever production builds for an unboxed run (the run's
    environment today; the model view, once #1255 lands) is what every replay's bash lane runs
    in, rather than a lane only tests take. These runs have no daemon, and the alternative (the
    sandboxed default with no opt-out) makes every bash turn fail closed on infrastructure. It
    does not weaken the boundary claim, which is pinned directly in the #540 suite: without the
    opt-out a startup fault aborts the run.

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
    `run_investigation` accepts it.

    `toolset` is the EIGHTH injection seam (#872, O7/M6): a foreign toolset — one defender
    does not own, carrying a tool whose return is a dict or a list — handed straight to
    `run_investigation(toolset=…)`. It exists because O1 is otherwise UNDRIVABLE on the
    shipped tree: all fourteen registered tools are annotated `-> str` except `query`, and
    `query`'s dict is discarded by `QueryCapture` at every candidate seam, so there is no
    in-tree value for the TOON gate to act on and no way to point one at it without patching
    a module attribute. Supplied once at the entry point and held for the whole run, like the
    nine existing optional seams; omitted, the run's tool set, capability list and
    model-visible text are identical to today's. Passed through only when supplied. RED until
    `run_investigation` accepts it.

    `resume` is NOT an injection seam — it is #920's turn-N branch, a runtime parameter
    (`branch.BranchSpec`) naming the run and the message this one continues from. It rides here
    because a resumed run is still a driven replay in every other respect, and the alternative
    is a second copy of this function's model wrapping, hermetic guard and seam assembly in the
    #920 scripts. Passed through only when supplied, so every existing call is byte-identical.
    It is MUTUALLY EXCLUSIVE with `store_factory=` — see `_refuse_conflicting_store_seams`.

    `defender_dir` is the TREE the run reads (#1003): the catalog it walks at run start, the
    adapters it rosters, the skills it prompts from. It defaults to this checkout, which is
    what every scenario before #1003 drove; a scenario about the run-start check over a
    DEPLOYMENT's own catalog (a planted template whose `verb:` disagrees with the shipped
    table) hands in a planted mirror of the tree instead. The same tree feeds the box's env,
    so a bash turn in such a scenario runs against the tree the run was told it is in.

    `orient_shim` is ORIENT's shim runner (`orient.ShimRunner`): the three read-only
    subprocesses behind message 0's lessons and corpus-vocabulary sections. Omitted, it is
    `no_orient_shims` — those sections are absent, the fail-safe shape a failed shim already
    has, and no scenario here is about them. Real, they were over a third of the whole unit
    suite's CPU (three interpreters per drive, ~0.7s of a ~0.95s replay) and made every replay
    depend on the checked-in lessons corpus. A scenario about those sections passes
    `orient._shim`.

    `run_state` is the run's live state (#1235 round 3). Production's summary does not carry
    it: `run_investigation(run_state=…)` is the seam, resolved once at its boundary to
    `RunState(run_dir, run_id)` when handed none. The harness builds that same state itself,
    injects it, and returns it in ITS OWN result under `"run_state"` — the one place a driven
    test reaches a run's state. A scenario whose run ends by RAISING (no result comes back)
    builds the state first and passes it here, so it still holds what the run decided on.
    `roster` is the adapters roster the run reads (`run_investigation(roster=…)`): the adapter
    modules whose declared settings checks judge each granted system at run start (#1256).
    Omitted, an injected registry that carries its own roster (`ModuleVerbRegistry.roster`,
    e.g. a planted estate's) hands the run that one, so the run judges the adapters it calls,
    as production's one roster does; otherwise the run reads `defender_dir`'s.
    `systems` is the run's judgement of its granted systems that run.py made before the run
    folder existed and hands its lifecycle (#1256 r4: one judgement per run;
    `run_investigation(systems=…)`). Passed through only when supplied: omitted, the driver
    judges them itself, as it does when started without one.

    `driver_summary` is the same drive returning production's summary untouched.

    `clock` is the run clock's source (#1255: `run_investigation(clock=…)`, a zero-argument
    callable returning an aware UTC datetime). Passed through only when supplied, so every
    existing call is byte-identical; RED until `run_investigation` accepts it.

    `wrap_model(kind, model)` (#1243) is applied to each scripted `FunctionModel` before it is
    handed out as a `BuiltModel` — `kind` is `"main"` or `"gather"` — so a scenario can put a
    production model wrapper (the provider retrier) between the run and its fake. Omitted, the
    fakes are handed out bare, as before."""
    # Legacy replay labels are retained in this helper's call shape. The real run identity
    # comes from its directory; materialize(run_id=...) preserves labels that are asserted.
    state = run_state if run_state is not None else RunState(run_dir, run_dir.name)
    summary = driver_summary(
        run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs, limits=limits, box=box,
        store_factory=store_factory, review_stages=review_stages, bounds=bounds,
        toolset=toolset, resume=resume, source_run=source_run, defender_dir=defender_dir, tenant=tenant,
        orient_shim=orient_shim, run_state=state, clock=clock, roster=roster, systems=systems,
        wrap_model=wrap_model,
    )
    return {**summary, "run_state": state}


def driver_summary(  # noqa: PLR0913, C901 — `drive`'s seams, one parameter each
        run_dir: Path, *, run_id: str, main, gather=None, verbs=None,
        limits=None, box=None, store_factory=None, review_stages=None, bounds=None,
        toolset=None, resume=None, source_run: Run | None = None, defender_dir: Path | None = None,
        tenant: Any = None, orient_shim: Any = None, run_state: RunState | None = None,
        clock: Callable[[], Any] | None = None, roster: Any = None, systems: Any = None, wrap_model: Any = None) -> dict:
    """`drive`'s run (every seam as `drive` documents it), returning `run_investigation`'s own
    summary exactly as production's caller gets it. `run_state` is what the run is handed
    (`run_investigation(run_state=…)`), the caller keeping its reference; omitted, it is not
    passed at all, so the run resolves its own at the boundary — production's path (`run.py`
    hands none)."""
    _refuse_conflicting_store_seams(resume, store_factory)
    tree = defender_dir if defender_dir is not None else DEFENDER
    make_model = _fake_make_model(main, gather,
                                  dispatches_correlation=resume is None and verbs is not None,
                                  wrap_model=wrap_model)

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
    if toolset is not None:
        seams["toolset"] = toolset
    if resume is not None:
        seams["resume"] = resume
        source = resume.source_run_dir
        seams["source_run"] = source_run if source_run is not None else Run.under(source.parent, source.name)
    elif source_run is not None:
        seams["source_run"] = source_run
    if run_state is not None:
        seams["run_state"] = run_state
    if clock is not None:
        seams["clock"] = clock
    if roster is None and isinstance(getattr(verbs, "roster", None), RosterRead):
        roster = verbs.roster
    if roster is not None:
        seams["roster"] = roster
    if systems is not None:
        seams["systems"] = systems
    # #1106: the run's TENANT and its per-run GRANTS are two required inputs of the driver (no
    # grant is fixed per process, and no reader finds the settings folder itself). A scenario
    # names its own tenant when it is about one; every other replay runs as the committed
    # fixture tenant set up under the test's data root (#1120 H2) — accepted through the real
    # `accept_tenant`, never a hand-built value.
    #
    # The driver takes them as ONE value (`RunTenant`), resolved before it runs, the way
    # `run.py` resolves it before the box: item 3's dispatch identity is checked here — for a
    # scenario that will dispatch the lead (an injected registry, no resume), exactly the runs
    # the driver itself would dispatch it on — so a scenario about a disagreeing lead-zero
    # config still sees `CorrelationDispatchError` out of `drive()` before anything is spent.
    run_tenant = _tenants1106.run_tenant(
        tenant if tenant is not None else _default_tenant(),
        defender_dir=tree,
        dispatches_lead_zero=resume is None and verbs is not None,
    )
    seams["box"] = box if box is not None else production_unboxed_box(run_dir, tree, run_tenant)
    with override_allow_model_requests(False):
        return asyncio.run(driver.run_investigation(
            alert_path=RunPaths(run_dir).alert, run=Run.under(run_dir.parent, run_dir.name),
            defender_dir=tree, make_model=make_model, tenant=run_tenant,
            orient_shim=orient_shim if orient_shim is not None else no_orient_shims, **seams,
        ))
