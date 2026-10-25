"""Reusable machinery for the hermetic e2e replay tests — NO test scripts."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

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
from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape  # noqa: E402

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

    def __init__(self, table: Mapping[str, Mapping[str, Callable[..., Any]]], *,
                 known_ids: frozenset[str] = frozenset()):
        self._table = {s: dict(v) for s, v in table.items()}
        self._known_ids = known_ids
        super().__init__(VerbGrant(
            role="fake",
            entries=tuple((s, v, "r") for s, verbs in self._table.items() for v in verbs),
        ))

    def branch_identities(self) -> frozenset[str]:
        return self._known_ids

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
    """Re-express a golden's recorded investigation.md writes as `append_block` calls (#810)."""
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
    """Parse a real `tool_trace.jsonl` into scripted Turns."""
    turns: list[Turn] = []
    for rec in read_jsonl_rows(Path(trace_path)):
        if rec.get("type") == "assistant":
            turns.append(_turn_from_record(rec, old_run_dir, new_run_dir))
    return _retarget_writes_as_appends(turns) if as_appends else turns



#: The run id a replay's folder carries when its scenario names none: a fixed fixture UUID.
#: #1187 (O2, declared change 1): `RunId` — so `Run.under`, which `drive` builds the run with —
#: admits canonical lowercase UUID text only, so the folder is never the bare word `run`.
REPLAY_RUN_ID = fixture_uuid("replay-run")


def materialize(tmp_path: Path, golden: Path, *, run_id: str = REPLAY_RUN_ID) -> Path:
    """The on-disk run dir a driven run starts from: `gather_raw/`, the copied alert, and the
    provenance stamp."""
    run_dir = tmp_path / (run_id if is_fixture_uuid_shape(run_id) else fixture_uuid(run_id))
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
    them), the review bundle (`drive`'s `holds` default) and the ORIENT shims (none)."""
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


def _default_tenant(agent: Path | None = None) -> tuple[Any, Path]:
    """The tenant a replay that names none runs as, and the PUBLISHED export the run reads
    (`<T>/exports/<commit>/`: its `agent/` and its `settings/`, one commit, O-B; #1108 P4,
    P-1/O11: every reader of tenant knowledge reads an export, made by the one real helper),
    never the clone's working tree.

    Without `agent`: the committed fixture tenant, set up under the current data root (#1120
    H2) — the test's own, or, for a module-scoped drive that runs before it, the session's
    (conftest's `session_data_root`). With `agent` (A8: a golden carries the agent content it
    reads): the fixture's settings with THAT tree as the agent half, under an id of its own
    (one per golden). Either is published through `tenant_1108_p4._support.publish_once` on each
    drive (an unchanged folder republishes the same commit), so an edit a test made to the
    tenant's folder is what the run reads."""
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root
    from defender.tests.tenancy.tenant_1108_p4._support import (
        export_dir,
        place_fixture,
        publish_once,
    )

    root = current_data_root()
    if agent is None:
        tenant_id = str(_tenants1106.fixture_tenant().id)
    else:
        tenant_id = fixture_uuid(f"tenant:golden-agent:{Path(agent).parent.name}")
        if not (root / tenant_id / "tenant.json").is_file():
            place_fixture(root, tenant_id, agent=Path(agent))
    published = publish_once(root.with_name(f"{root.name}-p4-forge"), root=root,
                             tenant_id=tenant_id)
    return published.tenant, export_dir(published.tenant, published.commit)


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
    token = getattr(run_tenant, "stage_token", None)
    agent = Path(run_tenant.agent)
    if token is None:
        # A run box is started over a run copy (`start_box` refuses a bare agent folder): a
        # replay tenant with none gets its agent half staged beside the run folder.
        from defender.tests.support.tenancy._run_copy_stage import staged_agent

        import tempfile

        agent, token = staged_agent(agent, Path(tempfile.mkdtemp(prefix="replay-run-copy-")))
    with _unsandboxed_allowed():
        return box_mod.start_box(run_dir, defender_dir, docker=_no_docker_daemon,
                                 tenant_agent=agent, tenant_id=run_tenant.tenant_id,
                                 staged_token=token)


def drive(  # noqa: PLR0913 — the harness entry point: one parameter per INJECTION SEAM
        run_dir: Path, *, run_id: str, main, gather=None, verbs=None,
        limits=None, box=None, store_factory=None, review_stages=None, bounds=None,
        toolset=None, resume=None, source_run: Run | None = None, defender_dir: Path | None = None,
        tenant: Any = None, orient_shim: Any = None, run_state: RunState | None = None,
        clock: Callable[[], Any] | None = None, roster: Any = None, systems: Any = None, wrap_model: Any = None,
        agent: Path | None = None) -> dict:
    """Run the real driver with injected fake models — no monkeypatching of the
    model symbol. `main`/`gather` are plain replay callables (ReplayFn / DenyProbe
    / NeverEndsModel); this wraps each in `FunctionModel`, so scripts stay
    plumbing-free.

    `agent` runs the replay as a tenant whose agent half is that tree (a golden's own `agent/`,
    #1108 P4 A8), published for real (`_default_tenant`); it cannot be combined with `tenant`."""
    # Legacy replay labels are retained in this helper's call shape. The real run identity
    # comes from its directory: materialize(run_id=<label>) names it the label's fixture UUID.
    state = run_state if run_state is not None else RunState(run_dir, run_dir.name)
    summary = driver_summary(
        run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs, limits=limits, box=box,
        store_factory=store_factory, review_stages=review_stages, bounds=bounds,
        toolset=toolset, resume=resume, source_run=source_run, defender_dir=defender_dir, tenant=tenant,
        orient_shim=orient_shim, run_state=state, clock=clock, roster=roster, systems=systems,
        wrap_model=wrap_model, agent=agent,
    )
    return {**summary, "run_state": state}


def driver_summary(  # noqa: PLR0913, C901 — `drive`'s seams, one parameter each
        run_dir: Path, *, run_id: str, main, gather=None, verbs=None,
        limits=None, box=None, store_factory=None, review_stages=None, bounds=None,
        toolset=None, resume=None, source_run: Run | None = None, defender_dir: Path | None = None,
        tenant: Any = None, orient_shim: Any = None, run_state: RunState | None = None,
        clock: Callable[[], Any] | None = None, roster: Any = None, systems: Any = None, wrap_model: Any = None,
        agent: Path | None = None) -> dict:
    """`drive`'s run (every seam as `drive` documents it), returning `run_investigation`'s own
    summary exactly as production's caller gets it. `run_state` is what the run is handed
    (`run_investigation(run_state=…)`), the caller keeping its reference; omitted, it is not
    passed at all, so the run resolves its own at the boundary — production's path (`run.py`
    hands none)."""
    _refuse_conflicting_store_seams(resume, store_factory)
    if agent is not None and tenant is not None:
        raise ValueError("drive(agent=...) builds its own tenant; tenant= beside it would be ignored")
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
        seams["source_run"] = source_run if source_run is not None else Run.under(fixture_runs_base(source.parent), source.name)
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
    roots: dict[str, Path] = {}
    if tenant is None:
        tenant, export = _default_tenant(agent)
        roots = {"agent_root": export / "agent", "settings_root": export / "settings"}
    run_tenant = _tenants1106.run_tenant(
        tenant, defender_dir=tree, **roots,
        dispatches_lead_zero=resume is None and verbs is not None,
    )
    seams["box"] = box if box is not None else production_unboxed_box(run_dir, tree, run_tenant)
    with override_allow_model_requests(False):
        return asyncio.run(driver.run_investigation(
            alert_path=RunPaths(run_dir).alert, run=Run.under(fixture_runs_base(run_dir.parent), run_dir.name),
            defender_dir=tree, make_model=make_model, tenant=run_tenant,
            orient_shim=orient_shim if orient_shim is not None else no_orient_shims, **seams,
        ))
