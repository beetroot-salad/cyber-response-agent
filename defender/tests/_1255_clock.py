"""#1255 slice D — the run clock's test machinery. Defines no tests.

The run clock (design rev 4, "Time"; dossier seam) is one host-owned clock every model-visible
time comes from. Its source is injected as `driver.run_investigation(clock=<zero-arg callable
returning an aware UTC datetime>)`; nothing else about it is fixed. Everything here drives the
REAL entry points with a source the test moves BY HAND:

* `FakeClock` — the injected source. It never moves on its own: a test (or a scripted model
  standing in for work that takes time) calls `advance`. So every reading the run can take is
  known before the run starts, and an expected time is a sum the test writes down, never a
  value read back from production.
* `Clocked` / `script` — a scripted model whose step `i` first advances the clock by its own
  seconds (the model "took that long"), then answers. A step may be a callable over the
  request text, for a call whose argument comes from what the model was shown (a lesson path).
* `drive_clocked` — `_replay_harness.drive(…, clock=…)`: the harness's own drive, with its
  defaults (production's unboxed mode for the box, #1255 C6), plus the clock. A name kept for
  the scenarios' keyword set (and `test_budget_enforcement_631`, which imports it).
* `run_main` — the dossier's FIXED arm composition: `run.main(argv, lifecycle=partial(
  run._run_investigation_lifecycle, investigate=partial(run._drive_investigation,
  investigate=<driver call with clock=>), start_box=…, stop_box=…, scrub=…), …)`, for a natural
  run (`[alert, --tenant T]`) and for an arm (`[--tenant T, --episode E, --world W]`) alike.
  The box is production's unboxed mode (`start_box` over a docker that is not there, with
  `DEFENDER_ALLOW_UNSANDBOXED`), as slice E's twin composition runs it.

The fakes inject time; none of them decides anything the design leaves to production.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import functools
import re
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender import _clock  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.tests import _review_bundle  # noqa: E402
from defender.tests.e2e import _replay_harness as H  # noqa: E402

DEFENDER = H.DEFENDER

#: Where every natural run's clock source starts: years after any wall time this suite runs at,
#: so a stamp taken from the wall clock can never coincide with one taken from the run clock,
#: and every framework message timestamp (pydantic stamps those itself, from the wall clock) is
#: EARLIER than every run-clock time — O4's "never earlier than the history's last timestamp"
#: then cannot be failed by the fixture itself (finding F-msg-ts in the slice report).
SOURCE_START = dt.datetime(2031, 3, 4, 5, 6, 7, tzinfo=dt.UTC)
#: Where an ARM's own clock source starts: later still, and nowhere near the source's readings,
#: so "the arm read its own source's absolute time" and "the arm started at the source's
#: reading" can never produce the same number.
ARM_START = dt.datetime(2040, 1, 1, 0, 0, 0, tzinfo=dt.UTC)

FLAG = "DEFENDER_BUDGET_ENFORCE"


class FakeClock:
    """A run clock source the test moves by hand: `clock()` is the reading, `advance(s)` moves
    it. Thread-safe (gather leads and oracle turns run on worker threads)."""

    def __init__(self, start: dt.datetime) -> None:
        assert start.utcoffset() == dt.timedelta(0), "the source must read aware UTC"
        self._now = start
        self._lock = threading.Lock()
        #: Every `advance` in order, for a test that wants to show a step really ran.
        self.advances: list[float] = []

    def __call__(self) -> dt.datetime:
        with self._lock:
            return self._now

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._now = self._now + dt.timedelta(seconds=seconds)
            self.advances.append(seconds)


def at(start: dt.datetime, seconds: float) -> dt.datetime:
    """`start` plus `seconds` — the test's own arithmetic for an expected reading."""
    return start + dt.timedelta(seconds=seconds)


def instant(raw: object) -> dt.datetime | None:
    """A stamp as the instant it names, whatever ISO spelling the writer chose (`Z` or
    `+00:00`, with or without fractional seconds), truncated to whole seconds — the contract is
    the instant, not the spelling."""
    parsed = _clock.parse_iso_utc(raw)
    return None if parsed is None else parsed.replace(microsecond=0)


# ---------------------------------------------------------------------------------------
# Scripted models that take time
# ---------------------------------------------------------------------------------------

Step = tuple[float, "H.Turn | Callable[[str], H.Turn]"]


class Clocked:
    """A scripted model: request `i` advances `clock` by step `i`'s seconds, then answers with
    its turn (a `Turn`, or a callable over this request's flattened text returning one). Past
    the script it answers text-only, as `ReplayFn` does. `seen[i]` is request `i`'s text."""

    __name__ = "Clocked"

    def __init__(self, clock: FakeClock, steps: Iterable[Step]) -> None:
        self.clock = clock
        self.steps = list(steps)
        self.calls = 0
        self.seen: list[str] = []
        self._lock = threading.Lock()

    def __call__(self, messages: list[Any], info: Any) -> ModelResponse:
        text = H.messages_text(messages)
        with self._lock:
            self.seen.append(text)
            if self.calls >= len(self.steps):
                return ModelResponse(parts=[TextPart(content="(script spent)")])
            seconds, turn = self.steps[self.calls]
            self.calls += 1
        if seconds:
            self.clock.advance(seconds)
        if callable(turn):
            turn = turn(text)
        parts: list[Any] = [TextPart(content=turn.text)] if turn.text else []
        parts += [ToolCallPart(tool_name=n, args=a) for n, a in turn.tool_calls]
        return ModelResponse(parts=parts or [TextPart(content="(done)")])


def script(clock: FakeClock, *steps: Step) -> Clocked:
    return Clocked(clock, steps)


# ---------------------------------------------------------------------------------------
# Turns the scenarios share
# ---------------------------------------------------------------------------------------

#: Three real lessons of the runtime corpus, by name, for the read rows the lessons log keeps.
LESSONS: tuple[str, ...] = tuple(sorted(
    p.stem for p in (DEFENDER / "lessons").glob("*.md") if not p.name.startswith("_")))[:3]
assert len(LESSONS) == 3, "the runtime lessons corpus holds fewer than three lessons"

_DEFENDER_DIR_LINE = re.compile(r"DEFENDER_DIR: `([^`]+)`")


def read_lesson(name: str) -> Callable[[str], H.Turn]:
    """MAIN reads lesson `name` at the path the model was SHOWN for the checkout (message 0's
    workspace map), so the call is the one a real model would make whatever path the run renders
    the checkout as (slice B's model view changes that rendering, not this script)."""

    def turn(text: str) -> H.Turn:
        found = _DEFENDER_DIR_LINE.search(text)
        assert found is not None, (
            "the model was never shown where the checkout is (no `DEFENDER_DIR:` line in its "
            "history) — the script cannot name a lesson the way a model would")
        return H.Turn(tool_calls=[("read_file", {"path": f"{found.group(1)}/lessons/{name}.md"})])

    return turn


def bash(command: str) -> H.Turn:
    return H.Turn(tool_calls=[("bash", {"command": command})])


def gather_turn(lead: str, system: str, goal: str = "measure this lead") -> H.Turn:
    return H.Turn(tool_calls=[("gather", {"lead_id": lead, "system": system, "goal": goal,
                                          "what_to_summarize": ["what the system says"]})])


def query(system: str, verb: str, params: Mapping[str, Any] | None = None) -> H.Turn:
    return H.Turn(tool_calls=[("query", {"system": system, "verb": verb,
                                         "params": dict(params or {})})])


DONE = H.Turn(text="Investigation complete.")


def append_first_fence() -> H.Turn:
    """MAIN lands the golden sshd investigation's FIRST block (2 open slots, so a branch point
    after it has a question to divide — `_triplet_947.branchable_investigation`'s measure)."""
    from defender.skills.invlang.parser import scan_fences

    golden = DEFENDER / "fixtures-e2e" / "golden-v2sshd" / "investigation.md"
    body = scan_fences(golden.read_text(encoding="utf-8")).bodies[0]
    return H.Turn(tool_calls=[("append_block", {"text": f"```invlang\n{body}\n```"})])


# ---------------------------------------------------------------------------------------
# Reading what the model can read
# ---------------------------------------------------------------------------------------

def lesson_rows(run_dir: Path) -> list[dict]:
    """The run's lessons log (model-readable, run root), as rows."""
    path = RunPaths(run_dir).lessons_loaded
    return read_jsonl_rows(path) if path.is_file() else []


def lesson_reads(run_dir: Path, name: str) -> list[dt.datetime | None]:
    """The instants of MAIN's `read` rows for lesson `name`, in log order."""
    return [instant(r.get("ts")) for r in lesson_rows(run_dir)
            if r.get("lesson_name") == name and r.get("kind") == "read" and r.get("role") == "main"]


def denial_rows(run_dir: Path) -> list[dict]:
    path = RunPaths(run_dir).policy_denials
    return read_jsonl_rows(path) if path.is_file() else []


def refusal_stem() -> str:
    """The budget refusal's literal lead-in, guarded non-empty (an empty needle is in every
    string)."""
    from defender.hooks.budget_enforcer import BUDGET_REFUSAL_MESSAGE

    stem = BUDGET_REFUSAL_MESSAGE.split("{", 1)[0].strip()
    assert stem, "the budget refusal opens with a placeholder; its stem is empty"
    return stem


def caps(**over: Any) -> dict:
    from defender.hooks.budget_enforcer import DEFAULT_LIMITS

    return {**DEFAULT_LIMITS, **over}


# ---------------------------------------------------------------------------------------
# The driver, with the clock
# ---------------------------------------------------------------------------------------

def _model_maker(main: Any, gather: Any, *, dispatches_correlation: bool) -> Callable[..., Any]:
    """`make_model` keyed on the model name, as `driver_summary` builds it: MAIN's double for
    every name but the gather model's; the correlation lead answered by the harness's own
    default (never MAIN's or the scenario's script)."""
    main_built = BuiltModel(FunctionModel(H._awaiting(main)), None)
    gather_fn = H._with_default_correlation(gather, main) if dispatches_correlation else gather
    gather_built = (BuiltModel(FunctionModel(H._awaiting(gather_fn)), None)
                    if gather_fn is not None else None)
    if gather_built is not None and driver.resolve_main_model() == driver.gather_model():
        raise ValueError("main and gather resolve to one model name; the doubles cannot differ")

    def make_model(name: str, effort: Any) -> Any:
        if gather_built is not None and name == driver.gather_model():
            return gather_built
        return main_built

    return make_model


def default_review_stages() -> Any:
    return _review_bundle.bundle(composer=_review_bundle.composer_reply("holds"))


def drive_clocked(  # noqa: PLR0913 — one keyword per seam a clock scenario varies
        run_dir: Path, *, clock: Callable[[], dt.datetime], main: Any, gather: Any = None,
        verbs: Any = None, limits: dict | None = None, tenant: Any = None,
        review_stages: Any = None) -> dict:
    """A natural run through `_replay_harness.drive(…, clock=clock)`: every seam the harness
    defaults (production's unboxed mode, the `holds` review bundle, no ORIENT shims, the
    committed fixture tenant) unless named here. Returns the summary plus `"run_state"`, as
    `drive` does."""
    return H.drive(run_dir, run_id=run_dir.name, main=main, gather=gather, verbs=verbs,
                   limits=limits, tenant=tenant, review_stages=review_stages, clock=clock)


# ---------------------------------------------------------------------------------------
# The arm composition (dossier), through `run.main`
# ---------------------------------------------------------------------------------------

@dataclass
class Launched:
    """What one `run.main` call through the composition left: its exit, the run folder the
    driver was handed, and the driver's summary (absent when the run never reached it)."""

    exit: Any = None
    refusal: str | None = None
    run_dir: Path | None = None
    run_id: str | None = None
    summary: dict | None = None
    kwargs: dict = field(default_factory=dict)


def _no_daemon(argv: list[str], **_kw: Any) -> Any:
    """No docker daemon: `start_box` turns this into its startup fault, which the
    `DEFENDER_ALLOW_UNSANDBOXED` opt-out turns into production's unboxed mode."""
    raise FileNotFoundError("docker")


def _driver_call(out: Launched, *, clock: Callable[[], dt.datetime], main: Any, gather: Any,
                 limits: dict | None, review_stages: Any) -> Callable[..., dict]:
    """The innermost `investigate`: `driver.run_investigation(**kw, make_model=…,
    review_stages=…, clock=…)`, everything else exactly as `_drive_investigation` hands it."""

    def investigate(**kw: Any) -> dict:
        out.run_dir = Path(kw["run"].run_dir)
        out.run_id = str(kw["run"].id)
        out.kwargs = dict(kw)
        dispatches = kw.get("resume") is None and kw.get("verbs") is not None
        extra: dict[str, Any] = {} if limits is None else {"limits": limits}
        with override_allow_model_requests(False):
            summary = asyncio.run(driver.run_investigation(
                **kw, make_model=_model_maker(main, gather, dispatches_correlation=dispatches),
                review_stages=review_stages if review_stages is not None
                else default_review_stages(),
                clock=clock, **extra))
        out.summary = dict(summary)
        return summary

    return investigate


def run_main(  # noqa: PLR0913 — the composition's seams, one keyword each
        argv: list[str], *, clock: Callable[[], dt.datetime], main: Any, gather: Any = None,
        limits: dict | None = None, review_stages: Any = None, start_box: Any = None,
        investigate: Callable[..., dict] | None = None, oracle: Any = None,
        verifier: Any = None, registry_cls: type | None = None,
        out: Launched | None = None) -> Launched:
    """`run.main(argv)` through the dossier's fixed composition. A refusal (`SystemExit`) is
    kept on the result rather than raised. `start_box` defaults to production's unboxed mode;
    `investigate` replaces the driver call (a static box check needs none); `registry_cls` is
    `_drive_investigation`'s own seam for a natural run's registry (default `quiet_registry`,
    so no natural run reaches a real backend); `out` lets a model double read what the driver
    was handed (`out.kwargs`, set before the driver runs)."""
    import defender.run as run_mod

    launched = out if out is not None else Launched()  # lint-default: ok — a fresh record per call unless the caller holds one
    inner = investigate if investigate is not None else _driver_call(
        launched, clock=clock, main=main, gather=gather, limits=limits, review_stages=review_stages)
    lifecycle = functools.partial(
        run_mod._run_investigation_lifecycle,
        investigate=functools.partial(
            run_mod._drive_investigation, investigate=inner,
            registry_cls=registry_cls if registry_cls is not None else quiet_registry()),
        start_box=start_box if start_box is not None
        else functools.partial(box_mod.start_box, docker=_no_daemon),
        stop_box=lambda *_a, **_k: None,
        scrub=lambda *_a, **_k: None)
    try:
        launched.exit = run_mod.main(
            argv, lifecycle=lifecycle, preflight=lambda *_a, **_k: 0,
            visualize=lambda *_a, **_k: None, enqueue=lambda *_a, **_k: False,
            oracle=oracle, verifier=verifier)
    except SystemExit as refused:
        launched.exit = "SystemExit"
        launched.refusal = str(refused.code)
    return launched


def quiet_registry() -> type:
    """A `ModuleVerbRegistry` class for `_drive_investigation(registry_cls=…)`: the real roster,
    grant and verb signatures (`functools.wraps`), every body answering an EMPTY elastic search
    envelope (built by the adapter's own `search_envelope`) instead of reaching a backend. The
    natural runs here script no query of their own; this keeps the correlation lead's harness
    call off the network. It decides nothing: validation, capture, rows stay production's."""
    from defender.runtime.verbs import ModuleVerbRegistry
    from defender.scripts.adapters.elastic_adapter import search_envelope

    def canned(fn: Any) -> Any:
        @functools.wraps(fn)
        def call(ctx: Any, /, **params: Any) -> Any:
            return search_envelope("logs-*", [], 0, False, "desc")

        return call

    class QuietBodies(ModuleVerbRegistry):
        def verbs(self, system: str) -> Mapping[str, Any]:
            return {name: canned(fn) for name, fn in super().verbs(system).items()}

    return QuietBodies


def natural_argv(alert: Path, tenant_id: str) -> list[str]:
    return [str(alert), "--tenant", tenant_id, "--no-learn"]


def arm_argv(tenant_id: str, episode_id: str, world: str) -> list[str]:
    return ["--tenant", tenant_id, "--episode", episode_id, "--world", world]


# ---------------------------------------------------------------------------------------
# A recorded source and a control episode forked from it
# ---------------------------------------------------------------------------------------

def opened_source(run_dir: Path) -> Any:
    """The source run as the launcher and the sibling open it: by id, in its tenant's runs."""
    from defender.tests import _triplet_947 as T

    return T.open_source(run_dir)


@contextlib.contextmanager
def _source_main_session(source_run_dir: Path) -> Iterator[list[tuple[int, Any]]]:
    """The source's own MAIN session as `(row id, message)` pairs in path order, read off the
    store the run wrote (the store is closed on exit)."""
    from defender.runtime import branch as branch_mod
    from defender.runtime import session_store as ss

    source = opened_source(source_run_dir)
    store = branch_mod.source_store_if_any(source.run_dir, source_run=source)
    assert store is not None, "the recorded source left no session store"
    try:
        session = branch_mod.session_for_run(store, source.run_dir, source_run=source)
        ids = ss.path_row_ids(store, session)
        messages = ss.hydrate(store, session, role="analysis")
        assert len(ids) == len(messages), (len(ids), len(messages))
        yield list(zip(ids, messages, strict=True))
    finally:
        store.close()


def branch_response(source_run_dir: Path, *, tool: str, arg_suffix: str) -> int:
    """The row id, on the source's own MAIN session, of the response that called `tool` with an
    argument ending `arg_suffix` — the scenario's branch point (D1: a tool-calling response).
    Read off the store the run wrote; nothing here derives a time."""
    with _source_main_session(source_run_dir) as rows:
        hits = [rid for rid, m in rows
                if isinstance(m, ModelResponse) and any(
                    isinstance(p, ToolCallPart) and p.tool_name == tool
                    and any(str(v).endswith(arg_suffix) for v in (p.args_as_dict() or {}).values())
                    for p in m.parts)]
    assert len(hits) == 1, f"expected one {tool}(…{arg_suffix}) response on the source, got {hits}"
    return hits[0]


def source_message_times(source_run_dir: Path) -> list[dt.datetime]:
    """Every timestamp the FRAMEWORK stamped on the source's MAIN session (each message's and
    each part's, truncated to whole seconds, distinct, sorted). Pydantic stamps these from the
    wall clock itself, so on a run whose clock source starts at `SOURCE_START` none of them is
    a run-clock reading — they are what today's `branch_point_time` derives a fork time from,
    and what C4 says the fork time is NOT. Read off the store; nothing here derives a time."""
    found: set[dt.datetime] = set()
    with _source_main_session(source_run_dir) as rows:
        for _rid, message in rows:
            for stamped in (message, *getattr(message, "parts", ())):
                moment = getattr(stamped, "timestamp", None)
                if isinstance(moment, dt.datetime):
                    found.add(_clock.as_utc(moment).replace(microsecond=0))
    return sorted(found)


def spelled(moment: dt.datetime) -> tuple[str, str]:
    """`moment`'s whole-second date-time as ISO text, with either separator a writer may use —
    the needle for "this instant is written somewhere in that text", whatever zone suffix or
    fraction follows it."""
    text = moment.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return text, text.replace("T", " ")


def mentions(text: str, moment: dt.datetime) -> bool:
    return any(needle in text for needle in spelled(moment))


def control_episode(tmp_path: Path, source_run_dir: Path, branch_message_id: int,
                    *, worlds: list[dict] | None = None) -> Path:
    """A control-world episode of the recorded source, forked at `branch_message_id`, laid out
    the way the existing sibling suites lay one out (`_triplet_947.episode` under the configured
    episodes root, its container made with the tenant's record). The manifest's derived half is
    the LAUNCHER's own derivation (`cli.episode_id_for`, `cli.branch_point_clock`), so it follows
    whatever the launcher derives; its shape is `_triplet_947.family_doc`'s (slice A's helper,
    which D1 changes)."""
    import os

    from defender import _tenant
    from defender.learning.branch import cli
    from defender.tests import _triplet_947 as T

    source = opened_source(source_run_dir)
    episode_id = cli.episode_id_for(str(source.id), branch_message_id)
    as_of = cli.branch_point_clock(source, branch_message_id)
    doc = T.family_doc(
        worlds=worlds if worlds is not None else [T.base_world()],
        source_run_dir=str(source.run_dir), source_run_id=str(source.id),
        episode_id=episode_id, branch_message_id=branch_message_id,
        as_of=as_of.isoformat().replace("+00:00", "Z"))
    root = Path(os.environ[T.EPISODES_BASE_ENV])
    ep = T.episode(tmp_path, doc=doc, episode_id=episode_id, root=root)
    (ep / "runs").mkdir(exist_ok=True)
    _tenant.ensure_runs_base_record(ep / "runs", T.mod("_tenant").read_tenant(
        source.run_dir.parent).tenant_id)
    return ep


#: `record_source`'s branch point B — the response that calls `read_file(LESSONS[1])` — arrives
#: at this reading of the source's clock: 10 s, then 600 s of MAIN work. The test's own sum.
BRANCH_READING = at(SOURCE_START, 610)
#: The earlier tool-calling response of the same source, `read_file(LESSONS[0])`, arrives here.
FIRST_READ_READING = at(SOURCE_START, 10)


def record_source(tmp_path: Path, *, limits: dict | None = None) -> tuple[str, Path]:
    """A source run recorded through `run.main` (natural, unboxed), its clock source at
    `SOURCE_START`. MAIN, in source-clock seconds: lands the golden investigation's first block
    at +0 (an open frontier — a branch point with nothing open is not branchable); dispatches
    lead `l-001` at +5 (one elastic query that reaches the system — a source that captured none
    is not branchable either); reads
    `LESSONS[0]` at +10; its next response, at +610, calls `read_file(LESSONS[1])` — the branch
    point (D1: a tool-calling MAIN response); it stops at +615. Returns `(tenant id, source run
    folder)`. The tenant and its runs base are `_triplet_947.runs_base`'s."""
    from defender.tests import _triplet_947 as T

    base, seed = T.runs_base(tmp_path)
    tenant_id = T.mod("_tenant").read_tenant(base).tenant_id
    clock = FakeClock(SOURCE_START)
    main = script(clock, (0, append_first_fence()), (5, gather_turn("l-001", "elastic")),
                  (5, read_lesson(LESSONS[0])), (600, read_lesson(LESSONS[1])), (5, DONE))
    gather = script(clock, (0, query("elastic", "query", {"native_query": "event.action:*"})),
                    (0, H.Turn(text="Summary: one query, no hits.")))
    out = run_main(natural_argv(RunPaths(seed).alert, tenant_id), clock=clock, main=main,
                   gather=gather, limits=limits)
    assert out.exit == 0, (f"the source run did not complete through run.main: exit={out.exit} "
        f"refusal={out.refusal}")
    assert out.run_dir is not None, (f"the source run did not complete through run.main: exit={out.exit} "
        f"refusal={out.refusal}")
    assert main.calls == 5, f"the source's script did not play out: main {main.seen} gather {gather.seen}"
    assert gather.calls == 2, f"the source's script did not play out: main {main.seen} gather {gather.seen}"
    return tenant_id, out.run_dir
