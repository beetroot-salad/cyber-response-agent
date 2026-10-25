"""Clock sources, scripted models, and run.main replay helpers."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

import asyncio
import contextlib
import datetime as dt
import functools
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
from defender import box as box_mod  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.tests.support.runtime.permissions import _review_bundle
from defender.tests.e2e import _replay_harness as H  # noqa: E402

DEFENDER = H.DEFENDER

SOURCE_START = dt.datetime(2031, 3, 4, 5, 6, 7, tzinfo=dt.UTC)
ARM_START = dt.datetime(2040, 1, 1, 0, 0, 0, tzinfo=dt.UTC)

FLAG = "DEFENDER_BUDGET_ENFORCE"


class FakeClock:
    """A run clock source the test moves by hand: `clock()` is the reading, `advance(s)` moves it."""

    def __init__(self, start: dt.datetime) -> None:
        assert start.utcoffset() == dt.timedelta(0), "the source must read aware UTC"
        self._now = start
        self._lock = threading.Lock()
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
    """Parse an ISO stamp as UTC, rounded down to whole seconds."""
    parsed = _clock.parse_iso_utc(raw)
    return None if parsed is None else parsed.replace(microsecond=0)


Step = tuple[float, "H.Turn | Callable[[str], H.Turn]"]


class Clocked:
    """Scripted model whose steps advance the clock before answering; seen records requests."""

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


#: #1108 P4 (O1, O4): the lessons corpus is the TENANT's (`agent/lessons/`, read from the run's
#: copy of its export), never the checkout's — the checkout holds none. These scenarios need
#: three lessons a run reads, so the clock drivers plant three made-up ones into the run
#: tenant's knowledge folder before the launch (`plant_lessons`); the launch-time publish takes
#: them into the export the run copies.
LESSONS: tuple[str, ...] = ("clock-lesson-a", "clock-lesson-b", "clock-lesson-c")


def lesson_text(name: str) -> str:
    """One made-up lesson (front matter in the corpus schema; content describes nothing)."""
    return (f"---\nname: {name}\ndescription: Made-up clock fixture lesson {name} (#1255, "
            "#1108 P4).\ntelemetry_source: [cmdb]\nattack_phase: [discovery]\n"
            f"source_signature: [fixture-clock-{name}]\nsource_finding_ids:\n"
            "  - fixture-run-1/1\ncreated_at: 2026-10-01T00:00:00Z\n---\n\n"
            f"Fixture content for the run-clock tests; {name} describes no real environment.\n")


def plant_lessons(tenant_id: str, data_root: Path | None = None, *,
                  agent: Path | None = None) -> Path | None:
    """Write `LESSONS` into tenant `tenant_id`'s own `knowledge/agent/lessons/` under the data
    root (default: this test's) — or into the agent half `agent` names — unchanged bytes when
    already there. Returns the folder, or `None` when there is no agent half to plant into."""
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root

    if agent is None:
        root = Path(data_root) if data_root is not None else current_data_root()
        agent = root / str(tenant_id) / "knowledge" / "agent"
    agent = Path(agent)
    if not agent.is_dir():
        return None
    lessons = agent / "lessons"
    lessons.mkdir(exist_ok=True)
    for name in LESSONS:
        path = lessons / f"{name}.md"
        text = lesson_text(name)
        if not path.is_file() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
    return lessons


def _argv_tenant(argv: Iterable[str]) -> str | None:
    args = list(argv)
    return args[args.index("--tenant") + 1] if "--tenant" in args[:-1] else None


def read_lesson(name: str) -> Callable[[str], H.Turn]:
    """Read a lesson by the path the run's model view gives the agent tree (#1108 P4: the run
    copy's `agent/` at the model root `MODEL_AGENT`; the lessons are the tenant's)."""
    from defender.tests.support.runtime.state._1255_view import MODEL_AGENT

    def turn(_text: str) -> H.Turn:
        return H.Turn(tool_calls=[("read_file", {"path": f"{MODEL_AGENT}/lessons/{name}.md"})])

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
    """Append the first golden block, leaving two open slots for a legal branch."""
    from defender.skills.invlang.parser import scan_fences

    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd" / "investigation.md"
    body = scan_fences(golden.read_text(encoding="utf-8")).bodies[0]
    return H.Turn(tool_calls=[("append_block", {"text": f"```invlang\n{body}\n```"})])


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
    """The budget refusal's literal lead-in, guarded non-empty (an empty needle is in every string)."""
    from defender.hooks.budget_enforcer import BUDGET_REFUSAL_MESSAGE

    stem = BUDGET_REFUSAL_MESSAGE.split("{", 1)[0].strip()
    assert stem, "the budget refusal opens with a placeholder; its stem is empty"
    return stem


def caps(**over: Any) -> dict:
    from defender.hooks.budget_enforcer import DEFAULT_LIMITS

    return {**DEFAULT_LIMITS, **over}


def _model_maker(main: Any, gather: Any, *, dispatches_correlation: bool) -> Callable[..., Any]:
    """Route model names to the scripted main, gather, and default correlation models."""
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
    """Drive a natural replay with an injected clock and the standard harness defaults. With
    no `tenant` the replay runs as the fixture tenant, into whose folder `LESSONS` are planted
    first (#1108 P4: the harness publishes the folder as it is); a named tenant (whose agent
    half the harness reads as it stands) gets them in that agent half."""
    if tenant is None:
        from defender.tests.support.tenancy import _tenants1106

        plant_lessons(str(_tenants1106.fixture_tenant().id))
    elif getattr(tenant, "agent", None) is not None:
        plant_lessons(str(tenant.id), agent=Path(location_path(tenant.agent)))
    return H.drive(run_dir, run_id=run_dir.name, main=main, gather=gather, verbs=verbs,
                   limits=limits, tenant=tenant, review_stages=review_stages, clock=clock)


@dataclass
class Launched:
    """Result and driver inputs captured from run.main, including launch refusals."""

    exit: Any = None
    refusal: str | None = None
    run_dir: Path | None = None
    run_id: str | None = None
    summary: dict | None = None
    kwargs: dict = field(default_factory=dict)


def _no_daemon(argv: list[str], **_kw: Any) -> Any:
    """Fail Docker startup so the explicit opt-out selects the real unboxed executor."""
    raise FileNotFoundError("docker")


def _driver_call(out: Launched, *, clock: Callable[[], dt.datetime], main: Any, gather: Any,
                 limits: dict | None, review_stages: Any) -> Callable[..., dict]:
    """Inject scripted models and the clock into the production driver inputs."""

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
    """`run.main(argv)` through the dossier's fixed composition."""
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
    from defender.tests.support.tenancy._launch_publish_p4 import in_process_publish

    tenant_id = _argv_tenant(argv)
    if tenant_id is not None:
        plant_lessons(tenant_id)
    try:
        # #1108 P4 (OD14, O11): the in-process launch-time publish (publishes the tenant for
        # real when run.main launches it).
        launched.exit = run_mod.main(
            argv, lifecycle=lifecycle, preflight=lambda *_a, **_k: 0,
            visualize=lambda *_a, **_k: None, enqueue=lambda *_a, **_k: False,
            oracle=oracle, verifier=verifier, publish=in_process_publish())
    except SystemExit as refused:
        launched.exit = "SystemExit"
        launched.refusal = str(refused.code)
    return launched


def quiet_registry() -> type:
    """Use real verb signatures with empty elastic answers instead of network calls."""
    from defender.runtime.verbs import ModuleVerbRegistry
    from defender.integrations.elastic_adapter import search_envelope

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


def opened_source(run_dir: Path) -> Any:
    """The source run as the launcher and the sibling open it: by id, in its tenant's runs."""
    from defender.tests.support.learning.branch import _triplet_947 as T

    return T.open_source(run_dir)


@contextlib.contextmanager
def _source_main_session(source_run_dir: Path) -> Iterator[list[tuple[int, Any]]]:
    """Read source MAIN rows in path order and close the store on exit."""
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
    """Find the source MAIN response calling tool with an argument ending in arg_suffix."""
    with _source_main_session(source_run_dir) as rows:
        hits = [rid for rid, m in rows
                if isinstance(m, ModelResponse) and any(
                    isinstance(p, ToolCallPart) and p.tool_name == tool
                    and any(str(v).endswith(arg_suffix) for v in (p.args_as_dict() or {}).values())
                    for p in m.parts)]
    assert len(hits) == 1, f"expected one {tool}(…{arg_suffix}) response on the source, got {hits}"
    return hits[0]


def source_message_times(source_run_dir: Path) -> list[dt.datetime]:
    """Sorted distinct whole-second framework timestamps from source MAIN messages and parts."""
    found: set[dt.datetime] = set()
    with _source_main_session(source_run_dir) as rows:
        for _rid, message in rows:
            for stamped in (message, *getattr(message, "parts", ())):
                moment = getattr(stamped, "timestamp", None)
                if isinstance(moment, dt.datetime):
                    found.add(_clock.as_utc(moment).replace(microsecond=0))
    return sorted(found)


def spelled(moment: dt.datetime) -> tuple[str, str]:
    """Whole-second ISO spellings with space and T separators."""
    text = moment.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return text, text.replace("T", " ")


def mentions(text: str, moment: dt.datetime) -> bool:
    return any(needle in text for needle in spelled(moment))


def control_episode(tmp_path: Path, source_run_dir: Path, branch_message_id: int,
                    *, worlds: list[dict] | None = None) -> Path:
    """Create a control-world episode and its tenant-owned run container."""
    from defender.tenancy import _tenant
    from defender.learning.branch import cli
    from defender.tests.support.learning.branch import _triplet_947 as T

    source = opened_source(source_run_dir)
    tenant = _tenant.accept_tenant(fixture_data_root(source.run_dir.parents[2]), source.tenant_id,
                                   defender_dir=DEFENDER)
    as_of = cli.branch_point_clock(source, branch_message_id)
    with cli.prepare_episode(tenant.runs_repository(), source) as view:
        doc = T.family_doc(
            worlds=worlds if worlds is not None else [T.base_world()],
            source_run_dir=str(source.run_dir), source_run_id=str(source.id),
            episode_id=view.episode_id, branch_message_id=branch_message_id,
            as_of=as_of.isoformat().replace("+00:00", "Z"))
        T.write_family(view.episode.dir, doc)
        view.start_runs([world["world_id"] for world in doc["worlds"]])
        return view.episode.dir


BRANCH_READING = at(SOURCE_START, 610)
FIRST_READ_READING = at(SOURCE_START, 10)


def record_source(tmp_path: Path, *, limits: dict | None = None) -> tuple[str, Path]:
    """A source run recorded through `run.main` (natural, unboxed), its clock source at `SOURCE_START`."""
    from defender.tests.support.learning.branch import _triplet_947 as T

    base, seed = location_path(T.runs_base)(tmp_path)
    tenant_id = T.current_tenant().id
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
