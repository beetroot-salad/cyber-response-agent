"""Record natural and control-arm requests, compare only permitted O4 differences, and scan identity leaks."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root

import asyncio
import dataclasses
import datetime as dt
import functools
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent


LEAD = "l-001"
CORRELATION_LEAD = "l-00c"

_LEAD_DOCS = [
    {"@timestamp": "2026-05-25T15:20:00.000Z", "user.name": "dev.dana",
     "source.ip": "172.18.0.15", "message": "Accepted password for dev.dana",
     "host.name": "office-ws-1"},
    {"@timestamp": "2026-05-25T15:21:00.000Z", "user.name": "dev.dana",
     "source.ip": "172.18.0.15", "message": "session opened for user dev.dana",
     "host.name": "office-ws-1"},
]
_CORRELATION_DOCS = [
    {"@timestamp": "2026-05-25T15:10:00.000Z", "user.name": "dev.dana",
     "kibana.alert.rule.name": "v2 sshd success after failures", "host.name": "office-ws-1"},
]

BRANCH_TURN = 1

LEAD_QUERY = {"system": "elastic", "verb": "query",
              "params": {"native_query": "user.name:dev.dana AND event.action:ssh_login"}}
CORRELATION_QUERY = {"system": "elastic", "verb": "alerts",
                     "params": {"native_query": "user.name:dev.dana"}}

LEAD_SUMMARY = ("Two ssh logins for dev.dana from 172.18.0.15 to office-ws-1 at 15:20Z and "
                "15:21Z; no failures in the window.")
CORRELATION_SUMMARY = "1 alert scoped to user.name dev.dana, 1 unscoped, across any rule."


def _golden_fences() -> list[str]:
    """The golden sshd investigation's fences, each as a block `append_block` lands."""
    from defender.skills.invlang.parser import scan_fences

    golden = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd" / "investigation.md"
    return [f"```invlang\n{body}\n```" for body in
            scan_fences(golden.read_text(encoding="utf-8")).bodies]


SIGNATURE = "v2-sshd-success-after-failures"


def main_script() -> list[Any]:
    """MAIN's turns, the same for the natural run and (from `BRANCH_TURN + 1`) the arm."""
    from defender.tests.e2e._replay_harness import Turn

    fences = _golden_fences()
    return [
        Turn(tool_calls=[("append_block", {"text": fences[0]})]),
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "elastic",
            "goal": "measure dev.dana's ssh logins to office-ws-1 around the alert",
            "what_to_summarize": ["successful and failed logins", "source addresses"],
        })]),
        Turn(tool_calls=[("bash", {
            "command": f"cat executed_queries.jsonl gather_summaries/{LEAD}.md"})]),
        Turn(tool_calls=[("bash", {
            "command": f"defender-invlang hypothesis-vocabulary --signature {SIGNATURE}"})]),
        Turn(tool_calls=[("read_file", {"path": "/runs/current/investigation.md"})]),
        Turn(tool_calls=[("append_block", {"text": "\n\n".join(fences[1:])})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
        Turn(text="Investigation complete."),
    ]


def gather_scripts() -> dict[str, list[Any]]:
    """Each lead's gather turns: one query, then the summary."""
    from defender.tests.e2e._replay_harness import Turn

    return {
        CORRELATION_LEAD: [Turn(tool_calls=[("query", CORRELATION_QUERY)]),
                           Turn(text=CORRELATION_SUMMARY)],
        LEAD: [Turn(tool_calls=[("query", LEAD_QUERY)]), Turn(text=LEAD_SUMMARY)],
    }


_ALERT_ID_FIELD = "kibana.alert.uuid"


def _answer(system: str, verb: str, params: Mapping[str, Any]) -> Any:
    """What the natural run's elastic answers."""
    from defender.integrations.elastic_adapter import search_envelope
    from defender.tests.e2e._lead_zero_808 import ALERTS_INDEX, EVENTS_INDEX, shell_doc

    if system != "elastic":
        raise AssertionError(f"the twin's script never asks {system}.{verb}")
    native = str(params.get("native_query") or "")
    if native.startswith(f"{_ALERT_ID_FIELD}:"):
        return search_envelope(ALERTS_INDEX, [shell_doc()], 1, False, "desc")
    if verb == "alerts":
        return search_envelope(ALERTS_INDEX, list(_CORRELATION_DOCS),
                               len(_CORRELATION_DOCS), False, "desc")
    return search_envelope(EVENTS_INDEX, list(_LEAD_DOCS), len(_LEAD_DOCS), False, "desc")


def canned_registry(answer: Callable[[str, str, Mapping[str, Any]], Any] = _answer) -> type:
    """Keep real verb signatures and grants while returning canned backend answers."""
    from defender.systems.verbs import ModuleVerbRegistry

    class CannedBodies(ModuleVerbRegistry):
        def verbs(self, system: str) -> Mapping[str, Any]:
            real = super().verbs(system)
            return {name: _canned(system, name, fn, answer) for name, fn in real.items()}

    return CannedBodies


def _canned(system: str, verb: str, fn: Any, answer: Callable[..., Any]) -> Any:
    @functools.wraps(fn)
    def call(ctx: Any, /, **params: Any) -> Any:
        return answer(system, verb, params)

    return call


READING_ROLES = ("main", "gather")


def read_policies(run_dir: Path, defender_dir: Path, tenant: Any) -> dict[str, Any]:
    """Compile MAIN and gather read policies with the tenant agent scope."""
    from defender.investigation.agent_definition import RunScope, compile_policy_for
    from defender.investigation.driver import MAIN_DEF, gather_def_for

    scope = RunScope(tenant_agent=tenant.agent)
    return {
        "main": compile_policy_for(MAIN_DEF, run_dir, defender_dir=defender_dir, scope=scope),
        "gather": compile_policy_for(gather_def_for(tenant.grants.gather), run_dir,
                                     defender_dir=defender_dir, scope=scope),
    }


def _readable(path: Path, *, run_dir: Path, defender_dir: Path, policy: Any) -> bool:
    """The real gate's answer (`permission.decide_read`) for one file, for one role."""
    from defender.investigation import permission

    return bool(permission.decide_read(path, run_dir=run_dir, defender_dir=defender_dir,
                                       policy=policy).allow)


def _text(path: Path) -> str:
    raw = path.read_bytes()  # lint-whole-read: ok — a test snapshot of a small run folder
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return repr(raw)


def files_snapshot(run_dir: Path | None, *, defender_dir: Path | None, policy: Any) -> dict[str, str]:
    """Capture every readable run file, preserving invalid UTF-8 as a byte repr."""
    if run_dir is None or defender_dir is None or policy is None or not run_dir.is_dir():
        return {}
    out: dict[str, str] = {}
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if _readable(path, run_dir=run_dir, defender_dir=defender_dir, policy=policy):
            out[str(path.relative_to(run_dir))] = _text(path)
    return out


def corpus_snapshot(run_dir: Path, defender_dir: Path, tenant_agent: Path | None,
                    policy: Any) -> dict[str, str]:
    """Capture readable checkout and tenant-agent Markdown by tree and relative path."""
    out: dict[str, str] = {}
    for label, base in (("checkout", defender_dir), ("agent", tenant_agent)):
        if base is None or not base.is_dir():
            continue
        for sub in ("lessons", "skills", "examples"):
            root = base / sub
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*.md")):
                if path.is_file() and _readable(path, run_dir=run_dir,
                                                defender_dir=defender_dir, policy=policy):
                    out[f"{label}:{path.relative_to(base)}"] = path.read_text(encoding="utf-8")
    return out


_RUN_ROOT_DENIED = frozenset({"provenance.json"})
_RAW_PAYLOAD = re.compile(r"gather_raw/l-[A-Za-z0-9]{1,64}/[0-9]+\.json")


def _alert_input_dir() -> str:
    from defender.records import RUN_LAYOUT

    return str(RUN_LAYOUT.alert_input_dir)


def in_read_scope(rel: Path, role: str) -> bool:
    """The static table above: whether `role` may read the run-relative file `rel`."""
    parts = rel.parts
    if not parts or "wire_logs" in parts:
        return False
    if len(parts) == 1:
        return parts[0] not in _RUN_ROOT_DENIED
    if parts[0] == "gather_summaries":
        return len(parts) == 2
    if parts[0] == "gather_raw":
        return role == "gather" and _RAW_PAYLOAD.fullmatch(rel.as_posix()) is not None
    return str(Path(*parts[:-1])) == _alert_input_dir() and len(parts) == len(
        Path(_alert_input_dir()).parts) + 1


def _part_wire(part: Any) -> dict[str, Any]:
    """Project provider-visible part fields; exclude timestamps and provider bookkeeping."""
    kind = getattr(part, "part_kind", type(part).__name__)
    out: dict[str, Any] = {"part_kind": kind}
    for name in ("content", "tool_name", "tool_call_id", "args"):
        if hasattr(part, name):
            value = getattr(part, name)
            out[name] = value if isinstance(value, (str, int, float, bool, type(None), list, dict)) \
                else repr(value)
    return out


def _tool_def_wire(tool: Any) -> dict[str, Any]:
    return {"name": tool.name, "description": tool.description,
            "parameters_json_schema": tool.parameters_json_schema,
            "strict": getattr(tool, "strict", None), "kind": getattr(tool, "kind", None)}


def wire_request(messages: list[Any], info: Any) -> dict[str, Any]:
    """Capture messages, instructions, tool definitions, output tools, and model settings."""
    msgs = []
    for msg in messages:
        entry: dict[str, Any] = {"kind": getattr(msg, "kind", type(msg).__name__),
                                 "parts": [_part_wire(p) for p in getattr(msg, "parts", [])]}
        instructions = getattr(msg, "instructions", None)
        if instructions is not None:
            entry["instructions"] = instructions
        msgs.append(entry)
    return {
        "messages": msgs,
        "instructions": getattr(info, "instructions", None),
        "function_tools": [_tool_def_wire(t) for t in info.function_tools],
        "output_tools": [_tool_def_wire(t) for t in info.output_tools],
        "allow_text_output": info.allow_text_output,
        "model_settings": json.loads(json.dumps(info.model_settings or {}, default=repr)),
    }


@dataclasses.dataclass
class Recording:
    """Collect provider requests, role-scoped files, corpus, clock readings, and run outcome."""

    label: str
    run_dir: Path | None = None
    requests: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    corpus: dict[str, str] = dataclasses.field(default_factory=dict)
    summary: dict[str, Any] = dataclasses.field(default_factory=dict)
    exit_code: Any = None
    refusal: str | None = None
    run_id: str | None = None
    clock: Any = dataclasses.field(default=None, repr=False)
    policies: dict[str, Any] = dataclasses.field(default_factory=dict, repr=False)
    defender_dir: Path | None = None

    def add(self, role: str, lead: str | None, wire: dict[str, Any]) -> None:
        seq = sum(1 for r in self.requests if r["role"] == role and r["lead"] == lead)
        files = (files_snapshot(self.run_dir, defender_dir=self.defender_dir,
                                policy=self.policies.get(role))
                 if role in READING_ROLES else {})
        self.requests.append({"role": role, "lead": lead, "seq": seq, "wire": wire,
                              "files": files, "clock_reads": self._clock_reads()})

    def _clock_reads(self) -> int:
        return len(self.clock.readings) if self.clock is not None else 0

    def as_json(self) -> dict[str, Any]:
        readings = self.clock.readings if self.clock is not None else []
        return {"label": self.label, "run_dir": str(self.run_dir) if self.run_dir else None,
                "run_id": self.run_id, "requests": self.requests, "corpus": self.corpus,
                "summary": json.loads(json.dumps(self.summary, default=repr)),
                "exit_code": self.exit_code,
                "refusal": self.refusal,
                "clock_readings": [t.isoformat() for t in readings]}


_DISPATCHED_LEAD = re.compile(r"\n## Dispatch\n```yaml\n(?:.*\n)*?lead_id: (\S+)\n")


class RoleModel:
    """Record requests and replay turns independently for each gather lead."""

    __name__ = "RoleModel"

    def __init__(self, recording: Recording, role: str, turns: list[Any] | None = None,
                 by_lead: Mapping[str, list[Any]] | None = None) -> None:
        from defender.tests.e2e._replay_harness import ReplayFn

        self.recording, self.role = recording, role
        self._replays = {None: ReplayFn(list(turns or [])),
                         **{lead: ReplayFn(list(script)) for lead, script in (by_lead or {}).items()}}

    def __call__(self, messages: list[Any], info: Any) -> Any:
        from defender.tests.e2e._replay_harness import messages_text

        found = (_DISPATCHED_LEAD.search(messages_text(messages[:1]))
                 if self.role == "gather" else None)
        lead = found.group(1) if found else None
        self.recording.add(self.role, lead, wire_request(messages, info))
        return self._replays[lead](messages, info)


def recording_review_stages(recording: Recording) -> Any:
    """Record review prompts while the existing review bundle answers holds."""
    from defender.investigation.review_roles import ReviewStages
    from defender.tests.support.runtime.permissions import _review_bundle

    def stage(name: str, reply: str) -> Any:
        async def call(request: Any) -> str:
            recording.add(f"review:{name}", None, {"prompt": request.prompt})
            return reply
        return call

    return ReviewStages(
        support=stage("support", _review_bundle.LENS_READING),
        ablation=stage("ablation", _review_bundle.LENS_READING),
        composer=stage("composer", _review_bundle.composer_reply("holds")),
    )


class SteppingClock:
    """Advance a fixed step per read and retain every reading."""

    def __init__(self, start: dt.datetime, step: dt.timedelta = dt.timedelta(seconds=1)) -> None:
        self._now, self._step = start, step
        self.readings: list[dt.datetime] = []

    def __call__(self) -> dt.datetime:
        now = self._now
        self.readings.append(now)
        self._now = now + self._step
        return now


NATURAL_CLOCK_START = dt.datetime(2026, 5, 25, 15, 30, tzinfo=dt.UTC)
ARM_CLOCK_START = dt.datetime(2026, 9, 1, 9, 0, tzinfo=dt.UTC)


def _driver_call(recording: Recording, main: RoleModel, gather: RoleModel,
                 clock: SteppingClock) -> Callable[..., dict[str, Any]]:
    """Inject recording models, review stages, and the required run clock into the real driver."""
    from pydantic_ai.models import override_allow_model_requests
    from pydantic_ai.models.function import FunctionModel

    from defender.investigation import driver
    from defender.providers import BuiltModel
    from defender.tests.e2e._replay_harness import _awaiting

    main_built = BuiltModel(FunctionModel(_awaiting(main)), None)
    gather_built = BuiltModel(FunctionModel(_awaiting(gather)), None)

    def make_model(name: str, effort: Any) -> Any:
        return gather_built if name == driver.gather_model() else main_built

    def investigate(**kw: Any) -> dict[str, Any]:
        recording.run_dir = Path(kw["run"].run_dir)
        recording.run_id = str(kw["run"].id)
        recording.defender_dir = Path(kw["defender_dir"])
        tenant = kw["tenant"]
        recording.policies = read_policies(recording.run_dir, recording.defender_dir, tenant)
        recording.corpus = corpus_snapshot(recording.run_dir, recording.defender_dir,
                                           tenant.agent,
                                           recording.policies["main"])
        recording.clock = clock
        with override_allow_model_requests(False):
            summary = asyncio.run(driver.run_investigation(
                **kw, make_model=make_model, review_stages=recording_review_stages(recording),
                clock=clock))
        recording.summary = dict(summary)
        return summary

    return investigate


def lifecycle(recording: Recording, *, main_turns: list[Any], clock: SteppingClock,
              registry_cls: type | None = None) -> Callable[..., dict[str, Any]]:
    """The orchestrator's fixed arm composition (dossier "Arm composition"), for either run."""
    import defender.run as run_mod
    from defender import box as box_mod
    from defender.tests.e2e._replay_harness import _no_docker_daemon

    main = RoleModel(recording, "main", turns=main_turns)
    gather = RoleModel(recording, "gather", by_lead=gather_scripts())
    drive_kw: dict[str, Any] = {"investigate": _driver_call(recording, main, gather, clock)}
    if registry_cls is not None:
        drive_kw["registry_cls"] = registry_cls
    return functools.partial(
        run_mod._run_investigation_lifecycle,
        investigate=functools.partial(run_mod._drive_investigation, **drive_kw),
        start_box=functools.partial(box_mod.start_box, docker=_no_docker_daemon),
        stop_box=lambda *_a, **_k: None,
        scrub=lambda *_a, **_k: None,
    )


def _no_preflight(*_a: Any, **_kw: Any) -> int:
    return 0


def _no_page(*_a: Any, **_kw: Any) -> None:
    return None


def _no_queue(*_a: Any, **_kw: Any) -> bool:
    return False


def run_main(argv: list[str], recording: Recording, *, main_turns: list[Any],
             clock: SteppingClock, registry_cls: type | None = None) -> None:
    """Run the production CLI composition and record its return code or refusal."""
    import defender.run as run_mod
    from defender.tests.support.tenancy._launch_publish_p4 import in_process_publish

    try:
        # #1108 P4 (OD14, O11): the in-process launch-time publish (publishes the tenant for
        # real when run.main launches it).
        recording.exit_code = run_mod.main(
            argv, lifecycle=lifecycle(recording, main_turns=main_turns, clock=clock,
                                      registry_cls=registry_cls),
            preflight=_no_preflight, visualize=_no_page, enqueue=_no_queue,
            publish=in_process_publish())
    except SystemExit as refused:
        recording.exit_code = "SystemExit"
        recording.refusal = str(refused.code)


_ENV_KEYS = ("DEFENDER_DATA_ROOT", "DEFENDER_EPISODES_BASE", "DEFENDER_LEARNING_STATE_DIR",
             "DEFENDER_RUN_VISUALIZATIONS_DIR", "DEFENDER_ALLOW_UNSANDBOXED")


def _source_run(tenant_id: str, run_id: str) -> Any:
    """The natural run, opened by id through its tenant's runs repository (as the launcher and the arm open a source)."""
    from defender.tenancy import _tenant
    from defender.records import RunId

    root = _tenant.resolve_data_root()
    tenant = _tenant.accept_tenant(fixture_data_root(root), tenant_id, defender_dir=DEFENDER)
    return tenant, tenant.runs_repository().open(RunId.parse(run_id))


def branch_message_id(source: Any, *, tool: str = "gather") -> int:
    """Find the tool-calling MAIN response for the requested branch tool."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    from defender.investigation import branch
    from defender.records import session_store

    store = branch.source_store_if_any(source.run_dir, source_run=source)
    assert store is not None, f"the natural run {source.run_dir} kept no session store"
    try:
        session = session_store.main_session_id(store)
        ids = session_store.path_row_ids(store, session)
        messages = session_store.hydrate(store, session, role="analysis")
    finally:
        store.close()
    assert len(ids) == len(messages), "the main path and its messages are not aligned"
    hits = [row for row, msg in zip(ids, messages, strict=True)
            if isinstance(msg, ModelResponse)
            and any(isinstance(p, ToolCallPart) and p.tool_name == tool for p in msg.parts)]
    assert len(hits) == 1, f"expected one main response calling {tool!r}, found {hits}"
    return hits[0]


def _fences_at_branch(natural: Recording) -> int:
    """Count document fences in MAIN's snapshot at the branch response."""
    from defender.skills.invlang.parser import scan_fences

    main = [r for r in natural.requests if r["role"] == "main"]
    doc = main[BRANCH_TURN]["files"].get("investigation.md", "")
    return len(scan_fences(doc).bodies)


CONTROL = "a"
REPLICATE = "r"


def replicate_world() -> dict[str, Any]:
    """The replicate's manifest entry (slice A's `world_doc`, role null, no facts, no axis)."""
    from defender.tests.support.learning.branch import _triplet_947 as T

    return T.world_doc(REPLICATE, role=None, axis=None, facts=[], story="the captured story")


def compose_control_episode(tenant_id: str, natural: Recording) -> tuple[str, int, dict[str, str]]:
    """Use launcher steps to prime the recording and create control and replicate arms."""
    from defender.learning.branch import cli
    from defender.tests.support.learning.branch import _triplet_947 as T

    tenant, source = _source_run(tenant_id, str(natural.run_id))
    k = branch_message_id(source)
    run_tenant = _resolve(tenant)
    view = cli.prepare_episode(tenant.runs_repository(), source)
    episode = view.episode
    try:
        as_of = cli.branch_point_clock(source, k)
        doc = T.family_doc(
            worlds=[T.base_world(), replicate_world()], episode_id=episode.dir.name,
            source_run_id=str(source.id), branch_message_id=k,
            fences_at=_fences_at_branch(natural),
            as_of=as_of.isoformat().replace("+00:00", "Z"),
            served_systems=cli.served_systems(run_tenant.grants.gather))
        doc.pop("source_run_dir", None)
        T.write_family(episode.dir, doc)
        view.start_runs([world["world_id"] for world in doc["worlds"]])
        return episode.dir.name, k, {w["label"]: w["world_id"] for w in doc["worlds"]}
    finally:
        view.close()


def _resolve(tenant: Any) -> Any:
    from defender.systems import run_tenant as run_tenant_mod

    return run_tenant_mod.run_tenant_for(tenant, defender_dir=DEFENDER,
                                         dispatches_lead_zero=False)


def plant_alert(path: Path) -> Path:
    """The case input: `_lead_zero_808`'s synthesized sshd alert, as an operator's file."""
    from defender.tests.e2e._lead_zero_808 import alert_doc

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(alert_doc()), encoding="utf-8")
    return path


def record_pair(*, tenant_id: str, alert: Path, arm: bool = True) -> dict[str, Any]:
    """Record a natural run, its replicate sibling, and its control arm through run.main."""
    natural = Recording("natural")
    run_main([str(alert), "--tenant", tenant_id, "--no-learn"], natural,
             main_turns=main_script(), clock=SteppingClock(NATURAL_CLOCK_START),
             registry_cls=canned_registry())
    out: dict[str, Any] = {"natural": natural.as_json(), "arm": None, "sibling": None,
                           "episode_id": None, "branch_message_id": None,
                           "composition_error": None}
    if not arm:
        return out
    try:
        episode_id, k, world_ids = compose_control_episode(tenant_id, natural)
    except Exception as failed:  # noqa: BLE001 — reported, so the test names the composition step
        out["composition_error"] = f"{type(failed).__name__}: {failed}"
        return out
    out["episode_id"], out["branch_message_id"] = episode_id, k
    out["world_id"], out["sibling_world_id"] = world_ids[CONTROL], world_ids[REPLICATE]
    for key, label in (("sibling", REPLICATE), ("arm", CONTROL)):
        world = Recording(key)
        run_main(["--tenant", tenant_id, "--episode", episode_id, "--world", label], world,
                 main_turns=main_script()[BRANCH_TURN + 1:],
                 clock=SteppingClock(ARM_CLOCK_START))
        out[key] = world.as_json()
    return out


_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?")
RUN_CLOCK = "<run-clock>"
_MIN_RUN_SPAN = dt.timedelta(hours=1)


def moment(text: str) -> dt.datetime | None:
    """`text` (one `_TIMESTAMP` match) as an aware UTC moment, or None when it does not parse."""
    try:
        when = dt.datetime.fromisoformat(text.replace(" ", "T", 1))
    except ValueError:
        return None
    return when.replace(tzinfo=dt.UTC) if when.tzinfo is None else when.astimezone(dt.UTC)


@dataclasses.dataclass(frozen=True)
class ClockWindow:
    """Inclusive run-clock range from the fork reading to a bounded run duration."""

    start: dt.datetime
    end: dt.datetime

    def holds(self, text: str) -> bool:
        when = moment(text)
        return when is not None and self.start <= when <= self.end


def _readings(recording: Mapping[str, Any]) -> list[dt.datetime]:
    return [dt.datetime.fromisoformat(t) for t in recording.get("clock_readings") or []]


def _window_from(readings: list[dt.datetime], at: int) -> ClockWindow | None:
    """Bound the clock window by twice the natural run span, with a minimum span."""
    if not readings:
        return None
    r = readings[min(max(at, 0), len(readings) - 1)]
    return ClockWindow(r, r + max(_MIN_RUN_SPAN, 2 * (readings[-1] - r)))


def start_window(recording: Mapping[str, Any]) -> ClockWindow | None:
    """Bound natural-run times by its clock readings; unclocked recordings forgive no time."""
    return _window_from(_readings(recording), 0)


def branch_window(natural: Mapping[str, Any], branch_turn: int = BRANCH_TURN,
                  ) -> ClockWindow | None:
    """Start the arm clock window at the natural run's last reading before the branch response."""
    readings = _readings(natural)
    mains = [r for r in natural["requests"] if r["role"] == "main"]
    if not readings or len(mains) <= branch_turn:
        return None
    return _window_from(readings, int(mains[branch_turn].get("clock_reads", 0)) - 1)


DURATION_KEYS = ("duration_ms", "duration_api_ms")
_DURATION = re.compile(
    r'(\\?"(?:' + "|".join(DURATION_KEYS) + r')\\?"\s*:\s*)(-?\d+(?:\.\d+)?)')

SESSION_KEYS = ("session_id", "parent_session_id", "case_id")
_UUID4_HEX = re.compile(r"[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}")
_WRAP_FRESH_SALT = re.compile(r"[0-9a-f]{16}")
_FRAME_SALT = re.compile(r"(</?run-)([0-9a-f]+)(-[a-z_-]+>)")
_TOOL_CALL_ID = re.compile(r"(?<![0-9A-Za-z_])(pyd_ai_)([0-9a-f]{32})(?![0-9A-Za-z_])")
_SESSION_IDS = (
    re.compile(r'(\\?"(?:' + "|".join(SESSION_KEYS) + r')\\?"\s*:\s*\\?")([0-9a-f]{32})(?=\\?")'),
    re.compile(r'(\\?"openai_prompt_cache_key\\?"\s*:\s*\\?")([0-9a-f]{32})(?=:)'),
)


def is_uuid4_hex(value: str) -> bool:
    """`value` is a `uuid.uuid4().hex`: 32 lowercase hex, version 4, variant 10."""
    return _UUID4_HEX.fullmatch(value) is not None


def is_fresh_salt(value: str) -> bool:
    """`value` is a salt a run role's frame is minted on: `wrap_fresh`'s 16 hex, or a review stage's `uuid4().hex`."""
    return _WRAP_FRESH_SALT.fullmatch(value) is not None or is_uuid4_hex(value)


def fresh_ids(text: str) -> list[tuple[str, str, int]]:
    """Return producer-tagged salts, tool-call IDs, and session IDs with their offsets."""
    out = [("frame salt", m.group(2), m.start(2)) for m in _FRAME_SALT.finditer(text)
           if is_fresh_salt(m.group(2))]
    out += [("tool-call id", m.group(2), m.start(2)) for m in _TOOL_CALL_ID.finditer(text)
            if is_uuid4_hex(m.group(2))]
    out += [("session id", m.group(2), m.start(2)) for pattern in _SESSION_IDS
            for m in pattern.finditer(text) if is_uuid4_hex(m.group(2))]
    return out


def normalize_o4(text: str, window: ClockWindow | None = None, *,
                 fork_turn: int | None = None) -> str:
    """`text` with the O4 classes replaced by placeholders and nothing else touched."""
    ids: dict[str, dict[str, str]] = {}

    def fresh(kind: str, token: str) -> str:
        seen = ids.setdefault(kind, {})
        return seen.setdefault(token, f"<{kind}{len(seen) + 1}>")

    def salt(m: re.Match[str]) -> str:
        if not is_fresh_salt(m.group(2)):
            return m.group(0)
        return f"{m.group(1)}{fresh('SALT', m.group(2))}{m.group(3)}"

    def call_id(m: re.Match[str]) -> str:
        return fresh("ID", m.group(2)) if is_uuid4_hex(m.group(2)) else m.group(0)

    def session_id(m: re.Match[str]) -> str:
        return (m.group(1) + fresh("SESSION", m.group(2)) if is_uuid4_hex(m.group(2))
                else m.group(0))

    def duration(m: re.Match[str]) -> str:
        if fork_turn is not None and float(m.group(2)) == fork_turn:
            return m.group(0)
        return f"{m.group(1)}<DUR>" if m.group(1).startswith("\\") else f'{m.group(1)}"<DUR>"'

    out = _FRAME_SALT.sub(salt, text)
    out = _TOOL_CALL_ID.sub(call_id, out)
    for pattern in _SESSION_IDS:
        out = pattern.sub(session_id, out)
    out = _TIMESTAMP.sub(
        lambda m: RUN_CLOCK if window is not None and window.holds(m.group(0)) else m.group(0),
        out)
    return _DURATION.sub(duration, out)


def _normalized(value: Any, window: ClockWindow | None, fork_turn: int | None = None) -> Any:
    """Normalize string leaves and pair fresh IDs across the complete request."""
    blob = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return json.loads(normalize_o4(blob, window, fork_turn=fork_turn))


@dataclasses.dataclass(frozen=True)
class Difference:
    """One channel on which two recordings differ, and the first content that differs there."""

    channel: str
    where: str
    first: str
    second: str
    sides: tuple[str, str] = ("natural", "arm")

    def __str__(self) -> str:
        return (f"{self.channel} @ {self.where}: {self.sides[0]}={self.first!r} "
                f"{self.sides[1]}={self.second!r}")


def _snip(text: str, at: int, width: int = 100) -> str:
    lo = max(0, at - width // 3)
    return ("…" if lo else "") + text[lo:at + width] + ("…" if at + width < len(text) else "")


def _first_text_difference(a: str, b: str) -> tuple[str, str]:
    """Each side around the first character at which `a` and `b` part."""
    at = next((i for i, (x, y) in enumerate(zip(a, b, strict=False)) if x != y),
              min(len(a), len(b)))
    return _snip(a, at), _snip(b, at)


def _brief(value: Any) -> str:
    """A one-line account of a message or part that only one side has."""
    if isinstance(value, dict) and "part_kind" in value:
        body = value.get("content", value.get("args"))
        body = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
        tool = f" {value['tool_name']}" if value.get("tool_name") else ""
        return f"{value['part_kind']}{tool}: {_snip(body or '', 0)}"
    if isinstance(value, dict) and "parts" in value:
        return f"{value.get('kind')} with {[_brief(p) for p in value['parts']]}"
    return _snip(json.dumps(value, ensure_ascii=False, default=repr), 0)


def _only_one_side(path: str, a: Any, b: Any, key: Any) -> tuple[str, str, str]:
    """A dict key or list item one side has and the other does not, shown rather than counted."""
    has_a = key in a if isinstance(a, dict) else key < len(a)
    has_b = key in b if isinstance(b, dict) else key < len(b)
    return (path, _brief(a[key]) if has_a else "<absent>", _brief(b[key]) if has_b else "<absent>")


def _first_container_difference(a: Any, b: Any, path: str) -> tuple[str, str, str] | None:
    if isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a or key not in b:
                return _only_one_side(f"{path}.{key}", a, b, key)
            found = _first_difference(a[key], b[key], f"{path}.{key}")
            if found:
                return found
        return None
    for i, (x, y) in enumerate(zip(a, b, strict=False)):
        found = _first_difference(x, y, f"{path}[{i}]")
        if found:
            return found
    if len(a) != len(b):
        i = min(len(a), len(b))
        return _only_one_side(f"{path}[{i}]", a, b, i)
    return None


def _first_difference(a: Any, b: Any, path: str = "") -> tuple[str, str, str] | None:
    """Locate the first differing JSON value, including a missing item."""
    if type(a) is not type(b):
        return path or "<root>", _brief(a), _brief(b)
    if isinstance(a, (dict, list)):
        return _first_container_difference(a, b, path)
    if a == b:
        return None
    if isinstance(a, str):
        na, nb = _first_text_difference(a, b)
        return path or "<root>", na, nb
    return path or "<root>", repr(a), repr(b)


_PER_REQUEST = 12


def _part_label(part: Mapping[str, Any]) -> str:
    tool = f" {part['tool_name']}" if part.get("tool_name") else ""
    return f"{part.get('part_kind', '?')}{tool}"


def _message_differences(i: int, x: Mapping[str, Any], y: Mapping[str, Any],
                         ) -> list[tuple[str, str, str]]:
    """One message's channels: its kind and instructions, then each part on its own."""
    out: list[tuple[str, str, str]] = []
    for field in ("kind", "instructions"):
        found = _first_difference(x.get(field), y.get(field), f"messages[{i}].{field}")
        if found:
            out.append(found)
    pa, pb = list(x.get("parts", [])), list(y.get("parts", []))
    for j, (u, v) in enumerate(zip(pa, pb, strict=False)):
        found = _first_difference(u, v, f"messages[{i}].parts[{j}]")
        if found:
            out.append((f"{found[0]} ({_part_label(u)})", found[1], found[2]))
    if len(pa) != len(pb):
        j = min(len(pa), len(pb))
        out.append(_only_one_side(f"messages[{i}].parts[{j}]", pa, pb, j))
    return out


def _request_differences(wa: Mapping[str, Any], wb: Mapping[str, Any],
                         ) -> list[tuple[str, str, str]]:
    """Report the first difference in each request channel, including instructions and tool definitions."""
    out: list[tuple[str, str, str]] = []
    ma, mb = list(wa.get("messages", [])), list(wb.get("messages", []))
    for i, (x, y) in enumerate(zip(ma, mb, strict=False)):
        out += _message_differences(i, x, y)
    if len(ma) != len(mb):
        i = min(len(ma), len(mb))
        out.append(_only_one_side(f"messages[{i}]", ma, mb, i))
    tools_a = {t["name"]: t for t in wa.get("function_tools", [])}
    tools_b = {t["name"]: t for t in wb.get("function_tools", [])}
    for name in sorted(set(tools_a) | set(tools_b)):
        found = _first_difference(tools_a.get(name), tools_b.get(name), f"tool[{name}]")
        if found:
            out.append(found)
    for field in sorted((set(wa) | set(wb)) - {"messages", "function_tools"}):
        found = _first_difference(wa.get(field), wb.get(field), field)
        if found:
            out.append(found)
    return out[:_PER_REQUEST]


def after_fork(recording: Mapping[str, Any], branch_turn: int) -> list[dict[str, Any]]:
    """Select requests after the tool-calling MAIN branch response."""
    reqs = list(recording["requests"])
    main_positions = [i for i, r in enumerate(reqs) if r["role"] == "main"]
    if len(main_positions) <= branch_turn:
        return []
    return reqs[main_positions[branch_turn] + 1:]


def streams(requests: list[dict[str, Any]]) -> dict[tuple[str, str | None], list[dict]]:
    """Group requests by role and gather lead while preserving each stream's order."""
    out: dict[tuple[str, str | None], list[dict]] = {}
    for r in requests:
        out.setdefault((r["role"], r["lead"]), []).append(r)
    return out


def _stream_name(key: tuple[str, str | None]) -> str:
    role, lead = key
    return f"{role}/{lead}" if lead else role


def _compare_streams(first: dict[tuple[str, str | None], list[dict]],
                     second: dict[tuple[str, str | None], list[dict]],
                     scope: str, sides: tuple[str, str],
                     windows: tuple[ClockWindow | None, ClockWindow | None],
                     forks: tuple[int | None, int | None] = (None, None),
                     ) -> list[Difference]:
    """Compare request counts, provider channels, and readable files within each stream."""
    wa, wb = windows
    fa, fb = forks
    diffs: list[Difference] = []
    for key in sorted(set(first) | set(second), key=lambda k: (k[0], k[1] or "")):
        a, b = first.get(key, []), second.get(key, [])
        name = _stream_name(key)
        if len(a) != len(b):
            diffs.append(Difference(f"{name} request count", scope,
                                    f"{len(a)} request(s)", f"{len(b)} request(s)", sides))
        for i, (x, y) in enumerate(zip(a, b, strict=False)):
            for where, na, nb in _request_differences(_normalized(x["wire"], wa, fa),
                                                      _normalized(y["wire"], wb, fb)):
                diffs.append(Difference(f"{name}#{i} request", where, na, nb, sides))
            for fname in sorted(set(x["files"]) | set(y["files"])):
                if (fname in x["files"]) != (fname in y["files"]):
                    diffs.append(Difference(
                        f"{name}#{i} files", fname,
                        "present" if fname in x["files"] else "absent",
                        "present" if fname in y["files"] else "absent", sides))
                    continue
                ta = normalize_o4(x["files"][fname], wa, fork_turn=fa)
                tb = normalize_o4(y["files"][fname], wb, fork_turn=fb)
                if ta != tb:
                    na, nb = _first_text_difference(ta, tb)
                    diffs.append(Difference(f"{name}#{i} files", fname, na, nb, sides))
    return diffs


def _request_times(request: Mapping[str, Any], window: ClockWindow) -> set[dt.datetime]:
    """The run-clock moments (inside `window`) one request shows, in its wire or its files."""
    texts = [json.dumps(request["wire"], ensure_ascii=False), *request["files"].values()]
    found = (moment(m.group(0)) for t in texts for m in _TIMESTAMP.finditer(t))
    return {w for w in found if w is not None and window.start <= w <= window.end}


def clock_order_faults(recording: Mapping[str, Any], window: ClockWindow | None, *,
                       label: str) -> list[Difference]:
    """Reject newly observed run-clock times that precede a stream's previous observations."""
    if window is None:
        return []
    faults: list[Difference] = []
    for key, reqs in streams(list(recording["requests"])).items():
        seen: set[dt.datetime] = set()
        for i, request in enumerate(reqs):
            times = _request_times(request, window)
            new = times - seen
            if seen and new and min(new) < max(seen):
                faults.append(Difference(
                    f"{label} {_stream_name(key)}#{i} run-clock order", "first shown here",
                    max(seen).isoformat(), min(new).isoformat(),
                    ("latest already shown", "earlier time new here")))
            seen |= times
    return faults


def corpus_differences(first: Mapping[str, Any], second: Mapping[str, Any],
                       sides: tuple[str, str]) -> list[Difference]:
    """Compare readable corpus pages, including missing pages."""
    pa, pb = first.get("corpus") or {}, second.get("corpus") or {}
    diffs: list[Difference] = []
    for name in sorted(set(pa) | set(pb)):
        if (name in pa) != (name in pb):
            diffs.append(Difference("corpus", name, "present" if name in pa else "absent",
                                    "present" if name in pb else "absent", sides))
        elif pa[name] != pb[name]:
            na, nb = _first_text_difference(pa[name], pb[name])
            diffs.append(Difference("corpus", name, na, nb, sides))
    return diffs


def compare(natural: Mapping[str, Any], arm: Mapping[str, Any], *,
            branch_turn: int = BRANCH_TURN, fork_turn: int | None = None) -> list[Difference]:
    """Compare an arm with its natural continuation using only permitted O4 normalization."""
    window = branch_window(natural, branch_turn)
    sides = ("natural", "arm")
    return [*_compare_streams(streams(after_fork(natural, branch_turn)),
                              streams(list(arm["requests"])), "after the fork",
                              sides, (window, window), (None, fork_turn)),
            *corpus_differences(natural, arm, sides),
            *clock_order_faults(arm, window, label="arm")]


def compare_layouts(first: Mapping[str, Any], second: Mapping[str, Any], *,
                    windows: tuple[ClockWindow | None, ClockWindow | None],
                    sides: tuple[str, str] = ("layout A", "layout B")) -> list[Difference]:
    """Compare every request, readable file, and corpus page across two layouts."""
    return [*_compare_streams(streams(list(first["requests"])),
                              streams(list(second["requests"])), "whole run", sides, windows),
            *corpus_differences(first, second, sides)]


@dataclasses.dataclass(frozen=True)
class Finding:
    """One forbidden token found in one model-visible surface."""

    channel: str
    what: str
    token: str
    context: str

    def __str__(self) -> str:
        return f"{self.channel}: {self.what} {self.token!r} in …{self.context}…"


_HEX_ID_TOKEN = re.compile(r"[0-9a-f]{32}|[0-9a-f]{16}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def _token_pattern(token: str) -> re.Pattern[str]:
    """`token` as a whole path or name: not glued to a longer name on either side."""
    if _HEX_ID_TOKEN.fullmatch(token):
        return re.compile(r"(?<![0-9A-Fa-f])" + re.escape(token) + r"(?![0-9A-Fa-f])",
                          re.IGNORECASE)
    return re.compile(r"(?<![\w.-])" + re.escape(token) + r"(?![\w.-])")


def host_tokens(meta: Mapping[str, Any]) -> dict[str, str]:
    """Return data-root, tenant, checkout, repository, home, and user tokens from the child layout."""
    out: dict[str, str] = {}
    for label, key in (("data root", "data_root"), ("data root (resolved)", "data_root_resolved"),
                       ("checkout path", "defender_dir"), ("checkout repo root", "repo_root"),
                       ("tenant name", "tenant")):
        if meta.get(key):
            out[label] = str(meta[key])
    home = str(meta.get("home") or "")
    if home and home != "/":
        out["host home"] = home
    if meta.get("user"):
        out["host user dir"] = f"/home/{meta['user']}"
    return out


def identity_tokens(pair: Mapping[str, Any], which: str) -> dict[str, str]:
    """O2's list (and P1's fixed names)."""
    natural_id = str(pair["natural"]["run_id"])
    if which == "natural":
        return {"natural run id": natural_id}
    out = {"source run id": natural_id}
    for key, name in (("arm", "arm run id"), ("sibling", "sibling run id")):
        if pair.get(key) and pair[key].get("run_id"):
            out[name] = str(pair[key]["run_id"])
    if pair.get("episode_id"):
        out["episode id"] = str(pair["episode_id"])
    for key, name in (("world_id", "world id"),
                      ("sibling_world_id", "sibling world id")):
        if pair.get(key):
            out[name] = str(pair[key])
    if pair.get("branch_message_id") is not None:
        labels = [label for key, label in (("arm", CONTROL), ("sibling", REPLICATE))
                  if pair.get(key)]
        out.update(fork_tokens(int(pair["branch_message_id"]), labels))
    return out


def fork_tokens(fork_turn: int, labels: Iterable[str]) -> dict[str, str]:
    """Return literal and folded encodings of the fork turn and world labels."""
    numbers = {"fork turn": fork_turn}
    for label in labels:
        numbers[f"world label {label}"] = ord(label)
        numbers[f"world label {label} with the fork turn"] = (fork_turn << 8) | ord(label)
    out: dict[str, str] = {}
    for name, number in numbers.items():
        made = uuid.UUID(int=number)
        out[f"{name} (uuid int)"] = made.hex
        out[f"{name} (uuid int, hyphenated)"] = str(made)
        out[f"{name} (16-hex int)"] = f"{number:016x}"
    return out


def _unversioned(hex32: str) -> str:
    """Remove UUID version and variant nibbles when checking derived identities."""
    return hex32[:12] + hex32[13:16] + hex32[17:]


def _id_shaped_forms(token: str) -> dict[str, str]:
    """Return token-derived 32-hex forms, retaining their derivation labels."""
    from defender.tests.support.runtime.state import _1255_identity as IDN

    out: dict[str, str] = {}
    for how, form in {"itself": token, **IDN.derived_forms(token)}.items():
        bare = form.replace("-", "").lower()
        if re.fullmatch(r"[0-9a-f]{32}", bare):
            out.setdefault(_unversioned(bare), how)
    return out


def _surfaces(recording: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """Enumerate model-visible request and file text with stable deduplication keys."""
    surfaces: list[tuple[str, str, str]] = []
    for key, reqs in streams(list(recording["requests"])).items():
        for i, r in enumerate(reqs):
            surfaces.append((f"{_stream_name(key)}#{i} request", f"{_stream_name(key)} request",
                             json.dumps(r["wire"], ensure_ascii=False)))
            surfaces += [(f"{_stream_name(key)}#{i} files:{name}", f"file {name}", text)
                         for name, text in r["files"].items()]
    surfaces += [(f"corpus:{name}", f"corpus {name}", text)
                 for name, text in recording.get("corpus", {}).items()]
    return surfaces


def _as_fresh_id(forgiven: list[tuple[str, int]], id_shaped: Mapping[str, str],
                 ) -> tuple[str, int] | None:
    """Find forgiven IDs matching a derived identity apart from UUID version and variant bits."""
    return next(((f"{id_shaped[_unversioned(v)]} as a fresh id", at)
                 for v, at in forgiven if _unversioned(v) in id_shaped), None)


def scan(recording: Mapping[str, Any], tokens: Mapping[str, str], *,
         encoded: bool = False) -> list[Finding]:
    """Every request (as sent) and every read-scope file at it, and the corpus, searched for each token."""
    from defender.tests.support.runtime.state import _1255_identity as IDN

    patterns = {label: (tok, _token_pattern(tok)) for label, tok in tokens.items() if tok}
    id_shaped = ({label: _id_shaped_forms(tok) for label, (tok, _) in patterns.items()}
                 if encoded else {})
    found: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for channel, surface, text in _surfaces(recording):
        views: list[str] | None = None
        forgiven = [(v, at) for _, v, at in fresh_ids(text) if len(v) == 32] if encoded else []
        for label, (tok, pat) in patterns.items():
            if (surface, label) in seen:
                continue
            m = pat.search(text)
            hit: tuple[str, int] | None = None
            if m:
                found.append(Finding(channel, label, tok, _snip(text, m.start(), 120)))
            elif encoded:
                if views is None:
                    views = IDN.decoded_views(text)
                hit = (IDN.encoded_form(text, tok, views=views)
                       or _as_fresh_id(forgiven, id_shaped[label]))
                if hit is not None:
                    found.append(Finding(channel, f"{label} ({hit[0]})", tok,
                                         _snip(text, hit[1], 120)))
            if m or hit is not None:
                seen.add((surface, label))
    return found


_NOT_COPIED = shutil.ignore_patterns(
    ".venv", "__pycache__", "*.pyc", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules", "run-visualizations", "_pending")


def copy_checkout(dest_root: Path) -> Path:
    """Copy code and knowledge so imports resolve to a distinct checkout; share this interpreter's venv."""
    dest_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(DEFENDER, dest_root / "defender", symlinks=True, ignore=_NOT_COPIED)
    shutil.copytree(REPO_ROOT / "knowledge", dest_root / "knowledge", symlinks=True,
                    ignore=_NOT_COPIED)
    (dest_root / "defender" / ".venv").symlink_to(Path(sys.prefix))
    return dest_root / "defender"


def _child_env(config: Mapping[str, Any]) -> dict[str, str]:
    """Strip provider keys and inherited layout knobs; set this child's roots and unboxed mode."""
    env = {k: v for k, v in os.environ.items()
           if not k.endswith("_API_KEY") and not k.startswith("DEFENDER_")
           and k not in ("PYTHONPATH", "PYTEST_CURRENT_TEST")}
    env.update({
        "PYTHONPATH": str(config["checkout_root"]),
        "DEFENDER_DATA_ROOT": str(config["data_root"]),
        "DEFENDER_EPISODES_BASE": str(config["episodes_root"]),
        "DEFENDER_LEARNING_STATE_DIR": str(config["learning_root"]),
        "DEFENDER_RUN_VISUALIZATIONS_DIR": str(config["pages_root"]),
        "DEFENDER_ALLOW_UNSANDBOXED": "1",
        "DEFENDER_LOG_LEVEL": "WARNING",
        "PYDANTIC_AI_NO_BANNER": "1",
    })
    return env


def start_layout(tmp: Path, *, label: str, tenant: str, arm: bool = True) -> subprocess.Popen:
    """Copy a host layout and launch its recording child process."""
    base = tmp / label
    checkout = copy_checkout(base / f"ck-{label}")
    config = {
        "label": label, "tenant": tenant, "arm": arm,
        "checkout_root": str(checkout.parent), "data_root": str(base / f"data-{label}"),
        "episodes_root": str(base / "episodes"), "learning_root": str(base / "learning"),
        "pages_root": str(base / "pages"), "out": str(base / "recording.json"),
        "alert": str(base / "input" / "alert.json"),
    }
    for key in ("data_root", "episodes_root", "learning_root", "pages_root"):
        Path(config[key]).mkdir(parents=True, exist_ok=True)
    (base / "config.json").write_text(json.dumps(config), encoding="utf-8")
    log = (base / "child.log").open("w", encoding="utf-8")
    return subprocess.Popen(
        [sys.executable, "-m", "defender.tests.e2e._1255_twin", str(base / "config.json")],
        cwd=str(base), env=_child_env(config), stdout=log, stderr=subprocess.STDOUT)


def finish_layout(proc: subprocess.Popen, tmp: Path, label: str,
                  timeout: float = 600) -> dict[str, Any]:
    """Read the child recording, or report its exit status and log tail."""
    base = tmp / label
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        code = "timeout"
    out = base / "recording.json"
    if out.is_file():
        return json.loads(out.read_text(encoding="utf-8"))
    tail = (base / "child.log").read_text(encoding="utf-8")[-4000:]
    return {"harness_error": f"layout {label} child exited {code} with no recording:\n{tail}"}


def _child(config_path: str) -> int:
    """Set up the tenant and record both executions plus their actual host layout."""
    import defender.run as run_mod
    from defender import _log, run_common
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    _log.configure(fmt="text", level="WARNING")
    set_up_tenant(Path(config["data_root"]), config["tenant"])
    pair = record_pair(tenant_id=config["tenant"], alert=plant_alert(Path(config["alert"])),
                       arm=bool(config["arm"]))
    pair["meta"] = {
        "label": config["label"], "tenant": config["tenant"],
        "data_root": config["data_root"],
        "data_root_resolved": str(Path(config["data_root"]).resolve()),
        "defender_dir": str(run_mod.DEFENDER_DIR), "repo_root": str(run_common.REPO_ROOT),
        "home": os.path.expanduser("~"), "user": getpass.getuser(),
    }
    Path(config["out"]).write_text(json.dumps(pair, default=repr), encoding="utf-8")
    return 0


if __name__ == "__main__":  # lint-log-setup: ok — a test child; `_child` configures logging first
    sys.exit(_child(sys.argv[1]))
