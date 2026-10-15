"""#1255 slice E — the twin check's machinery (O5). NO test scripts.

The design's "Twin check (O5)": record a natural run with a scripted model and an injected
clock, fork a control-world arm from it at a tool-calling main turn (D1), drive the arm with
the same script, and compare — at every model request after the fork, for main, gather and
review — the full request the provider would be sent (messages, tool results, tool
definitions; part timestamps are never sent and are left out) and, after each tool call, every
file in the model's read scope. Only the named O4 list is normalised. The pair runs under two
different host layouts (data root, tenant name, checkout path) and must still compare equal;
every compared request and file is also scanned for host layout and arm identity.

WHAT IS PRODUCTION AND WHAT IS NOT
----------------------------------
Both runs go through `run.main` — the natural run as `run.py <alert> --tenant T`, the arm as
`run.py --tenant T --episode <ep> --world <control>` — with the orchestrator's fixed arm
composition (dossier "Arm composition"): `lifecycle=partial(run._run_investigation_lifecycle,
investigate=partial(run._drive_investigation, investigate=<driver call>), start_box=…,
stop_box=…, scrub=…)`. Everything between the argv and the driver is production: tenant
acceptance, materialisation, the episode door, the world and its registry, the lifecycle.

The seams this module fills, and why each is the honest one:

* the MODEL — `make_model` hands the driver `FunctionModel`s that replay a script and record
  every request (`RoleModel`); `override_allow_model_requests(False)` keeps the run hermetic;
* the REVIEW stages — the run's `review_stages=` bundle, as recording stages answering `holds`;
* the CLOCK — `run_investigation(clock=…)` (the orchestrator's run-clock seam), a fake that
  steps deterministically and keeps every reading. Passed only when the driver accepts the
  keyword; before slice D the seam does not exist, and the twin check then fails on that
  precondition rather than comparing: only a clocked recording says which times are the run
  clock's (forgiven inside their window, `ClockWindow`) and which are not (compared exactly);
* the BOX — `start_box=partial(box.start_box, docker=_no_docker_daemon)` under
  `DEFENDER_ALLOW_UNSANDBOXED=1`: production's own unboxed mode (the design's "Every mode",
  which is what lets the twin run in CI without a box). The docker double only fails to start;
  `stop_box`/`scrub` are no-ops because an unsandboxed box has nothing to stop or scan;
* the DATA SOURCE of the natural run only — `_drive_investigation(registry_cls=…)`, the
  drive function's existing registry seam, given a `ModuleVerbRegistry` whose verbs keep the
  real adapters' signatures, grant and roster and answer canned envelopes instead of reaching
  a cluster (`canned_registry`). The arm builds its own `WorldRegistry` (production) and is
  served from the family's recording that `prime_base` took from the natural run's capture.

The episode the arm opens is composed from the launcher's own steps (`cli.prepare_episode`,
`cli.branch_point_clock`, the episode view's `create_container`) plus a manifest built by
slice A's `_triplet_947.family_doc` with one control world. The launcher's questioner and
pre-flight replay are not run: neither changes what a control arm sees.

TWO LAYOUTS, AND WHY A SUBPROCESS
---------------------------------
`run.DEFENDER_DIR` and `run_common.REPO_ROOT` are `Path(__file__).resolve()` at import, so the
checkout path a run sees is fixed by where `defender` was imported from. A symlinked tree
resolves back to the real one (probe P-E1 in the slice return); only a COPY moves it. So each
layout is a copy of the checkout (`copy_checkout`) run in its own interpreter with
`PYTHONPATH` at the copy (`record_layout`), with its own data root and tenant name. The child
writes its recording as JSON; the parent compares.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import functools
import getpass
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent

# --------------------------------------------------------------------------------------
# The script. One natural run, written for the model view (P1): every path the model hands
# back is a model path or a run-relative operand, so the same script is valid in both runs
# before and after the view lands.
# --------------------------------------------------------------------------------------

#: The lead MAIN dispatches at the branch turn. Its gather is re-run in the arm (D1: gather
#: calls at the branch turn are re-run, never inherited), against the arm's world.
LEAD = "l-001"
#: The correlation lead the harness dispatches before MAIN's first turn (natural run only).
CORRELATION_LEAD = "l-00c"

#: The canned answer documents. Keys deliberately NOT in sorted order: a world that
#: re-serialises with sorted keys (G8) changes the bytes the model reads, and the twin must
#: see that.
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

#: Where on MAIN's turns the branch point sits (0-based): the gather dispatch. The arm forks at
#: this response — a main response that called tools whose answers are not in the history.
BRANCH_TURN = 1

#: Each query a script issues, by lead.
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

    golden = DEFENDER / "fixtures-e2e" / "golden-v2sshd" / "investigation.md"
    return [f"```invlang\n{body}\n```" for body in
            scan_fences(golden.read_text(encoding="utf-8")).bodies]


#: The signature the alert's record carries — what the corpus walk is keyed on.
SIGNATURE = "v2-sshd-success-after-failures"


def main_script() -> list[Any]:
    """MAIN's turns, the same for the natural run and (from `BRANCH_TURN + 1`) the arm.

    0. land the golden's FIRST block (an open frontier: 2 open slots, measured by slice A's
       `branchable_investigation`), so the branch point has a question to divide;
    1. dispatch one gather lead — THE BRANCH POINT (D1: a tool-calling main response);
    2. read the queries table and the lead's summary through `cat`, by run-relative operands
       (what the box's working directory makes of them in either run);
    3. walk the corpus through the invlang shim: its listing names example cases by their run
       folder (P-U6), and the shim runs on the run's environment;
    4. read the document back through the file tool, by its model path (P1);
    5. land the rest of the golden document (the lessons push answers every append);
    6. close `inconclusive` on the golden's own ceiling tests, which runs the review gate;
    7. end.
    """
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


# --------------------------------------------------------------------------------------
# The natural run's data source: the real adapters' verbs, signatures and grant; canned bodies.
# --------------------------------------------------------------------------------------

_ALERT_ID_FIELD = "kibana.alert.uuid"


def _answer(system: str, verb: str, params: Mapping[str, Any]) -> Any:
    """What the natural run's elastic answers. The alert's shell fetch (item 1's by-alert-id
    call) gets the alert's own document; the correlation lead's call and the lead's call get
    their own envelopes. Built by the REAL `search_envelope`, so no shape the adapter could
    not produce is served."""
    from defender.scripts.adapters.elastic_adapter import search_envelope
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
    """A `ModuleVerbRegistry` class for `_drive_investigation(registry_cls=…)`: the real roster,
    the real grant, each real verb's signature and markers (`functools.wraps`), and a body
    that returns `answer(system, verb, params)` instead of reaching a backend. It decides
    nothing: validation, capture, rows and the breaker stay production's."""
    from defender.runtime.verbs import ModuleVerbRegistry

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


# --------------------------------------------------------------------------------------
# Recording: what each model request carried, and the read-scope files at that moment.
# --------------------------------------------------------------------------------------

#: The roles whose requests carry a read-scope snapshot, and the policy each reads through.
#: The review roles are left out: they hold no tool at all (`review_roles._review_def`:
#: `tools=ToolSet()`), so their whole model-visible input is the prompt they are handed, which
#: their request records.
READING_ROLES = ("main", "gather")


def read_policies(run_dir: Path, defender_dir: Path, tenant: Any) -> dict[str, Any]:
    """The run's compiled read policies, per role, exactly as the driver binds them: MAIN's
    definition, and gather's over the run's gather grant (`gather_def_for`), both scoped with
    the tenant's agent half (`RunScope(tenant_agent=…)`). Every gather lead reads through the
    same read shapes whichever verb grant it holds (the correlation lead's is narrower in verbs
    only), so one gather policy serves every lead."""
    from defender.runtime.agent_definition import RunScope, compile_policy_for
    from defender.runtime.driver import MAIN_DEF, gather_def_for

    scope = RunScope(tenant_agent=getattr(tenant, "agent", None))
    return {
        "main": compile_policy_for(MAIN_DEF, run_dir, defender_dir=defender_dir, scope=scope),
        "gather": compile_policy_for(gather_def_for(tenant.grants.gather), run_dir,
                                     defender_dir=defender_dir, scope=scope),
    }


def _readable(path: Path, *, run_dir: Path, defender_dir: Path, policy: Any) -> bool:
    """The real gate's answer (`permission.decide_read`) for one file, for one role."""
    from defender.runtime import permission

    return bool(permission.decide_read(path, run_dir=run_dir, defender_dir=defender_dir,
                                       policy=policy).allow)


def _text(path: Path) -> str:
    raw = path.read_bytes()  # lint-whole-read: ok — a test snapshot of a small run folder
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return repr(raw)


def files_snapshot(run_dir: Path | None, *, defender_dir: Path | None, policy: Any) -> dict[str, str]:
    """Every file of the run folder the role's gate admits a read of, as text (bytes that are
    not UTF-8 are shown as their repr, so a difference still names itself). Decided per file by
    the gate itself, so the snapshot is what the role could read, not a copy of the rules."""
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
    """The read-only half of the read scope: every `.md` under `lessons|skills|examples` of the
    checkout and the tenant's agent half that MAIN's gate admits, keyed by the tree it sits in
    and its relative path. It never changes during a run and is compared once per run."""
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


#: PARITY ONLY — never what the twin snapshots by. The run-folder half of each role's read
#: scope, written out from `runtime/permission/policies/_common.read_shapes` (the run root one
#: segment deep; `gather_summaries/<one>`; the alert input directory one deep; and, for gather
#: alone — `raw=True` — `gather_raw/l-<lead>/<n>.json`) and `files.decide_read`'s denies
#: (`gather_raw/` without a shape naming it, anything under `wire_logs/`, `provenance.json` at
#: the run root), at base 4b3628ed. `test_1255_twin_read_scope_parity` holds the gate to it, so
#: a change in the rules shows as a parity failure rather than as a quietly different snapshot.
_RUN_ROOT_DENIED = frozenset({"provenance.json"})
_RAW_PAYLOAD = re.compile(r"gather_raw/l-[A-Za-z0-9]{1,64}/[0-9]+\.json")


def _alert_input_dir() -> str:
    from defender.run_repository import RUN_LAYOUT

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
    """The fields of one message part a provider is sent. Timestamps, provider bookkeeping and
    usage are not sent and are left out (design: "part timestamps are never sent")."""
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
    """One model request as the provider would be sent it: every message's parts (sent fields
    only) and instructions, the tool definitions, the output tools and the settings."""
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
    """One run's record: every model request (role, lead, its index within that role/lead, the
    wire request, the files that role's gate admits at that moment, how many times the run
    clock's source had been read by then), the review stages' prompts, the corpus once, every
    reading the clock source gave, and the driver's summary."""

    label: str
    run_dir: Path | None = None
    requests: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    corpus: dict[str, str] = dataclasses.field(default_factory=dict)
    summary: dict[str, Any] = dataclasses.field(default_factory=dict)
    clock_injected: bool = False
    exit_code: Any = None
    refusal: str | None = None
    run_id: str | None = None
    #: Held off the JSON: the clock source handed to the run, the run's compiled read policies
    #: per role (`read_policies`), and the tree the run reads.
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
                "clock_injected": self.clock_injected, "exit_code": self.exit_code,
                "refusal": self.refusal,
                "clock_readings": [t.isoformat() for t in readings]}


#: The lead id a gather dispatch names, read off the gather's first request (the Dispatch
#: block `tools_gather` renders) — the replay harness's own pattern.
_DISPATCHED_LEAD = re.compile(r"\n## Dispatch\n```yaml\n(?:.*\n)*?lead_id: (\S+)\n")


class RoleModel:
    """A `FunctionModel` callable for one role: records every request into `recording`, then
    answers the next scripted turn. For the gather role, the script is chosen per lead (the
    lead id is read off the conversation), so concurrent leads are recorded per lead."""

    __name__ = "RoleModel"

    def __init__(self, recording: Recording, role: str, turns: list[Any] | None = None,
                 by_lead: Mapping[str, list[Any]] | None = None) -> None:
        self.recording, self.role = recording, role
        self._turns = list(turns or [])
        self._by_lead = {k: list(v) for k, v in (by_lead or {}).items()}
        self._used: dict[str | None, int] = {}

    def _lead_of(self, messages: list[Any]) -> str | None:
        if self.role != "gather":
            return None
        from defender.tests.e2e._replay_harness import messages_text

        found = _DISPATCHED_LEAD.search(messages_text(messages[:1]))
        return found.group(1) if found else None

    def __call__(self, messages: list[Any], info: Any) -> Any:
        from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart

        lead = self._lead_of(messages)
        self.recording.add(self.role, lead, wire_request(messages, info))
        script = self._turns if self.role != "gather" else self._by_lead.get(lead or "", [])
        n = self._used.get(lead, 0)
        self._used[lead] = n + 1
        if n >= len(script):
            return ModelResponse(parts=[TextPart(content="(replay exhausted)")])
        turn = script[n]
        parts: list[Any] = [TextPart(content=turn.text)] if turn.text else []
        parts += [ToolCallPart(tool_name=name, args=args) for name, args in turn.tool_calls]
        return ModelResponse(parts=parts or [TextPart(content="(done)")])


def recording_review_stages(recording: Recording) -> Any:
    """The run's review bundle: every stage records the prompt it was handed (the review roles'
    model-visible input) and answers as `_review_bundle` does, the composer finding `holds`."""
    from defender.runtime.review_roles import ReviewStages
    from defender.tests import _review_bundle

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
    """The run clock's source for a test: a timezone-aware UTC reading that advances a fixed
    step on every read, so every time the run derives is deterministic. Every reading it gave
    is kept, so the recording can say what the clock read by each request."""

    def __init__(self, start: dt.datetime, step: dt.timedelta = dt.timedelta(seconds=1)) -> None:
        self._now, self._step = start, step
        self.readings: list[dt.datetime] = []

    def __call__(self) -> dt.datetime:
        now = self._now
        self.readings.append(now)
        self._now = now + self._step
        return now


#: The natural run's clock source starts here; the arm's source starts months later, as a real
#: arm launched after its source would (design: the arm's run clock starts at the snapshot's
#: reading and advances by what its source advances). The two are far apart, and both far
#: from the wall clock, so a time an arm channel reads off its own source — or off the wall —
#: lies outside the run clock's window (`clock_window`) and is compared exactly, and named.
NATURAL_CLOCK_START = dt.datetime(2026, 5, 25, 15, 30, tzinfo=dt.UTC)
ARM_CLOCK_START = dt.datetime(2026, 9, 1, 9, 0, tzinfo=dt.UTC)


def driver_accepts_clock() -> bool:
    from defender.runtime import driver

    return "clock" in inspect.signature(driver.run_investigation).parameters


def _driver_call(recording: Recording, main: RoleModel, gather: RoleModel,
                 clock: SteppingClock) -> Callable[..., dict[str, Any]]:
    """The innermost `investigate` of the arm composition: `driver.run_investigation(**kw,
    make_model=…, review_stages=…, clock=…)`, everything else exactly as `_drive_investigation`
    hands it over."""
    from pydantic_ai.models import override_allow_model_requests
    from pydantic_ai.models.function import FunctionModel

    from defender.runtime import driver
    from defender.runtime.providers import BuiltModel
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
                                           getattr(tenant, "agent", None),
                                           recording.policies["main"])
        extra: dict[str, Any] = {}
        if driver_accepts_clock():
            extra["clock"] = clock
            recording.clock_injected = True
            recording.clock = clock
        with override_allow_model_requests(False):
            summary = asyncio.run(driver.run_investigation(
                **kw, make_model=make_model, review_stages=recording_review_stages(recording),
                **extra))
        recording.summary = dict(summary)
        return summary

    return investigate


def lifecycle(recording: Recording, *, main_turns: list[Any], clock: SteppingClock,
              registry_cls: type | None = None) -> Callable[..., dict[str, Any]]:
    """The orchestrator's fixed arm composition (dossier "Arm composition"), for either run."""
    import defender.run as run_mod
    from defender.runtime import box as box_mod
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
    """`run.main(argv)` with the composition above; its exit (a return code, or the
    `SystemExit` a refusal raises) is kept on the recording rather than raised."""
    import defender.run as run_mod

    try:
        recording.exit_code = run_mod.main(
            argv, lifecycle=lifecycle(recording, main_turns=main_turns, clock=clock,
                                      registry_cls=registry_cls),
            preflight=_no_preflight, visualize=_no_page, enqueue=_no_queue)
    except SystemExit as refused:
        recording.exit_code = "SystemExit"
        recording.refusal = str(refused.code)


# --------------------------------------------------------------------------------------
# The pair, in one process: natural run, the control episode, the arm.
# --------------------------------------------------------------------------------------

_ENV_KEYS = ("DEFENDER_DATA_ROOT", "DEFENDER_EPISODES_BASE", "DEFENDER_LEARNING_STATE_DIR",
             "DEFENDER_RUN_VISUALIZATIONS_DIR", "DEFENDER_ALLOW_UNSANDBOXED")


def _source_run(tenant_id: str, run_id: str) -> Any:
    """The natural run, opened by id through its tenant's runs repository (as the launcher and
    the arm open a source)."""
    from defender import _tenant
    from defender.run_repository import RunId

    root = _tenant.resolve_data_root()
    tenant = _tenant.accept_tenant(root, tenant_id, defender_dir=DEFENDER)
    return tenant, tenant.runs_repository().open(RunId.parse(run_id))


def branch_message_id(source: Any, *, tool: str = "gather") -> int:
    """The row id, on the source's MAIN path, of the main response that dispatched `tool` — the
    branch point D1 admits: a tool-calling response whose answers are not in the history. Read
    off the source's own store, as the launcher reads its branch point."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart

    from defender.runtime import branch, session_store

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
    """How many invlang fences the document held when the branch response arrived: the
    document in the read-scope snapshot of MAIN's request that answered with that turn."""
    from defender.skills.invlang.parser import scan_fences

    main = [r for r in natural.requests if r["role"] == "main"]
    doc = main[BRANCH_TURN]["files"].get("investigation.md", "")
    return len(scan_fences(doc).bodies)


#: The control world's label in the twin's family (slice A's `base_world`: role A, no facts).
CONTROL = "a"
#: A null replicate world (`role: null`, no facts): the control's sibling, launched first, so the
#: control arm's runs folder holds a sibling as a production arm's does ("Every mode": the real
#: runs folder "for an arm holds its siblings"). It is served the base answers too, so nothing
#: it leaves behind may reach the control arm's model.
REPLICATE = "r"


def replicate_world() -> dict[str, Any]:
    """The replicate's manifest entry (slice A's `world_doc`, role null, no facts, no axis)."""
    from defender.tests import _triplet_947 as T

    return T.world_doc(REPLICATE, role=None, axis=None, facts=[], story="the captured story")


def compose_control_episode(tenant_id: str, natural: Recording) -> tuple[str, int]:
    """The episode a control arm of the natural run opens, composed from the launcher's own
    steps: the episode claimed and primed from the source's capture (`prepare_episode`), T0
    derived from the branch point (`branch_point_clock`), the manifest (slice A's builder, one
    control world and its null replicate), and the arms' container made with the tenant's
    record. Returns `(episode_id, branch_message_id)`."""
    from defender import _tenant
    from defender.learning.branch import cli
    from defender.tests import _triplet_947 as T

    tenant, source = _source_run(tenant_id, str(natural.run_id))
    k = branch_message_id(source)
    episode_id = cli.episode_id_for(str(source.id), k)
    run_tenant = _resolve(tenant)
    episode = cli.prepare_episode(episode_id, source, data_root=_tenant.resolve_data_root())
    try:
        as_of = cli.branch_point_clock(source, k)
        doc = T.family_doc(
            worlds=[T.base_world(), replicate_world()], episode_id=episode.dir.name,
            source_run_id=str(source.id), branch_message_id=k,
            fences_at=_fences_at_branch(natural),
            as_of=as_of.isoformat().replace("+00:00", "Z"),
            served_systems=cli.served_systems(run_tenant.grants.gather))
        doc.pop("source_run_dir", None)
        if not _manifest_declares_prompt():
            doc.pop(RETIRED_PROMPT_FIELD, None)
        T.write_family(episode.dir, doc)
        tenant.runs_repository().episode(episode.dir.name, held=episode).create_container()
        return episode.dir.name, k
    finally:
        episode.close()


#: The manifest field #1255 removes (D1, P4: an arm is told nothing on arrival).
RETIRED_PROMPT_FIELD = "continuation_prompt"


def _manifest_declares_prompt() -> bool:
    """Does this tree's family manifest still declare the continuation prompt (pre-#1255)?

    Read off the loaded `Family` rather than assumed — slice A's `declares_retired_prompt`
    rule for `BranchSpec`, applied to the manifest — so the episode composes on both sides of
    #1255: before it the loader refuses a manifest without the field, after it the field is
    gone. Whether it is gone is slice A's demand, never answered here. Delete with A's twin
    once #1255 has landed."""
    from defender.runtime.branch import _family

    return RETIRED_PROMPT_FIELD in {f.name for f in dataclasses.fields(_family.Family)}


def _resolve(tenant: Any) -> Any:
    from defender.runtime import run_tenant as run_tenant_mod

    return run_tenant_mod.run_tenant_for(tenant, defender_dir=DEFENDER,
                                         dispatches_lead_zero=False)


def plant_alert(path: Path) -> Path:
    """The case input: `_lead_zero_808`'s synthesized sshd alert, as an operator's file."""
    from defender.tests.e2e._lead_zero_808 import alert_doc

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(alert_doc()), encoding="utf-8")
    return path


def record_pair(*, tenant_id: str, alert: Path, arm: bool = True) -> dict[str, Any]:
    """One layout's pair, in this process: the natural run through `run.main`, then (with
    `arm`) the control episode composed from it, its replicate sibling and then the control
    arm, each through `run.main` with the same script from the turn after the branch point.
    Returns the recordings as JSON-able dicts plus what the pair was composed from."""
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
        episode_id, k = compose_control_episode(tenant_id, natural)
    except Exception as failed:  # noqa: BLE001 — reported, so the test names the composition step
        out["composition_error"] = f"{type(failed).__name__}: {failed}"
        return out
    out["episode_id"], out["branch_message_id"] = episode_id, k
    for key, label in (("sibling", REPLICATE), ("arm", CONTROL)):
        world = Recording(key)
        run_main(["--tenant", tenant_id, "--episode", episode_id, "--world", label], world,
                 main_turns=main_script()[BRANCH_TURN + 1:],
                 clock=SteppingClock(ARM_CLOCK_START))
        out[key] = world.as_json()
    return out


# --------------------------------------------------------------------------------------
# O4: the ONLY differences the comparison forgives. Each rule names the O4 class it is.
# Anything not matched here is compared byte for byte.
# --------------------------------------------------------------------------------------

#: O4 "timestamps" — but only the RUN CLOCK's (design, O4: "Time must be consistent, not
#: equal. Every time the model can see agrees with every other one and never runs earlier than
#: the history's last timestamp"). An ISO-8601 moment, date and time, any precision, any zone
#: spelling (naive read as UTC), is forgiven only when it falls inside the run clock's window
#: (`ClockWindow`): from the natural run's reading R up to R plus a run-length bound. Every
#: other moment — the history's own times, the alert's, the data's, a time before R, a time off
#: the arm's own clock source or off the wall — is compared exactly, so it is named.
_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?")
#: What a forgiven run-clock time reads as after normalisation.
RUN_CLOCK = "<run-clock>"
#: The run-length bound's floor: a window is at least this long past R.
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
    """The run-clock times a comparison forgives: `start` (R, a reading of the natural run's
    clock source) to `end` (R plus the run-length bound), both inclusive."""

    start: dt.datetime
    end: dt.datetime

    def holds(self, text: str) -> bool:
        when = moment(text)
        return when is not None and self.start <= when <= self.end


def _readings(recording: Mapping[str, Any]) -> list[dt.datetime]:
    return [dt.datetime.fromisoformat(t) for t in recording.get("clock_readings") or []]


def _window_from(readings: list[dt.datetime], at: int) -> ClockWindow | None:
    """The window from reading number `at` (0-based) on: R, and a bound of twice the run's own
    span after R, never less than `_MIN_RUN_SPAN` — far short of the arm source's start
    (months on) and of the wall clock."""
    if not readings:
        return None
    r = readings[min(max(at, 0), len(readings) - 1)]
    return ClockWindow(r, r + max(_MIN_RUN_SPAN, 2 * (readings[-1] - r)))


def start_window(recording: Mapping[str, Any]) -> ClockWindow | None:
    """A whole run's window: from its clock source's first reading. None for a run that was
    never handed a clock (then no time is forgiven)."""
    return _window_from(_readings(recording), 0)


def branch_window(natural: Mapping[str, Any], branch_turn: int = BRANCH_TURN,
                  ) -> ClockWindow | None:
    """The window an arm of `natural` is held to: R is the natural run's last clock reading
    before MAIN's request `branch_turn` was answered (the branch response) — taken from the
    natural recording, never from the arm. None for an unclocked natural run."""
    readings = _readings(natural)
    mains = [r for r in natural["requests"] if r["role"] == "main"]
    if not readings or len(mains) <= branch_turn:
        return None
    return _window_from(readings, int(mains[branch_turn].get("clock_reads", 0)) - 1)
#: O4 "durations": a number under a key that names an elapsed measure.
_DURATION = re.compile(
    r'("(?:[a-z_]*_)?(?:ms|seconds|secs|duration|elapsed|wall)(?:_[a-z_]*)?"\s*:\s*)'
    r"-?\d+(?:\.\d+)?")
#: O4 "fresh random ids", each minted per occurrence by its own owner:
#:   a frame delimiter's salt (`_untrusted.wrap_fresh`, one per frame),
#:   the framework's tool-call id (`pyd_ai_<uuid hex>`),
#:   a bare uuid4 hex or hyphenated uuid (case ids, start tokens).
#: Replaced by first appearance WITHIN one compared value (`<ID1>`, `<ID2>`, …), so a value that
#: reuses one id twice still has to reuse it twice. A content digest (64 hex) is NOT an id: two
#: digests differ exactly when the bytes they digest do.
_FRAME_SALT = re.compile(r"(</?run-)([0-9a-f]+)(-[a-z_-]+>)")
_FRESH_ID = re.compile(
    r"pyd_ai_[0-9a-f]{32}|(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{12}(?![0-9a-f])|(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")


def normalize_o4(text: str, window: ClockWindow | None = None) -> str:
    """`text` with the O4 classes replaced by placeholders and nothing else touched. A time is
    replaced only when `window` holds it; with no window, every time stays as it is."""
    ids: dict[str, str] = {}

    def fresh(token: str) -> str:
        return ids.setdefault(token, f"<ID{len(ids) + 1}>")

    out = _FRAME_SALT.sub(lambda m: f"{m.group(1)}{fresh('salt:' + m.group(2))}{m.group(3)}",
                          text)
    out = _FRESH_ID.sub(lambda m: fresh(m.group(0)), out)
    out = _TIMESTAMP.sub(
        lambda m: RUN_CLOCK if window is not None and window.holds(m.group(0)) else m.group(0),
        out)
    return _DURATION.sub(r"\1<DUR>", out)


def _normalized(value: Any, window: ClockWindow | None) -> Any:
    """Every string leaf of a JSON value through `normalize_o4`, and the ids renumbered over the
    WHOLE value (one request), so a call id and the return that answers it stay paired."""
    blob = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return json.loads(normalize_o4(blob, window))


# --------------------------------------------------------------------------------------
# The comparison: every model request after the fork, per role and per lead, and the read-scope
# files at each of them. Each difference names its channel and its first differing content.
# --------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Difference:
    """One channel on which two recordings differ, and the first content that differs there.

    `sides` names the two recordings (the arm against its natural continuation, or one layout
    against another)."""

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
    """The first JSON path at which `a` and `b` differ, and each side's content there. An item
    only one side has is shown, not counted."""
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


#: At most this many differences are named per request: enough to see every channel a request
#: carries without one broken request burying the rest of the report.
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
    """Every channel of one request that differs, each with its first differing content: each
    message part on its own (a tool result, a prompt, a call), each message's instructions,
    then the request's own fields (tool definitions per tool, output tools, settings, and a
    review stage's prompt)."""
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
    """The natural run's requests made after its branch response arrived: everything recorded
    after MAIN's request number `branch_turn` (the request the branch turn answered)."""
    reqs = list(recording["requests"])
    main_positions = [i for i, r in enumerate(reqs) if r["role"] == "main"]
    if len(main_positions) <= branch_turn:
        return []
    return reqs[main_positions[branch_turn] + 1:]


def streams(requests: list[dict[str, Any]]) -> dict[tuple[str, str | None], list[dict]]:
    """Requests grouped per role and per lead, each in its own order — so concurrent gather
    leads are compared per lead (O4: the order of concurrent work)."""
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
                     ) -> list[Difference]:
    """Each role/lead stream of `first` against `second`, request by request: the count, each
    request's channels (O4-normalised, each side's run-clock times by its own window), and the
    read-scope files at that request."""
    wa, wb = windows
    diffs: list[Difference] = []
    for key in sorted(set(first) | set(second), key=lambda k: (k[0], k[1] or "")):
        a, b = first.get(key, []), second.get(key, [])
        name = _stream_name(key)
        if len(a) != len(b):
            diffs.append(Difference(f"{name} request count", scope,
                                    f"{len(a)} request(s)", f"{len(b)} request(s)", sides))
        for i, (x, y) in enumerate(zip(a, b, strict=False)):
            for where, na, nb in _request_differences(_normalized(x["wire"], wa),
                                                      _normalized(y["wire"], wb)):
                diffs.append(Difference(f"{name}#{i} request", where, na, nb, sides))
            for fname in sorted(set(x["files"]) | set(y["files"])):
                if (fname in x["files"]) != (fname in y["files"]):
                    diffs.append(Difference(
                        f"{name}#{i} files", fname,
                        "present" if fname in x["files"] else "absent",
                        "present" if fname in y["files"] else "absent", sides))
                    continue
                ta = normalize_o4(x["files"][fname], wa)
                tb = normalize_o4(y["files"][fname], wb)
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
    """O4 "never runs earlier": per role/lead stream, a run-clock time that first shows at a
    request must not be earlier than the latest run-clock time that stream already showed. A
    time inside the window can still run backwards; normalising it away would hide that."""
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


def compare(natural: Mapping[str, Any], arm: Mapping[str, Any], *,
            branch_turn: int = BRANCH_TURN) -> list[Difference]:
    """O1: every difference between the arm and the natural continuation of its source after
    the fork — per role and lead, the request count, each request's channels and the
    read-scope files at it — and every run-clock time of the arm's that runs backwards. Only
    the O4 list is normalised; run-clock times by the natural run's branch window
    (`branch_window`), on both sides."""
    window = branch_window(natural, branch_turn)
    return [*_compare_streams(streams(after_fork(natural, branch_turn)),
                              streams(list(arm["requests"])), "after the fork",
                              ("natural", "arm"), (window, window)),
            *clock_order_faults(arm, window, label="arm")]


def compare_layouts(first: Mapping[str, Any], second: Mapping[str, Any], *,
                    windows: tuple[ClockWindow | None, ClockWindow | None],
                    sides: tuple[str, str] = ("layout A", "layout B")) -> list[Difference]:
    """O3: one run kind recorded under two host layouts — every request and read-scope file
    from the first request on, and the read-only corpus. `windows` are each side's own run-clock
    window: a natural run's `start_window`, an arm's natural run's `branch_window`."""
    diffs = _compare_streams(streams(list(first["requests"])), streams(list(second["requests"])),
                             "whole run", sides, windows)
    for name in sorted(set(first["corpus"]) | set(second["corpus"])):
        a, b = first["corpus"].get(name), second["corpus"].get(name)
        if a != b:
            na, nb = _first_text_difference(a or "<absent>", b or "<absent>")
            diffs.append(Difference("corpus", name, na, nb, sides))
    return diffs


# --------------------------------------------------------------------------------------
# The scan: host layout (O3) and arm identity (O2) in every compared request and file. A
# test-time detector only (design: "substring scanning for host prefixes is a test-time
# detector only").
# --------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Finding:
    """One forbidden token found in one model-visible surface."""

    channel: str
    what: str
    token: str
    context: str

    def __str__(self) -> str:
        return f"{self.channel}: {self.what} {self.token!r} in …{self.context}…"


def _token_pattern(token: str) -> re.Pattern[str]:
    """`token` as a whole path or name: not glued to a longer name on either side. A path token
    may be followed by `/` (anything under it is still that host path)."""
    return re.compile(r"(?<![\w.-])" + re.escape(token) + r"(?![\w.-])")


def host_tokens(meta: Mapping[str, Any]) -> dict[str, str]:
    """O3's list for one layout, from what the child process actually ran with: the data root
    (as given and resolved), the tenant folder name, the checkout path and its repo root, and
    the host user's home."""
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
    """O2's list (and P1's fixed names). A natural run shows no run id of its own (its folder's
    name; `/runs/current` hides it); an arm shows none of: its own run id, its source run's id,
    its sibling's run id, the episode id, the episode token, the world token. The tokens are
    the ones production composed (`_child` records them). (The fork turn is a bare integer and
    the world label a single letter: neither can be scanned for; equality covers them.)"""
    natural_id = str(pair["natural"]["run_id"])
    if which == "natural":
        return {"natural run id": natural_id}
    out = {"source run id": natural_id}
    for key, name in (("arm", "arm run id"), ("sibling", "sibling run id")):
        if pair.get(key) and pair[key].get("run_id"):
            out[name] = str(pair[key]["run_id"])
    if pair.get("episode_id"):
        out["episode id"] = str(pair["episode_id"])
    if pair.get("episode_token"):
        out["episode token"] = str(pair["episode_token"])
    for key, name in (("world_token", "world token"),
                      ("sibling_world_token", "sibling world token")):
        if pair.get(key):
            out[name] = str(pair[key])
    return out


def scan(recording: Mapping[str, Any], tokens: Mapping[str, str]) -> list[Finding]:
    """Every request (as sent) and every read-scope file at it, and the corpus, searched for
    each token. One finding per (surface, token)."""
    patterns = {label: (tok, _token_pattern(tok)) for label, tok in tokens.items() if tok}
    # (channel, the surface a finding is reported once for, text): a request stream's
    # requests are one surface; a file is one surface whichever request snapshot shows it.
    surfaces: list[tuple[str, str, str]] = []
    for key, reqs in streams(list(recording["requests"])).items():
        for i, r in enumerate(reqs):
            surfaces.append((f"{_stream_name(key)}#{i} request", f"{_stream_name(key)} request",
                             json.dumps(r["wire"], ensure_ascii=False)))
            surfaces += [(f"{_stream_name(key)}#{i} files:{name}", f"file {name}", text)
                         for name, text in r["files"].items()]
    surfaces += [(f"corpus:{name}", f"corpus {name}", text)
                 for name, text in recording.get("corpus", {}).items()]
    found: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for channel, surface, text in surfaces:
        for label, (tok, pat) in patterns.items():
            m = pat.search(text)
            if m and (surface, label) not in seen:
                seen.add((surface, label))
                found.append(Finding(channel, label, tok, _snip(text, m.start(), 120)))
    return found


# --------------------------------------------------------------------------------------
# A layout: a copy of the checkout, its own data root and tenant, its own interpreter.
# --------------------------------------------------------------------------------------

#: What a copy of the checkout leaves out: caches, the environment, and output folders.
_NOT_COPIED = shutil.ignore_patterns(
    ".venv", "__pycache__", "*.pyc", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules", "run-visualizations", "_pending")


def copy_checkout(dest_root: Path) -> Path:
    """A copy of this checkout's `defender/` and `knowledge/` at `dest_root` — a checkout at a
    different path, which a symlink is not (`Path(__file__).resolve()` would follow it home).
    The copy's `defender/.venv` names this interpreter's environment, as a checkout's does, so
    the shims run the same Python. Returns the copy's `defender/`."""
    dest_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(DEFENDER, dest_root / "defender", symlinks=True, ignore=_NOT_COPIED)
    shutil.copytree(REPO_ROOT / "knowledge", dest_root / "knowledge", symlinks=True,
                    ignore=_NOT_COPIED)
    (dest_root / "defender" / ".venv").symlink_to(Path(sys.prefix))
    return dest_root / "defender"


def _child_env(config: Mapping[str, Any]) -> dict[str, str]:
    """The child's environment: this one, minus provider keys and the knobs the layout owns,
    plus the layout's roots and production's unboxed mode."""
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
    """Copy the checkout under `tmp/<label>/`, and start a child recording the pair there with
    its own data root and tenant. `finish_layout` collects it."""
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
    """The child's recording, or — when it produced none — a record naming why, with the tail
    of its log, so a broken harness reads as such rather than as a comparison."""
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
    """The child process: set the layout's tenant up, record the pair, write it out with what
    the run saw of the host (`meta`)."""
    import defender.run as run_mod
    from defender import _log, run_common
    from defender.tests._data_root_1078 import set_up_tenant

    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    _log.configure(fmt="text", level="WARNING")
    set_up_tenant(Path(config["data_root"]), config["tenant"])
    pair = record_pair(tenant_id=config["tenant"], alert=plant_alert(Path(config["alert"])),
                       arm=bool(config["arm"]))
    if pair.get("episode_id"):
        from defender.runtime.branch._family import episode_token_for

        pair["episode_token"] = episode_token_for(pair["episode_id"])
        pair["world_token"] = _world_token(pair["episode_id"], CONTROL)
        pair["sibling_world_token"] = _world_token(pair["episode_id"], REPLICATE)
    pair["meta"] = {
        "label": config["label"], "tenant": config["tenant"],
        "data_root": config["data_root"],
        "data_root_resolved": str(Path(config["data_root"]).resolve()),
        "defender_dir": str(run_mod.DEFENDER_DIR), "repo_root": str(run_common.REPO_ROOT),
        "home": os.path.expanduser("~"), "user": getpass.getuser(),
        "clock_seam": driver_accepts_clock(),
    }
    Path(config["out"]).write_text(json.dumps(pair, default=repr), encoding="utf-8")
    return 0


def _world_token(episode_id: str, label: str) -> str | None:
    """A world's token as production composes it (its arm's resume target)."""
    import defender.run as run_mod
    from defender import _tenant
    from defender._episode_handle import Episode, episode_dir

    try:
        root = _tenant.resolve_data_root()
        with Episode.open(episode_dir(root, episode_id)) as episode:
            return str(run_mod.resume_world(episode, label, tenant=lambda: None).token)
    except Exception:  # noqa: BLE001 — the token is a scan input; its absence is reported there
        return None


if __name__ == "__main__":  # lint-log-setup: ok — a test child; `_child` configures logging first
    sys.exit(_child(sys.argv[1]))
