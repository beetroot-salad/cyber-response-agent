"""#632: shared machinery for the verb-authorization tests. NOT a test module."""
from __future__ import annotations

from defender.records import RunPaths
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.systems.verb_grant import (  # noqa: E402
    DENY_ALL,
    VERB_CLASSES,
    GrantError,
    VerbGrant,
)
from defender.systems.verbs import (  # noqa: E402
    DENIED,
    GRANTED,
    UNDECLARED,
    VerbContext,
    VerbRegistry,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)

LEAD = "l-001"
ADAPTERS_DIR = DEFENDER / "integrations"

PAYLOAD = [
    {"@timestamp": "2026-01-01T00:00:00Z", "user.name": "dev.dana", "event.action": "ssh_login"},
]

# The verb-grant census, as literals: an independently written list, never read back from the
# definition it is checked against.
GATHER_PAIRS: tuple[tuple[str, str], ...] = (
    ("change-mgmt", "active-changes"), ("change-mgmt", "get-change"),
    ("change-mgmt", "list-changes"),
    ("cmdb", "get-host"), ("cmdb", "list-hosts"),
    ("elastic", "alerts"), ("elastic", "esql"), ("elastic", "query"),
    ("host-state", "authorized-keys"), ("host-state", "container-inspect"),
    ("host-state", "fim-checksum"), ("host-state", "package-list"),
    ("host-state", "passwd"), ("host-state", "proc-tree"),
    ("identity", "can-access"), ("identity", "get-user"), ("identity", "list-roles"),
    ("identity", "list-users"),
    # The tacit-knowledge registry lookup (#983). Read-only (`r`) like every pair here: no
    # run-path verb may write the registry.
    ("tacit-knowledge", "lookup"),
    ("threat-intel", "list-indicators"), ("threat-intel", "lookup"),
    ("ticket", "list-tickets"),
)
BENIGN_JUDGE_PAIRS: tuple[tuple[str, str], ...] = (
    ("ticket", "get-ticket"), ("ticket", "key-pattern"), ("ticket", "list-tickets"),
)
# Granted to nobody. `cmdb.list-roles` collides with the granted `identity.list-roles`, so it
# can only be screened as a pair.
UNGRANTED_PAIRS: tuple[tuple[str, str], ...] = (
    ("cmdb", "list-roles"), ("identity", "list-authorized-hosts"),
)
HEALTH_CHECK = "health-check"

# The evidence surface a denial must conserve: the payload tree and the queries table. Not
# `llm_requests.jsonl` or the tool trace, which move on every model call; these two are what an
# implementation that "leaves nothing behind" by deleting evidence would disturb.
EVIDENCE_SURFACE = ("gather_raw", "executed_queries.jsonl")


def evidence_snapshot(run_dir: Path) -> dict[str, bytes]:
    """Every file on the run's evidence surface, relative path -> exact bytes: deleting a file
    and re-creating a shorter one evades a name-set comparison."""
    out: dict[str, bytes] = {}
    for name in EVIDENCE_SURFACE:
        p = run_dir / name
        if p.is_file():
            out[name] = p.read_bytes()
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file():
                    out[str(f.relative_to(run_dir))] = f.read_bytes()
    return out


class WatchingReplay(ReplayFn):
    """A replay model that snapshots the run's evidence surface at every model request, so
    conservation is observed inside one run: the gather leg is called to emit its query and
    again with the tool result, so consecutive snapshots straddle the call under test (two
    runs cannot be compared: artifacts carry timestamps and a run id)."""

    def __init__(self, turns: list[Turn], run_dir: Path):
        super().__init__(turns)
        self.run_dir = run_dir
        self.snapshots: list[dict[str, bytes]] = []

    def __call__(self, messages, info):  # noqa: ANN001 — the framework's callable protocol
        self.snapshots.append(evidence_snapshot(self.run_dir))
        return super().__call__(messages, info)


SYSTEMS: tuple[str, ...] = tuple(sorted(
    {s for s, _ in (*GATHER_PAIRS, *BENIGN_JUDGE_PAIRS, *UNGRANTED_PAIRS)}
))


def grant_of(role: str, pairs, *, verb_class: str = "r") -> VerbGrant:
    """A `VerbGrant` over `pairs`, every entry expecting `verb_class`."""
    return VerbGrant(role=role, entries=tuple((s, v, verb_class) for s, v in pairs))


class ScopedFakeVerbs(VerbRegistry):
    """The injected registry: a real `VerbRegistry` subclass over a plain `{system: {verb: fn}}`
    table, scoped by a real `VerbGrant`. A subclass because the seam is nominally typed (it
    must refuse a duck-typed table); it decides nothing itself: `decide()` is the base class's
    production code, and an undeclared system raises `KeyError`."""

    def __init__(self, table: Mapping[str, Mapping[str, Callable[..., Any]]], grant: VerbGrant,
                 *, call_run: str | None = None):
        super().__init__(grant)
        self._table = {s: dict(v) for s, v in table.items()}
        self.call_run = call_run

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

    def _cold_verb_names(self, system: str) -> frozenset[str]:
        return frozenset(self._table.get(system, {}))

    def verbs(self, system: str) -> Mapping[str, Callable[..., Any]]:
        return self._table[system]


def recording_table(rec: VerbRecorder, systems_verbs: Mapping[str, tuple[str, ...]],
                    *, raises: BaseException | None = None) -> dict:
    """A verb table whose every entry records what it was handed and then returns `PAYLOAD`
    (or raises `raises`). It classifies nothing."""

    def make(verb: str):
        def fn(ctx: VerbContext, *, native_query: str = "FROM logs", **rest: Any):
            rec.record(verb, ctx, {"native_query": native_query, **rest})
            if raises is not None:
                raise raises
            return PAYLOAD
        return fn

    return {s: {v: make(v) for v in verbs} for s, verbs in systems_verbs.items()}


class _Run:
    """One driven replay: the run dir, the two replay models, and every surface a denial
    is asserted against — the evidence table, the payload tree, the breaker, and the
    policy-denial stream."""

    def __init__(self, run_dir: Path, main: ReplayFn, gather: ReplayFn,
                 summary: dict | None = None):
        self.run_dir, self.main, self.gather = run_dir, main, gather
        #: What `drive()` returned: the driver's summary plus `run_state`, the run's one
        #: `RunState` the harness injected (#1235), the only place a driven run's breaker is read.
        self.summary = summary if summary is not None else {}

    @property
    def rows(self) -> list[dict]:
        p = self.run_dir / "executed_queries.jsonl"
        return read_jsonl_rows(p) if p.is_file() else []

    @property
    def own_rows(self) -> list[dict]:
        """`.rows` without the harness-authored leads (`l-000`/`l-00c`, #808): only this test's
        own dispatched lead, not lead-0's unconditional pre-ORIENT resolution."""
        from defender.investigation.lead_zero import RESERVED_LEAD_IDS
        return [r for r in self.rows if r.get("lead_id") not in RESERVED_LEAD_IDS]

    @property
    def own_evidence(self) -> list[dict]:
        """`.own_rows` less the `∅.` sentinels: the rows a call that reached a system wrote (a
        denial writes a `∅.denied` sentinel row, #860). `lead_repository.joined`'s split, by
        the writer's own predicate."""
        from defender.knowledge._query_rules import is_reserved_query_id
        return [r for r in self.own_rows if not is_reserved_query_id(str(r.get("query_id", "")))]

    @property
    def own_denied_rows(self) -> list[dict]:
        """The `∅.denied` sentinel rows this test's lead wrote, one per refused call. Exact id,
        not `is_reserved_query_id`: other sentinels are other refusals (a repeat trip's), which
        must not satisfy "the denial left its row"."""
        from defender.knowledge._query_rules import DENIED_QUERY_ID
        return [r for r in self.own_rows if r.get("query_id") == DENIED_QUERY_ID]

    @property
    def denials(self) -> list[dict]:
        p = RunPaths(self.run_dir).policy_denials
        return read_jsonl_rows(p) if p.is_file() else []

    @property
    def own_denials(self) -> list[dict]:
        """`.denials` without the harness's ancestor-fetch attempt (#808): lead-0 calls
        `elastic.alerts` before MAIN's first turn, so its denial, if any, is always first. A
        denial record carries no `lead_id`, so only a leading `alerts` entry is dropped; a
        test's own later `elastic.alerts` denial is kept."""
        d = self.denials
        if d and d[0].get("verb") == "alerts":
            return d[1:]
        return d

    @property
    def payload_files(self) -> list[Path]:
        """The payloads a query call allocates: `gather_raw/{lead_id}/{seq}.json`. Scoped, not
        globbed: dispatch writes a flat `gather_raw/{lead_id}.lead.json` sidecar before any
        query runs, and a recursive glob would count that run state as query state."""
        root = self.run_dir / "gather_raw" / LEAD
        return sorted(p for p in root.rglob("*.json") if p.is_file()) if root.is_dir() else []

    @property
    def snapshots(self) -> list[dict[str, bytes]]:
        """The evidence-surface snapshots taken at each gather model request, present only
        when the drive asked for them."""
        return getattr(self.gather, "snapshots", [])

    @property
    def gather_saw(self) -> str:
        return self.gather.seen[-1] if self.gather.seen else ""

    @property
    def gather_delta(self) -> str:
        """The model-visible text the drive added past the first request: what the tool calls
        contributed (`seen` entries are cumulative). Absence checks need it, since the ambient
        gather prompt already names the tree, the run and the systems."""
        if not self.gather.seen:
            return ""
        head = self.gather.seen[0]
        assert self.gather.seen[-1].startswith(head), \
            "the flattened history is not append-only — the delta is not the drive's own result"
        return self.gather.seen[-1][len(head):]

    @property
    def breaker(self) -> dict:
        return breaker_doc(self.summary["run_state"])


def breaker_doc(state: Any) -> dict:
    """The run's circuit-breaker state, read off its `RunState` (no file holds it, #1235):
    `{"systems": {}, "total_failures": 0}` before the first failure. The one reader behind
    `.breaker` here and in `e2e/_lead_zero_808.py`; a driven run's state is the summary's
    `run_state`."""
    return state.breaker_snapshot()


def q(system: str, verb: str, params: dict | None = None, query_id: str | None = None) -> Turn:
    """One scripted `query` tool call — the model-facing shape of the tool under test."""
    args: dict = {"system": system, "verb": verb, "params": params or {}}
    if query_id is not None:
        args["query_id"] = query_id
    return Turn(tool_calls=[("query", args)])


DONE = Turn(text="Summary: measured the lead.")


def run_gather(tmp_path: Path, *, verbs, turns: list[Turn], system: str = "elastic",
               run_id: str = "vauth632", watch: bool = False, tenant: Any = None) -> _Run:
    """Drive a real run: main dispatches one gather lead and the nested gather agent replays
    `turns` against the injected scoped registry; everything between the two fakes is
    production code. `watch` snapshots the evidence surface at every gather model request."""
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": system, "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = WatchingReplay(turns, run_dir) if watch else ReplayFn(turns)
    summary = drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs, tenant=tenant)
    return _Run(run_dir, main, gather, summary)


__all__ = [
    "ADAPTERS_DIR",
    "EVIDENCE_SURFACE",
    "WatchingReplay",
    "evidence_snapshot",
    "DENIED",
    "DENY_ALL",
    "DONE",
    "GATHER_PAIRS",
    "GRANTED",
    "GrantError",
    "HEALTH_CHECK",
    "LEAD",
    "PAYLOAD",
    "SYSTEMS",
    "UNDECLARED",
    "UNGRANTED_PAIRS",
    "VERB_CLASSES",
    "ScopedFakeVerbs",
    "VerbGrant",
    "VerbRegistry",
    "breaker_doc",
    "grant_of",
    "q",
    "recording_table",
    "run_gather",
]
