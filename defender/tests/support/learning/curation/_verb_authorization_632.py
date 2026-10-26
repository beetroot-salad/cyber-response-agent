"""#632 — shared machinery for the verb-authorization spec suite. NOT a test module."""
from __future__ import annotations

from defender.run_repository import RunPaths
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.runtime.verb_grant import (  # noqa: E402
    DENY_ALL,
    VERB_CLASSES,
    GrantError,
    VerbGrant,
)
from defender.runtime.verbs import (  # noqa: E402
    DENIED,
    GRANTED,
    UNDECLARED,
    ModuleVerbRegistry,
    VerbContext,
    VerbDecision,
    VerbRegistry,
    read_roster,
)
from defender.kit.verbs import verb_class_of
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

SALT = "aabbccddeeff0011"
LEAD = "l-001"
ADAPTERS_DIR = DEFENDER / "integrations"

PAYLOAD = [
    {"@timestamp": "2026-01-01T00:00:00Z", "user.name": "dev.dana", "event.action": "ssh_login"},
]

# The two shipped grants, as the design's census settled them (c18/g4). Held here as
# literals so `test_the_shipped_grants_name_exactly_the_censused_verbs` compares the
# DEFINITION's grant against an independently written list rather than against itself.
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
    # #983's addition to the census: the tacit-knowledge registry lookup, the one anchor kind a
    # container-root authorization contract can reach. `r` like every pair here, and that class
    # is the whole of mechanism B's provenance argument — no run-path verb may write the file.
    ("tacit-knowledge", "lookup"),
    ("threat-intel", "list-indicators"), ("threat-intel", "lookup"),
    ("ticket", "list-tickets"),
)
BENIGN_JUDGE_PAIRS: tuple[tuple[str, str], ...] = (
    ("ticket", "get-ticket"), ("ticket", "key-pattern"), ("ticket", "list-tickets"),
)
# Granted to nobody: in the registry, exercised by no template and no run (c18). `cmdb`'s
# entry is the collision — `identity.list-roles` above IS granted to gather, so this pair can
# only be screened for as a pair.
UNGRANTED_PAIRS: tuple[tuple[str, str], ...] = (
    ("cmdb", "list-roles"), ("identity", "list-authorized-hosts"),
)
# The four verbs today's committed skill prose advertises with copy-paste call examples,
# one of them as an instruction to use it (g10). The correspondence demand fails on these
# until the change lands.
WITHHELD_FROM_GATHER: tuple[tuple[str, str], ...] = (
    ("ticket", "get-ticket"), ("ticket", "key-pattern"), *UNGRANTED_PAIRS,
)
HEALTH_CHECK = "health-check"
GATHER_ROLE = "gather"

# The store's real list envelope. `list_tickets` answers `{"total", "tickets"}`, so the
# granted-call positive control answers in that shape rather than a lighter fixture of its
# own. (#1221 removed the gather-side ticket screen that once enforced the shape and the
# self-case exclusion that shared this helper; a reply is now served as the store answered.)
def ticket_envelope(*keys: str) -> dict:
    return {"tickets": [{"key": k, "status": "closed"} for k in keys], "total": len(keys)}


# The evidence surface a denial must conserve: the payload tree and the queries table, both
# under the run dir. Scoped deliberately — `llm_requests.jsonl` and the tool trace move on
# every model call, so folding them in would make conservation unassertable, while these two
# are exactly what the run allocated and exactly what an implementation that "leaves nothing
# behind" by DELETING evidence would have to disturb.
EVIDENCE_SURFACE = ("gather_raw", "executed_queries.jsonl")


def evidence_snapshot(run_dir: Path) -> dict[str, bytes]:
    """Every file on the run's evidence surface, relative path -> exact bytes.

    Bytes, not a listing: the exploit this exists to catch deletes a file and re-creates a
    shorter one, which a name-set comparison cannot see."""
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
    """A replay model that snapshots the run's evidence surface at every model request.

    This is how conservation is observed from INSIDE one real run rather than by comparing
    two runs: the gather leg is called once to emit its query and again once the tool result
    comes back, so consecutive snapshots straddle exactly the call under test. Comparing two
    separate runs could not work — the artifacts carry timestamps and a run id."""

    def __init__(self, turns: list[Turn], run_dir: Path):
        super().__init__(turns)
        self.run_dir = run_dir
        self.snapshots: list[dict[str, bytes]] = []

    def __call__(self, messages, info):  # noqa: ANN001 — the framework's callable protocol
        self.snapshots.append(evidence_snapshot(self.run_dir))
        return super().__call__(messages, info)

# One verb name, withheld on one system and granted on another. It is the reason every roster
# assertion in this suite reads pairs: `list-roles` must appear (identity grants it to gather)
# and must not appear (cmdb's is granted to nobody), and no rendering satisfies both halves of
# a name-keyed screen.
COLLIDING_VERB = "list-roles"
GRANTED_COLLIDING_PAIR = ("identity", COLLIDING_VERB)
WITHHELD_COLLIDING_PAIR = ("cmdb", COLLIDING_VERB)

_CALL_ID = re.compile(r"\b([a-z][a-z0-9-]*)\.([a-z][a-z0-9-]*)\b")
_VERB_KWARG = re.compile(r"""verb\s*=\s*["']([a-z][a-z0-9-]*)["']""")

SYSTEMS: tuple[str, ...] = tuple(sorted(
    {s for s, _ in (*GATHER_PAIRS, *BENIGN_JUDGE_PAIRS, *UNGRANTED_PAIRS)}
))


def declared_verbs_everywhere() -> frozenset[str]:
    """Every verb NAME the shipped adapters declare, read cold off the real tree."""
    roster = read_roster(ADAPTERS_DIR)
    return frozenset(v for system in SYSTEMS for v in roster.declared_verbs(system))


def bare_only_surfaces(files, verb_names: frozenset[str]) -> tuple[Path, ...]:
    """The committed files that name a declared verb ONLY as a bare name — no `S.v` call id
    and no `verb='v'` keyword anywhere in them."""
    out = []
    for p in files:
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        qualified = {m.group(2) for m in _CALL_ID.finditer(text)} | set(_VERB_KWARG.findall(text))
        if qualified & verb_names:
            continue  # a pair audit already reaches this file
        if any(re.search(rf"(?<![\w-]){re.escape(v)}(?![\w-])", text) for v in verb_names):
            out.append(p)
    return tuple(sorted(out))


def roster_pairs(text: str) -> set[tuple[str, str]]:
    """Every `(system, verb)` pair a roster text advertises, read off the qualified
    `{system}.{verb}` call ids it renders.

    This is the roster's rendered shape as a contract, not a parsing convenience. A verb name
    on its own does not say what it authorizes, so a roster that renders bare names cannot be
    screened at all — the withheld set and the granted set share a name. Every assertion that
    a verb IS advertised goes through this function too, so a roster which renders nothing
    parseable fails its positive half rather than passing its negative one vacuously."""
    return {(m.group(1), m.group(2)) for m in _CALL_ID.finditer(text)}


def grant_of(role: str, pairs, *, verb_class: str = "r") -> VerbGrant:
    """A `VerbGrant` over `pairs`, every entry expecting `verb_class`."""
    return VerbGrant(role=role, entries=tuple((s, v, verb_class) for s, v in pairs))


def shipped_grants() -> dict[str, VerbGrant]:
    """The run grants the real-tree model-surface audit is handed, keyed by role.

    Gather is the only shipped verb-bearing role since #922 retired the judge and
    its generated guidance, which had advertised ticket verbs after nothing could
    dispatch them. The audit checks the remaining instruction and query surfaces.

    #1106 M4: the grant is a RUN's, projected from its tenant's table — `GATHER_DEF`
    carries none. The shipped one is the committed playground tenant's."""
    from defender.tests.support.tenancy import _tenants1106 as T1106

    return {GATHER_ROLE: T1106.fixture_grants().gather}




class ScopedFakeVerbs(VerbRegistry):
    """The injected registry: a REAL `VerbRegistry` subclass over a plain
    `{system: {verb: fn}}` table, scoped by a real `VerbGrant`.

    It is a subclass and not a duck-typed stand-in on purpose — §7 R15 makes the seam
    nominally typed, so a table that merely answers the registry's questions is exactly
    what the entry point must refuse. It makes no admission decision of its own: an
    undeclared system raises `KeyError`, and `decide()` — the grant decision — is the base
    class's, which is production code."""

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


class RegistryShaped:
    """A registry-SHAPED object that never went through `VerbRegistry.__init__` — the
    duck-typed stand-in §7 R15 requires the seam to reject. It answers every question the
    registry answers, which is precisely why `unconstructable` is hollow without a type."""

    def __init__(self, table: Mapping[str, Mapping[str, Callable[..., Any]]]):
        self._table = {s: dict(v) for s, v in table.items()}

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

    def verbs(self, system: str) -> Mapping[str, Callable[..., Any]]:
        return self._table[system]

    def decide(self, system: str, verb: str) -> Any:  # answers the question, holds no grant
        return VerbDecision(outcome=GRANTED, fn=self._table[system][verb], refusal=None)


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
        """`.rows` filtered to exclude #808's harness-authored leads (`l-000`/`l-00c`) —
        the rows produced by THIS test's own dispatched lead, not lead-0's unconditional
        pre-ORIENT resolution against the run's alert fixture."""
        from defender.runtime.lead_zero import RESERVED_LEAD_IDS
        return [r for r in self.rows if r.get("lead_id") not in RESERVED_LEAD_IDS]

    @property
    def own_evidence(self) -> list[dict]:
        """`.own_rows` less the `∅.` sentinels — the rows a call that REACHED a system wrote,
        which is what "no evidence row" means since #860 made a denial a `∅.denied` sentinel
        row of its own. The split is `lead_repository.joined`'s (`.queries` vs `.sentinels`),
        spelled with the writer's own predicate."""
        from defender.knowledge._query_rules import is_reserved_query_id
        return [r for r in self.own_rows if not is_reserved_query_id(str(r.get("query_id", "")))]

    @property
    def own_denied_rows(self) -> list[dict]:
        """The `∅.denied` sentinel rows THIS test's lead wrote — one per call the grant check
        refused, since #860. Exact-id, not `is_reserved_query_id`: the other sentinels are
        other refusals, and a test asserting "the denial left its row" must not be satisfied
        by a repeat trip's."""
        from defender.knowledge._query_rules import DENIED_QUERY_ID
        return [r for r in self.own_rows if r.get("query_id") == DENIED_QUERY_ID]

    @property
    def denials(self) -> list[dict]:
        p = RunPaths(self.run_dir).policy_denials
        return read_jsonl_rows(p) if p.is_file() else []

    @property
    def own_denials(self) -> list[dict]:
        """`.denials` with #808's harness-authored ancestor-fetch attempt dropped, if it's
        there — item 1 issues its own `elastic.alerts` call synchronously before MAIN's
        first turn, so if that call itself lands as a policy denial (the registry declares
        `alerts` but does not grant it), its record is always the FIRST in the stream. A
        policy-denial record carries no `lead_id` by design (§7 R12), so unlike `own_rows`
        this can't filter by id — it can only rely on lead-0's fixed position. Only the
        LEADING entry is ever dropped, and only when it is `alerts`: a test that later
        scripts its own genuine `elastic.alerts` denial (as part of its own turns, after
        lead-0's own attempt) keeps that record."""
        d = self.denials
        if d and d[0].get("verb") == "alerts":
            return d[1:]
        return d

    @property
    def payload_files(self) -> list[Path]:
        """The payloads a QUERY CALL allocates: `gather_raw/{lead_id}/{seq}.json`, inside the
        lead-scoped subdirectory and nowhere else.

        Scoped, not globbed. Dispatch writes one flat `gather_raw/{lead_id}.lead.json`
        sidecar at the ROOT of this tree before any query runs, consumes no sequence number
        and does not create the lead-scoped subdirectory at all — so a recursive glob of the
        whole tree conflates run state with query state and demands an empty tree no correct
        implementation can produce. The two never share a directory level; that measured
        disjointness is what makes this property assertable."""
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
        """The model-visible text the drive ADDED past the first request — the channel a tool
        result or a refusal comes back on.

        `seen` entries are cumulative flattened histories, so this delta is exactly what the
        tool calls contributed. Assertions that something is ABSENT need it: the ambient
        gather prompt names the tree, the run and the systems, so `not in seen[-1]` can fail
        for reasons that have nothing to do with the tool result under test."""
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
    """The run's circuit-breaker state, read off the run's `RunState` (#1235 round 2: nothing
    writes `circuit_breaker.json`, and no process-wide table keyed by the folder holds it) —
    `{"systems": {}, "total_failures": 0}` before the first recorded failure. THE reader, which
    the harness result classes here and in `e2e/_lead_zero_808.py` expose as `.breaker`; a
    driven run's state is the driver summary's `run_state`."""
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
    """Drive a REAL run: main dispatches one gather lead, the nested gather agent replays
    `turns` against the INJECTED scoped registry. Everything between the two fakes —
    dispatch, the query tool, the grant decision, the capture capability, the breaker, the
    two tables and the policy-denial stream — is production code.

    `watch` snapshots the evidence surface at every gather model request, which is what the
    conservation half of the denial demand reads."""
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
    "COLLIDING_VERB",
    "EVIDENCE_SURFACE",
    "GATHER_ROLE",
    "WatchingReplay",
    "evidence_snapshot",
    "shipped_grants",
    "ticket_envelope",
    "DENIED",
    "DENY_ALL",
    "DONE",
    "GATHER_PAIRS",
    "GRANTED",
    "GRANTED_COLLIDING_PAIR",
    "GrantError",
    "HEALTH_CHECK",
    "LEAD",
    "PAYLOAD",
    "SALT",
    "SYSTEMS",
    "UNDECLARED",
    "UNGRANTED_PAIRS",
    "VERB_CLASSES",
    "WITHHELD_COLLIDING_PAIR",
    "WITHHELD_FROM_GATHER",
    "ModuleVerbRegistry",
    "RegistryShaped",
    "ScopedFakeVerbs",
    "VerbContext",
    "VerbDecision",
    "VerbGrant",
    "VerbRegistry",
    "bare_only_surfaces",
    "breaker_doc",
    "declared_verbs_everywhere",
    "grant_of",
    "q",
    "recording_table",
    "roster_pairs",
    "run_gather",
    "verb_class_of",
]
