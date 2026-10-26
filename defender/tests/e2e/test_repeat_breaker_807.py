"""#807 ask (1) — the executable spec for gather's REPEAT CIRCUIT BREAKER."""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import append_jsonl, read_jsonl_rows  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.learning import lead_repository  # noqa: E402
from defender.learning.leads import lead_extraction  # noqa: E402
from defender.runtime import circuit_breaker  # noqa: E402
from defender.runtime.lead_zero import RESERVED_LEAD_IDS  # noqa: E402
from defender.knowledge._query_rules import _json_safe_params  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry, VerbContext, VerbRegistry  # noqa: E402
from defender.kit.faults import TransportFault, UpstreamFault  # noqa: E402
from defender.knowledge import _query_rules  # noqa: E402
from defender.runtime import record_query  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import (  # noqa: E402
    DONE,
    PAYLOAD,
    ROW_KEYS,
    elastic_ok,
    q,
    raising,
)

# THE SURFACE UNDER TEST — none of it exists on this base (RED by construction)
from defender.runtime.record_query import (
    REJECTION_BUDGET,
    REPEAT_ESCAPE,
    REPEAT_THRESHOLD,
    RepeatTrip,
    in_rejection_domain,
    rejection_budget_trip,
    rejection_trip,
    repeat_trip,
)
from defender.runtime.verbs import read_roster  # noqa: E402
from defender.tests.support.shared.contracts._after_start_1256 import AfterStart, Relink  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "aabbccddeeff0011"
LEAD = "l-001"
SIBLING = "l-002"

CORPUS = DEFENDER / "tests" / "fixtures" / "e2e" / "repeat-corpus-807"

# The idiom `_run_gather`'s three shipped terminal branches already use, and the ONLY
# vocabulary any prompt in the corpus teaches main (defender/SKILL.md:394 — G19).
INCOMPLETE_IDIOM = "Treat this lead as incomplete and reason from what was captured."

SUMMARY_TURN = Turn(text="Before the stop I ran what I could; the answers are above.")


def _file_rows(run_dir: Path, lead: str) -> list[dict]:
    """This lead's rows as the FILE holds them, in file order (the post-run record)."""
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead]


class _Res:
    """One driven replay: the run dir, the two replay models, the tables on disk and the
    result `drive()` returned, whose `run_state` is the run's own state (#1235)."""

    def __init__(self, run_dir: Path, main: ReplayFn, gather: ReplayFn, summary: dict):
        self.run_dir, self.main, self.gather, self.summary_dict = run_dir, main, gather, summary

    @property
    def state(self):  # noqa: ANN201 — `RunState`, imported nowhere at module top (#1235)
        """The run's `RunState`, as `drive()` returned it."""
        return self.summary_dict["run_state"]

    @property
    def rows(self) -> list[dict]:
        return read_jsonl_rows(RunPaths(self.run_dir).executed_queries)

    @property
    def own_rows(self) -> list[dict]:
        """.rows filtered to exclude #808's harness-authored leads (l-000/l-00c)."""
        return [r for r in self.rows if r.get("lead_id") not in RESERVED_LEAD_IDS]

    def rows_for(self, lead: str) -> list[dict]:
        return [r for r in self.rows if r.get("lead_id") == lead]

    def summary(self, lead: str = LEAD) -> str:
        """The string `_run_gather` returned for `lead` — byte-identical to what main got,
        because `_persist_gather_summary` writes the very object the function returns."""
        return (self.run_dir / "gather_summaries" / f"{lead}.md").read_text(encoding="utf-8")

    @property
    def main_saw(self) -> str:
        return self.main.seen[-1]

    @property
    def gather_saw(self) -> str:
        return self.gather.seen[-1]

    @property
    def breaker(self) -> dict:
        """The run's infra-breaker state, off the run's own state (#1235: never a file in the
        run dir; `_BLANK_BREAKER` when nothing failed)."""
        return self.state.breaker_snapshot()

    @property
    def denials(self) -> list[dict]:
        return read_jsonl_rows(RunPaths(self.run_dir).policy_denials)


#: The breaker state of a run in which nothing failed (`breaker_snapshot()`'s blank shape).
_BLANK_BREAKER = {"systems": {}, "total_failures": 0}


def _dispatch(lead: str, system: str) -> tuple[str, dict]:
    return ("gather", {
        "lead_id": lead, "system": system, "goal": "measure this lead",
        "what_to_summarize": ["auth events"],
    })


def _run(
    root: Path, *, verbs, turns: list[Turn], run_id: str, system: str = "elastic",
    lead: str = LEAD, planted: list[dict] | None = None, tenant: Any = None,
) -> _Res:
    """Drive a REAL run: main dispatches one gather lead, the nested gather agent replays
    `turns` against the INJECTED verb registry. Everything between the two fakes — dispatch,
    the query tool, the repeat guard, the capture capability, the infra breaker, the two"""
    run_dir = materialize(root, GOLDEN_AB3, run_id=run_id)
    if planted:
        _seed(run_dir, planted)
    main = ReplayFn([Turn(tool_calls=[_dispatch(lead, system)]),
                     Turn(text="Investigation complete.")])
    gather = ReplayFn(turns)
    summary = drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs, tenant=tenant)
    return _Res(run_dir, main, gather, summary)


#: The planted source's run folder name (`_branch_947.planted_source`'s `name=`), so the table
#: can be written into it before the source is built.
SOURCE_RUN = fixture_uuid("run-source-001")


def _run_inherited(
    root: Path, *, table: bytes, rows: list[dict], verbs, turns: list[Turn], run_id: str,
    system: str = "elastic", lead: str = LEAD,
) -> _Res:
    """Drive a REAL branch sibling (`drive(..., resume=spec)`) whose source's queries table is
    `table` — the shape a resumed lead's run starts from. The source is
    `_branch_947.planted_source` (a store, a case link, the golden document; not the N4
    fixture — the implementer's fixture-only snapshot planting may snapshot it), which carries no
    claim for its leads, so the sibling's MAIN can dispatch `lead` again; seeding copies the
    table's rows for the inherited leads, and each `rows` entry's sidecar, into the sibling and
    records them on the sibling's state (#1235 round 2) before its first turn."""
    from defender.tests.support.learning.branch._branch_947 import (
        GOLDEN_INVESTIGATION, LEGACY_BRANCH_CALL, planted_source, spec_at,
    )
    from defender.tests.support.storage._session_store_705 import runs_base

    source = runs_base(root) / SOURCE_RUN
    RunPaths(source).executed_queries.parent.mkdir(parents=True, exist_ok=True)
    RunPaths(source).executed_queries.write_bytes(table)
    for row in rows:
        rel = row.get("payload_path")
        if rel:
            (source / rel).parent.mkdir(parents=True, exist_ok=True)
            (source / rel).write_text("" if row.get("exit_code") else "[]", encoding="utf-8")
    store, planted, _session, path_ids = planted_source(
        root, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"), queries=None,
        name=SOURCE_RUN)
    assert planted == source, (planted, source)
    # #1255 (D1): a tool-calling MAIN response after the document landed, not the RETURN the
    # pre-#1255 shape branched at. The source is hand-planted (`planted_source`, not N4's).
    spec = spec_at(store, source, path_ids[LEGACY_BRANCH_CALL])
    store.close()
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    sibling = root / "defender-runs" / fixture_uuid("run-sibling-807")
    RunPaths(sibling).gather_raw.mkdir(parents=True)
    from defender.tests.support.storage._alert_plant import plant_alert
    plant_alert(sibling, RunPaths(source).alert.read_bytes())
    main = ReplayFn([Turn(tool_calls=[_dispatch(lead, system)]),
                     Turn(text="Investigation complete.")])
    gather = ReplayFn(turns)
    summary = drive(sibling, run_id=run_id, main=main, gather=gather, verbs=verbs, resume=spec)
    assert summary.get("truncated_by") is None, f"the sibling did not run to its end: {summary}"
    return _Res(sibling, main, gather, summary)


def _jsonl(rows: list[dict]) -> bytes:
    import json

    return "".join(json.dumps(r) + "\n" for r in rows).encode("utf-8")


def _run_two_leads(
    root: Path, *, verbs, turns: list[Turn], run_id: str,
    first: tuple[str, str] = (LEAD, "elastic"), second: tuple[str, str] = (SIBLING, "elastic"),
) -> _Res:
    """Two leads dispatched SERIALLY (one gather tool call per main turn), so one shared
    gather replay script serves them in order: the first lead consumes turns until it stops,
    the second picks up at the next turn."""
    run_dir = materialize(root, GOLDEN_AB3, run_id=run_id)
    main = ReplayFn([
        Turn(tool_calls=[_dispatch(*first)]),
        Turn(tool_calls=[_dispatch(*second)]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(turns)
    summary = drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs)
    return _Res(run_dir, main, gather, summary)


@pytest.fixture(scope="module")
def three_identical_requests(tmp_path_factory, checkout_roster):
    """ONE driven run of the canonical trip — one lead asking elastic the same query three
    times, then `DONE` — shared by the demands that only READ it: its run dir and tables, the
    verb recorder, and the two replay scripts. A demand that seeds, plants or needs a second"""
    from defender.skills.invlang.validate import hold_capabilities, release_capabilities

    rec = VerbRecorder()
    hold_capabilities(checkout_roster)
    try:
        r = _run(tmp_path_factory.mktemp("repeat-trip"), verbs=elastic_ok(rec),
                 run_id="d807-trip", turns=[
                     q("elastic", "query", {"native_query": "FROM logs"}),
                     q("elastic", "query", {"native_query": "FROM logs"}),
                     q("elastic", "query", {"native_query": "FROM logs"}),
                     DONE,
                 ])
    finally:
        release_capabilities()
    return r, rec


_SEEDED_PAYLOAD = "abcdefghijkl"


def _row(
    lead: str, seq: int, system: str, verb: str, params: dict, *,
    exit_code: int = 0, query_id: str | None = None, digest: str | None = None,
) -> dict:
    """One queries-table row in the frozen key shape, with `error_class`, `payload_digest` and
    `payload_sha256` computed by the PRODUCTION helpers rather than restated — a seeded fixture
    that disagrees with `error_class_for_exit`, or one whose recorded hash does not belong to"""
    payload_text = "" if exit_code != 0 else _SEEDED_PAYLOAD
    return {
        "lead_id": lead,
        "seq": seq,
        "system": system,
        "verb": verb,
        "query_id": query_id if query_id is not None else f"{system}.{verb}",
        "params": params,
        "raw_command": " ".join([system, verb, *(f"{k}={v}" for k, v in params.items())]),
        "payload_path": f"gather_raw/{lead}/{seq}.json",
        "exit_code": exit_code,
        "error_class": circuit_breaker.error_class_for_exit(exit_code),
        "payload_status": "error" if exit_code != 0 else "ok",
        "payload_digest": digest if digest is not None else (
            f"exit={exit_code}; seeded" if exit_code != 0
            else record_query.payload_digest(payload_text, "", 0)
        ),
        "payload_sha256": record_query.payload_sha256(payload_text),
        "system_key": "",
    }


def _seed(run_dir: Path, rows: list[dict]) -> None:
    """Plant a queries table (and each row's sidecar) in a fresh run folder BEFORE the run
    starts. No host recorded these rows for the run, and since #1235 round 2 no file is ever
    read into a run's state: they are on disk and nowhere else."""
    for row in rows:
        rel = row.get("payload_path")
        if not rel:
            continue
        p = run_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("" if row.get("exit_code") else "[]", encoding="utf-8")
    append_jsonl(RunPaths(run_dir).executed_queries, rows)


def _corpus(run_name: str) -> list[dict]:
    return read_jsonl_rows(CORPUS / run_name / "executed_queries.jsonl")


def _replay(rows: list[dict], *, threshold: int = REPEAT_THRESHOLD) -> list[tuple[str, int]]:
    """O1's stated oracle, driving the PRODUCTION predicate: accumulate each lead's rows in
    file order and STOP accumulating for a lead at its first trip, because M3's trip
    terminates the lead ("must stop at seq 4 rather than 36" — the doc's own words). A replay"""
    seen: dict[str, list[dict]] = {}
    stopped: set[str] = set()
    trips: list[tuple[str, int]] = []
    for row in rows:
        lead = row.get("lead_id")
        if not isinstance(lead, str) or lead in stopped:
            continue
        prior = seen.setdefault(lead, [])
        hit = repeat_trip(
            prior, lead, system=row.get("system"), verb=row.get("verb"),
            params=row.get("params"), threshold=threshold,
        )
        if hit is not None:
            trips.append((lead, row.get("seq")))
            stopped.add(lead)
            continue
        prior.append(row)
    return trips


def _replay_rejections(
    rows: list[dict], *, threshold: int = REPEAT_THRESHOLD, budget: int = REJECTION_BUDGET,
) -> list[tuple[str, int, str]]:
    """The same oracle for the COMPANION guard (#826 item 4), differing from `_replay` only in
    the production predicate it drives — which is the claim under test: the two guards are one
    counting rule over two disjoint domains, so one replay shape serves both."""
    seen: dict[str, list[dict]] = {}
    stopped: set[str] = set()
    trips: list[tuple[str, int, str]] = []
    for row in rows:
        lead = row.get("lead_id")
        if not isinstance(lead, str) or lead in stopped:
            continue
        prior = seen.setdefault(lead, [])
        guarded = in_rejection_domain(row)
        kind: str | None = None
        if guarded:
            if rejection_trip(
                prior, lead, system=row.get("system"), verb=row.get("verb"),
                params=row.get("params"), threshold=threshold,
                system_key=row.get("system_key"),
            ) is not None:
                kind = "repeat"
            elif rejection_budget_trip(prior, lead, budget=budget) is not None:
                kind = "budget"
        prior.append(row)
        if kind is not None:
            trips.append((lead, row.get("seq"), kind))
            stopped.add(lead)
    return trips


def named_verbs(rec: VerbRecorder, *, system: str = "elastic", verb: str = "sshd-auth-window") -> FakeVerbs:
    """The happy-path registry under a DISTINCTIVE (system, verb) pair, so an assertion that
    the dead-end message names the repeated request cannot pass on a generic word."""

    def probe(ctx: VerbContext, *, native_query: str, limit: int = 10) -> list[dict]:
        rec.record(verb, ctx, {"native_query": native_query, "limit": limit})
        return PAYLOAD

    return FakeVerbs({system: {verb: probe}})


def two_systems(rec: VerbRecorder) -> FakeVerbs:
    """Two systems, two differently-shaped verbs — the registry the escape's
    system-agnosticism is measured against."""

    def sshd(ctx: VerbContext, *, native_query: str) -> list[dict]:
        rec.record("elastic.sshd-auth-window", ctx, {"native_query": native_query})
        return PAYLOAD

    def trust(ctx: VerbContext, *, host: str) -> list[dict]:
        rec.record("cmdb.host-trust-edges", ctx, {"host": host})
        return PAYLOAD

    return FakeVerbs({"elastic": {"sshd-auth-window": sshd}, "cmdb": {"host-trust-edges": trust}})


def nested_params(rec: VerbRecorder) -> FakeVerbs:
    """A verb whose params carry a NESTED mapping, so key-order normalisation can be observed
    at a nesting level `sort_keys=True` has to reach rather than at the top level only."""

    def probe(ctx: VerbContext, *, filt: dict, tag: str = "t") -> list[dict]:
        rec.record("probe", ctx, {"filt": filt, "tag": tag})
        return PAYLOAD

    return FakeVerbs({"elastic": {"probe": probe}})


def typed_params(rec: VerbRecorder) -> FakeVerbs:
    """A verb declaring a `str` and a `float` param — the two axes the canonicalizer must NOT
    fold (case/Unicode on the string, int-vs-float on the number)."""

    def probe(ctx: VerbContext, *, native_query: str, threshold: float = 1.0) -> list[dict]:
        rec.record("probe", ctx, {"native_query": native_query, "threshold": threshold})
        return PAYLOAD

    return FakeVerbs({"elastic": {"probe": probe}})


def parameterless(rec: VerbRecorder) -> FakeVerbs:
    """The shape 8 of GATHER_DEF's 28 granted pairs really have (P-e, executed: all seven
    `health-check` verbs plus `identity.list-roles`) — a verb declaring NO params at all, so
    `{}` is the only call it can ever receive."""

    def health_check(ctx: VerbContext) -> dict:
        rec.record("health-check", ctx, {})
        return {"status": "ok"}

    return FakeVerbs({"elastic": {"health-check": health_check}})


class GrantScopedVerbs(VerbRegistry):
    """A real registry over a real `VerbGrant` that DECLARES a verb it does not GRANT — the
    only way to reach `decide`'s DENIED outcome (a withheld real verb) rather than its
    UNDECLARED one. Dumb data: it injects no fault and makes no admission decision of its"""

    def __init__(self, table: dict[str, dict], grant: VerbGrant):
        super().__init__(grant)
        self._table = {s: dict(v) for s, v in table.items()}

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

    def _cold_verb_names(self, system: str) -> frozenset[str]:
        return frozenset(self._table.get(system, {}))

    def verbs(self, system: str):
        return self._table[system]


def granted_and_withheld(rec: VerbRecorder) -> GrantScopedVerbs:
    def probe(ctx: VerbContext, *, native_query: str) -> list[dict]:
        rec.record("probe", ctx, {"native_query": native_query})
        return PAYLOAD

    def withheld(ctx: VerbContext, *, native_query: str) -> list[dict]:  # pragma: no cover
        rec.record("withheld", ctx, {"native_query": native_query})
        return PAYLOAD

    return GrantScopedVerbs(
        {"elastic": {"probe": probe, "withheld": withheld}},
        VerbGrant(role="gather", entries=(("elastic", "probe", "r"),)),
    )


_BROKEN_ADAPTER = (
    'raise RuntimeError("elastic adapter cannot be imported")\n'
    "\n"
    "def probe(ctx, *, native_query: str) -> list:\n"
    "    return []\n"
    "\n"
    'VERBS = {"probe": probe}\n'
)


_LOADABLE_ADAPTER = (
    "def check_settings(*_a, **_k):\n"
    "    return None\n"
    "\n"
    "def probe(ctx, *, native_query: str) -> list:\n"
    "    return [{'probed': native_query}]\n"
    "\n"
    'VERBS = {"probe": probe}\n'
)


def unloadable_adapter(root: Path) -> tuple[ModuleVerbRegistry, Relink]:
    """The REAL production registry over a REAL adapter module, and the `Relink` that makes it
    one that raises at import — a level-1 fault, not a stand-in for one."""
    adapters = root / "adapters"
    adapters.mkdir(parents=True)
    (adapters / "elastic_adapter.py").write_text(_LOADABLE_ADAPTER, encoding="utf-8")
    registry = ModuleVerbRegistry(read_roster(adapters),
                                  VerbGrant(role="gather", entries=(("elastic", "probe", "r"),)))
    return registry, Relink(adapters / "elastic_adapter.py", _BROKEN_ADAPTER)


def _after_start(relink: Relink, turns: list[Turn]) -> list:
    """`turns`, its first one breaking the adapter when the gather model asks for it."""
    return [AfterStart(turns[0], relink.break_), *turns[1:]]


def _bad_args(params: dict) -> Turn:
    """A tool call the pydantic ARG SCHEMA turns back, so the row is written by
    `wrap_tool_validate` from the RAW pre-validation arguments. `bogus_extra_arg` is P-a's
    executed `extra_argument` shape: the rejection row it leaves recovers a perfectly normal"""
    return Turn(tool_calls=[("query", {
        "system": "elastic", "verb": "query", "params": params, "bogus_extra_arg": "x",
    })])


def test_repeat_trip_predicate_seam(tmp_path):
    assert REPEAT_THRESHOLD == 3, "C11's fitted floor did not ship as the module constant"

    key = {"system": "elastic", "verb": "query", "params": {"native_query": "FROM logs"}}
    rows = [_row(LEAD, 0, "elastic", "query", {"native_query": "FROM logs"})]

    assert repeat_trip([], LEAD, **key) is None, "an empty table is zero prior occurrences"
    assert repeat_trip(rows, LEAD, **key) is None, "the second occurrence is not yet a trip"

    rows.append(_row(LEAD, 1, "elastic", "query", {"native_query": "FROM logs"}))
    hit = repeat_trip(rows, LEAD, **key)
    assert isinstance(hit, RepeatTrip)
    assert hit.occurrence == REPEAT_THRESHOLD
    assert hit.first_seq == 0

    assert repeat_trip(rows[:1], LEAD, threshold=2, **key) is not None, \
        "the threshold must be a parameter the replay oracle can sweep"

    other = {"system": "cmdb", "verb": "host-trust-edges", "params": {"host": "db-1"}}
    other_rows = [_row(LEAD, s, "cmdb", "host-trust-edges", {"host": "db-1"}) for s in (0, 1)]
    assert repeat_trip(other_rows[:1], LEAD, **other) is None, \
        "a second system trips EARLIER than N — the threshold is per-system"
    assert repeat_trip(other_rows, LEAD, **other) is not None, \
        "a second system trips LATER than N — the threshold is per-system"

    # The seam's whole purpose: it eats rows read straight off a RECORDED table.
    recorded = [r for r in _corpus("reviewer-measure-0807-b") if r["lead_id"] == LEAD]
    assert recorded, "the recorded corpus fixture is missing its repeat lead"
    assert repeat_trip(
        recorded[:4], LEAD, system=recorded[4]["system"], verb=recorded[4]["verb"],
        params=recorded[4]["params"],
    ) is not None, "the production predicate could not be driven over a recorded run"


def test_repeat_trips_on_third_identical_request(three_identical_requests):
    r, rec = three_identical_requests
    assert len(rec.calls) == 2, "calls 1 and 2 must execute; call 3 must not"
    rows = r.own_rows
    assert len(rows) == 3
    assert [row["exit_code"] for row in rows] == [0, 0, 64]
    assert INCOMPLETE_IDIOM in r.summary()


def test_repeat_key_is_lead_scoped(tmp_path):
    rec = VerbRecorder()
    foreign = [
        _row(SIBLING, 0, "elastic", "query", {"native_query": "FROM logs"}),
        _row(SIBLING, 1, "elastic", "query", {"native_query": "FROM logs"}),
    ]
    scoped = _run_inherited(
        tmp_path / "scoped", table=_jsonl(foreign), rows=foreign, verbs=elastic_ok(rec),
        run_id="d807-scope", turns=[
            q("elastic", "query", {"native_query": "FROM logs"}),
            q("elastic", "query", {"native_query": "FROM logs"}),
            DONE,
        ])
    assert len(rec.calls) == 2, "a sibling lead's rows were counted toward this lead's budget"
    assert INCOMPLETE_IDIOM not in scoped.summary()

    own = VerbRecorder()
    mine = [
        _row(LEAD, 0, "elastic", "query", {"native_query": "FROM logs"}),
        _row(LEAD, 1, "elastic", "query", {"native_query": "FROM logs"}),
    ]
    control = _run_inherited(
        tmp_path / "own", table=_jsonl(mine), rows=mine, verbs=elastic_ok(own),
        run_id="d807-scope-ctl", turns=[q("elastic", "query", {"native_query": "FROM logs"}), DONE])
    assert own.calls == [], "the control could not see a difference: this lead's own rows must count"
    assert INCOMPLETE_IDIOM in control.summary()


def test_repeat_key_ignores_query_id(tmp_path):
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-qid", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}, query_id="elastic.db-1-sshd-a"),
        q("elastic", "query", {"native_query": "FROM logs"}, query_id="elastic.db-1-sshd-b"),
        q("elastic", "query", {"native_query": "FROM logs"}, query_id="elastic.db-1-sshd-c"),
        DONE,
    ])
    assert len(rec.calls) == 2
    rows = r.own_rows
    assert [row["query_id"] for row in rows[:2]] == ["elastic.db-1-sshd-a", "elastic.db-1-sshd-b"]
    assert rows[2]["exit_code"] == 64, "three coined ids for one request did not trip"
    assert INCOMPLETE_IDIOM in r.summary()


def test_repeat_trip_never_reaches_the_backend(three_identical_requests):
    r, rec = three_identical_requests
    assert len(rec.calls) == 2, "the refused call reached the backend"
    assert rec.verbs == ["query", "query"]
    assert r.own_rows[2]["exit_code"] == 64
    assert r.own_rows[2]["payload_status"] == "error", "a refused call recorded a payload"
    assert (r.run_dir / r.own_rows[2]["payload_path"]).read_text(encoding="utf-8") == "", \
        "the refused call's sidecar holds a backend answer"


def test_repeat_trip_sits_after_grant_and_infra_breaker(tmp_path):
    denied_rec = VerbRecorder()
    denied = _run(
        tmp_path / "denied", verbs=granted_and_withheld(denied_rec), run_id="d807-denied", turns=[
            q("elastic", "withheld", {"native_query": "FROM logs"}),
            q("elastic", "withheld", {"native_query": "FROM logs"}),
            q("elastic", "withheld", {"native_query": "FROM logs"}),
            DONE,
        ])
    assert denied_rec.calls == []
    assert [row["query_id"] for row in denied.own_rows] == [_query_rules.DENIED_QUERY_ID] * 3, \
        "a DENIED call wrote an evidence row, or not its sentinel"
    assert len(denied.denials) == 3, "the denial record is the DENIED path's audit artifact"
    assert denied.gather.calls == 4, "a denied repeat tripped the guard — it is answered above M2"
    assert INCOMPLETE_IDIOM not in denied.summary()

    down_rec = VerbRecorder()
    down = _run(
        tmp_path / "down", verbs=raising(down_rec, TransportFault("connection refused")),
        run_id="d807-down", turns=[
            q("elastic", "probe", {}), q("elastic", "probe", {}), q("elastic", "probe", {}), DONE,
        ])
    assert len(down_rec.calls) == 2, "the tripped system was queried again"
    assert len(down.own_rows) == 2, "the down-message call recorded a row"
    assert "is DOWN" in down.gather_saw
    assert down.gather.calls == 4, "the infra breaker's answer was replaced by a dead end"


def test_repeat_trip_row_is_agent_fixable(three_identical_requests):
    r, rec = three_identical_requests
    trip = r.own_rows[2]
    assert trip["exit_code"] != 0, "no trip happened, so the negative is vacuous"
    assert trip["exit_code"] == 64
    assert trip["error_class"] == "agent-fixable"
    assert trip["error_class"] == circuit_breaker.error_class_for_exit(trip["exit_code"])
    assert trip["system"] == "elastic"
    assert trip["verb"] == "query"


def test_repeat_trip_leaves_the_infra_breaker_untouched(tmp_path, three_identical_requests):
    r, rec = three_identical_requests
    assert r.own_rows[2]["exit_code"] == 64, "no trip happened, so the negative is vacuous"
    assert r.breaker == _BLANK_BREAKER, "the repeat trip recorded infra-breaker state"
    assert not (r.run_dir / "circuit_breaker.json").exists(), \
        "a breaker file was written into the run dir (#1235: the breaker is in memory only)"
    assert circuit_breaker.is_tripped(r.state, "elastic") is False

    prior_rec = VerbRecorder()

    def cmdb_probe(ctx: VerbContext, *, native_query: str = "FROM hosts") -> list[dict]:
        raise TransportFault("cmdb unreachable")

    def elastic_query(ctx: VerbContext, *, native_query: str, limit: int = 10) -> list[dict]:
        prior_rec.record("query", ctx, {"native_query": native_query, "limit": limit})
        return PAYLOAD

    prior = _run_two_leads(
        tmp_path / "prior", run_id="d807-breaker-prior",
        verbs=FakeVerbs({"cmdb": {"probe": cmdb_probe}, "elastic": {"query": elastic_query}}),
        first=(SIBLING, "cmdb"), second=(LEAD, "elastic"), turns=[
            q("cmdb", "probe", {"native_query": "FROM hosts-1"}),
            q("cmdb", "probe", {"native_query": "FROM hosts-2"}),
            SUMMARY_TURN,
            q("elastic", "query", {"native_query": "FROM logs"}),
            q("elastic", "query", {"native_query": "FROM logs"}),
            q("elastic", "query", {"native_query": "FROM logs"}),
            DONE,
        ])
    assert len(prior_rec.calls) == 2, "the elastic lead never reached its trip"
    assert prior.rows_for(LEAD)[2]["exit_code"] == 64, "no trip happened, so the negative is vacuous"
    assert INCOMPLETE_IDIOM in prior.summary()
    assert circuit_breaker.is_tripped(prior.state, "cmdb") is True, \
        "the repeat trip cleared an unrelated system's earlier infra trip"
    assert prior.breaker["systems"]["cmdb"]["failures"] == 2, \
        "the repeat trip moved an unrelated system's failure count"
    assert "tripped_at" in prior.breaker["systems"]["cmdb"], \
        "the repeat trip rewrote the earlier trip's stamp away"
    assert prior.breaker["total_failures"] == 2, \
        "the repeat trip counted toward the run-level kill limit"
    assert "elastic" not in prior.breaker["systems"], \
        "the repeat trip opened breaker state for its own system"

    ctl_rec = VerbRecorder()
    ctl = _run(
        tmp_path / "infra", verbs=raising(ctl_rec, TransportFault("connection refused")),
        run_id="d807-breaker-ctl", turns=[q("elastic", "probe", {}), DONE])
    assert ctl.breaker["systems"]["elastic"]["failures"] == 1, \
        "the control could not see a breaker write at all"


def test_trip_row_conforms_to_the_frozen_row_contract(three_identical_requests):
    r, rec = three_identical_requests
    trip = r.own_rows[2]
    assert trip["exit_code"] == 64, "row 2 must be the trip itself, not an ordinary third success"
    assert set(trip) == ROW_KEYS
    assert trip["lead_id"] == LEAD
    assert trip["seq"] == 2
    assert trip["params"] == {"native_query": "FROM logs"}
    assert trip["payload_path"] == f"gather_raw/{LEAD}/2.json"


def test_dead_end_return_contract(tmp_path):
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=named_verbs(rec), run_id="d807-return", turns=[
        q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
        q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
        q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
        DONE,
    ])
    summary = r.summary()

    assert f"gather for {LEAD}" in summary
    assert INCOMPLETE_IDIOM in summary
    assert re.match(r"<run-[0-9a-f]+-untrusted>", summary), "the summary was not framed"
    salt = re.match(r"<run-([0-9a-f]+)-untrusted>", summary).group(1)
    assert summary.endswith(f"</run-{salt}-untrusted>"), "the frame never closed on its own salt"
    assert "sshd-auth-window" in summary, "the message does not name the repeated request"
    assert REPEAT_ESCAPE in summary, "the escape never reached the string main receives"
    assert summary in r.main_saw, \
        "the persisted account and the string main received are not the same object"


def test_dead_end_is_contained_to_the_lead(tmp_path):
    rec = VerbRecorder()
    r = _run_two_leads(tmp_path, verbs=elastic_ok(rec), run_id="d807-contained", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        SUMMARY_TURN,                                       # the stopped lead's summary (#987)
        q("elastic", "query", {"native_query": "FROM other"}),
        DONE,
    ])
    assert r.main.calls == 3, "main never took its turns after the dead end — the run unwound"
    assert INCOMPLETE_IDIOM in r.summary(LEAD)
    assert INCOMPLETE_IDIOM not in r.summary(SIBLING), "the sibling lead was collateral damage"
    assert len(rec.calls) == 3, "the sibling lead's own query never ran"


def test_repeat_key_normalizes_param_key_order(tmp_path):
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=nested_params(rec), run_id="d807-order", turns=[
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {
            "filt": {"host": "db-1", "user": "dana"}, "tag": "t"}})]),
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {
            "tag": "t", "filt": {"host": "db-1", "user": "dana"}}})]),
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {
            "filt": {"user": "dana", "host": "db-1"}, "tag": "t"}})]),
        DONE,
    ])
    assert len(rec.calls) == 2, "key order alone made two calls read as different requests"
    assert r.own_rows[2]["exit_code"] == 64
    assert INCOMPLETE_IDIOM in r.summary()


def test_repeat_key_separates_requests_that_differ_by_a_byte(tmp_path):
    base = {"native_query": unicodedata.normalize("NFC", "FROM café"), "threshold": 1.0}
    variants = [
        ("case", {**base, "native_query": "from café"}),
        ("unicode", {**base, "native_query": unicodedata.normalize("NFD", "FROM café")}),
        ("int-vs-float", {**base, "threshold": 1}),
        # the verb's own default for `threshold` IS 1.0, so this call is SEMANTICALLY the base
        # call — the canonicalizer carries no per-verb knowledge of defaults, so it is two keys.
        ("semantic-default", {"native_query": base["native_query"]}),
    ]
    rows = [
        _row(LEAD, 0, "elastic", "probe", base),
        _row(LEAD, 1, "elastic", "probe", base),
    ]
    for label, params in variants:
        assert repeat_trip(rows, LEAD, system="elastic", verb="probe", params=params) is None, \
            f"{label}: two byte-different requests were folded onto one key"
    assert repeat_trip(rows, LEAD, system="elastic", verb="probe", params=base) is not None, \
        "the control could not see a difference: byte-identical params must count"

    long_name = "e" * 1024
    assert repeat_trip(rows, LEAD, system=long_name, verb="probe", params=base) is None
    long_rows = [_row(LEAD, s, long_name, "probe", base) for s in (0, 1)]
    assert repeat_trip(long_rows, LEAD, system=long_name, verb="probe", params=base) is not None, \
        "a kilobyte-long system name is one more distinct key, not a special case"

    rec = VerbRecorder()
    r = _run(tmp_path, verbs=typed_params(rec), run_id="d807-bytes", turns=[
        q("elastic", "probe", dict(base)),
        q("elastic", "probe", dict(variants[0][1])),
        q("elastic", "probe", dict(variants[2][1])),
        DONE,
    ])
    assert len(rec.calls) == 3, "a byte-different repeat was refused end to end"
    assert INCOMPLETE_IDIOM not in r.summary()


def test_repeat_count_is_derived_from_the_table(tmp_path):
    organic_rec = VerbRecorder()
    organic = _run(tmp_path / "organic", verbs=elastic_ok(organic_rec), run_id="d807-derive-a", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    assert len(organic_rec.calls) == 2
    assert organic.own_rows[2]["exit_code"] == 64

    prefix = [_row(LEAD, s, "elastic", "query", {"native_query": "FROM logs"}) for s in (0, 1)]
    seeded_rec = VerbRecorder()
    seeded = _run_inherited(
        tmp_path / "seeded", table=_jsonl(prefix), rows=prefix, verbs=elastic_ok(seeded_rec),
        run_id="d807-derive-b", turns=[q("elastic", "query", {"native_query": "FROM logs"}), DONE],
    )
    assert seeded_rec.calls == [], \
        "the session executed the request — the rows the run inherited were not on its state"
    assert seeded.rows_for(LEAD)[2]["exit_code"] == 64
    assert INCOMPLETE_IDIOM in seeded.summary()

    planted_rec = VerbRecorder()
    planted = _run(
        tmp_path / "planted", verbs=elastic_ok(planted_rec), run_id="d807-derive-c",
        planted=prefix, turns=[q("elastic", "query", {"native_query": "FROM logs"}), DONE],
    )
    assert len(planted_rec.calls) == 1, \
        "rows planted in the folder before the run started were read into the run's state"
    assert _file_rows(planted.run_dir, LEAD)[-1]["seq"] == 0, \
        "the run's first row did not start its own seq at 0"
    assert INCOMPLETE_IDIOM not in planted.summary()


def test_repeat_predicate_fails_open_on_a_damaged_table(tmp_path):
    torn = b'{"lead_id": "l-001", "seq": 4, "sys'
    damaged = [
        _row(LEAD, 0, "elastic", "query", {"native_query": "FROM logs"}),
        {"seq": 1, "system": "elastic", "verb": "query", "params": {}},  # G17's 7-key judge row
        {**_row(LEAD, 2, "elastic", "query", {}), "params": "not-a-dict"},
        _row(LEAD, 3, "elastic", "query", {"native_query": "FROM logs"}),
    ]
    rec = VerbRecorder()
    r = _run_inherited(
        tmp_path / "damaged", table=_jsonl(damaged) + torn, rows=damaged, verbs=elastic_ok(rec),
        run_id="d807-damaged", turns=[q("elastic", "query", {"native_query": "FROM logs"}), DONE])
    assert [row["seq"] for row in r.state.lead_rows(LEAD)][:3] == [0, 2, 3], \
        "a torn line, a foreign row shape or a non-dict params field was not survived"
    assert rec.calls == [], "the inherited rows no longer count the lead's two real occurrences"
    assert INCOMPLETE_IDIOM in r.summary()

    one = [_row(LEAD, 0, "elastic", "query", {"native_query": "FROM logs"})]
    bad_utf8 = _jsonl(one).replace(b"FROM logs", b"\xff\xfeFROM logs")
    u = _run_inherited(tmp_path / "utf8", table=bad_utf8, rows=one, verbs=elastic_ok(VerbRecorder()),
                       run_id="d807-utf8", turns=[DONE])
    assert len(u.state.lead_rows(LEAD)) == 1, \
        "invalid UTF-8 raised or dropped the row where read_jsonl_rows' errors='replace' keeps it"


def test_tripping_call_carries_no_repeat_note(three_identical_requests):
    r, rec = three_identical_requests
    seen = r.gather_saw
    assert seen.count("[record_query] REPEAT") == 1, \
        "the second occurrence's REPEAT notice is the control; the tripping call must add none"
    assert r.gather.calls == 4, (
        "the tripping call was answered like an ordinary query and the lead went on (5+), or "
        "the summary turn #987 gives a stopped lead did not run (3). Neither adds a REPEAT "
        "annotation, which is what the count above this line is for."
    )
    assert INCOMPLETE_IDIOM not in seen, "the dead end was handed to the GATHER model"
    assert INCOMPLETE_IDIOM in r.summary()


def test_repeat_guard_never_fires_above_its_own_placement(tmp_path):
    registry, relink = unloadable_adapter(tmp_path / "tree")
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

    root = tmp_path / "tenant-data"
    S.plant(root, table="dispositions:\n  elastic:\n    probe: {roles: [gather]}\n")
    r = _run(
        tmp_path / "run", verbs=registry, run_id="d807-loaderr", tenant=S.tenant_folder_of(root),
        turns=_after_start(relink, [
            q("elastic", "probe", {"native_query": "FROM logs"}),
            q("elastic", "probe", {"native_query": "FROM logs"}),
            q("elastic", "probe", {"native_query": "FROM logs"}),
            DONE,
        ]))
    assert relink.broken == 1, "premise: the adapter was never broken after the run's start"
    rows = r.own_rows
    assert len(rows) == 2, \
        "the third load-error call was recorded — the breaker that owns this repeat never answered it"
    assert {row["exit_code"] for row in rows} == {2}, \
        "a load-error call was recorded as anything other than the infra fault it is"
    assert all(row["exit_code"] != 64 for row in rows), "the guard wrote a trip row above its placement"
    assert circuit_breaker.is_tripped(r.state, "elastic") is True
    assert "is DOWN" in r.gather_saw, "the third call was not answered by the down-message"
    assert r.gather.calls == 4, "a GatherDeadEnd ended the lead where the infra breaker owns it"
    assert INCOMPLETE_IDIOM not in r.summary()
    assert _replay(rows, threshold=2) == [], \
        "replay tripped on rows `_grant_check` wrote above M2 — live and replay disagree"


def test_load_error_repeat_is_answered_by_the_breaker_not_the_run_kill(tmp_path):
    registry, relink = unloadable_adapter(tmp_path / "tree")
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

    root = tmp_path / "tenant-data"
    S.plant(root, table="dispositions:\n  elastic:\n    probe: {roles: [gather]}\n")
    r = _run(
        tmp_path / "run", verbs=registry, run_id="d878-loaderr", tenant=S.tenant_folder_of(root),
        turns=_after_start(relink, [q("elastic", "probe", {"native_query": "FROM logs"})] * 5
                           + [DONE]))
    assert relink.broken == 1, "premise: the adapter was never broken after the run's start"
    rows = r.own_rows
    assert len(rows) == 2, "a call answered by the down-message still recorded an evidence row"
    assert {row["exit_code"] for row in rows} == {2}
    assert r.gather_saw.count("is DOWN") == 3, \
        "the three calls past the trip were not each answered by the breaker's down-message"
    assert r.breaker["total_failures"] == circuit_breaker.PER_SYSTEM_FAIL_LIMIT, \
        "a down-answered call counted a failure — five of them spend RUN_FAIL_KILL_LIMIT"
    assert r.breaker["total_failures"] < circuit_breaker.RUN_FAIL_KILL_LIMIT
    assert r.gather.calls == 6, "the lead ended early — RunAborted or a dead end cut it short"
    assert INCOMPLETE_IDIOM not in r.summary(), "the lead reported itself incomplete"
    assert r.main.calls == 2, \
        "MAIN never resumed after the gather lead — the run died inside it"


def test_repeat_trip_empty_params_is_its_own_domain_member(tmp_path):
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=parameterless(rec), run_id="d807-empty", turns=[
        q("elastic", "health-check", {}),
        q("elastic", "health-check", {}),
        q("elastic", "health-check", {}),
        DONE,
    ])
    assert len(rec.calls) == 2, "a parameterless verb was exempted from the guard"
    rows = r.own_rows
    assert [row["params"] for row in rows] == [{}, {}, {}]
    assert rows[2]["exit_code"] == 64
    assert INCOMPLETE_IDIOM in r.summary()


def test_counted_domain_excludes_validate_path_rows(tmp_path):
    params = {"native_query": "FROM logs"}

    rejected_rec = VerbRecorder()
    rejected = _run(tmp_path / "rejected", verbs=elastic_ok(rejected_rec), run_id="d807-fa", turns=[
        _bad_args(params), _bad_args(params), q("elastic", "query", params), DONE,
    ])
    rows = rejected.own_rows
    assert len(rows) == 3, "the two schema rejections did not leave their validate-path rows"
    assert [row["exit_code"] for row in rows[:2]] == [64, 64]
    assert rows[0]["params"] == params, "P-a's shape changed: the rejection row lost the key it collides on"
    assert set(rows[0]) == ROW_KEYS, \
        "the validate-path row's sentinel identity was added as a key of its own"
    assert set(rows[1]) == ROW_KEYS, \
        "the validate-path row's sentinel identity was added as a key of its own"
    assert rows[2]["exit_code"] == 0, "a call the argument schema turned back was counted as an occurrence"
    assert len(rejected_rec.calls) == 1, "the genuine third call never reached the backend"
    assert INCOMPLETE_IDIOM not in rejected.summary()
    assert _replay(rows) == [], \
        "the replay oracle counted validate-path rows the live guard skipped — they disagree"

    grant_rec = VerbRecorder()
    unresolvable = _run(
        tmp_path / "unresolvable", verbs=elastic_ok(grant_rec), run_id="d807-fa-grant", turns=[
            q("elastic", "nosuch-verb", params), q("elastic", "nosuch-verb", params),
            q("elastic", "nosuch-verb", params), DONE,
        ])
    grant_rows = unresolvable.own_rows
    assert len(grant_rows) == 3, "the unresolvable branch stopped recording its rows"
    assert [row["exit_code"] for row in grant_rows] == [64, 64, 64]
    assert [row["verb"] for row in grant_rows] == ["nosuch-verb"] * 3
    assert all(set(row) == ROW_KEYS for row in grant_rows), \
        "the above-M2 sentinel identity was added as a key of its own"
    assert grant_rec.calls == [], "an unresolvable verb reached the backend"
    assert _replay(grant_rows) == [], \
        "M2's oracle trips on a repeat M2 can never refuse — live and replay disagree"
    assert unresolvable.gather.calls == 4, (
        "the third identical rejection did not end the lead — the companion guard is silent "
        "(5+), or the lead ended but #987's summary turn did not follow (3)"
    )
    assert INCOMPLETE_IDIOM in unresolvable.summary()
    assert _replay_rejections(grant_rows) == [(LEAD, 2, "repeat")], \
        "the companion guard's live stop and its replay over the same table disagree"

    genuine_rec = VerbRecorder()
    genuine = _run(tmp_path / "genuine", verbs=elastic_ok(genuine_rec), run_id="d807-fa-ctl", turns=[
        q("elastic", "query", params), q("elastic", "query", params),
        q("elastic", "query", params), DONE,
    ])
    assert genuine.own_rows[2]["exit_code"] == 64, \
        "the control could not see a difference: two EXECUTED occurrences must refuse the third"
    assert len(genuine_rec.calls) == 2
    assert INCOMPLETE_IDIOM in genuine.summary()


def test_repeat_key_normalizes_the_live_call_to_its_stored_form(tmp_path):
    live = {"native_query": "FROM logs", "threshold": float("nan")}
    stored = _json_safe_params(dict(live))
    assert stored != live, "the transform this demand is about did nothing — the fixture is inert"

    rows = [_row(LEAD, s, "elastic", "probe", stored) for s in (0, 1)]
    hit = repeat_trip(rows, LEAD, system="elastic", verb="probe", params=live)
    assert hit is not None, "a live non-finite param never recognised its own stored rows"
    assert hit.occurrence == REPEAT_THRESHOLD, "the normalized live call landed on the wrong occurrence"

    # Rows-in and live-in are the same call: replaying the STORED form must agree exactly.
    assert repeat_trip(rows, LEAD, system="elastic", verb="probe", params=stored) is not None
    assert repeat_trip(rows[:1], LEAD, system="elastic", verb="probe", params=live) is None


def test_trip_row_survives_the_learning_extractors_payload_gate(three_identical_requests):
    r, rec = three_identical_requests
    trip = r.own_rows[2]
    assert trip["payload_status"] == "error"
    sidecar = r.run_dir / trip["payload_path"]
    assert sidecar.is_file(), "the trip row's sidecar is missing — extract_from_joined drops the row"
    assert sidecar.read_text(encoding="utf-8") == ""

    own_leads = [
        lead for lead in lead_repository.joined(r.run_dir)
        if lead.lead_id not in RESERVED_LEAD_IDS
    ]
    executed = lead_extraction.extract_from_joined(own_leads)
    assert len(executed) == 3, "the trip row was dropped before the learning loop could see it"
    assert executed[2].payload_status == "error"
    assert executed[2].error_class == "agent-fixable"


def test_screen_refused_repeats_count_toward_the_trip(tmp_path):
    rec = VerbRecorder()
    bad = {"native_query": "FROM logs", "nosuch_param": 1}
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-screen", turns=[
        q("elastic", "query", bad), q("elastic", "query", bad), q("elastic", "query", bad), DONE,
    ])
    assert rec.calls == [], "a param-invalid call reached the backend"
    assert r.gather_saw.count("unknown param(s)") == 2, \
        "the screen must still teach on the first two; only the third is a dead end"
    assert r.gather.calls == 4, (
        "the third refusal was a ModelRetry, not a dead end (5+) — or the dead end fired and "
        "#987's summary turn did not follow it (3)"
    )
    rows = r.own_rows
    assert len(rows) == 3
    assert [row["exit_code"] for row in rows] == [64, 64, 64]
    assert rows[2]["params"] == bad, "the trip row did not record the request as the lead sent it"
    assert INCOMPLETE_IDIOM in r.summary()


def test_concurrent_identical_siblings_still_stop_the_lead(tmp_path):
    rec = VerbRecorder()
    same = {"system": "elastic", "verb": "probe", "params": {"tag": "alpha"}}

    def probe(ctx: VerbContext, *, tag: str) -> list[dict]:
        rec.record("probe", ctx, {"tag": tag})
        return [{"tag": tag}]

    r = _run(tmp_path, verbs=FakeVerbs({"elastic": {"probe": probe}}), run_id="d807-conc", turns=[
        Turn(tool_calls=[("query", same)]),
        Turn(tool_calls=[("query", same)]),
        Turn(tool_calls=[("query", same), ("query", same)]),
        DONE,
    ])
    assert len(rec.calls) == 2, "a sibling of the tripping call still reached the backend"
    assert r.gather.calls == 4, (
        "the concurrent trip did not end the lead (5+), or it ended and the summary turn did "
        "not follow (3) — which on THIS script needs BOTH siblings answered, each by its own "
        "execution: the first to trip closes the door, the other is either its own trip or "
        "`QUERY_NOT_RUN`"
    )
    assert INCOMPLETE_IDIOM in r.summary()
    assert any(row["exit_code"] == 64 for row in r.own_rows), "no trip row was written at all"
    assert [row["exit_code"] for row in r.own_rows[:2]] == [0, 0]


def test_dead_end_message_does_not_echo_model_authored_params(tmp_path):
    canary = "CANARY-4f2a-model-authored-filter"
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=named_verbs(rec), run_id="d807-noecho", turns=[
        q("elastic", "sshd-auth-window", {"native_query": canary}),
        q("elastic", "sshd-auth-window", {"native_query": canary}),
        q("elastic", "sshd-auth-window", {"native_query": canary}),
        DONE,
    ])
    summary = r.summary()
    assert INCOMPLETE_IDIOM in summary, "no dead end happened, so the negative is vacuous"
    assert "sshd-auth-window" in summary, "the message names nothing at all"
    assert canary not in summary, "the model's own params text crossed into main's context"
    assert canary not in r.main_saw, \
        "the params fragment reached main's context by some other surface than the summary"
    assert canary not in (r.run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8")

    rows = r.own_rows
    assert rows[0]["params"]["native_query"] == canary, \
        "the control failed: the request is unrecoverable through the sanctioned path too"
    assert canary in rows[0]["raw_command"]
    assert rows[2]["params"]["native_query"] == canary


def test_dead_end_message_names_the_earliest_matching_seq(tmp_path):
    rec = VerbRecorder()
    prefix = [
        _row(LEAD, 9, "elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
        _row(LEAD, 5, "elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
    ]
    r = _run_inherited(
        tmp_path, table=_jsonl(prefix), rows=prefix, verbs=named_verbs(rec),
        run_id="d807-earliest",
        turns=[q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}), DONE],
    )
    summary = r.summary()
    assert INCOMPLETE_IDIOM in summary, "no dead end happened"
    assert "seq 5" in summary, "the message did not name the earliest matching occurrence"
    assert "seq 9" not in summary, "the message named the latest matching occurrence"

    hit = repeat_trip(
        _file_rows(r.run_dir, LEAD)[:2], LEAD, system="elastic", verb="sshd-auth-window",
        params={"native_query": "FROM logs"},
    )
    assert hit is not None
    assert hit.first_seq == 5


def test_repeat_of_a_failing_request_still_trips(tmp_path):
    rec = VerbRecorder()
    r = _run(
        tmp_path, verbs=raising(rec, UpstreamFault("no matching documents")),
        run_id="d807-failing", turns=[
            q("elastic", "probe", {}), q("elastic", "probe", {}), q("elastic", "probe", {}), DONE,
        ])
    assert len(rec.calls) == 2, "the third identical failing request still reached the backend"
    rows = r.own_rows
    assert [row["exit_code"] for row in rows] == [1, 1, 64]
    assert r.breaker == _BLANK_BREAKER, \
        "an agent-fixable failure opened the infra breaker and answered first"
    assert INCOMPLETE_IDIOM in r.summary()
