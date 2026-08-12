"""#807 ask (1) — the executable spec for gather's REPEAT CIRCUIT BREAKER.

Every test here is one demand of `spec-flow/specs/spec_graph_807.yaml`, named after its
`discharged_by` pointer and carrying that demand's observable-outcome prose in its docstring
(the demand itself is a pointer — `check_binds` scans the docstring in place of an `outcome`).

THE CODE DOES NOT EXIST YET. This suite is RED by construction: the import block below names
the surface the implementation must build, and that is the point — the tests are the spec the
code is written against.

The surface this suite pins (all of it new, all of it in
`defender/scripts/gather_tools/record_query.py` beside `_request_key`/`repeat_note`, which is
fork F3's provisional site; the NAME `repeat_trip` is the part §7 pinned, because an
implementation that spells it otherwise makes `check_binds` skip the concept silently)
--------------------------------------------------------------------------------------------
`REPEAT_THRESHOLD = 3`
    A module constant, and the SAME N for every system: `test_repeat_trip_predicate_seam`
    drives a second (system, verb) pair and it trips at the same occurrence, so no per-system
    override survives this suite. C11's sweep fixes the value with evidence and N=2 is *proven*
    to refuse correct work (it refuses pr815's l-008 and l-015, which both returned real
    summaries). F-P's other half — "no env var" — is deliberately NOT claimed here: an
    import-time `env_int(…, 3)` read defaults to 3 and passes every in-process assertion, so a
    test at this address would certify nothing. That half lives in the graph's
    `repeat_threshold` refinement and in `handoff.forks`, where the implementer meets it.

`lead_rows(run_dir, lead) -> list[dict]`
    THE read the guard derives its count from: this lead's rows off
    `{run_dir}/executed_queries.jsonl`, in file order, torn/unparseable lines dropped, and
    `[]` on ANY `OSError`. It is a seam because F-Q's fail-open posture is otherwise
    unobservable — `read_jsonl_rows` propagates `PermissionError` and only `PermissionError`
    (P-d, executed), so the guard needs exactly one `except OSError` and the spec has to be
    able to drive it. It is also the third copy of the read+filter loop `_next_seq` and
    `repeat_note` already carry, which `lint_duplicate_helpers` would flag (G20).

`repeat_trip(rows, lead, *, system, verb, params, threshold=REPEAT_THRESHOLD) -> RepeatTrip | None`
    THE predicate, over queries-table ROWS, keyed `(lead_id, system, verb, canonical(params))`
    — so O1/O3's replay oracle drives the production predicate over a recorded run with no
    live agent (`repeat_trip_predicate_seam`). It normalises its incoming `params` to the
    STORED form (`_json_safe_params`, then `record_query._request_key`) before keying, so the
    live guard and the replay oracle are literally one function over one input shape (F-B,
    §7 auto). It counts only rows THE GUARD COULD ITSELF HAVE REFUSED — rows written at or
    below M2. A row written ABOVE M2 is never an occurrence, live or on replay, and there are
    three such writers: `wrap_tool_validate`'s rejection row, and BOTH of `_grant_check`'s
    row-writing branches — the adapter load error (`query_tool.py:219-226`, exit 2) and the
    non-`GRANTED`/unresolvable branch (`:238-244`, exit 64 + `ModelRetry`). Any wider domain
    lets the replay oracle report a trip no live run can produce, which is exactly what
    `trip_row_is_itself_an_occurrence_on_replay`'s own justification forbids (F-A, §7 human:
    option 1 in round 1, narrowed to this criterion in round 2).

`RepeatTrip(first_seq, occurrence)`
    `first_seq` — the EARLIEST matching row's seq (F-H(b): deterministic under duplicate or
    non-monotonic seqs, and it names the occurrence that started the repetition; "earliest" is
    read off the seq, not off file order, because the count itself is order-independent).
    `occurrence` — this call's 1-based occurrence number, `== threshold` at a trip.

`REPEAT_ESCAPE`
    ONE fixed, system-agnostic sentence, identical on every trip (F-G, §7 auto). A per-system
    escape table would make the guard a progress oracle, which N2 forbids by name, and would
    have been *wrong* on `reviewer-measure-0807`, whose repeat lead was already on the escape
    path the issue proposed (C9).

`GatherDeadEnd(reason, escape)`
    Raised out of `QueryCapture.wrap_tool_execute` at M2's placement and caught at
    `_run_gather` beside `UsageLimitExceeded`. P-c walked 137 frames and found it arrives
    UNWRAPPED (pydantic-ai's `_call_tools` uses `create_task` + `asyncio.wait`, never a
    TaskGroup), so `except GatherDeadEnd` hits and the dead end stays lead-level; the paired
    control shows the alternative costs the whole run.

How faults are induced here
---------------------------
Down the hierarchy, never off it. Almost everything below is *real input through the real
primitive in the test itself*: real malformed tool arguments through the real pydantic arg
schema, a real adapter module that raises at import through the real `ModuleVerbRegistry`, a
real torn line and a real chmod-000 file through the real `read_jsonl_rows`, real concurrency
through the real two-calls-in-one-turn shape. Where a fake stands in for a dependency it is
the harness's `verbs=` injection seam and it injects faults ONLY — never classifies, never
decides policy — and its fault content cites the executed claim that observed it on the real
dependency (`P-a` for the five validate-path rejection shapes, `P-b`/`P-b2` for
`_persist_payload`'s swallow and `payload_digest`'s shape, `P-d` for `read_jsonl_rows`'
exception surface, `P-c` for the unwrapped arrival at `_run_gather`). There is no
`monkeypatch.setattr` in this file: every fake enters through an injection seam the entry
point already declares.

RF-J2, carried from the seam and binding on this file
-----------------------------------------------------
The fitted corpus (three runs, 266 rows) holds ZERO rows written by `wrap_tool_validate` and
ZERO repeat groups whose calls failed. F-A and F-E were decided in favour of readings the
replay oracle CANNOT discriminate. `test_counted_domain_excludes_validate_path_rows` and
`test_screen_refused_repeats_count_toward_the_trip` therefore drive the REAL path, live; a
green `test_repeat_replay_*` does not discharge either of them.
"""
from __future__ import annotations

import json
import os
import re
import unicodedata
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import append_jsonl, read_jsonl_rows, write_guarded  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.learning import lead_repository  # noqa: E402
from defender.learning.leads import lead_extraction  # noqa: E402
from defender.runtime import circuit_breaker, observe  # noqa: E402
from defender.runtime.lead_zero import RESERVED_LEAD_IDS  # noqa: E402
from defender.runtime.query_tool import _json_safe_params  # noqa: E402
from defender.runtime.verb_grant import VerbGrant  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry, VerbContext, VerbRegistry  # noqa: E402
from defender.scripts.adapters.faults import TransportFault, UpstreamFault  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
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

# ---- THE SURFACE UNDER TEST — none of it exists on this base (RED by construction) ----
from defender.scripts.gather_tools.record_query import (  # noqa: E402
    REPEAT_ESCAPE,
    REPEAT_THRESHOLD,
    REPEAT_TRIP_QUERY_ID,
    GatherDeadEnd,
    RepeatTrip,
    lead_rows,
    rejection_trip,
    repeat_trip,
)

pytestmark = pytest.mark.e2e

SALT = "aabbccddeeff0011"
LEAD = "l-001"
SIBLING = "l-002"

CORPUS = DEFENDER / "fixtures-e2e" / "repeat-corpus-807"

# The idiom `_run_gather`'s three shipped terminal branches already use, and the ONLY
# vocabulary any prompt in the corpus teaches main (defender/SKILL.md:394 — G19).
INCOMPLETE_IDIOM = "Treat this lead as incomplete and reason from what was captured."




class _Res:
    """One driven replay: the run dir, the two replay models, and the tables on disk."""

    def __init__(self, run_dir: Path, main: ReplayFn, gather: ReplayFn):
        self.run_dir, self.main, self.gather = run_dir, main, gather

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
        p = self.run_dir / "circuit_breaker.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}

    @property
    def denials(self) -> list[dict]:
        return read_jsonl_rows(self.run_dir / observe.POLICY_DENIALS)


def _dispatch(lead: str, system: str) -> tuple[str, dict]:
    return ("gather", {
        "lead_id": lead, "system": system, "goal": "measure this lead",
        "what_to_summarize": ["auth events"],
    })


def _run(
    root: Path, *, verbs, turns: list[Turn], run_id: str, system: str = "elastic",
    lead: str = LEAD, seed: list[dict] | None = None,
    breaker: list[tuple[str, int]] | None = None,
) -> _Res:
    """Drive a REAL run: main dispatches one gather lead, the nested gather agent replays
    `turns` against the INJECTED verb registry. Everything between the two fakes — dispatch,
    the query tool, the repeat guard, the capture capability, the infra breaker, the two
    tables — is production code.

    `breaker` pre-seeds infra-breaker state through the PRODUCTION `record_outcome`, one
    (system, exit_code) per call, so a run can start from a breaker document an earlier,
    unrelated failure already wrote rather than from a fresh one."""
    run_dir = materialize(root, GOLDEN_AB3)
    if seed:
        _seed(run_dir, seed)
    for brk_system, brk_exit in (breaker or []):
        circuit_breaker.record_outcome(run_dir, brk_system, brk_exit)
    main = ReplayFn([Turn(tool_calls=[_dispatch(lead, system)]), Turn(text="Investigation complete.")])
    gather = ReplayFn(turns)
    drive(run_dir, run_id=run_id, salt=SALT, main=main, gather=gather, verbs=verbs)
    return _Res(run_dir, main, gather)


def _run_two_leads(
    root: Path, *, verbs, turns: list[Turn], run_id: str,
    first: tuple[str, str] = (LEAD, "elastic"), second: tuple[str, str] = (SIBLING, "elastic"),
) -> _Res:
    """Two leads dispatched SERIALLY (one gather tool call per main turn), so one shared
    gather replay script serves them in order: the first lead consumes turns until it stops,
    the second picks up at the next turn."""
    run_dir = materialize(root, GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[_dispatch(*first)]),
        Turn(tool_calls=[_dispatch(*second)]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(turns)
    drive(run_dir, run_id=run_id, salt=SALT, main=main, gather=gather, verbs=verbs)
    return _Res(run_dir, main, gather)


def _row(
    lead: str, seq: int, system: str, verb: str, params: dict, *,
    exit_code: int = 0, query_id: str | None = None, digest: str | None = None,
) -> dict:
    """One queries-table row in the frozen twelve-key shape, with `error_class` computed by
    the PRODUCTION classifier rather than restated — a seeded fixture that disagrees with
    `error_class_for_exit` would be a fixture asserting its own arithmetic."""
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
            f"exit={exit_code}; seeded" if exit_code != 0 else "12 bytes, 1 line(s)"
        ),
    }


def _seed(run_dir: Path, rows: list[dict]) -> None:
    """Pre-seed the queries table (and each row's sidecar) exactly as a resumed or
    already-running lead leaves it. The count is DERIVED per call from rows on disk, so a
    seeded table and an organically-accumulated one are the same input to the guard."""
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
    terminates the lead ("must stop at seq 4 rather than 36" — the doc's own words). A replay
    that counted every recorded row through to the end is not the oracle O1 names."""
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
    rows: list[dict], *, threshold: int = REPEAT_THRESHOLD,
) -> list[tuple[str, int]]:
    """The same oracle for the COMPANION guard (#826 item 4), differing from `_replay` only in
    the production predicate it drives — which is the claim under test: the two guards are one
    counting rule over two disjoint domains, so one replay shape serves both.

    The trip row is accumulated BEFORE the stop, unlike `_replay`: the companion guard's
    rejection row is written for every call including its last, so the recorded table holds
    exactly `threshold` matching rows at a trip, and an oracle that withheld the last one would
    disagree with the table the live run actually left."""
    seen: dict[str, list[dict]] = {}
    stopped: set[str] = set()
    trips: list[tuple[str, int]] = []
    for row in rows:
        lead = row.get("lead_id")
        if not isinstance(lead, str) or lead in stopped:
            continue
        prior = seen.setdefault(lead, [])
        hit = rejection_trip(
            prior, lead, system=row.get("system"), verb=row.get("verb"),
            params=row.get("params"), threshold=threshold,
        )
        prior.append(row)
        if hit is not None:
            trips.append((lead, row.get("seq")))
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
    UNDECLARED one. Dumb data: it injects no fault and makes no admission decision of its
    own; `VerbRegistry.decide` and the grant do all the work."""

    def __init__(self, table: dict[str, dict], grant: VerbGrant):
        super().__init__(grant)
        self._table = {s: dict(v) for s, v in table.items()}

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

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


def unloadable_adapter(root: Path) -> ModuleVerbRegistry:
    """The REAL production registry over a REAL adapter module that raises at import — a
    level-1 fault, not a stand-in for one. `decide` resolves the grant cold (an AST read of
    the `VERBS = {...}` literal), then imports to bind the verb, and the import raises."""
    adapters = root / "adapters"
    adapters.mkdir(parents=True)
    (adapters / "elastic_adapter.py").write_text(_BROKEN_ADAPTER, encoding="utf-8")
    return ModuleVerbRegistry(adapters, VerbGrant(role="gather", entries=(("elastic", "probe", "r"),)))


def _bad_args(params: dict) -> Turn:
    """A tool call the pydantic ARG SCHEMA turns back, so the row is written by
    `wrap_tool_validate` from the RAW pre-validation arguments. `bogus_extra_arg` is P-a's
    executed `extra_argument` shape: the rejection row it leaves recovers a perfectly normal
    `system='elastic'`, `verb='query'` and the model's own `params` — byte-identical in key to
    the corrected retry's."""
    return Turn(tool_calls=[("query", {
        "system": "elastic", "verb": "query", "params": params, "bogus_extra_arg": "x",
    })])




def test_repeat_trip_predicate_seam(tmp_path):
    """repeat_trip_predicate_seam — an IMPORTABLE predicate `repeat_trip` over queries-table
    ROWS, keyed (lead_id, system, verb, canonical(params)) with threshold N, so O1/O3's replay
    oracle drives the production predicate over a recorded run with no live agent. It reuses
    `record_query._request_key` (never a second canonicalizer), returns None below the
    threshold and a `RepeatTrip` naming the earliest matching seq at it, and `REPEAT_THRESHOLD`
    is the module constant N = 3 — one N for EVERY system, with no per-system override: a
    second (system, verb) pair trips at the same occurrence as the first."""
    # rejected: N2 — it is not a progress oracle; it answers only "have I sent this exact
    #   request before", nothing more.
    # rejected: keying on payload_digest instead of request identity — C10: pr815's l-015 seq
    #   8/16/17 returned the same 745-byte empty payload for three genuinely different
    #   questions, so a digest key refuses correct work.
    # rejected: persisting the count in circuit_breaker.json — the count is DERIVED per call
    #   from rows already on disk; the existing breaker persists because it is run-scoped and
    #   cross-lead, this predicate is lead-scoped.
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

    # NO PER-SYSTEM OVERRIDE: a different system with a differently-shaped verb pays the same
    # N, so the constant is the only source of the value in effect. (F-P's other half, "no env
    # var", is not asserted anywhere in this suite and the module docstring says why: an
    # import-time env read defaulting to 3 passes any in-process check, so such a test would
    # certify nothing.)
    other = {"system": "cmdb", "verb": "host-trust-edges", "params": {"host": "db-1"}}
    other_rows = [_row(LEAD, s, "cmdb", "host-trust-edges", {"host": "db-1"}) for s in (0, 1)]
    assert repeat_trip(other_rows[:1], LEAD, **other) is None, \
        "a second system trips EARLIER than N — the threshold is per-system"
    assert repeat_trip(other_rows, LEAD, **other) is not None, \
        "a second system trips LATER than N — the threshold is per-system"

    # The seam's whole purpose: it eats rows read straight off a RECORDED table.
    recorded = [r for r in _corpus("reviewer-measure-0807-b") if r["lead_id"] == LEAD]
    assert recorded, "the recorded corpus fixture is missing its repeat lead"
    # seq 4 is this fixture's actual trip point (test_repeat_replay_trips_the_two_recorded_leads
    # pins it): rows 0-3 accumulated give two prior occurrences of seq4's request (seq2, seq3),
    # so this is the third occurrence.
    assert repeat_trip(
        recorded[:4], LEAD, system=recorded[4]["system"], verb=recorded[4]["verb"],
        params=recorded[4]["params"],
    ) is not None, "the production predicate could not be driven over a recorded run"


def test_gather_dead_end_type(tmp_path):
    """gather_dead_end_type — `GatherDeadEnd(reason, escape)` exists, is raised out of
    `QueryCapture.wrap_tool_execute` at M2's placement (so the tripping call never returns a
    tool result to the gather model and gather is never asked again), and is catchable at
    `gather_dispatch` — `_run_gather` returns a string instead of letting it unwind."""
    # rejected: letting GatherDeadEnd escape `_run_gather` the way RunAborted does — refuted
    #   by P1/P-c, executed in both directions: uncaught at that placement it kills the run.
    # The type check runs LAST: a null-stub target answers `issubclass(<stub>, Exception)`
    # with a TypeError (not a class), which would otherwise mask this test's own
    # demand-specific assertions behind unrelated machinery.
    made = GatherDeadEnd(reason="r", escape="e")
    assert made.reason == "r", "GatherDeadEnd did not carry its reason through construction"
    assert made.escape == "e", "GatherDeadEnd did not carry its escape through construction"

    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-type", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    assert r.gather.calls == 3, \
        "the tripping call returned a tool result instead of raising — the gather model got a 4th turn"
    assert r.main.calls == 2, "the raise was not caught at _run_gather"
    assert INCOMPLETE_IDIOM in r.summary(), "the dead end did not land the idiom's incomplete message"
    assert issubclass(GatherDeadEnd, Exception), "GatherDeadEnd must be an Exception subclass to be raised"


def test_repeat_trips_on_third_identical_request(tmp_path):
    """repeat_trips_on_third_identical_request — the positive control every negative in this
    spec pairs with: with `repeat_threshold` N = 3, the first two identical requests in a lead
    EXECUTE and the third is refused before the backend, ending the lead with a
    `GatherDeadEnd`. N = 3 is C11's floor — at N = 2 the guard refuses a lead that went on to
    succeed."""
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-trip", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    assert len(rec.calls) == 2, "calls 1 and 2 must execute; call 3 must not"
    rows = r.own_rows
    assert len(rows) == 3
    assert [row["exit_code"] for row in rows] == [0, 0, 64]
    assert INCOMPLETE_IDIOM in r.summary()


def test_repeat_replay_trips_the_two_recorded_leads(tmp_path):
    """repeat_replay_trips_the_two_recorded_leads — O1's stated oracle, over the recorded
    corpus: driving `repeat_trip` across `reviewer-measure-0807-b`'s
    `executed_queries` trips exactly once, at l-001 seq 4 (not seq 36); across
    `reviewer-measure-0807` exactly once, at l-001 seq 9. A conforming replay stops
    accumulating for a lead at its first trip, and the predicate is a pure function of row
    content — no path, inode or mtime enters the key or the count, so a staged copy agrees."""
    assert _replay(_corpus("reviewer-measure-0807-b")) == [("l-001", 4)]
    assert _replay(_corpus("reviewer-measure-0807")) == [("l-001", 9)]


def test_repeat_replay_never_trips_the_drift_run(tmp_path):
    """repeat_replay_never_trips_the_drift_run — O3, over `pr815-rerun-0808` (131 rows, 15
    leads, including a 36-call and a 34-call lead): `repeat_trip` fires ZERO times. The guard
    never refuses a call that differs from its predecessors. Positive control on the SAME
    corpus, proving the observation channel can see a trip at all: at threshold 2 the same
    replay trips l-008 at seq 1 and l-015 at seq 9 — and both of those leads returned real
    summaries, which is exactly why N = 2 is rejected."""
    # rejected: N1 — the guard deliberately does not detect semantic drift. pr815's l-012 (36
    #   distinct calls) and l-015 (eight coined db-1-sshd-* ids for one question) walk past it;
    #   request_limit stays the boundary for drift.
    # rejected: N = 2 — C11/G4/P4, and the control below: it refuses correct work.
    rows = _corpus("pr815-rerun-0808")
    assert _replay(rows) == []
    assert sorted(_replay(rows, threshold=2)) == [("l-008", 1), ("l-015", 9)]


def test_repeat_key_is_lead_scoped(tmp_path):
    """repeat_key_is_lead_scoped — `executed_queries` is ONE table for every lead in the run,
    so `repeat_trip.identity` filters on `lead_id`: an identical request issued by a DIFFERENT
    lead never counts toward this lead's trip, whatever the physical write order. Two sibling
    leads each pay their own full N, and a re-dispatch to a new lead_id starts at zero
    occurrences. Control on the same address: the SAME two rows carrying THIS lead's id do
    count, and the very same call is refused."""
    rec = VerbRecorder()
    foreign = [
        _row(SIBLING, 0, "elastic", "query", {"native_query": "FROM logs"}),
        _row(SIBLING, 1, "elastic", "query", {"native_query": "FROM logs"}),
    ]
    scoped = _run(tmp_path / "scoped", verbs=elastic_ok(rec), run_id="d807-scope", seed=foreign, turns=[
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
    control = _run(tmp_path / "own", verbs=elastic_ok(own), run_id="d807-scope-ctl", seed=mine, turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    assert own.calls == [], "the control could not see a difference: this lead's own rows must count"
    assert INCOMPLETE_IDIOM in control.summary()


def test_repeat_key_ignores_query_id(tmp_path):
    """repeat_key_ignores_query_id — `query_id` is the axis `repeat_trip.identity` and
    `request_key.identity` deliberately EXCLUDE: three calls with identical (system, verb,
    params) under three DIFFERENT coined query_ids are one request, and the third is refused.
    Design-derived, not census-observed, and that is the point — every repeated call in both
    recorded repeat leads carried a CONSTANT query_id, so a predicate that wrongly includes it
    replays identically to the correct one."""
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


def test_repeat_trip_never_reaches_the_backend(tmp_path):
    """repeat_trip_never_reaches_the_backend — M2: the refused call is refused WITHOUT
    executing. `interacts(query_tool->verbs_registry)` is never driven for it — the verb
    function is entered twice and never a third time, and the third call's params never reach
    a transport."""
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-backend", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    assert len(rec.calls) == 2, "the refused call reached the backend"
    assert rec.verbs == ["query", "query"]
    assert r.own_rows[2]["exit_code"] == 64
    assert r.own_rows[2]["payload_status"] == "error", "a refused call recorded a payload"
    assert (r.run_dir / r.own_rows[2]["payload_path"]).read_text(encoding="utf-8") == "", \
        "the refused call's sidecar holds a backend answer"


def test_repeat_trip_sits_after_grant_and_infra_breaker(tmp_path):
    """repeat_trip_sits_after_grant_and_infra_breaker — M2's placement, stated as its two
    observable consequences. (a) A DENIED repeat still produces its record in `denial_log` and
    never an evidence row in `executed_queries` — the guard never sees it, so it never trips.
    (b) A repeat on an already-tripped system still answers the `circuit_breaker`'s
    down-message: the key-flow ordering `_grant_check -> _tripped_message -> repeat check` is
    checked on every call regardless of what the repeat count would also conclude."""
    denied_rec = VerbRecorder()
    denied = _run(
        tmp_path / "denied", verbs=granted_and_withheld(denied_rec), run_id="d807-denied", turns=[
            q("elastic", "withheld", {"native_query": "FROM logs"}),
            q("elastic", "withheld", {"native_query": "FROM logs"}),
            q("elastic", "withheld", {"native_query": "FROM logs"}),
            DONE,
        ])
    assert denied_rec.calls == []
    assert denied.own_rows == [], "a DENIED call wrote an evidence row"
    assert len(denied.denials) == 3, "the denial record is the DENIED path's only artifact"
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


def test_repeat_trip_row_is_agent_fixable(tmp_path):
    """repeat_trip_row_is_agent_fixable — O4: the refused call appends a row to
    `executed_queries` with a NON-ZERO exit and `error_class == "agent-fixable"` — not absent,
    not null. The exit code is `USAGE_EXIT_CODE` (64), the code the tool already uses for a
    call that never executed: it yields "agent-fixable" for free and leaves
    `circuit_breaker.record_outcome` a no-op. Today 37/37 of one repeat lead's rows carry
    `error_class: null`, so to every existing guard all 37 repeats are successful queries."""
    # rejected: N5 — whether the offline pitfalls curator consumes the row is out of scope
    #   (#823); O4 stops at "the trip is recorded".
    # rejected: exit 2 (the module's own DEFAULT_FAULT_EXIT) — it yields error_class "infra",
    #   failing O4 outright, AND marks the system DOWN after two trips (G12, executed).
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-o4", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    trip = r.own_rows[2]
    assert trip["exit_code"] != 0, "no trip happened, so the negative is vacuous"
    assert trip["exit_code"] == 64
    assert trip["error_class"] == "agent-fixable"
    assert trip["error_class"] == circuit_breaker.error_class_for_exit(trip["exit_code"])
    assert trip["system"] == "elastic"
    assert trip["verb"] == "query"


def test_repeat_trip_leaves_the_infra_breaker_untouched(tmp_path):
    """repeat_trip_leaves_the_infra_breaker_untouched — a repeat is an AGENT dead end, not an
    unreachable system: the trip must NOT increment `circuit_breaker` and must not mark the
    system DOWN for the rest of the run. Driven in both starting states — from a fresh run dir
    (no breaker document is created at all) and from a run whose breaker document an EARLIER,
    UNRELATED infra failure already wrote, where that earlier trip must survive the repeat trip
    byte for byte. Positive control on the same address under the complementary condition: an
    exit-2 adapter fault DOES write breaker state, so the observation channel can see the
    difference."""
    rec = VerbRecorder()
    r = _run(tmp_path / "trip", verbs=elastic_ok(rec), run_id="d807-breaker", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    assert r.own_rows[2]["exit_code"] == 64, "no trip happened, so the negative is vacuous"
    assert not (r.run_dir / "circuit_breaker.json").exists(), \
        "the repeat trip wrote infra-breaker state"
    assert r.breaker == {}
    assert circuit_breaker.is_tripped(r.run_dir, "elastic") is False

    # The SAME trip, in a run that already carries an unrelated system's infra trip: two real
    # exit-2 outcomes on `cmdb` through the production `record_outcome` put it at
    # PER_SYSTEM_FAIL_LIMIT = 2 (G12, executed), i.e. DOWN, before the lead's first call.
    prior_rec = VerbRecorder()
    prior = _run(
        tmp_path / "prior", verbs=elastic_ok(prior_rec), run_id="d807-breaker-prior",
        breaker=[("cmdb", 2), ("cmdb", 2)], turns=[
            q("elastic", "query", {"native_query": "FROM logs"}),
            q("elastic", "query", {"native_query": "FROM logs"}),
            q("elastic", "query", {"native_query": "FROM logs"}),
            DONE,
        ])
    assert prior.own_rows[2]["exit_code"] == 64, "no trip happened, so the negative is vacuous"
    assert INCOMPLETE_IDIOM in prior.summary()
    assert circuit_breaker.is_tripped(prior.run_dir, "cmdb") is True, \
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


def test_trip_row_conforms_to_the_frozen_row_contract(tmp_path):
    """trip_row_conforms_to_the_frozen_row_contract — the trip row's payload carries the SAME
    twelve frozen keys as any other queries row: no thirteenth key, no amendment to
    `test_row_contract_frozen`. Every downstream reader written against twelve keys still
    reads it, and the key set is imported from the existing contract rather than restated, so
    the two cannot drift."""
    # rejected: a thirteenth key (e.g. `refusal_kind`) — typed and unambiguous, but it breaks
    #   `test_row_contract_frozen` and every reader written against twelve keys; that is a
    #   deliberate contract amendment this issue did not propose. F-I option 2 puts the
    #   repetition in the existing detail field instead (see trip_row_detail_names_the_repetition).
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-frozen", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    trip = r.own_rows[2]
    assert trip["exit_code"] == 64, "row 2 must be the trip itself, not an ordinary third success"
    assert set(trip) == ROW_KEYS
    assert trip["lead_id"] == LEAD
    assert trip["seq"] == 2
    assert trip["params"] == {"native_query": "FROM logs"}
    assert trip["payload_path"] == f"gather_raw/{LEAD}/2.json"


def test_trip_row_is_distinguishable_from_a_finished_leads_rows(tmp_path):
    """trip_row_is_distinguishable_from_a_finished_leads_rows — O4's contrast, and what is
    absent today: a stopped lead's record in `executed_queries` carries a non-zero exit and a
    non-null `error_class`, while a lead that finished has rows that are ALL exit 0 with
    `error_class` null and no `circuit_breaker` state. Both leads are in one run, so the
    difference is a property of the rows and not of the fixture."""
    rec = VerbRecorder()
    r = _run_two_leads(tmp_path, verbs=elastic_ok(rec), run_id="d807-contrast", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM other"}),
        DONE,
    ])
    stopped = r.rows_for(LEAD)
    finished = r.rows_for(SIBLING)
    assert len(stopped) == 3
    assert len(finished) == 1

    assert any(row["exit_code"] != 0 for row in stopped)
    assert any(row["error_class"] is not None for row in stopped)
    assert [row["exit_code"] for row in finished] == [0]
    assert [row["error_class"] for row in finished] == [None]
    assert r.breaker == {}


def test_dead_end_return_contract(tmp_path):
    """dead_end_return_contract — `gather_dispatch` catches `GatherDeadEnd` in the same except
    chain as UsageLimitExceeded and returns ONE string that (a) opens with the terminal idiom
    its three sibling branches already use — "gather for {lead_id} … Treat this lead as
    incomplete and reason from what was captured" — so main's established handling still
    fires and the message arrives into the one vocabulary any prompt in the corpus teaches;
    (b) names the repeated request, the structural cause and the escape; and (c) is
    `_wrap(…, "untrusted", deps.salt)`-wrapped into `model_context` and written verbatim to
    `gather_summaries/{lead_id}.md`, exactly like the three branches beside it — so it is the
    lead's surviving account after main's context is folded."""
    # rejected: returning the structural reason ALONE, dropping the idiom — C5's evidence that
    #   main re-dispatches is evidence about its response to the INCOMPLETE framing, and no
    #   prompt in the corpus teaches dead-end or refusal vocabulary (G19). O2's own sentence
    #   is "hands back a reason main can act on, NOT JUST 'incomplete'".
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
    assert summary.startswith(f"<run-{SALT}-untrusted>")
    assert summary.endswith(f"</run-{SALT}-untrusted>")
    assert "sshd-auth-window" in summary, "the message does not name the repeated request"
    assert REPEAT_ESCAPE in summary, "the escape never reached the string main receives"
    assert summary in r.main_saw, \
        "the persisted account and the string main received are not the same object"


def test_dead_end_is_contained_to_the_lead(tmp_path):
    """dead_end_is_contained_to_the_lead — `GatherDeadEnd` must NOT unwind the run the way
    RunAborted does: it crosses the budget-enforcement capability's `tool_execute` wrapper
    unaltered, `run_investigation` completes, main receives the string as the gather tool's
    result and keeps going, and a SIBLING lead dispatched afterwards runs normally. Scope
    stated: lead-level containment only — the in-flight sibling CALL's fate stays unpinned."""
    rec = VerbRecorder()
    r = _run_two_leads(tmp_path, verbs=elastic_ok(rec), run_id="d807-contained", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM other"}),
        DONE,
    ])
    assert r.main.calls == 3, "main never took its turns after the dead end — the run unwound"
    assert INCOMPLETE_IDIOM in r.summary(LEAD)
    assert INCOMPLETE_IDIOM not in r.summary(SIBLING), "the sibling lead was collateral damage"
    assert len(rec.calls) == 3, "the sibling lead's own query never ran"


def test_dead_end_message_names_repeat_and_structural_cause(tmp_path):
    """dead_end_message_names_repeat_and_structural_cause — the string `gather_dispatch`
    writes into `model_context` names the repeated request (its `system`, its `verb`, and the
    earlier seq it repeats) and states the cause is STRUCTURAL rather than a transient to
    retry through. ORACLE LIMIT, carried verbatim from the doc: a test can assert the
    message's content and that `_run_gather` returns it — NOT that main does something better
    with it. Nothing here pretends to observe an improved re-dispatch."""
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=named_verbs(rec), run_id="d807-msg", turns=[
        q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
        q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
        q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
        DONE,
    ])
    summary = r.summary()
    assert "elastic" in summary
    assert "sshd-auth-window" in summary
    assert "seq 0" in summary, "the message does not name the earlier occurrence it repeats"
    assert "structural" in summary, "the message does not state the cause is structural"


def test_repeat_key_normalizes_param_key_order(tmp_path):
    """repeat_key_normalizes_param_key_order — `json.dumps(sort_keys=True)` inside
    `request_key.identity` normalises key order away at EVERY nesting level, so two calls
    whose params differ only in key order — top level or nested — are ONE request under
    `repeat_trip.identity`, and the second is an occurrence of the first. Any variation that
    does not survive that canonicalization collapses to one key regardless of what the lead
    intended."""
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
    """repeat_key_separates_requests_that_differ_by_a_byte — the canonicalizer behind
    `repeat_trip.identity` and `request_key.identity` is STRUCTURAL and carries no per-verb,
    locale or numeric knowledge: no case folding, no Unicode normalization, no int/float
    folding, no per-verb defaults, and no length or charset constraint on `system`/`verb` (a
    kilobyte-long name is one more distinct key). Two renderings that differ as byte strings
    are two keys and must not count toward one another — the O3 direction of the same
    predicate. A kilobyte-long system name is exercised at the predicate only: such a call is
    answered by `_grant_check` ABOVE M2, so it can leave rows but can never itself be refused
    by the guard."""
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
    """repeat_count_is_derived_from_the_table — M1's one deliberate choice, "no new persisted
    state, no new file": the count `repeat_trip` reads is a pure function of the lead's rows
    in `executed_queries` on disk and of nothing in the session. A lead that accumulated its
    occurrences organically and a lead whose table was PRE-SEEDED before the process started
    trip at the same occurrence — in the seeded run the session never executed the request
    even once, and the guard still refuses it."""
    organic_rec = VerbRecorder()
    organic = _run(tmp_path / "organic", verbs=elastic_ok(organic_rec), run_id="d807-derive-a", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    assert len(organic_rec.calls) == 2
    assert organic.own_rows[2]["exit_code"] == 64

    seeded_rec = VerbRecorder()
    seeded = _run(
        tmp_path / "seeded", verbs=elastic_ok(seeded_rec), run_id="d807-derive-b",
        seed=[_row(LEAD, s, "elastic", "query", {"native_query": "FROM logs"}) for s in (0, 1)],
        turns=[q("elastic", "query", {"native_query": "FROM logs"}), DONE],
    )
    assert seeded_rec.calls == [], \
        "the session executed the request — the count came from memory, not from the table"
    assert seeded.own_rows[2]["exit_code"] == 64
    assert INCOMPLETE_IDIOM in seeded.summary()


def test_repeat_count_is_zero_before_the_lead_has_rows(tmp_path):
    """repeat_count_is_zero_before_the_lead_has_rows — the first call of a lead reads ZERO
    prior occurrences from `executed_queries`: never an error, never a trip. This covers both
    the absent file (the table does not exist yet) and the file that exists with no rows for
    THIS lead."""
    missing = tmp_path / "missing" / "run"
    missing.mkdir(parents=True)
    assert lead_rows(missing, LEAD) == [], "a lead with no table rows must read as zero occurrences"
    assert repeat_trip(lead_rows(missing, LEAD), LEAD, system="elastic", verb="query",
                       params={"native_query": "FROM logs"}) is None

    rec = VerbRecorder()
    r = _run(
        tmp_path / "foreign", verbs=elastic_ok(rec), run_id="d807-zero",
        seed=[_row(SIBLING, s, "elastic", "query", {"native_query": "FROM logs"}) for s in (0, 1, 2)],
        turns=[q("elastic", "query", {"native_query": "FROM logs"}), DONE],
    )
    assert len(rec.calls) == 1, "the lead's first call was refused against another lead's rows"
    assert lead_rows(r.run_dir, LEAD)[0]["seq"] == 0
    assert INCOMPLETE_IDIOM not in r.summary()


def test_repeat_predicate_fails_open_on_a_damaged_table(tmp_path):
    """repeat_predicate_fails_open_on_a_damaged_table — the guard inherits the posture BOTH
    existing readers of `executed_queries` already have and must not be the first reader that
    raises. `lead_rows` drops a torn trailing line, skips a foreign row carrying no `lead_id`,
    survives a stored `params` that is not a dict, survives invalid UTF-8, and returns `[]` on
    any OSError — a chmod-000 table yields zero prior occurrences and the call proceeds rather
    than crashing the query tool. Stated cost: tampering and corruption are therefore
    SILENT."""
    run_dir = tmp_path / "damaged"
    run_dir.mkdir(parents=True)
    table = RunPaths(run_dir).executed_queries
    append_jsonl(table, [
        _row(LEAD, 0, "elastic", "query", {"native_query": "FROM logs"}),
        {"seq": 1, "system": "elastic", "verb": "query", "params": {}},  # G17's 7-key judge row
        {**_row(LEAD, 2, "elastic", "query", {}), "params": "not-a-dict"},
        _row(LEAD, 3, "elastic", "query", {"native_query": "FROM logs"}),
    ])
    write_guarded(table, '{"lead_id": "l-001", "seq": 4, "sys', mode="append")

    rows = lead_rows(run_dir, LEAD)
    assert [r["seq"] for r in rows] == [0, 2, 3], \
        "a torn line, a foreign row shape or a non-dict params field was not survived"
    assert repeat_trip(rows, LEAD, system="elastic", verb="query",
                       params={"native_query": "FROM logs"}) is not None

    bad_utf8 = tmp_path / "utf8" / "run"
    bad_utf8.mkdir(parents=True)
    RunPaths(bad_utf8).executed_queries.write_bytes(
        b'{"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "query", '
        b'"params": {"native_query": "\xff\xfeFROM logs"}}\n'
    )
    assert len(lead_rows(bad_utf8, LEAD)) == 1, \
        "invalid UTF-8 raised where read_jsonl_rows' errors='replace' does not (P-d)"

    # P-d, executed as a non-root user: of the three read faults F-Q hedged over, only
    # PermissionError propagates out of `read_jsonl_rows` — a directory returns [] via
    # is_file() and invalid UTF-8 never raises at all. Root ignores permission bits, so this
    # arm is meaningless there (defender/CLAUDE.md says so of the four #631 siblings); CI runs
    # non-root and it is the arm with the teeth.
    a_dir = tmp_path / "isdir" / "run"
    (a_dir / "executed_queries.jsonl").mkdir(parents=True)
    assert lead_rows(a_dir, LEAD) == []

    if os.geteuid() != 0:
        locked = tmp_path / "locked" / "run"
        locked.mkdir(parents=True)
        append_jsonl(RunPaths(locked).executed_queries, [
            _row(LEAD, 0, "elastic", "query", {"native_query": "FROM logs"}),
        ])
        RunPaths(locked).executed_queries.chmod(0o000)
        with pytest.raises(PermissionError):
            read_jsonl_rows(RunPaths(locked).executed_queries)
        assert lead_rows(locked, LEAD) == [], \
            "the guard's own read propagated PermissionError — it must fail OPEN"


def test_tripping_call_carries_no_repeat_note(tmp_path):
    """tripping_call_carries_no_repeat_note — the regression witness for M2's ordering: the
    tripping call never reaches `_model_view`, so `gather_model_context` never carries a
    `REPEAT` annotation AND a dead end for the same call. Any placement after `handler(args)`
    breaks this. Positive control on the same address under the complementary condition: the
    shipped `repeat_note` DOES fire on the second, non-tripping occurrence, so exactly one
    REPEAT annotation reaches the gather model across the whole lead."""
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-note", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    seen = r.gather_saw
    assert seen.count("[record_query] REPEAT") == 1, \
        "the second occurrence's REPEAT notice is the control; the tripping call must add none"
    assert r.gather.calls == 3, "the tripping call produced a model view at all"
    assert INCOMPLETE_IDIOM not in seen, "the dead end was handed to the GATHER model"
    assert INCOMPLETE_IDIOM in r.summary()


def test_repeat_key_is_the_shipped_request_key(tmp_path):
    """repeat_key_is_the_shipped_request_key — `record_query`'s shipped `repeat_note` and the
    new guard are TWO READERS of one `request_key` over one table, bound per reader edge. The
    note fires when one prior row shares the key (the second occurrence); the guard trips on
    the third. One call can be both, and the two can never disagree about WHAT "the same
    request" IS, because they call the SAME `_request_key` over the SAME rows — the key, and
    therefore the set of rows each counts, is one answer. A second canonicalizer is also a
    `lint_duplicate_helpers` finding.

    SCOPE, stated: the KEY is what this demand pins, not the seq. The two readers select
    DIFFERENT rows from the matching set on purpose — the shipped `repeat_note` names the first
    match in file order among rows with `seq <` the current call, while F-H(b) makes the guard
    name the earliest match by seq over all of them (`dead_end_message_names_the_earliest
    _matching_seq` drives the shape where those differ). This run's three calls are in seq
    order, so here they land on the same row; nothing in this suite asserts they agree in
    general, and they do not."""
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=named_verbs(rec), run_id="d807-coherence", turns=[
        q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}, query_id="elastic.a"),
        q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}, query_id="elastic.b"),
        q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}, query_id="elastic.c"),
        DONE,
    ])
    assert "[record_query] REPEAT — this is the same request you ran at seq 0" in r.gather_saw, \
        "the shipped note did not recognise the second occurrence the guard counted"
    assert "seq 0" in r.summary(), \
        "seq 0 is the earliest matching row in this in-order run — the guard named another"

    rows = lead_rows(r.run_dir, LEAD)
    key = record_query._request_key("elastic", "sshd-auth-window", {"native_query": "FROM logs"})
    counted = [
        row for row in rows
        if record_query._request_key(row["system"], row["verb"], row["params"]) == key
    ]
    assert len(counted) == 3, "the guard and the shipped key disagree about the counted rows"


def test_repeat_guard_never_fires_above_its_own_placement(tmp_path):
    """repeat_guard_never_fires_above_its_own_placement — three identical calls to a system
    whose ADAPTER FAILS TO LOAD produce NO `GatherDeadEnd` and no trip row: the load-error
    branch records its row from `_grant_check`, ABOVE M2, so no such call ever reaches the
    repeat check, and two exit-2 rows mark the system DOWN so the third is answered by the
    infra breaker's down-message in any case. The `circuit_breaker` owns this shape end to
    end. Because no such call can reach the guard, its rows are outside the counted domain
    (`counted_domain_excludes_validate_path_rows`) and a REPLAY over this run's own table must
    reach the same verdict the live run did — at any threshold, including the N = 2 the two
    recorded rows would otherwise satisfy. Positive control:
    `repeat_trips_on_third_identical_request`, the same three identical calls against a
    loadable adapter, which DOES trip."""
    r = _run(
        tmp_path / "run", verbs=unloadable_adapter(tmp_path / "tree"), run_id="d807-loaderr",
        turns=[
            q("elastic", "probe", {"native_query": "FROM logs"}),
            q("elastic", "probe", {"native_query": "FROM logs"}),
            q("elastic", "probe", {"native_query": "FROM logs"}),
            DONE,
        ])
    rows = r.own_rows
    assert len(rows) >= 2, "the load-error branch stopped recording its rows"
    assert {row["exit_code"] for row in rows} == {2}, \
        "a load-error call was recorded as anything other than the infra fault it is"
    assert all(row["exit_code"] != 64 for row in rows), "the guard wrote a trip row above its placement"
    assert circuit_breaker.is_tripped(r.run_dir, "elastic") is True
    assert r.gather.calls == 4, "a GatherDeadEnd ended the lead where the infra breaker owns it"
    assert INCOMPLETE_IDIOM not in r.summary()
    assert _replay(rows, threshold=2) == [], \
        "replay tripped on rows `_grant_check` wrote above M2 — live and replay disagree"


def test_repeat_trip_empty_params_is_its_own_domain_member(tmp_path):
    """repeat_trip_empty_params_is_its_own_domain_member — `{}` is a real, frequent call, not
    a coercion fallback: 8 of GATHER_DEF's 28 granted (system, verb) pairs declare a literally
    EMPTY parameter set (all seven health-checks plus identity.list-roles, P-e executed), so
    for them `{}` is the only call there is. `repeat_trip.domain.distinguished[{}]` is
    exercised as its own domain member — an empty-params request counts and trips like any
    other, with no carve-out, so N = 3 is a permanent two-call-per-lead ceiling for such a
    verb. The risk is accepted and named: a health-check reads as a plausibly legitimate
    re-poll of changed system state."""
    # rejected: exempting parameterless verbs — a per-verb exception the doc never proposes,
    #   a hole a repeating lead can sit in indefinitely, and verb knowledge the guard
    #   otherwise has none of (N2: "have I sent this exact request before, nothing more").
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


def test_lead_repository_reads_the_trip_row_unchanged(tmp_path):
    """lead_repository_reads_the_trip_row_unchanged — `lead_repository.load_queries` is a
    reader of `executed_queries` this change does not move, and it must keep reading: after a
    trip, `joined` returns the lead with all three rows in seq order, the trip row's
    `raw_ref` resolves to a real on-disk payload, `stage_tables` copies it into the learning
    corpus unfiltered, and `repeat_trip` over the STAGED copy reaches the identical verdict —
    no path, inode or mtime enters the key or the count.

    #841 moved WHICH LIST the trip row joins into, and nothing else: it is a refusal record,
    not a query the defender ran, so `JoinedLead.queries` no longer holds it and
    `JoinedLead.observations` does. Every fact this test was written to protect is asserted
    below through `.rows`, which is the seq-ordered remerge — the row is not dropped, its
    payload is still reachable to the join surface, staging is still byte-unfiltered, and the
    replay verdict is still identical."""
    rec = VerbRecorder()
    r = _run(tmp_path / "src", verbs=elastic_ok(rec), run_id="d807-repo", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    leads = [
        lead for lead in lead_repository.joined(r.run_dir)
        if lead.lead_id not in RESERVED_LEAD_IDS
    ]
    assert [lead.lead_id for lead in leads] == [LEAD]
    rows = leads[0].rows
    assert [qr.seq for qr in rows] == [0, 1, 2]
    # #841's split, on the one lead that has both populations: the two calls that reached
    # elastic are the queries, the refusal is the observation.
    assert [qr.seq for qr in leads[0].queries] == [0, 1]
    assert [qr.seq for qr in leads[0].observations] == [2]
    trip = rows[2]
    assert trip.query_id == REPEAT_TRIP_QUERY_ID
    assert trip.observation
    assert trip.exit_code == 64
    assert trip.error_class == "agent-fixable"
    assert trip.raw_ref is not None, "the trip row's payload is unreachable to the join surface"
    assert trip.raw_ref.is_file()

    dst = tmp_path / "staged"
    lead_repository.stage_tables(r.run_dir, dst)
    assert read_jsonl_rows(dst / "executed_queries.jsonl") == r.rows
    assert _replay(read_jsonl_rows(dst / "executed_queries.jsonl")) == _replay(r.rows)


def test_counted_domain_excludes_validate_path_rows(tmp_path):
    """counted_domain_excludes_validate_path_rows — the counted domain is EXACTLY the rows THE
    GUARD COULD ITSELF HAVE REFUSED: rows written at or below M2. A row written ABOVE M2 is
    never an occurrence of the request it was trying to be, live or on replay, and three
    writers sit up there. (i) `wrap_tool_validate` — the fifth `_record` site, which fires
    precisely when one of the identity fields is unreadable and builds identity from the RAW
    pre-validation arguments. (ii) `_grant_check`'s non-`GRANTED`/unresolvable branch, which
    records an exit-64 row and raises `ModelRetry` before the guard is reached. (iii)
    `_grant_check`'s adapter-load-error branch, which records an exit-2 row (driven by
    `repeat_guard_never_fires_above_its_own_placement`, which pins the replay verdict over its
    own table). Two calls the argument schema turned back under a key byte-identical to a
    genuine one do NOT refuse the genuine third call, so O3 ("the guard never refuses a call
    that differs from its predecessors") holds by construction. THE REASON THE DOMAIN IS THIS
    NARROW: `repeat_guard_never_fires_above_its_own_placement` pins that no such call can ever
    reach the guard, so counting its rows would let the replay oracle report a trip no live run
    can produce — the divergence `trip_row_is_itself_an_occurrence_on_replay`'s own
    justification forbids, and the only argument the artifact gives for why the trip row itself
    counts. Every arm therefore asserts the LIVE verdict and the REPLAY verdict over the same
    table. P-a, an executed break-attempt over all five rejection shapes, found NO discriminator
    among the twelve frozen keys, so an above-M2 row must carry a sentinel identity the guard
    skips: that sentinel is production work this test only observes, and it must live INSIDE
    the twelve (`set(row) == ROW_KEYS` is asserted on every such row here, so a thirteenth key
    is not an available implementation).

    WHAT THIS TEST NO LONGER SAYS (#826 item 4). Its second arm used to pin that three
    identical UNRESOLVABLE-verb calls end the lead nowhere — `gather.calls == 4`, no incomplete
    idiom — under `unresolvable_verb_repeat_loops_are_out_of_scope`, the non-obligation #807
    recorded rather than leaving the gap silent. That non-obligation was discharged by the
    follow-up it was filed against: those loops are now owned by the COMPANION guard, at their
    own placement, over their own domain. The narrowing this test exists to pin is UNCHANGED
    and is the whole point of the arm as rewritten — M2's guard still refuses none of them,
    and `_replay` over their table still reports no trip. What changed is only that "M2 does
    not own this" stopped meaning "nobody does". The first arm is untouched: two rejections
    are below threshold, so the corrected third call still executes.

    Positive control on the same address under the complementary condition: replace the two
    rejections with two genuine executions of the same request and the very same third call IS
    refused — by M2, whose own domain those rows are in."""
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
        "the validate-path row's sentinel identity was added as a thirteenth key"
    assert set(rows[1]) == ROW_KEYS, \
        "the validate-path row's sentinel identity was added as a thirteenth key"
    assert rows[2]["exit_code"] == 0, "a call the argument schema turned back was counted as an occurrence"
    assert len(rejected_rec.calls) == 1, "the genuine third call never reached the backend"
    assert INCOMPLETE_IDIOM not in rejected.summary()
    assert _replay(rows) == [], \
        "the replay oracle counted validate-path rows the live guard skipped — they disagree"

    # `_grant_check`'s unresolvable branch: an UNDECLARED verb records its own exit-64 row and
    # raises ModelRetry, all strictly above M2. Three identical such calls are a repeat group
    # under (lead_id, system, verb, canonical(params)) and M2 can refuse none of them — so
    # `_replay`, M2's own oracle, must report no trip over their table either, or the oracle
    # overstates M2's reach. This is the shape the fitted corpus cannot expose: its 6 exit-64
    # rows sit under distinct keys, so no group of >= 3 at one key exists in any recorded run
    # (RF-J2's blind quadrant).
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
        "the above-M2 sentinel identity was added as a thirteenth key"
    assert grant_rec.calls == [], "an unresolvable verb reached the backend"
    assert _replay(grant_rows) == [], \
        "M2's oracle trips on a repeat M2 can never refuse — live and replay disagree"
    # The narrowing above is what this test pins; the stop below belongs to the OTHER guard,
    # and is asserted here so the two verdicts stay recorded against the same table rather
    # than in two suites that could drift into contradicting each other.
    assert unresolvable.gather.calls == 3, \
        "the third identical rejection did not end the lead — the companion guard is silent"
    assert INCOMPLETE_IDIOM in unresolvable.summary()
    assert _replay_rejections(grant_rows) == [(LEAD, 2)], \
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


def test_trip_row_is_itself_an_occurrence_on_replay(tmp_path):
    """trip_row_is_itself_an_occurrence_on_replay — the trip row is written from inside
    `wrap_tool_execute`, so it is one row like any other and DOES count toward a later check
    of the same key in the same lead. Live this is unreachable (M3 terminates the lead), so it
    bites only on replay — and it has to, or a replay of a recorded table stops matching the
    live run it replays. Driven over a REAL trip row produced by a real run, not a
    hand-written one."""
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-triprow", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    rows = r.own_rows
    trip = rows[2]
    assert trip["exit_code"] == 64, "no trip row was produced, so the premise is vacuous"

    key = {"system": "elastic", "verb": "query", "params": {"native_query": "FROM logs"}}
    assert repeat_trip([rows[0]], LEAD, **key) is None
    with_trip = repeat_trip([rows[0], trip], LEAD, **key)
    assert with_trip is not None, "the trip row was skipped, so a replay drifts from the live run"
    assert with_trip.occurrence == REPEAT_THRESHOLD

    assert _replay(rows) == [(LEAD, 2)], "the replay of this run's own table misses its own trip"


def test_repeat_key_normalizes_the_live_call_to_its_stored_form(tmp_path):
    """repeat_key_normalizes_the_live_call_to_its_stored_form — the guard converts the LIVE
    call to its stored form (`_json_safe_params`, then `request_key`) before keying, so
    `repeat_trip` is literally one function over one input shape and the predicate O1's
    obligations are measured with is the predicate that runs. Probed disagreement this
    closes: a live `{"threshold": nan}` keys as `NaN` while the row the same call wrote holds
    `"nan"`, so without the normalisation a repeated non-finite param never recognises its own
    prior rows and never trips. The stored form here is produced by the PRODUCTION transform,
    not restated, so the test re-probes the real round trip on every run."""
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


def test_trip_row_survives_the_learning_extractors_payload_gate(tmp_path):
    """trip_row_survives_the_learning_extractors_payload_gate — the trip is written through
    the existing `_record` path, so `lead_extraction` — O4's named audience — really sees it:
    `payload_status` computes to "error", a valid enum member, so `extract_from_joined` cannot
    raise LeadAuthorError and kill the run's whole lead-author pass; and the EMPTY
    `gather_raw/{lead}/{seq}.json` sidecar is still written, so the row is not dropped by the
    payload-existence gate that runs BEFORE the error_class filter — which is precisely the
    blind spot O4 exists to close."""
    # rejected: a bespoke trip-row writer that skips _persist_payload — `payload_path: null`
    #   is its natural shape, and such a row is invisible to extract_from_joined: O4 satisfied
    #   on paper and defeated in fact for its named audience.
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-extract", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
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
    """screen_refused_repeats_count_toward_the_trip — M2 places the guard ABOVE `_screen`, so
    the guard owns the repeats it can see: three identical calls that each fail the verb's own
    parameter check are counted, and the third ends the lead with a `GatherDeadEnd` instead of
    earning a third identical corrective ModelRetry the model has already ignored twice. The
    trip row is therefore written before any verb looked at the call's parameters. Not
    discharged by replay — the fitted corpus holds zero repeat groups whose calls failed, so
    this drives the real path."""
    rec = VerbRecorder()
    bad = {"native_query": "FROM logs", "nosuch_param": 1}
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-screen", turns=[
        q("elastic", "query", bad), q("elastic", "query", bad), q("elastic", "query", bad), DONE,
    ])
    assert rec.calls == [], "a param-invalid call reached the backend"
    assert r.gather_saw.count("unknown param(s)") == 2, \
        "the screen must still teach on the first two; only the third is a dead end"
    assert r.gather.calls == 3, "the third refusal was a ModelRetry, not a dead end"
    rows = r.own_rows
    assert len(rows) == 3
    assert [row["exit_code"] for row in rows] == [64, 64, 64]
    assert rows[2]["params"] == bad, "the trip row did not record the request as the lead sent it"
    assert INCOMPLETE_IDIOM in r.summary()


def test_concurrent_identical_siblings_still_stop_the_lead(tmp_path):
    """concurrent_identical_siblings_still_stop_the_lead — `gather_dispatch` drives
    `query_tool` CONCURRENTLY (two query calls in one gather turn is a pinned existing
    scenario), and the guard's read sits before `handler(args)` and outside `_seq_lock`. That
    placement is WHY the spec states N as a FLOOR rather than an exact cap — but the floor is
    a CONSTRAINT ON WHAT MAY BE ASSERTED, carried by the
    `repeat_threshold_is_a_floor_not_an_exact_cap` clause, and it is not something this test
    demonstrates: the overshoot needs two same-key siblings to read one stale count, an
    interleaving neither this run nor the fitted corpus produces. What this test DOES
    demonstrate is the obligation that survives concurrency: with two prior occurrences on the
    key, a turn issuing two identical siblings STOPS THE LEAD — neither sibling reaches the
    backend, a trip row lands in `executed_queries`, and main receives the dead end. It
    deliberately asserts NO exact row count and no exact trip seq: under concurrency the spec
    pins neither."""
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
    assert r.gather.calls == 3, "the concurrent trip did not end the lead"
    assert INCOMPLETE_IDIOM in r.summary()
    assert any(row["exit_code"] == 64 for row in r.own_rows), "no trip row was written at all"
    assert [row["exit_code"] for row in r.own_rows[:2]] == [0, 0]


def test_gather_dead_end_payload_binds_reason_and_escape(tmp_path):
    """gather_dead_end_payload_binds_reason_and_escape — `GatherDeadEnd`'s payload has both
    its slots BOUND: a `reason` naming this trip's own repeated request, and an `escape`
    that is ONE fixed, system-agnostic sentence, identical on every trip. The escape states
    the structural fact and hands the decision to main; it names no system and no verb,
    because a per-system escape table would make the guard a progress oracle — and the one
    concrete escape the issue proposed was already the path one of the two recorded repeat
    leads was repeating on."""
    # rejected: a per-system escape table derived from skills/{system}/execution.md — N2
    #   forbids it by name, and it would have been WRONG on reviewer-measure-0807 (C9).
    # rejected: dropping `escape` and carrying only `reason` — it changes the declared
    #   two-part payload and removes the only part aimed at what main should do next.
    assert REPEAT_ESCAPE.strip(), "the escape slot is bound to nothing"
    # All SEVEN granted systems, off P-e's executed census of GATHER_DEF's 28 (system, verb)
    # pairs — `change-mgmt` is a granted system like the other six.
    for system in ("elastic", "cmdb", "identity", "ticket", "threat-intel", "host-state",
                   "change-mgmt"):
        assert system not in REPEAT_ESCAPE, f"the escape names {system} — it is not system-agnostic"
    # …and no VERB either: the demand's outcome is that the escape names no system AND no verb.
    # These are real verb names off the same census and off the corpus (`esql` is 0807 l-001's
    # 37 calls, C9). Bare `query` is deliberately absent from this tuple: it is a granted verb
    # name AND an ordinary English word a system-agnostic sentence may legitimately use, so
    # banning it would fail an escape that names nothing. The discriminating check for that
    # residue is the identity of the escape across the two trips driven below, on two different
    # (system, verb) pairs.
    for verb in ("health-check", "list-roles", "esql", "sshd-auth-window", "host-trust-edges"):
        assert verb not in REPEAT_ESCAPE, f"the escape names {verb} — it is not verb-agnostic"

    rec = VerbRecorder()
    r = _run_two_leads(
        tmp_path, verbs=two_systems(rec), run_id="d807-escape",
        first=(LEAD, "elastic"), second=(SIBLING, "cmdb"), turns=[
            q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
            q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
            q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
            q("cmdb", "host-trust-edges", {"host": "db-1"}),
            q("cmdb", "host-trust-edges", {"host": "db-1"}),
            q("cmdb", "host-trust-edges", {"host": "db-1"}),
            DONE,
        ])
    first, second = r.summary(LEAD), r.summary(SIBLING)
    assert REPEAT_ESCAPE in first
    assert REPEAT_ESCAPE in second
    assert "sshd-auth-window" in first
    assert "host-trust-edges" in second
    assert "host-trust-edges" not in first, "the reason slot is not this trip's own request"
    assert "sshd-auth-window" not in second


def test_dead_end_message_does_not_echo_model_authored_params(tmp_path):
    """dead_end_message_does_not_echo_model_authored_params — the dead end names the request's
    IDENTITY (`system`, `verb`, the earlier seq) and never echoes the model-authored `params`
    text: an unbounded, attacker-influenced fragment must not cross into main's context on a
    refusal path, by way of either surface the dead end reaches — the string written into
    `model_context` or the `gather_summaries/{lead_id}.md` account that survives compaction.
    Positive control, the shape a redaction demands: the very same bytes ARE recoverable
    through the sanctioned path — they are in the queries-table row's `params` and
    `raw_command`, which is where main is pointed to find the exact request from
    (lead_id, seq)."""
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
    """dead_end_message_names_the_earliest_matching_seq — when several rows share the key, the
    message names the EARLIEST matching row's seq, so it is deterministic under duplicate or
    non-monotonic seqs and it names the occurrence that started the repetition rather than the
    one a concurrent write can shift. Driven over a table whose two matching rows were written
    out of order (seq 9 first, then seq 5): the message names seq 5."""
    rec = VerbRecorder()
    r = _run(
        tmp_path, verbs=named_verbs(rec), run_id="d807-earliest",
        seed=[
            _row(LEAD, 9, "elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
            _row(LEAD, 5, "elastic", "sshd-auth-window", {"native_query": "FROM logs"}),
        ],
        turns=[q("elastic", "sshd-auth-window", {"native_query": "FROM logs"}), DONE],
    )
    summary = r.summary()
    assert INCOMPLETE_IDIOM in summary, "no dead end happened"
    assert "seq 5" in summary, "the message did not name the earliest matching occurrence"
    assert "seq 9" not in summary, "the message named the latest matching occurrence"

    hit = repeat_trip(
        lead_rows(r.run_dir, LEAD)[:2], LEAD, system="elastic", verb="sshd-auth-window",
        params={"native_query": "FROM logs"},
    )
    assert hit is not None
    assert hit.first_seq == 5


def test_dead_end_message_states_the_leads_executed_query_count(tmp_path):
    """dead_end_message_states_the_leads_executed_query_count — the message states how many
    queries this lead executed BEFORE the stop, so the inherited idiom's "reason from what was
    captured" stops pointing at nothing and main can tell "this lead found things and then
    looped" from "this lead never got anywhere". The guard already has the number from its own
    table read, so this costs no new I/O. DELIBERATELY BEYOND O2's literal oracle, which names
    only the repeated request and the structural cause: the widening is the human's, recorded
    here as such. A lead that executed four queries before repeating its second one for the
    third time names 4 — not 5, which would count the refused call itself."""
    rec = VerbRecorder()
    key = {"native_query": "FROM logs"}
    r = _run(tmp_path, verbs=named_verbs(rec), run_id="d807-count", turns=[
        q("elastic", "sshd-auth-window", {"native_query": "FROM alpha"}),
        q("elastic", "sshd-auth-window", key),
        q("elastic", "sshd-auth-window", {"native_query": "FROM beta"}),
        q("elastic", "sshd-auth-window", key),
        q("elastic", "sshd-auth-window", key),
        DONE,
    ])
    assert len(rec.calls) == 4, "the lead did not execute the four queries this assertion counts"
    summary = r.summary()
    assert INCOMPLETE_IDIOM in summary
    assert "seq 1" in summary, "the message names the wrong earlier occurrence"
    assert re.search(r"\b4\b", summary), \
        "the message does not state how many queries the lead executed before the stop"
    assert not re.search(r"\b5\b", summary), \
        "the count includes the refused call — it must be the queries executed BEFORE the stop"


def test_trip_row_detail_names_the_repetition(tmp_path):
    """trip_row_detail_names_the_repetition — the trip row announces itself as a repeat in the
    row's EXISTING detail field, `payload_digest`, which `_record` already fills for a non-zero
    exit as `f"exit={code}; {detail[:160]}"`. Without it the trip row is byte-shaped like a
    bad-parameter refusal — same exit, same error_class, same empty payload, same twelve keys
    — and O4's named audience, the learning loop, reads "fix this parameter" off it. Contrast
    asserted in the same run: an ordinary `_screen` parameter refusal's detail names the
    parameter and never the repetition."""
    rec = VerbRecorder()
    r = _run(tmp_path, verbs=elastic_ok(rec), run_id="d807-detail", turns=[
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        q("elastic", "query", {"native_query": "FROM logs", "nosuch_param": 1}),
        q("elastic", "query", {"native_query": "FROM logs"}),
        DONE,
    ])
    rows = r.own_rows
    assert len(rows) == 4
    refusal, trip = rows[2], rows[3]

    assert refusal["payload_digest"].startswith("exit=64; ")
    assert "unknown param(s)" in refusal["payload_digest"]
    assert "repeat" not in refusal["payload_digest"].lower(), \
        "the contrast is gone: a parameter refusal already claims to be a repeat"

    assert trip["payload_digest"].startswith("exit=64; ")
    assert "repeat" in trip["payload_digest"].lower(), \
        "the trip row is indistinguishable from a bad-parameter refusal"
    assert "seq 0" in trip["payload_digest"], \
        "the detail does not say which earlier call the trip counted"
    assert len(trip["payload_digest"]) <= len("exit=64; ") + 160, \
        "the detail is truncated at 160 chars by _record; it must fit"
    assert set(trip) == ROW_KEYS, "the repetition was named by adding a thirteenth key"


def test_repeat_of_a_failing_request_still_trips(tmp_path):
    """repeat_of_a_failing_request_still_trips — `repeat_trip.identity` carries no outcome
    component: M1 counts occurrences of a REQUEST, not of a success, and the guard's rationale
    applies at least as strongly to a request that keeps failing identically. Three identical
    calls whose verb raises an agent-fixable upstream fault each write their own row and the
    third is refused — and because those rows are exit 1, not an infra exit, the
    `circuit_breaker` never opens and cannot answer first. Not discharged by replay: the
    fitted corpus contains zero failing-repeat groups."""
    rec = VerbRecorder()
    r = _run(
        tmp_path, verbs=raising(rec, UpstreamFault("no matching documents")),
        run_id="d807-failing", turns=[
            q("elastic", "probe", {}), q("elastic", "probe", {}), q("elastic", "probe", {}), DONE,
        ])
    assert len(rec.calls) == 2, "the third identical failing request still reached the backend"
    rows = r.own_rows
    assert [row["exit_code"] for row in rows] == [1, 1, 64]
    assert r.breaker == {}, "an agent-fixable failure opened the infra breaker and answered first"
    assert INCOMPLETE_IDIOM in r.summary()
