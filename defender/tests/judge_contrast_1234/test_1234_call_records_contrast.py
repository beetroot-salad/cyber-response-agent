"""#1234 slice `call_records_contrast` — one identity per call on both call records (A12), the
contrast row built from them (design M2, A2, A14), and fail-closed writes of either record.

Every scenario here runs the REAL path (I-10, 45-dispositions-drift): the launcher over the
#1224 fixture tenant with real pre-flight, each sibling the real `run.main --tenant T
--episode <id> --world L` driven in-process (`S.real_family`), so both call records are written
by the real writers — the registry's `decide_call` / `_deliver` / `_record_beside`, the query
tool's `append_query_row` / `_record_denied`, the shim's `_record_shim_failure`, and the seed's
`_inherit_evidence`. A test reads the call id OFF the rows; it never plants one.

THE DEFAULT SHAPE (observed at 463833df by this writer's smoke runs). The source run made three
pre-branch calls on the held lead `l-001` (idp `Q1`, edr `Q2`, siem-x `L3`) and one post-branch
call (`QP`); `capture_sentinel` adds J3's inherited `∅.denied` row. Every sibling's table starts
with that seeded prefix, byte-identical in every run (JQ-01 (i)); its own rows follow. World
`b`'s oracle alters `QP`; `edr lookup` is withheld, so the grant refuses it (a `refused` ledger
row and a `∅.denied` table row).

HOW FAULTS ENTER (author.md's hierarchy; nothing is monkey-patched):
  * a live outage is the estate's real `faults.UpstreamFault` (`Estate.fail`), GA-40;
  * an adapter that cannot load is the adapter file importing a module that does not exist —
    p32's own shape (`test_jp01_scope_adapter_fault`, JP-01/JP-02 "fault" rows);
  * a failed write of a call record is a DIRECTORY planted at the record's name — by the
    estate's adapter just before it answers (`Estate1234.break_write`), or by `_Between` just
    before the gather model's next call. AP-01 observed the lost ledger write (swallowed for
    error and refusal rows, an infra fault for a delivered row); JP-02 `s_tw_denied` the lost
    `∅.denied` table write; the survey's smoke the table write raising `NotPlainEntry` out of
    `run.main`;
  * "the estate recovers between two identical calls" is `_Between` re-answering the key —
    AP-01a's and JP-02 `s_lw_realerror`'s own shape;
  * where a shape cannot be produced by one run in a deterministic order (A32's ledger order
    against table order — AP-14 observed it only under an injected stall), the archived file is
    permuted with `S.rewrite_jsonl` after the real writers wrote it: real rows, real ids, one
    order changed. Likewise A30's oracle row with no table row.

COINED NAMES. F2 leaves the contrast row's fields to the implementer. They are spelled ONCE, in
`S.COINED` (`ctx.*`, `contrast.*`, `entry.*`, `cut.*`); the accessors (`_contrast`, `_field`,
`_numbers`, `_focus_calls`, `_reference_calls`, `_entry_at`) are their only readers here.
A call number is the table row's 0-based line index — the numbering `S.table_ptr` cites.
"""
from __future__ import annotations

import ast
import contextlib
import json
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import pytest

from defender.tests.judge_contrast_1234 import _spec1234 as S

# --------------------------------------------------------------------------------------
# Names: the contrast row's fields live in `S.COINED` (`ctx.*`, `contrast.*`, `entry.*`,
# `cut.*`); main's own cut-short mark in `S.EXISTING`.
# --------------------------------------------------------------------------------------

CUT_SHORT = S.EXISTING["row.cut_short"]

# --------------------------------------------------------------------------------------
# Scenario vocabulary.
# --------------------------------------------------------------------------------------

#: Fresh keys no recording holds, so they reach the estate's adapter (Estate1234's docstring).
BOB = S.query_params("user:bob")
CAROL = S.query_params("user:carol")
DAVE = S.query_params("user:dave")
#: The in-test positive control of "no further call is served": a fresh key the estate answers,
#: asked BEFORE the failing call, which its call log must show it received.
ERIN = S.query_params("user:erin")
REP = S.query_params("user:rep")
SENT_TWO = {"entity": "sent-two"}
#: The second withheld verb (a ledger-only denial needs a withheld call after the door closed).
IDP_LOOKUP = {"entity": "alice"}
WITHHELD = (("edr", "lookup"), ("idp", "lookup"))
#: The source run's pre-branch calls on the held lead (`S.source_calls(post=False)`).
PRE_BRANCH = len(S.source_calls(post=False))
LEDGER_GLOB = "*/served/*.{label}.jsonl"
TABLE_GLOB = "*/runs/*-{label}/executed_queries.jsonl"
#: `Estate1234.break_write` patterns (filled per call by the adapter).
BREAK_LEDGER = "{episode}/served/*.{label}.jsonl"
BREAK_TABLE = "{run_dir}/executed_queries.jsonl"


def q(system: str, verb: str, params: Mapping[str, Any]) -> Any:
    return S.query_turn(system, verb, params)


def reject_turn() -> Any:
    """A call the query tool rejects before any system is reached (an unknown verb): an exit-64
    table row, no ledger row (JP-02 "TABLE-ONLY rows")."""
    return q("idp", "no_such_verb", {})


class _Between:
    """One gather-model turn preceded by a host-side action fired when the model ASKS for it —
    after the previous call's two records were written (ledger before table, JP-01), before this
    call is made. `make` builds the turn lazily (a reducer turn needs the run's own payload
    path). The action only injects: a fault planted, or the estate recovering (AP-01a,
    JP-02 `s_lw_realerror`). It decides nothing."""

    def __init__(self, turn: Any = None, *, before: Callable[[], Any] | None = None,
                 make: Callable[[], Any] | None = None) -> None:
        self._turn, self._before, self._make, self._fired = turn, before, make, False
        self.text = ""

    @property
    def tool_calls(self) -> list:
        if not self._fired:
            self._fired = True
            if self._before is not None:
                self._before()
        return (self._make() if self._make is not None else self._turn).tool_calls


def _run_dir(label: str) -> Path:
    return next(p for p in S.episodes_root().glob(f"*/runs/*-{label}") if p.is_dir())


def reducer_make(label: str = "b") -> Callable[[], Any]:
    """A failing terminal reduce (`cat <payload> | defender-sql …`) over the newest payload this
    run wrote: the real `_record_shim_failure` appends a `∅.bash-shim` row (observed in a
    sibling by this writer's smoke: exit 69 `EXIT_NO_RUNTIME`, recorded infra; where duckdb is
    installed, the missing table fails the reduce the same way)."""
    def make() -> Any:
        raw = _run_dir(label) / "gather_raw" / "l-001"
        payload = max(raw.glob("*.json"), key=lambda p: int(p.stem))
        return S.S24.replay_harness().Turn(tool_calls=[("bash", {
            "command": f"cat {payload} | defender-sql 'SELECT * FROM no_such_table_1234'"})])
    return make


def reducer_turn(label: str = "b") -> _Between:
    return _Between(make=reducer_make(label))


def plant_dir_at(glob: str, label: str = "b") -> Callable[[], None]:
    """The host action: the record at `glob` (this world's) becomes a directory, so the real
    writer's next open of it fails (mode bits cannot do it as root)."""
    def plant() -> None:
        for path in S.episodes_root().glob(glob.format(label=label)):
            S.plant_dir(path)
    return plant


def altering(*markers: str, name: str = "oracle-b") -> Any:
    """World b's sibling oracle: each call whose request carries one of `markers` is served the
    forged row (claim adds fg-b-1 for f1, as `S.altering_oracle` does on QP); every other call
    passes unchanged."""
    s24 = S.S24
    return S.Routed({m: s24.oracle(s24.submit(S.CHANGED_B, s24.claim(
        added=[s24.added("fg-b-1", "f1")]))) for m in markers},
        default=S.passing_oracle(), name=name, last_wins=True)


def j3(src: Path) -> None:
    """J3's inherited `∅.denied` row in the source (one pre-branch sentinel)."""
    S.capture_sentinel(src)


def j3_and_lead_zero(src: Path) -> None:
    """J3's row plus a lead-zero row (`l-000`, lead zero's own system `elastic`) in the source;
    the real seed copies both into every sibling (this writer's smoke: `l-000` is held)."""
    S.capture_sentinel(src)
    S.capture_sentinel(src, lead="l-000", seq=0, system="elastic", verb="query",
                       query_id="elastic.query", exit_code=0,
                       params={"native_query": "FROM alerts"})


def estate(tmp_path: Path, withheld: Iterable[tuple[str, str]] = (("edr", "lookup"),)) -> Any:
    return S.Estate1234(tmp_path / "estate", withheld=tuple(withheld))


def launch(tmp_path: Path, est: Any = None, *,
           after_source: Callable[[Path], None] | None = j3, calls: Any = None,
           **worlds: Any) -> Any:
    """`S.real_family` over `est` (default: edr lookup withheld) with per-world scripts and
    J3's sentinel in the source unless told otherwise (`after_source=None`: none)."""
    return S.real_family(tmp_path, dict(worlds),
                         estate=est if est is not None else estate(tmp_path),
                         after_source=after_source, calls=calls)


# --------------------------------------------------------------------------------------
# Locating rows (the subjects) in the archived records.
# --------------------------------------------------------------------------------------


def lines(rows: list[dict], params: Mapping[str, Any], *, query_id: str | None = None) -> list[int]:
    """Line indices of `rows` whose params are `params` (and query id, when given)."""
    want = S.canonical(params)
    return [i for i, r in enumerate(rows)
            if isinstance(r.get("params"), dict) and S.canonical(r["params"]) == want
            and (query_id is None or r.get("query_id") == query_id)]


def line_where(rows: list[dict], **match: Any) -> int:
    """The one line index whose row carries every `match` column."""
    hits = [i for i, r in enumerate(rows) if all(r.get(k) == v for k, v in match.items())]
    assert len(hits) == 1, f"fixture: expected one row with {match}, got lines {hits}"
    return hits[0]


def ledger_index(rows: list[dict], params: Mapping[str, Any], source: str) -> int:
    hits = [i for i, r in enumerate(rows) if r.get("source") == source
            and isinstance(r.get("params"), dict)
            and S.canonical(r["params"]) == S.canonical(params)]
    assert len(hits) == 1, f"fixture: expected one {source} ledger row for {params}, got {hits}"
    return hits[0]


def own(rows: list[dict], inherited: int) -> list[dict]:
    """This run's own table rows: those after the seeded prefix."""
    return rows[inherited:]


def estate_calls(built: Any, params: Mapping[str, Any]) -> list[dict]:
    """Calls the estate's adapter RECEIVED with `params` (the wire, as the tenant saw it)."""
    want = S.canonical(params)
    return [c for c in built.est.calls() if S.canonical(c["params"]) == want]


# --------------------------------------------------------------------------------------
# The coined accessors — this file's only readers of the contrast row's coined names.
# --------------------------------------------------------------------------------------


def _get(obj: Any, key: str) -> Any:
    """`obj[key]` or `obj.key`; a missing coined field is an assertion naming it (render's
    result lacks the contrast row's field), never a bare `KeyError`/`AttributeError`."""
    if isinstance(obj, Mapping):
        assert key in obj, f"{type(obj).__name__} carries no {key!r} (COINED): {sorted(obj)}"
        return obj[key]
    assert hasattr(obj, key), f"{type(obj).__name__} carries no {key!r} field (COINED)"
    return getattr(obj, key)


def _contrast(ctx: Any, run: str) -> Any:
    return _get(_get(ctx, S.COINED["ctx.contrast"]), run)


def _field(row: Any, name: str) -> Any:
    return _get(row, S.COINED[name])


def _numbers(entries: Iterable[Any]) -> list[Any]:
    return [_get(e, S.COINED["entry.call"]) for e in entries]


def _focus_calls(ctx: Any) -> list[Any]:
    return list(_get(ctx, S.COINED["ctx.focus_calls"]))


def _reference_calls(ctx: Any) -> Any:
    return _get(ctx, S.COINED["ctx.reference_calls"])


def _entry_at(entries: Iterable[Any], call: Any, source: Any = ...) -> list[Any]:
    """The entries of a list at call number `call` (and ledger decision `source`)."""
    return [e for e in entries if _get(e, S.COINED["entry.call"]) == call
            and (source is ... or _get(e, S.COINED["entry.source"]) == source)]


def _blocked_flags(entries: Iterable[Any], call: Any) -> list[Any]:
    return [_get(e, S.COINED["entry.blocked"]) for e in _entry_at(entries, call)]


def _counts(row: Any) -> dict[str, Any]:
    counts = _field(row, "contrast.counts")
    return {str(k): counts[k] for k in counts}


def _cut_short_reason(row: Mapping[str, Any]) -> str:
    """The world row's ungradable reason, once the row is marked cut short."""
    assert row.get(S.EXISTING["row.ungradable"]) is True, f"the world was graded: {row}"
    assert row.get(CUT_SHORT), f"the world is not cut short: {row}"
    return str(row.get(S.COINED["row.ungradable_reason"]) or "")


# ======================================================================================
# The contrast row (render -> JudgeContext), over real records.
# ======================================================================================


def test_1234_contrast_row_names_the_first_altered_investigator_call(tmp_path: Path) -> None:
    """A run's contrast row names its first altered investigator call: the lowest post-branch
    query-table call number whose row joins by call id to an `oracle` ledger row of that run
    (A12); inherited rows (no id of this run) never pair; or it says there was none.

    render builds the JudgeContext from executed_queries and the served_ledger, joined on their
    identity (the host-written call id). The default triad: b's oracle alters QP (b's own row
    after the seeded prefix); a and c were served no altered answer. The seeded prefix holds an
    `idp query user:alice` row and J3's `∅.denied` row, and every sibling repeats both calls
    after the branch — the exact shape in which JQ-01 (iv) saw a key join steal the post-branch
    rows' ledger partners for the inherited rows. With the id join each post-branch row keeps
    its partner: nothing is unserved or unmapped, and b's refused ledger row joins its OWN
    `∅.denied` row, not J3's."""
    built = launch(tmp_path)
    inherited = PRE_BRANCH + 1
    rows_b = built.table_rows("b")
    qp_line = lines(rows_b, S.QP)[0]
    own_q1 = lines(rows_b, S.Q1)[1]
    j3_line, own_denied = lines(rows_b, S.DENIED_LOOKUP, query_id=S.DENIED_QUERY_ID)
    assert j3_line < inherited <= min(qp_line, own_q1, own_denied), "fixture: own rows follow"

    ctx = S.render_context(built, "b")
    b = _contrast(ctx, "b")
    assert _field(b, "contrast.first_altered") == qp_line, (
        "b's first altered call is its own QP row, numbered in its query table")
    for run in ("a", "c"):
        assert _field(_contrast(ctx, run), "contrast.first_altered") is None, (
            f"{run} was served no altered answer: its row says there was none")
    assert list(_field(b, "contrast.unserved")) == [], "an inherited row stole a post-branch partner"
    assert list(_field(b, "contrast.unmapped")) == []
    assert sorted(_numbers(_field(b, "contrast.blocked"))) == [j3_line, own_denied], (
        "b's refused ledger row joins its own ∅.denied row; J3's inherited row is listed apart")


def test_1234_contrast_row_counts_calls_leads_and_external_refusals(tmp_path: Path) -> None:
    """A run's contrast row says whether it was shown its facts (any oracle ledger row), names
    the leads that received altered answers, counts its calls by system and verb from the query
    table (inherited pre-branch rows counted as pre-branch calls in the shared baseline), lists
    its blocked calls (ledger refused/fault rows and J3's inherited ∅.denied row; outage
    real-error rows are listed as served with an error, not blocked), lists as unserved each
    table row carrying this run's call id with no ledger row (rejects, ∅.repeat-trip and
    ∅.bash-shim included, I-1), and as unmapped each ledger row whose id is in no table row; a
    sibling's seeded lead-zero row is inherited, not unserved (I-2).

    render reads executed_queries (its inherited rows seeded by _inherit_evidence) and the
    served_ledger into the JudgeContext. World b runs: a reject; a repeat of the inherited
    call; QP (altered); the withheld edr lookup (refused); an outage (BOB); a failing reduce
    (∅.bash-shim); three identical failing calls (the repeat guard trips: ∅.repeat-trip, and
    the door closes); then the withheld idp lookup, which the closed door leaves as a
    ledger-only refusal (JP-02 s_door, reproduced in this writer's smoke)."""
    est = estate(tmp_path, WITHHELD)
    est.fail("idp", "query", BOB, fault="UpstreamFault", detail="shard down")
    est.fail("idp", "query", REP, fault="UpstreamFault", detail="500 upstream")
    turns_b = [reject_turn(), q("idp", "query", S.Q1), q("idp", "query", S.QP),
               q("edr", "lookup", S.DENIED_LOOKUP), q("idp", "query", BOB), reducer_turn("b"),
               q("idp", "query", REP), q("idp", "query", REP), q("idp", "query", REP),
               q("idp", "lookup", IDP_LOOKUP), S.done_turn()]
    built = launch(tmp_path, est, after_source=j3_and_lead_zero,
                   b=S.RealWorld("b", turns=turns_b, oracle=S.altering_oracle()))
    inherited = PRE_BRANCH + 2
    rows = built.table_rows("b")
    lead_zero = line_where(rows, lead_id="l-000")
    j3_line, own_denied = lines(rows, S.DENIED_LOOKUP, query_id=S.DENIED_QUERY_ID)
    reject = line_where(rows, verb="no_such_verb")
    qp_line = lines(rows, S.QP)[0]
    bob = lines(rows, BOB)[0]
    shim = line_where(rows, query_id=S.BASH_SHIM_QUERY_ID)
    rep_failed = lines(rows, REP, query_id="idp.query")
    trip = lines(rows, REP, query_id=S.REPEAT_TRIP_QUERY_ID)
    assert max(lead_zero, j3_line) < inherited, "fixture: both sit in the seed"
    assert len(rep_failed) == 2, "fixture: the guard trips on the third"
    assert len(trip) == 1, "fixture: the guard trips on the third"
    door = [r for r in built.ledger_rows("b") if (r.get("system"), r.get("verb")) == ("idp",
                                                                                     "lookup")]
    assert len(door) == 1, "fixture: a ledger-only refusal"
    assert not lines(rows, IDP_LOOKUP), "fixture: a ledger-only refusal"

    ctx = S.render_context(built, "b")
    b = _contrast(ctx, "b")
    assert _field(b, "contrast.shown") is True
    assert list(_field(b, "contrast.altered_leads")) == ["l-001"]
    assert _field(b, "contrast.first_altered") == qp_line
    assert _counts(b) == {"idp.query": 7, "edr.query": 1, "siem-x.lookup": 1, "edr.lookup": 2,
                          "elastic.query": 1, "idp.no_such_verb": 1, "idp.bash": 1}, (
        "every row of the query table is counted by system and verb, the seeded rows included")
    assert Counter(_numbers(_field(b, "contrast.blocked"))) == Counter([j3_line, own_denied, None]), (
        "blocked: J3's inherited row, b's refused call, and the ledger-only refusal (no number)")
    assert sorted(_field(b, "contrast.errored")) == sorted([bob, *rep_failed]), (
        "the outage rows are served with an error")
    assert sorted(_field(b, "contrast.unserved")) == sorted([reject, shim, *trip]), (
        "rejects, ∅.bash-shim and ∅.repeat-trip carry b's id and no ledger row: unserved")
    assert lead_zero not in _field(b, "contrast.unserved"), "lead zero's seeded row is inherited"
    assert lead_zero in _field(b, "contrast.baseline")
    unmapped = list(_field(b, "contrast.unmapped"))
    assert [_get(e, S.CALL_ID) for e in unmapped] == [door[0][S.CALL_ID]]
    assert _numbers(unmapped) == [None]
    for run in ("a", "c"):
        ref = _contrast(ctx, run)
        assert _field(ref, "contrast.shown") is False
        assert list(_field(ref, "contrast.altered_leads")) == []
        assert _field(ref, "contrast.first_altered") is None


def test_1234_repeated_identical_call_joins_each_occurrence_by_its_call_id(tmp_path: Path) -> None:
    """When one (system, verb, params) call appears more than once in executed_queries.jsonl,
    each occurrence joins by its own call id to its own ledger row (A12): an errored attempt
    and its altered retry keep their own call numbers, and the contrast table carries no
    ambiguity flag (there is no repeat pairing).

    render joins executed_queries to the served_ledger on their identity, the call id, into the
    JudgeContext. World b calls CAROL twice (both answered) and BOB twice: the first BOB errors
    live, the estate recovers, and the retry is served the altered answer."""
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    est.fail("idp", "query", BOB, fault="UpstreamFault", detail="shard down")
    turns_b = [q("idp", "query", CAROL), q("idp", "query", CAROL), q("idp", "query", BOB),
               _Between(q("idp", "query", BOB),
                        before=lambda: est.answer("idp", "query", BOB, S.BASE_ANSWER)),
               S.done_turn()]
    built = launch(tmp_path, est, b=S.RealWorld("b", turns=turns_b, oracle=altering("user:bob")))
    rows = built.table_rows("b")
    carol, bob = lines(rows, CAROL), lines(rows, BOB)
    assert len(carol) == 2, "fixture: each identical call left two rows"
    assert len(bob) == 2, "fixture: each identical call left two rows"

    b = _contrast(S.render_context(built, "b"), "b")
    assert _field(b, "contrast.first_altered") == bob[1], "the retry keeps its own call number"
    assert sorted(_field(b, "contrast.errored")) == [bob[0]], "the errored attempt keeps its own"
    assert list(_field(b, "contrast.unserved")) == [], "each occurrence joined its own ledger row; none is left over on either side"
    assert list(_field(b, "contrast.unmapped")) == [], "each occurrence joined its own ledger row; none is left over on either side"
    names = [str(k) for k in (b if isinstance(b, Mapping) else vars(b))]
    assert not [n for n in names if "ambig" in n.lower()], f"an ambiguity flag survives: {names}"


def test_1234_retried_call_first_live_error_then_altered_answer(tmp_path: Path) -> None:
    """The host ledger owns what was served, read in full (no first-row-wins); the query table
    owns call order and numbering; the join is exact on the host-written call id carried by
    every ledger row and every table row of this run (A12). The live error and the altered
    retry are two calls with two ids, each joined to its own ledger row [real-error, altered]:
    shown-its-facts is true, the first altered call is the retry's call number, the first error
    is a counted real-error call (not a gap, A2), and the call list shows both.

    render reads the served_ledger and executed_queries (joined on their identity) into the
    JudgeContext's contrast row and the judged world's call list. World b asks BOB, gets the
    live system's error, the estate recovers, and the identical retry is served altered."""
    est = estate(tmp_path)
    est.fail("idp", "query", BOB, fault="UpstreamFault", detail="shard down")
    turns_b = [q("idp", "query", BOB),
               _Between(q("idp", "query", BOB),
                        before=lambda: est.answer("idp", "query", BOB, S.BASE_ANSWER)),
               S.done_turn()]
    built = launch(tmp_path, est, b=S.RealWorld("b", turns=turns_b, oracle=altering("user:bob")))
    first, retry = lines(built.table_rows("b"), BOB)
    assert [r["source"] for r in built.ledger_rows("b")] == ["real-error", "oracle"], (
        "fixture: the ledger holds both calls, the error first")

    ctx = S.render_context(built, "b")
    b = _contrast(ctx, "b")
    assert _field(b, "contrast.shown") is True
    assert _field(b, "contrast.first_altered") == retry
    assert first in _field(b, "contrast.errored"), "the first error is a counted real-error call"
    assert first not in _numbers(_field(b, "contrast.blocked")), "an outage is not a gap"
    calls = _focus_calls(ctx)
    assert len(_entry_at(calls, first, "real-error")) == 1, "the call list shows the error"
    assert len(_entry_at(calls, retry, "oracle")) == 1, "and the altered retry, numbered apart"


def test_1234_retried_call_first_fault_then_answered(tmp_path: Path) -> None:
    """A ledger `fault` row is a blocked call (A2): the faulted call is listed in the
    refusal-and-fault list and as a found gap with its count; the answered retry is a separate
    call with its own call id that is not blocked and shows its served row. Both ledger rows are
    read and joined by id, so both calls appear. A2 gives no recovery exception.

    render reads the served_ledger into the JudgeContext's refusal-and-fault list;
    read_world_ledger feeds the user_record's found gaps. The siem-x adapter cannot load on
    b's first `siem-x lookup` (p32's shape: an import of a module that does not exist; the
    source here makes no siem-x call, so no earlier load is cached) and is repaired before the
    identical retry. No J3 sentinel here, so the fault is b's only blocked call."""
    calls = [S.S24.Call("idp", "query", S.Q1, S.BASE_ANSWER),
             S.S24.Call("edr", "query", S.Q2, S.BASE_ANSWER), S.POST]
    est = estate(tmp_path)
    est.answer("siem-x", "lookup", S.L3, S.BASE_ANSWER)
    adapter = est.adapters / "siem_x_adapter.py"
    good = adapter.read_text(encoding="utf-8")
    broken = good.replace("from __future__ import annotations\n",
                          "from __future__ import annotations\nimport _no_such_dependency_1234\n",
                          1)
    turns_b = [_Between(q("siem-x", "lookup", S.L3),
                        before=lambda: adapter.write_text(broken, encoding="utf-8")),
               _Between(q("siem-x", "lookup", S.L3),
                        before=lambda: adapter.write_text(good, encoding="utf-8")),
               S.done_turn()]
    built = launch(tmp_path, est, calls=calls, after_source=None,
                   b=S.RealWorld("b", turns=turns_b))
    faulted, answered = lines(built.table_rows("b"), S.L3)
    assert [r["source"] for r in built.ledger_rows("b")] == ["fault", "passthrough"], (
        "fixture: the fault and the answered retry are both on the ledger")

    b = _contrast(S.render_context(built, "b"), "b")
    blocked = list(_field(b, "contrast.blocked"))
    assert _numbers(blocked) == [faulted], "the faulted call is blocked; the retry is not"
    assert _get(blocked[0], S.COINED["entry.source"]) == "fault"
    assert answered not in _field(b, "contrast.unserved")
    assert list(_field(b, "contrast.unmapped")) == []

    S.grade(built, S.judge(), draws=1)
    key = (S.found_run("b"), "siem-x", "lookup", S.canonical(S.L3))
    found = [g for g in S.found_gaps(built) if S.gap_key(g) == key]
    assert len(found) == 1, f"one found gap for the faulted call, counted once (the retry is no gap): {found}"
    assert found[0].get(S.COINED["found.count"]) == 1, f"one found gap for the faulted call, counted once (the retry is no gap): {found}"


def test_1234_altered_answer_matching_no_investigator_call(tmp_path: Path) -> None:
    """Join is exact on the call id (A12). A ledger row whose id is in no table row of this run
    is reported as an unmapped altered call (no call number or lead invented); a table row
    carrying this run's id and no ledger row is counted with its system/verb and flagged
    unserved. A table row with no id of this run is inherited: shared baseline, never paired and
    never listed unserved (in a sibling run, lead zero's row, when present, is such a seeded
    copy). No ambiguity flag is raised (A12). Neither unmapped nor unserved is silently dropped.

    render reads executed_queries and the served_ledger into the JudgeContext. The real writers
    leave b's records with a reject (b's id, no ledger row) and QP's altered call; QP's table
    row is then removed from the archived table (`S.rewrite_jsonl`), so b's `oracle` ledger row
    matches no row of b's query table — the situation A30 names, which no single run writes."""
    built = launch(tmp_path, after_source=j3_and_lead_zero,
                   b=S.RealWorld("b", turns=[reject_turn(), q("idp", "query", S.Q1),
                                             q("idp", "query", S.QP), S.done_turn()],
                                 oracle=S.altering_oracle()))
    inherited = PRE_BRANCH + 2
    oracle_row = next(r for r in built.ledger_rows("b") if r.get("source") == "oracle")
    S.rewrite_jsonl(built.table_path("b"),
                    lambda rows: [r for i, r in enumerate(rows) if i not in lines(rows, S.QP)])
    rows = built.table_rows("b")
    reject = line_where(rows, verb="no_such_verb")
    lead_zero = line_where(rows, lead_id="l-000")

    b = _contrast(S.render_context(built, "b"), "b")
    unmapped = list(_field(b, "contrast.unmapped"))
    assert [_get(e, S.CALL_ID) for e in unmapped] == [oracle_row[S.CALL_ID]]
    assert _numbers(unmapped) == [None]
    assert _get(unmapped[0], S.COINED["entry.source"]) == "oracle"
    assert _field(b, "contrast.first_altered") is None, "no call number is invented"
    assert list(_field(b, "contrast.altered_leads")) == [], "no lead is invented"
    assert _field(b, "contrast.shown") is True, "the altered answer was still served"
    assert list(_field(b, "contrast.unserved")) == [reject]
    assert _counts(b).get("idp.no_such_verb") == 1, "the unserved row is counted"
    assert set(range(inherited)) <= set(_field(b, "contrast.baseline")), "the seed is baseline"
    assert lead_zero not in _field(b, "contrast.unserved")


def test_1234_first_altered_call_when_ledger_order_and_query_order_disagree(tmp_path: Path) -> None:
    """The query table owns call order and numbering (A2): the first altered call is the lowest
    table call number among altered answers, whatever order the ledger records them; each
    altered ledger row joins its table row by call id (A12), so neither the order of the two
    files nor repeats of one key affect the result.

    render reads executed_queries for order and the served_ledger, joined on identity, into the
    JudgeContext. World b's oracle alters BOB, then CAROL (asked twice); the archived ledger's
    BOB row is then moved after CAROL's (`S.rewrite_jsonl`), so the ledger records CAROL's
    altered answers first while the table numbers BOB first — AP-14 observed ledger and table
    order disagreeing across leads."""
    est = estate(tmp_path)
    est.answer("idp", "query", BOB, S.BASE_ANSWER)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    built = launch(tmp_path, est, b=S.RealWorld(
        "b", turns=[q("idp", "query", BOB), q("idp", "query", CAROL), q("idp", "query", CAROL),
                    S.done_turn()], oracle=altering("user:bob", "user:carol")))
    rows = built.table_rows("b")
    bob, carol = lines(rows, BOB), lines(rows, CAROL)
    assert len(bob) == 1, "fixture: BOB asked first"
    assert len(carol) == 2, "fixture: BOB asked first"
    assert bob[0] < carol[0], "fixture: BOB asked first"
    assert lines([r for r in built.ledger_rows("b") if r.get("source") == "oracle"], CAROL), (
        "fixture: CAROL was served altered too, so there are two altered calls to order")

    def bob_last(ledger: list[dict]) -> list[dict]:
        moved = ledger.pop(ledger_index(ledger, BOB, "oracle"))
        return [*ledger, moved]

    reordered = S.rewrite_jsonl(built.ledger_path("b"), bob_last)
    assert S.canonical(reordered[-1]["params"]) == S.canonical(BOB), "fixture: BOB's row last"
    first_oracle = next(r for r in reordered if r.get("source") == "oracle")
    assert S.canonical(first_oracle["params"]) == S.canonical(CAROL), (
        "fixture: the ledger now records CAROL's altered answer first")

    b = _contrast(S.render_context(built, "b"), "b")
    assert _field(b, "contrast.first_altered") == bob[0]
    assert list(_field(b, "contrast.unserved")) == []
    assert list(_field(b, "contrast.unmapped")) == []


def test_1234_calls_before_the_branch_point_in_each_runs_counts(tmp_path: Path) -> None:
    """Pre-branch calls are inherited table rows (no id of this run, A12): they are in each
    run's call numbering and system/verb counts and lie in the shared baseline region,
    identically for every run; they are never paired with a ledger row and never listed
    unserved.

    render reads executed_queries — the seed _inherit_evidence wrote into every sibling — into
    each run's contrast row of the JudgeContext. The default triad; siem-x lookup and edr query
    were asked only before the branch."""
    built = launch(tmp_path)
    inherited = PRE_BRANCH + 1
    seeds = [built.table_rows(w)[:inherited] for w in "abc"]
    assert seeds[0] == seeds[1] == seeds[2], "fixture: the seed is identical in every run"

    ctx = S.render_context(built, "b")
    for run in "abc":
        row = _contrast(ctx, run)
        counts = _counts(row)
        assert counts.get("siem-x.lookup") == 1, f"{run}: the pre-branch calls are counted"
        assert counts.get("edr.query") == 1, f"{run}: the pre-branch calls are counted"
        assert counts.get("edr.lookup") == 2, f"{run}: J3's seeded row and its own refusal"
        assert set(range(inherited)) <= set(_field(row, "contrast.baseline")), (
            f"{run}: the pre-branch rows lie in the shared baseline")
        assert not set(range(inherited)) & set(_field(row, "contrast.unserved")), (
            f"{run}: an inherited row is never unserved")
    qp_line = lines(built.table_rows("b"), S.QP)[0]
    assert qp_line >= inherited, "fixture: QP follows the seed"
    assert _field(_contrast(ctx, "b"), "contrast.first_altered") == qp_line, (
        "the call numbering counts the inherited rows")


def test_1234_shared_baseline_when_the_judged_world_was_never_shown_its_facts(
        tmp_path: Path) -> None:
    """The inherited pre-branch rows (no id of this run) are shared baseline in every run, the
    judged world's included (A12). With no altered answer nothing bounds a further region: the
    table states that the judged world was never shown its facts and marks no post-branch call
    as baseline noise.

    render reads executed_queries into the JudgeContext. World b's oracle passes every call, so
    b receives no altered answer."""
    built = launch(tmp_path, b=S.RealWorld("b", oracle=S.passing_oracle()))
    inherited = PRE_BRANCH + 1
    assert all(r.get("source") != "oracle" for r in built.ledger_rows("b")), "fixture"

    ctx = S.render_context(built, "b")
    b = _contrast(ctx, "b")
    assert _field(b, "contrast.shown") is False, "the table states b was never shown its facts"
    assert _field(b, "contrast.first_altered") is None
    for run in "abc":
        assert sorted(_field(_contrast(ctx, run), "contrast.baseline")) == list(range(inherited)), (
            f"{run}: the shared baseline is the seeded rows, and no post-branch call")


def test_1234_am_repeat_pairing_when_one_attempt_left_no_ledger_row(tmp_path: Path) -> None:
    """Each call carries its own host-written call id on both records (A12), so each ledger row
    joins its own table row exactly; ledger order, lead stalls and repeats of one key do not
    matter. A table row carrying this run's id and no ledger row is unserved (exactly that row);
    a ledger row whose id is in no table row is unmapped. A failed write to either record ends
    the run and the world is cut short naming the failed write (A12), so the first attempt
    cannot lose its refused or fault row silently; an attempt cancelled mid-delivery leaves no
    row on either side (AP-01). The first altered call is the lowest table call number among
    the calls whose id joins an altered ledger row (A2; #28). Calls the query tool rejected
    before any system was reached carry this run's id on their table row and have no ledger
    row, so they are unserved (A12; T8 names rejects among the native unserved kinds); they are
    not blocked calls. A pointer to an unserved row is an ordinary conduct pointer, not a
    blocked-call row (a table `∅.` row counts as blocked only via its ledger partner, J3's row
    aside).

    render joins the served_ledger and executed_queries on identity into the JudgeContext. World
    b: a reject, the withheld edr lookup (refused), BOB erroring live, then (the estate
    recovered) BOB's identical retry served altered. The control makes the same reject and
    refusal. b's reply files two investigator findings: one whose pair is the two reject rows,
    one whose pair is the two `∅.denied` rows (blocked through their ledger partners) — the
    second is gap-only, the first is not. (The failed-write arm is pinned by
    test_1234_failed_served_ledger_write_ends_the_run and its table twin.)"""
    est = estate(tmp_path)
    est.fail("idp", "query", BOB, fault="UpstreamFault", detail="shard down")
    turns_b = [reject_turn(), q("edr", "lookup", S.DENIED_LOOKUP), q("idp", "query", BOB),
               _Between(q("idp", "query", BOB),
                        before=lambda: est.answer("idp", "query", BOB, S.BASE_ANSWER)),
               S.done_turn()]
    turns_a = [reject_turn(), q("edr", "lookup", S.DENIED_LOOKUP), S.done_turn()]
    built = launch(tmp_path, est, a=S.RealWorld("a", turns=turns_a, disposition="benign"),
                   b=S.RealWorld("b", turns=turns_b, oracle=altering("user:bob")))
    rows_b, rows_a = built.table_rows("b"), built.table_rows("a")
    reject_b, reject_a = line_where(rows_b, verb="no_such_verb"), line_where(rows_a,
                                                                             verb="no_such_verb")
    denied_b = lines(rows_b, S.DENIED_LOOKUP, query_id=S.DENIED_QUERY_ID)[-1]
    denied_a = lines(rows_a, S.DENIED_LOOKUP, query_id=S.DENIED_QUERY_ID)[-1]
    first, retry = lines(rows_b, BOB)

    b = _contrast(S.render_context(built, "b"), "b")
    assert list(_field(b, "contrast.unserved")) == [reject_b], "exactly the reject is unserved"
    assert reject_b not in _numbers(_field(b, "contrast.blocked")), "a reject is not a blocked call"
    assert denied_b in _numbers(_field(b, "contrast.blocked"))
    assert list(_field(b, "contrast.unmapped")) == []
    assert _field(b, "contrast.first_altered") == retry
    assert first in _field(b, "contrast.errored")

    reply = S.world_reply("lead-quality", ["idp"], investigator=[
        S.inv("lead-quality", contrast=[S.table_ptr("b", reject_b), S.table_ptr("a", reject_a)]),
        S.inv("lead-quality", contrast=[S.table_ptr("b", denied_b), S.table_ptr("a", denied_a)],
              claim="the refusal was never worked around")])
    S.grade(built, S.judge({"b": reply}), draws=1)
    queued = {r.get("finding_id") for r in S.from_world(S.defender_queue(), "b")}
    assert built.finding_id("b", 0, 0) in queued, (
        "a pair of unserved reject rows is ordinary conduct: the finding queues")
    assert built.finding_id("b", 0, 1) not in queued, (
        "the pair of blocked ∅.denied rows is gap-only: never on the defender queue")


def test_1234_am_blocked_call_with_only_one_record_in_the_rendered_views(tmp_path: Path) -> None:
    """Views render blocked calls from ledger rows (A2) plus J3's row (A14). A ledger-only denial
    (the door closed) is listed in the judged world's call list and in the contrast table's
    refusal list as a blocked call with no table call number (unmapped, A12). J3's row (the
    inherited `∅.denied` row: no id of this run, identical in every readable run's table, A12)
    appears in the judged world's call list, in section 5's reference call list and in the
    contrast table's refusal list as a blocked call under its table call number, identically in
    every run, and once in the user record. A killed-shim infra sentinel has no ledger partner
    and is not J3's row, so it is not blocked: an ordinary table call under its table call
    number, inherited (shared baseline) when it is a seeded pre-branch copy and unserved when it
    carries this run's id.

    render and _build_prompt present the served_ledger and executed_queries through the
    JudgeContext's call lists and contrast rows. The source holds J3's row and a pre-branch
    `∅.bash-shim` row (both seeded); world b makes a failing reduce of its own, trips the repeat
    guard (the door closes), then asks the withheld idp lookup: a `refused` ledger row and no
    table row (JP-02 s_door)."""
    est = estate(tmp_path, WITHHELD)
    est.fail("idp", "query", REP, fault="UpstreamFault", detail="500 upstream")

    def source(src: Path) -> None:
        S.capture_sentinel(src)
        S.capture_sentinel(src, system="idp", verb="bash", seq=4,
                           params={"command": "cat x.json | defender-sql 'SELECT 1'"},
                           query_id=S.BASH_SHIM_QUERY_ID, exit_code=2)

    turns_b = [reducer_turn("b"), q("idp", "query", REP), q("idp", "query", REP),
               q("idp", "query", REP), q("idp", "lookup", IDP_LOOKUP), S.done_turn()]
    built = launch(tmp_path, est, after_source=source,
                   b=S.RealWorld("b", turns=turns_b, oracle=S.altering_oracle()))
    inherited = PRE_BRANCH + 2
    rows = built.table_rows("b")
    j3_line = lines(rows, S.DENIED_LOOKUP, query_id=S.DENIED_QUERY_ID)[0]
    seeded_shim, own_shim = [i for i, r in enumerate(rows)
                             if r.get("query_id") == S.BASH_SHIM_QUERY_ID]
    assert seeded_shim < inherited <= own_shim, "fixture: one seeded shim row, one of b's own"
    assert not lines(rows, IDP_LOOKUP), "fixture: the door-closed refusal has no table row"

    ctx = S.render_context(built, "b")
    calls = _focus_calls(ctx)
    door = _entry_at(calls, None, "refused")
    assert len(door) == 1, "the ledger-only denial is a blocked call with no table call number"
    assert _get(door[0], S.COINED["entry.blocked"]) is True, "the ledger-only denial is a blocked call with no table call number"
    assert _blocked_flags(calls, j3_line) == [True], "J3's row, blocked, under its number"
    for line in (seeded_shim, own_shim):
        assert _blocked_flags(calls, line) == [False], (
            "a killed-shim sentinel is an ordinary table call under its number")
    refs = _reference_calls(ctx)
    for run in ("a", "c"):
        assert _blocked_flags(refs[run], j3_line) == [True], (
            f"J3's row is a blocked call in reference {run}'s call list, same number")
    for run in "abc":
        assert j3_line in _numbers(_field(_contrast(ctx, run), "contrast.blocked")), run
    b = _contrast(ctx, "b")
    assert None in _numbers(_field(b, "contrast.blocked"))
    assert len(list(_field(b, "contrast.unmapped"))) == 1
    assert own_shim in _field(b, "contrast.unserved")
    assert seeded_shim not in _field(b, "contrast.unserved")
    assert seeded_shim in _field(b, "contrast.baseline")
    assert not {own_shim, seeded_shim} & set(_numbers(_field(b, "contrast.blocked")))

    S.grade(built, S.judge(), draws=1)
    family_key = (S.COINED["found.family_run"], "edr", "lookup", S.canonical(S.DENIED_LOOKUP))
    once = [g for g in S.found_gaps(built) if S.gap_key(g) == family_key]
    assert len(once) == 1, f"J3's row is listed once in the user record, as the family's: {once}"
    assert once[0].get(S.COINED["found.count"]) == 1, f"J3's row is listed once in the user record, as the family's: {once}"


def test_1234_world_ledger_read_keeps_every_row_of_a_repeated_triple(tmp_path: Path) -> None:
    """The world-ledger read keeps every well-formed row of the world in file order: two calls
    with one (system, verb, params) triple and distinct call ids are two rows (A2: read in full,
    no first-row-wins), and the contrast table joins each to its own table row by call id;
    today judge/family.py mapping_key keeps the first row of a triple (three ledger rows read as
    two, GT-7). The control is a ledger with no repeated triple.

    read_world_ledger over b's served_ledger (its identity: the call id). World b asks CAROL
    twice, both answered; world c (the control here) repeats no triple."""
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    built = launch(tmp_path, est, b=S.RealWorld(
        "b", turns=[q("idp", "query", S.Q1), q("idp", "query", CAROL),
                    q("idp", "query", CAROL), S.done_turn()], oracle=S.passing_oracle()))
    raw_b, raw_c = built.ledger_rows("b"), built.ledger_rows("c")
    assert len(lines(raw_b, CAROL)) == 2, "fixture: two ledger rows share one triple"

    read = S.sym(S.JUDGE_FAMILY, "read_world_ledger")
    with S.mod("_io").bind(built.ep) as bound:
        kept_b = read(bound, "b", episode_token=built.token)[0]
        kept_c = read(bound, "c", episode_token=built.token)[0]
    assert [S.canonical(r["params"]) for r in kept_c] == \
        [S.canonical(r["params"]) for r in raw_c], "control: every row of c is kept, in order"
    assert [S.canonical(r["params"]) for r in kept_b] == \
        [S.canonical(r["params"]) for r in raw_b], "both CAROL rows are kept, in file order"
    carol_ids = [r.get(S.CALL_ID) for r in kept_b
                 if S.canonical(r["params"]) == S.canonical(CAROL)]
    assert len(set(carol_ids)) == 2, "two calls, two ids"
    assert None not in carol_ids, "two calls, two ids"

    b = _contrast(S.render_context(built, "b"), "b")
    assert list(_field(b, "contrast.unserved")) == [], "each CAROL row joined its own table row"
    assert list(_field(b, "contrast.unmapped")) == [], "each CAROL row joined its own table row"


def test_1234_outage_rows_and_the_user_record(tmp_path: Path) -> None:
    """An outage (`real-error`) is not a blocked call (A2): the contrast table lists it as
    served with an error, and it is in neither the found gaps nor the user record's gap list. A
    finding resting only on outage rows is not gap-only; an investigator finding resting on them
    is an investigator finding (T2) and is queued when it passes the two-run rule.

    render reads the served_ledger into the JudgeContext; the user_record is judge.yaml's user
    section. BOB is down for every world (a live UpstreamFault). b's reply files one finding
    whose pair is the two outage rows (b's and the control's served_ledger rows) and, as the
    observable control, one whose pair is the two refused rows (gap-only); and it names two
    gaps, unflagged, one on b's outage row and, as the observable control of the user record's
    gap list, one on b's refused row."""
    est = estate(tmp_path)
    est.fail("idp", "query", BOB, fault="UpstreamFault", detail="shard down")
    with_outage = [*S.default_turns()[:-1], q("idp", "query", BOB), S.done_turn()]
    built = launch(tmp_path, est,
                   a=S.RealWorld("a", turns=list(with_outage), disposition="benign"),
                   b=S.RealWorld("b", turns=list(with_outage), oracle=S.altering_oracle()))
    bob_line = lines(built.table_rows("b"), BOB)[0]
    out_b = ledger_index(built.ledger_rows("b"), BOB, "real-error")
    out_a = ledger_index(built.ledger_rows("a"), BOB, "real-error")
    ref_b = ledger_index(built.ledger_rows("b"), S.DENIED_LOOKUP, "refused")
    ref_a = ledger_index(built.ledger_rows("a"), S.DENIED_LOOKUP, "refused")

    b = _contrast(S.render_context(built, "b"), "b")
    assert bob_line in _field(b, "contrast.errored"), "listed as served with an error"
    assert bob_line not in _numbers(_field(b, "contrast.blocked")), "not a blocked call"

    reply = S.world_reply("lead-quality", ["idp"], investigator=[
        S.inv("lead-quality", contrast=[built.served("b", out_b), built.served("a", out_a)],
              claim="the investigator stopped at the first error"),
        S.inv("lead-quality", contrast=[built.served("b", ref_b), built.served("a", ref_a)],
              claim="the refusal was never worked around")],
        gaps=[S.gap(S.marker("b", "outage-gap"), evidence=[built.served("b", out_b)]),
              S.gap(S.marker("b", "refusal-gap"), evidence=[built.served("b", ref_b)])])
    S.grade(built, S.judge({"b": reply}), draws=1)
    bob_key = S.canonical(BOB)
    gaps = S.found_gaps(built)
    assert [g for g in gaps if S.gap_key(g)[1:3] == ("edr", "lookup")], (
        "control: the refused calls are found gaps, so the census ran")
    assert not [g for g in gaps if S.gap_key(g)[3] == bob_key], "an outage is no found gap"
    named = S.named_gaps(built)
    assert [g for g in named if S.gap_key(g)[3] == S.canonical(S.DENIED_LOOKUP)], (
        f"control: the gap named on b's refusal is not listed, so the list proves nothing: {named}")
    assert not [g for g in named if S.gap_key(g)[3] == bob_key], (
        "the gap named on an outage row was listed as a blocked call")
    queued = {r.get("finding_id") for r in S.from_world(S.defender_queue(), "b")}
    assert built.finding_id("b", 0, 0) in queued, "resting on outage rows: it queues"
    assert built.finding_id("b", 0, 1) not in queued, "resting on refusals: gap-only"


# ======================================================================================
# A failed write of either call record ends the run (A12).
# ======================================================================================


def _cut_short_family(tmp_path: Path, variant: str) -> tuple[Any, str, str]:
    """One of s_AN01's three failed writes: b's served ledger, b's query table, or the
    control's served ledger. Returns the family, the run whose write failed and its record."""
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    if variant == "ledger":
        est.break_write("idp", "query", BOB, BREAK_LEDGER)
        turns = [q("edr", "lookup", S.DENIED_LOOKUP), q("idp", "query", BOB),
                 q("idp", "query", CAROL), S.done_turn()]
        return launch(tmp_path, est, b=S.RealWorld("b", turns=turns)), "b", "ledger"
    if variant == "table":
        turns = [q("edr", "lookup", SENT_TWO), q("idp", "query", S.Q1),
                 _Between(q("edr", "lookup", S.DENIED_LOOKUP), before=plant_dir_at(TABLE_GLOB)),
                 q("idp", "query", CAROL), S.done_turn()]
        return launch(tmp_path, est, b=S.RealWorld("b", turns=turns)), "b", "table"
    est.break_write("idp", "query", BOB, BREAK_LEDGER)
    turns = [q("idp", "query", S.Q1), q("idp", "query", BOB), q("idp", "query", CAROL),
             S.done_turn()]
    return (launch(tmp_path, est, a=S.RealWorld("a", turns=turns, disposition="benign")),
            "a", "ledger")


@pytest.mark.parametrize("variant", ["ledger", "table", "control"])
def test_1234_an_world_cut_short_by_a_failed_call_record_write(tmp_path: Path,
                                                             variant: str) -> None:
    """A failed write of either call record ends the run and the world is cut short naming the
    failed write (A12): M1's existing cut-short state, with the failed write as its named
    reason, not a new state. A cut-short planted world is ungradable and leaves every reference
    set (M1, A3); a cut-short control stamps the family not graded, naming it (A3). The run's
    already-recorded ledger rows are read for found gaps like every run's, so its earlier
    refused and fault calls are listed, one entry per blocked call with a count. The call whose
    write failed is no found gap (no row of it was recorded); it is named on the world's row as
    the cut-short cause. A failed query-table write leaves that call's ledger row in place, so a
    `refused` or `fault` ledger row of it is a found gap. A ledger the failed write left
    unreadable is contained to that run's census entry, named unread with its cause.

    grade_episode over the archive: the world's cut_short state, the reference sets, and the
    user_record's found gaps read from each served_ledger. `ledger`: b's ledger write for BOB
    fails (the adapter planted a directory at it) after an earlier refusal was recorded — the
    directory leaves b's ledger unreadable. `table`: b's earlier refusal (sent-two) is recorded
    whole, then the table becomes a directory just before the second refusal, whose ledger row
    lands and whose `∅.denied` table write fails. `control`: the control's ledger write fails."""
    built, run, record = _cut_short_family(tmp_path, variant)
    judge = S.judge()
    S.grade(built, judge, draws=1)
    if variant == "control":
        stamp = S.stamp(built)
        assert isinstance(stamp, dict), "a cut-short control stamps the family not graded"
        assert S.word_re(S.COINED["cut.ledger"]).search(str(stamp.get("reason"))), (
            f"the stamp names the control's failed write: {stamp}")
        assert not judge.called("b"), "no world is graded"
        assert not judge.called("c"), "no world is graded"
        return
    reason = _cut_short_reason(S.row(built, run))
    assert S.word_re(S.COINED[f"cut.{record}"]).search(reason), f"the failed write is named: {reason}"
    refs = _reference_calls(S.render_context(built, "c"))
    assert "a" in refs, "a cut-short world leaves every reference set"
    assert run not in refs, "a cut-short world leaves every reference set"
    gaps = [g for g in S.found_gaps(built) if g.get(S.COINED["found.run"]) == S.found_run(run)]
    if variant == "ledger":
        assert [g for g in gaps if g.get(S.COINED["found.unread"])], (
            f"b's unreadable ledger is named unread in its census entry: {gaps}")
        assert not [g for g in gaps if S.gap_key(g)[3] == S.canonical(BOB)], (
            "the call whose write failed is no found gap")
        return
    for params in (SENT_TWO, S.DENIED_LOOKUP):
        key = (S.found_run(run), "edr", "lookup", S.canonical(params))
        hit = [g for g in gaps if S.gap_key(g) == key]
        assert len(hit) == 1, f"{params}: a refused ledger row of the run is a found gap: {gaps}"
        assert hit[0].get(S.COINED["found.count"]) == 1, f"{params}: a refused ledger row of the run is a found gap: {gaps}"


def _ledger_fails(est: Any, writer: str) -> Any:
    """b's call whose served-ledger row fails to write, per writer."""
    if writer == "_deliver":  # the delivered row of an answered call
        est.break_write("idp", "query", BOB, BREAK_LEDGER)
        return q("idp", "query", BOB)
    if writer == "_record_beside":  # the real-error row of a live outage
        est.break_write("idp", "query", BOB, BREAK_LEDGER, fault="UpstreamFault")
        return q("idp", "query", BOB)
    # decide_call: the refused row of the withheld verb (it never reaches an adapter)
    return _Between(q("edr", "lookup", S.DENIED_LOOKUP), before=plant_dir_at(LEDGER_GLOB))


@pytest.mark.parametrize("writer", ["_deliver", "_record_beside", "decide_call"])
def test_1234_failed_served_ledger_write_ends_the_run(tmp_path: Path, writer: str) -> None:
    """A served-ledger write that fails (decide_call's refused/fault row, _deliver's delivered
    row, _record_beside's error or refusal row) ends the run: the failure is not swallowed, no
    further call is served, and the world is archived cut short naming the failed write (A12;
    today _record_beside swallows it, AP-01/JP-02).

    One parametrized case per writer of the served_ledger: the record becomes a directory just
    before that writer's row. CAROL — a fresh key the estate answers — is the next call b's
    investigator asks; the estate's own call log shows whether it was served. ERIN, asked
    before the failing call, is the positive control: the same log shows it received."""
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    est.answer("idp", "query", ERIN, S.BASE_ANSWER)
    failing = _ledger_fails(est, writer)
    built = launch(tmp_path, est, b=S.RealWorld("b", turns=[
        q("idp", "query", S.Q1), q("idp", "query", ERIN), failing, q("idp", "query", CAROL),
        S.done_turn()]))
    assert estate_calls(built, ERIN), "control: the estate's call log never saw ERIN"
    assert estate_calls(built, CAROL) == [], "no further call is served after the failed write"
    assert (built.ep / "worlds" / "b").is_dir(), "the world is archived"
    S.grade(built, S.judge(), draws=1)
    reason = _cut_short_reason(S.row(built, "b"))
    assert S.word_re(S.COINED["cut.ledger"]).search(reason), (
        f"the failed served-ledger write is named: {reason}")


def _table_fails(est: Any, writer: str) -> Any:
    """b's call whose query-table row fails to write, per writer."""
    if writer == "append_query_row":  # the row of an answered call
        est.break_write("idp", "query", BOB, BREAK_TABLE)
        return q("idp", "query", BOB)
    if writer == "_record_denied":  # the ∅.denied row of the withheld verb
        return _Between(q("edr", "lookup", S.DENIED_LOOKUP), before=plant_dir_at(TABLE_GLOB))
    # _record_shim_failure: the shim's direct ∅.bash-shim append
    return _Between(before=plant_dir_at(TABLE_GLOB), make=reducer_make("b"))


@pytest.mark.parametrize("writer", ["append_query_row", "_record_denied", "_record_shim_failure"])
def test_1234_failed_query_table_write_ends_the_run(tmp_path: Path, writer: str) -> None:
    """A query-table write that fails (_record_denied's ∅.denied row, append_query_row's row,
    the shim's ∅.bash-shim append, or any other writer of executed_queries.jsonl) ends the run
    and the world is archived cut short naming the failed write (A12; today _record_denied
    swallows it, JP-02 s_tw_denied).

    One parametrized case per writer of executed_queries (_record_denied, append_query_row,
    _record_shim_failure): the table becomes a directory just before that writer's row. CAROL
    is the next call; the estate's call log shows whether it was served. ERIN, asked before
    the failing call, is the positive control: the same log shows it received."""
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    est.answer("idp", "query", ERIN, S.BASE_ANSWER)
    failing = _table_fails(est, writer)
    built = launch(tmp_path, est, b=S.RealWorld("b", turns=[
        q("idp", "query", S.Q1), q("idp", "query", ERIN), failing, q("idp", "query", CAROL),
        S.done_turn()]))
    assert estate_calls(built, ERIN), "control: the estate's call log never saw ERIN"
    assert estate_calls(built, CAROL) == [], "no further call is served after the failed write"
    assert (built.ep / "worlds" / "b").is_dir(), "the world is archived, not lost"
    S.grade(built, S.judge(), draws=1)
    reason = _cut_short_reason(S.row(built, "b"))
    assert S.word_re(S.COINED["cut.table"]).search(reason), (
        f"the failed query-table write is named: {reason}")


# ======================================================================================
# The call id itself (A12, I-1).
# ======================================================================================


def test_1234_one_call_carries_one_host_written_id_on_both_records(tmp_path: Path) -> None:
    """Before a call reaches the registry the query tool allocates a host-written call id naming
    the run and the call; the registry writes it on every served-ledger row of that call
    (refused/fault from decide_call, delivered/real-error from _deliver/_record_beside) and the
    query tool writes the same id on the call's table row; no two calls of one run share an id,
    and a repeated identical call gets its own id (A12; JP-01: no id is in scope today).

    QueryCapture drives decide_call and the serve path; the served_ledger and executed_queries
    (append_query_row's rows) carry the identity. World b makes a passthrough call, CAROL twice,
    the altered QP, the withheld edr lookup (refused before anything is served) and an outage."""
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    est.fail("idp", "query", BOB, fault="UpstreamFault", detail="shard down")
    built = launch(tmp_path, est, b=S.RealWorld("b", turns=[
        q("idp", "query", S.Q1), q("idp", "query", CAROL), q("idp", "query", CAROL),
        q("idp", "query", S.QP), q("edr", "lookup", S.DENIED_LOOKUP), q("idp", "query", BOB),
        S.done_turn()], oracle=S.altering_oracle()))
    inherited = PRE_BRANCH + 1
    ledger_b = built.ledger_rows("b")
    table_b = own(built.table_rows("b"), inherited)
    assert sorted({r["source"] for r in ledger_b}) == \
        ["oracle", "passthrough", "real-error", "refused"], "fixture: every ledger source"
    assert len(ledger_b) == len(table_b) == 6, "fixture: six calls, a row each on both records"

    ledger_ids = [r.get(S.CALL_ID) for r in ledger_b]
    table_ids = [r.get(S.CALL_ID) for r in table_b]
    assert all(ledger_ids), "every row of both records carries the id"
    assert all(table_ids), "every row of both records carries the id"
    assert len(set(ledger_ids)) == 6, "no two calls share an id"
    assert set(ledger_ids) == set(table_ids), "the same ids on both records"
    by_id = {r[S.CALL_ID]: r for r in table_b}
    for row in ledger_b:
        partner = by_id[row[S.CALL_ID]]
        assert (partner["system"], partner["verb"], S.canonical(partner["params"])) == \
            (row["system"], row["verb"], S.canonical(row["params"])), "one id, one call"
    carol_ids = [r.get(S.CALL_ID) for r in ledger_b
                 if S.canonical(r["params"]) == S.canonical(CAROL)]
    assert len(set(carol_ids)) == 2, "the repeated identical call has its own id"
    seeded = {r.get(S.CALL_ID) for r in built.table_rows("b")[:inherited]}
    assert not seeded & set(ledger_ids), "an inherited row carries no id of this run"
    others = {r.get(S.CALL_ID) for w in "ac" for r in
              [*built.ledger_rows(w), *built.table_rows(w)]}
    assert not others & set(ledger_ids), "the id names the run: no other run carries b's ids"


def test_1234_every_query_table_writer_writes_this_runs_call_id(tmp_path: Path) -> None:
    """Every row a run writes into its query table carries this run's call id: rejects (exit
    64), ∅.repeat-trip, ∅.denied, the shim's direct-append ∅.bash-shim and every other writer of
    executed_queries.jsonl; only rows _inherit_evidence seeds carry no id of this run (I-1).

    The writers are picked by census (every production caller of append_query_row); each is
    then driven once in world b's run: the query tool's _record (an answered call, a reject, an
    undeclared system, ∅.repeat-trip), _record_denied (∅.denied), _record_shim_failure
    (∅.bash-shim). Lead zero's writer has no surface in a sibling: no lead zero is dispatched on
    `--episode` (I-2)."""
    writers = {site.split(":")[0] for site in S.call_sites("append_query_row", under="")}
    assert {"runtime/query_tool.py", "runtime/tools/_bash.py"} <= writers, (
        f"census: the subjects driven below are production writers ({sorted(writers)})")
    est = estate(tmp_path)
    est.fail("idp", "query", REP, fault="UpstreamFault", detail="500 upstream")
    built = launch(tmp_path, est, b=S.RealWorld("b", turns=[
        reject_turn(), q("ghost-system", "query", {"q": "x"}), q("idp", "query", S.Q1),
        q("edr", "lookup", S.DENIED_LOOKUP), reducer_turn("b"), q("idp", "query", REP),
        q("idp", "query", REP), q("idp", "query", REP), S.done_turn()]))
    inherited = PRE_BRANCH + 1
    rows = built.table_rows("b")
    mine = own(rows, inherited)
    kinds = {r.get("query_id") for r in mine} | {r.get("exit_code") for r in mine}
    assert {S.DENIED_QUERY_ID, S.BASH_SHIM_QUERY_ID, S.REPEAT_TRIP_QUERY_ID,
            S.REJECT_EXIT} <= kinds, f"fixture: every writer wrote its row ({kinds})"

    ids = [r.get(S.CALL_ID) for r in mine]
    assert all(ids), f"rows this run wrote with no call id: {[r for r in mine if not r.get(S.CALL_ID)]}"
    assert len(set(ids)) == len(ids), "each row its own call"
    assert not [r for r in rows[:inherited] if r.get(S.CALL_ID) in set(ids)], (
        "only the seeded rows carry no id of this run")
    others = {r.get(S.CALL_ID) for w in "ac" for r in built.table_rows(w)}
    assert not others & set(ids), "the ids are this run's"


# --------------------------------------------------------------------------------------
# The writer census (47-dissolve-amended "For the writer" (1); I-1).
# --------------------------------------------------------------------------------------

#: Every production write site of a world's call records: `<file>::<function>` holding the call
#: that writes (`writes_by`); the functions that reach it in the same file (each must let a
#: failed write through: A12); how a failed write is handled; whose call id its rows carry; the
#: test that drives it.
CALL_RECORD_WRITERS: dict[str, dict[str, Any]] = {
    "learning/branch/estate/registry.py::WorldRegistry._deliver": {
        "writes_by": "record", "via": (), "failed_write": "ends the run",
        "call_id": "this run's", "driven_by": "test_1234_failed_served_ledger_write_ends_the_run"},
    "learning/branch/estate/registry.py::_record_beside": {
        "writes_by": "record", "via": ("WorldRegistry.decide_call", "WorldRegistry._base"),
        "failed_write": "ends the run", "call_id": "this run's",
        "driven_by": "test_1234_failed_served_ledger_write_ends_the_run"},
    "runtime/query_tool.py::QueryCapture._record": {
        "writes_by": "append_query_row", "via": ("QueryCapture._record_denied",),
        "failed_write": "ends the run", "call_id": "this run's",
        "driven_by": "test_1234_failed_query_table_write_ends_the_run"},
    "runtime/tools/_bash.py::_record_shim_failure": {
        "writes_by": "append_query_row", "via": (), "failed_write": "ends the run",
        "call_id": "this run's", "driven_by": "test_1234_failed_query_table_write_ends_the_run"},
    "runtime/lead_zero/_capture.py::_record_manual_row": {
        "writes_by": "append_query_row", "via": (), "failed_write": "ends the run",
        "call_id": "this run's",
        "driven_by": "test_1234_every_query_table_writer_writes_this_runs_call_id"},
    "scripts/gather_tools/record_query.py::append_query_row": {
        "writes_by": "write_guarded", "via": (), "failed_write": "ends the run",
        "call_id": "this run's", "driven_by": "test_1234_failed_query_table_write_ends_the_run"},
    "runtime/branch/_seed.py::_inherit_evidence": {
        "writes_by": "write_guarded", "via": (), "failed_write": "refuses the seed",
        "call_id": "none of this run's (seeded)",
        "driven_by": "test_1234_every_query_table_writer_writes_this_runs_call_id"},
    # The archive's verbatim copy of the run's finished table into `worlds/<X>/`.
    "learning/lead_repository.py::stage_tables": {
        "writes_by": "copy2", "via": (), "failed_write": "raises out of the archive",
        "call_id": "the run's own, copied verbatim",
        "driven_by": "test_1234_one_call_carries_one_host_written_id_on_both_records"},
}

_WRITE_PRIMITIVES = frozenset({"write_guarded", "write_text", "write_bytes", "open", "copyfile",
                               "copy", "copy2", "append"})


def _called(node: ast.Call) -> str | None:
    fn = node.func
    return fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else None


def _mentions(nodes: Iterable[ast.AST], word: str) -> bool:
    for top in nodes:
        for n in ast.walk(top):
            if (isinstance(n, ast.Attribute) and word in n.attr) or (
                    isinstance(n, ast.Name) and word in n.id) or (
                    isinstance(n, ast.Constant) and isinstance(n.value, str) and word in n.value):
                return True
    return False


def _scoped(tree: ast.AST) -> Iterable[tuple[str, ast.AST]]:
    """Every node with the qualified name (`Class.method`) of the function it sits in."""
    def walk(node: ast.AST, scope: tuple[str, ...]) -> Iterable[tuple[str, ast.AST]]:
        for child in ast.iter_child_nodes(node):
            inner = (*scope, child.name) if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else scope
            yield ".".join(inner) or "<module>", child
            yield from walk(child, inner)
    yield from walk(tree, ())


def call_record_write_sites(trees: Iterable[tuple[str, ast.AST]]) -> set[str]:
    """`<file>::<function>` of every call that writes a world's call record: the query table's
    one append (`append_query_row`), any write primitive aimed at `executed_queries`, and a
    `record(...)` on a ledger."""
    sites: set[str] = set()
    for rel, tree in trees:
        for scope, node in _scoped(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _called(node)
            table = name == "append_query_row" or (
                name in _WRITE_PRIMITIVES and _mentions([*node.args, *node.keywords],
                                                        "executed_queries"))
            ledger = name == "record" and isinstance(node.func, ast.Attribute) and _mentions(
                [node.func.value], "ledger")
            if table or ledger:
                sites.add(f"{rel}::{scope}")
    return sites


def _shipped() -> dict[str, ast.AST]:
    out: dict[str, ast.AST] = {}
    for path in sorted(S.DEFENDER.rglob("*.py")):
        rel = path.relative_to(S.DEFENDER).as_posix()
        if "__pycache__" in rel or rel.startswith(("tests/", ".venv/")):
            continue
        with contextlib.suppress(SyntaxError, UnicodeDecodeError):
            out[rel] = ast.parse(path.read_text(encoding="utf-8"))
    return out


def _swallowing_handlers(tree: ast.AST, scope: str, callee: str) -> list[int]:
    """Lines of broad `except` handlers in function `scope` that guard a call to `callee` and
    never raise — where a failed write would be swallowed."""
    found: list[int] = []
    for name, node in _scoped(tree):
        if name != scope or not isinstance(node, ast.Try):
            continue
        guards = any(isinstance(c, ast.Call) and _called(c) == callee
                     for stmt in node.body for c in ast.walk(stmt))
        for handler in node.handlers if guards else ():
            broad = handler.type is None or _mentions([handler.type], "Exception") or _mentions(
                [handler.type], "OSError")
            if broad and not any(isinstance(n, ast.Raise) for n in ast.walk(handler)):
                found.append(handler.lineno)
    return found


def test_1234_every_call_record_write_site_is_in_the_census(tmp_path: Path) -> None:
    """A census lists every production write site of the served ledger and of
    executed_queries.jsonl (at least decide_call, _deliver, _record_beside, _record_denied,
    append_query_row, the shim's ∅.bash-shim append and _inherit_evidence's seed) with how each
    handles a failed write and whether it writes the call id; a planted extra write site is
    reported.

    `CALL_RECORD_WRITERS` is the census; `call_record_write_sites` scans the shipped tree for
    the calls that write either record. The scan finds exactly the census's sites; a module
    planted beside the tree with one more writer of each record is reported; every row names
    the test above that drives it; and no function on a row's path (the site, and the functions
    reaching it — decide_call reaches the ledger through _record_beside, _record_denied the
    table through _record) guards the write with a broad handler that swallows it (A12: a
    failed write ends the run)."""
    shipped = _shipped()
    found = call_record_write_sites(shipped.items())
    assert found == set(CALL_RECORD_WRITERS), (
        f"census drift — unlisted: {sorted(found - set(CALL_RECORD_WRITERS))}; "
        f"gone: {sorted(set(CALL_RECORD_WRITERS) - found)}")

    planted = tmp_path / "planted_writer.py"
    planted.write_text(
        "from defender.scripts.gather_tools.record_query import append_query_row\n\n\n"
        "def sneaky_row(run_dir, row):\n    append_query_row(run_dir, **row)\n\n\n"
        "class Sneaky:\n    def sneaky_ledger(self, call):\n        self.ledger.record(call)\n",
        encoding="utf-8")
    with_plant = [*shipped.items(),
                  ("planted/planted_writer.py", ast.parse(planted.read_text(encoding="utf-8")))]
    assert call_record_write_sites(with_plant) - set(CALL_RECORD_WRITERS) == {
        "planted/planted_writer.py::sneaky_row",
        "planted/planted_writer.py::Sneaky.sneaky_ledger"}, "a planted write site is reported"

    tests_here = {n for n in globals() if n.startswith("test_1234_")}
    swallowed: dict[str, list[int]] = {}
    for site, row in CALL_RECORD_WRITERS.items():
        assert row["driven_by"] in tests_here, f"{site}: driven by no test in this file"
        rel, scope = site.split("::")
        lines_ = _swallowing_handlers(shipped[rel], scope, row["writes_by"])
        for via in row["via"]:
            lines_ += _swallowing_handlers(shipped[rel], via, scope.rsplit(".", 1)[-1])
        if lines_:
            swallowed[site] = lines_
    assert swallowed == {}, f"a failed write is swallowed (site: handler lines): {swallowed}"


# ======================================================================================
# Concurrency (GT-1).
# ======================================================================================


def test_1234_two_leads_calls_at_once_leave_intact_distinct_ledger_and_table_rows(
        tmp_path: Path) -> None:
    """The served-ledger writers (decide_call, _deliver, _record_beside) run on separate worker
    threads (GT-1): two gather leads dispatched in one main turn issue calls whose ledger writes
    overlap in those threads, including two identical calls, one refused call and one errored
    call. After both leads finish, every ledger row is whole and parses, the row count equals the
    calls made, no row is lost or duplicated, and each call has its own host-written call id on
    its ledger row and its table row (the table writer, append_query_row, stays on the event loop
    thread, so the table needs the in-turn form only). The exact join pairs every call with its
    own partner. The failure signal is count, parse and key distinctness, not a torn line: the
    lock-removed control did not tear a line at 500 B to 3 MB.

    QueryCapture serves both leads; the served_ledger and executed_queries carry the identity.
    World b's main dispatches two new leads in ONE turn (`RealWorld.concurrent_leads`, requested
    of the shared machinery); the shared gather script's five calls land on whichever lead asks
    next (the set is fixed, the interleaving is not)."""
    est = estate(tmp_path)
    est.answer("idp", "query", BOB, S.BASE_ANSWER)
    est.answer("idp", "query", DAVE, S.BASE_ANSWER)
    est.fail("idp", "query", CAROL, fault="UpstreamFault", detail="shard down")
    turns = [q("idp", "query", BOB), q("idp", "query", BOB), q("edr", "lookup", S.DENIED_LOOKUP),
             q("idp", "query", CAROL), q("idp", "query", DAVE), S.done_turn(), S.done_turn()]
    built = launch(tmp_path, est, b=S.RealWorld(
        "b", turns=turns, oracle=S.passing_oracle(), main_leads=("l-002", "l-003"),
        concurrent_leads=True))
    inherited = PRE_BRANCH + 1
    table = own(built.table_rows("b"), inherited)
    assert {r["lead_id"] for r in table} == {"l-002", "l-003"}, "fixture: both leads ran"

    raw = [line for line in built.ledger_path("b").read_text(encoding="utf-8").splitlines()
           if line.strip()]
    parsed = [json.loads(line) for line in raw]
    assert len(parsed) == 5, f"one whole ledger row per call made, none lost or doubled: {raw}"
    assert sorted(r["source"] for r in parsed) == \
        ["passthrough", "passthrough", "passthrough", "real-error", "refused"]
    ledger_ids = [r.get(S.CALL_ID) for r in parsed]
    table_ids = [r.get(S.CALL_ID) for r in table]
    assert all(ledger_ids), "five calls, five ids"
    assert len(set(ledger_ids)) == 5, "five calls, five ids"
    assert len(table) == 5, "each id on both records"
    assert set(table_ids) == set(ledger_ids), "each id on both records"
    by_id = {r[S.CALL_ID]: r for r in table}
    for row in parsed:
        assert S.canonical(by_id[row[S.CALL_ID]]["params"]) == S.canonical(row["params"]), (
            "the exact join pairs the call with its own partner")
