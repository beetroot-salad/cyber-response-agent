"""#1234 judge contrast: contrast rows and call records (ids, retries, write failures) for judged runs."""
from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

import json
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

from defender.tests.learning.judge.contrast_contracts import _spec1234 as S


CUT_SHORT = S.EXISTING["row.cut_short"]


#: Fresh keys no recording holds, so they reach the estate's adapter (Estate1234's docstring).
BOB = S.query_params("user:bob")
CAROL = S.query_params("user:carol")
DAVE = S.query_params("user:dave")
#: The in-test positive control of "no further call is served": a fresh key the estate answers,
#: asked BEFORE the failing call, which its call log must show it received.
ERIN = S.query_params("user:erin")
REP = S.query_params("user:rep")
#: The second withheld verb (a ledger-only denial needs a withheld call after the door closed).
IDP_LOOKUP = {"entity": "alice"}
WITHHELD = (("edr", "lookup"), ("idp", "lookup"))
#: The source run's pre-branch calls on the held lead (`S.source_calls(post=False)`).
PRE_BRANCH = len(S.source_calls(post=False))
LEDGER_GLOB = "served/{world_id}.jsonl"
#: `Estate1234.break_write` patterns (filled per call by the adapter).
BREAK_LEDGER = "{episode}/served/{world_id}.jsonl"


def q(system: str, verb: str, params: Mapping[str, Any]) -> Any:
    return S.query_turn(system, verb, params)


def reject_turn() -> Any:
    """A call the query tool rejects before any system is reached (an unknown verb): an exit-64
    table row, no ledger row."""
    return q("idp", "no_such_verb", {})


class _Between:
    """One gather-model turn preceded by a host-side action fired when the model asks for it:
    after the previous call's two records were written (ledger before table), before this call
    is made. `make` builds the turn lazily (a reducer turn needs the run's own payload path).
    The action only injects (a fault planted, or the estate recovering); it decides nothing."""

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


def _arms(label: str) -> list[tuple[Path, str]]:
    """`(episode folder, arm id)` for `label` in every episode under the tenant's episodes
    folder that has a roster naming it (the arm folder is the roster's id)."""
    out = []
    for ep in sorted(S.episodes_root().iterdir()) if S.episodes_root().is_dir() else []:
        arm = S.T.read_roster(ep).get(S.T.world_id(ep, label))
        if arm is not None:
            out.append((ep, arm))
    return out



def _run_dir(label: str) -> Path:
    return next(ep / "runs" / arm for ep, arm in _arms(label) if (ep / "runs" / arm).is_dir())


def reducer_make(label: str = "b") -> Callable[[], Any]:
    """A failing terminal reduce (`cat <payload> | defender-sql …`) over the newest payload this
    run wrote, so the real `_record_shim_failure` appends a `∅.bash-shim` row (exit 69
    `EXIT_NO_RUNTIME` without duckdb; with it, the missing table fails the reduce the same
    way)."""
    def make() -> Any:
        run_dir = _run_dir(label)
        raw = run_dir / "gather_raw" / "l-001"
        payload = max(raw.glob("*.json"), key=lambda p: int(p.stem))
        # The gather model names the payload by its model path,
        # `/runs/current/gather_raw/l-001/<n>.json`, never the arm's host run folder.
        return S.S24.replay_harness().Turn(tool_calls=[("bash", {
            "command": f"cat {model_path(payload, run_dir=run_dir)} | defender-sql "
                       "'SELECT * FROM no_such_table_1234'"})])
    return make


def reducer_turn(label: str = "b") -> _Between:
    return _Between(make=reducer_make(label))


def plant_dir_at(glob: str) -> Callable[[], None]:
    """The host action: world b's record at `glob` becomes a directory, so the real
    writer's next open of it fails (mode bits cannot do it as root)."""
    def plant() -> None:
        for ep, _arm in _arms("b"):
            for path in ep.glob(glob.format(world_id=T.world_id(ep, "b"))):
                S.plant_dir(path)
    return plant


def altering(*markers: str) -> Any:
    """World b's sibling oracle: each call whose request carries one of `markers` is served the
    forged row (claim adds fg-b-1 for f1, as `S.altering_oracle` does on QP); every other call
    passes unchanged."""
    s24 = S.S24
    return S.Routed({m: s24.oracle(s24.submit(S.CHANGED_B, s24.claim(
        added=[s24.added("fg-b-1", "f1")]))) for m in markers},
        default=S.passing_oracle(), name="oracle-b", last_wins=True)


def j3(src: Path) -> None:
    """One inherited pre-branch `∅.denied` sentinel in the source."""
    S.capture_sentinel(src)


def j3_and_lead_zero(src: Path) -> None:
    """`j3`'s row plus a lead-zero row (`l-000`, on lead zero's own system `elastic`) in the
    source; the real seed copies both into every sibling."""
    S.capture_sentinel(src)
    S.capture_sentinel(src, lead="l-000", seq=0, system="elastic", verb="query",
                       query_id="elastic.query", exit_code=0,
                       params={"native_query": "FROM alerts"})


def estate(tmp_path: Path, withheld: Iterable[tuple[str, str]] = (("edr", "lookup"),)) -> Any:
    return S.Estate1234(tmp_path / "estate", withheld=tuple(withheld))


def launch(tmp_path: Path, est: Any = None, *,
           after_source: Callable[[Path], None] | None = j3, calls: Any = None,
           **worlds: Any) -> Any:
    """`S.real_family` over `est` (default: edr lookup withheld) with per-world scripts and the
    `j3` sentinel in the source unless told otherwise (`after_source=None`: none)."""
    return S.real_family(tmp_path, dict(worlds),
                         estate=est if est is not None else estate(tmp_path),
                         after_source=after_source, calls=calls)


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


def test_1234_contrast_row_names_the_first_altered_investigator_call(tmp_path: Path) -> None:
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
        "b's refused ledger row joins its own ∅.denied row; the inherited sentinel's is listed apart")


def test_1234_contrast_row_counts_calls_leads_and_external_refusals(tmp_path: Path) -> None:
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
        "blocked: the inherited sentinel, b's refused call, and the ledger-only refusal (no number)")
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


def test_1234_retried_call_first_live_error_then_altered_answer(tmp_path: Path) -> None:
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


def test_1234_altered_answer_matching_no_investigator_call(tmp_path: Path) -> None:
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


def test_1234_am_repeat_pairing_when_one_attempt_left_no_ledger_row(tmp_path: Path) -> None:
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
        S.inv("lead-quality", contrast=[built.table("b", reject_b), built.table("a", reject_a)]),
        S.inv("lead-quality", contrast=[built.table("b", denied_b), built.table("a", denied_a)],
              claim="the refusal was never worked around")])
    S.grade(built, S.judge({"b": reply}), draws=1)
    queued = {r.get("finding_id") for r in S.from_world(S.defender_queue(), "b")}
    assert built.finding_id("b", 0, 0) in queued, (
        "a pair of unserved reject rows is ordinary conduct: the finding queues")
    assert built.finding_id("b", 0, 1) not in queued, (
        "the pair of blocked ∅.denied rows is gap-only: never on the defender queue")


def test_1234_am_blocked_call_with_only_one_record_in_the_rendered_views(tmp_path: Path) -> None:
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
    assert _blocked_flags(calls, j3_line) == [True], "the inherited sentinel is blocked under its number"
    for line in (seeded_shim, own_shim):
        assert _blocked_flags(calls, line) == [False], (
            "a killed-shim sentinel is an ordinary table call under its number")
    refs = _reference_calls(ctx)
    for run in ("a", "c"):
        assert _blocked_flags(refs[run], j3_line) == [True], (
            f"the inherited sentinel is blocked in reference {run}'s call list, same number")
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
    assert len(once) == 1, f"the inherited sentinel is listed once, as the family's: {once}"
    assert once[0].get(S.COINED["found.count"]) == 1, f"the inherited sentinel is listed once, as the family's: {once}"


def test_1234_world_ledger_read_keeps_every_row_of_a_repeated_triple(tmp_path: Path) -> None:
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    built = launch(tmp_path, est, b=S.RealWorld(
        "b", turns=[q("idp", "query", S.Q1), q("idp", "query", CAROL),
                    q("idp", "query", CAROL), S.done_turn()], oracle=S.passing_oracle()))
    raw_b, raw_c = built.ledger_rows("b"), built.ledger_rows("c")
    assert len(lines(raw_b, CAROL)) == 2, "fixture: two ledger rows share one triple"

    read = S.sym(S.JUDGE_FAMILY, "read_world_ledger")
    with S.mod("_io").bind(built.ep) as bound:
        kept_b = read(bound, T.world_id(built.ep, "b"))[0]
        kept_c = read(bound, T.world_id(built.ep, "c"))[0]
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


def _cut_short_family(tmp_path: Path, variant: str) -> tuple[Any, str]:
    """A failed served-ledger write: b's (`ledger`) or the control's. Returns the family and the
    run whose write failed."""
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    est.break_write("idp", "query", BOB, BREAK_LEDGER)
    if variant == "ledger":
        turns = [q("edr", "lookup", S.DENIED_LOOKUP), q("idp", "query", BOB),
                 q("idp", "query", CAROL), S.done_turn()]
        return launch(tmp_path, est, b=S.RealWorld("b", turns=turns)), "b"
    turns = [q("idp", "query", S.Q1), q("idp", "query", BOB), q("idp", "query", CAROL),
             S.done_turn()]
    return launch(tmp_path, est, a=S.RealWorld("a", turns=turns, disposition="benign")), "a"


@pytest.mark.parametrize("variant", ["ledger", "control"])
def test_1234_an_world_cut_short_by_a_failed_call_record_write(tmp_path: Path,
                                                             variant: str) -> None:
    built, run = _cut_short_family(tmp_path, variant)
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
    assert S.word_re(S.COINED["cut.ledger"]).search(reason), f"the failed write is named: {reason}"
    refs = _reference_calls(S.render_context(built, "c"))
    assert "a" in refs, "a cut-short world leaves every reference set"
    assert run not in refs, "a cut-short world leaves every reference set"
    gaps = [g for g in S.found_gaps(built) if g.get(S.COINED["found.run"]) == S.found_run(run)]
    assert [g for g in gaps if g.get(S.COINED["found.unread"])], (
        f"b's unreadable ledger is named unread in its census entry: {gaps}")
    assert not [g for g in gaps if S.gap_key(g)[3] == S.canonical(BOB)], (
        "the call whose write failed is no found gap")


def _ledger_fails(est: Any, writer: str) -> Any:
    """b's call whose served-ledger row fails to write, per writer."""
    if writer == "_deliver":  # the delivered row of an answered call
        est.break_write("idp", "query", BOB, BREAK_LEDGER)
        return q("idp", "query", BOB)
    if writer == "_record_beside":  # the real-error row of a live outage
        est.break_write("idp", "query", BOB, BREAK_LEDGER, fault="UpstreamFault")
        return q("idp", "query", BOB)
    # authorize_call: the refused row of the withheld verb (it never reaches an adapter)
    return _Between(q("edr", "lookup", S.DENIED_LOOKUP), before=plant_dir_at(LEDGER_GLOB))


@pytest.mark.parametrize("writer", ["_deliver", "_record_beside", "authorize_call"])
def test_1234_failed_served_ledger_write_ends_the_run(tmp_path: Path, writer: str) -> None:
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    est.answer("idp", "query", ERIN, S.BASE_ANSWER)
    failing = _ledger_fails(est, writer)
    built = launch(tmp_path, est, b=S.RealWorld("b", turns=[
        q("idp", "query", S.Q1), q("idp", "query", ERIN), failing, q("idp", "query", CAROL),
        S.done_turn()]))
    assert estate_calls(built, ERIN), "control: the estate's call log never saw ERIN"
    assert estate_calls(built, CAROL) == [], "no further call is served after the failed write"
    assert (built.ep / "worlds" / T.world_id(built.ep, "b")).is_dir(), "the world is archived"
    S.grade(built, S.judge(), draws=1)
    reason = _cut_short_reason(S.row(built, "b"))
    assert S.word_re(S.COINED["cut.ledger"]).search(reason), (
        f"the failed served-ledger write is named: {reason}")


def test_1234_one_call_carries_one_host_written_id_on_both_records(tmp_path: Path) -> None:
    est = estate(tmp_path)
    est.answer("idp", "query", CAROL, S.BASE_ANSWER)
    est.fail("idp", "query", BOB, fault="UpstreamFault", detail="shard down")
    built = launch(tmp_path, est, b=S.RealWorld("b", turns=[
        q("idp", "query", S.Q1), q("idp", "query", CAROL), q("idp", "query", CAROL),
        q("idp", "query", S.QP), q("edr", "lookup", S.DENIED_LOOKUP), q("idp", "query", BOB),
        S.done_turn()], oracle=S.altering_oracle()))
    inherited = PRE_BRANCH + 1
    ledger_b = built.ledger_rows("b")
    rows_b = built.table_rows("b")
    table_b = own(rows_b, inherited)
    assert sorted({r["source"] for r in ledger_b}) == \
        ["oracle", "passthrough", "real-error", "refused"], "fixture: every ledger source"
    assert len(ledger_b) == len(table_b) == 6, "fixture: six calls, a row each on both records"

    ledger_ids = [r.get(S.CALL_ID) for r in ledger_b]
    assert all(ledger_ids), "every ledger row carries the id"
    assert len(set(ledger_ids)) == 6, "no two calls share an id"
    carol_ids = [r.get(S.CALL_ID) for r in ledger_b
                 if S.canonical(r["params"]) == S.canonical(CAROL)]
    assert len(set(carol_ids)) == 2, "the repeated identical call has its own id"
    others = {r.get(S.CALL_ID) for w in "ac" for r in built.ledger_rows(w)}
    assert not others & set(ledger_ids), "the id names the run: no other run carries b's ids"

    b = _contrast(S.render_context(built, "b"), "b")
    assert list(_field(b, "contrast.unserved")) == [], "an own row lost its ledger partner"
    assert list(_field(b, "contrast.unmapped")) == [], "a ledger row found no table row"
    assert _field(b, "contrast.first_altered") == lines(rows_b, S.QP)[-1]
    assert sorted(_field(b, "contrast.errored")) == lines(rows_b, BOB)
    own_denied = lines(rows_b, S.DENIED_LOOKUP, query_id=S.DENIED_QUERY_ID)[-1]
    assert own_denied in _numbers(_field(b, "contrast.blocked")), (
        "the refused call's table row is not joined to its `refused` ledger row")
    carrying = [r for w in "abc" for r in built.table_rows(w) if S.CALL_ID in r]
    assert not carrying, f"a query-table row carries the call id: {carrying[:2]}"


def test_1234_two_leads_calls_at_once_leave_intact_distinct_ledger_and_table_rows(
        tmp_path: Path) -> None:
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
    assert all(ledger_ids), "five calls, five ids"
    assert len(set(ledger_ids)) == 5, "five calls, five ids"
    assert len(table) == 5, "a table row per call"
    # The table carries no id; the exact join is the host's, read by the judge.
    rows = built.table_rows("b")
    b = _contrast(S.render_context(built, "b"), "b")
    assert list(_field(b, "contrast.unserved")) == [], (
        "the exact join pairs every call with its own partner")
    assert list(_field(b, "contrast.unmapped")) == [], (
        "the exact join pairs every call with its own partner")
    assert sorted(_field(b, "contrast.errored")) == lines(rows, CAROL)
    assert not [r for r in table if S.CALL_ID in r], "a query-table row carries the call id"
