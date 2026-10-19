"""#1015 e2e: a gather lead that spends its above-guard rejections is stopped by the host (budget), whatever the names, with the repeat guard's precedence, replay parity and no model-authored byte reaching main."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import session_store  # noqa: E402
from defender.runtime.agent_role import GATHER_AGENT_ID_PREFIX  # noqa: E402
from defender.runtime.circuit_breaker import AGENT_FIXABLE_ERROR_CLASS  # noqa: E402
from defender.scripts.gather_tools import record_query as rq  # noqa: E402
# `wrap_fresh`'s frame grammar and the real store's read channel, both spent from their one
# home rather than re-spelled here — `_frames680` carries no optional dependency of its own.
from defender.tests.support.learning.curation._frames680 import FRAME_RE  # noqa: E402
from defender.tests.support.storage._session_store_705 import sql  # noqa: E402
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import LEAD, _Res, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402
from defender.tests.e2e.test_855_model_named_systems import (  # noqa: E402
    PARAMS,
    _above_guard,
    _bad_args,
    _dead_end,
    _summary,
)
from defender.tests.e2e.test_repeat_breaker_807 import (  # noqa: E402
    INCOMPLETE_IDIOM,
    _replay_rejections,
)

from defender.scripts.gather_tools.record_query import (  # noqa: E402
    REJECTION_BUDGET,
    REJECTION_BUDGET_ESCAPE,
    RejectionBudgetTrip,
    rejection_budget_dead_end_reason,
)

pytestmark = pytest.mark.e2e

B = REJECTION_BUDGET

LOUD_SYSTEM = "Zq7-Wintermute-Phantom"
LOUD_VERB = "Zq7-Sunspot-Verb"
LOUD_PARAM = "Zq7-CANARY-PARAM"


def _terminator(r: _Res) -> str | None:
    """How this lead's gather session ENDED, read out of the real session store the run wrote — the one place the..."""
    store = session_store.open_store_for_read(session_store.resolve_store_path(_run_handle_1165(r.run_dir)))
    try:
        rows = sql(
            store, "SELECT truncated_by FROM session WHERE agent_id = ?",
            (f"{GATHER_AGENT_ID_PREFIX}{LEAD}",),
        )
    finally:
        store.close()
    assert rows, "this lead opened no gather session — the run never dispatched"
    return rows[0][0]


def _budget_phrase(occurrence: int = B) -> str:
    """The leading phrase `rejection_detail` gives a budget trip's row — spent from the PRODUCER, not re-spelled."""
    return rq.rejection_detail(RejectionBudgetTrip(occurrence=occurrence, budget=B))


def _summary_body(r: _Res) -> str:
    """The summary main receives with its untrusted frame removed."""
    summary = _summary(r)
    m = FRAME_RE.fullmatch(summary)
    assert m is not None, \
        f"the summary is not one whole frame: {summary[:120]!r}"
    assert m.group("tag") == "untrusted", \
        f"the summary's one frame is not the untrusted one: {m.group('tag')!r}"
    return m.group("body")


def _summary_header(r: _Res) -> str:
    """The HARNESS-AUTHORED half of what main receives:"""
    body = _summary_body(r)
    header, sep, tail = body.partition("\n\n")
    assert sep, (
        "main's message carries no summary under the notice at all — #987 requires either the "
        f"summary the gather agent wrote or the fixed sentence saying it could not: {body!r}"
    )
    assert tail.strip(), "the summary under the notice is empty"
    return header


def _assert_budget_stop(r: _Res, *, occurrence: int = B) -> None:
    """THE THREE-PART ORACLE."""
    assert _terminator(r) == session_store.TRUNCATED_BY_DEAD_END, \
        f"the lead ended as {_terminator(r)!r}, not by the host's own decision"

    rows = _above_guard(r)
    assert rows, "no above-guard rejection was recorded, so the assertions below are vacuous"
    digest = rows[-1]["payload_digest"]
    assert digest.startswith(f"exit=64; {_budget_phrase(occurrence)}"), \
        f"the trip row does not lead with the budget phrase: {digest!r}"
    assert "turned back at seq" not in digest, \
        "a budget stop's row says the call repeated one already turned back — O2"

    reason = rejection_budget_dead_end_reason(
        RejectionBudgetTrip(occurrence=occurrence, budget=B))
    summary = _summary(r)
    assert "the lead's whole allowance" in summary, \
        "main was not told the lead spent its allowance — the reason below may be empty"
    assert REJECTION_BUDGET_ESCAPE in summary, "main was handed no escape for a budget stop"
    assert INCOMPLETE_IDIOM in summary, "the fixed idiom stopped following the escape"
    assert rq.REPEAT_ESCAPE not in summary, \
        "a budget stop handed main the repeat guard's escape"

    assert _summary_header(r) == (
        f"gather for {LEAD} hit a dead end: {reason} {REJECTION_BUDGET_ESCAPE} "
        f"{INCOMPLETE_IDIOM}"
    ), "main's context carries something besides the host's own two sentences — O4"


# ── O1: the bound holds however the calls differ ───────────────────────────────────────────


def test_a_budget_of_distinct_ghosts_ends_the_lead_at_the_schema_placement(tmp_path):
    """O1 through `wrap_tool_validate` — the argument schema turns the call back, so the row is written from the..."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-schema", verbs=elastic_ok(rec), turns=[
        *[_bad_args(f"ghost{i}") for i in range(B + 3)],
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B, \
        f"the lead wrote {len(rows)} above-guard rejections against a budget of {B}"
    assert len({row["system_key"] for row in rows}) == B, \
        "the ghosts did not key distinctly, so the REPEAT guard could have taken this stop"
    _assert_budget_stop(r)
    assert rec.calls == [], "the lead ran on past its dead end and executed a later call"


def test_a_budget_of_distinct_ghosts_ends_the_lead_at_the_grant_placement(tmp_path):
    """O1 through the SECOND above-guard placement."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-grant", verbs=elastic_ok(rec), turns=[
        *[q(f"ghost{i}", "query", PARAMS) for i in range(B + 3)],
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B, \
        f"the grant placement wrote {len(rows)} rejections against a budget of {B}"
    assert len({row["system_key"] for row in rows}) == B
    _assert_budget_stop(r)
    assert rec.calls == [], "the lead ran on past its dead end"


def test_a_successful_query_between_rejections_does_not_refill_the_budget(tmp_path):
    """O1's "regardless of successful calls in between" — the C3/C4 heart of this issue, and the explicit..."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-interleaved", verbs=elastic_ok(rec), turns=[
        _bad_args("g1"), _bad_args("g2"), q("elastic", "query", {"native_query": "FROM a"}),
        _bad_args("g3"), _bad_args("g4"), q("elastic", "query", {"native_query": "FROM b"}),
        _bad_args("g5"), _bad_args("g6"), q("elastic", "query", {"native_query": "FROM c"}),
        _bad_args("g7"), DONE,
    ])

    assert [row["exit_code"] for row in r.own_rows] == [64, 64, 0, 64, 64, 0, 64, 64], \
        "the lead did not run the interleaved shape through to its sixth rejection"
    assert rec.calls, \
        "no successful call reached the backend, so no reset was ever available"
    assert len(_above_guard(r)) == B
    _assert_budget_stop(r)
    assert len(rec.calls) == 2, "the lead ran on past its dead end and executed a third query"


# ── O5: below the budget, nothing changed ──────────────────────────────────────────────────


def test_a_lead_one_rejection_short_of_the_budget_is_untouched(tmp_path):
    """O5 — the liveness half."""
    below_rec = VerbRecorder()
    below = _run(tmp_path / "below", run_id="d1015-below", verbs=elastic_ok(below_rec), turns=[
        *[_bad_args(f"ghost{i}") for i in range(B - 1)],
        q("elastic", "query", PARAMS), DONE,
    ])
    at_rec = VerbRecorder()
    at = _run(tmp_path / "at", run_id="d1015-at", verbs=elastic_ok(at_rec), turns=[
        *[_bad_args(f"ghost{i}") for i in range(B)],
        q("elastic", "query", PARAMS), DONE,
    ])

    assert len(_above_guard(below)) == B - 1, "the rejections below the budget lost their rows"
    assert _terminator(below) is None, \
        f"a lead below the budget was stamped {_terminator(below)!r}"
    assert not _dead_end(below), "a lead below the budget was told it hit a dead end"
    assert len(below_rec.calls) == 1, "the corrected call never reached the backend"

    assert len(_above_guard(at)) == B
    assert _terminator(at) == session_store.TRUNCATED_BY_DEAD_END, \
        "one more rejection changed nothing, so the negatives above say nothing"
    assert _dead_end(at)
    assert at_rec.calls == [], "the lead at its budget still executed the corrected call"


# ── O2: the repeat guard's promise, and its precedence ─────────────────────────────────────


# ── O3: the recorded table replays to the same stop, of the same kind ──────────────────────


def test_the_replay_of_each_table_agrees_with_the_live_run_on_the_kind_of_stop(tmp_path):
    """O3 — an operator auditing a recorded run has only `executed_queries.jsonl`, and the stop must be..."""
    rec = VerbRecorder()
    budget = _run(tmp_path / "budget", run_id="d1015-replay-budget", verbs=elastic_ok(rec),
                  turns=[*[_bad_args(f"ghost{i}") for i in range(B)], DONE])
    repeat = _run(tmp_path / "repeat", run_id="d1015-replay-repeat", turns=[
        *[_bad_args("ghostone")] * 3, DONE])
    inter_rec = VerbRecorder()
    inter = _run(tmp_path / "inter", run_id="d1015-replay-inter", verbs=elastic_ok(inter_rec),
                 turns=[
                     _bad_args("g1"), _bad_args("g2"),
                     q("elastic", "query", {"native_query": "FROM a"}),
                     _bad_args("g3"), _bad_args("g4"),
                     q("elastic", "query", {"native_query": "FROM b"}),
                     _bad_args("g5"), _bad_args("g6"), DONE,
                 ])
    run_on = _run(tmp_path / "runon", run_id="d1015-replay-runon", turns=[
        *[_bad_args(f"ghost{i}") for i in range(B - 1)], DONE])

    # The live verdicts first: a parity claim over a table nobody stopped on is vacuous.
    _assert_budget_stop(budget)
    _assert_budget_stop(inter)
    assert _terminator(repeat) == session_store.TRUNCATED_BY_DEAD_END
    assert "turned back at seq" in _above_guard(repeat)[-1]["payload_digest"]
    assert _terminator(run_on) is None
    assert not _dead_end(run_on)

    assert _replay_rejections(budget.rows) == [(LEAD, B - 1, "budget")], \
        "the replay disagrees with the live budget stop, on the table that run wrote"
    assert _replay_rejections(repeat.rows) == [(LEAD, rq.REPEAT_THRESHOLD - 1, "repeat")], \
        "the replay reports the wrong guard for a stop the live run took as a repeat"
    assert _replay_rejections(inter.rows) == [(LEAD, 7, "budget")], \
        "the replay lost the stop's seq once successful rows sat between the rejections"
    assert _replay_rejections(run_on.rows) == [], \
        "the replay refuses a lead the live run let run on"


# ── O4: nothing the model wrote crosses into main ──────────────────────────────────────────


# ── the arms the adversary's pass added ────────────────────────────────────────────────────


def test_the_repeat_guard_takes_a_stop_that_is_both_a_repeat_and_the_budgets(tmp_path):
    """PRECEDENCE, on the only table where it is observable — and it is a claim about what MAIN is told, not an..."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-both", verbs=elastic_ok(rec), turns=[
        _bad_args("ghostone"), _bad_args("ghostone"),
        *[_bad_args(f"g{i}") for i in range(3)],
        _bad_args("ghostone"),
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B, \
        f"the lead wrote {len(rows)} rejections — the two guards did not collide on the last"
    assert rq.rejection_budget_trip(rows[:-1], LEAD) is not None, \
        "the budget would not have tripped here either, so this arm pins no precedence"

    digest = rows[-1]["payload_digest"]
    assert "turned back at seq" in digest, \
        "the budget took a stop the repeat guard owns — main lost the specific sentence"
    assert _budget_phrase() not in digest, "the budget's phrase reached a repeat guard's row"

    body = _summary_body(r)
    assert rq.REPEAT_ESCAPE in body, "main was handed the wrong escape for a repeat stop"
    assert REJECTION_BUDGET_ESCAPE not in body
    assert "the lead's whole allowance" not in body, \
        "main was told it spent its allowance for a stop taken on a repeat"

    assert _replay_rejections(r.rows) == [(LEAD, rows[-1]["seq"], "repeat")], \
        "the replay names a different guard than the one the live run stopped on — O3"
    assert rec.calls == [], "the lead ran on past its dead end"


def test_no_byte_the_model_authored_reaches_main_through_the_grant_placements_stop(tmp_path):
    """O4 at the SECOND placement."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-grant-leak", verbs=elastic_ok(rec), turns=[
        *[q(f"{LOUD_SYSTEM}-{i}", f"{LOUD_VERB}-{i}",
            {"native_query": f"FROM {LOUD_PARAM}-{i}"}) for i in range(B)],
        q("elastic", "query", PARAMS), DONE,
    ])

    rows = _above_guard(r)
    assert len(rows) == B, "the grant placement did not take this stop"
    _assert_budget_stop(r)

    body = _summary_body(r)
    for canary in (LOUD_VERB, LOUD_PARAM):
        assert canary in str(r.rows), \
            f"{canary} never reached the table, so its absence from main's context says nothing"
    assert len({row["system_key"] for row in rows}) == B, \
        "the ghosts did not key distinctly, so no per-call name existed for the stop to leak"
    for canary in (LOUD_SYSTEM, LOUD_VERB, LOUD_PARAM):
        assert canary not in body, \
            f"the model's own {canary!r} crossed into main's context through the grant stop"
    assert LOUD_SYSTEM not in str(r.rows), \
        "#1016 stopped withholding the model's system from the grant check's own row"
    for row in rows:
        assert row["system_key"] not in body, \
            "a ghost's fingerprint — a stable identifier of the model's string — reached main"

    # The truncation escape the whole-string canaries above cannot see: no run of six
    # characters from any dispatched value is in main's context either.
    for value in (LOUD_SYSTEM, LOUD_VERB, LOUD_PARAM):
        for i in range(len(value) - 5):
            assert value[i:i + 6] not in body, \
                f"a {value[i:i + 6]!r} fragment of the model's own argument reached main"


def test_a_lead_iterating_on_a_declared_systems_parameters_is_not_the_budgets(tmp_path):
    """C13, LIVE — the design's loudest non-obligation, and the one the predicate's unit arms cannot carry alone."""
    rec = VerbRecorder()
    r = _run(tmp_path, run_id="d1015-below", verbs=elastic_ok(rec), turns=[
        *[q("elastic", "query", {"native_query": f"FROM t{i}", "nope": i}) for i in range(5)],
        _bad_args("ghostone"),
        q("elastic", "query", PARAMS), DONE,
    ])

    below = [row for row in r.own_rows
             if not rq.in_rejection_domain(row)
             and row.get("error_class") == AGENT_FIXABLE_ERROR_CLASS]
    assert len(below) == 5, \
        f"the lead wrote {len(below)} below-guard refusals — this arm drives the wrong shape"
    assert len(_above_guard(r)) == 1, "the ghost did not land above the guard"

    assert _terminator(r) is None, \
        f"a healthy lead was ended as {_terminator(r)!r} — the budget counted C13's population"
    assert not _dead_end(r), "the lead was stopped after one above-guard rejection"
    assert rec.calls, "the corrected query never ran — the lead was killed before it"
    assert _replay_rejections(r.rows) == [], \
        "the replay reports a stop the live run did not take — O3"
