"""#826 — the four defects the #807 spec carved out and pointed at a follow-up.

This module holds the parts that need no agent: the elastic sort surface (item 2), the
failing-repeat wording of `repeat_note` (item 3), and the companion guard's predicate and
counted domain (item 4). Item 1 and the live behaviour of items 3 and 4 are driven end to end
in `tests/e2e/test_826_gather_deferred.py`.

Each test names the defect it closes, because every one of them is a REGRESSION in the strict
sense: the code shipped, the behaviour was measured, and the measurement is what the issue
records. `reviewer-measure-0807-b` is cited by number where it is the evidence.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.runtime.circuit_breaker import (
    AGENT_FIXABLE_ERROR_CLASS,
    INFRA_ERROR_CLASS,
    error_class_for_exit,
)
from defender.scripts.adapters import elastic_adapter as ea
from defender.scripts.adapters.faults import UpstreamFault
from defender.scripts.gather_tools import record_query as rq

LEAD = "l-001"


def _row(
    seq: int, *, system: str = "elastic", verb: str = "query",
    params: dict | None = None, exit_code: int = 64, query_id: str | None = None,
    lead: str = LEAD, digest: str | None = None,
) -> dict:
    """One queries-table row, with `error_class` computed by the PRODUCTION classifier — a
    fixture that restated it would be asserting its own arithmetic against the domain filter
    under test."""
    return {
        "lead_id": lead,
        "seq": seq,
        "system": system,
        "verb": verb,
        "query_id": query_id if query_id is not None else f"{system}.{verb}",
        "params": params if params is not None else {"native_query": "FROM logs"},
        "raw_command": f"{system} {verb}",
        "payload_path": f"gather_raw/{lead}/{seq}.json",
        "exit_code": exit_code,
        "error_class": error_class_for_exit(exit_code),
        "payload_status": "error" if exit_code else "ok",
        "payload_digest": digest if digest is not None else (
            f"exit={exit_code}; rejected" if exit_code else "12 bytes, 1 line(s)"
        ),
    }


def _above(seq: int, **kw) -> dict:
    return _row(seq, query_id=rq.ABOVE_GUARD_QUERY_ID, **kw)


# --------------------------------------------------------------------------------------- #
# ITEM 2 — the hardcoded `@timestamp` descending sort.
# --------------------------------------------------------------------------------------- #

def _body(**kw) -> dict:
    args = {
        "query_string": "host:db-1", "time_start": None, "time_end": None,
        "time_field": "@timestamp", "limit": 20, "sort": ea.DEFAULT_SORT,
    }
    args.update(kw)
    return ea._build_search_body(**args)


def test_the_default_sort_is_unchanged_newest_first():
    """The knob is ADDITIVE. Every call that does not mention `sort` must produce the exact
    body it produced before item 2 — `@timestamp` descending — or the fix is a silent
    behaviour change to every shipped query template and every recorded run's meaning."""
    assert ea.DEFAULT_SORT == ea.SORT_NEWEST_FIRST == "desc"
    assert _body()["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert ea.query.__kwdefaults__["sort"] == ea.DEFAULT_SORT
    assert ea.alerts.__kwdefaults__["sort"] == ea.DEFAULT_SORT


def test_a_lead_can_ask_for_the_start_of_its_window():
    """THE DEFECT (item 2): the order was hardcoded `desc`, so every capped result was the 20
    most RECENT matching docs and a lead asking what happened FIRST was answered with what
    happened last. `reviewer-measure-0807-b` is the measurement — `l-001`'s 20 docs spanned
    11:49:17-11:55:06 while the alert it was sent to explain sits at 11:40:23, entirely
    outside them, and no parameter existed that could have asked for the other end."""
    assert _body(sort="asc")["sort"] == [{"@timestamp": {"order": "asc"}}]
    # The window is untouched by the order — the same bracket, read from the other end.
    asc = _body(sort="asc", time_start="2026-08-07T11:30:00Z", time_end="2026-08-07T12:00:00Z")
    desc = _body(time_start="2026-08-07T11:30:00Z", time_end="2026-08-07T12:00:00Z")
    assert asc["query"] == desc["query"]
    assert asc["size"] == desc["size"]
    assert asc["sort"] != desc["sort"]


def test_an_unusable_sort_is_refused_and_says_what_the_two_orders_are():
    """`validate_params` checks param TYPES, not values, so `sort` is the adapter's own to
    refuse — and it refuses toward the fix, naming both orders and saying neither pages, since
    a lead that reaches for a third slice has to be told there is not one."""
    with pytest.raises(UpstreamFault) as exc:
        ea.resolve_sort("ascending")
    detail = exc.value.detail
    assert "ascending" in detail
    assert ea.SORT_OLDEST_FIRST in detail
    assert ea.SORT_NEWEST_FIRST in detail
    assert "narrow the window" in detail
    for refused in ("@timestamp", "", "DESC", None, 1):
        with pytest.raises(UpstreamFault):
            ea.resolve_sort(refused)  # type: ignore[arg-type]
    # A refused value must never reach Elasticsearch as a sort clause.
    with pytest.raises(UpstreamFault):
        _body(sort="rand()")


def test_the_result_envelope_says_which_end_of_the_window_it_holds():
    """The other half of item 2's complaint: "no signal to the lead that it got a slice at
    all". `returned_span` states WHICH docs came back; the envelope now states the order they
    were taken in, so a payload read off disk long after the call still answers "first 20 or
    last 20" without re-deriving it from the request."""
    docs = [{"@timestamp": "2026-08-07T11:40:23Z"}]
    env = ea.search_envelope("logs-*", docs, total=142, truncated=True, sort="asc")
    assert env["sort"] == "asc"
    assert (env["total"], env["returned"], env["truncated"]) == (142, 1, True)
    assert ea.search_envelope("logs-*", docs, 1, False, ea.DEFAULT_SORT)["sort"] == "desc"


def test_the_sort_param_is_visible_to_the_model_on_both_search_verbs():
    """A knob the dispatch catalog does not advertise is not a knob. Both search verbs declare
    it, with a default, so no existing call becomes invalid — the `esql` verb takes none of
    this, its ordering living in the pipe."""
    from defender.runtime.verbs import declared_params

    for verb in (ea.query, ea.alerts):
        declared = declared_params(verb)
        assert "sort" in declared, "the model cannot ask for an order it is never shown"
        assert declared["sort"].default == ea.DEFAULT_SORT
    assert "sort" not in declared_params(ea.esql)


# --------------------------------------------------------------------------------------- #
# ITEM 3 — ask (2)'s repeat notice never fired for a FAILING repeat.
# --------------------------------------------------------------------------------------- #

def _write(tmp_path: Path, rows: list[dict]) -> Path:
    from defender._io import append_jsonl
    from defender._run_paths import RunPaths

    append_jsonl(RunPaths(tmp_path).executed_queries, rows)
    return tmp_path


def test_a_repeat_whose_calls_keep_failing_is_named(tmp_path):
    """THE DEFECT (item 3): `_model_view` returned early for a non-zero exit ABOVE its
    `repeat_note` call, so the one population that never got a "you are repeating yourself"
    signal was the population repeating a request whose calls keep FAILING — the population
    most likely to loop, since a failure gives it nothing new to reason from either.

    The comparison itself needed no change: a failed call's digest is already `_record`'s
    `exit={code}; {detail}` form, so two failures match each other."""
    digest = "exit=1; Elasticsearch query failed (HTTP 400): parse_exception"
    _write(tmp_path, [_row(0, exit_code=1, digest=digest)])
    note = rq.repeat_note(
        tmp_path, LEAD, seq=1, system="elastic", verb="query",
        params={"native_query": "FROM logs"}, payload_digest=digest, exit_code=1,
    )
    assert note is not None, "a failing repeat still gets no signal"
    assert "REPEAT" in note
    assert "seq 0" in note


def test_a_failing_repeat_is_never_told_it_returned_a_payload(tmp_path):
    """The wording is the point, not just the firing. A call that failed returned no payload
    at all — telling it that "it returned the same payload byte for byte" describes an
    observation it does not have, and the fact that actually matched is the identical ERROR."""
    digest = "exit=64; unknown param(s) ['fields']"
    _write(tmp_path, [_row(0, exit_code=64, digest=digest)])
    failing = rq.repeat_note(
        tmp_path, LEAD, seq=1, system="elastic", verb="query",
        params={"native_query": "FROM logs"}, payload_digest=digest, exit_code=64,
    )
    assert failing is not None
    assert "payload" not in failing, failing
    assert "failed the same way" in failing

    ok_digest = "12 bytes, 1 line(s)"
    _write(tmp_path / "ok", [_row(0, exit_code=0, digest=ok_digest)])
    succeeding = rq.repeat_note(
        tmp_path / "ok", LEAD, seq=1, system="elastic", verb="query",
        params={"native_query": "FROM logs"}, payload_digest=ok_digest,
    )
    assert succeeding is not None
    assert "same payload byte for byte" in succeeding, \
        "the shipped success wording changed — item 3 was only ever about the failing arm"


def test_a_changed_request_that_fails_identically_is_a_no_op_too(tmp_path):
    """The NO-OP arm carries over with the same correction: a *different* request that failed
    with the identical error did not reach whatever is rejecting it, which is a different
    (and more useful) fact than "the result set did not move"."""
    digest = "exit=64; unknown param(s) ['fields']"
    _write(tmp_path, [_row(0, exit_code=64, params={"native_query": "a"}, digest=digest)])
    note = rq.repeat_note(
        tmp_path, LEAD, seq=1, system="elastic", verb="query",
        params={"native_query": "b"}, payload_digest=digest, exit_code=64,
    )
    assert note is not None
    assert "NO-OP" in note
    assert "seq 0" in note
    assert "identical error" in note


def test_the_exit_code_selects_wording_and_never_whether_a_note_fires(tmp_path):
    """`exit_code` must not become a second, quieter filter. The rows that match are the rows
    that match; a caller passing the wrong exit code gets the wrong PROSE, never silence."""
    digest = "exit=1; boom"
    _write(tmp_path, [_row(0, exit_code=1, digest=digest)])
    kw = dict(
        seq=1, system="elastic", verb="query",
        params={"native_query": "FROM logs"}, payload_digest=digest,
    )
    assert rq.repeat_note(tmp_path, LEAD, exit_code=1, **kw) is not None
    assert rq.repeat_note(tmp_path, LEAD, exit_code=0, **kw) is not None
    assert rq.repeat_note(tmp_path, LEAD, **kw) is not None, "the default changed behaviour"


# --------------------------------------------------------------------------------------- #
# ITEM 4 — the argument-schema repeat class had no guard and no record.
# --------------------------------------------------------------------------------------- #

def test_the_companion_guard_counts_what_the_first_guard_cannot_see():
    """THE DEFECT (item 4): a repeat loop the pydantic ARGUMENT SCHEMA turns back never
    reached `wrap_tool_execute`'s guard — its rows carry `ABOVE_GUARD_QUERY_ID` precisely so
    they cannot count there — and was bounded only by `DEFAULT_TOOL_RETRIES = 10`, whose
    exhaustion returned the same "Treat this lead as incomplete" idiom with no repeat named
    and no trip row.

    `rejection_trip` is that class's predicate, and the two guards' domains are COMPLEMENTARY:
    every row belongs to exactly one of them, so neither can report a trip the other's
    placement could have prevented."""
    rejections = [_above(0), _above(1)]
    assert rq.rejection_trip(rejections[:1], LEAD, system="elastic", verb="query",
                             params={"native_query": "FROM logs"}) is None
    trip = rq.rejection_trip(rejections, LEAD, system="elastic", verb="query",
                            params={"native_query": "FROM logs"})
    assert trip == rq.RepeatTrip(first_seq=0, occurrence=rq.REPEAT_THRESHOLD)

    # ... and the SAME rows are invisible to the first guard, which is why this one exists.
    assert rq.repeat_trip(rejections, LEAD, system="elastic", verb="query",
                          params={"native_query": "FROM logs"}) is None
    # ... and executed rows are invisible to THIS one, so a lead is never stopped twice for
    # the same two occurrences.
    executed = [_row(0, exit_code=0), _row(1, exit_code=0)]
    assert rq.rejection_trip(executed, LEAD, system="elastic", verb="query",
                             params={"native_query": "FROM logs"}) is None
    assert rq.repeat_trip(executed, LEAD, system="elastic", verb="query",
                          params={"native_query": "FROM logs"}) is not None


def test_the_infra_half_of_the_above_guard_rows_stays_the_breakers():
    """The domain is narrower than `ABOVE_GUARD_QUERY_ID` alone, by `error_class`. The third
    above-guard writer is `_grant_check`'s adapter-load-error branch, whose rows are `infra`
    (exit 2) and whose repeat `circuit_breaker` already owns end to end — two failures mark
    the system down and the third call gets the down-message. Counting them here would give
    one shape two owners and turn an outage into a lead-level dead end."""
    load_errors = [_above(0, exit_code=2), _above(1, exit_code=2)]
    assert error_class_for_exit(2) == INFRA_ERROR_CLASS
    assert error_class_for_exit(64) == AGENT_FIXABLE_ERROR_CLASS
    assert rq.rejection_trip(load_errors, LEAD, system="elastic", verb="query",
                             params={"native_query": "FROM logs"}) is None
    # An infra row must not even top up a count the agent-fixable rows nearly reached.
    mixed = [_above(0, exit_code=2), _above(1, exit_code=64)]
    assert rq.rejection_trip(mixed, LEAD, system="elastic", verb="query",
                             params={"native_query": "FROM logs"}) is None


def test_the_companion_guard_keys_on_the_same_identity_as_the_first():
    """One counting rule, two domains — never two definitions of what a repeat IS. A guard
    that canonicalised `params` differently at its own placement would refuse a lead for
    calls the other guard would have called distinct."""
    params = {"b": 2, "a": [1, {"z": None}]}
    reordered = {"a": [1, {"z": None}], "b": 2}
    rows = [_above(0, params=params), _above(1, params=params)]
    assert rq.rejection_trip(rows, LEAD, system="elastic", verb="query",
                             params=reordered) is not None
    assert rq.rejection_trip(rows, LEAD, system="elastic", verb="query",
                             params={"a": 1}) is None
    # A different lead's rejections are a different lead's problem.
    assert rq.rejection_trip(
        [_above(0, params=params, lead="l-002"), _above(1, params=params, lead="l-002")],
        LEAD, system="elastic", verb="query", params=params,
    ) is None


def test_the_trip_row_detail_says_turned_back_not_issued():
    """A downstream reader that could not tell the companion guard's trip row from the first
    guard's would report a lead as having QUERIED something it never queried: nothing the
    companion guard counts ever reached a system of record. Both details stay inside
    `_record`'s 160-character digest truncation."""
    trip = rq.RepeatTrip(first_seq=0, occurrence=3)
    detail = rq.rejection_trip_detail(trip)
    assert "turned back" in detail
    assert "seq 0" in detail
    assert "3rd" in detail
    assert "issued" not in detail
    assert "issued" in rq.repeat_trip_detail(trip), "the executed-path wording drifted"
    assert len(detail) <= 160

    reason = rq.rejection_dead_end_reason("elastic", "nosuch-verb", trip)
    assert "elastic nosuch-verb" in reason
    assert "rejected before it ran" in reason
    assert "structural" in reason
