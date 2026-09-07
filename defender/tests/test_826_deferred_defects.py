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

import hashlib
import re
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


#: The payload text a seeded SUCCESS row stands for (#877 F-9): the fixture derives both its
#: digest and its content hash from it rather than stating either.
_SEEDED_PAYLOAD = "abcdefghijkl"


def _row(
    seq: int, *, system: str = "elastic", verb: str = "query",
    params: dict | None = None, exit_code: int = 64, query_id: str | None = None,
    lead: str = LEAD, digest: str | None = None,
) -> dict:
    """One queries-table row, with `error_class` and `payload_sha256` computed by the
    PRODUCTION helpers — a fixture that restated either would be asserting its own arithmetic
    against the domain filter under test. A failed row's persisted payload text is `""`, which
    is what both writers hash, so every failure shares one content hash and the digest is what
    separates two of them (#877 F-9)."""
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
            f"exit={exit_code}; rejected" if exit_code
            else rq.payload_digest(_SEEDED_PAYLOAD, "", 0)
        ),
        "payload_sha256": rq.payload_sha256("" if exit_code else _SEEDED_PAYLOAD),
    }


def _above(seq: int, **kw) -> dict:
    return _row(seq, query_id=rq.ABOVE_GUARD_QUERY_ID, **kw)


# ITEM 2 — the hardcoded `@timestamp` descending sort.

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


# ITEM 3 — ask (2)'s repeat notice never fired for a FAILING repeat.

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
        params={"native_query": "FROM logs"}, payload_digest=digest,
        payload_sha256=rq.payload_sha256(""), exit_code=1,
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
        params={"native_query": "FROM logs"}, payload_digest=digest,
        payload_sha256=rq.payload_sha256(""), exit_code=64,
    )
    assert failing is not None
    assert "payload" not in failing, failing
    assert "failed the same way" in failing

    ok_digest = rq.payload_digest(_SEEDED_PAYLOAD, "", 0)
    _write(tmp_path / "ok", [_row(0, exit_code=0)])
    succeeding = rq.repeat_note(
        tmp_path / "ok", LEAD, seq=1, system="elastic", verb="query",
        params={"native_query": "FROM logs"}, payload_digest=ok_digest,
        payload_sha256=rq.payload_sha256(_SEEDED_PAYLOAD),
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
        params={"native_query": "b"}, payload_digest=digest,
        payload_sha256=rq.payload_sha256(""), exit_code=64,
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
        payload_sha256=rq.payload_sha256(""),
    )
    assert rq.repeat_note(tmp_path, LEAD, exit_code=1, **kw) is not None
    assert rq.repeat_note(tmp_path, LEAD, exit_code=0, **kw) is not None
    assert rq.repeat_note(tmp_path, LEAD, **kw) is not None, "the default changed behaviour"


# ITEM 4 — the argument-schema repeat class had no guard and no record.

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

    # The trip row is ALSO this call's rejection record — the row it would otherwise have
    # written does not exist separately — so the error it produced is kept as a tail, and the
    # trip phrase leads so the 160-char digest truncation eats the tail rather than it.
    with_cause = rq.rejection_trip_detail(trip, "unknown param(s) ['fields']")
    assert with_cause.startswith(detail)
    assert "unknown param(s)" in with_cause
    assert len(rq.rejection_trip_detail(trip, "x" * 500)[:160]) == 160
    assert detail in rq.rejection_trip_detail(trip, "x" * 500)[:160], \
        "a long rejection pushed the repetition itself out of the digest"

    reason = rq.rejection_dead_end_reason("elastic", "nosuch-verb", trip)
    assert "elastic nosuch-verb" in reason
    assert "rejected before it ran" in reason
    assert "structural" in reason


# #871 — the companion guard could not tell two UNDECLARED systems apart, because #855 keeps
# their names off the row and every one of them coarsens to `system=""`. `system_key` carries
# the identity across the seam as a digest. These are the predicate-level arms; the lead-level
# ones are in `tests/e2e/test_855_model_named_systems.py`.


def test_the_fingerprint_gives_three_answers_and_each_one_is_a_decision():
    """`system_fingerprint(raw, recorded)` is where the coarsened row's identity is minted.
    Three answers, and none of them is a default: `""` when the row kept its system (a
    declared system keys as ITSELF, or `elastic`'s above-guard rejections would form a group
    its below-guard rows are not in); `""` when the raw string is blank or whitespace (N5 — an
    argument with no readable system in it is one mistake however it is malformed); a digest
    otherwise. That the two above-guard WRITERS actually spend this function rather than
    deriving their own is observed on a live table, in
    `..._only_a_coarsened_row_carries_a_system_key_and_it_is_a_digest`.

    The digest is pinned to a FIXED function of the string rather than left to the
    implementation, because O3 is a claim across time: a table recorded by one build is
    replayed by a later one, and any per-process or salted hash (`hash()` is randomized per
    interpreter) makes yesterday's dead end unauditable while passing every in-process
    assertion here."""
    assert rq.system_fingerprint("ghostone", "elastic") == "", \
        "a row that kept its system took a fingerprint too, splitting that system's count"
    assert rq.system_fingerprint("elastic", "elastic") == ""
    assert rq.system_fingerprint("", "") == "", "a blank system was given an identity (N5)"
    assert rq.system_fingerprint("   ", "") == "", "whitespace was read as a readable system"

    fp = rq.system_fingerprint("ghostone", "")
    assert re.fullmatch(r"[0-9a-f]{16}", fp), f"not a 16-char lowercase hex digest: {fp!r}"
    assert fp == rq.system_fingerprint("ghostone", ""), "the same string keyed two ways"
    assert fp != rq.system_fingerprint("ghosttwo", ""), "two strings keyed one way"
    assert fp == hashlib.sha256(b"ghostone").hexdigest()[:16], \
        "the digest is not a fixed function of the string, so a recorded table cannot be replayed"


def test_two_undeclared_systems_are_two_counts_at_the_predicate():
    """THE DEFECT (#871): `rejection_trip` keyed on `(system, verb, params)` alone, and #855
    makes `system` `""` for every undeclared name — so `ghostone` and `ghosttwo` under one
    verb and params were one group and the third such rejection ended the lead, which is the
    one thing #826 item 4's guard promised it would never do to a call that DIFFERS.

    Driven at the predicate rather than only end to end because the split has to be visible in
    BOTH directions on the same rows: the same ghost still trips, and a different ghost does
    not inherit the count."""
    one, two = rq.system_fingerprint("ghostone", ""), rq.system_fingerprint("ghosttwo", "")
    params = {"native_query": "FROM logs"}
    mixed = [dict(_above(0, system=""), system_key=one),
             dict(_above(1, system=""), system_key=two)]

    assert rq.rejection_trip(mixed, LEAD, system="", verb="query", params=params,
                             system_key=one) is None, \
        "a rejection was refused on a count another undeclared system earned"

    repeated = [dict(_above(0, system=""), system_key=one),
                dict(_above(1, system=""), system_key=one)]
    trip = rq.rejection_trip(repeated, LEAD, system="", verb="query", params=params,
                            system_key=one)
    assert trip == rq.RepeatTrip(first_seq=0, occurrence=rq.REPEAT_THRESHOLD), \
        "the same undeclared system named three times stopped being bounded"
    assert rq.rejection_trip(repeated, LEAD, system="", verb="query", params=params,
                             system_key=two) is None


def test_a_row_written_before_the_fourteenth_column_existed_still_counts():
    """THE COERCION, and it is load-bearing: `_row` above builds the row keys LITERALLY and
    carries no `system_key`, which is exactly the shape of every row already on disk from a
    run that predates this column. `row.get("system_key")` is `None` there, and a guard that
    compared `None` against the live `""` would silently stop counting every pre-existing
    rejection — the same silent terminator #826 item 4 closed, reopened by its own fix.

    Both sides coerce, because #807's replay oracle passes `row.get("system_key")` straight
    into the live argument the way it passes `system`: over an archived table that is `None`
    on every row, and an oracle that could not match its own input is not the parity O3 asks
    for.

    The negative on the same rows is what makes this more than "coerce and always match": a
    call that DID mint a fingerprint must not count keyless rows toward its own total."""
    params = {"native_query": "FROM logs"}
    keyless = [_above(0), _above(1)]
    assert "system_key" not in keyless[0], \
        "the fixture grew the column, and with it the only evidence of the coercion"

    assert rq.rejection_trip(keyless, LEAD, system="elastic", verb="query", params=params,
                             system_key="") is not None, \
        "a row written before the column existed stopped counting"
    assert rq.rejection_trip(keyless, LEAD, system="elastic", verb="query", params=params,
                             system_key=None) is not None, \
        "the replay oracle's own argument shape matches nothing"
    explicit_none = [dict(_above(0), system_key=None), dict(_above(1), system_key=None)]
    assert rq.rejection_trip(explicit_none, LEAD, system="elastic", verb="query",
                             params=params, system_key="") is not None

    assert rq.rejection_trip(keyless, LEAD, system="elastic", verb="query", params=params,
                             system_key=rq.system_fingerprint("ghostone", "")) is None, \
        "a fingerprinted call inherited the count of rows that carry no fingerprint"


def test_the_first_guard_is_untouched_by_the_second_guards_new_identity():
    """`repeat_trip`'s callers pass no `system_key` and must behave exactly as they did: its
    domain is the EXECUTED rows, whose `system` is always the dispatched name, so there is no
    identity for a fingerprint to add and a default that leaked one would split a real
    system's repeat count by placement."""
    params = {"native_query": "FROM logs"}
    executed = [_row(0, exit_code=0), _row(1, exit_code=0)]
    assert rq.repeat_trip(executed, LEAD, system="elastic", verb="query",
                          params=params) == rq.RepeatTrip(
        first_seq=0, occurrence=rq.REPEAT_THRESHOLD)
    assert rq.repeat_trip(executed, LEAD, system="elastic", verb="query", params=params,
                          system_key="") is not None, \
        "the shared counting loop's keyword did not reach the first guard"
