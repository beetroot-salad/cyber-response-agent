"""#826: elastic sort surface, failing-repeat wording of `repeat_note`, and the companion guard's
predicate and counted domain (regressions for shipped behaviour)."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from defender.systems.circuit_breaker import (
    AGENT_FIXABLE_ERROR_CLASS,
    INFRA_ERROR_CLASS,
    error_class_for_exit,
)
from defender.integrations import elastic_adapter as ea
from defender.kit.faults import UpstreamFault
from defender.knowledge import _query_rules
from defender.investigation import record_query as rq

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
    return _row(seq, query_id=_query_rules.ABOVE_GUARD_QUERY_ID, **kw)


# ITEM 2 — the hardcoded `@timestamp` descending sort.

def _body(**kw) -> dict:
    args = {
        "query_string": "host:db-1", "time_start": None, "time_end": None,
        "time_field": "@timestamp", "limit": 20, "sort": ea.DEFAULT_SORT,
    }
    args.update(kw)
    return ea._build_search_body(**args)


def test_the_default_sort_is_unchanged_newest_first():
    assert ea.DEFAULT_SORT == ea.SORT_NEWEST_FIRST == "desc"
    assert _body()["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert ea.query.__kwdefaults__["sort"] == ea.DEFAULT_SORT
    assert ea.alerts.__kwdefaults__["sort"] == ea.DEFAULT_SORT


def test_a_lead_can_ask_for_the_start_of_its_window():
    """THE DEFECT (item 2)."""
    assert _body(sort="asc")["sort"] == [{"@timestamp": {"order": "asc"}}]
    # The window is untouched by the order — the same bracket, read from the other end.
    asc = _body(sort="asc", time_start="2026-08-07T11:30:00Z", time_end="2026-08-07T12:00:00Z")
    desc = _body(time_start="2026-08-07T11:30:00Z", time_end="2026-08-07T12:00:00Z")
    assert asc["query"] == desc["query"]
    assert asc["size"] == desc["size"]
    assert asc["sort"] != desc["sort"]


def test_an_unusable_sort_is_refused_and_says_what_the_two_orders_are():
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
    """The other half of item 2's complaint."""
    docs = [{"@timestamp": "2026-08-07T11:40:23Z"}]
    env = ea.search_envelope("logs-*", docs, total=142, truncated=True, sort="asc")
    assert env["sort"] == "asc"
    assert (env["total"], env["returned"], env["truncated"]) == (142, 1, True)
    assert ea.search_envelope("logs-*", docs, 1, False, ea.DEFAULT_SORT)["sort"] == "desc"


def test_the_sort_param_is_visible_to_the_model_on_both_search_verbs():
    from defender.kit.verbs import declared_params

    for verb in (ea.query, ea.alerts):
        declared = declared_params(verb)
        assert "sort" in declared, "the model cannot ask for an order it is never shown"
        assert declared["sort"].default == ea.DEFAULT_SORT
    assert "sort" not in declared_params(ea.esql)


# ITEM 3 — ask (2)'s repeat notice never fired for a FAILING repeat.

def _write(tmp_path: Path, rows: list[dict]):  # noqa: ANN202 — a `RunState` (#1235)
    """A run that starts holding `rows` — a branch sibling's inherited prefix, handed to the
    run's state the way seeding hands it (`RunState.inherit_rows`, #1235 round 2). Returns the
    state: the live reader (`repeat_note` here) reads it, never `executed_queries.jsonl`."""
    from defender.investigation.run_state import RunState

    tmp_path.mkdir(parents=True, exist_ok=True)
    state = RunState(tmp_path, "r826")
    state.inherit_rows(rows)
    return state


def test_a_repeat_whose_calls_keep_failing_is_named(tmp_path):
    """THE DEFECT (item 3)."""
    digest = "exit=1; Elasticsearch query failed (HTTP 400): parse_exception"
    state = _write(tmp_path, [_row(0, exit_code=1, digest=digest)])
    note = rq.repeat_note(
        state, LEAD, seq=1, system="elastic", verb="query",
        params={"native_query": "FROM logs"}, payload_digest=digest,
        payload_sha256=rq.payload_sha256(""), exit_code=1,
    )
    assert note is not None, "a failing repeat still gets no signal"
    assert "REPEAT" in note
    assert "seq 0" in note


def test_a_failing_repeat_is_never_told_it_returned_a_payload(tmp_path):
    digest = "exit=64; unknown param(s) ['fields']"
    state = _write(tmp_path, [_row(0, exit_code=64, digest=digest)])
    failing = rq.repeat_note(
        state, LEAD, seq=1, system="elastic", verb="query",
        params={"native_query": "FROM logs"}, payload_digest=digest,
        payload_sha256=rq.payload_sha256(""), exit_code=64,
    )
    assert failing is not None
    assert "payload" not in failing, failing
    assert "failed the same way" in failing

    ok_digest = rq.payload_digest(_SEEDED_PAYLOAD, "", 0)
    ok_state = _write(tmp_path / "ok", [_row(0, exit_code=0)])
    succeeding = rq.repeat_note(
        ok_state, LEAD, seq=1, system="elastic", verb="query",
        params={"native_query": "FROM logs"}, payload_digest=ok_digest,
        payload_sha256=rq.payload_sha256(_SEEDED_PAYLOAD),
    )
    assert succeeding is not None
    assert "same payload byte for byte" in succeeding, \
        "the shipped success wording changed — item 3 was only ever about the failing arm"


def test_a_changed_request_that_fails_identically_is_a_no_op_too(tmp_path):
    digest = "exit=64; unknown param(s) ['fields']"
    state = _write(tmp_path, [_row(0, exit_code=64, params={"native_query": "a"}, digest=digest)])
    note = rq.repeat_note(
        state, LEAD, seq=1, system="elastic", verb="query",
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
    state = _write(tmp_path, [_row(0, exit_code=1, digest=digest)])
    kw = dict(
        seq=1, system="elastic", verb="query",
        params={"native_query": "FROM logs"}, payload_digest=digest,
        payload_sha256=rq.payload_sha256(""),
    )
    assert rq.repeat_note(state, LEAD, exit_code=1, **kw) is not None
    assert rq.repeat_note(state, LEAD, exit_code=0, **kw) is not None
    assert rq.repeat_note(state, LEAD, **kw) is not None, "the default changed behaviour"


# ITEM 4 — the argument-schema repeat class had no guard and no record.

def test_the_companion_guard_counts_what_the_first_guard_cannot_see():
    """THE DEFECT (item 4)."""
    rejections = [_above(0), _above(1)]
    assert rq.rejection_trip(rejections[:1], LEAD, system="elastic", verb="query",
                             params={"native_query": "FROM logs"}, system_key="") is None
    trip = rq.rejection_trip(rejections, LEAD, system="elastic", verb="query",
                            params={"native_query": "FROM logs"}, system_key="")
    assert trip == rq.RepeatTrip(first_seq=0, occurrence=rq.REPEAT_THRESHOLD)

    # ... and the SAME rows are invisible to the first guard, which is why this one exists.
    assert rq.repeat_trip(rejections, LEAD, system="elastic", verb="query",
                          params={"native_query": "FROM logs"}) is None
    # ... and executed rows are invisible to THIS one, so a lead is never stopped twice for
    # the same two occurrences.
    executed = [_row(0, exit_code=0), _row(1, exit_code=0)]
    assert rq.rejection_trip(executed, LEAD, system="elastic", verb="query",
                             params={"native_query": "FROM logs"}, system_key="") is None
    assert rq.repeat_trip(executed, LEAD, system="elastic", verb="query",
                          params={"native_query": "FROM logs"}) is not None


def test_the_infra_half_of_the_above_guard_rows_stays_the_breakers():
    """The domain is narrower than `ABOVE_GUARD_QUERY_ID` alone, by `error_class`."""
    load_errors = [_above(0, exit_code=2), _above(1, exit_code=2)]
    assert error_class_for_exit(2) == INFRA_ERROR_CLASS
    assert error_class_for_exit(64) == AGENT_FIXABLE_ERROR_CLASS
    assert rq.rejection_trip(load_errors, LEAD, system="elastic", verb="query",
                             params={"native_query": "FROM logs"}, system_key="") is None
    # An infra row must not even top up a count the agent-fixable rows nearly reached.
    mixed = [_above(0, exit_code=2), _above(1, exit_code=64)]
    assert rq.rejection_trip(mixed, LEAD, system="elastic", verb="query",
                             params={"native_query": "FROM logs"}, system_key="") is None


def test_the_companion_guard_keys_on_the_same_identity_as_the_first():
    params = {"b": 2, "a": [1, {"z": None}]}
    reordered = {"a": [1, {"z": None}], "b": 2}
    rows = [_above(0, params=params), _above(1, params=params)]
    assert rq.rejection_trip(rows, LEAD, system="elastic", verb="query",
                             params=reordered, system_key="") is not None
    assert rq.rejection_trip(rows, LEAD, system="elastic", verb="query",
                             params={"a": 1}, system_key="") is None
    # A different lead's rejections are a different lead's problem.
    assert rq.rejection_trip(
        [_above(0, params=params, lead="l-002"), _above(1, params=params, lead="l-002")],
        LEAD, system="elastic", verb="query", params=params, system_key="",
    ) is None


def test_the_fingerprint_gives_three_answers_and_each_one_is_a_decision():
    """`system_fingerprint(raw, recorded)` is where the coarsened row's identity is minted."""
    assert rq.system_fingerprint("ghostone", "elastic") == "", \
        "a row that kept its system took a fingerprint too, splitting that system's count"
    assert rq.system_fingerprint("elastic", "elastic") == ""
    assert rq.system_fingerprint("", "") == "", "a blank system was given an identity (N5)"
    assert rq.system_fingerprint("   ", "") == "", "whitespace was read as a readable system"

    fp = rq.system_fingerprint("ghostone", "")
    assert re.fullmatch(r"[0-9a-f]{64}", fp), f"not a full-width lowercase hex digest: {fp!r}"
    assert fp == rq.system_fingerprint("ghostone", ""), "the same string keyed two ways"
    assert fp != rq.system_fingerprint("ghosttwo", ""), "two strings keyed one way"
    assert fp == hashlib.sha256(b"ghostone").hexdigest(), \
        "the digest is not a fixed function of the string, so a recorded table cannot be replayed"


def test_the_fingerprint_hashes_the_whole_string_exactly_as_the_model_wrote_it():
    """`ghostone`/`ghosttwo`/`ghostthree` cannot pin this on their own."""
    for raw in ("elastic-prod", "elastic-staging", "Elastic", " elastic ", "\u00e9lastic"):
        assert rq.system_fingerprint(raw, "") == \
            hashlib.sha256(raw.encode("utf-8")).hexdigest(), \
            f"{raw!r} was normalised or truncated before hashing"

    prefixed = {rq.system_fingerprint(r, "")
                for r in ("elastic-prod", "elastic-staging", "elastic-dev")}
    assert len(prefixed) == 3, \
        "three environment variants of one name are one group again — a truncating digest"
    assert rq.system_fingerprint("Elastic", "") != rq.system_fingerprint("elastic", ""), \
        "case was folded away, so two names the registry tells apart key the same"
    assert rq.system_fingerprint(" ghostone ", "") != rq.system_fingerprint("ghostone", ""), \
        "surrounding whitespace was stripped before hashing, not merely tested for emptiness"


def test_an_unencodable_system_string_is_fingerprinted_rather_than_raising():
    lone = "\ud800ghost"
    fp = rq.system_fingerprint(lone, "")
    assert re.fullmatch(r"[0-9a-f]{64}", fp), \
        f"an unencodable system string did not produce a digest: {fp!r}"
    assert fp != rq.system_fingerprint("\ud801ghost", ""), \
        "two different unencodable ghosts collided — the encoding folded them to one byte"


def test_two_undeclared_systems_are_two_counts_at_the_predicate():
    """THE DEFECT (#871)."""
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


def test_the_identity_is_the_pair_and_the_request_half_still_counts():
    """`system_key` EXTENDS the identity;"""
    ghost = rq.system_fingerprint("ghostone", "")
    varied = [dict(_above(0, system="", params={"native_query": "FROM one"}), system_key=ghost),
              dict(_above(1, system="", params={"native_query": "FROM two"}), system_key=ghost)]

    assert rq.rejection_trip(varied, LEAD, system="", verb="query",
                             params={"native_query": "FROM three"},
                             system_key=ghost) is None, \
        "three different requests under one ghost ended the lead — the request key was dropped"
    assert rq.rejection_trip(varied, LEAD, system="", verb="nosuch-verb",
                             params={"native_query": "FROM one"},
                             system_key=ghost) is None, \
        "a different verb inherited the count, so only the digest is being compared"

    same = [dict(_above(0, system=""), system_key=ghost),
            dict(_above(1, system=""), system_key=ghost)]
    assert rq.rejection_trip(same, LEAD, system="", verb="query",
                             params={"native_query": "FROM logs"},
                             system_key=ghost) is not None, \
        "one ghost and one request stopped being a group, so the negatives above say nothing"


def test_a_call_with_no_readable_system_inherits_no_ghosts_count():
    """The other direction of the wildcard, and the one no arm here reaches."""
    params = {"native_query": "FROM logs"}
    ghosts = [dict(_above(0, system=""), system_key=rq.system_fingerprint("ghostone", "")),
              dict(_above(1, system=""), system_key=rq.system_fingerprint("ghosttwo", ""))]

    assert rq.rejection_trip(ghosts, LEAD, system="", verb="query", params=params,
                             system_key="") is None, \
        "an unreadable call was refused on a count two named ghosts earned"

    blanks = [dict(_above(0, system=""), system_key=""),
              dict(_above(1, system=""), system_key="")]
    assert rq.rejection_trip(blanks, LEAD, system="", verb="query", params=params,
                             system_key="") is not None, \
        "two unreadable calls stopped being one mistake (N5), so the negative above is vacuous"


def test_an_invisible_system_string_is_no_more_readable_than_an_empty_one():
    """N5's equivalence class is "nothing a reader could tell apart from an empty argument",
    and `.strip()` is not that question."""
    invisible = ["\u200b", "\u200b\u200b", "\ufeff", "\u200c\u200d", "\u2060", "\u00ad",
                 "\x00", "\x00\x00"]
    for raw in invisible:
        assert rq.system_fingerprint(raw, "") == "", \
            f"{raw!r} renders as an empty system argument and was given an identity anyway"

    params = {"native_query": "FROM logs"}
    rows = [dict(_above(0, system=""), system_key=rq.system_fingerprint(invisible[0], "")),
            dict(_above(1, system=""), system_key=rq.system_fingerprint(invisible[1], ""))]
    assert rq.rejection_trip(rows, LEAD, system="", verb="query", params=params,
                             system_key=rq.system_fingerprint(invisible[2], "")) is not None, \
        "three indistinguishable invisible strings were three repeat groups, so the loop " \
        "they make is bounded by nothing"

    assert rq.system_fingerprint("\u200bg", "") != "", \
        "a string carrying one readable character stopped being fingerprinted"


def test_the_dead_end_message_asks_the_same_readability_question_the_fold_does():
    trip = rq.RepeatTrip(first_seq=0, occurrence=rq.REPEAT_THRESHOLD)
    unreadable = "system/verb unreadable in the call's own arguments"

    for verb in ("\u200b", "\ufeff", "\x00", "", "   "):
        assert unreadable in rq.rejection_dead_end_reason("", verb, trip), \
            f"an invisible verb {verb!r} was named to MAIN instead of reported unreadable"

    assert unreadable not in rq.rejection_dead_end_reason("", "nosuch-verb", trip), \
        "a readable verb stopped being named, so the assertions above say nothing"
    assert "an undeclared system query" in rq.rejection_dead_end_reason(
        "an undeclared system", "query", trip), \
        "the host's own words for a ghost stopped reaching the message"


def test_readability_is_a_fixed_function_of_the_string_not_of_the_interpreter():
    """WHICH predicate answers N5, pinned — the arm above pins that invisible strings fold, and
    every predicate that folds them passes it."""
    for raw in ("\ue000", "\uf8ff", "\U000f0000", "\u0378", "\U0002fffe"):
        assert rq.names_something_readable(raw), \
            f"{raw!r} was folded into the no-readable-system group; if it is unassigned today " \
            "that answer changes under a newer Unicode database, and the recorded key with it"
        assert rq.system_fingerprint(raw, "") != "", \
            f"{raw!r} minted no identity, so two calls naming two of these are one repeat group"

    # The complementary direction, so this is not satisfied by "fingerprint everything".
    for raw in ("\u200b", "\ufeff", "\x00", "", "\u00a0"):
        assert not rq.names_something_readable(raw), \
            f"{raw!r} renders as nothing and was read as a readable system name"


def test_a_non_string_system_is_coerced_rather_than_raising():
    for raw in (None, 12345, True, {"n": 1}, ["ghost"], b"ghost"):
        assert rq.system_fingerprint(raw, "") == "", \
            f"a non-string system argument ({raw!r}) was fingerprinted or raised"


def test_a_row_written_before_the_fourteenth_column_existed_still_counts():
    """THE COERCION, and it is load-bearing."""
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
    """`repeat_trip`'s callers pass no `system_key` and must behave exactly as they did."""
    params = {"native_query": "FROM logs"}
    executed = [_row(0, exit_code=0), _row(1, exit_code=0)]
    assert rq.repeat_trip(executed, LEAD, system="elastic", verb="query",
                          params=params) == rq.RepeatTrip(
        first_seq=0, occurrence=rq.REPEAT_THRESHOLD)
    assert rq.repeat_trip(executed, LEAD, system="elastic", verb="query", params=params,
                          system_key="") is not None, \
        "the shared counting loop's keyword did not reach the first guard"
