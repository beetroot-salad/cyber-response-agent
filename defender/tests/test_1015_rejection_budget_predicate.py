"""#1015 — the PER-LEAD REJECTION BUDGET, at the predicate and at the strings it composes.

THE CODE DOES NOT EXIST YET. Every symbol in the import block below is the surface the design
doc (issue #1015, "Discussion outcome — intent + design") specifies, so this module is RED by
construction until it is built. The live half — a real gather lead driven to a real budget stop
through the real `QueryCapture` placements — is `tests/e2e/test_1015_rejection_budget.py`.

WHAT THE DEFECT IS
------------------
`rejection_trip` (#826 item 4, #871) bounds a repeat loop ABOVE the guard by IDENTITY: three
rejections of the SAME request end the lead. Nothing bounds a lead whose rejections all
DIFFER. Measured on main (the issue's C3/C4, reproduced here by the e2e half): 30 distinct
ghost names end at `UnexpectedModelBehavior` after 11 rejections with pydantic-ai's own text
(and its documentation URL) crossing into main's context; one successful call every nine turns
resets the framework's per-tool retry count (`ToolManager.for_run_step` rebuilds `retries`
excluding `succeeded_tools`) and the lead spends its whole request budget — 36 rejections
against 4 real queries. `names_something_readable` is deliberately blind to assigned-but-blank
codepoints (U+3164, U+2800, U+115F, U+1160, U+FE0F), so the family of distinct identities is
unbounded and no cleverer notion of emptiness closes it.

THE CONTAINMENT is an AGGREGATE, identity-blind bound over exactly `rejection_trip`'s domain:
`lead_id == lead`, `query_id == ABOVE_GUARD_QUERY_ID`, `error_class == agent-fixable`.

THE OBLIGATIONS these arms carry (verbatim ids from the design doc)
------------------------------------------------------------------
O1  a bounded host-decided stop, regardless of identity or interleaved success
O2  the repeat guard's promise stands — a budget stop must not say "turned back at seq"
O4  no model-authored byte reaches main's context through the budget stop
O5  a lead below the budget is untouched

`REJECTION_BUDGET < DEFAULT_TOOL_RETRIES` is the invariant that makes O1 reachable at all: at
or above the framework's ceiling the framework wins the race and main gets its text instead of
the host's. The same rule `challenge_gate.Bounds.__post_init__` enforces for its turn bound.
"""
from __future__ import annotations

import dataclasses
import inspect

import pytest

from defender.runtime.circuit_breaker import (
    AGENT_FIXABLE_ERROR_CLASS,
    INFRA_ERROR_CLASS,
    error_class_for_exit,
)
from defender.runtime.driver import DEFAULT_TOOL_RETRIES
from defender.scripts.gather_tools import record_query as rq

# THE SURFACE UNDER TEST — none of it exists on this base (RED by construction)
from defender.scripts.gather_tools.record_query import (  # noqa: E402
    REJECTION_BUDGET,
    REJECTION_BUDGET_ESCAPE,
    RejectionBudgetTrip,
    rejection_budget_dead_end_reason,
    rejection_budget_trip,
    rejection_dead_end,
    rejection_detail,
)

LEAD = "l-001"
OTHER_LEAD = "l-002"

#: A `system`/`verb` pair no budget string may ever echo, and one that cannot be mistaken for
#: prose if it leaks. The complementary control is the REPEAT branch, which is entitled to name
#: its target and does.
LOUD_SYSTEM = "Zq7-Wintermute-Phantom"
LOUD_VERB = "Zq7-Sunspot-Verb"


def _row(
    seq: int, *, lead: str = LEAD, system: str = "", verb: str = "query",
    params: dict | None = None, exit_code: int = 64, query_id: str | None = None,
    system_key: str = "",
) -> dict:
    """One queries-table row with `error_class` computed by the PRODUCTION classifier, and the
    fourteenth column (`system_key`, #871) spelled out — a fixture that restated the class
    would be asserting its own arithmetic against the domain filter under test, and one that
    omitted the key could not build the "no two rows share any identity element" table the
    blindness arm needs."""
    params = {"native_query": "FROM logs"} if params is None else params
    return {
        "lead_id": lead,
        "seq": seq,
        "system": system,
        "verb": verb,
        "query_id": query_id if query_id is not None else f"{system or 'elastic'}.{verb}",
        "params": params,
        "raw_command": f"{system} {verb}",
        "payload_path": f"gather_raw/{lead}/{seq}.json",
        "exit_code": exit_code,
        "error_class": error_class_for_exit(exit_code),
        "payload_status": "error" if exit_code else "ok",
        "payload_digest": f"exit={exit_code}; rejected" if exit_code else "12 bytes, 1 line(s)",
        "payload_sha256": rq.payload_sha256("" if exit_code else "abcdefghijkl"),
        "system_key": system_key,
    }


def _above(seq: int, **kw) -> dict:
    kw.setdefault("query_id", rq.ABOVE_GUARD_QUERY_ID)
    return _row(seq, **kw)


def _ghosts(n: int, *, lead: str = LEAD) -> list[dict]:
    """`n` rows in the budget's domain, no two of which share ANY identity element the repeat
    guard keys on: different `system` half, different verb, different params, different
    fingerprint. This is the table the repeat guard is blind to and the budget must not be."""
    return [
        _above(
            i, lead=lead,
            system="elastic" if i % 2 else "",
            verb=f"verb-{i}",
            params={"native_query": f"FROM t{i}"},
            system_key=rq.system_fingerprint(f"ghost{i}", ""),
        )
        for i in range(n)
    ]


def _same(n: int, *, lead: str = LEAD) -> list[dict]:
    """`n` rows in the budget's domain that are identical in every identity element — the table
    the REPEAT guard already bounds. The budget must answer these exactly as it answers
    `_ghosts`, which is the whole of "identity-blind"."""
    key = rq.system_fingerprint("ghostone", "")
    return [_above(i, lead=lead, system_key=key) for i in range(n)]


# ── the constant and the invariant that makes the guard reachable ──────────────────────────


def test_the_budget_is_a_literal_strictly_below_the_frameworks_own_ceiling():
    """O1 — the design fixes `REJECTION_BUDGET = 6`: three times the largest above-guard
    agent-fixable count any archived lead carries (C7: 42 runs, 320 leads, max 2) and 40% of
    the framework ceiling.

    STRICTLY BELOW `DEFAULT_TOOL_RETRIES` is the invariant, not a coincidence. pydantic-ai
    raises `UnexpectedModelBehavior` at the eleventh FAILED STEP for one tool name, and a lead
    whose only `query` failures are above-guard rows has rejections >= failed steps — so at or
    above the ceiling the framework wins the race and main is handed
    "Tool 'query' exceeded max retries count of 10 … https://ai.pydantic.dev/…" instead of the
    host's own sentence. `challenge_gate.Bounds.__post_init__` enforces the same rule on its
    turn bound for the same reason. The margin is what makes the stop the HOST's."""
    assert isinstance(REJECTION_BUDGET, int)
    assert not isinstance(REJECTION_BUDGET, bool)
    assert REJECTION_BUDGET == 6, \
        "the budget is its own literal, sized by C7's census — not derived from the threshold"
    assert REJECTION_BUDGET != rq.REPEAT_THRESHOLD, \
        "the aggregate bound was spelled as the repeat guard's threshold; they answer " \
        "different questions and one edit must not move both"
    assert REJECTION_BUDGET < DEFAULT_TOOL_RETRIES, \
        "at or above the framework's per-tool retry ceiling the framework raises first and " \
        "main gets pydantic-ai's text, not the host's — O1 is unreachable"


# ── the predicate ──────────────────────────────────────────────────────────────────────────


def test_the_budget_counts_rejections_it_cannot_tell_apart():
    """O1 — the aggregate bound is IDENTITY-BLIND, and that is the whole reason it exists: the
    repeat guard bounds a lead by identity, so an unbounded family of identities (distinct
    ghost names, whitespace drift, assigned-but-blank codepoints) walks straight past it.

    Stated as an EQUALITY between two tables rather than as a count over one: `_ghosts` shares
    no identity element between any two rows, `_same` shares all of them, and the budget must
    return the same answer for both. A predicate that read `system_key` — or `system`, `verb`,
    `params` — would separate the first table into singletons and never trip on it.

    The control is the repeat guard over the SAME rows: it is silent, which is what makes the
    budget's answer a new bound rather than a restatement of one that already held."""
    assert rejection_budget_trip(_ghosts(REJECTION_BUDGET - 1), LEAD) == \
        rejection_budget_trip(_same(REJECTION_BUDGET - 1), LEAD), \
        "the budget gave two answers to two tables that differ only in identity"
    assert rejection_budget_trip(_ghosts(REJECTION_BUDGET - 1), LEAD) == \
        RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET), \
        "a lead that spent the whole budget on calls that all differ was not stopped"
    assert rejection_budget_trip(_ghosts(REJECTION_BUDGET - 2), LEAD) is None, \
        "the budget stopped a lead one rejection early"

    # The repeat guard over the very same rows, asked as the live placement asks it — for the
    # NEXT distinct ghost. Silent, at every prefix.
    for n in range(len(_ghosts(REJECTION_BUDGET)) + 1):
        assert rq.rejection_trip(
            _ghosts(REJECTION_BUDGET)[:n], LEAD, system="", verb="verb-next",
            params={"native_query": "FROM next"},
            system_key=rq.system_fingerprint("ghost-next", ""),
        ) is None, "the repeat guard already bounded this table — the budget adds nothing"


def test_the_occurrence_is_one_more_than_what_the_table_already_holds():
    """The `occurrence = count + 1` contract, and the `budget=` keyword the replay oracle
    drives the predicate through. Read at `budget=1`, where the predicate trips at every
    prefix and the occurrence it reports is therefore observable at each of them — at the
    shipped budget every answer below the trip is `None` and the arithmetic is invisible.

    `occurrence` is THIS call's 1-based number, not the table's row count: the row for the call
    being guarded has not been written yet when the guard is asked."""
    rows = _ghosts(REJECTION_BUDGET + 2)
    for n in range(len(rows) + 1):
        assert rejection_budget_trip(rows[:n], LEAD, budget=1) == \
            RejectionBudgetTrip(occurrence=n + 1, budget=1), \
            f"the occurrence disagreed with the {n} rows already on the table"

    sig = inspect.signature(rejection_budget_trip)
    assert sig.parameters["budget"].kind is inspect.Parameter.KEYWORD_ONLY, \
        "`budget` must be the keyword `_replay_rejections` names beside `threshold`"
    assert sig.parameters["budget"].default == REJECTION_BUDGET, \
        "the predicate's default budget is not the module constant, so a caller that omits " \
        "the keyword is bounded by something else"


def test_a_tripped_table_holds_exactly_the_budget():
    """ACCUMULATE BEFORE STOP, the shape `rejection_trip` already has: the guarded call's own
    rejection row is written whether or not it trips, so a recorded table holds exactly
    `budget` rows at a trip — and a replay over that table must reach the same verdict at the
    same row. An oracle withholding the last row, or a guard that refused before recording,
    would disagree with the table the live run actually leaves."""
    assert rejection_budget_trip(_ghosts(REJECTION_BUDGET - 2), LEAD) is None
    assert rejection_budget_trip(_ghosts(REJECTION_BUDGET - 1), LEAD) is not None
    assert rejection_budget_trip(_ghosts(REJECTION_BUDGET), LEAD) is not None, \
        "the trip row itself stopped counting, so a replay of a recorded table cannot " \
        "reproduce the run that wrote it"


def test_an_infra_rejection_is_still_the_breakers_and_never_the_budgets():
    """The domain is EXACTLY `rejection_trip`'s, and narrower than `ABOVE_GUARD_QUERY_ID`
    alone: `_grant_check`'s adapter-load rows are `infra` (exit 2) and `circuit_breaker` owns
    their repeat end to end. Counting them here would give one shape two owners and turn an
    outage into a lead-level dead end.

    The negative and its control are the SAME call with one row swapped, so "the budget never
    trips" cannot pass for coverage."""
    prior = _ghosts(REJECTION_BUDGET - 2)
    infra = _above(99, exit_code=2, system_key=rq.system_fingerprint("ghost-infra", ""))
    fixable = _above(99, exit_code=64, system_key=rq.system_fingerprint("ghost-infra", ""))

    assert error_class_for_exit(2) == INFRA_ERROR_CLASS
    assert error_class_for_exit(64) == AGENT_FIXABLE_ERROR_CLASS
    assert rejection_budget_trip([*prior, infra], LEAD) is None, \
        "an adapter-load failure was counted against the lead's rejection allowance"
    assert rejection_budget_trip([*prior, fixable], LEAD) is not None, \
        "the budget stopped counting altogether, so the negative above says nothing"


def test_a_below_guard_refusal_is_not_the_budgets_either():
    """C13 is why: parameter refusals against a DECLARED system, with a real query id, run 4+
    per lead in 30 of the 320 archived leads, with tails of 30, 71 and 98 — the model iterating
    on a real system's parameters under specific coaching. A budget of 6 over those would end
    healthy leads. The domain stays the companion guard's, exactly.

    Same shape as above: one row swapped between the negative and its control."""
    prior = _ghosts(REJECTION_BUDGET - 2)
    below = _row(99, system="elastic", verb="query", exit_code=64)
    above = _above(99, system="elastic", verb="query", exit_code=64)

    assert below["query_id"] != rq.ABOVE_GUARD_QUERY_ID
    assert rejection_budget_trip([*prior, below], LEAD) is None, \
        "a parameter refusal below the guard was counted against the rejection budget"
    assert rejection_budget_trip([*prior, above], LEAD) is not None, \
        "the budget stopped counting altogether, so the negative above says nothing"


def test_another_leads_rejections_are_another_leads_problem():
    """One budget per lead (the design's "not per-run"): leads are already bounded by main's
    request limit, and a sibling's thrashing must not end this one. The control is the same
    rows re-labelled, so this cannot pass on a predicate that never counts."""
    borrowed = _ghosts(REJECTION_BUDGET - 1, lead=OTHER_LEAD)
    own = _ghosts(REJECTION_BUDGET - 1, lead=LEAD)

    assert rejection_budget_trip(borrowed, LEAD) is None, \
        "a sibling lead's rejections were spent against this lead's allowance"
    assert rejection_budget_trip(own, LEAD) is not None, \
        "the budget never trips at all, so the negative above says nothing"
    assert rejection_budget_trip([*borrowed, *own[:1]], LEAD) is None, \
        "a sibling's rows topped up a count this lead had not earned"


# ── the trip type ──────────────────────────────────────────────────────────────────────────


def test_the_budget_trip_carries_integers_and_nothing_else():
    """S1's FIRST half. The design discharges "no model-authored byte reaches main through the
    budget stop" with two facts, and this is the one that lives in the data model: the trip
    type the reason function is handed holds INTEGERS ONLY, so there is no field for a system
    string, a digest, a verb or a params fragment to travel in.

    Asserted on the FIELDS, not on the values of one instance: a `str` field that happened to
    be empty in a fixture is exactly the leak this forecloses, and it would pass any
    "the name is not in the reason" check built from that fixture."""
    assert dataclasses.is_dataclass(RejectionBudgetTrip)
    fields = dataclasses.fields(RejectionBudgetTrip)
    assert [f.name for f in fields] == ["occurrence", "budget"]
    for f in fields:
        assert f.type in ("int", int), \
            f"{f.name} is typed {f.type!r} — the trip may carry integers and nothing else"

    trip = RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET)
    with pytest.raises(dataclasses.FrozenInstanceError):
        trip.occurrence = 99  # type: ignore[misc]

    assert trip != rq.RepeatTrip(first_seq=0, occurrence=REJECTION_BUDGET), \
        "the two guards' trips compare equal, so no dispatcher can tell them apart"


# ── the strings ────────────────────────────────────────────────────────────────────────────


def test_the_budget_reason_names_no_target_because_it_is_handed_none():
    """O4 — the reason `GatherDeadEnd` carries into main's context. It takes NO target and NO
    verb: the count is over the lead, not over a request, and there is no one request to name.

    The SIGNATURE is asserted, not just the output. A reason function that accepted a target
    and happened not to spend it is one edit away from spending it, and the two above-guard
    placements each hold a raw model string at the moment they call it — the #855 leak channel,
    one function over.

    The complementary control is `rejection_dead_end_reason`, the REPEAT branch, which is
    entitled to name its (already coarsened) target and does: so "no loud string in the text"
    is not satisfied here by a function that says nothing at all."""
    sig = inspect.signature(rejection_budget_dead_end_reason)
    assert len(sig.parameters) == 1, \
        f"the budget reason takes a target it must never name: {list(sig.parameters)}"

    trip = RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET)
    reason = rejection_budget_dead_end_reason(trip)
    assert reason == (
        f"{REJECTION_BUDGET} requests in this lead were rejected before they ran — each named "
        "a system the run does not declare, a verb it does not have, or arguments the tool "
        "could not read. That is the lead's whole allowance for such requests; the rejections "
        "are structural, not transients to retry through."
    )

    control = rq.rejection_dead_end_reason(
        LOUD_SYSTEM, LOUD_VERB, rq.RepeatTrip(first_seq=0, occurrence=rq.REPEAT_THRESHOLD))
    assert LOUD_SYSTEM in control, \
        "the repeat branch stopped naming its system, so this suite's leak checks are vacuous"
    assert LOUD_VERB in control, \
        "the repeat branch stopped naming its verb, so this suite's leak checks are vacuous"
    assert LOUD_SYSTEM not in reason
    assert LOUD_VERB not in reason


def test_the_budget_reason_reports_the_rejections_that_actually_happened():
    """The count in the sentence is the OCCURRENCE, not the budget. The two coincide on the
    ordinary stop, and the design admits they need not: the `query` tool is not declared
    `sequential` (C16), so parallel calls in one model step can both read a stale count and the
    stop lands within the step rather than at the exact B-th row. A sentence that reported the
    allowance instead of the count would then tell main a number of rejections that did not
    happen."""
    over = rejection_budget_dead_end_reason(
        RejectionBudgetTrip(occurrence=REJECTION_BUDGET + 1, budget=REJECTION_BUDGET))
    assert over.startswith(f"{REJECTION_BUDGET + 1} requests in this lead were rejected"), \
        "the reason reports the allowance rather than the rejections that happened"


def test_neither_budget_string_reads_as_a_completed_lead():
    """`_run_gather`'s dead-end arm appends the fixed `INCOMPLETE_IDIOM` immediately after the
    escape, and G19 names that sentence as the only vocabulary any prompt teaches main. A
    budget string containing "complete" would sit beside it as an opposed disposition — the
    reason `REPEAT_ESCAPE`'s own comment gives for avoiding the word."""
    reason = rejection_budget_dead_end_reason(
        RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET))
    assert REJECTION_BUDGET_ESCAPE == (
        "Further requests of that shape will be turned back the same way. Move on with what "
        "this lead has already captured."
    )
    idiom = "Treat this lead as incomplete and reason from what was captured."
    assert "complete" in idiom, \
        "the screen below cannot detect the word it screens for"
    assert "complete" not in REJECTION_BUDGET_ESCAPE
    assert "complete" not in reason
    assert LOUD_SYSTEM not in REJECTION_BUDGET_ESCAPE
    assert LOUD_VERB not in REJECTION_BUDGET_ESCAPE
    assert REJECTION_BUDGET_ESCAPE != rq.REPEAT_ESCAPE, \
        "the two guards hand main the same escape, so the sentence cannot say why it stopped"


# ── the two dispatchers ────────────────────────────────────────────────────────────────────


def test_the_detail_dispatcher_keeps_the_two_guards_sentences_apart():
    """O2 — #871's owner's promise, at the row. `rejection_trip_detail` says the request
    "repeats the one already turned back at seq N"; the budget stops a lead for SPENDING, not
    for repeating, and its detail must say so. A reader that could not tell the two apart would
    report a lead as having been refused for a call that differed from its predecessors — the
    one thing the repeat guard promises it never does.

    The repeat branch is asserted BOUND to `rejection_trip_detail` rather than restated: the
    dispatcher must not be a second copy of a sentence that already has an owner."""
    repeat = rq.RepeatTrip(first_seq=0, occurrence=rq.REPEAT_THRESHOLD)
    budget = RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET)

    assert rejection_detail(repeat, "boom") == rq.rejection_trip_detail(repeat, "boom"), \
        "the dispatcher re-derives the repeat guard's detail instead of spending its owner"
    assert "turned back at seq" in rejection_detail(repeat, "boom")

    detail = rejection_detail(budget, "boom")
    assert detail == (
        f"refused: {rq._ordinal(REJECTION_BUDGET)} rejection before anything ran in this lead "
        f"(budget {REJECTION_BUDGET}); rejected: boom"
    )
    assert "turned back at seq" not in detail, \
        "a budget stop's row claims the call repeated one already turned back — O2"


def test_the_budget_phrase_leads_the_row_digest_and_survives_its_truncation():
    """`_record` cuts the detail at 160 characters (`query_tool.py:581`), and the row it cuts
    is BOTH the rejection record and the trip record — the append-only table would otherwise
    permanently forget why the last call was malformed. So the budget phrase LEADS and the
    schema's own error text is the tail that gets eaten, exactly as `rejection_trip_detail`
    arranges it. A phrase that did not fit would leave the offline readers unable to tell a
    budget stop from an ordinary rejection at all."""
    budget = RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET)
    phrase = (
        f"refused: {rq._ordinal(REJECTION_BUDGET)} rejection before anything ran in this lead "
        f"(budget {REJECTION_BUDGET})"
    )
    assert len(phrase) <= 160
    long_tail = rejection_detail(budget, "x" * 500)
    assert len(long_tail[:160]) == 160, "the tail is not long enough to test the truncation"
    assert long_tail[:160].startswith(phrase), \
        "a long schema error pushed the budget phrase itself out of the digest"
    assert "turned back at seq" not in long_tail[:160]


def test_the_dead_end_dispatcher_hands_the_budget_no_target_to_leak():
    """O4 at the seam both placements reach it through. `rejection_dead_end(trip, target, verb)`
    is called from `wrap_tool_validate` and from `_grant_check`'s unresolvable branch, and at
    both of them `target` and `verb` are derived from the model's own arguments. On the BUDGET
    branch they must be discarded outright, not merely unused by today's wording.

    The repeat branch is the control on the same call, under the complementary condition: it
    spends both, and is bound to `rejection_dead_end_reason` and `REPEAT_ESCAPE` rather than
    restating either."""
    repeat = rq.RepeatTrip(first_seq=0, occurrence=rq.REPEAT_THRESHOLD)
    budget = RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET)

    r = rejection_dead_end(repeat, LOUD_SYSTEM, LOUD_VERB)
    assert isinstance(r, rq.GatherDeadEnd)
    assert r.reason == rq.rejection_dead_end_reason(LOUD_SYSTEM, LOUD_VERB, repeat)
    assert r.escape == rq.REPEAT_ESCAPE
    assert LOUD_SYSTEM in r.reason, \
        "the repeat branch stopped naming its target, so the negative below is vacuous"

    b = rejection_dead_end(budget, LOUD_SYSTEM, LOUD_VERB)
    assert isinstance(b, rq.GatherDeadEnd)
    assert b.reason == rejection_budget_dead_end_reason(budget)
    assert b.escape == REJECTION_BUDGET_ESCAPE
    assert LOUD_SYSTEM not in b.reason, \
        "the model's own system string crossed into main's context through the budget stop"
    assert LOUD_SYSTEM not in b.escape
    assert LOUD_VERB not in b.reason, \
        "the model's own verb crossed into main's context through the budget stop"
    assert LOUD_VERB not in b.escape
    assert "turned back at seq" not in b.reason, \
        "a budget stop tells main the request repeated one already turned back — O2"


def test_each_dispatcher_spends_the_sentences_owner_rather_than_copying_it():
    """The two arms above assert the dispatchers' repeat branches EQUAL their owners' output,
    which a byte-identical copy of the owner's body satisfies exactly as well as a call does.
    Equality is the right check for what main receives; it is the wrong one for the claim those
    docstrings actually make — "BOUND to its owner, not restated".

    The distinction is not pedantry: `rejection_trip_detail`'s leading phrase and
    `rejection_dead_end_reason`'s sentence are read by the offline collectors and by main, and
    a copy drifts the first time either owner is reworded — silently, with every equality arm
    here still green because both copies were updated in whichever file the author had open.

    Read off the SOURCE, the way this repo's own lints answer a "who derives this" question,
    because there is no runtime seam to observe: a delegating call and an inlined copy are
    indistinguishable from their return values, which is the whole problem."""
    detail_src = inspect.getsource(rejection_detail)
    assert "rejection_trip_detail(" in detail_src, \
        "the repeat branch restates a detail sentence that already has an owner"
    assert "turned back at seq" not in detail_src, \
        "the repeat guard's phrase is spelled a second time here — one rewording drifts them"

    dead_end_src = inspect.getsource(rejection_dead_end)
    assert "rejection_dead_end_reason(" in dead_end_src, \
        "the repeat branch restates a reason that already has an owner"
    assert "REPEAT_ESCAPE" in dead_end_src, \
        "the repeat escape is not spent from its constant"
    assert "Sending this exact request again" not in dead_end_src, \
        "REPEAT_ESCAPE's text is copied here rather than referenced"
    assert "rejection_budget_dead_end_reason(" in dead_end_src, \
        "the budget branch restates its own reason instead of spending its owner"
    assert "were rejected before they ran" not in dead_end_src, \
        "the budget reason's text is copied into the dispatcher"
