"""#1015 — the PER-LEAD REJECTION BUDGET, at the predicate and at the strings it composes.

The repeat guard bounds a lead's above-guard rejections by identity; this aggregate,
identity-blind bound stops a lead whose rejections all differ. The live half is
`tests/e2e/test_1015_rejection_budget.py`."""
from __future__ import annotations

import dataclasses
import inspect

import pytest
from pydantic import ValidationError

from defender.systems.circuit_breaker import (
    AGENT_FIXABLE_ERROR_CLASS,
    INFRA_ERROR_CLASS,
    error_class_for_exit,
)
from defender.knowledge import _query_rules
from defender.investigation import record_query as rq

# The surface under test.
from defender.investigation.record_query import (  # noqa: E402
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

LOUD_SYSTEM = "Zq7-Wintermute-Phantom"
LOUD_VERB = "Zq7-Sunspot-Verb"


def _row(
    seq: int, *, lead: str = LEAD, system: str = "", verb: str = "query",
    params: dict | None = None, exit_code: int = 64, query_id: str | None = None,
    system_key: str = "",
) -> dict:
    """One queries-table row with `error_class` from the production classifier (a fixture
    restating it would check its own arithmetic) and `system_key` spelled out."""
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
    """An above-guard row. `query_id` is forced, not defaulted: a caller passing its own gets a
    `TypeError` rather than a row silently outside the domain."""
    return _row(seq, query_id=_query_rules.ABOVE_GUARD_QUERY_ID, **kw)


def _ghosts(n: int, *, lead: str = LEAD) -> list[dict]:
    """`n` rows in the budget's domain that the repeat guard keys APART, one per row — the table it
    is blind to and the budget must not be. They alternate the two shapes an above-guard writer
    emits: a coarsened ghost (`system=""` with a digest) and a declared system with no digest."""
    return [
        _above(
            i, lead=lead,
            system="" if i % 2 else "elastic",
            verb=f"verb-{i}",
            params={"native_query": f"FROM t{i}"},
            system_key=rq.system_fingerprint(f"ghost{i}", "") if i % 2 else "",
        )
        for i in range(n)
    ]


def _same(n: int) -> list[dict]:
    """`n` rows in the budget's domain that are identical in every identity element — the table
    the REPEAT guard already bounds. The budget must answer these exactly as it answers
    `_ghosts`, which is the whole of "identity-blind"."""
    key = rq.system_fingerprint("ghostone", "")
    return [_above(i, system_key=key) for i in range(n)]


# ── the predicate ──────────────────────────────────────────────────────────────────────────


def test_the_budget_counts_rejections_it_cannot_tell_apart():
    """The budget is identity-blind: it answers `_ghosts` (no two rows alike) exactly as `_same`
    (all alike), while the identity-keyed repeat guard stays silent over the same rows."""
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
    """The `occurrence = count + 1` contract (the guarded call's own row is not written yet) and the
    `budget=` keyword the replay oracle uses; at `budget=1` every prefix trips, so each shows its
    occurrence."""
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
    """Accumulate before stop, as `rejection_trip` does: the tripping call's row is recorded too, so
    a replay of the recorded table reaches the same verdict at the same row."""
    assert rejection_budget_trip(_ghosts(REJECTION_BUDGET - 2), LEAD) is None
    assert rejection_budget_trip(_ghosts(REJECTION_BUDGET - 1), LEAD) is not None
    assert rejection_budget_trip(_ghosts(REJECTION_BUDGET), LEAD) is not None, \
        "the trip row itself stopped counting, so a replay of a recorded table cannot " \
        "reproduce the run that wrote it"


def test_an_infra_rejection_is_still_the_breakers_and_never_the_budgets():
    """The domain is exactly `rejection_trip`'s: an `infra` (exit 2) adapter-load row is the
    circuit breaker's and is never counted. One swapped row separates negative and control."""
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
    """A below-guard parameter refusal (declared system, real query id) is not counted: healthy
    archived leads iterate on a real system's parameters like this, sometimes dozens of times."""
    prior = _ghosts(REJECTION_BUDGET - 2)
    below = _row(99, system="elastic", verb="query", exit_code=64)
    above = _above(99, system="elastic", verb="query", exit_code=64)

    assert below["query_id"] != _query_rules.ABOVE_GUARD_QUERY_ID
    assert rejection_budget_trip([*prior, below], LEAD) is None, \
        "a parameter refusal below the guard was counted against the rejection budget"
    assert rejection_budget_trip([*prior, above], LEAD) is not None, \
        "the budget stopped counting altogether, so the negative above says nothing"


def test_another_leads_rejections_are_another_leads_problem():
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
    """The trip holds integers only (asserted on its fields, so no model string has a field to ride
    in), is frozen and keyword-only (two equal adjacent ints transpose silently), and is not a
    `RepeatTrip` either way round (both dispatchers branch on `isinstance`)."""
    assert dataclasses.is_dataclass(RejectionBudgetTrip)
    fields = dataclasses.fields(RejectionBudgetTrip)
    assert [f.name for f in fields] == ["occurrence", "budget"]
    for f in fields:
        assert f.type in ("int", int), \
            f"{f.name} is typed {f.type!r} — the trip may carry integers and nothing else"

    trip = RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET)
    with pytest.raises(dataclasses.FrozenInstanceError):
        trip.occurrence = 99  # type: ignore[misc]

    with pytest.raises(ValidationError) as refused:
        RejectionBudgetTrip(REJECTION_BUDGET, REJECTION_BUDGET)  # type: ignore[misc]
    assert {e["type"] for e in refused.value.errors()} >= {"unexpected_positional_argument"}

    repeat = rq.RepeatTrip(first_seq=0, occurrence=REJECTION_BUDGET)
    assert not isinstance(trip, rq.RepeatTrip), \
        "a budget trip answers `isinstance(..., RepeatTrip)`, so both dispatchers describe " \
        "it as a repeat"
    assert not isinstance(repeat, RejectionBudgetTrip), \
        "a repeat trip answers `isinstance(..., RejectionBudgetTrip)`, so the totality check " \
        "in each dispatcher stops discriminating"


# ── the strings ────────────────────────────────────────────────────────────────────────────


def test_the_budget_reason_names_no_target_because_it_is_handed_none():
    """The budget's dead-end reason takes no target or verb at all (a function accepting a model
    string is one edit from leaking it); the repeat branch, which names both, is the control."""
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
    """The sentence counts the occurrence, not the budget: parallel calls in one step can overshoot,
    and main must not be told a number that did not happen."""
    over = rejection_budget_dead_end_reason(
        RejectionBudgetTrip(occurrence=REJECTION_BUDGET + 1, budget=REJECTION_BUDGET))
    assert over.startswith(f"{REJECTION_BUDGET + 1} requests in this lead were rejected"), \
        "the reason reports the allowance rather than the rejections that happened"


# ── the two dispatchers ────────────────────────────────────────────────────────────────────


def test_the_budget_phrase_leads_the_row_digest_and_survives_its_truncation():
    """The budget phrase leads the row's detail and fits `_record`'s 160-character digest cut, so a
    budget stop stays distinguishable offline; the schema error is the tail that gets eaten."""
    budget = RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET)
    phrase = (
        f"refused: {rq._ordinal(REJECTION_BUDGET)} request in this lead rejected before it ran "
        f"(budget {REJECTION_BUDGET})"
    )
    assert len(phrase) <= 160
    long_tail = rejection_detail(budget, "x" * 500)
    assert len(long_tail[:160]) == 160, "the tail is not long enough to test the truncation"
    assert long_tail[:160].startswith(phrase), \
        "a long schema error pushed the budget phrase itself out of the digest"
    assert "turned back at seq" not in long_tail[:160]


def test_the_dead_end_dispatcher_hands_the_budget_no_target_to_leak():
    """`rejection_dead_end` discards the model-derived `target` and `verb` on the budget branch; the
    repeat branch, which spends them, is the control on the same call."""
    repeat = rq.RepeatTrip(first_seq=0, occurrence=rq.REPEAT_THRESHOLD)
    budget = RejectionBudgetTrip(occurrence=REJECTION_BUDGET, budget=REJECTION_BUDGET)

    r = rejection_dead_end(repeat, target=LOUD_SYSTEM, verb=LOUD_VERB)
    assert isinstance(r, rq.GatherDeadEnd)
    assert r.reason == rq.rejection_dead_end_reason(LOUD_SYSTEM, LOUD_VERB, repeat)
    assert r.escape == rq.REPEAT_ESCAPE
    assert LOUD_SYSTEM in r.reason, \
        "the repeat branch stopped naming its target, so the negative below is vacuous"

    b = rejection_dead_end(budget, target=LOUD_SYSTEM, verb=LOUD_VERB)
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
        "a budget stop tells main the request repeated one already turned back"
