"""`session_store.read_ledger(store, run_id)` (contract-chosen name, #1377 r7 S5): the one read of a run's spend ledger, returning `total`, `complete` and `by_agent` (agent id -> USD)."""
from __future__ import annotations

import pytest

from defender.configuration import usage_cost
from defender.records import SessionPaths
from defender.records import session_store as ss
from defender.tests.support.jobs._jobs1342 import REFUSED, RESPONSE, UNSEEN, insert_spend
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import fixture_runs_base

RUN = fixture_uuid("ledger-read")
USAGE = {"input_tokens": 100_000, "output_tokens": 8_000, "cache_read_input_tokens": 50_000, "cache_creation_input_tokens": 2_000}
SONNET, HAIKU, KIMI, UNPRICED = "claude-sonnet-4-6", "claude-haiku-4-5", "kimi-k3", "claude-opus-9-0"


def _cost(model: str, n: int = 1) -> float:
    return n * usage_cost(model, USAGE)


def _sealed_read(store, run_id=RUN):
    """The run's ledger as a run that ended without a failed write leaves it: sealed (r7.3 T1), then read."""
    ss.seal_ledger(store, run_id)
    return ss.read_ledger(store, run_id)


@pytest.fixture
def ledger(tmp_path):
    """An open store, and a planter of rows into its ledger."""
    with ss.open_store(case_id="ledger-read", sessions=SessionPaths(fixture_runs_base(tmp_path / "runs"))) as store:
        def plant(rows, *, agent_id="main", run_id=RUN, **row):
            insert_spend(store.path, run_id, rows, agent_id=agent_id, **row)
        yield store, plant


def test_s5_r7_the_read_sums_every_priced_row_and_each_agent_s_own(ledger):
    """Rows of MAIN, two leads, the correlation lead and two review lenses: the total, each agent's sum, complete. (r7 S5)"""
    store, plant = ledger
    plant([(SONNET, USAGE)] * 2)
    plant([(HAIKU, USAGE)], agent_id="gather:l-001")
    plant([(HAIKU, USAGE)] * 3, agent_id="gather:l-00c")
    plant([(KIMI, USAGE)], agent_id="review:support")
    plant([(KIMI, USAGE)], agent_id="review:ablation")

    read = _sealed_read(store)

    want = {"main": _cost(SONNET, 2), "gather:l-001": _cost(HAIKU), "gather:l-00c": _cost(HAIKU, 3),
            "review:support": _cost(KIMI), "review:ablation": _cost(KIMI)}
    assert read.by_agent == pytest.approx(want)
    assert read.total == pytest.approx(sum(want.values()))
    assert read.complete is True


def test_s5_r7_a_row_is_priced_at_its_requested_model_never_the_name_the_provider_reported(ledger):
    """A row requesting sonnet and reporting a spelling with no price, and one requesting haiku and reporting sonnet. (r7 S1)"""
    store, plant = ledger
    plant([(SONNET, USAGE)], reported="claude-sonnet-4-6-rerouted")
    plant([(HAIKU, USAGE)], agent_id="gather:l-001", reported=SONNET)
    assert usage_cost("claude-sonnet-4-6-rerouted", USAGE) == 0.0, "premise: the reported spelling has no price"

    read = _sealed_read(store)

    assert read.by_agent == pytest.approx({"main": _cost(SONNET), "gather:l-001": _cost(HAIKU)})
    assert read.complete is True


@pytest.mark.parametrize(("outcome", "complete"), [(RESPONSE, True), (REFUSED, True), (UNSEEN, False)])
def test_s2a_r7_refused_and_unseen_rows_add_nothing_and_only_an_unseen_row_makes_the_ledger_incomplete(ledger, outcome, complete):
    """One priced response beside one row of each outcome: the sum is the response (the outcome's own row is $0), the agent has a row, complete as the design says. (r7 S2a)"""
    store, plant = ledger
    plant([(SONNET, USAGE)])
    plant([(HAIKU, {})] if outcome != RESPONSE else [(HAIKU, USAGE)], agent_id="gather:l-00c", outcome=outcome)

    read = _sealed_read(store)

    lead = _cost(HAIKU) if outcome == RESPONSE else 0.0
    assert read.by_agent == pytest.approx({"main": _cost(SONNET), "gather:l-00c": lead}), (
        "an agent whose request ended unpriced has its own $0 entry: a row was written")
    assert read.total == pytest.approx(_cost(SONNET) + lead)
    assert read.complete is complete


@pytest.mark.parametrize("requested", [UNPRICED, ""], ids=["no pricing row", "empty name"])
def test_s2b_r7_d_an_unpriced_requested_model_adds_nothing_and_leaves_the_ledger_incomplete(ledger, requested):
    """A response requesting a model with no pricing row, or no name at all (never Sonnet): $0 and incomplete; the priced row beside it is the control. (r7 S2b, D)"""
    store, plant = ledger
    plant([(SONNET, USAGE)])
    plant([(requested, USAGE)], agent_id="gather:l-001", reported=SONNET)

    read = _sealed_read(store)

    assert read.total == pytest.approx(_cost(SONNET)), "an unpriced row was priced"
    assert read.by_agent["gather:l-001"] == 0.0
    assert read.complete is False


def test_s5_r7_the_read_is_one_run_s_rows_and_a_run_with_none_is_zero_and_complete(ledger):
    """Another run's rows sit in the same database: they are not this run's spend; a run with no rows reads $0, complete, no agents. (r7 S5)"""
    store, plant = ledger
    plant([(SONNET, USAGE)] * 4, run_id=fixture_uuid("another run"))
    plant([(HAIKU, {})], run_id=fixture_uuid("another run"), outcome=UNSEEN)

    read = _sealed_read(store)

    assert (read.total, read.complete, dict(read.by_agent)) == (0.0, True, {})


@pytest.mark.parametrize("agent_id", ["mainframe", "main:2", "gatherer:l-001", "review2", "", "planner", "gather", "review", "gather:", "review:"])
def test_f_r7_an_agent_id_outside_the_four_kinds_is_an_error_at_read_never_main(ledger, agent_id):
    """A row of an id that is not main, `gather:*` or `review:*`: the read raises. A known-id ledger reads (the control). (r7.1 F)"""
    store, plant = ledger
    plant([(SONNET, USAGE)])
    assert ss.read_ledger(store, RUN).total == pytest.approx(_cost(SONNET)), "control: the four kinds read"
    plant([(SONNET, USAGE)], agent_id=agent_id)

    with pytest.raises(Exception):  # noqa: B017, PT011 — the design says an error, not which
        ss.read_ledger(store, RUN)


_UNKNOWN_IDS = ("gather", "review", "gather:", "review:", "planner", "mainframe", "")
_ROW_FAULTS = {"unpriced requested model": UNPRICED, "empty requested model": ""}
_FAULTS = {**{name: ("model", value) for name, value in _ROW_FAULTS.items()},
           **{f"unknown agent id {i!r}": ("agent", i) for i in _UNKNOWN_IDS}}


@pytest.mark.parametrize("outcome", [RESPONSE, REFUSED, UNSEEN])
@pytest.mark.parametrize(("kind", "value"), _FAULTS.values(), ids=_FAULTS.keys())
def test_f5_r7_a_row_fault_is_a_fault_whatever_the_row_s_outcome(ledger, outcome, kind, value):
    """Every outcome (response, refused, unseen) crossed with every row fault (a requested model with no pricing row, an empty
    one, an agent id outside the four kinds), planted beside a priced response row: a model fault leaves the ledger incomplete
    with the row adding nothing, an unknown agent id makes the read raise; the outcome never excuses either. The same outcome
    at a priced model and a known agent is the control. (r7 S2b, D; r7.1 F)"""
    store, plant = ledger
    counts = USAGE if outcome == RESPONSE else {}
    control_run = fixture_uuid("f5 control")
    plant([(SONNET, USAGE)], run_id=control_run)
    plant([(HAIKU, counts)], agent_id="gather:l-001", outcome=outcome, run_id=control_run)
    control = _sealed_read(store, control_run)
    assert control.complete is (outcome != UNSEEN), "control: the outcome alone decides completeness"
    assert control.total == pytest.approx(_cost(SONNET) + (_cost(HAIKU) if outcome == RESPONSE else 0.0))
    plant([(SONNET, USAGE)])
    plant([(HAIKU, counts)], agent_id="gather:l-001", outcome=outcome)

    if kind == "model":
        plant([(value, counts)], agent_id="gather:l-002", outcome=outcome, reported=SONNET if outcome == RESPONSE else None)
        read = _sealed_read(store)
        assert read.complete is False, f"a {outcome} row requesting {value!r} reads complete"
        assert read.total == pytest.approx(control.total), "the faulted row was priced"
        assert read.by_agent["gather:l-002"] == 0.0
    else:
        plant([(SONNET, counts)], agent_id=value, outcome=outcome)
        with pytest.raises(Exception):  # noqa: B017, PT011 — the design says an error, not which
            _sealed_read(store)


def _lead_ids_by_membership() -> list[str]:
    """Lead ids drawn from the whole class `LEAD_ID_RE` matches: every one-step edit of the correlation lead's id over the
    lead-id alphabet (one character inserted, dropped, replaced or re-cased at each position), its prefixes and extensions,
    and seeded random bodies of every length from 1 to 64."""
    import random
    import string

    from defender.records import LEAD_ID_RE

    reserved, alphabet = "l-00c", string.ascii_letters + string.digits
    body = reserved.removeprefix("l-")
    found: set[str] = {reserved, "l-00C", "l-" + body.upper()}
    for i in range(len(body) + 1):
        for ch in alphabet:
            found.add(f"l-{body[:i]}{ch}{body[i:]}")
            if i < len(body):
                found.add(f"l-{body[:i]}{ch}{body[i + 1:]}")
    found |= {f"l-{body[:i] + body[i + 1:]}" for i in range(len(body))}
    found |= {f"l-{body[:i]}" for i in range(1, len(body))}
    rng = random.Random(1377)
    found |= {"l-" + "".join(rng.choice(alphabet) for _ in range(n)) for n in range(1, 65) for _ in range(3)}
    found.add("l-" + "0" * 64)
    found.add("l-" + body + "c" * 61)
    ids = sorted(i for i in found if LEAD_ID_RE.match(i))
    assert reserved in ids
    assert len(ids) > 400
    return ids


def test_f8_r7_1_f_an_agent_id_is_the_correlation_kind_exactly_when_its_lead_is_the_reserved_one():
    """Over every lead id the lead-id rule admits (generated: the reserved id's one-step edits, prefixes, extensions and random
    bodies up to the longest), `gather:<id>` is the correlation kind iff `<id>` is exactly the reserved `l-00c`, and the gather
    kind otherwise; no id starting with, containing or ending in the reserved one is. (r7.1 F; triage F8)"""
    from defender._agent_role import agent_kind

    def kind(agent_id: str) -> str:
        found = agent_kind(agent_id)
        return str(getattr(found, "value", found)).lower()

    wrong = {i: kind(f"gather:{i}") for i in _lead_ids_by_membership()
             if kind(f"gather:{i}") != ("correlation" if i == "l-00c" else "gather")}
    assert not wrong, f"{len(wrong)} lead ids of the wrong kind, e.g. {dict(list(wrong.items())[:5])}"
    assert kind("main") == "main"
    assert kind("review:support") == "review"


# --- r7.3 T1: the ledger says for itself whether it is complete (the seal) ------------------------------

OTHER = fixture_uuid("another run")
#: Each case is a sequence of writes to the ledger (`rows`: a priced response of the run or of the other run; `seal`: that run's
#: seal) and whether the run's ledger then reads complete. The sum is every priced row whatever the seal says.
_SEALS = {
    "sealed after its rows": ([("rows", RUN), ("seal", RUN)], True),
    "never sealed": ([("rows", RUN)], False),
    "a run with no rows, never sealed": ([], False),
    "a run with no rows, sealed": ([("seal", RUN)], True),
    "a row after the seal": ([("rows", RUN), ("seal", RUN), ("rows", RUN)], False),
    "a row after the seal of a run with none": ([("seal", RUN), ("rows", RUN)], False),
    "another run's row after the seal": ([("rows", RUN), ("seal", RUN), ("rows", OTHER)], True),
    "another run's row before the seal": ([("rows", RUN), ("rows", OTHER), ("seal", RUN)], True),
    "only another run sealed": ([("rows", RUN), ("rows", OTHER), ("seal", OTHER)], False),
    "another run's row after the other's seal": ([("rows", RUN), ("seal", RUN), ("rows", OTHER), ("seal", OTHER)], True),
}


@pytest.mark.parametrize("case", _SEALS, ids=_SEALS)
def test_t1_r7_3_a_ledger_reads_complete_only_when_its_seal_matches_the_run_s_last_row(ledger, case):
    """A run's ledger is complete only with its own seal and no row of the run written after it (another run's rows, written
    before or after, change nothing); the sum is the priced rows either way. (r7.3 T1)"""
    store, plant = ledger
    steps, complete = _SEALS[case]
    for what, run in steps:
        if what == "seal":
            ss.seal_ledger(store, run)
        else:
            plant([(SONNET, USAGE)], run_id=run)

    read = ss.read_ledger(store, RUN)

    assert read.complete is complete, case
    own = sum(1 for what, run in steps if what == "rows" and run == RUN)
    assert read.total == pytest.approx(_cost(SONNET, own)), "the seal changed the sum"
    assert read.by_agent == (pytest.approx({"main": _cost(SONNET, own)}) if own else {})
    again = ss.read_ledger(store, RUN)
    assert (again.complete, again.total) == (read.complete, read.total), "reading changed the ledger"


@pytest.mark.parametrize(("outcome", "model"), [(UNSEEN, HAIKU), (RESPONSE, UNPRICED), (REFUSED, UNPRICED)],
                         ids=["unseen", "unpriced response", "unpriced refused"])
def test_t1_r7_3_a_seal_does_not_excuse_an_unseen_or_unpriced_row(ledger, outcome, model):
    """The three conditions hold together: a sealed ledger with an unseen or an unpriced row still reads incomplete, and the
    same ledger without that row reads complete. (r7.3 T1; r7 S2a, S2b)"""
    store, plant = ledger
    plant([(SONNET, USAGE)])
    assert _sealed_read(store).complete is True, "control: sealed and priced"
    other = fixture_uuid("t1 faulted")
    plant([(SONNET, USAGE)], run_id=other)
    plant([(model, {} if outcome != RESPONSE else USAGE)], agent_id="gather:l-001", outcome=outcome, run_id=other)

    assert _sealed_read(store, other).complete is False
