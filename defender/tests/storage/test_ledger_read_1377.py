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


@pytest.fixture
def ledger(tmp_path):
    """An open store, and a planter of rows into its ledger."""
    with ss.open_store(case_id="ledger-read", sessions=SessionPaths(fixture_runs_base(tmp_path))) as store:
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

    read = ss.read_ledger(store, RUN)

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

    read = ss.read_ledger(store, RUN)

    assert read.by_agent == pytest.approx({"main": _cost(SONNET), "gather:l-001": _cost(HAIKU)})
    assert read.complete is True


@pytest.mark.parametrize(("outcome", "complete"), [(RESPONSE, True), (REFUSED, True), (UNSEEN, False)])
def test_s2a_r7_refused_and_unseen_rows_add_nothing_and_only_an_unseen_row_makes_the_ledger_incomplete(ledger, outcome, complete):
    """One priced response beside one row of each outcome: the sum is the response (the outcome's own row is $0), the agent has a row, complete as the design says. (r7 S2a)"""
    store, plant = ledger
    plant([(SONNET, USAGE)])
    plant([(HAIKU, {})] if outcome != RESPONSE else [(HAIKU, USAGE)], agent_id="gather:l-00c", outcome=outcome)

    read = ss.read_ledger(store, RUN)

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

    read = ss.read_ledger(store, RUN)

    assert read.total == pytest.approx(_cost(SONNET)), "an unpriced row was priced"
    assert read.by_agent["gather:l-001"] == 0.0
    assert read.complete is False


def test_s5_r7_the_read_is_one_run_s_rows_and_a_run_with_none_is_zero_and_complete(ledger):
    """Another run's rows sit in the same database: they are not this run's spend; a run with no rows reads $0, complete, no agents. (r7 S5)"""
    store, plant = ledger
    plant([(SONNET, USAGE)] * 4, run_id=fixture_uuid("another run"))
    plant([(HAIKU, {})], run_id=fixture_uuid("another run"), outcome=UNSEEN)

    read = ss.read_ledger(store, RUN)

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
