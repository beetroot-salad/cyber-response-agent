"""The order in which a run's endings are chosen (#1465): one table, each site naming its rows.

Each case is a failure the run can meet, bare or inside a group, and the ending it must take.
The expectations are the orderings the sites had before the table existed, so a reordering of
the table or an edit to a site's rows fails here and not only in an end-to-end run."""
from __future__ import annotations

import logging

import pytest
from pydantic_ai.exceptions import ModelHTTPError

from defender import box as box_mod
from defender.hooks.budget_enforcer import BudgetKill
from defender.investigation import run_endings as endings
from defender.providers import ProviderDown, ProviderRejected
from defender.records import run_end
from defender.systems.circuit_breaker import RunAborted
from defender.systems.verbs import ServingAbort

LOST = box_mod.BoxLost("box gone")
FENCE = box_mod.BoxOutputLimitExceeded(1)
LEDGER = run_end.CallRecordWriteFailed(run_end.TRUNCATED_BY_SERVED_LEDGER, "disk full")
DOWN = ProviderDown("m", 503, 3)
REFUSED = ProviderRejected(401, "bad key")
KILL = BudgetKill("over budget")
ABORT = RunAborted(1, ["elastic"])
SERVING = ServingAbort()
INTERRUPT = KeyboardInterrupt()


def _group(*leaves: BaseException) -> BaseException:
    return BaseExceptionGroup("leads", list(leaves))


def _words(found: endings.RunEnding | None) -> tuple[str, str] | None:
    return None if found is None else (found.exit_class, found.exit_reason)


BOX_LOST = (run_end.TRUNCATED_BY_BOX_LOST, "BoxLost")
BOX_FENCE = (run_end.TRUNCATED_BY_BOX_OUTPUT_LIMIT, "BoxOutputLimitExceeded")
LEDGER_END = (run_end.TRUNCATED_BY_SERVED_LEDGER, "CallRecordWriteFailed")
DOWN_END = (run_end.TRUNCATED_BY_PROVIDER_DOWN, "ProviderDown")
REJECTED_END = (run_end.TRUNCATED_BY_PROVIDER_REJECTED, "ProviderRejected")


@pytest.mark.parametrize(("exc", "expected"), [
    (LOST, BOX_LOST),
    (DOWN, DOWN_END),
    (REFUSED, REJECTED_END),
    (LEDGER, LEDGER_END),
    # Concurrent leads: the box first, the fence before a lost box.
    (_group(LOST, FENCE), BOX_FENCE),
    (_group(DOWN, REFUSED, LEDGER, LOST), BOX_LOST),
    (_group(DOWN, REFUSED, LEDGER), LEDGER_END),
    (_group(DOWN, REFUSED), DOWN_END),
    # A kill or abort beside an ending decides the run itself, except beside a call record.
    (_group(LOST, KILL), None),
    (_group(LOST, ABORT), None),
    (_group(LOST, SERVING), None),
    (_group(DOWN, KILL), None),
    (_group(REFUSED, ABORT), None),
    (_group(LEDGER, KILL), LEDGER_END),
    # A serving abort stops a box ending but not a provider outage.
    (_group(DOWN, SERVING), DOWN_END),
    (_group(DOWN, LOST, KILL), None),
    # An interrupt beside an ending propagates, again except beside a call record.
    (_group(DOWN, INTERRUPT), None),
    (_group(LOST, INTERRUPT), None),
    (_group(LEDGER, INTERRUPT), LEDGER_END),
    (_group(ValueError("other"), DOWN), DOWN_END),
    (ValueError("other"), None),
    (_group(ValueError("other")), None),
], ids=lambda value: type(value).__name__ if isinstance(value, BaseException) else None)
def test_the_whole_table_picks_the_ending_the_run_took_before_it_had_one_owner(exc, expected):
    assert _words(endings.ending_in(exc)) == expected


def test_a_bare_http_refusal_ends_the_run_rejected_after_the_other_endings():
    refusal = ModelHTTPError(401, "m", "bad key")
    assert _words(endings.ending_in(refusal)) == REJECTED_END
    assert _words(endings.ending_in(_group(refusal, DOWN))) == DOWN_END
    assert _words(endings.ending_in(_group(refusal, KILL))) is None
    # A temporary error beside a refusal does not hide it.
    assert _words(endings.ending_in(_group(ModelHTTPError(503, "m", "x"), refusal))) == REJECTED_END


def test_the_correlation_lead_leaves_a_call_record_failure_to_propagate():
    assert endings.ending_in(_group(LEDGER, DOWN), endings.CORRELATION_ENDINGS).exit_class == (
        run_end.TRUNCATED_BY_PROVIDER_DOWN)
    assert endings.ending_in(LEDGER, endings.CORRELATION_ENDINGS) is None
    assert _words(endings.ending_in(LOST, endings.CORRELATION_ENDINGS)) == BOX_LOST
    refusal = ModelHTTPError(401, "m", "bad key")
    assert _words(endings.ending_in(refusal, endings.CORRELATION_ENDINGS)) == REJECTED_END


def test_a_gather_lead_stamps_only_a_box_ending_or_an_outage_on_the_way_up():
    stamped = endings.STAMPED_ON_THE_WAY_UP
    assert _words(endings.ending_in(_group(DOWN, LOST), stamped)) == BOX_LOST
    assert _words(endings.ending_in(_group(DOWN, LEDGER), stamped)) == DOWN_END
    assert endings.ending_in(_group(LEDGER, REFUSED), stamped) is None


@pytest.mark.parametrize(("exc", "propagates"), [
    (_group(LOST, KILL), True),  # a box ending is let through even beside a kill
    (_group(LOST, SERVING), True),
    (_group(DOWN, REFUSED), True),
    (_group(REFUSED), True),
    (_group(DOWN, KILL), False),
    (_group(REFUSED, ABORT), False),
    (_group(LEDGER), False),
    (_group(ModelHTTPError(401, "m", "bad key")), False),  # lead zero never read HTTP errors
    (_group(ValueError("other")), False),
], ids=lambda value: None)
def test_lead_zero_lets_a_group_through_only_for_the_endings_it_always_did(exc, propagates):
    carried = endings.carries_box_ending(exc) or (
        endings.ending_in(exc, endings.LEAD_ZERO_PROPAGATES) is not None)
    assert carried is propagates


def test_the_box_ending_logs_its_own_words_and_a_refusal_keeps_its_traceback(caplog):
    logger = logging.getLogger("run-endings-test")
    with caplog.at_level(logging.ERROR, logger="run-endings-test"):
        endings.log_ending(logger, endings.ending_in(LOST), LOST, "ending the run")
        endings.log_ending(logger, endings.ending_in(DOWN), DOWN, "ending the run")
        try:
            raise REFUSED
        except ProviderRejected as refused:
            endings.log_ending(logger, endings.ending_in(refused), refused, "stopping")
    box, down, refusal = caplog.records
    assert box.getMessage() == "box gone"
    assert down.getMessage().endswith("; ending the run")
    assert refusal.getMessage().endswith("; stopping")
    assert refusal.exc_info is not None
    assert box.exc_info is None
    assert down.exc_info is None
