"""#1344 amendment 1 and #1278 Wake, as #1487 Flow 3 moves them: the family-less post-step's CLI form, and the
"work still waiting" question, a predicate in `defender.learning_store.tick` (`work_waiting`) over the tick's store,
which the post-step's helper asks with the adapter it bound (the tenant, the author lane, the thresholds; Amendment
r5.2). The post-step writes no record, so what it leaves waiting is read from the store alone. Store state is built with
the store's own verbs, a real PostgreSQL. The post-step's own behaviour (no record, no hand-over, no database) is
`test_1344_post_step.py`; the helper's answer and the worker's reading of it are
`tests/jobs/test_1487_post_step_waiting.py`."""
from __future__ import annotations

import re
from typing import Any

import pytest

from defender.learning.branch import post_step
from defender.tests.learning.feedback_1414 import _lessons1414 as L
from defender.tests.support.jobs._jobs1342 import T1, T2, register_tenant
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    LEAD_LANE,
    ONE,
    call,
    finding,
    lapse_lease,
)
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture

pytestmark = pytest.mark.postgres

TENANT = T1


@pytest.fixture(autouse=True)
def _tenant(migrated_database):  # noqa: F811 — the imported fixture
    """The tenant the scenarios build state for, active in the test's own database."""
    register_tenant(migrated_database, TENANT)
    return migrated_database


def thresholds_of(finding_at: int = 1) -> dict[str, int]:
    """The kinds' thresholds as the worker's environment gives them: `finding` varies, the rest are the defaults of
    `learning.core.store_tick.thresholds` (questioner 5, pitfalls 3, one request or instruction wakes)."""
    return {"finding": finding_at, "questioner_finding": 5, "pitfall": 3, "curation_request": 1,
            "feedback_instruction": 1}


def waiting_of(dsn: str, tenant: str, *, finding_at: int = 1) -> bool:
    """`work_waiting` over the tick's store as the helper binds it: an adapter over a store of its own, bound to the
    tenant, the author lane and the thresholds handed in."""
    from defender.learning_store import blocking
    from defender.learning_store.tick import StoreAdapter, work_waiting

    with blocking(dsn) as store:
        return work_waiting(StoreAdapter(store, tenant=tenant, lane=AUTHOR_LANE, owner="post-step:test",
                                         thresholds=thresholds_of(finding_at)))


def test_a1_without_a_job_the_argv_parses_as_a_family_less_post_step():
    """`--job` may be left out; the parse names no job. (amendment 1)"""
    ns = post_step.parse_post_step_args(["--tenant", "t", "--parent-pid", "1"])
    assert ns.job is None


# --- Flow 3: the predicate over the store ------------------------------------------------------------------------------


def _queued(dsn: str, tenant: str, *ids: str) -> None:
    call(dsn, "publish_findings", tenant, "run-1", [finding(i) for i in ids], kind="finding")


def _claimed(dsn: str, tenant: str) -> Any:
    _queued(dsn, tenant, "f1")
    return call(dsn, "claim", tenant, AUTHOR_LANE, owner="host-a", thresholds=ONE)


def _reviewed(dsn: str, tenant: str) -> Any:
    claim = _claimed(dsn, tenant)
    call(dsn, "in_review", claim, 7, {})
    return claim


def _pitfalls(dsn: str, tenant: str) -> None:
    for n in range(3):
        call(dsn, "add_pitfall", tenant, {"schema_version": 1, "pitfall_id": f"p{n}", "source_run": "r", "system": "elastic",
                                          "query_id": "elastic.esql", "goal": "g", "executed_query": "x",
                                          "stderr_digest": f"exit=1; digest {n}", "error_class": "agent-fixable"})


def _overdue(dsn: str, tenant: str) -> None:
    claim = _reviewed(dsn, tenant)
    execute(dsn, "UPDATE learning.batches SET last_checked = now() - interval '1 hour' WHERE id = %s", (claim.batch_id,))


def _checked(dsn: str, tenant: str) -> None:
    call(dsn, "note_check", tenant, _reviewed(dsn, tenant).batch_id)


def _closed_with_feedback(dsn: str, tenant: str) -> None:
    # no item is held, so the closed batch's items stay in_batch, due a replacement
    call(dsn, "end_review", tenant, _reviewed(dsn, tenant).batch_id, expect_phase="in_review", outcome="closed",
         published=[], held=[])


def _lead_rejected(dsn: str, tenant: str) -> None:
    """A lead-lane batch whose PR was closed with words: its pitfall stays in the batch, due a replacement nobody but an operator makes."""
    call(dsn, "add_pitfall", tenant, {"schema_version": 1, "pitfall_id": "p0", "source_run": "r", "system": "elastic",
                                      "query_id": "elastic.esql", "goal": "g", "executed_query": "x",
                                      "stderr_digest": "exit=1; digest 0", "error_class": "agent-fixable"})
    claim = call(dsn, "claim", tenant, LEAD_LANE, owner="lead-drain", thresholds=ONE)
    call(dsn, "in_review", claim, 7, {})
    call(dsn, "end_review", tenant, claim.batch_id, expect_phase="in_review", outcome="closed", published=[], held=[])


def _merged(dsn: str, tenant: str) -> None:
    call(dsn, "end_review", tenant, _reviewed(dsn, tenant).batch_id, expect_phase="in_review", outcome="merged",
         published=[("finding", "f1")], held=[])


def _abandon_asked(dsn: str, tenant: str, lane: str = AUTHOR_LANE, *, settled: bool = False) -> None:
    """A batch of `lane` in review, parked for a person, who asked for its abandon (#1537: only the request is recorded;
    a tick carries it out once it has read the PR, `settle_abandon`). `settled`: a tick has since carried it out (its PR
    found closed), so the batch is ended."""
    from defender.tests.support.learning.core._release1537 import why

    if lane == LEAD_LANE:
        _pitfalls(dsn, tenant)
        claim = call(dsn, "claim", tenant, LEAD_LANE, owner="lead-drain", thresholds=ONE)
    else:
        _queued(dsn, tenant, "f1")
        claim = call(dsn, "claim", tenant, AUTHOR_LANE, owner="host-a", thresholds=ONE)
    call(dsn, "in_review", claim, 7, {})
    call(dsn, "needs_person", tenant, claim.batch_id, why("foreign_pr", "a person is needed"))
    call(dsn, "request_abandon", tenant, str(claim.batch_id), actor="person")
    if settled:
        assert call(dsn, "settle_abandon", tenant, str(claim.batch_id), pr_number=7, pr_state="closed") is True, \
            "premise: the abandon was carried out"


def _others_batch(dsn: str, tenant: str) -> None:
    """Every kind of state of scenarios above, in another tenant: none of it is this tenant's."""
    register_tenant(dsn, T2)
    _reviewed(dsn, T2)
    _queued(dsn, T2, "g1", "g2")


#: Store state a family-less post-step finds, built with the store's own verbs.
_SCENARIOS = {
    "items_at_threshold": lambda dsn, t: _queued(dsn, t, "f1", "f2"),
    "below_threshold": lambda dsn, t: _queued(dsn, t, "f1"),
    "lapsed_lease": lambda dsn, t: lapse_lease(dsn, _claimed(dsn, t).batch_id),
    "live_working_batch": _claimed,
    "overdue_check": _overdue,
    "fresh_check_in_review": _checked,
    "due_replacement": _closed_with_feedback,
    "merged_and_nothing_else": _merged,
    "lead_batch_closed_with_words": _lead_rejected,  # a lead replacement is operator-only: Wake does not count it (D9)
    "one_feedback_instruction_item": lambda dsn, t: L.instruct(dsn, t, 101),  # threshold 1, below the judge's 5 (A4 Wake)
    "pitfalls_at_threshold": _pitfalls,  # the lead lane is operator-only: nothing a post-step can act on (D9)
    "abandon_asked_author_batch": _abandon_asked,  # a person's abandon a tick has still to carry out (#1537)
    "abandon_settled_author_batch": lambda dsn, t: _abandon_asked(dsn, t, settled=True),
    "another_tenants_batches_and_items": _others_batch,
}


@pytest.mark.parametrize(("scenario", "waiting"), [
    ("items_at_threshold", True), ("lapsed_lease", True), ("overdue_check", True), ("due_replacement", True),
    ("fresh_check_in_review", True), ("live_working_batch", True), ("abandon_asked_author_batch", True),
    ("one_feedback_instruction_item", True),
    ("below_threshold", False), ("merged_and_nothing_else", False), ("pitfalls_at_threshold", False),
    ("lead_batch_closed_with_words", False), ("abandon_settled_author_batch", False),
    ("another_tenants_batches_and_items", False)])
def test_o7_flow3_the_predicate_is_true_exactly_when_the_stores_state_gives_the_tenant_something_to_do(
        migrated_database, scenario, waiting):  # noqa: F811 — the imported fixture
    """Items at threshold, a lapsed lease, a batch overdue for a check, a due replacement, any batch still to be
    reconciled, or a person's abandon a tick has still to carry out: waiting. Items below threshold, a merged batch
    alone, lead-lane items alone, an abandon carried out, another tenant's state: not. (O7, Flow 3, Wake, D9, #1537)"""
    dsn = migrated_database
    _SCENARIOS[scenario](dsn, TENANT)

    assert waiting_of(dsn, TENANT, finding_at=2 if scenario in {"items_at_threshold", "below_threshold"} else 1) is waiting


@pytest.mark.parametrize(("finding_at", "waiting"), [(2, True), (3, False)])
def test_o7_flow3_the_thresholds_are_those_its_store_was_bound_to(migrated_database, finding_at, waiting):  # noqa: F811
    """Two queued findings: at threshold 2 the author gate opens, so work waits; at 3 it stays shut. The predicate reads
    the thresholds its store was bound to, not a setting of its own. (O7, Flow 3)"""
    _queued(migrated_database, TENANT, "f1", "f2")
    assert waiting_of(migrated_database, TENANT, finding_at=finding_at) is waiting


@pytest.mark.parametrize(("settled", "waiting"), [(False, True), (True, False)], ids=["abandon-asked", "abandon-settled"])
def test_o7_flow3_another_lanes_batch_a_person_asked_to_abandon_keeps_work_waiting(  # noqa: F811 — the imported fixture
        migrated_database, settled, waiting):  # noqa: F811
    """A lead-lane batch a person asked to abandon is a batch not yet ended, so work waits though the predicate is bound
    to the author lane; once a tick has carried the abandon out, nothing waits. Since #1537 no ended batch is left for a
    tick to close, so the lanes the tick reconciles add nothing a not-ended batch does not. (O7, Flow 3)"""
    _abandon_asked(migrated_database, TENANT, LEAD_LANE, settled=settled)
    assert waiting_of(migrated_database, TENANT) is waiting


# --- Wake: every batch not yet ended, whatever its lane and phase ---------------------------------------------------------


def _lane_batch(dsn: str, tenant: str, lane: str, phase: str) -> None:
    """One batch of `lane` in `phase`, built with the store's own verbs (a revert batch has no items)."""
    if lane == "revert":
        claim = call(dsn, "claim_revert", tenant, owner="reverter")
    elif lane == "feedback":  # the feedback lane's batches are registry batches, made under the lane's tick lock (A4)
        held = call(dsn, "begin_feedback_tick", tenant, owner="host-a")
        claim = call(dsn, "claim_registry", held)
    elif lane == LEAD_LANE:
        call(dsn, "add_pitfall", tenant, {"schema_version": 1, "pitfall_id": "p0", "source_run": "r", "system": "elastic",
                                          "query_id": "elastic.esql", "goal": "g", "executed_query": "x",
                                          "stderr_digest": "exit=1; digest 0", "error_class": "agent-fixable"})
        claim = call(dsn, "claim", tenant, LEAD_LANE, owner="lead-drain", thresholds=ONE)
    else:
        _queued(dsn, tenant, "f1")
        claim = call(dsn, "claim", tenant, AUTHOR_LANE, owner="host-a", thresholds=ONE)
    if phase in ("in_review", "needs_person"):
        call(dsn, "in_review", claim, 7, {})
    if phase == "needs_person":
        from defender.tests.support.learning.core._release1537 import why

        call(dsn, "needs_person", tenant, claim.batch_id, why("foreign_pr", "a person is needed"))
    if lane == "feedback":
        call(dsn, "end_feedback_tick", held)


WAKE_LANES = ("author", "lead_author", "revert", "feedback")
WAKE_PHASES = ("working", "in_review", "needs_person")


@pytest.mark.parametrize("lane", WAKE_LANES)
@pytest.mark.parametrize("phase", WAKE_PHASES)
def test_o7_flow3_a_batch_of_any_lane_in_any_phase_but_ended_makes_the_predicate_true(migrated_database, lane, phase):  # noqa: F811
    """With nothing else queued and every threshold above what exists, a not-yet-ended batch of any lane, working, in
    review or waiting for a person, keeps the tenant waiting: its lease, PR or release may still change what a tick must
    do. (O7, Flow 3, Wake)"""
    _lane_batch(migrated_database, TENANT, lane, phase)

    assert waiting_of(migrated_database, TENANT, finding_at=5) is True


def test_wake_the_lanes_and_phases_above_are_every_one_the_schema_allows(migrated_database):  # noqa: F811 — the imported fixture
    """A lane or phase the schema gains has no case above until it is added: this fails first. (Wake)"""
    [(lanes,)] = execute(migrated_database, "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_batches_lane'")
    [(phases,)] = execute(migrated_database, "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_batches_phase'")
    quoted = lambda text: set(re.findall(r"'([a-z_]+)'", text))  # noqa: E731
    assert quoted(lanes) | {"revert"} == set(WAKE_LANES)
    assert quoted(phases) - {"ended"} == set(WAKE_PHASES)
