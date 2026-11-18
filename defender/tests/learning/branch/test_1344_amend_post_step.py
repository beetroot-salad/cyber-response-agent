"""#1344 amendment 1 and #1278 Wake, as #1487 Flow 3 moves them: the family-less post-step's CLI form, and the worker's
"work still waiting" question, now an async predicate in `defender.learning_store.tick` over the learning store with the
reconcile lanes and the thresholds passed as values (`learning_store` may not import `defender.learning`). The post-step
writes no record, so what it leaves waiting is read from the store alone. Store state is built with the store's own
verbs, a real PostgreSQL. The post-step's own behaviour (no record, no hand-over, no database) is
`test_1344_post_step.py`; the worker's use of the predicate is `tests/jobs/test_1487_post_step_waiting.py`."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import anyio
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
    learning_store,
)
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture

pytestmark = pytest.mark.postgres

#: The lanes the author tick reconciles (`AUTHOR_DRAIN_RECONCILES`), spelled out as the worker passes them.
RECONCILES = (AUTHOR_LANE, LEAD_LANE, "feedback")
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


def waiting_of(dsn: str, tenant: str, *, finding_at: int = 1, reconcile_lanes=RECONCILES) -> bool:
    """`lane_waiting` over a store of its own, from sync code, the lanes and thresholds handed in as values."""
    from defender.learning_store.tick import lane_waiting

    async def go() -> bool:
        async with learning_store(dsn) as store:
            return await lane_waiting(store, tenant, reconcile_lanes=reconcile_lanes, thresholds=thresholds_of(finding_at))

    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(anyio.run, go).result()


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


def _abandoned_with_pr(dsn: str, tenant: str, lane: str = AUTHOR_LANE, *, checked: bool = False) -> None:
    """A batch of `lane` in review whose PR a person closed by abandoning it: ended, the PR still to be closed by a
    tick (unless a reconcile has looked since, `checked`)."""
    if lane == LEAD_LANE:
        _pitfalls(dsn, tenant)
        claim = call(dsn, "claim", tenant, LEAD_LANE, owner="lead-drain", thresholds=ONE)
    else:
        _queued(dsn, tenant, "f1")
        claim = call(dsn, "claim", tenant, AUTHOR_LANE, owner="host-a", thresholds=ONE)
    call(dsn, "in_review", claim, 7, {})
    call(dsn, "abandon", tenant, claim.batch_id, by="person")
    if checked:
        call(dsn, "note_check", tenant, claim.batch_id)


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
    "abandoned_author_batch_pr_open": _abandoned_with_pr,  # closing: its PR is still to be closed
    "abandoned_author_batch_pr_checked": lambda dsn, t: _abandoned_with_pr(dsn, t, checked=True),
    "another_tenants_batches_and_items": _others_batch,
}


@pytest.mark.parametrize(("scenario", "waiting"), [
    ("items_at_threshold", True), ("lapsed_lease", True), ("overdue_check", True), ("due_replacement", True),
    ("fresh_check_in_review", True), ("live_working_batch", True), ("abandoned_author_batch_pr_open", True),
    ("one_feedback_instruction_item", True),
    ("below_threshold", False), ("merged_and_nothing_else", False), ("pitfalls_at_threshold", False),
    ("lead_batch_closed_with_words", False), ("abandoned_author_batch_pr_checked", False),
    ("another_tenants_batches_and_items", False)])
def test_o7_flow3_the_predicate_is_true_exactly_when_the_stores_state_gives_the_tenant_something_to_do(
        migrated_database, scenario, waiting):  # noqa: F811 — the imported fixture
    """Items at threshold, a lapsed lease, a batch overdue for a check, a due replacement, any batch still to be
    reconciled, or an abandoned batch whose PR is still to close: waiting. Items below threshold, a merged batch alone,
    lead-lane items alone, a checked abandoned batch, another tenant's state: not. (O7, Flow 3, Wake, D9)"""
    dsn = migrated_database
    _SCENARIOS[scenario](dsn, TENANT)

    assert waiting_of(dsn, TENANT, finding_at=2 if scenario in {"items_at_threshold", "below_threshold"} else 1) is waiting


@pytest.mark.parametrize(("finding_at", "waiting"), [(2, True), (3, False)])
def test_o7_flow3_the_thresholds_are_the_values_the_caller_passes(migrated_database, finding_at, waiting):  # noqa: F811
    """Two queued findings: at threshold 2 the author gate opens, so work waits; at 3 it stays shut. The predicate reads
    the thresholds it is handed, not a setting of its own. (O7, Flow 3)"""
    _queued(migrated_database, TENANT, "f1", "f2")
    assert waiting_of(migrated_database, TENANT, finding_at=finding_at) is waiting


@pytest.mark.parametrize(("reconcile_lanes", "waiting"), [(RECONCILES, True), ((AUTHOR_LANE, "feedback"), False)])
def test_o7_flow3_the_reconcile_lanes_are_the_values_the_caller_passes(migrated_database, reconcile_lanes, waiting):  # noqa: F811
    """A lead-lane batch abandoned with its PR open is a closing batch of a reconciled lane only when the caller names
    the lane. (O7, Flow 3)"""
    _abandoned_with_pr(migrated_database, TENANT, LEAD_LANE)
    assert waiting_of(migrated_database, TENANT, reconcile_lanes=reconcile_lanes) is waiting


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
        call(dsn, "needs_person", tenant, claim.batch_id, "a person is needed")
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
