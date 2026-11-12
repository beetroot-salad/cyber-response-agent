"""#1476 review (second round), findings 4, 5 and 9: whether a lane has work is answered once, by the claim's rules.

The tick's gate, the claim's pre-check and the post-step's wake each kept their own copy of "is the lane busy, is
anything due" beside the claim's SQL, and the copies disagreed: keyless pitfalls counted as one mistake in the copies
and as several in the claim, and a batch waiting for a person kept a tenant's checks running though no tick moves it.
`LearningStore.lane_work` is the claim's own rules with nothing claimed; `lane_waiting` asks it."""
from __future__ import annotations

import pytest

from defender.learning.core.store_tick import lane_waiting
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, LEAD_LANE
from defender.tests.support.shared._fixture_uuid import fixture_uuid

pytestmark = pytest.mark.postgres

BLUE = fixture_uuid("tenant:1278-lane-work-blue")
ONE = {"finding": 1, "questioner_finding": 1, "pitfall": 1, "curation_request": 1}


@pytest.fixture
def store(migrated_database):
    from defender.learning.store import blocking

    register_tenant(migrated_database, BLUE)
    with blocking(migrated_database) as s:
        yield s


def _keyless_pitfall(n: int) -> dict:
    """A pitfall with no `pitfall_id` and a diagnosis with nothing in it: each is its own mistake (the store keys it
    by its digest)."""
    return {"schema_version": 1, "source_run": f"r{n}", "system": "elastic", "query_id": "elastic.esql",
            "goal": f"goal {n}", "executed_query": f"query {n}", "stderr_digest": "", "error_class": "agent-fixable"}


def _finding(fid: str) -> dict:
    return {"finding_id": fid, "run_id": "run-1", "direction": "defender", "goal": "g"}


def test_keyless_pitfalls_at_threshold_are_work_exactly_when_the_claim_would_take_them(store):
    """Five keyless pitfalls are five mistakes to the claim, so at a threshold of three the lead lane has work, and the
    claim takes them. (finding 5)"""
    for n in range(5):
        store.add_pitfall(BLUE, _keyless_pitfall(n))
    limits = {**ONE, "pitfall": 3}

    assert lane_waiting(store, BLUE, LEAD_LANE, tick_thresholds=limits), "the wake test says no work the claim would take"
    assert store.lane_work(BLUE, LEAD_LANE, thresholds=limits).claimable
    assert store.claim(BLUE, LEAD_LANE, owner="o", thresholds=limits) is not None


def test_a_batch_waiting_for_a_person_is_no_work_for_any_tick(store):
    """A batch handed to a person, and items waiting behind it, keep no tenant's checks running: no tick moves them,
    and the claim refuses the busy lane. (finding 4)"""
    store.publish_findings(BLUE, "run-1", [_finding("f1")], kind="finding")
    held = store.claim(BLUE, AUTHOR_LANE, owner="o", thresholds=ONE)
    store.needs_person(BLUE, held.batch_id, "an open PR on the prefix that no batch made")
    store.publish_findings(BLUE, "run-2", [_finding("f2")], kind="finding")

    assert not lane_waiting(store, BLUE, AUTHOR_LANE, tick_thresholds=ONE)
    work = store.lane_work(BLUE, AUTHOR_LANE, thresholds=ONE)
    assert (work.busy, work.claimable) == (True, True)


def test_an_author_lane_revert_in_review_makes_the_lane_busy_as_the_claim_finds_it(store):
    """A revert PR in review blocks a new author batch in the claim, so the gate finds the lane busy too, while the
    revert itself is work for a tick to reconcile. (finding 9)"""
    held = store.claim_revert(BLUE, owner="o")
    store.in_review(held, 7, {})
    store.publish_findings(BLUE, "run-1", [_finding("f1")], kind="finding")

    assert store.lane_work(BLUE, AUTHOR_LANE, thresholds=ONE).busy
    assert lane_waiting(store, BLUE, AUTHOR_LANE, tick_thresholds=ONE), "a revert in review is a tick's to reconcile"
