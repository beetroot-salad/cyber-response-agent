"""#1344 amendment 1 (from #1278, owner-approved 2026-11-07): the family-less post-step's CLI form and record.

Without `--job` the post-step is the worker's family-less check of a tenant: it does the same work (publish the
handed `pending` jobs, then the drain's gate), and its record is kept under the tenant's own id,
`<runs>/<tenant id>.post-step.json`, one per tenant, named by `job_lane.post_step_key`. What it publishes and what it
leaves waiting are the learning store's (#1278): a real PostgreSQL."""
from __future__ import annotations

import json
import re
import os
from pathlib import Path
from typing import Any

import pytest

from defender.learning.branch import post_step
from defender.records.job_lane import post_step_key
from defender.tests.learning.branch.test_1344_post_step import (  # noqa: F401 — store_dsn is the module's autouse fixture
    _job_episode, _learning_paths, _queue, hand_pending, store_dsn)
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, LEAD_LANE, ONE, call, finding, lapse_lease
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared._postgres1339 import execute, migrated_database  # noqa: F401 — fixture

pytestmark = pytest.mark.postgres


def _record_at(ep: Path, key: str) -> dict:
    data_root, tenant_id = J.episode_location(ep)
    return json.loads((Path(data_root) / tenant_id / "runs" / f"{key}.post-step.json").read_text(encoding="utf-8"))


def test_a1_without_a_job_the_argv_parses_as_a_family_less_post_step():
    """`--job` may be left out; the parse names no job. (amendment 1)"""
    ns = post_step.parse_post_step_args(["--tenant", "t", "--parent-pid", "1"])
    assert ns.job is None


def test_a1_the_record_key_is_the_job_or_else_the_tenant():
    """One place names the record: the job it followed, or the tenant's own id without one. (amendment 1)"""
    tenant = "0b5f2b4e-3c7d-4f7a-9a51-1f0a8f0c2d11"
    job = "6f1d2c3b-8e4a-4b5c-9d6e-7f8a9b0c1d2e"
    assert str(post_step_key(tenant, job)) == job
    assert str(post_step_key(tenant, None)) == tenant


def test_a1_a_family_less_post_step_publishes_runs_the_gate_and_records_under_the_tenant(tmp_path):
    """No `--job`: the handed pending job is published, the gate runs after it, and the record is
    `<tenant id>.post-step.json`. (amendment 1, O8, O14)"""
    ep, _new = _job_episode(tmp_path, "a")
    data_root, tenant_id = J.episode_location(ep)
    seen: list[int] = []

    hand_pending(data_root, tenant_id, None, [ep.name])
    post_step.main(["--tenant", tenant_id, "--parent-pid", str(os.getppid())],
                   author_tick=lambda *_a, **_k: seen.append(len(_queue(ep))) or 0,
                   directory=T.launcher_directory(tenant_id))

    assert seen, "the gate did not run"
    assert seen[0] > 0, "the gate ran before publishing"
    assert _record_at(ep, tenant_id) == {"published": [ep.name], "refused": [], "waiting": False}  # below threshold (amendment 3)
    data_root, _ = J.episode_location(ep)
    assert not (Path(data_root) / tenant_id / "runs" / f"{ep.name}.post-step.json").exists(), \
        "a family-less post-step wrote under a job's name"


def test_a1_a_family_less_post_step_with_nothing_pending_still_runs_the_gate(tmp_path):
    """The check's point is the gate: it runs with nothing to publish, and the record says nothing was. (amendment 1)"""
    ep, _new = _job_episode(tmp_path, "b")
    data_root, tenant_id = J.episode_location(ep)
    ticks: list[int] = []

    hand_pending(data_root, tenant_id, None, [])
    post_step.main(["--tenant", tenant_id, "--parent-pid", str(os.getppid())],
                   author_tick=lambda *_a, **_k: ticks.append(1) or 0, directory=T.launcher_directory(tenant_id))

    assert ticks == [1]
    assert _record_at(ep, tenant_id) == {"published": [], "refused": [], "waiting": False}  # nothing queued (amendment 3)


# --- Wake (#1278 amendment): the record's `waiting` counts the store's state ----------------------------------------


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
    "pitfalls_at_threshold": _pitfalls,  # the lead lane is operator-only: nothing a post-step can act on (D9)
}


@pytest.mark.parametrize(("scenario", "waiting"), [
    ("items_at_threshold", True), ("lapsed_lease", True), ("overdue_check", True), ("due_replacement", True),
    ("fresh_check_in_review", True), ("live_working_batch", True),
    ("below_threshold", False), ("merged_and_nothing_else", False), ("pitfalls_at_threshold", False),
    ("lead_batch_closed_with_words", False)])
def test_wake_the_post_step_says_work_waits_exactly_when_the_stores_state_gives_it_something_to_do(
        tmp_path, monkeypatch, scenario, waiting):
    """Items at threshold, a lapsed lease, a batch overdue for a check, a due replacement, or any batch still to be
    reconciled (its lease may lapse and its PR change later, so the tenant's checks must go on) leave the record without
    `waiting: false`; items below threshold, a merged batch with nothing else, or lead-lane items alone leave it.
    (Wake, D9, amendment 3)"""
    from defender.tests.support.learning.core._store1278 import DSN_ENV

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "2" if scenario in {"items_at_threshold", "below_threshold"} else "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "5")
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    ep, _ = _job_episode(tmp_path, f"wake-{scenario}", findings=False)
    data_root, tenant_id = J.episode_location(ep)
    _SCENARIOS[scenario](os.environ[DSN_ENV], tenant_id)

    hand_pending(data_root, tenant_id, None, [])
    post_step.main(["--tenant", tenant_id, "--parent-pid", str(os.getppid())],
                   author_tick=lambda *_a, **_k: 0, directory=T.launcher_directory(tenant_id))

    assert _record_at(ep, tenant_id) == {"published": [], "refused": [], **({} if waiting else {"waiting": False})}


# --- Wake: every batch not yet ended, whatever its lane and phase ---------------------------------------------------------


def _lane_batch(dsn: str, tenant: str, lane: str, phase: str) -> None:
    """One batch of `lane` in `phase`, built with the store's own verbs (a revert batch has no items)."""
    if lane == "revert":
        claim = call(dsn, "claim_revert", tenant, owner="reverter")
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


WAKE_LANES = ("author", "lead_author", "revert")
WAKE_PHASES = ("working", "in_review", "needs_person")


@pytest.mark.parametrize("lane", WAKE_LANES)
@pytest.mark.parametrize("phase", WAKE_PHASES)
def test_wake_a_batch_of_any_lane_in_any_phase_but_ended_keeps_the_tenants_checks_running(tmp_path, monkeypatch, lane, phase):
    """With nothing else queued, a not-yet-ended batch of the author lane, the lead lane or a revert, working, in review or
    waiting for a person, leaves the record without `waiting: false`: its lease, its PR or a person's release may still
    change what the tick must do. (Wake)"""
    from defender.tests.support.learning.core._store1278 import DSN_ENV

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "5")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "5")
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "3")
    ep, _ = _job_episode(tmp_path, f"wake-{lane}-{phase}", findings=False)
    data_root, tenant_id = J.episode_location(ep)
    _lane_batch(os.environ[DSN_ENV], tenant_id, lane, phase)

    hand_pending(data_root, tenant_id, None, [])
    post_step.main(["--tenant", tenant_id, "--parent-pid", str(os.getppid())],
                   author_tick=lambda *_a, **_k: 0, directory=T.launcher_directory(tenant_id))

    assert _record_at(ep, tenant_id) == {"published": [], "refused": []}


def test_wake_the_lanes_and_phases_above_are_every_one_the_schema_allows(migrated_database):  # noqa: F811 — the imported fixture
    """A lane or phase the schema gains has no case above until it is added: this fails first. (Wake)"""
    [(lanes,)] = execute(migrated_database, "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_batches_lane'")
    [(phases,)] = execute(migrated_database, "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_batches_phase'")
    quoted = lambda text: set(re.findall(r"'([a-z_]+)'", text))  # noqa: E731
    assert quoted(lanes) | {"revert"} == set(WAKE_LANES)
    assert quoted(phases) - {"ended"} == set(WAKE_PHASES)
