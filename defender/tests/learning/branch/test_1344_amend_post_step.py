"""#1344 amendment 1 (from #1278, owner-approved 2026-11-07): the family-less post-step's CLI form and record.

Without `--job` the post-step is the worker's family-less check of a tenant: it does the same work (publish the
handed `pending` jobs, then the drain's gate), and its record is kept under the tenant's own id,
`<runs>/<tenant id>.post-step.json`, one per tenant, named by `job_lane.post_step_key`. No database."""
from __future__ import annotations

import json
import os
from pathlib import Path

from defender.learning.branch import post_step
from defender.records.job_lane import post_step_key
from defender.tests.learning.branch.test_1344_post_step import _job_episode, _queue, hand_pending
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.judge import _judge_921 as J


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
