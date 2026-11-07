"""#1344 O8, O14: the post-step publishes the tenant's pending jobs' findings, then runs the drain's gate, and its
record tells the worker the truth. State lives at the tenant's real learning folder, as production's does. No database."""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path

from defender.learning.core.config import LoopPaths
from defender.learning.core.state import FINDINGS, LearningState
from defender.tenancy._tenant import requested_tenant
from defender.tests.learning.branch.test_1344_job_lane import sink_files
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import fixture_data_root


class Boom(Exception):
    """An exception class no production code lists."""


def _job_episode(tmp_path, name: str, *, topic: str = "the lead was never revisited", findings: bool = True):
    """A graded job episode under the tenant's real episodes folder: its judge ran in the job lane."""
    est = S.estate(tmp_path)
    est.place(tenant_id=S.FIXTURE_TENANT)
    episode_id = fixture_uuid(f"1344-post-{name}")
    ep = S.judged_episode(tmp_path, doc=S.family_v2(episode_id=episode_id), outcome=None, episode_id=episode_id)
    S.outcome_record(ep, "accepted", family_stamp=False)
    J.comparable_family_stamp(ep)
    filed = [J.finding_doc(bucket="lead-quality", subject="defender", topic=topic)] if findings else []
    world = J.reply_doc(findings=filed)
    world.update(bucket="lead-quality", systems=["idp"])
    judge = J.scripted_judge(default=S.as_reply_text(world), family_default=S.as_reply_text(J.family_reply()))
    before = {p for p in ep.rglob("*") if p.is_file()}
    J.grade(ep, judge=judge, job_lane=True)
    return ep, sorted({p for p in ep.rglob("*") if p.is_file()} - before)


def _tenant_of(ep: Path):
    data_root, tenant_id = J.episode_location(ep)
    return requested_tenant(fixture_data_root(data_root), tenant_id)


def _queue(ep: Path) -> list[dict]:
    with LearningState.open(LoopPaths.for_tenant(_tenant_of(ep))) as state:
        return state.rows(FINDINGS)


def _record(ep: Path, job: str) -> dict:
    data_root, tenant_id = J.episode_location(ep)
    return json.loads((Path(data_root) / tenant_id / "runs" / f"{job}.post-step.json").read_text(encoding="utf-8"))


def _post_step(ep: Path, job: str, pending: list[str], *, tick=None) -> None:
    from defender.learning.branch import post_step

    _data_root, tenant_id = J.episode_location(ep)
    argv = ["--job", job, "--tenant", tenant_id, "--pending", *pending, "--parent-pid", str(os.getppid())]
    post_step.main(argv, author_tick=tick if tick is not None else (lambda *_a, **_k: 0))


def test_o8_the_post_step_publishes_then_runs_the_drain_gate_and_records_it(tmp_path):
    """The gate is asked only after this job's findings reached the queue; the worker's record says so. (O8, D-C)"""
    ep, _new = _job_episode(tmp_path, "a")
    assert _queue(ep) == [], "premise: a job's judge left the queue alone"
    seen: list[int] = []

    _post_step(ep, ep.name, [ep.name], tick=lambda *_a, **_k: seen.append(len(_queue(ep))) or 0)

    assert seen, "the drain gate never ran"
    assert seen[0] > 0, "the gate ran before publishing"
    assert _record(ep, ep.name) == {"published": [ep.name], "refused": []}


def test_o8_it_publishes_every_pending_job_of_the_tenant_not_only_its_own(tmp_path):
    """A job whose own post-step was lost is published by the next one. (O14, Publishing)"""
    lost, _ = _job_episode(tmp_path, "lost", topic="a topic the lost job found")
    own, _ = _job_episode(tmp_path, "own", topic="a topic the own job found")

    _post_step(own, own.name, [lost.name, own.name])

    assert sorted(_record(own, own.name)["published"]) == sorted([lost.name, own.name])
    topics = {row["topic"] for row in _queue(own)}
    assert {"a topic the lost job found", "a topic the own job found"} <= topics


def test_o8_retained_deliveries_wake_the_gate_for_a_job_that_published_nothing(tmp_path):
    """No new findings and a batch retained from an earlier tick: the gate still runs. (O8)"""
    ep, _ = _job_episode(tmp_path, "empty", findings=False)
    with LearningState.open(LoopPaths.for_tenant(_tenant_of(ep))) as state:
        state.record_delivery("author-b1", {"branch": "learning/b1", "batch_id": "b1", "label": "author",
                                            "reason": "push refused", "at": "2026-11-07T00:00:00Z"})
    ticks: list[int] = []

    _post_step(ep, ep.name, [ep.name], tick=lambda *_a, **_k: ticks.append(1) or 0)

    assert ticks == [1]
    assert _record(ep, ep.name) == {"published": [ep.name], "refused": []}


def test_o8_a_failing_gate_leaves_the_record_truthful_about_what_was_published(tmp_path):
    """The tick raises after publishing: the findings are in the queue and the record says so. (O8, O14)"""
    ep, _ = _job_episode(tmp_path, "tickfails")

    def failing(*_a, **_k):
        raise Boom("the author tick failed")

    with contextlib.suppress(Exception, SystemExit):
        _post_step(ep, ep.name, [ep.name], tick=failing)

    assert _queue(ep), "premise: publishing happened"
    assert _record(ep, ep.name) == {"published": [ep.name], "refused": []}


def test_o8_findings_that_fail_validation_are_refused_and_do_not_hold_back_a_good_job(tmp_path):
    """One bad row refuses its job for good; the other job in the same post-step publishes. (O8, O14, Publishing)"""
    bad, bad_files = _job_episode(tmp_path, "bad", topic="a topic the bad job found")
    good, _ = _job_episode(tmp_path, "good", topic="a topic the good job found")
    sunk = sink_files(bad_files)
    assert sunk, f"premise: the job lane left no findings file in the episode: {bad_files}"
    for path in sunk:
        path.write_text(json.dumps({"finding_id": "not-a-finding"}) + "\n", encoding="utf-8")

    _post_step(good, good.name, [bad.name, good.name])

    assert _record(good, good.name) == {"published": [good.name], "refused": [bad.name]}
    assert {row["topic"] for row in _queue(good)} == {"a topic the good job found"}


def test_o8_a_queue_level_failure_is_neither_published_nor_refused_and_retries(tmp_path):
    """The queue cannot be appended to: the job stays pending; once it can, the next post-step publishes it. (O8, O14)"""
    ep, _ = _job_episode(tmp_path, "transient")
    queue = LoopPaths.for_tenant(_tenant_of(ep)).state_dir / FINDINGS.queue
    queue.parent.mkdir(parents=True, exist_ok=True)
    queue.mkdir()

    with contextlib.suppress(Exception, SystemExit):
        _post_step(ep, ep.name, [ep.name])
    assert _record(ep, ep.name) == {"published": [], "refused": []}

    queue.rmdir()
    _post_step(ep, ep.name, [ep.name])
    assert _record(ep, ep.name) == {"published": [ep.name], "refused": []}
    assert _queue(ep), "the retry published nothing"
