"""#1344 O8, O14: the post-step publishes the tenant's pending jobs' findings, then runs the drain's gate, and its
record tells the worker the truth. State lives at the tenant's real learning folder, as production's does. No database."""
from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from defender.learning.core.config import LoopPaths
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS, LearningState
from defender.records._locations import unwrap_learning_root
from defender.tenancy._tenant import requested_tenant
from defender.tests.learning.branch.test_1344_job_lane import (
    _SIBLING, _WORKER, _await_pid, _gone, _running, child_env, sink_files)
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import fixture_data_root


class Boom(Exception):
    """An exception class no production code lists."""


def _job_episode(tmp_path, name: str, *, topic: str = "the lead was never revisited", findings: bool = True,
                 subject: str = "defender", comparable: bool = True):
    """A graded job episode under the tenant's real episodes folder: its judge ran in the job lane.
    `subject="world"` files a world finding, `subject="both"` one of each; `comparable=False` leaves a family no judge
    call is bought for."""
    est = S.estate(tmp_path)
    est.place(tenant_id=S.FIXTURE_TENANT)
    episode_id = fixture_uuid(f"1344-post-{name}")
    ep = S.judged_episode(tmp_path, doc=S.family_v2(episode_id=episode_id), outcome=None, episode_id=episode_id)
    S.outcome_record(ep, "accepted", family_stamp=False)
    if comparable:
        J.comparable_family_stamp(ep)
    subjects = ("defender", "world") if subject == "both" else (subject,)
    # Beside a defender finding, the world's is `mislabelled`: an `incoherent` one leaves the draw not measured.
    world_bucket = "mislabelled" if subject == "both" else "incoherent"
    filed = [J.finding_doc(bucket=world_bucket if one == "world" else "lead-quality", subject=one,
                           topic=topic if subject != "both" else f"{topic} ({one})",
                           **({"systems": ["idp"]} if one == "world" else {}))
             for one in subjects] if findings else []
    world = J.reply_doc(findings=filed)
    world.update(bucket="lead-quality", systems=["idp"])
    judge = J.scripted_judge(default=S.as_reply_text(world), family_default=S.as_reply_text(J.family_reply()))
    before = {p for p in ep.rglob("*") if p.is_file()}
    J.grade(ep, judge=judge, job_lane=True)
    if not comparable:
        assert not judge.calls, "premise: a family that is not comparable bought no judge call"
    _learning_paths(ep)
    return ep, sorted({p for p in ep.rglob("*") if p.is_file()} - before)


def _tenant_of(ep: Path):
    data_root, tenant_id = J.episode_location(ep)
    return requested_tenant(fixture_data_root(data_root), tenant_id)


def _learning_paths(ep: Path) -> LoopPaths:
    """The tenant's real learning state paths, its folder made as the host's prepare step makes it."""
    paths = LoopPaths.for_tenant(_tenant_of(ep))
    unwrap_learning_root(paths.state_dir).mkdir(parents=True, exist_ok=True)
    return paths


def _queue(ep: Path, channel=FINDINGS) -> list[dict]:
    with LearningState.open(_learning_paths(ep)) as state:
        return state.rows(channel)


def _record(ep: Path, job: str) -> dict:
    data_root, tenant_id = J.episode_location(ep)
    return json.loads((Path(data_root) / tenant_id / "runs" / f"{job}.post-step.json").read_text(encoding="utf-8"))


def _post_step(ep: Path, job: str, pending: list[str], *, tick=None) -> None:
    """The real post-step, its tenant admitted through the host acceptance from records handed in as `directory=`,
    as the launcher and the job entry take theirs."""
    from defender.learning.branch import post_step

    _data_root, tenant_id = J.episode_location(ep)
    argv = ["--job", job, "--tenant", tenant_id, "--pending", *pending, "--parent-pid", str(os.getppid())]
    post_step.main(argv, author_tick=tick if tick is not None else (lambda *_a, **_k: 0),
                   directory=T.launcher_directory(tenant_id))


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
    topics = {row["subject_topic"] for row in _queue(own)}
    assert {"a topic the lost job found", "a topic the own job found"} <= topics


def test_o8_retained_deliveries_wake_the_gate_for_a_job_that_published_nothing(tmp_path):
    """No new findings and a batch retained from an earlier tick: the gate still runs. (O8)"""
    ep, _ = _job_episode(tmp_path, "empty", findings=False)
    with LearningState.open(_learning_paths(ep)) as state:
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
    assert {row["subject_topic"] for row in _queue(good)} == {"a topic the good job found"}


def _sink_channels() -> list:
    """Every channel the episode's findings sink holds (the sink's own table, not a hand-named list)."""
    from defender.learning.judge import enqueue
    from defender.tests.support.learning.curation._drain719 import channel_of

    return [pytest.param(channel_of(name), id=name) for name in sorted(enqueue._SINK_RECORDS)]


def _sink_file(ep: Path, channel) -> Path:
    from defender.learning.judge import enqueue
    from defender.records.formats import LAYOUT

    return ep / getattr(LAYOUT, enqueue._SINK_RECORDS[channel.name])


@pytest.mark.parametrize("bad", _sink_channels())
def test_o8_one_invalid_row_in_any_channel_refuses_the_job_and_no_channel_publishes_any_of_its_rows(tmp_path, bad):
    """A job holding valid rows in every channel the sink holds, and one row that fails its channel's rule planted in
    `bad`: the record refuses the job, and no channel's queue gains a row of it (screened before anything is
    appended). (O8, O14, Publishing)"""
    ep, _ = _job_episode(tmp_path, f"bad-in-{bad.name}", subject="both")
    channels = [p.values[0] for p in _sink_channels()]
    for channel in channels:
        held = [json.loads(x) for x in _sink_file(ep, channel).read_text(encoding="utf-8").splitlines() if x.strip()]
        assert held, f"premise: the job holds valid rows in {channel.name}"
    with _sink_file(ep, bad).open("a", encoding="utf-8") as f:
        f.write(json.dumps({"finding_id": "not-a-finding"}) + "\n")

    _post_step(ep, ep.name, [ep.name])

    assert _record(ep, ep.name) == {"published": [], "refused": [ep.name]}
    assert {channel.name: _queue(ep, channel) for channel in channels} == {channel.name: [] for channel in channels}, (
        "a channel published rows of a refused job")


def test_o8_a_queue_level_failure_is_neither_published_nor_refused_and_retries(tmp_path):
    """The queue cannot be appended to: the job stays pending; once it can, the next post-step publishes it. (O8, O14)"""
    ep, _ = _job_episode(tmp_path, "transient")
    queue = unwrap_learning_root(_learning_paths(ep).state_dir) / FINDINGS.queue
    queue.parent.mkdir(parents=True, exist_ok=True)
    queue.mkdir()

    with contextlib.suppress(Exception, SystemExit):
        _post_step(ep, ep.name, [ep.name])
    assert _record(ep, ep.name) == {"published": [], "refused": []}

    queue.rmdir()
    _post_step(ep, ep.name, [ep.name])
    assert _record(ep, ep.name) == {"published": [ep.name], "refused": []}
    assert _queue(ep), "the retry published nothing"


def test_o8_a_post_step_with_nothing_pending_still_runs_the_gate(tmp_path):
    """An empty `--pending`: nothing to publish, and the drain's gate is still asked once; the record is empty. (O8)"""
    ep, _ = _job_episode(tmp_path, "nothing", findings=False)
    ticks: list[int] = []

    _post_step(ep, ep.name, [], tick=lambda *_a, **_k: ticks.append(1) or 0)

    assert ticks == [1], "the gate did not run for a post-step with nothing pending"
    assert _record(ep, ep.name) == {"published": [], "refused": []}


def test_o8_a_questioners_findings_reach_the_questioner_channel_not_the_investigators(tmp_path):
    """A job whose judge filed a world finding: publishing puts it on the questioner channel only. (O14, Publishing)"""
    ep, _ = _job_episode(tmp_path, "world", subject="world", topic="a topic the world finding carries")

    _post_step(ep, ep.name, [ep.name])

    assert _record(ep, ep.name) == {"published": [ep.name], "refused": []}
    assert {row["subject_topic"] for row in _queue(ep, QUESTIONER_FINDINGS)} == {"a topic the world finding carries"}
    assert _queue(ep) == [], "a world finding reached the investigators' queue"


def test_o8_a_completed_job_whose_judge_was_never_asked_publishes_as_done(tmp_path):
    """No findings file because the verdict graded nothing: published (so the row reads done), not refused, not pending for ever. (O14)"""
    ep, new = _job_episode(tmp_path, "ungraded", comparable=False)
    assert not sink_files(new), "premise: the episode holds no findings"

    _post_step(ep, ep.name, [ep.name])

    assert _record(ep, ep.name) == {"published": [ep.name], "refused": []}
    assert _queue(ep) == []


_POST_STEP = textwrap.dedent("""
    import os, sys
    from defender.learning.branch import post_step
    from defender.learning.branch.cli import _default_spawn
    from defender.tests.support.learning.branch import _triplet_947 as T

    tenant, pid_file, sibling = sys.argv[1:4]

    def tick(*_a, **_k):
        return _default_spawn([sys.executable, "-c", sibling, pid_file], env=dict(os.environ))

    post_step.main(["--job", sys.argv[4], "--tenant", tenant, "--pending", "--parent-pid", str(os.getppid())],
                   author_tick=tick, directory=T.launcher_directory(tenant))
""")


def test_o9_the_real_post_step_takes_the_tick_it_started_with_it_when_its_worker_is_killed(tmp_path):
    """SIGKILL the worker above the REAL post-step: its tie fires, and the tick's child (through the real spawn) is gone. (O9, O8)"""
    ep, _ = _job_episode(tmp_path, "chain", findings=False)
    _data_root, tenant_id = J.episode_location(ep)
    pid_file = tmp_path / "tick.pid"
    worker = subprocess.Popen([sys.executable, "-c", _WORKER, _POST_STEP, tenant_id, str(pid_file), _SIBLING, ep.name],
                              env=child_env())
    child = None
    try:
        child = _await_pid(pid_file)
        assert _running(child), "control: the tick's child is up"
        worker.kill()
        worker.wait()
        assert _gone(child), "the tick's child outlived the worker above the real post-step"
    finally:
        worker.kill()
        worker.wait()
        if child is not None and _running(child):
            os.kill(child, signal.SIGKILL)
