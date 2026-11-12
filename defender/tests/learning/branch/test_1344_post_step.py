"""#1344 O8, O14: the post-step publishes the tenant's pending jobs' findings, then runs the drain's gate, and its
record tells the worker the truth. State lives at the tenant's real learning folder, as production's does. No database."""
from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest

from defender.learning.core.config import LoopPaths
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS, LearningState
from defender.records._locations import unwrap_learning_root
from defender.tenancy._tenant import requested_tenant
from defender.tests.learning.branch.test_1344_job_lane import (
    sink_files)
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
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


def hand_pending(data_root, tenant_id: str, job: str | None, pending: list[str]) -> None:
    """What the worker does before it starts a post-step: the pending jobs, written where the post-step reads them."""
    from defender.records.job_lane import JobLane
    from defender.tenancy import data_root_from_path

    with JobLane.open(data_root_from_path(Path(data_root)), tenant_id, make=True) as lane:
        lane.write_post_step_pending(job, pending)


def _record(ep: Path, job: str) -> dict:
    data_root, tenant_id = J.episode_location(ep)
    return json.loads((Path(data_root) / tenant_id / "runs" / f"{job}.post-step.json").read_text(encoding="utf-8"))


def post_step_in_container(job: str | None, tenant_id: str, **seams) -> int:
    """The real post-step in its job container (#1170 A6): its argv as the helper starts it (no `--parent-pid`), and a
    job socket answering the helper's `launch` facts (the helper's own answers are `tests/jobs/`'s)."""
    from defender.learning.branch import post_step
    from defender.tests.support.jobs._socket_standin1170 import SocketStandIn

    argv = [*(["--job", job] if job is not None else []), "--tenant", tenant_id]
    with SocketStandIn(tenant_id, launch={"kind": "post-step", "job": job}) as helper:
        return post_step.main(argv, environ=helper.environ(), **seams)


def _post_step(ep: Path, job: str, pending: list[str], *, tick=None, waiting=lambda *_a, **_k: True) -> None:
    """The real post-step in its job container, the worker's pending list handed to it."""
    data_root, tenant_id = J.episode_location(ep)
    hand_pending(data_root, tenant_id, job, pending)
    post_step_in_container(job, tenant_id, author_tick=tick if tick is not None else (lambda *_a, **_k: 0),
                           still_waiting=waiting)


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


def test_a_pending_job_whose_episode_is_gone_is_refused_not_left_pending_for_ever(tmp_path):
    """Nothing brings a deleted episode back, so its job is refused, never retried by every later post-step; the
    other pending job is still published. (O14, #1446 review)"""
    import shutil

    ep, _new = _job_episode(tmp_path, "kept")
    gone, _ = _job_episode(tmp_path, "gone")
    shutil.rmtree(gone)

    _post_step(ep, ep.name, [gone.name, ep.name])

    assert _record(ep, ep.name) == {"published": [ep.name], "refused": [gone.name]}


def test_a_post_step_handed_no_readable_list_publishes_nothing_and_still_runs_the_gate(tmp_path):
    """No list where the worker writes it: nothing is published or refused (every job stays pending for the next
    post-step), and the drain's gate still runs. (O8, O14, #1446 review)"""
    ep, _new = _job_episode(tmp_path, "unhanded")
    _data_root, tenant_id = J.episode_location(ep)
    ticks: list[int] = []
    post_step_in_container(ep.name, tenant_id, author_tick=lambda *_a, **_k: ticks.append(1) or 0,
                           still_waiting=lambda *_a, **_k: True)

    assert _record(ep, ep.name) == {"published": [], "refused": []}
    assert ticks == [1]
    assert _queue(ep) == []


def test_a3_a_post_step_whose_gate_would_find_nothing_left_says_so_after_the_gate(tmp_path):
    """After the gate, the drain's own test is asked whether work still waits; `waiting: false` is written only when
    nothing does, and only after the gate ran. (amendment 3)"""
    ep, _ = _job_episode(tmp_path, "idle", findings=False)
    order: list[str] = []

    _post_step(ep, ep.name, [], tick=lambda *_a, **_k: order.append("gate") or 0,
               waiting=lambda *_a, **_k: order.append("asked") or False)

    assert order == ["gate", "asked"]
    assert _record(ep, ep.name) == {"published": [], "refused": [], "waiting": False}


@pytest.mark.parametrize("answer", [True, "fault"])
def test_a3_work_still_waiting_or_an_unknown_answer_leaves_the_record_without_the_flag(tmp_path, answer):
    """A record without `waiting` keeps the tenant's checks running: written so when work waits or the question
    faults. (amendment 3)"""
    ep, _ = _job_episode(tmp_path, "busy", findings=False)

    def waiting(*_a, **_k):
        if answer == "fault":
            raise RuntimeError("the learning state could not be opened")
        return answer

    _post_step(ep, ep.name, [], waiting=waiting)

    assert _record(ep, ep.name) == {"published": [], "refused": []}


@pytest.mark.parametrize(("threshold", "waiting"), [("2", True), ("3", False)])
def test_a3_still_waiting_is_the_author_drain_gate_s_own_test(tmp_path, monkeypatch, threshold, waiting):
    """Two published findings: at threshold 2 the author drain's gate would open, so work waits; at 3 it stays shut, so
    nothing does. The question the post-step asks is the gate's own. (amendment 3)"""
    from defender.learning.core.drains import author_work_waiting

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", threshold)
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "5")
    ep, _ = _job_episode(tmp_path, f"gate-{threshold}")
    _post_step(ep, ep.name, [ep.name])
    assert len(_queue(ep)) == 2, "premise: the job's two findings were published"

    assert author_work_waiting(_learning_paths(ep)) is waiting
