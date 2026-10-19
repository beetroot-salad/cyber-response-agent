"""#1007 — D3/M7: the second authored corpus, its curator, and the one drain tick they share."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from defender.learning.core import drains
from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL
from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.branch import _world_1007 as W
from defender.tests.support.learning.curation._curator1134 import author_trees
from defender.tests.e2e import _box665 as B
from defender.tests.learning.judge.contrast_contracts import _spec1234 as S
from defender.tests.e2e.test_922_spine import (
    RepoBranch,
    readonly_sources,
    writable_sources,
)
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS

pytestmark = pytest.mark.e2e


@pytest.fixture(autouse=True)
def _thresholds(monkeypatch):
    """Both channels' thresholds at 1, stated rather than inherited: the shipped default of 5
    would make every assertion below vacuous on a drain that never woke."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")


class TwoLaneRecorder:
    """The `trigger_author=` seam, recording BOTH curators' inbound payloads."""

    def __init__(self, agent, *, run: tuple[str, ...] = (), fail_on: tuple[str, ...] = (),
                 fault_class: type[BaseException] = RuntimeError):
        self.calls: list[dict] = []
        self._agent = agent
        self._run = run
        self._fail_on = fail_on
        self._fault_class = fault_class

    def __call__(self, paths, state, channel, threshold_env, module_name, pending_label,
                 *, box=None) -> None:
        self.calls.append({
            "pending_file": Path(state.describe(channel)), "threshold_env": threshold_env,
            "module_name": module_name, "pending_label": pending_label, "box": box,
        })
        if module_name in self._fail_on:
            raise self._fault_class(f"{module_name} faulted mid-batch")
        if module_name not in self._run:
            return
        from defender.learning.author.lessons import run as lessons_run

        cfg = dataclasses.replace(
            lessons_run.build_author_config(
                paths, state=state, trees=author_trees(paths), box=box),
            invoke_agent=self._agent,
        )
        lessons_run.run_batch(paths=paths, cfg=cfg, hold_committed=True, box=box)

    @property
    def modules(self) -> list[str]:
        return [c["module_name"] for c in self.calls]


def world_queue_row(fid: str = "ep-1/b/0/0", **extra) -> dict:
    row = dict(D.finding_row(fid, run_id="ep-1", direction=W.SUBJECT_WORLD),
               subject=W.SUBJECT_WORLD, type="incoherent", world="b",
               systems=[W.SYSTEM], provenance="model",
               subject_anchor="facts", subject_topic="answer shape",
               citations=["family.yaml#worlds/b"], source_run_dir="episodes/ep-1")
    row.pop("judge_outcome", None)          # #1234 A4: a row carrying the retired name is held
    row.update(extra)
    return row


def defender_queue_row(fid: str = "ep-1/b/0/1", **extra) -> dict:
    row = dict(D.finding_row(fid, run_id="ep-1", direction="family"),
               subject=W.SUBJECT_DEFENDER, type="lead-set",
               subject_anchor="l-001", subject_topic="coverage",
               contrast_evidence=["worlds/b/report.md", "worlds/a/report.md"],
               on_verdict_path=True, world_label_doubted=False,
               source_run_dir="episodes/ep-1/worlds/b")
    row.pop("judge_outcome", None)          # #1234 A4: a row carrying the retired name is held
    row.update(extra)
    return row


def drive(paths, trigger, *, rec=None):
    rec = rec or B.BoxLifecycleRecorder()
    rc = drains.author_drain(
        paths, trigger_author=trigger, branch=RepoBranch(paths.repo_root, events=rec.events),
        start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub)
    return rc, rec


def test_the_questioner_curator_gate_is_idempotency_only(tmp_path):
    """The questioner curator's gate is IDEMPOTENCY ONLY — no ground-truth check, no family
    partition."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    curator = W.mod("learning.author.questioner.run")
    cfg = curator.build_questioner_config(
        paths, state=W.learning_state(paths), trees=author_trees(paths))

    # `CorpusAuthorConfig.gate`'s own documented order, which is what `drain.run_batch`
    # unpacks: `held, consumed_pre, to_author = cfg.gate(keyed, cfg)`.
    held, consumed_pre, to_author = cfg.gate([world_queue_row()], cfg)

    assert [r["finding_id"] for r in to_author] == ["ep-1/b/0/0"], (
        f"a world row with no defender ground truth was held: {held}")
    assert held == [], f"the gate held a world row it has no ground-truth rule for: {held}"
    assert consumed_pre == []


def test_the_questioner_queue_alone_wakes_the_drain(tmp_path):
    """The questioner queue over threshold wakes the drain ON ITS OWN."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(paths, QUESTIONER_FINDINGS, [world_queue_row()])
    assert D.pending(paths, FINDINGS) == []

    trigger = TwoLaneRecorder(D.recording(D.committing("questioner-lesson")))
    rc, rec = drive(paths, trigger)

    assert rc == 0
    assert W.QUESTIONER_CURATOR_MODULE in trigger.modules, (
        f"the questioner queue alone did not wake the drain: {trigger.modules}")
    assert rec.only_request() is not None, "no box was created for the questioner-only tick"


def test_the_author_drain_triggers_exactly_its_two_named_curators(tmp_path):
    """One tick triggers EXACTLY the two named curators — no more, and no fewer."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(paths, FINDINGS, [defender_queue_row()])
    D.seed(paths, QUESTIONER_FINDINGS, [world_queue_row()])

    trigger = TwoLaneRecorder(D.recording(D.committing("lesson")))
    rc, _rec = drive(paths, trigger)

    assert rc == 0
    assert sorted(trigger.modules) == sorted(
        [W.DEFENDER_CURATOR_MODULE, W.QUESTIONER_CURATOR_MODULE]), (
        f"one tick triggered {trigger.modules} — the drain's curator set is not the two "
        "literals it names")
    by_module = {c["module_name"]: c for c in trigger.calls}
    assert by_module[W.DEFENDER_CURATOR_MODULE]["pending_file"] == paths.state_root / FINDINGS.queue
    assert by_module[W.QUESTIONER_CURATOR_MODULE]["pending_file"] == (
        paths.state_root / QUESTIONER_FINDINGS.queue)


def test_a_full_findings_queue_alone_still_wakes_the_drain(tmp_path):
    """SURVIVAL: the incumbent findings-only drive still wakes the drain and still runs."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(paths, FINDINGS, [defender_queue_row()])
    assert D.pending(paths, QUESTIONER_FINDINGS) == []

    trigger = TwoLaneRecorder(D.recording(D.committing("family-lesson")),
                              run=(W.DEFENDER_CURATOR_MODULE,))
    rc, rec = drive(paths, trigger)

    assert rc == 0
    assert W.DEFENDER_CURATOR_MODULE in trigger.modules, (
        "the findings queue alone no longer wakes the drain")
    assert writable_sources(rec.only_request()) == {
        paths.lessons_dir, paths.lessons_questioner_dir}


def test_the_lead_author_label_never_mounts_the_questioner_corpus(tmp_path):
    """The `lead_author_drain` label mounts the skills tree and NEITHER lessons corpus."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")

    request = drains._drain_box_request(
        paths.repo_root, "batch-1", LEAD_AUTHOR_DRAIN_LABEL, paths)

    assert writable_sources(request) == {paths.with_repo_root(paths.repo_root).skills_dir}, (
        f"the lead-author box's writable mounts are "
        f"{sorted(map(str, writable_sources(request)))}")
    assert paths.lessons_questioner_dir not in writable_sources(request)


def test_the_author_drain_box_mounts_exactly_the_two_lessons_corpora_writable(tmp_path):
    """The author drain's box mounts EXACTLY the two lessons corpora writable."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    wt = paths.with_repo_root(paths.repo_root)

    request = drains._drain_box_request(paths.repo_root, "batch-1", AUTHOR_DRAIN_LABEL, paths)

    assert writable_sources(request) == {wt.lessons_dir, wt.lessons_questioner_dir}, (
        f"the author drain box's writable mounts are "
        f"{sorted(map(str, writable_sources(request)))}")
    assert readonly_sources(request) == {paths.repo_root}, (
        "the drain box lost its read-only worktree mount — without it the exact set above "
        "could be satisfied by a request that mounts nothing at all")


def test_an_unrecognized_drain_label_gets_no_box_at_all(tmp_path):
    """An UNRECOGNIZED drain label gets no box at all (#1179 amendment, O1')."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    wt = paths.with_repo_root(paths.repo_root)

    with pytest.raises(AttributeError):
        drains._drain_box_request(paths.repo_root, "batch-1", "a_third_drain", paths)

    request = drains._drain_box_request(paths.repo_root, "batch-1", AUTHOR_DRAIN_LABEL, paths)
    assert {wt.lessons_dir, wt.lessons_questioner_dir} <= writable_sources(request)


def test_one_author_drain_tick_opens_one_branch_and_one_pr_for_both_corpora(tmp_path):
    """One tick, one worktree, one box, one branch and one PR lease — covering both corpora."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(paths, FINDINGS, [defender_queue_row()])
    D.seed(paths, QUESTIONER_FINDINGS, [world_queue_row()])

    trigger = TwoLaneRecorder(D.recording(D.committing("lesson")))
    rc, rec = drive(paths, trigger)

    assert rc == 0
    starts = [e for e in rec.events if str(e).startswith("start_batch")]
    finishes = [e for e in rec.events if str(e).startswith("finish_batch")]
    assert len(starts) == 1, f"one tick started {len(starts)} batches: {rec.events}"
    assert len(finishes) <= 1, f"one tick finished {len(finishes)} batches: {rec.events}"
    assert len(rec.requests) == 1, f"one tick created {len(rec.requests)} boxes"
    assert len(trigger.modules) == 2


def test_each_curator_consumes_its_own_channel_and_is_scoped_to_its_own_corpus(tmp_path):
    """Per-curator consumption and per-curator corpus scoping."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    curator = W.mod("learning.author.questioner.run")
    D.seed(paths, FINDINGS, [defender_queue_row()])
    D.seed(paths, QUESTIONER_FINDINGS, [world_queue_row()])

    trigger = TwoLaneRecorder(D.recording(D.committing("questioner-lesson")),
                              run=(W.QUESTIONER_CURATOR_MODULE,))
    drive(paths, trigger)

    assert D.pending(paths, FINDINGS), (
        "the defender queue was consumed by a tick in which only the questioner curator ran")
    cfg = curator.build_questioner_config(
        paths, state=W.learning_state(paths), trees=author_trees(paths))
    assert Path(cfg.corpus_dir) == paths.lessons_questioner_dir, (
        f"the questioner curator's corpus dir is {cfg.corpus_dir}")


@pytest.mark.parametrize("fault_class", [RuntimeError, TimeoutError],
                         ids=["escapes-the-catch", "swallowed-as-an-oserror"])
def test_a_faulting_curator_leaves_the_others_commit_and_consumed_markers_intact(
        tmp_path, fault_class):
    """One curator's fault leaves the other's landed commit AND CONSUMED MARKERS intact, and IS
    RECORDED — A2's three clauses, one assertion each."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    D.seed(paths, FINDINGS, [defender_queue_row()])
    D.seed(paths, QUESTIONER_FINDINGS, [world_queue_row()])
    head_before = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()

    def faulting_tick(stem):
        trigger = TwoLaneRecorder(D.recording(D.committing(stem)),
                                  run=(W.DEFENDER_CURATOR_MODULE,),
                                  fail_on=(W.QUESTIONER_CURATOR_MODULE,),
                                  fault_class=fault_class)
        drive(paths, trigger)
        return trigger

    first = faulting_tick("family-lesson")
    faulting_tick("must-not-author-twice")

    assert W.QUESTIONER_CURATOR_MODULE in first.modules, (
        f"the questioner curator was never triggered, so no fault was induced and every "
        f"assertion below holds vacuously: {first.modules}")
    head_after = D.git(paths.repo_root, "rev-parse", "HEAD").stdout.strip()
    assert head_after != head_before, (
        "the defender curator's landed commit was rolled back by the other lane's fault")
    assert list(paths.lessons_dir.glob("*.md")), (
        "the defender corpus lost its authored document to the other curator's fault")

    landed = D.pending_by_id(paths, FINDINGS)
    consumed = {r.get(FINDINGS.id_key) for r in D.consumed(paths, FINDINGS)}
    assert "ep-1/b/0/1" not in landed, (
        f"the defender curator authored, committed and rotated, and its row is still queued: "
        f"{landed} — the next tick authors the same lesson again")
    assert "ep-1/b/0/1" in consumed, (
        f"the defender curator's consumed markers do not name its landed row: {consumed} — its "
        "commit is on HEAD and nothing records that the row behind it was retired")

    stranded = D.pending_by_id(paths, QUESTIONER_FINDINGS)
    assert "ep-1/b/0/0" in stranded, (
        f"the FAULTING curator's row was consumed anyway: {stranded} — a fault after "
        "consumption and before authoring retires a finding no lesson was ever written from, "
        "which is the failure per-curator consumption exists to prevent")
    assert not D.consumed(paths, QUESTIONER_FINDINGS), (
        "the faulting lane wrote consumed markers for rows it never authored")

    stuck = D.stuck_records(paths, QUESTIONER_FINDINGS)
    assert stuck, (
        f"a {fault_class.__name__} took the questioner curator out of a tick that then committed "
        "and pushed, and left no durable record of it — A2's third clause is 'and IS RECORDED'; "
        "a log line in a stream nobody keeps is not a record an operator can read afterwards")
    assert any(r.get("fault_class") == fault_class.__name__ for r in stuck), (
        f"the stuck record names {[r.get('fault_class') for r in stuck]} rather than "
        f"{fault_class.__name__!r} — a record that cannot say WHICH fault stopped the lane "
        "cannot tell an outage from a bug")
    assert not D.stuck_records(paths, FINDINGS), (
        "the SURVIVING lane carries a stuck record — the fault was recorded against the curator "
        "that landed its work")


def test_nothing_lands_outside_the_declared_write_set(tmp_path, monkeypatch):
    """M1 to M5 write EXACTLY the five artifacts this change declares, and nothing else."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    built = W.contrast_family(tmp_path, monkeypatch)
    ep = built.ep
    before = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}
    judge = S.judge({"b": S.world_reply("lead-quality", ["idp"], investigator=[S.inv()],
                                        world=[S.wf("mislabelled")])})

    S.grade(built, judge, state=W.learning_state(paths))

    # The control: the pass graded and queued on BOTH channels, so the write set below is the
    # one a whole pass leaves rather than the one a refused pass leaves.
    for channel in (FINDINGS, QUESTIONER_FINDINGS):
        assert W.queue_rows(paths, channel), (
            f"the pass queued nothing on {channel.queue}, so the write set below is not a "
            "whole pass's")
    after = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}
    allowed = {Path(W.JUDGE_NAME), Path(W.OUTCOME_NAME), Path(W.SAMPLES_NAME)}
    new = {p for p in after - before
           if p not in allowed and p.parts[0] not in ("served", "worlds", "draws", "wire_logs")}
    assert new == set(), (
        f"the pass wrote artifacts outside the declared set: {sorted(map(str, new))}")
    queue_files = {p.name for p in (paths.state_root / FINDINGS.queue).parent.glob("*") if p.is_file()}
    assert queue_files <= {(paths.state_root / FINDINGS.queue).name, W.QUESTIONER_QUEUE_FILENAME,
                           (paths.state_root / FINDINGS.append_lock).name,
                           (paths.state_root / QUESTIONER_FINDINGS.append_lock).name,
                           (paths.state_root / FINDINGS.consumed).name,
                           (paths.state_root / QUESTIONER_FINDINGS.consumed).name, ".lock"}, (
        f"the queue directory gained {sorted(queue_files)}")
