"""#1007 — D3/M7: the second authored corpus, its curator, and the one drain tick they share."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.learning.branch import _triplet_947 as T

import dataclasses
from pathlib import Path

import pytest

from defender.learning.core import drains
from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.branch import _world_1007 as W
from defender.tests.support.learning.curation._curator1134 import author_trees
from defender.tests.e2e import _box665 as B
from defender.tests.learning.judge.contrast_contracts import _spec1234 as S
from defender.tests.e2e.test_922_spine import (
    draft_root,
    drive_tenant_author_drain,
    tenant_paths,
    writable_sources,
)
from defender.learning.core.state import FINDINGS, PITFALLS, QUESTIONER_FINDINGS
from defender.tests.tenancy.tenant_1108_delivery._support import merge_on_remote
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSONS_PREFIX,
    remote_branches,
    touched,
)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

pytestmark = pytest.mark.e2e


@pytest.fixture(autouse=True)
def _thresholds(monkeypatch):
    """Both channels' thresholds at 1, stated rather than inherited: the shipped default of 5
    would make every assertion below vacuous on a drain that never woke."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")


@pytest.fixture
def tenant(tmp_path, data_root):
    """The fixture tenant published for real, its forge bound (#1108 P4 flow 4)."""
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        yield t


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
                 *, box=None, **kw) -> None:
        self.calls.append({
            "pending_file": Path(state.describe(channel)), "threshold_env": threshold_env,
            "module_name": module_name, "pending_label": pending_label, "box": box,
        })
        if module_name in self._fail_on:
            raise self._fault_class(f"{module_name} faulted mid-batch")
        if module_name not in self._run:
            return
        # Each module's own builder and entry (the questioner curator over its own corpus).
        if module_name == W.QUESTIONER_CURATOR_MODULE:
            from defender.learning.author.questioner import run as module

            build = module.build_questioner_config
        else:
            from defender.learning.author.lessons import run as module

            build = module.build_author_config
        cfg = dataclasses.replace(
            build(paths, state=state, trees=author_trees(paths), box=box, **kw),
            invoke_agent=self._agent,
        )
        module.run_batch(cfg=cfg, hold_committed=True, box=box)

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
               contrast_evidence=[f"worlds/{T.fixture_world_id('b')}/report.md", f"worlds/{T.fixture_world_id('a')}/report.md"],
               on_verdict_path=True, world_label_doubted=False,
               source_run_dir="episodes/ep-1/worlds/b")
    row.pop("judge_outcome", None)          # #1234 A4: a row carrying the retired name is held
    row.update(extra)
    return row


def drive(t, paths, trigger, *, rec=None):
    """The REAL `author_drain` over the tenant path (#1108 P4; `test_922_spine`'s driver)."""
    return drive_tenant_author_drain(t, paths, trigger, rec=rec)


def lane_sources(request, *lanes: str) -> set[Path]:
    """The draft's `agent/<lane>` folders of the box `request` mounts."""
    return {draft_root(request) / "agent" / lane for lane in lanes}


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


def test_the_questioner_queue_alone_wakes_the_drain(tenant, tmp_path):
    """The questioner queue over threshold wakes the drain ON ITS OWN (tenant path, #1108 P4)."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    D.seed(paths, QUESTIONER_FINDINGS, [world_queue_row()])
    assert D.pending(paths, FINDINGS) == []

    trigger = TwoLaneRecorder(D.recording(D.committing("questioner-lesson")))
    rc, rec = drive(t, paths, trigger)

    assert rc == 0
    assert W.QUESTIONER_CURATOR_MODULE in trigger.modules, (
        f"the questioner queue alone did not wake the drain: {trigger.modules}")
    assert rec.only_request() is not None, "no box was created for the questioner-only tick"


def test_the_author_drain_triggers_exactly_its_two_named_curators(tenant, tmp_path):
    """One tick triggers EXACTLY the two named curators — no more, and no fewer (tenant path,
    #1108 P4)."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    D.seed(paths, FINDINGS, [defender_queue_row()])
    D.seed(paths, QUESTIONER_FINDINGS, [world_queue_row()])

    trigger = TwoLaneRecorder(D.recording(D.committing("lesson")))
    rc, _rec = drive(t, paths, trigger)

    assert rc == 0
    assert sorted(trigger.modules) == sorted(
        [W.DEFENDER_CURATOR_MODULE, W.QUESTIONER_CURATOR_MODULE]), (
        f"one tick triggered {trigger.modules} — the drain's curator set is not the two "
        "literals it names")
    by_module = {c["module_name"]: c for c in trigger.calls}
    assert by_module[W.DEFENDER_CURATOR_MODULE]["pending_file"] == location_path(paths.state_root) / FINDINGS.queue
    assert by_module[W.QUESTIONER_CURATOR_MODULE]["pending_file"] == (
        location_path(paths.state_root) / QUESTIONER_FINDINGS.queue)


def test_a_full_findings_queue_alone_still_wakes_the_drain(tenant, tmp_path):
    """SURVIVAL: the incumbent findings-only drive still wakes the drain and still runs, its
    box getting the draft's two lesson corpora writable (tenant path, #1108 P4)."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    D.seed(paths, FINDINGS, [defender_queue_row()])
    assert D.pending(paths, QUESTIONER_FINDINGS) == []

    trigger = TwoLaneRecorder(D.recording(D.committing("family-lesson")),
                              run=(W.DEFENDER_CURATOR_MODULE,))
    rc, rec = drive(t, paths, trigger)

    assert rc == 0
    assert W.DEFENDER_CURATOR_MODULE in trigger.modules, (
        "the findings queue alone no longer wakes the drain")
    request = rec.only_request()
    assert writable_sources(request) == lane_sources(request, "lessons", "lessons-questioner")


def test_the_lead_author_label_never_mounts_the_questioner_corpus(tenant, tmp_path, monkeypatch):
    """The `lead_author_drain` lane mounts the draft's skills tree writable and NEITHER lessons
    corpus (tenant path, #1108 P4: the box is the batch's, over its draft). Woken by a pitfalls
    row over a threshold of 1; the lane's work steps are no-ops."""
    from defender.tests.support.learning.core._declared870 import shim_row

    t = tenant
    paths = tenant_paths(t, tmp_path)
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    D.seed(paths, PITFALLS, [shim_row("run-1:0")])
    rec = B.BoxLifecycleRecorder()

    rc = drains.lead_author_drain(
        paths, run_lead_author=lambda *_a, **_k: None, run_pitfalls=lambda *_a, **_k: 0,
        client=t.forge.client, identity=t.vault.identity(),
        start_box=rec.start_box, stop_box=rec.stop_box)

    assert rc == 0
    request = rec.only_request()
    assert writable_sources(request) == lane_sources(request, "skills"), (
        f"the lead-author box's writable mounts are "
        f"{sorted(map(str, writable_sources(request)))}")
    assert not lane_sources(request, "lessons", "lessons-questioner") & writable_sources(request)


def test_the_author_drain_box_mounts_exactly_the_two_lessons_corpora_writable(tenant, tmp_path):
    """The author drain's box mounts EXACTLY the draft's two lessons corpora writable, beside
    its read-only product code (`code`) and draft root (`staged`) — the read-only half keeps the
    exact set from being satisfied by a request that mounts nothing (tenant path, #1108 P4)."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    D.seed(paths, FINDINGS, [defender_queue_row()])

    rc, rec = drive(t, paths, TwoLaneRecorder(D.recording(D.committing("lesson"))))

    assert rc == 0
    request = rec.only_request()
    assert writable_sources(request) == lane_sources(request, "lessons", "lessons-questioner"), (
        f"the author drain box's writable mounts are "
        f"{sorted(map(str, writable_sources(request)))}")
    assert sorted(m.kind for m in request.mounts if not m.writable) == ["code", "staged"], (
        request.mounts)


# `test_an_unrecognized_drain_label_gets_no_box_at_all` (#1179 O1') is deleted with
# `drains._drain_box_request` (#1108 P4): no entry takes a label from outside any more; the two
# lanes' boxes are pinned through their real entries above and by
# `tenant_1108_p4/test_drains.py::test_flow4_author_drain_publishes_then_delivers_a_lesson_pr_on_the_tenant_forge_O7`.


def test_each_curator_consumes_its_own_channel_and_is_scoped_to_its_own_corpus(tenant, tmp_path):
    """Per-curator consumption and per-curator corpus scoping (tenant path, #1108 P4): a tick in
    which only the questioner curator runs leaves the defender queue alone, and the questioner
    curator's corpus is the draft's `agent/lessons-questioner`."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    D.seed(paths, FINDINGS, [defender_queue_row()])
    D.seed(paths, QUESTIONER_FINDINGS, [world_queue_row()])

    agent = D.recording(D.committing("questioner-lesson"))
    trigger = TwoLaneRecorder(agent, run=(W.QUESTIONER_CURATOR_MODULE,))
    _rc, rec = drive(t, paths, trigger)

    assert D.pending(paths, FINDINGS), (
        "the defender queue was consumed by a tick in which only the questioner curator ran")
    assert agent.calls, "the questioner curator never reached its model step"
    (questioner_corpus,) = lane_sources(rec.only_request(), "lessons-questioner")
    assert Path(agent.calls[0]["cfg"].corpus_dir) == questioner_corpus, (
        f"the questioner curator's corpus dir is {agent.calls[0]['cfg'].corpus_dir}")


@pytest.mark.parametrize("fault_class", [RuntimeError, TimeoutError],
                         ids=["escapes-the-catch", "swallowed-as-an-oserror"])
def test_a_faulting_curator_leaves_the_others_commit_and_consumed_markers_intact(
        tenant, tmp_path, fault_class):
    """One curator's fault leaves the other's landed commit AND CONSUMED MARKERS intact, and IS
    RECORDED — A2's three clauses, one assertion each (tenant path, #1108 P4: the landed commit
    is the batch's on the tenant origin; a human merges it before the second tick, whose
    idempotency read retires the row)."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    D.seed(paths, FINDINGS, [defender_queue_row()])
    D.seed(paths, QUESTIONER_FINDINGS, [world_queue_row()])
    main = t.origin_main()

    def faulting_tick(stem):
        trigger = TwoLaneRecorder(D.recording(D.committing(stem)),
                                  run=(W.DEFENDER_CURATOR_MODULE,),
                                  fail_on=(W.QUESTIONER_CURATOR_MODULE,),
                                  fault_class=fault_class)
        drive(t, paths, trigger)
        return trigger

    first = faulting_tick("family-lesson")
    (branch, tip), = remote_branches(t.remote, LESSONS_PREFIX).items()
    merge_on_remote(t.p3, t.scratch, branch)
    faulting_tick("must-not-author-twice")

    assert W.QUESTIONER_CURATOR_MODULE in first.modules, (
        f"the questioner curator was never triggered, so no fault was induced and every "
        f"assertion below holds vacuously: {first.modules}")
    landed = touched(t.remote, main, tip)
    assert [p for p in landed if p.startswith("agent/lessons/family-lesson-")], (
        f"the defender curator's commit did not land on the tenant branch: {landed}")
    assert not [p for p in landed if p.startswith("agent/lessons-questioner/")], landed

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
           if p not in allowed and p.parts[0] not in ("served", "worlds", "judge", "wire_logs")}
    assert new == set(), (
        f"the pass wrote artifacts outside the declared set: {sorted(map(str, new))}")
    queue_files = {p.name for p in (location_path(paths.state_root) / FINDINGS.queue).parent.glob("*") if p.is_file()}
    assert queue_files <= {(location_path(paths.state_root) / FINDINGS.queue).name, W.QUESTIONER_QUEUE_FILENAME,
                           (location_path(paths.state_root) / FINDINGS.append_lock).name,
                           (location_path(paths.state_root) / QUESTIONER_FINDINGS.append_lock).name,
                           (location_path(paths.state_root) / FINDINGS.consumed).name,
                           (location_path(paths.state_root) / QUESTIONER_FINDINGS.consumed).name, ".lock"}, (
        f"the queue directory gained {sorted(queue_files)}")
