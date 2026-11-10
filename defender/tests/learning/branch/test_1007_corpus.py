"""#1007: the second authored corpus, its curator, and the one drain tick they share.

The drain tests drive the real tenant path (#1108 P4) over the learning store (#1278): the box is the batch's, over its
draft; the curators' items are the claim's, by kind.
"""
from __future__ import annotations

import dataclasses
import logging
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.learning.branch import _triplet_947 as T  # noqa: E402
from defender.tests.support.learning.branch import _world_1007 as W  # noqa: E402
from defender.tests.support.learning.core._curators1278 import (  # noqa: E402
    Reply, ScriptedModel, result, scripted)
from defender.tests.support.learning.core._store1278 import (  # noqa: E402
    call, lesson_citing, migrated_database, world)  # noqa: F401 — fixtures
from defender.tests.support.learning.curation import _drain719 as D  # noqa: E402
from defender.tests.support.learning.judge import _gate_1278 as G  # noqa: E402
from defender.tests.learning.judge.contrast_contracts import _spec1234 as S  # noqa: E402
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS  # noqa: E402
from defender.tests.tenancy.tenant_1108_p4._drain_support import (  # noqa: E402
    AUTHOR_DRAFT_LANES, BoxSpy, author_drain, draft_lane_trees, lead_author_drain)
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: E402, F401 — fixture `world` is built on

_KIND_OF = {W.DEFENDER_CURATOR_MODULE: "finding", W.QUESTIONER_CURATOR_MODULE: "questioner_finding"}


class TwoLaneRecorder:
    """The tick's `trigger_author` seam (#1278: `(paths, None, kind, threshold_env, module, label, *, batch, box, items,
    feedback, outcomes)`), recording BOTH curators' calls and the items each was handed. `run` names the modules whose
    REAL curator then runs over those items (`run_batch`, its model `agent`); `fail_on` names the modules that fault."""

    def __init__(self, agent=None, *, run: tuple[str, ...] = (), fail_on: tuple[str, ...] = (),
                 fault_class: type[BaseException] = RuntimeError):
        self.calls: list[dict] = []
        self._agent = agent
        self._run = run
        self._fail_on = fail_on
        self._fault_class = fault_class

    def __call__(self, paths, _state, kind, threshold_env, module_name, pending_label,
                 *, box=None, batch=None, items=(), feedback=None, outcomes=None, **_kw) -> None:
        self.calls.append({
            "kind": kind, "keys": [key for _k, key, _p in items], "threshold_env": threshold_env,
            "module_name": module_name, "pending_label": pending_label, "box": box,
        })
        if module_name in self._fail_on:
            raise self._fault_class(f"{module_name} faulted mid-batch")
        if module_name not in self._run:
            return
        # Each module's own builder and entry (the questioner curator over its own corpus), over the draft the batch
        # handed it, never `paths`' product-checkout corpus.
        if module_name == W.QUESTIONER_CURATOR_MODULE:
            from defender.learning.author.questioner import run as module

            build = module.build_questioner_config
        else:
            from defender.learning.author.lessons import run as module

            build = module.build_author_config
        with draft_lane_trees(batch, AUTHOR_DRAFT_LANES) as trees:
            cfg = dataclasses.replace(
                build(paths, trees=trees, box=box, batch=batch, feedback=feedback), invoke_agent=self._agent)
            module.run_batch(cfg=cfg, items=items, outcomes=outcomes, box=box)

    @property
    def modules(self) -> list[str]:
        return [c["module_name"] for c in self.calls]


def world_queue_row(fid: str = "ep-1/b/0/0", **extra) -> dict:
    row = dict(D.finding_row(fid, run_id="ep-1", direction=W.SUBJECT_WORLD),
               subject=W.SUBJECT_WORLD, type="incoherent", world="b",
               systems=[W.SYSTEM], provenance="model",
               subject_anchor="facts", subject_topic="answer shape",
               citations=["family.yaml#worlds/b"], source_run_dir="episodes/ep-1")
    row.pop("judge_outcome", None)          # a row carrying the retired name is held (#1234)
    row.update(extra)
    return row


def defender_queue_row(fid: str = "ep-1/b/0/1", **extra) -> dict:
    row = dict(D.finding_row(fid, run_id="ep-1", direction="family"),
               subject=W.SUBJECT_DEFENDER, type="lead-set",
               subject_anchor="l-001", subject_topic="coverage",
               contrast_evidence=[f"worlds/{T.fixture_world_id('b')}/report.md", f"worlds/{T.fixture_world_id('a')}/report.md"],
               on_verdict_path=True, world_label_doubted=False,
               source_run_dir="episodes/ep-1/worlds/b")
    row.pop("judge_outcome", None)          # a row carrying the retired name is held (#1234)
    row.update(extra)
    return row


def _seed(w, *rows: dict, kind: str = "finding") -> None:
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", list(rows), kind=kind)


def _items(w) -> dict:
    return {(i.kind, i.key): i for i in call(w.dsn, "work", w.t.tenant_id)}


def _tick(w, trigger=None, *, model=None) -> tuple[int, BoxSpy]:
    box = BoxSpy()
    if model is None:
        return author_drain(w.t, w.paths, trigger=trigger, box=box), box
    with scripted(model, w.monkeypatch):
        return author_drain(w.t, w.paths, trigger=None, box=box, make_model=model.make_model), box


def _writable(request) -> set[Path]:
    return {Path(m.source) for m in request.mounts if m.writable}


def _lane_sources(request, *lanes: str) -> set[Path]:
    """The draft's `agent/<lane>` folders of the box `request` mounts."""
    (staged,) = [Path(m.source) for m in request.mounts if m.kind == "staged"]
    return {staged / "agent" / lane for lane in lanes}


def test_the_questioner_curator_gate_is_idempotency_only(tmp_path):
    """No ground-truth check and no family partition: a world row goes straight to authoring."""
    cfg = G.questioner_cfg(G.gate_lane(tmp_path))

    # `cfg.gate` returns `(held, consumed_pre, to_author)`, the order `drain.run_batch` unpacks.
    held, consumed_pre, to_author = cfg.gate([world_queue_row()], cfg)

    assert [r["finding_id"] for r in to_author] == ["ep-1/b/0/0"], (
        f"a world row with no defender ground truth was held: {held}")
    assert held == [], f"the gate held a world row it has no ground-truth rule for: {held}"
    assert consumed_pre == []


@pytest.mark.postgres
@pytest.mark.parametrize("seeded", ["questioner-alone", "both-kinds"])
def test_the_author_tick_hands_each_curator_exactly_its_own_kinds_items(world, seeded):  # noqa: F811 — the imported fixture
    """One tick triggers the curator of each kind that has items, no other, each handed its own kind's items: a
    questioner row ALONE still wakes the questioner curator (and a box is made for it)."""
    w = world
    if seeded == "both-kinds":
        _seed(w, defender_queue_row())
    _seed(w, world_queue_row(), kind="questioner_finding")
    trigger = TwoLaneRecorder()

    rc, box = _tick(w, trigger)

    assert rc == 0
    wanted = {"finding": ["ep-1/b/0/1"], "questioner_finding": ["ep-1/b/0/0"]}
    if seeded == "questioner-alone":
        wanted.pop("finding")
    assert {c["kind"]: c["keys"] for c in trigger.calls} == wanted, (
        f"the tick triggered {[(c['module_name'], c['keys']) for c in trigger.calls]}")
    assert {c["module_name"] for c in trigger.calls} <= {W.DEFENDER_CURATOR_MODULE, W.QUESTIONER_CURATOR_MODULE}
    assert len(box.requests) == 1, "no box was made for the tick's curators"


@pytest.mark.postgres
def test_the_author_drain_box_mounts_exactly_the_two_lessons_corpora_writable(world):  # noqa: F811 — the imported fixture
    """Beside the writable corpora the box mounts read-only product code (`code`) and draft root
    (`staged`); checking that half keeps a request that mounts nothing from passing."""
    w = world
    _seed(w, defender_queue_row())
    model = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("ep-1/b/0/1")}, result(committed=["ep-1/b/0/1"])))

    rc, box = _tick(w, model=model)

    assert rc == 0
    (request,) = box.requests
    assert _writable(request) == _lane_sources(request, "lessons", "lessons-questioner"), (
        f"the author drain box's writable mounts are {sorted(map(str, _writable(request)))}")
    assert sorted(m.kind for m in request.mounts if not m.writable) == ["code", "staged"], request.mounts


@pytest.mark.postgres
def test_the_lead_author_label_never_mounts_the_questioner_corpus(world, monkeypatch):  # noqa: F811 — the imported fixture
    """The `lead_author_drain` box mounts the draft's skills tree writable and NEITHER lessons corpus. Woken by one
    pitfall (threshold 1)."""
    from defender.learning.leads.pitfalls_curator import REDUCER_REL
    from defender.tests.support.learning.core._declared870 import shim_row
    from defender.tests.tenancy.tenant_1108_p4._support import FIXTURE

    w = world
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    call(w.dsn, "add_pitfall", w.t.tenant_id, shim_row("run-1:0"))
    page = (FIXTURE / REDUCER_REL).read_text(encoding="utf-8")
    model = ScriptedModel(pitfalls=Reply({REDUCER_REL: page.rstrip("\n") + "\n- **Name the unnested column.**\n"}))
    box = BoxSpy()

    with scripted(model, w.monkeypatch):
        rc = lead_author_drain(w.t, w.paths, box=box, run_lead_author=lambda *_a, **_k: None,
                               make_model=model.make_model)

    assert rc == 0
    (request,) = box.requests
    assert _writable(request) == _lane_sources(request, "skills"), (
        f"the lead-author box's writable mounts are {sorted(map(str, _writable(request)))}")
    assert not _lane_sources(request, "lessons", "lessons-questioner") & _writable(request)


def test_each_curator_is_scoped_to_its_own_corpus(tmp_path):
    """A claim in which only the questioner curator runs hands it the draft's `agent/lessons-questioner` as its
    corpus, and touches no defender item."""
    agent = D.recording(D.committing("questioner-lesson"))
    lane = G.gate_lane(tmp_path)

    rc, outcomes = G.claim(G.questioner_cfg(lane, invoke_agent=agent), [world_queue_row()], kind="questioner_finding")

    assert rc == 0
    assert agent.calls, "the questioner curator never reached its model step"
    assert Path(agent.calls[0]["cfg"].corpus_dir) == lane.sibling_dir, (
        f"the questioner curator's corpus dir is {agent.calls[0]['cfg'].corpus_dir}")
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/0"]
    assert set(outcomes) <= {("questioner_finding", "ep-1/b/0/0")}, f"a fate was named for another item: {outcomes}"


@pytest.mark.postgres
@pytest.mark.parametrize("fault_class", [RuntimeError, TimeoutError],
                         ids=["escapes-the-catch", "swallowed-as-an-oserror"])
def test_a_faulting_curator_leaves_the_others_commit_and_items_intact(world, caplog, fault_class):  # noqa: F811 — the imported fixture
    """One curator's fault leaves the other's landed commit and its item intact, is logged by name and class, and
    leaves the faulting curator's item waiting, not authored or consumed (`drains._store_curators`: each curator's
    fault is contained to it; its items take what the batch's commits show)."""
    w = world
    _seed(w, defender_queue_row())
    _seed(w, world_queue_row(), kind="questioner_finding")
    trigger = TwoLaneRecorder(D.recording(D.committing("family-lesson")), run=(W.DEFENDER_CURATOR_MODULE,),
                              fail_on=(W.QUESTIONER_CURATOR_MODULE,), fault_class=fault_class)

    with caplog.at_level(logging.ERROR):
        rc, _box = _tick(w, trigger)

    assert rc == 0
    assert W.QUESTIONER_CURATOR_MODULE in trigger.modules, (
        f"the questioner curator was never triggered, so no fault was induced and every assertion holds vacuously: "
        f"{trigger.modules}")
    items = _items(w)
    assert items[("finding", "ep-1/b/0/1")].status == "in_batch", (
        f"the defender curator authored and committed, and its row is not in the batch: {items}")
    assert items[("questioner_finding", "ep-1/b/0/0")].status == "waiting", (
        f"the faulting curator's row left waiting although no lesson was written: {items}")
    assert any(W.QUESTIONER_CURATOR_MODULE in r.getMessage() and fault_class.__name__ in r.getMessage()
               for r in caplog.records), "the fault was not logged against the curator that took it, by class"
    assert not any(W.DEFENDER_CURATOR_MODULE in r.getMessage() and "took this curator out" in r.getMessage()
                   for r in caplog.records), "the surviving curator was recorded as faulted"


def test_nothing_lands_outside_the_declared_write_set(tmp_path, monkeypatch):
    """A graded pass writes nothing outside the declared episode artifacts, and its rows go to the store."""
    built = W.contrast_family(tmp_path, monkeypatch)
    ep = built.ep
    before = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}
    judge = S.judge({"b": S.world_reply("lead-quality", ["idp"], investigator=[S.inv()],
                                        world=[S.wf("mislabelled")])})

    S.grade(built, judge)

    # Control: the pass queued on BOTH channels, so the write set is a whole pass's, not a
    # refused one's.
    for channel in (FINDINGS, QUESTIONER_FINDINGS):
        assert S.env_state().rows(channel), (
            f"the pass queued nothing as {channel.name}, so the write set below is not a whole pass's")
    after = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}
    allowed = {Path(W.JUDGE_NAME), Path(W.OUTCOME_NAME), Path(W.SAMPLES_NAME)}
    new = {p for p in after - before
           if p not in allowed and p.parts[0] not in ("served", "worlds", "judge", "wire_logs")}
    assert new == set(), (
        f"the pass wrote artifacts outside the declared set: {sorted(map(str, new))}")
