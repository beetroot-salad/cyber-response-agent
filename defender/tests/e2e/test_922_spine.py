"""#922 — the surviving training spine, and the drain that must stop deriving itself from a
table the cutover deletes."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
import json
from pathlib import Path

import pytest

from defender.learning.author.lessons import run as lessons_run
from defender.learning.core import drains
from defender.tests.support.learning.curation import _drain719 as D
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.e2e import _box665 as B
from defender.tests.support.learning.core import _state1135
from defender.learning.core.state import FINDINGS
from defender.tests.tenancy.tenant_1108_delivery._support import merge_on_remote
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    AUTHOR_DRAFT_LANES,
    LESSONS_PREFIX,
    draft_lane_trees,
    drain_paths,
    product_repo,
    remote_branches,
    touched,
    under,
)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, git, published_tenant

pytestmark = pytest.mark.e2e


RETIRED_OBSERVATION_QUEUES = (
    "actor_observations.jsonl",
    "actor_environment_observations.jsonl",
    "environment_observations.jsonl",
)

#: The retired sibling corpora, by directory name for the same reason.
RETIRED_CORPORA = ("lessons-actor", "lessons-environment")


@pytest.fixture(autouse=True)
def _isolated_roots(tmp_path, monkeypatch):
    """Every shared root this spine touches, pointed inside `tmp_path`."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")
    # Stated rather than inherited: the drive below queues two family rows, and the shipped
    # default of 5 would make every assertion below vacuous on a drain that never woke.
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")


class TriggerRecorder:
    """The `trigger_author=` seam: records the inbound payload of every curator trigger, and
    runs the REAL findings curator for the findings one."""

    def __init__(self, agent) -> None:
        self.calls: list[dict] = []
        #: The modules whose REAL `run_batch` returned. The drain records a curator's fault and
        #: goes on (rc 0), so a curator knocked out of the tick looks like one that held every
        #: row; a demand about what the curator did checks this first.
        self.completed: list[str] = []
        self._agent = agent

    def __call__(self, paths, state, channel, threshold_env, module_name, pending_label,
                 *, batch, box=None, **kw) -> None:
        # #1108 P4 (OD16, class ii): the drain hands the tick's batch; the curator runs over
        # that batch's draft lanes with `batch=` (as `_drain_support.CuratorTrigger` does),
        # never over checkout trees built from `paths`.
        assert batch is not None, "the drain handed the findings trigger no batch"
        self.calls.append({
            "pending_file": state.describe(channel), "threshold_env": threshold_env,
            "module_name": module_name, "pending_label": pending_label, "box": box,
            "batch": batch,
        })
        if module_name != "author":
            return
        with draft_lane_trees(batch, AUTHOR_DRAFT_LANES) as trees:
            cfg = dataclasses.replace(
                lessons_run.build_author_config(
                    paths, state=state, trees=trees, box=box, batch=batch, **kw),
                invoke_agent=self._agent,
            )
            assert Path(cfg.corpus_dir).is_relative_to(Path(batch.draft_root)), (
                f"the curator's corpus {cfg.corpus_dir} is not in the batch's draft")
            lessons_run.run_batch(paths=paths, state=state, cfg=cfg, hold_committed=True,
                                  box=box)
        self.completed.append(module_name)

    @property
    def modules(self) -> list[str]:
        return [c["module_name"] for c in self.calls]


def graded_episode(tmp_path: Path, paths, *, reply=None):
    """One accepted episode graded by the REAL family judge, its rows on the REAL queue."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []},
                            dispositions={"a": "benign", "b": "malicious", "c": "malicious"})
    (ep / "worlds" / J.world_id(ep, "b") / "report.md").write_text(J.report_text("benign"), encoding="utf-8")
    from defender.learning.core.state import LearningState

    with LearningState.open(paths) as state:
        J.grade_at(
            ep, judge=J.FakeJudge(
                default=reply or J.as_reply_text(J.reply_doc()),
                family_default=J.as_reply_text(J.family_reply())),
            draws=1, state=state)
    return ep, J.judge_record(ep)


@pytest.fixture
def tenant(tmp_path, data_root):
    """The fixture tenant published for real, its forge bound (#1108 P4: the drain's batches
    are branches of the tenant repo, delivered to its forge)."""
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        yield t


def tenant_paths(t, tmp_path):
    """The tenant's learning paths over a scratch product checkout, its state root made."""
    paths = drain_paths(t, product_repo(tmp_path))
    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)
    return paths


def drive_tenant_author_drain(t, paths, trigger, *, rec=None):
    """The REAL `author_drain` over the tenant path (#1108 P4 flow 4): the tenant forge fake's
    client, an identity over its issuer fake, and the box seams (assumed seams, see
    `tenant_1108_p4/_drain_support.py`)."""
    rec = rec or B.BoxLifecycleRecorder()
    rc = drains.author_drain(
        paths, trigger_author=trigger, client=t.forge.client, identity=t.vault.identity(),
        start_box=rec.start_box, stop_box=rec.stop_box)
    return rc, rec


def draft_root(request) -> Path:
    """The batch draft's root: the box's one `staged` mount."""
    (staged,) = [Path(m.source) for m in request.mounts if m.kind == "staged"]
    return staged


def writable_sources(request) -> set[Path]:
    return {Path(m.source) for m in request.mounts if m.writable}


def readonly_sources(request) -> set[Path]:
    return {Path(m.source) for m in request.mounts if not m.writable}


def stuff_retired_queues(paths, *, rows: int = 25) -> None:
    """Put every retired observation queue far over any threshold the drain could read."""
    (location_path(paths.state_root) / FINDINGS.queue).parent.mkdir(parents=True, exist_ok=True)
    for name in RETIRED_OBSERVATION_QUEUES:
        ((location_path(paths.state_root) / FINDINGS.queue).parent / name).write_text(
            "".join(json.dumps(D.obs_row(f"{name}-{i}")) + "\n" for i in range(rows)),
            encoding="utf-8")


def test_922_graded_episode_reaches_the_corpus_through_the_family_partition(tenant, tmp_path):
    """GUARD (#922; re-spelled onto the tenant path, #1108 P4): the graded episode's family rows
    reach the findings curator, which authors one lesson attributing them, delivered as one
    commit on a `lessons/` branch of the tenant repo; the rows stay queued (`hold_committed`)
    until a later tick reads the attribution back from the merged corpus and retires them as
    `consumed_idempotent` without authoring again or opening another branch."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    _ep, record = graded_episode(tmp_path, paths)
    channel = FINDINGS

    assert all(row["measured"] for row in record["worlds"]), "a graded world was not measured"
    queued = [r["finding_id"] for r in D.pending(paths, channel)]
    assert record["enqueued_rows"] == len(queued) == 2, (
        f"the graded episode did not put its rows on the shared queue: {queued}")
    assert {r["direction"] for r in D.pending(paths, channel)} == {"family"}, (
        "the spine's producer is the family judge; a non-family row here means the drive is "
        "not exercising the partition this demand is about")

    main = t.origin_main()
    agent = D.recording(D.committing("family-lesson"))
    first = TriggerRecorder(agent)
    rc, _rec = drive_tenant_author_drain(t, paths, first)

    assert rc == 0, "author_drain did not complete its batch"
    assert first.completed == ["author"], "the findings curator was taken out of the tick"
    assert len(agent.calls) == 1, (
        f"the findings curator ran {len(agent.calls)} times, not once")
    authored = [r["finding_id"] for r in agent.calls[0]["rows"]]
    assert authored == queued, (
        f"the curator was handed {authored}, not the graded episode's rows {queued} — the "
        "family partition did not admit them for authoring")

    (branch, tip), = remote_branches(t.remote, LESSONS_PREFIX).items()
    landed = touched(t.remote, main, tip)
    assert len(landed) == 1, f"the batch landed {landed}, not one lesson"
    assert landed[0].startswith("agent/lessons/family-lesson-"), landed
    body = git(t.remote, "show", f"{tip}:{landed[0]}")
    for fid in queued:
        assert fid in body, f"the committed lesson does not attribute {fid}"
    assert {r["finding_id"] for r in D.pending(paths, channel)} == set(queued), (
        "the committed rows left the queue before the batch's PR merged — `hold_committed=True` "
        "is what keeps them there for the next tick to retire")

    merge_on_remote(t.p3, t.scratch, branch)
    branches = remote_branches(t.remote, LESSONS_PREFIX)
    second = D.recording(D.committing("must-not-run-twice"))
    again = TriggerRecorder(second)
    assert drive_tenant_author_drain(t, paths, again)[0] == 0
    assert again.completed == ["author"], "the second tick's curator was taken out of the tick"
    assert second.calls == [], (
        "the second tick authored the same findings again — the corpus attribution the first "
        "tick wrote is not being read back")
    consumed = {r["finding_id"]: r for r in D.consumed(paths, channel)}
    assert set(consumed) == set(queued), (
        f"the rows did not rotate off the queue as consumed: {sorted(consumed)}")
    assert all(r["consumed_category"] == "consumed_idempotent" for r in consumed.values())
    assert D.pending(paths, channel) == [], "the authored rows are still queued"
    assert remote_branches(t.remote, LESSONS_PREFIX) == branches, (
        "the second tick opened a second batch for findings already in the corpus")


def test_922_a_caught_family_is_consumed_without_authoring(tenant, tmp_path):
    """GUARD (#922; tenant path, #1108 P4): a retired-word family row is held, never authored:
    no curator call, no batch branch or PR on the tenant forge, nothing consumed."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    channel = FINDINGS
    D.seed(paths, channel, [
        dict(D.finding_row("ep-caught/b/0/0", run_id="ep-caught", direction="family"),
             type="decision-discipline", judge_outcome="caught", subject_anchor="l-001",
             subject_topic="holding-system coverage",
             source_run_dir="episodes/ep-caught/worlds/b"),
    ])

    agent = D.recording(D.committing("must-not-run"))
    trigger = TriggerRecorder(agent)
    rc, _rec = drive_tenant_author_drain(t, paths, trigger)

    assert rc == 0
    assert trigger.completed == ["author"], (
        "the findings curator was taken out of the tick, so 'never authored' proves nothing")
    assert agent.calls == [], (
        "a retired-word family row reached the curator — the partition authored a row the "
        "retired design would have read")
    assert remote_branches(t.remote, LESSONS_PREFIX) == {}, (
        "a retired-word family row produced a batch on the tenant repo")
    assert t.forge.creates == []
    assert D.consumed(paths, channel) == [], "the retired-word row was consumed, not held"
    assert [r["finding_id"] for r in D.pending(paths, channel)] == ["ep-caught/b/0/0"], (
        "the retired-word row left the queue instead of being held")


def test_922_author_drain_triggers_exactly_the_findings_curator(tenant, tmp_path):
    """#922 (tenant path, #1108 P4): the drain triggers its two named curators, never one per
    retired observation queue, and hands the findings trigger the findings queue."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    graded_episode(tmp_path, paths)
    stuff_retired_queues(paths)

    trigger = TriggerRecorder(D.recording(D.committing("family-lesson")))
    rc, _rec = drive_tenant_author_drain(t, paths, trigger)

    assert rc == 0
    assert trigger.completed == ["author"], "the findings curator was taken out of the tick"
    assert sorted(trigger.modules) == ["author", "questioner_curator"], (
        f"author_drain triggered {trigger.modules} — it is still discovering its curators by "
        "iterating the direction table, so the retired observation channels are still drained")
    call = next(c for c in trigger.calls if c["module_name"] == "author")
    assert call["pending_file"] == str(location_path(paths.state_root) / FINDINGS.queue), (
        f"the findings trigger names {call['pending_file']}, not the findings queue")
    assert call["threshold_env"] == "LEARNING_AUTHOR_THRESHOLD"
    assert call["pending_label"] == "pending"


def test_922_the_drain_box_gets_exactly_the_lessons_corpus_writable(tenant, tmp_path):
    """#922 (tenant path, #1108 P4): the drain box's writable mounts are exactly the draft's two
    lesson corpora, its read-only mounts the product code (`code`) and the draft root
    (`staged`), never the tenant clone, and no retired corpus is bound."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    graded_episode(tmp_path, paths)
    stuff_retired_queues(paths)

    rec = B.BoxLifecycleRecorder()
    trigger = TriggerRecorder(D.recording(D.committing("family-lesson")))
    rc, rec = drive_tenant_author_drain(t, paths, trigger, rec=rec)

    assert rc == 0
    assert trigger.completed == ["author"], "the findings curator was taken out of the tick"
    request = rec.only_request()
    draft = draft_root(request)
    assert writable_sources(request) == {draft / "agent" / "lessons",
                                         draft / "agent" / "lessons-questioner"}, (
        f"the drain box's writable mounts are {sorted(map(str, writable_sources(request)))} — "
        "the mount set is still derived from the direction table, so a retired corpus is "
        "still handed to the batch as a writable bind")
    assert sorted(m.kind for m in request.mounts if not m.writable) == ["code", "staged"], (
        request.mounts)
    assert not [m for m in request.mounts
                if under(m.source, t.clone) or under(t.clone, m.source)], request.mounts
    for retired in RETIRED_CORPORA:
        assert B.mount_for(request, retired) is None, (
            f"{retired} is still bound into the drain box")


def test_922_a_full_findings_queue_alone_wakes_the_drain(tenant, tmp_path):
    """GUARD (#922; tenant path, #1108 P4): the findings queue alone wakes the drain, whose box
    gets the draft's two lesson corpora writable."""
    t = tenant
    paths = tenant_paths(t, tmp_path)
    graded_episode(tmp_path, paths)
    for name in RETIRED_OBSERVATION_QUEUES:
        assert not ((location_path(paths.state_root) / FINDINGS.queue).parent / name).exists(), (
            "this control is about a findings-only queue; an observation queue exists")

    trigger = TriggerRecorder(D.recording(D.committing("family-lesson")))
    rec = B.BoxLifecycleRecorder()
    rc, rec = drive_tenant_author_drain(t, paths, trigger, rec=rec)

    assert rc == 0
    assert trigger.completed == ["author"], "the findings curator was taken out of the tick"
    assert "author" in trigger.modules, (
        "the findings queue alone did not wake the drain — the surviving channel's own "
        "threshold no longer answers the wake gate")
    draft = draft_root(rec.only_request())
    assert writable_sources(rec.only_request()) == {draft / "agent" / "lessons",
                                                    draft / "agent" / "lessons-questioner"}
